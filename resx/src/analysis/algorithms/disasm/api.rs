use super::*;
/// One CALL or JMP in a function, with its resolved target label.
#[derive(Debug, Clone)]
pub struct ApiCall {
    pub rva: u32,
    pub kind: String,    // "call" or "jmp"
    pub target_rva: u32, // 0 when indirect/unresolvable
    pub label: String,   // resolved name or "sub_XXXXXXXX"
    pub dll: String,     // non-empty for IAT imports
    pub is_import: bool,
    pub is_indirect: bool,
    /// How the indirect target was seen/resolved, e.g. "rax ← IAT [rip+0x1234]".
    /// None for direct (non-indirect) calls.
    pub indirect_method: Option<String>,
    /// Selector values that route to this switch-dispatch target.
    /// Empty for non-switch entries.  Printed on a `when:` sub-line.
    pub switch_cases: Vec<u32>,
}

/// Short lowercase name for a register, normalized to 64-bit form.
fn register_short_name(reg: Register) -> String {
    format!("{:?}", reg.full_register()).to_lowercase()
}

/// Describes how an indirect register's value originated.
pub(super) struct RegSource {
    pub(super) label: String,
    pub(super) dll: String,
    pub(super) is_import: bool,
    /// Human-readable description of how the register was loaded.
    pub(super) method: String,
    pub(super) target_rva: u32,
    pub(super) iat_slot_rva: u32,
}

/// Expression type for backward register slicing.
#[derive(Debug, Clone)]
enum RegExpr {
    Unknown,
    Imm(u64),
    Va(u64),
    Import {
        dll: String,
        func: String,
        slot_rva: u32,
    },
    WdfFunction {
        func: String,
        table: String,
        offset: u64,
    },
    Derived(String),
}

fn combine_add(base: RegExpr, rhs: u64) -> RegExpr {
    match base {
        RegExpr::Imm(v) => RegExpr::Imm(v.wrapping_add(rhs)),
        RegExpr::Va(v) => RegExpr::Va(v.wrapping_add(rhs)),
        RegExpr::Import {
            dll,
            func,
            slot_rva,
        } => RegExpr::Derived(format!(
            "{dll}!{func} @IAT+0x{rhs:X} [slot 0x{slot_rva:08X}]"
        )),
        RegExpr::WdfFunction {
            func,
            table,
            offset,
        } => RegExpr::Derived(format!("{table}[0x{offset:X}]/{func} + 0x{rhs:X}")),
        RegExpr::Derived(s) => RegExpr::Derived(format!("({s}) + 0x{rhs:X}")),
        RegExpr::Unknown => RegExpr::Unknown,
    }
}

fn combine_sub(base: RegExpr, rhs: u64) -> RegExpr {
    match base {
        RegExpr::Imm(v) => RegExpr::Imm(v.wrapping_sub(rhs)),
        RegExpr::Va(v) => RegExpr::Va(v.wrapping_sub(rhs)),
        RegExpr::Import {
            dll,
            func,
            slot_rva,
        } => RegExpr::Derived(format!(
            "{dll}!{func} @IAT-0x{rhs:X} [slot 0x{slot_rva:08X}]"
        )),
        RegExpr::WdfFunction {
            func,
            table,
            offset,
        } => RegExpr::Derived(format!("{table}[0x{offset:X}]/{func} - 0x{rhs:X}")),
        RegExpr::Derived(s) => RegExpr::Derived(format!("({s}) - 0x{rhs:X}")),
        RegExpr::Unknown => RegExpr::Unknown,
    }
}

fn expr_to_regsource(expr: RegExpr, reg: Register) -> RegSource {
    let reg_name = register_short_name(reg);
    match expr {
        RegExpr::Import {
            dll,
            func,
            slot_rva,
        } => RegSource {
            label: func,
            dll,
            is_import: true,
            method: format!("{reg_name} ← IAT slot 0x{slot_rva:08X}"),
            target_rva: 0,
            iat_slot_rva: slot_rva,
        },
        RegExpr::WdfFunction {
            func,
            table,
            offset,
        } => RegSource {
            label: func,
            dll: "WDF".to_owned(),
            is_import: true,
            method: format!("{reg_name} ← {table}[0x{offset:X}]"),
            target_rva: 0,
            iat_slot_rva: 0,
        },
        RegExpr::Va(va) => RegSource {
            label: format!("0x{va:016X}"),
            dll: String::new(),
            is_import: false,
            method: format!("{reg_name} ← VA 0x{va:016X}"),
            target_rva: va as u32,
            iat_slot_rva: 0,
        },
        RegExpr::Imm(v) => RegSource {
            label: format!("0x{v:016X}"),
            dll: String::new(),
            is_import: false,
            method: format!("{reg_name} ← imm 0x{v:016X}"),
            target_rva: 0,
            iat_slot_rva: 0,
        },
        RegExpr::Derived(s) => RegSource {
            label: format!("[{s}]"),
            dll: String::new(),
            is_import: false,
            method: format!("{reg_name} ← {s}"),
            target_rva: 0,
            iat_slot_rva: 0,
        },
        RegExpr::Unknown => RegSource {
            label: format!("[via {reg_name}]"),
            dll: String::new(),
            is_import: false,
            method: format!("unresolved register {reg_name}"),
            target_rva: 0,
            iat_slot_rva: 0,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn resolve_reg_expr(
    insns: &[Instruction],
    until_idx: usize,
    reg: Register,
    image_base: u64,
    pe: &PeFile,
    raw: &[u8],
    symbols: Option<&SymbolIndex>,
    depth: usize,
) -> RegExpr {
    use iced_x86::Mnemonic;

    if depth > 8 {
        return RegExpr::Unknown;
    }

    let full_reg = reg.full_register();

    // Scan at most 64 instructions backwards from until_idx.
    // Use enumerate to get the absolute index directly — avoids the O(N)
    // linear position() search that made this catastrophically slow on large images.
    let scan_start = until_idx.saturating_sub(64);
    for (rel, insn) in insns[scan_start..until_idx].iter().enumerate().rev() {
        if insn.iced.op_count() == 0 || insn.iced.op0_kind() != OpKind::Register {
            continue;
        }

        let dst = insn.iced.op0_register().full_register();
        if dst != full_reg {
            continue;
        }

        let insn_pos = scan_start + rel;

        return match insn.iced.mnemonic() {
            Mnemonic::Mov => match insn.iced.op1_kind() {
                OpKind::Register => {
                    let src = insn.iced.op1_register().full_register();
                    resolve_reg_expr(
                        insns,
                        insn_pos,
                        src,
                        image_base,
                        pe,
                        raw,
                        symbols,
                        depth + 1,
                    )
                }
                OpKind::Immediate8 => RegExpr::Imm(insn.iced.immediate8() as u64),
                OpKind::Immediate16 => RegExpr::Imm(insn.iced.immediate16() as u64),
                OpKind::Immediate32 | OpKind::Immediate32to64 => {
                    RegExpr::Imm(insn.iced.immediate32() as u64)
                }
                OpKind::Immediate64 => RegExpr::Imm(insn.iced.immediate64()),
                OpKind::Memory => {
                    let mem_base = insn.iced.memory_base().full_register();
                    if mem_base == full_reg && insn.iced.memory_index() == Register::None {
                        let base = resolve_reg_expr(
                            insns,
                            insn_pos,
                            full_reg,
                            image_base,
                            pe,
                            raw,
                            symbols,
                            depth + 1,
                        );
                        if let RegExpr::Va(table_va) = base {
                            let Some(table_name) = symbols
                                .and_then(|si| si.lookup(table_va))
                                .map(|hit| hit.symbol.name)
                                .filter(|name| crate::analysis::wdf::is_wdf_table_symbol(name))
                            else {
                                return RegExpr::Unknown;
                            };
                            let offset = insn.iced.memory_displacement64();
                            if let Some(func) = crate::analysis::wdf::function_from_offset(
                                offset,
                                if pe.arch == 64 { 8 } else { 4 },
                            ) {
                                return RegExpr::WdfFunction {
                                    func: func.name.to_owned(),
                                    table: table_name,
                                    offset,
                                };
                            }
                        }
                    }

                    let slot_va =
                        if matches!(insn.iced.memory_base(), Register::RIP | Register::EIP) {
                            insn.iced.ip_rel_memory_address()
                        } else if insn.iced.memory_base() == Register::None
                            && insn.iced.memory_index() == Register::None
                        {
                            insn.iced.memory_displacement64()
                        } else {
                            0
                        };

                    if slot_va >= image_base {
                        let slot_rva = (slot_va - image_base) as u32;
                        if let Some((dll, func)) =
                            crate::formats::pe::resolve_iat_slot(pe, raw, slot_rva)
                        {
                            RegExpr::Import {
                                dll,
                                func,
                                slot_rva,
                            }
                        } else {
                            RegExpr::Va(slot_va)
                        }
                    } else {
                        RegExpr::Unknown
                    }
                }
                _ => RegExpr::Unknown,
            },

            Mnemonic::Lea => {
                if matches!(insn.iced.memory_base(), Register::RIP | Register::EIP) {
                    RegExpr::Va(insn.iced.ip_rel_memory_address())
                } else if insn.iced.memory_base() == Register::None
                    && insn.iced.memory_index() == Register::None
                {
                    RegExpr::Va(insn.iced.memory_displacement64())
                } else {
                    RegExpr::Derived(format!("lea {}", insn.operands))
                }
            }

            Mnemonic::Add => {
                let base = resolve_reg_expr(
                    insns,
                    insn_pos,
                    full_reg,
                    image_base,
                    pe,
                    raw,
                    symbols,
                    depth + 1,
                );
                match insn.iced.op1_kind() {
                    OpKind::Immediate8 => combine_add(base, insn.iced.immediate8() as u64),
                    OpKind::Immediate16 => combine_add(base, insn.iced.immediate16() as u64),
                    OpKind::Immediate32 | OpKind::Immediate32to64 => {
                        combine_add(base, insn.iced.immediate32() as u64)
                    }
                    OpKind::Immediate64 => combine_add(base, insn.iced.immediate64()),
                    _ => RegExpr::Derived(format!(
                        "{} + {}",
                        register_short_name(full_reg),
                        insn.operands
                    )),
                }
            }

            Mnemonic::Sub => {
                let base = resolve_reg_expr(
                    insns,
                    insn_pos,
                    full_reg,
                    image_base,
                    pe,
                    raw,
                    symbols,
                    depth + 1,
                );
                match insn.iced.op1_kind() {
                    OpKind::Immediate8 => combine_sub(base, insn.iced.immediate8() as u64),
                    OpKind::Immediate16 => combine_sub(base, insn.iced.immediate16() as u64),
                    OpKind::Immediate32 | OpKind::Immediate32to64 => {
                        combine_sub(base, insn.iced.immediate32() as u64)
                    }
                    OpKind::Immediate64 => combine_sub(base, insn.iced.immediate64()),
                    _ => RegExpr::Derived(format!(
                        "{} - {}",
                        register_short_name(full_reg),
                        insn.operands
                    )),
                }
            }

            Mnemonic::Xor
                if insn.iced.op1_kind() == OpKind::Register
                    && insn.iced.op1_register().full_register() == full_reg =>
            {
                RegExpr::Imm(0)
            }

            Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::And
            | Mnemonic::Or => RegExpr::Derived(format!(
                "{} {}",
                insn.mnemonic.to_lowercase(),
                insn.operands
            )),

            _ => RegExpr::Unknown,
        };
    }

    RegExpr::Unknown
}

pub(super) fn track_indirect_register(
    insns: &[Instruction],
    call_idx: usize,
    target_reg: Register,
    image_base: u64,
    pe: &PeFile,
    raw: &[u8],
    symbols: Option<&SymbolIndex>,
) -> Option<RegSource> {
    Some(expr_to_regsource(
        resolve_reg_expr(insns, call_idx, target_reg, image_base, pe, raw, symbols, 0),
        target_reg,
    ))
}

pub(super) fn track_wdf_table_register(
    insns: &[Instruction],
    call_idx: usize,
    target_reg: Register,
    symbols: Option<&SymbolIndex>,
    pe: &PeFile,
) -> Option<RegSource> {
    let full_reg = target_reg.full_register();
    let scan_start = call_idx.saturating_sub(96);
    let has_wdf_globals_arg = insns[scan_start..call_idx]
        .iter()
        .rev()
        .take(16)
        .any(|insn| {
            insn.comment.contains("WdfDriverGlobals")
                || (insn.iced.mnemonic() == Mnemonic::Mov
                    && insn.iced.op_count() >= 2
                    && insn.iced.op0_kind() == OpKind::Register
                    && insn.iced.op0_register().full_register() == Register::RCX
                    && insn.iced.op1_kind() == OpKind::Memory)
        });
    for table_idx in (scan_start..call_idx).rev() {
        let insn = &insns[table_idx];
        if insn.iced.mnemonic() != Mnemonic::Mov
            || insn.iced.op_count() < 2
            || insn.iced.op0_kind() != OpKind::Register
            || insn.iced.op0_register().full_register() != full_reg
            || insn.iced.op1_kind() != OpKind::Memory
            || insn.iced.memory_base().full_register() != full_reg
            || insn.iced.memory_index() != Register::None
        {
            continue;
        }

        let offset = insn.iced.memory_displacement64();
        let Some(func) =
            crate::analysis::wdf::function_from_offset(offset, if pe.arch == 64 { 8 } else { 4 })
        else {
            continue;
        };

        for root in insns[scan_start..table_idx].iter().rev().take(32) {
            if root.iced.mnemonic() != Mnemonic::Mov
                || root.iced.op_count() < 2
                || root.iced.op0_kind() != OpKind::Register
                || root.iced.op0_register().full_register() != full_reg
                || root.iced.op1_kind() != OpKind::Memory
                || !matches!(root.iced.memory_base(), Register::RIP | Register::EIP)
            {
                continue;
            }

            let table_va = root.iced.ip_rel_memory_address();
            let table_name = root
                .comment
                .split_whitespace()
                .find(|part| crate::analysis::wdf::is_wdf_table_symbol(part))
                .map(|part| part.trim_end_matches("(data)").to_owned())
                .or_else(|| {
                    symbols
                        .and_then(|si| si.lookup(table_va))
                        .map(|hit| hit.symbol.name)
                        .filter(|name| crate::analysis::wdf::is_wdf_table_symbol(name))
                })
                .or_else(|| has_wdf_globals_arg.then(|| "WdfFunctions".to_owned()))?;
            if !crate::analysis::wdf::is_wdf_table_symbol(&table_name) {
                return None;
            }
            return Some(RegSource {
                label: func.name.to_owned(),
                dll: "WDF".to_owned(),
                is_import: true,
                method: format!(
                    "{} ← {}[0x{:X}]",
                    register_short_name(target_reg),
                    table_name,
                    offset
                ),
                target_rva: 0,
                iat_slot_rva: 0,
            });
        }
    }
    None
}

/// Flag suspicious indirect control-flow for annotation in the disasm listing.
pub(super) fn suspicious_flow_note(instr: &iced_x86::Instruction) -> Option<String> {
    use iced_x86::Mnemonic;
    let m = instr.mnemonic();

    if matches!(m, Mnemonic::Call | Mnemonic::Jmp) && instr.op0_kind() == OpKind::Register {
        return Some(format!(
            "indirect {} via {}",
            format!("{:?}", m).to_lowercase(),
            format!("{:?}", instr.op0_register().full_register()).to_lowercase()
        ));
    }

    if matches!(
        m,
        Mnemonic::Rol | Mnemonic::Ror | Mnemonic::Shl | Mnemonic::Shr | Mnemonic::Sar
    ) {
        return Some("bit-mix / pointer-transform candidate".to_owned());
    }

    None
}

/// Walk `insns` and resolve every CALL/JMP to its target name.
/// Handles direct calls (using the symbol index), indirect IAT calls
/// (`resolve_iat_slot`), and register-indirect calls (backward register tracking).
///
/// Register-indirect *JMPs* that cannot be resolved here are **skipped** — their
/// targets are resolved by the switch-dispatch path in the caller and merged in
/// afterwards.  Register-indirect *CALLs* that cannot be resolved are always
/// emitted so the caller has full visibility of every call site.
pub fn collect_api_calls(
    insns: &[Instruction],
    pe: &PeFile,
    raw: &[u8],
    symbol_index: &SymbolIndex,
    image_base: u64,
    hostile: bool,
) -> Vec<ApiCall> {
    let mut results = Vec::new();

    for (idx, insn) in insns.iter().enumerate() {
        if !insn.is_call && !insn.is_jmp {
            continue;
        }
        let kind = if insn.is_call { "call" } else { "jmp" }.to_string();

        if insn.call_target != 0 {
            // Direct near call / unconditional jmp with an immediate target.
            let target_rva = insn.call_target.wrapping_sub(image_base) as u32;
            let label = if let Some(hit) = symbol_index.lookup(insn.call_target) {
                hit.symbol.name.clone()
            } else {
                format!("sub_{:08X}", target_rva)
            };
            results.push(ApiCall {
                rva: insn.rva,
                kind,
                target_rva,
                label,
                dll: String::new(),
                is_import: false,
                is_indirect: false,
                indirect_method: None,
                switch_cases: Vec::new(),
            });
        } else if insn.iced.op_count() > 0 && insn.iced.op0_kind() == OpKind::Memory {
            // Indirect call/jmp — most commonly `call [rip+rel32]` through the IAT.
            if is_guard_dispatch_call(insn, symbol_index) {
                if let Some(src) =
                    track_wdf_table_register(insns, idx, Register::RAX, Some(symbol_index), pe)
                        .or_else(|| {
                            track_indirect_register(
                                insns,
                                idx,
                                Register::RAX,
                                image_base,
                                pe,
                                raw,
                                Some(symbol_index),
                            )
                        })
                {
                    results.push(ApiCall {
                        rva: insn.rva,
                        kind,
                        target_rva: src.target_rva,
                        label: src.label,
                        dll: src.dll,
                        is_import: src.is_import,
                        is_indirect: true,
                        indirect_method: Some(format!(
                            "{} via {}",
                            src.method, "__guard_dispatch_icall_fptr"
                        )),
                        switch_cases: Vec::new(),
                    });
                    continue;
                }
            }

            let slot_va = if insn.iced.memory_base() == Register::RIP
                || insn.iced.memory_base() == Register::EIP
            {
                insn.iced.ip_rel_memory_address()
            } else if insn.iced.memory_base() == Register::None
                && insn.iced.memory_index() == Register::None
            {
                insn.iced.memory_displacement64()
            } else {
                0
            };

            if slot_va != 0 && slot_va >= image_base {
                let slot_rva = (slot_va - image_base) as u32;
                if let Some((dll, func)) = crate::formats::pe::resolve_iat_slot(pe, raw, slot_rva) {
                    let iat_method = if insn.iced.memory_base() == Register::RIP
                        || insn.iced.memory_base() == Register::EIP
                    {
                        format!("IAT [rip+0x{:X}]", insn.iced.memory_displacement64())
                    } else {
                        format!("IAT [0x{:X}]", slot_va)
                    };
                    results.push(ApiCall {
                        rva: insn.rva,
                        kind,
                        target_rva: 0,
                        label: func,
                        dll,
                        is_import: true,
                        is_indirect: true,
                        indirect_method: Some(iat_method),
                        switch_cases: Vec::new(),
                    });
                    continue;
                }
            }

            // IAT resolution failed — use whatever the comment already has.
            let label = if !insn.comment.is_empty() {
                insn.comment.clone()
            } else {
                format!("[{}]", insn.operands)
            };
            let mem_method = if insn.iced.memory_base() == Register::RIP
                || insn.iced.memory_base() == Register::EIP
            {
                format!("[rip+0x{:X}]", insn.iced.memory_displacement64())
            } else {
                format!("[{}]", insn.operands)
            };
            results.push(ApiCall {
                rva: insn.rva,
                kind,
                target_rva: 0,
                label,
                dll: String::new(),
                is_import: false,
                is_indirect: true,
                indirect_method: Some(mem_method),
                switch_cases: Vec::new(),
            });
        } else if insn.iced.op_count() > 0 && insn.iced.op0_kind() == OpKind::Register {
            // Register-indirect call/jmp: `call rax`, `jmp r9`, etc.
            // Attempt to resolve by scanning backwards for the register's source.
            let reg = insn.iced.op0_register();
            let reg_name = register_short_name(reg);

            let src =
                track_wdf_table_register(insns, idx, reg, Some(symbol_index), pe).or_else(|| {
                    track_indirect_register(
                        insns,
                        idx,
                        reg,
                        image_base,
                        pe,
                        raw,
                        Some(symbol_index),
                    )
                });
            let is_unresolved = src
                .as_ref()
                .map(|s| !s.is_import && s.target_rva == 0 && s.iat_slot_rva == 0)
                .unwrap_or(true);

            if let Some(src) = src {
                // Emit resolved or partially-resolved result.
                // For unresolved JMPs, only emit when hostile (they are handled by
                // switch-dispatch otherwise).
                if insn.is_call || hostile || !is_unresolved {
                    results.push(ApiCall {
                        rva: insn.rva,
                        kind,
                        target_rva: src.target_rva,
                        label: src.label,
                        dll: src.dll,
                        is_import: src.is_import,
                        is_indirect: true,
                        indirect_method: Some(src.method),
                        switch_cases: Vec::new(),
                    });
                }
            } else if insn.is_call || hostile {
                // Fallback: completely unresolvable register.
                results.push(ApiCall {
                    rva: insn.rva,
                    kind,
                    target_rva: 0,
                    label: format!("[via {reg_name}]"),
                    dll: String::new(),
                    is_import: false,
                    is_indirect: true,
                    indirect_method: Some(format!("unresolved register {reg_name}")),
                    switch_cases: Vec::new(),
                });
            }
            // Non-hostile unresolved JMP via register: left for the switch-dispatch path.
        }
    }

    results
}

pub(super) fn is_guard_dispatch_call(insn: &Instruction, symbol_index: &SymbolIndex) -> bool {
    if !insn.is_call || insn.iced.op_count() == 0 || insn.iced.op0_kind() != OpKind::Memory {
        return false;
    }
    let slot_va = if matches!(insn.iced.memory_base(), Register::RIP | Register::EIP) {
        insn.iced.ip_rel_memory_address()
    } else if insn.iced.memory_base() == Register::None
        && insn.iced.memory_index() == Register::None
    {
        insn.iced.memory_displacement64()
    } else {
        0
    };
    slot_va != 0
        && symbol_index
            .describe(slot_va)
            .map(|desc| desc.contains("__guard_dispatch_icall"))
            .unwrap_or(false)
}

pub(super) fn collect_data_refs(instr: &iced_x86::Instruction) -> Vec<u64> {
    let mut refs = Vec::new();

    if instr.memory_base() == Register::RIP || instr.memory_base() == Register::EIP {
        refs.push(instr.ip_rel_memory_address());
    } else if instr.memory_base() == Register::None && instr.memory_index() == Register::None {
        let disp = instr.memory_displacement64();
        if disp != 0 {
            refs.push(disp);
        }
    }

    for op_idx in 0..instr.op_count() {
        match instr.op_kind(op_idx) {
            OpKind::Immediate64 => refs.push(instr.immediate64()),
            OpKind::Immediate32 => refs.push(instr.immediate32() as u64),
            _ => {}
        }
    }

    refs.sort_unstable();
    refs.dedup();
    refs
}

pub(super) fn describe_segment_access(instr: &iced_x86::Instruction) -> Option<String> {
    if instr.memory_index() != Register::None {
        return None;
    }
    let seg = instr.memory_segment();
    let disp = instr.memory_displacement64();
    match seg {
        Register::FS => describe_fs_access(disp),
        Register::GS => describe_gs_access(disp),
        _ => None,
    }
}

fn describe_fs_access(disp: u64) -> Option<String> {
    let name = match disp {
        0x18 => "TEB.Self",
        0x2C => "TEB.ThreadLocalStoragePointer",
        0x30 => "TEB.ProcessEnvironmentBlock",
        _ => return None,
    };
    Some(format!("fs:[0x{:X}] => {}", disp, name))
}

fn describe_gs_access(disp: u64) -> Option<String> {
    let name = match disp {
        0x30 => "TEB.Self",
        0x58 => "TEB.ThreadLocalStoragePointer",
        0x60 => "TEB.ProcessEnvironmentBlock",
        _ => return None,
    };
    Some(format!("gs:[0x{:X}] => {}", disp, name))
}

pub(super) fn describe_immediate_literals(instr: &iced_x86::Instruction) -> Vec<String> {
    let mut out = Vec::new();
    for op_idx in 0..instr.op_count() {
        let value = match instr.op_kind(op_idx) {
            OpKind::Immediate8 => Some(instr.immediate8() as u64),
            OpKind::Immediate16 => Some(instr.immediate16() as u64),
            OpKind::Immediate32 => Some(instr.immediate32() as u64),
            OpKind::Immediate32to64 => Some(instr.immediate32to64() as u64),
            OpKind::Immediate64 => Some(instr.immediate64()),
            _ => None,
        };
        if let Some(value) = value.and_then(describe_status_literal) {
            out.push(value.to_owned());
        }
    }
    out
}

fn describe_status_literal(value: u64) -> Option<&'static str> {
    crate::core::status::ntstatus_name(value as u32)
}
