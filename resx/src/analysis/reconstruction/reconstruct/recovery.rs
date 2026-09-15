use super::*;

pub(super) fn build_pdb_function_index(symbols: &[PdbSymbol]) -> HashMap<u32, PdbFunction> {
    let mut out = HashMap::new();
    for sym in symbols {
        if sym.kind != "function" || sym.rva == 0 {
            continue;
        }
        let replace = out
            .get(&sym.rva)
            .map(|old: &PdbFunction| old.size == 0 && sym.size > 0)
            .unwrap_or(true);
        if replace {
            out.insert(
                sym.rva,
                PdbFunction {
                    size: sym.size,
                    type_name: sym.type_name.clone(),
                },
            );
        }
    }
    out
}

pub(super) fn callback_spec(name: &str) -> Option<CallbackSpec> {
    let name = normalize_api_name(name);
    let spec = match name.as_str() {
        "createthread" | "beginthreadex" | "_beginthreadex" => CallbackSpec {
            relation: "thread-start",
            tag: "thread-spawn",
            arg_index: 3,
        },
        "beginthread" | "_beginthread" => CallbackSpec {
            relation: "thread-start",
            tag: "thread-spawn",
            arg_index: 1,
        },
        "createremotethread" => CallbackSpec {
            relation: "thread-start",
            tag: "thread-spawn",
            arg_index: 4,
        },
        "queueuserworkitem"
        | "rtlqueueworkitem"
        | "createthreadpoolwork"
        | "trysubmitthreadpoolcallback"
        | "createthreadpooltimer"
        | "createthreadpoolwait" => CallbackSpec {
            relation: "work-callback",
            tag: "workpool",
            arg_index: 1,
        },
        "tpallocwork" | "tpalloctimer" | "tpallocwait" => CallbackSpec {
            relation: "work-callback",
            tag: "workpool",
            arg_index: 2,
        },
        "registerwaitforsingleobject" => CallbackSpec {
            relation: "work-callback",
            tag: "workpool",
            arg_index: 3,
        },
        _ => return None,
    };
    Some(spec)
}

pub(super) fn thread_api_intent(name: &str) -> Option<&'static str> {
    match normalize_api_name(name).as_str() {
        "switchtothread" | "ntyieldexecution" | "zwyieldexecution" => Some("thread-yield"),
        "openthread" | "ntopenthread" | "zwopenthread" => Some("thread-open"),
        "getthreadcontext"
        | "wow64getthreadcontext"
        | "ntgetcontextthread"
        | "zwgetcontextthread" => Some("thread-context-read"),
        "setthreadcontext"
        | "wow64setthreadcontext"
        | "ntsetcontextthread"
        | "zwsetcontextthread" => Some("thread-context-write"),
        "suspendthread" | "ntsuspendthread" | "zwsuspendthread" => Some("thread-suspend"),
        "resumethread" | "ntresumethread" | "zwresumethread" => Some("thread-resume"),
        "queuethreadapc" | "ntqueueapcthread" | "zwqueueapcthread" => Some("thread-apc"),
        "getthreadid" | "getcurrentthreadid" | "teb" => Some("thread-id"),
        "getcurrentthread" | "duplicatehandle" => Some("thread-handle"),
        _ => None,
    }
}

pub(super) fn describe_thread_intent(
    call: &ApiCall,
    insns: &[Instruction],
    pe: &PeFile,
    raw: &[u8],
) -> Option<String> {
    let intent = thread_api_intent(&call.label)?;
    let name = normalize_api_name(&call.label);
    let mut detail = format!("thread intent: {}", intent);

    if matches!(
        name.as_str(),
        "switchtothread" | "ntyieldexecution" | "zwyieldexecution"
    ) {
        detail.push_str(" (current thread yields; no target thread handle)");
        return Some(detail);
    }

    let interesting_arg = match name.as_str() {
        "openthread" | "ntopenthread" | "zwopenthread" => Some(3),
        "getthreadcontext"
        | "wow64getthreadcontext"
        | "ntgetcontextthread"
        | "zwgetcontextthread"
        | "setthreadcontext"
        | "wow64setthreadcontext"
        | "ntsetcontextthread"
        | "zwsetcontextthread"
        | "suspendthread"
        | "ntsuspendthread"
        | "zwsuspendthread"
        | "resumethread"
        | "ntresumethread"
        | "zwresumethread"
        | "queuethreadapc"
        | "ntqueueapcthread"
        | "zwqueueapcthread" => Some(1),
        _ => None,
    };

    if let Some(arg) = interesting_arg {
        if let Some(value) = recover_immediate_arg(insns, call.rva, arg, pe, raw) {
            detail.push_str(&format!("; arg{}=0x{:X}", arg, value));
        } else {
            detail.push_str(&format!("; arg{} unresolved", arg));
        }
    }
    Some(detail)
}

pub(super) fn recover_immediate_arg(
    insns: &[Instruction],
    call_rva: u32,
    arg_index: usize,
    pe: &PeFile,
    raw: &[u8],
) -> Option<u64> {
    let call_idx = insns.iter().position(|insn| insn.rva == call_rva)?;
    if pe.arch == 64 {
        let reg = x64_arg_register(arg_index)?;
        return resolve_immediate_register_before(insns, call_idx, reg, pe, raw, 0);
    }
    recover_x86_stack_immediate_arg(insns, call_idx, arg_index, pe, raw)
}

pub(super) fn recover_x86_stack_immediate_arg(
    insns: &[Instruction],
    call_idx: usize,
    arg_index: usize,
    pe: &PeFile,
    raw: &[u8],
) -> Option<u64> {
    let mut seen_args = 0usize;
    for (idx, insn) in insns[..call_idx].iter().enumerate().rev().take(48) {
        if insn.iced.mnemonic() != Mnemonic::Push || insn.iced.op_count() == 0 {
            continue;
        }
        seen_args += 1;
        if seen_args != arg_index {
            continue;
        }
        if let Some(value) = immediate_operand_value(&insn.iced, 0) {
            return Some(value);
        }
        if insn.iced.op0_kind() == OpKind::Register {
            return resolve_immediate_register_before(
                insns,
                idx,
                insn.iced.op0_register().full_register(),
                pe,
                raw,
                0,
            );
        }
        break;
    }
    None
}

pub(super) fn recover_callback_target(
    insns: &[Instruction],
    call_rva: u32,
    arg_index: usize,
    pe: &PeFile,
    raw: &[u8],
) -> Option<(u32, String)> {
    let call_idx = insns.iter().position(|insn| insn.rva == call_rva)?;
    if pe.arch == 64 {
        let reg = x64_arg_register(arg_index)?;
        return resolve_register_before(insns, call_idx, reg, pe, raw, 0)
            .map(|(rva, method)| (rva, format!("{} {}", register_name(reg), method)));
    }

    resolve_x86_stack_arg(insns, call_idx, arg_index, pe, raw)
}

pub(super) fn resolve_x86_stack_arg(
    insns: &[Instruction],
    call_idx: usize,
    arg_index: usize,
    pe: &PeFile,
    raw: &[u8],
) -> Option<(u32, String)> {
    let mut seen_args = 0usize;
    for (idx, insn) in insns[..call_idx].iter().enumerate().rev().take(48) {
        if insn.iced.mnemonic() != Mnemonic::Push || insn.iced.op_count() == 0 {
            continue;
        }
        seen_args += 1;
        if seen_args != arg_index {
            continue;
        }
        if let Some(rva) = code_target_from_operand(&insn.iced, 0, pe, raw, false) {
            return Some((rva, "stack push immediate".to_owned()));
        }
        if insn.iced.op0_kind() == OpKind::Register {
            let reg = insn.iced.op0_register().full_register();
            return resolve_register_before(insns, idx, reg, pe, raw, 0).map(|(rva, method)| {
                (rva, format!("stack push {} {}", register_name(reg), method))
            });
        }
        break;
    }
    None
}

pub(super) fn resolve_register_before(
    insns: &[Instruction],
    before_idx: usize,
    reg: Register,
    pe: &PeFile,
    raw: &[u8],
    depth: usize,
) -> Option<(u32, String)> {
    if depth > 6 {
        return None;
    }
    let wanted = reg.full_register();
    let scan_start = before_idx.saturating_sub(64);

    for (idx, insn) in insns[scan_start..before_idx].iter().enumerate().rev() {
        let absolute_idx = scan_start + idx;
        let iced = &insn.iced;
        if iced.op_count() == 0 || iced.op0_kind() != OpKind::Register {
            continue;
        }
        let dst = iced.op0_register().full_register();
        if dst != wanted {
            continue;
        }

        match iced.mnemonic() {
            Mnemonic::Lea | Mnemonic::Mov => {
                if iced.op1_kind() == OpKind::Register {
                    let src = iced.op1_register().full_register();
                    return resolve_register_before(insns, absolute_idx, src, pe, raw, depth + 1)
                        .map(|(rva, method)| {
                            (rva, format!("<- {} {}", register_name(src), method))
                        });
                }

                let deref_memory = iced.mnemonic() == Mnemonic::Mov;
                if let Some(rva) = code_target_from_operand(iced, 1, pe, raw, deref_memory) {
                    let method = if iced.mnemonic() == Mnemonic::Lea {
                        "loaded address".to_owned()
                    } else if deref_memory && iced.op1_kind() == OpKind::Memory {
                        "loaded function pointer".to_owned()
                    } else {
                        "loaded immediate".to_owned()
                    };
                    return Some((rva, method));
                }
                return None;
            }
            Mnemonic::Xor
                if iced.op1_kind() == OpKind::Register
                    && iced.op1_register().full_register() == wanted =>
            {
                return None;
            }
            _ => return None,
        }
    }

    None
}

pub(super) fn resolve_immediate_register_before(
    insns: &[Instruction],
    before_idx: usize,
    reg: Register,
    pe: &PeFile,
    raw: &[u8],
    depth: usize,
) -> Option<u64> {
    if depth > 6 {
        return None;
    }
    let wanted = reg.full_register();
    let scan_start = before_idx.saturating_sub(64);

    for (idx, insn) in insns[scan_start..before_idx].iter().enumerate().rev() {
        let absolute_idx = scan_start + idx;
        let iced = &insn.iced;
        if iced.op_count() == 0 || iced.op0_kind() != OpKind::Register {
            continue;
        }
        if iced.op0_register().full_register() != wanted {
            continue;
        }

        match iced.mnemonic() {
            Mnemonic::Mov | Mnemonic::Lea => {
                if let Some(value) = immediate_operand_value(iced, 1) {
                    return Some(value);
                }
                if iced.op1_kind() == OpKind::Register {
                    return resolve_immediate_register_before(
                        insns,
                        absolute_idx,
                        iced.op1_register().full_register(),
                        pe,
                        raw,
                        depth + 1,
                    );
                }
                if iced.op1_kind() == OpKind::Memory {
                    let addr = memory_address(iced)?;
                    if let Some(value) = read_pointer_value(pe, raw, addr) {
                        return Some(value);
                    }
                }
                return None;
            }
            Mnemonic::Xor
                if iced.op1_kind() == OpKind::Register
                    && iced.op1_register().full_register() == wanted =>
            {
                return Some(0);
            }
            _ => return None,
        }
    }

    None
}

pub(super) fn code_target_from_operand(
    instr: &iced_x86::Instruction,
    op_index: u32,
    pe: &PeFile,
    raw: &[u8],
    deref_memory: bool,
) -> Option<u32> {
    let kind = instr.op_kind(op_index);
    match kind {
        OpKind::Immediate8 => code_rva_from_value(pe, instr.immediate8() as u64),
        OpKind::Immediate16 => code_rva_from_value(pe, instr.immediate16() as u64),
        OpKind::Immediate32 | OpKind::Immediate32to64 => {
            code_rva_from_value(pe, instr.immediate32() as u64)
        }
        OpKind::Immediate64 => code_rva_from_value(pe, instr.immediate64()),
        OpKind::Memory => {
            let addr = memory_address(instr)?;
            if deref_memory {
                read_pointer_target(pe, raw, addr)
            } else {
                code_rva_from_value(pe, addr)
            }
        }
        _ => None,
    }
}

pub(super) fn immediate_operand_value(instr: &iced_x86::Instruction, op_index: u32) -> Option<u64> {
    match instr.op_kind(op_index) {
        OpKind::Immediate8 => Some(instr.immediate8() as u64),
        OpKind::Immediate16 => Some(instr.immediate16() as u64),
        OpKind::Immediate32 | OpKind::Immediate32to64 => Some(instr.immediate32() as u64),
        OpKind::Immediate64 => Some(instr.immediate64()),
        _ => None,
    }
}

pub(super) fn memory_address(instr: &iced_x86::Instruction) -> Option<u64> {
    if matches!(instr.memory_base(), Register::RIP | Register::EIP) {
        Some(instr.ip_rel_memory_address())
    } else if instr.memory_base() == Register::None && instr.memory_index() == Register::None {
        let value = instr.memory_displacement64();
        (value != 0).then_some(value)
    } else {
        None
    }
}

pub(super) fn read_pointer_target(pe: &PeFile, raw: &[u8], address: u64) -> Option<u32> {
    let slot_rva = pe
        .va_to_rva(address)
        .or_else(|| code_rva_from_value(pe, address))?;
    let off = pe.rva_to_offset(slot_rva)?;
    let value = read_pointer_value_at_offset(pe, raw, off);
    code_rva_from_value(pe, value)
}

pub(super) fn read_pointer_value(pe: &PeFile, raw: &[u8], address: u64) -> Option<u64> {
    let slot_rva = pe.va_to_rva(address).or_else(|| {
        u32::try_from(address)
            .ok()
            .filter(|rva| pe.rva_to_section(*rva).is_some())
    })?;
    let off = pe.rva_to_offset(slot_rva)?;
    Some(read_pointer_value_at_offset(pe, raw, off))
}

pub(super) fn read_pointer_value_at_offset(pe: &PeFile, raw: &[u8], off: usize) -> u64 {
    if pe.arch == 64 {
        read_u64(raw, off)
    } else {
        read_u32(raw, off) as u64
    }
}

pub(super) fn code_rva_from_value(pe: &PeFile, value: u64) -> Option<u32> {
    pe.va_to_rva(value)
        .or_else(|| {
            u32::try_from(value)
                .ok()
                .filter(|rva| pe.rva_to_section(*rva).is_some())
        })
        .filter(|rva| is_executable_rva(pe, *rva))
}

pub(super) fn executable_target_rva(pe: &PeFile, rva: u32) -> Option<u32> {
    (rva != 0 && is_executable_rva(pe, rva)).then_some(rva)
}

pub(super) fn is_executable_rva(pe: &PeFile, rva: u32) -> bool {
    pe.rva_to_section(rva)
        .is_some_and(|section| section.is_executable())
}

pub(super) fn x64_arg_register(arg_index: usize) -> Option<Register> {
    match arg_index {
        1 => Some(Register::RCX),
        2 => Some(Register::RDX),
        3 => Some(Register::R8),
        4 => Some(Register::R9),
        _ => None,
    }
}

pub(super) fn relation_title(relation: &str) -> String {
    match relation {
        "thread-start" => "Thread Start".to_owned(),
        "work-callback" => "Workpool Callback".to_owned(),
        _ => "Callback".to_owned(),
    }
}

pub(super) fn root_name(
    root: &PeStartupRoutine,
    symbol_index: &SymbolIndex,
    image_base: u64,
) -> String {
    let name = best_symbol_name(symbol_index, image_base, root.rva);
    if name.starts_with("sub_") {
        format!("{} {}", root.kind, name)
    } else {
        name
    }
}

pub(super) fn best_symbol_name(symbol_index: &SymbolIndex, image_base: u64, rva: u32) -> String {
    let va = image_base + rva as u64;
    if let Some(hit) = symbol_index.lookup(va) {
        if hit.displacement == 0 {
            return hit.symbol.name;
        }
        if hit.displacement <= 0x20 {
            return format!("{}+0x{:X}", hit.symbol.name, hit.displacement);
        }
    }
    format!("sub_{:08X}", rva)
}

pub(super) fn call_target_name(call: &ApiCall) -> String {
    if call.dll.is_empty() {
        call.label.clone()
    } else {
        format!("{}!{}", call.dll, call.label)
    }
}

pub(super) fn join_detail(parts: &[String]) -> String {
    parts
        .iter()
        .filter(|part| !part.trim().is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("; ")
}

pub(super) fn normalize_api_name(name: &str) -> String {
    name.rsplit(['!', ':'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('_')
        .trim_end_matches(['A', 'W'])
        .to_ascii_lowercase()
}

pub(super) fn is_terminator_api(name: &str) -> bool {
    matches!(
        normalize_api_name(name).as_str(),
        "exitprocess"
            | "rtlexituserprocess"
            | "terminateprocess"
            | "ntterminateprocess"
            | "zwterminateprocess"
            | "exitthread"
            | "rtlexituserthread"
            | "ntterminatethread"
            | "zwterminatethread"
            | "terminatethread"
            | "exit"
            | "quick_exit"
            | "abort"
    )
}

pub(super) fn register_name(reg: Register) -> &'static str {
    match reg.full_register() {
        Register::RAX => "rax",
        Register::RBX => "rbx",
        Register::RCX => "rcx",
        Register::RDX => "rdx",
        Register::RSI => "rsi",
        Register::RDI => "rdi",
        Register::R8 => "r8",
        Register::R9 => "r9",
        Register::R10 => "r10",
        Register::R11 => "r11",
        Register::R12 => "r12",
        Register::R13 => "r13",
        Register::R14 => "r14",
        Register::R15 => "r15",
        Register::EAX => "eax",
        Register::EBX => "ebx",
        Register::ECX => "ecx",
        Register::EDX => "edx",
        _ => "reg",
    }
}

pub(super) fn hex32(value: u32) -> String {
    format!("0x{:08X}", value)
}

pub(super) fn hex64(value: u64) -> String {
    format!("0x{:016X}", value)
}
