use iced_x86::{
    Decoder, DecoderOptions, Formatter, GasFormatter, IntelFormatter, Mnemonic, OpKind, Register,
};

use crate::analysis::symbols::SymbolIndex;
use crate::core::config::Config;
use crate::core::known::describe_known_address;
use crate::formats::pe::{Export, PeFile};

#[derive(Debug, Clone)]
pub struct Instruction {
    pub rva: u32,
    pub va: u64,
    pub file_off: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub mnemonic: String,
    pub operands: String,
    pub iced: iced_x86::Instruction,
    pub comment: String,
    pub is_call: bool,
    pub is_jmp: bool,
    pub is_jcc: bool,
    pub call_target: u64,
}

pub fn is_ret(m: Mnemonic) -> bool {
    matches!(m, Mnemonic::Ret | Mnemonic::Retf)
        || format!("{:?}", m).to_lowercase().starts_with("ret")
}

pub fn is_jmp(m: Mnemonic) -> bool {
    m == Mnemonic::Jmp
}

pub fn is_jcc(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jrcxz
            | Mnemonic::Loop
            | Mnemonic::Loope
            | Mnemonic::Loopne
    )
}

pub fn is_sys(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Syscall
            | Mnemonic::Sysenter
            | Mnemonic::Sysexit
            | Mnemonic::Int
            | Mnemonic::Iretq
            | Mnemonic::Iretd
            | Mnemonic::Iret
    )
}

struct SymResolver {
    symbols: SymbolIndex,
}

impl iced_x86::SymbolResolver for SymResolver {
    fn symbol(
        &mut self,
        _instruction: &iced_x86::Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<iced_x86::SymbolResult<'_>> {
        self.symbols
            .exact_name(address)
            .map(|name| iced_x86::SymbolResult::with_str(address, name))
    }
}

fn resolve_call_target(instr: &iced_x86::Instruction) -> u64 {
    if instr.op_count() == 0 {
        return 0;
    }
    match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            instr.near_branch_target()
        }
        OpKind::Immediate64 => instr.immediate64(),
        OpKind::Immediate32 => instr.immediate32() as u64,
        _ => 0,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn disassemble_at(
    raw: &[u8],
    file_off: usize,
    start_rva: u32,
    arch: u32,
    image_base: u64,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    cfg: &Config,
) -> Result<Vec<Instruction>, String> {
    if file_off >= raw.len() {
        return Err(format!(
            "file offset 0x{:X} out of bounds (file size {})",
            file_off,
            raw.len()
        ));
    }

    let mut chunk = &raw[file_off..];
    if cfg.max_bytes > 0 && chunk.len() > cfg.max_bytes {
        chunk = &chunk[..cfg.max_bytes];
    }

    let symbol_index = symbols
        .cloned()
        .unwrap_or_else(|| SymbolIndex::from_exports_and_pdb(exports, &[], image_base));
    let ip = image_base + start_rva as u64;

    let mut intel_fmt = IntelFormatter::with_options(
        Some(Box::new(SymResolver {
            symbols: symbol_index.clone(),
        })),
        None,
    );
    let mut gas_fmt = GasFormatter::with_options(
        Some(Box::new(SymResolver {
            symbols: symbol_index.clone(),
        })),
        None,
    );

    let mut decoder = Decoder::with_ip(arch, chunk, ip, DecoderOptions::NONE);
    let mut iced = iced_x86::Instruction::default();

    let est_insns = if cfg.max_insns > 0 {
        cfg.max_insns
    } else {
        (chunk.len() / 4).max(16)
    };
    let mut insns: Vec<Instruction> = Vec::with_capacity(est_insns);
    let mut current_rva = start_rva;
    let mut pos = 0usize;
    let mut last_ret_idx: Option<usize> = None;
    let mut padding_after_ret = 0usize;

    while pos < chunk.len() {
        if cfg.max_insns > 0 && insns.len() >= cfg.max_insns {
            break;
        }

        decoder.set_position(pos).ok();
        decoder.set_ip(ip + pos as u64);

        if !decoder.can_decode() {
            break;
        }
        decoder.decode_out(&mut iced);

        let i_len = iced.len();
        let i_bytes: Vec<u8> = chunk[pos..pos + i_len.min(chunk.len() - pos)].to_vec();
        let pc = ip + pos as u64;
        let m = iced.mnemonic();

        let mut text = String::new();
        if cfg.intel_syntax {
            intel_fmt.format(&iced, &mut text);
        } else {
            gas_fmt.format(&iced, &mut text);
        }

        let (mnem, ops) = if let Some(sp) = text.find(' ') {
            (text[..sp].to_uppercase(), text[sp + 1..].trim().to_owned())
        } else {
            (text.to_uppercase(), String::new())
        };

        let mut comment_parts: Vec<String> = Vec::new();
        let call_target = if m == Mnemonic::Call || is_jmp(m) || is_jcc(m) {
            let tgt = resolve_call_target(&iced);
            if tgt != 0 {
                if let Some(desc) = symbol_index.describe(tgt) {
                    comment_parts.push(desc);
                } else {
                    let t_rva = tgt.wrapping_sub(image_base) as u32;
                    comment_parts.push(format!("→ RVA 0x{:08X}", t_rva));
                }
            }
            tgt
        } else {
            0
        };

        for addr in collect_data_refs(&iced) {
            if let Some(desc) = describe_known_address(addr).or_else(|| {
                (addr >= image_base)
                    .then(|| symbol_index.describe(addr))
                    .flatten()
            }) {
                if !comment_parts.iter().any(|p| p == &desc) {
                    comment_parts.push(desc);
                }
            }
        }

        let comment = comment_parts.join(" | ");
        let is_int3 = i_bytes.len() == 1 && i_bytes[0] == 0xCC;
        let is_all_pad = i_bytes.iter().all(|&b| b == 0xCC || b == 0x90 || b == 0x00);

        let insn = Instruction {
            rva: current_rva,
            va: pc,
            file_off: (file_off + pos) as u64,
            bytes: i_bytes,
            text,
            mnemonic: mnem,
            operands: ops,
            iced,
            comment,
            is_call: m == Mnemonic::Call,
            is_jmp: is_jmp(m),
            is_jcc: is_jcc(m),
            call_target,
        };

        insns.push(insn);

        if is_ret(m) {
            last_ret_idx = Some(insns.len() - 1);
            padding_after_ret = 0;
        } else if let Some(ret_idx) = last_ret_idx {
            if is_all_pad || m == Mnemonic::Nop || is_int3 {
                padding_after_ret += i_len;
                if padding_after_ret >= 3 {
                    insns.truncate(ret_idx + 1);
                    break;
                }
            } else {
                last_ret_idx = None;
                padding_after_ret = 0;
            }
        }

        if last_ret_idx.is_none() && is_int3 {
            break;
        }

        pos += i_len;
        current_rva += i_len as u32;
    }

    Ok(insns)
}

pub fn find_string_refs(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    insns: &[Instruction],
) -> Vec<String> {
    use iced_x86::Mnemonic;
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for insn in insns {
        let m = insn.iced.mnemonic();
        if !matches!(
            m,
            Mnemonic::Mov | Mnemonic::Lea | Mnemonic::Push | Mnemonic::Cmp
        ) {
            continue;
        }
        for op_idx in 0..insn.iced.op_count() {
            let va: u64 = match insn.iced.op_kind(op_idx) {
                OpKind::Memory
                    if insn.iced.memory_base() == Register::None
                        && insn.iced.memory_index() == Register::None =>
                {
                    insn.iced.memory_displacement64()
                }
                OpKind::Immediate64 => insn.iced.immediate64(),
                OpKind::Immediate32 => insn.iced.immediate32() as u64,
                _ => 0,
            };
            if va == 0 || seen.contains(&va) || va < pe.image_base {
                continue;
            }
            let rva = (va - pe.image_base) as u32;
            if let Some(off) = pe.rva_to_offset(rva) {
                let s = crate::formats::pe::read_cstr(raw, off);
                if s.len() >= 4 && is_printable_ascii(&s) {
                    seen.insert(va);
                    let display = if s.len() > 128 {
                        format!("{}…", &s[..128])
                    } else {
                        s
                    };
                    results.push(format!("0x{:08X} → \"{}\"", rva, display));
                }
            }
        }
    }
    results
}

fn is_printable_ascii(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| (0x20..=0x7E).contains(&b))
}

pub fn find_xrefs(insns: &[Instruction], exports: &[Export], image_base: u64) -> Vec<String> {
    let mut seen = std::collections::HashSet::new();
    let mut results = Vec::new();
    for insn in insns {
        if !insn.is_call && !insn.is_jmp {
            continue;
        }
        if insn.call_target == 0 || seen.contains(&insn.call_target) {
            continue;
        }
        seen.insert(insn.call_target);
        let rva = insn.call_target.wrapping_sub(image_base) as u32;
        if let Some(name) = exports
            .iter()
            .find(|e| !e.name.is_empty() && image_base + e.rva as u64 == insn.call_target)
            .map(|e| e.name.as_str())
        {
            results.push(format!("RVA 0x{:08X} → {}", rva, name));
        } else {
            results.push(format!("RVA 0x{:08X}", rva));
        }
    }
    results
}

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
}

/// Walk `insns` and resolve every CALL/JMP to its target name.
/// Handles direct calls (using the symbol index) and indirect IAT calls
/// (using `resolve_iat_slot`).
pub fn collect_api_calls(
    insns: &[Instruction],
    pe: &PeFile,
    raw: &[u8],
    symbol_index: &SymbolIndex,
    image_base: u64,
) -> Vec<ApiCall> {
    let mut results = Vec::new();

    for insn in insns {
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
            });
        } else if insn.iced.op_count() > 0 && insn.iced.op0_kind() == OpKind::Memory {
            // Indirect call/jmp — most commonly `call [rip+rel32]` through the IAT.
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
                    results.push(ApiCall {
                        rva: insn.rva,
                        kind,
                        target_rva: 0,
                        label: func,
                        dll,
                        is_import: true,
                        is_indirect: true,
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
            results.push(ApiCall {
                rva: insn.rva,
                kind,
                target_rva: 0,
                label,
                dll: String::new(),
                is_import: false,
                is_indirect: true,
            });
        }
        // else: call_target==0 and not a memory operand (e.g. `call rax`) — skip
    }

    results
}

fn collect_data_refs(instr: &iced_x86::Instruction) -> Vec<u64> {
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
