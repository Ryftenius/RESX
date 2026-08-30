use iced_x86::{
    Decoder, DecoderOptions, Formatter, GasFormatter, IntelFormatter, Mnemonic, OpKind, Register,
};

use crate::analysis::symbols::SymbolIndex;
use crate::core::config::Config;
use crate::core::known::describe_known_address;
use crate::formats::pe::{attribute_to_func, Export, PeFile};

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
    pe: &crate::formats::pe::PeFile,
    file_off: usize,
    start_rva: u32,
    arch: u32,
    image_base: u64,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    cfg: &Config,
) -> Result<Vec<Instruction>, String> {
    disassemble_at_inner(
        raw, pe, file_off, start_rva, arch, image_base, exports, symbols, cfg, true,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn disassemble_at_unbounded(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    file_off: usize,
    start_rva: u32,
    arch: u32,
    image_base: u64,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    cfg: &Config,
) -> Result<Vec<Instruction>, String> {
    disassemble_at_inner(
        raw, pe, file_off, start_rva, arch, image_base, exports, symbols, cfg, false,
    )
}

#[allow(clippy::too_many_arguments)]
fn disassemble_at_inner(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    file_off: usize,
    start_rva: u32,
    arch: u32,
    image_base: u64,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    cfg: &Config,
    honor_runtime_bounds: bool,
) -> Result<Vec<Instruction>, String> {
    if file_off >= raw.len() {
        return Err(format!(
            "file offset 0x{:X} out of bounds (file size {})",
            file_off,
            raw.len()
        ));
    }

    let runtime_function = honor_runtime_bounds
        .then(|| crate::formats::pe::read_runtime_function(pe, raw, start_rva))
        .flatten();
    let runtime_size = if honor_runtime_bounds {
        runtime_function
            .as_ref()
            .and_then(|func| func.end_rva.checked_sub(start_rva))
            .map(|size| size as usize)
            .filter(|&size| size > 0)
    } else {
        None
    };

    let section_limit = pe
        .rva_to_section(start_rva)
        .and_then(|section| {
            section
                .virtual_address
                .saturating_add(section.virtual_size.max(section.raw_size))
                .checked_sub(start_rva)
        })
        .map(|size| size as usize)
        .unwrap_or_else(|| raw.len().saturating_sub(file_off));

    let decode_len = runtime_size
        .unwrap_or(section_limit)
        .min(section_limit)
        .min(raw.len().saturating_sub(file_off));
    let mut chunk = &raw[file_off..file_off + decode_len];
    if runtime_size.is_none() && cfg.max_bytes > 0 && chunk.len() > cfg.max_bytes {
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
        if runtime_size.is_none() && cfg.max_insns > 0 && insns.len() >= cfg.max_insns {
            break;
        }

        decoder.set_position(pos).ok();
        decoder.set_ip(ip + pos as u64);

        if !decoder.can_decode() {
            break;
        }
        decoder.decode_out(&mut iced);

        let i_len = iced.len();
        if i_len == 0 {
            break;
        }
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
            if let Some(desc) = describe_known_address(addr)
                .or_else(|| describe_string_address(raw, pe, image_base, addr))
                .or_else(|| {
                    (addr >= image_base)
                        .then(|| symbol_index.describe(addr))
                        .flatten()
                })
            {
                if !comment_parts.iter().any(|p| p == &desc) {
                    comment_parts.push(desc);
                }
            }
        }

        if let Some(seg_desc) = describe_segment_access(&iced) {
            if !comment_parts.iter().any(|p| p == &seg_desc) {
                comment_parts.push(seg_desc);
            }
        }
        for literal_desc in describe_immediate_literals(&iced) {
            if !comment_parts.iter().any(|p| p == &literal_desc) {
                comment_parts.push(literal_desc);
            }
        }

        if cfg.hostile {
            if let Some(note) = suspicious_flow_note(&iced) {
                if !comment_parts.iter().any(|p| p == &note) {
                    comment_parts.push(note);
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

        if runtime_size.is_none() && is_ret(m) {
            last_ret_idx = Some(insns.len() - 1);
            padding_after_ret = 0;
        } else if runtime_size.is_none() {
            if let Some(ret_idx) = last_ret_idx {
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
        }

        if runtime_size.is_none() && last_ret_idx.is_none() && is_int3 {
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
    let mut seen_addrs = std::collections::HashSet::new();
    let mut seen_slices = std::collections::HashSet::new();
    let mut reg_ptrs: std::collections::HashMap<Register, u64> = std::collections::HashMap::new();
    let mut reg_lens: std::collections::HashMap<Register, u64> = std::collections::HashMap::new();

    for insn in insns {
        let m = insn.iced.mnemonic();
        track_string_registers(&mut reg_ptrs, &mut reg_lens, &insn.iced);

        if !matches!(
            m,
            Mnemonic::Mov | Mnemonic::Lea | Mnemonic::Push | Mnemonic::Cmp
        ) {
            if m == Mnemonic::Call {
                for (addr_reg, len_reg) in [
                    (Register::RCX, Register::RDX),
                    (Register::R8, Register::R9),
                    (Register::ECX, Register::EDX),
                ] {
                    let Some(&addr) = reg_ptrs.get(&addr_reg) else {
                        continue;
                    };
                    let Some(&len) = reg_lens.get(&len_reg) else {
                        continue;
                    };
                    if len == 0 || len > 0x1000 {
                        continue;
                    }
                    if let Some((rva, rendered)) =
                        describe_string_slice_address(raw, pe, pe.image_base, addr, len as usize)
                    {
                        if seen_slices.insert((rva, len as u32)) {
                            results.push(format!("0x{:08X} len 0x{:X} → {}", rva, len, rendered));
                        }
                    }
                }
            }
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
            if va == 0 || seen_addrs.contains(&va) || va < pe.image_base {
                continue;
            }
            let rva = (va - pe.image_base) as u32;
            if let Some(off) = pe.rva_to_offset(rva) {
                let ascii = crate::formats::pe::read_cstr(raw, off);
                if ascii.len() >= 4 && is_printable_ascii(&ascii) {
                    seen_addrs.insert(va);
                    let display = if ascii.len() > 128 {
                        format!("{}…", &ascii[..128])
                    } else {
                        ascii
                    };
                    results.push(format!("0x{:08X} → \"{}\"", rva, display));
                    continue;
                }

                if let Some(wide) = read_utf16_cstr(raw, off) {
                    if wide.len() >= 4 && is_printable_text(&wide) {
                        seen_addrs.insert(va);
                        let display = if wide.len() > 128 {
                            format!("{}…", wide.chars().take(128).collect::<String>())
                        } else {
                            wide
                        };
                        results.push(format!("0x{:08X} → L\"{}\"", rva, display));
                    }
                }
            }
        }
    }
    results
}

fn track_string_registers(
    reg_ptrs: &mut std::collections::HashMap<Register, u64>,
    reg_lens: &mut std::collections::HashMap<Register, u64>,
    instr: &iced_x86::Instruction,
) {
    let mnemonic = instr.mnemonic();
    if mnemonic == Mnemonic::Lea && instr.op0_kind() == OpKind::Register {
        let dest = instr.op0_register().full_register();
        if let Some(addr) = memory_operand_address(instr) {
            reg_ptrs.insert(dest, addr);
            reg_lens.remove(&dest);
            return;
        }
    }

    if mnemonic == Mnemonic::Mov && instr.op0_kind() == OpKind::Register {
        let dest = instr.op0_register().full_register();
        match instr.op1_kind() {
            OpKind::Immediate8 => {
                reg_lens.insert(dest, instr.immediate8() as u64);
                reg_ptrs.remove(&dest);
            }
            OpKind::Immediate16 => {
                reg_lens.insert(dest, instr.immediate16() as u64);
                reg_ptrs.remove(&dest);
            }
            OpKind::Immediate32 | OpKind::Immediate32to64 => {
                let value = instr.immediate32() as u64;
                reg_lens.insert(dest, value);
                reg_ptrs.remove(&dest);
            }
            OpKind::Immediate64 => {
                let value = instr.immediate64();
                reg_lens.insert(dest, value);
                reg_ptrs.remove(&dest);
            }
            OpKind::Memory => {
                if let Some(addr) = memory_operand_address(instr) {
                    reg_ptrs.insert(dest, addr);
                    reg_lens.remove(&dest);
                } else {
                    reg_ptrs.remove(&dest);
                    reg_lens.remove(&dest);
                }
            }
            OpKind::Register => {
                let src = instr.op1_register().full_register();
                if let Some(value) = reg_ptrs.get(&src).copied() {
                    reg_ptrs.insert(dest, value);
                } else {
                    reg_ptrs.remove(&dest);
                }
                if let Some(value) = reg_lens.get(&src).copied() {
                    reg_lens.insert(dest, value);
                } else {
                    reg_lens.remove(&dest);
                }
            }
            _ => {
                reg_ptrs.remove(&dest);
                reg_lens.remove(&dest);
            }
        }
        return;
    }

    if mnemonic == Mnemonic::Xor
        && instr.op0_kind() == OpKind::Register
        && instr.op1_kind() == OpKind::Register
        && instr.op0_register().full_register() == instr.op1_register().full_register()
    {
        let dest = instr.op0_register().full_register();
        reg_lens.insert(dest, 0);
        reg_ptrs.remove(&dest);
    }
}

fn memory_operand_address(instr: &iced_x86::Instruction) -> Option<u64> {
    if matches!(instr.memory_base(), Register::RIP | Register::EIP) {
        return Some(instr.ip_rel_memory_address());
    }
    if instr.memory_base() == Register::None && instr.memory_index() == Register::None {
        let disp = instr.memory_displacement64();
        if disp != 0 {
            return Some(disp);
        }
    }
    None
}

fn is_printable_ascii(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| (0x20..=0x7E).contains(&b) || matches!(b, b'\r' | b'\n' | b'\t'))
}

fn is_printable_text(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|ch| !ch.is_control() || matches!(ch, '\r' | '\n' | '\t'))
}

fn is_plausible_literal_text(s: &str) -> bool {
    if !is_printable_text(s) || s.len() < 4 || !s.is_ascii() {
        return false;
    }

    let mut sensible = 0usize;
    let mut alpha = 0usize;
    let mut total = 0usize;
    for ch in s.chars() {
        total += 1;
        if ch.is_ascii_alphanumeric()
            || ch.is_ascii_punctuation()
            || ch == ' '
            || ch == '\t'
            || ch == '\r'
            || ch == '\n'
        {
            sensible += 1;
        }
        if ch.is_ascii_alphabetic() {
            alpha += 1;
        }
    }

    sensible * 100 / total >= 85 && alpha >= 3
}

fn describe_string_address(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    image_base: u64,
    addr: u64,
) -> Option<String> {
    if addr < image_base {
        return None;
    }
    let rva = (addr - image_base) as u32;
    let off = pe.rva_to_offset(rva)?;

    let ascii = crate::formats::pe::read_cstr(raw, off);
    if ascii.len() >= 4 && is_printable_ascii(&ascii) {
        let display = if ascii.len() > 96 {
            format!("{}…", &ascii[..96])
        } else {
            ascii
        };
        return Some(format!("\"{}\"", display));
    }

    let wide = read_utf16_cstr(raw, off)?;
    if wide.len() >= 4 && is_plausible_literal_text(&wide) {
        let display = if wide.len() > 96 {
            format!("{}…", wide.chars().take(96).collect::<String>())
        } else {
            wide
        };
        return Some(format!("L\"{}\"", display));
    }

    None
}

fn describe_string_slice_address(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    image_base: u64,
    addr: u64,
    len: usize,
) -> Option<(u32, String)> {
    if addr < image_base || len < 2 {
        return None;
    }
    let rva = (addr - image_base) as u32;
    let off = pe.rva_to_offset(rva)?;
    let end = off.checked_add(len)?;
    if end > raw.len() {
        return None;
    }

    let slice = &raw[off..end];
    if let Ok(text) = std::str::from_utf8(slice) {
        if is_plausible_literal_text(text) {
            let display = if text.len() > 96 {
                format!("{}…", &text[..96])
            } else {
                text.to_owned()
            };
            return Some((rva, format!("\"{}\"", display)));
        }
    }

    if len.is_multiple_of(2) {
        let mut units = Vec::with_capacity(len / 2);
        for chunk in slice.as_chunks::<2>().0 {
            units.push(u16::from_le_bytes(*chunk));
        }
        if let Ok(text) = String::from_utf16(&units) {
            if is_printable_text(&text) && text.chars().any(|ch| ch.is_alphabetic()) {
                let display = if text.chars().count() > 96 {
                    format!("{}…", text.chars().take(96).collect::<String>())
                } else {
                    text
                };
                return Some((rva, format!("L\"{}\"", display)));
            }
        }
    }

    None
}

fn read_utf16_cstr(raw: &[u8], off: usize) -> Option<String> {
    if off + 2 > raw.len() {
        return None;
    }

    let mut units = Vec::new();
    let mut pos = off;
    while pos + 1 < raw.len() {
        let unit = u16::from_le_bytes([raw[pos], raw[pos + 1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
        pos += 2;
        if units.len() >= 256 {
            break;
        }
    }

    if units.len() < 2 {
        return None;
    }
    String::from_utf16(&units).ok()
}

pub fn find_xrefs(
    raw: &[u8],
    pe: &PeFile,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    target_rva: u32,
    target_name: &str,
) -> Vec<String> {
    let mut results = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let image_base = pe.image_base;

    for section in &pe.sections {
        if section.characteristics & 0x2000_0000 == 0 {
            continue;
        }
        if section.raw_offset == 0 || section.raw_size == 0 {
            continue;
        }

        let start = section.raw_offset as usize;
        let end = (start + section.raw_size as usize).min(raw.len());
        let bytes = &raw[start..end];
        let mut decoder = Decoder::with_ip(
            pe.arch,
            bytes,
            image_base + section.virtual_address as u64,
            DecoderOptions::NONE,
        );
        let mut iced = iced_x86::Instruction::default();
        let mut insns: Vec<Instruction> = Vec::new();
        let mut pos = 0usize;

        while pos < bytes.len() {
            decoder.set_position(pos).ok();
            decoder.set_ip(image_base + section.virtual_address as u64 + pos as u64);
            if !decoder.can_decode() {
                break;
            }
            decoder.decode_out(&mut iced);
            let len = iced.len();
            if len == 0 || pos + len > bytes.len() {
                break;
            }
            let site_rva = section.virtual_address + pos as u32;
            let pc = image_base + site_rva as u64;
            insns.push(Instruction {
                rva: site_rva,
                va: pc,
                file_off: (start + pos) as u64,
                bytes: bytes[pos..pos + len].to_vec(),
                text: String::new(),
                mnemonic: String::new(),
                operands: String::new(),
                iced,
                comment: String::new(),
                is_call: iced.mnemonic() == Mnemonic::Call,
                is_jmp: is_jmp(iced.mnemonic()),
                is_jcc: is_jcc(iced.mnemonic()),
                call_target: if iced.mnemonic() == Mnemonic::Call
                    || is_jmp(iced.mnemonic())
                    || is_jcc(iced.mnemonic())
                {
                    resolve_call_target(&iced)
                } else {
                    0
                },
            });
            pos += len;
        }

        for (idx, insn) in insns.iter().enumerate() {
            let site_rva = insn.rva;
            let owner = attribute_to_func(site_rva, exports)
                .map(|e| e.name.clone())
                .or_else(|| {
                    symbols.and_then(|si| {
                        si.lookup(pe.image_base + site_rva as u64).map(|m| {
                            if m.displacement == 0 {
                                m.symbol.name.clone()
                            } else {
                                format!("{}+0x{:X}", m.symbol.name, m.displacement)
                            }
                        })
                    })
                })
                .unwrap_or_else(|| format!("sub_{:08X}", site_rva));

            if insn.call_target != 0 {
                let dest_rva = insn.call_target.wrapping_sub(image_base) as u32;
                if dest_rva == target_rva {
                    let kind = if insn.is_call { "CALL" } else { "JMP" };
                    let line = format!(
                        "{} {} [site 0x{:08X}] -> {} [target 0x{:08X}]",
                        kind, owner, site_rva, target_name, target_rva
                    );
                    if seen.insert(line.clone()) {
                        results.push(line);
                    }
                }
                continue;
            }

            if insn.iced.op_count() > 0 && insn.iced.op0_kind() == OpKind::Memory {
                if let Some(symbol_index) = symbols {
                    if is_guard_dispatch_call(insn, symbol_index) {
                        if let Some(src) =
                            track_wdf_table_register(&insns, idx, Register::RAX, symbols, pe)
                                .or_else(|| {
                                    track_indirect_register(
                                        &insns,
                                        idx,
                                        Register::RAX,
                                        image_base,
                                        pe,
                                        raw,
                                        Some(symbol_index),
                                    )
                                })
                        {
                            if src.dll.eq_ignore_ascii_case("WDF")
                                && src.label.eq_ignore_ascii_case(target_name)
                            {
                                let kind = if insn.is_call { "CALL" } else { "JMP" };
                                let line = format!(
                                    "{} {} [site 0x{:08X}] -> {}!{} via {}",
                                    kind, owner, site_rva, src.dll, src.label, src.method
                                );
                                if seen.insert(line.clone()) {
                                    results.push(line);
                                }
                            }
                        }
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
                if slot_va >= image_base {
                    let slot_rva = (slot_va - image_base) as u32;
                    if slot_rva == target_rva {
                        let kind = if insn.is_call { "CALL" } else { "JMP" };
                        let line = if let Some((dll_name, func_name)) =
                            crate::formats::pe::resolve_iat_slot(pe, raw, slot_rva)
                        {
                            format!(
                                "{} {} [site 0x{:08X}] -> {}!{} [IAT 0x{:08X}]",
                                kind, owner, site_rva, dll_name, func_name, slot_rva
                            )
                        } else {
                            format!(
                                "{} {} [site 0x{:08X}] -> {} [IAT 0x{:08X}]",
                                kind, owner, site_rva, target_name, slot_rva
                            )
                        };
                        if seen.insert(line.clone()) {
                            results.push(line);
                        }
                    }
                }
                continue;
            }

            if insn.iced.op_count() > 0 && insn.iced.op0_kind() == OpKind::Register {
                let reg = insn.iced.op0_register();
                if let Some(src) =
                    track_wdf_table_register(&insns, idx, reg, symbols, pe).or_else(|| {
                        track_indirect_register(&insns, idx, reg, image_base, pe, raw, symbols)
                    })
                {
                    let matches_target = (src.iat_slot_rva != 0 && src.iat_slot_rva == target_rva)
                        || (src.dll.eq_ignore_ascii_case("WDF")
                            && src.label.eq_ignore_ascii_case(target_name));
                    if matches_target {
                        let kind = if insn.is_call { "CALL" } else { "JMP" };
                        let line = if src.dll.eq_ignore_ascii_case("WDF") {
                            format!(
                                "{} {} [site 0x{:08X}] -> {}!{} via {}",
                                kind, owner, site_rva, src.dll, src.label, src.method
                            )
                        } else {
                            format!(
                                "{} {} [site 0x{:08X}] -> {}!{} [IAT 0x{:08X}] via {}",
                                kind,
                                owner,
                                site_rva,
                                src.dll,
                                src.label,
                                src.iat_slot_rva,
                                src.method
                            )
                        };
                        if seen.insert(line.clone()) {
                            results.push(line);
                        }
                    }
                }
            }
        }
    }
    results.sort();
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
struct RegSource {
    label: String,
    dll: String,
    is_import: bool,
    /// Human-readable description of how the register was loaded.
    method: String,
    target_rva: u32,
    iat_slot_rva: u32,
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

fn track_indirect_register(
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

fn track_wdf_table_register(
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
fn suspicious_flow_note(instr: &iced_x86::Instruction) -> Option<String> {
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

fn is_guard_dispatch_call(insn: &Instruction, symbol_index: &SymbolIndex) -> bool {
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

fn describe_segment_access(instr: &iced_x86::Instruction) -> Option<String> {
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

fn describe_immediate_literals(instr: &iced_x86::Instruction) -> Vec<String> {
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
    match value as u32 {
        0x00000000 => Some("STATUS_SUCCESS"),
        0x00000001 => Some("STATUS_WAIT_1"),
        0x00000103 => Some("STATUS_PENDING"),
        0x00000104 => Some("STATUS_REPARSE"),
        0x40000005 => Some("STATUS_SEGMENT_NOTIFICATION"),
        0x80000005 => Some("STATUS_BUFFER_OVERFLOW"),
        0x80000006 => Some("STATUS_NO_MORE_FILES"),
        0x8000000D => Some("STATUS_PARTIAL_COPY"),
        0xC0000005 => Some("STATUS_ACCESS_VIOLATION"),
        0xC0000008 => Some("STATUS_INVALID_HANDLE"),
        0xC000000D => Some("STATUS_INVALID_PARAMETER"),
        0xC0000017 => Some("STATUS_NO_MEMORY"),
        0xC0000018 => Some("STATUS_CONFLICTING_ADDRESSES"),
        0xC0000022 => Some("STATUS_ACCESS_DENIED"),
        0xC0000023 => Some("STATUS_BUFFER_TOO_SMALL"),
        0xC0000034 => Some("STATUS_OBJECT_NAME_NOT_FOUND"),
        0xC0000035 => Some("STATUS_OBJECT_NAME_COLLISION"),
        0xC000003A => Some("STATUS_OBJECT_PATH_NOT_FOUND"),
        0xC0000043 => Some("STATUS_SHARING_VIOLATION"),
        0xC0000054 => Some("STATUS_FILE_LOCK_CONFLICT"),
        0xC000007A => Some("STATUS_PROCEDURE_NOT_FOUND"),
        0xC000009A => Some("STATUS_INSUFFICIENT_RESOURCES"),
        0xC00000BB => Some("STATUS_NOT_SUPPORTED"),
        0xC0000135 => Some("STATUS_DLL_NOT_FOUND"),
        0xC0000139 => Some("STATUS_ENTRYPOINT_NOT_FOUND"),
        0xC0000142 => Some("STATUS_DLL_INIT_FAILED"),
        0xC0000225 => Some("STATUS_NOT_FOUND"),
        _ => None,
    }
}
