use super::*;

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

pub(super) fn describe_string_address(
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
            units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
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
