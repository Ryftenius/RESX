use super::api::{is_guard_dispatch_call, track_indirect_register, track_wdf_table_register};
use super::*;
use crate::formats::pe::attribute_to_func;

pub fn find_xrefs(
    raw: &[u8],
    pe: &PeFile,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    target_rva: u32,
    target_name: &str,
) -> Vec<String> {
    let mut results = Vec::new();
    if !matches!(pe.machine, 0x14c | 0x8664) {
        return results;
    }
    let mut budget = 65_536usize;
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
        let Some(bytes) = pe.rva_bytes(raw, section.virtual_address) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(
            pe.arch,
            bytes,
            image_base + section.virtual_address as u64,
            DecoderOptions::NONE,
        );
        let mut iced = iced_x86::Instruction::default();
        let mut insns: Vec<Instruction> = Vec::new();
        let mut pos = 0usize;

        while pos < bytes.len() && budget != 0 {
            budget -= 1;
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
                block_start: section.virtual_address,
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
            if results.len() >= 4096 {
                results.push("Analysis incomplete: cross-reference result budget reached".into());
                return results;
            }
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

            if !insn.is_call && !insn.is_jmp && !insn.is_jcc {
                if insn.iced.is_ip_rel_memory_operand()
                    && pe.va_to_rva(insn.iced.ip_rel_memory_address()) == Some(target_rva)
                {
                    let kind = if insn.iced.mnemonic() == Mnemonic::Lea {
                        "ADDRESS"
                    } else {
                        "MEMORY"
                    };
                    let line = format!("{kind} {owner} [site 0x{site_rva:08X}] -> {target_name} [target 0x{target_rva:08X}]");
                    if seen.insert(line.clone()) {
                        results.push(line);
                    }
                }
                continue;
            }

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
    if budget == 0 {
        results.push("Analysis incomplete: cross-reference instruction budget reached".into());
    }
    results.sort();
    results
}
