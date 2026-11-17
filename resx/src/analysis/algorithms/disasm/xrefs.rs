use super::api::{is_guard_dispatch_call, track_indirect_register, track_wdf_table_register};
use super::*;
use crate::formats::pe::ExportOwnerIndex;

/// Instructions decoded per chunk of the linear sweep.
const XREF_CHUNK_INSNS: usize = 32_768;
/// Earlier instructions kept from the previous chunk; register tracking looks back
/// at most 96 instructions.
const XREF_CARRY_INSNS: usize = 256;
/// Hard ceiling on decoded instructions for hostile images with huge code sections.
const XREF_MAX_INSNS: usize = 64 * 1024 * 1024;

pub fn find_xrefs(
    raw: &[u8],
    pe: &PeFile,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    target_rva: u32,
    target_name: &str,
    overlap_seams: bool,
) -> Vec<String> {
    let image = crate::analysis::image::ImageFacts::new(pe, raw);
    let mut results = Vec::new();
    if !matches!(pe.machine, 0x14c | 0x8664) {
        return results;
    }
    // Every instruction is at least one byte, so the executable bytes bound the sweep.
    let code_bytes: usize = pe
        .sections
        .iter()
        .filter(|s| s.characteristics & 0x2000_0000 != 0)
        .map(|s| s.raw_size as usize)
        .sum();
    let mut budget = code_bytes.min(XREF_MAX_INSNS);
    let mut seen = std::collections::HashSet::new();
    let image_base = pe.image_base;
    let dispatch_slot = super::api::guard_dispatch_slot(pe, raw);
    let scan = XrefScan {
        raw,
        pe,
        exports,
        symbols,
        image: &image,
        image_base,
        dispatch_slot,
        target_rva,
        target_name,
        owner_index: ExportOwnerIndex::new(exports),
    };

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
        let mut insns: Vec<Instruction> = Vec::with_capacity(XREF_CHUNK_INSNS + XREF_CARRY_INSNS);
        let mut pos = 0usize;

        while pos < bytes.len() && budget != 0 {
            let carried = insns.len();
            let mut section_done = false;
            while insns.len() - carried < XREF_CHUNK_INSNS && budget != 0 {
                if pos >= bytes.len() {
                    section_done = true;
                    break;
                }
                budget -= 1;
                decoder.set_position(pos).ok();
                decoder.set_ip(image_base + section.virtual_address as u64 + pos as u64);
                if !decoder.can_decode() {
                    section_done = true;
                    break;
                }
                decoder.decode_out(&mut iced);
                let len = iced.len();
                if len == 0 || pos + len > bytes.len() {
                    section_done = true;
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

            for idx in carried..insns.len() {
                if results.len() >= 4096 {
                    results
                        .push("Analysis incomplete: cross-reference result budget reached".into());
                    return results;
                }
                scan.instruction(&insns, idx, &mut results, &mut seen);
            }
            let keep_from = insns.len().saturating_sub(XREF_CARRY_INSNS);
            insns.drain(..keep_from);
            if section_done {
                break;
            }
        }
    }
    if overlap_seams {
        let seams = crate::analysis::overlap_scan::scan_seam_calls(raw, pe);
        for call in seams.calls {
            let matching = match call.target {
                crate::analysis::overlap_scan::SeamTarget::Direct(rva)
                | crate::analysis::overlap_scan::SeamTarget::ImportSlot(rva) => rva == target_rva,
            };
            if !matching {
                continue;
            }
            if results.len() >= 4096 {
                results.push("Analysis incomplete: cross-reference result budget reached".into());
                break;
            }
            let owner = scan
                .owner_index
                .at_or_before(exports, call.site_rva)
                .map(|e| e.name.clone())
                .or_else(|| {
                    symbols.and_then(|si| {
                        si.lookup(pe.image_base + call.site_rva as u64)
                            .map(|m| m.symbol.name.clone())
                    })
                })
                .unwrap_or_else(|| format!("sub_{:08X}", call.site_rva));
            let kind = if call.is_jump { "JMP" } else { "CALL" };
            let line = format!("{kind} {owner} [site 0x{:08X}] -> {target_name} [target 0x{target_rva:08X}] [overlap seam]", call.site_rva);
            if seen.insert(line.clone()) {
                results.push(line);
            }
        }
        if seams.truncated {
            results.push("Analysis incomplete: overlap seam budget reached".into());
        }
    }
    if budget == 0 {
        results.push("Analysis incomplete: cross-reference instruction budget reached".into());
    }
    results.sort();
    results
}

struct XrefScan<'a> {
    raw: &'a [u8],
    pe: &'a PeFile,
    exports: &'a [Export],
    symbols: Option<&'a SymbolIndex>,
    image: &'a crate::analysis::image::ImageFacts<'a>,
    image_base: u64,
    dispatch_slot: u64,
    target_rva: u32,
    target_name: &'a str,
    owner_index: ExportOwnerIndex,
}

impl XrefScan<'_> {
    fn instruction(
        &self,
        insns: &[Instruction],
        idx: usize,
        results: &mut Vec<String>,
        seen: &mut std::collections::HashSet<String>,
    ) {
        let (raw, pe, exports, symbols, image_base, dispatch_slot, target_rva, target_name) = (
            self.raw,
            self.pe,
            self.exports,
            self.symbols,
            self.image_base,
            self.dispatch_slot,
            self.target_rva,
            self.target_name,
        );
        let image = self.image;
        let insn = &insns[idx];
        {
            {
                let site_rva = insn.rva;
                // Most decoded instructions do not reference the requested target.
                // Resolve their owner only when emitting a matching result; a PE
                // can legally contain tens of thousands of export names.
                let owner_name = std::cell::OnceCell::new();
                let owner = || {
                    owner_name.get_or_init(|| {
                        self.owner_index
                            .at_or_before(exports, site_rva)
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
                            .unwrap_or_else(|| format!("sub_{:08X}", site_rva))
                    })
                };

                if !insn.is_call && !insn.is_jmp && !insn.is_jcc {
                    if insn.iced.is_ip_rel_memory_operand()
                        && pe.va_to_rva(insn.iced.ip_rel_memory_address()) == Some(target_rva)
                    {
                        let kind = if insn.iced.mnemonic() == Mnemonic::Lea {
                            "ADDRESS"
                        } else {
                            "MEMORY"
                        };
                        let line = format!("{kind} {} [site 0x{site_rva:08X}] -> {target_name} [target 0x{target_rva:08X}]", owner());
                        if seen.insert(line.clone()) {
                            results.push(line);
                        }
                    }
                    return;
                }

                if insn.call_target != 0 {
                    let dest_rva = insn.call_target.wrapping_sub(image_base) as u32;
                    if dest_rva == target_rva {
                        let kind = if insn.is_call { "CALL" } else { "JMP" };
                        let line = format!(
                            "{} {} [site 0x{:08X}] -> {} [target 0x{:08X}]",
                            kind,
                            owner(),
                            site_rva,
                            target_name,
                            target_rva
                        );
                        if seen.insert(line.clone()) {
                            results.push(line);
                        }
                    }
                    return;
                }

                if insn.iced.op_count() > 0 && insn.iced.op0_kind() == OpKind::Memory {
                    {
                        if is_guard_dispatch_call(insn, symbols, dispatch_slot) {
                            if let Some(src) =
                                track_wdf_table_register(insns, idx, Register::RAX, symbols, pe)
                                    .or_else(|| {
                                        track_indirect_register(
                                            insns,
                                            idx,
                                            Register::RAX,
                                            image_base,
                                            image,
                                            symbols,
                                        )
                                    })
                            {
                                if src.dll.eq_ignore_ascii_case("WDF")
                                    && src.label.eq_ignore_ascii_case(target_name)
                                {
                                    let kind = if insn.is_call { "CALL" } else { "JMP" };
                                    let line = format!(
                                        "{} {} [site 0x{:08X}] -> {}!{} via {}",
                                        kind,
                                        owner(),
                                        site_rva,
                                        src.dll,
                                        src.label,
                                        src.method
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
                                    kind,
                                    owner(),
                                    site_rva,
                                    dll_name,
                                    func_name,
                                    slot_rva
                                )
                            } else {
                                format!(
                                    "{} {} [site 0x{:08X}] -> {} [IAT 0x{:08X}]",
                                    kind,
                                    owner(),
                                    site_rva,
                                    target_name,
                                    slot_rva
                                )
                            };
                            if seen.insert(line.clone()) {
                                results.push(line);
                            }
                        }
                    }
                    return;
                }

                if insn.iced.op_count() > 0 && insn.iced.op0_kind() == OpKind::Register {
                    let reg = insn.iced.op0_register();
                    if let Some(src) = track_wdf_table_register(insns, idx, reg, symbols, pe)
                        .or_else(|| {
                            track_indirect_register(insns, idx, reg, image_base, image, symbols)
                        })
                    {
                        let matches_target = (src.iat_slot_rva != 0
                            && src.iat_slot_rva == target_rva)
                            || (src.dll.eq_ignore_ascii_case("WDF")
                                && src.label.eq_ignore_ascii_case(target_name));
                        if matches_target {
                            let kind = if insn.is_call { "CALL" } else { "JMP" };
                            let line = if src.dll.eq_ignore_ascii_case("WDF") {
                                format!(
                                    "{} {} [site 0x{:08X}] -> {}!{} via {}",
                                    kind,
                                    owner(),
                                    site_rva,
                                    src.dll,
                                    src.label,
                                    src.method
                                )
                            } else {
                                format!(
                                    "{} {} [site 0x{:08X}] -> {}!{} [IAT 0x{:08X}] via {}",
                                    kind,
                                    owner(),
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
    }
}
