use super::*;

pub fn find_startup_routines(pe: &PeFile, raw: &[u8]) -> Vec<PeStartupRoutine> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    if pe.entry_point != 0
        && pe
            .rva_to_section(pe.entry_point)
            .is_some_and(|section| section.is_executable())
        && pe.rva_slice(raw, pe.entry_point, 1).is_some()
        && seen.insert((pe.entry_point, "pe-entry".to_owned()))
    {
        let section_name = pe
            .rva_to_section(pe.entry_point)
            .map(|section| section.name.clone())
            .unwrap_or_default();
        out.push(PeStartupRoutine {
            kind: "PE Entry Point".to_owned(),
            source: "AddressOfEntryPoint".to_owned(),
            rva: pe.entry_point,
            va: pe.image_base.saturating_add(pe.entry_point as u64),
            section_name,
            note: "declared executable entry point; transfer and execution unobserved".to_owned(),
        });
    }

    if let Some(tls) = read_tls_info(pe, raw) {
        for (index, callback) in tls.callbacks.into_iter().enumerate() {
            let section_name = pe
                .rva_to_section(callback.rva)
                .map(|section| section.name.clone())
                .unwrap_or_default();
            out.push(PeStartupRoutine {
                    kind: "TLS Callback".to_owned(),
                    source: ".tls".to_owned(),
                    rva: callback.rva,
                    va: callback.va,
                    section_name,
                    note: format!("declared TLS callback index {index}; table order and repeated entries preserved; invocation unobserved"),
                });
        }
    }

    let ptr_width = if pe.arch == 64 { 8usize } else { 4usize };
    let mut startup_pointer_budget = 65_536usize;
    for section in &pe.sections {
        if !is_xl_like_section(&section.name) || section.raw_size == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(raw.len());
        let mut hits = 0usize;
        let mut off = start;
        while off + ptr_width <= end && hits < 32 && startup_pointer_budget != 0 {
            startup_pointer_budget -= 1;
            let value = if ptr_width == 8 {
                read_u64(raw, off)
            } else {
                read_u32(raw, off) as u64
            };
            off += ptr_width;
            let Some(target_rva) = pe.va_to_rva(value) else {
                continue;
            };
            let Some(target_section) = pe.rva_to_section(target_rva) else {
                continue;
            };
            if !target_section.is_executable() || pe.rva_slice(raw, target_rva, 1).is_none() {
                continue;
            }
            if !seen.insert((target_rva, "xl-pointer".to_owned())) {
                continue;
            }
            hits += 1;
            out.push(PeStartupRoutine {
                kind: "XL Startup".to_owned(),
                source: section.name.clone(),
                rva: target_rva,
                va: value,
                section_name: target_section.name.clone(),
                note: format!(
                    "{} pointer at +0x{:X} targets executable bytes; startup use is unverified",
                    section.name,
                    off.saturating_sub(start + ptr_width)
                ),
            });
        }
    }

    for candidate in find_real_entry_candidates(pe, raw) {
        if seen.insert((candidate.rva, candidate.kind.clone())) {
            out.push(candidate);
        }
    }

    out.sort_by_key(|entry| startup_kind_priority(&entry.kind));
    out
}

#[derive(Clone, Debug)]
struct StartupEdge {
    target_rva: u32,
    via: &'static str,
    note: String,
}

#[derive(Clone, Debug)]
struct PendingCodePtr {
    target_rva: u32,
    source: &'static str,
}

const STARTUP_SCAN_MAX_DEPTH: usize = 1;
const STARTUP_HANDOFF_LIMIT: usize = 8;
const STARTUP_MAIN_CANDIDATE_LIMIT: usize = 4;
const STARTUP_PENDING_PTR_LIMIT: usize = 6;

fn find_real_entry_candidates(pe: &PeFile, raw: &[u8]) -> Vec<PeStartupRoutine> {
    let mut out = Vec::new();
    let mut seen_rvas = BTreeSet::new();
    let mut queue = VecDeque::from([(pe.entry_point, 0usize)]);
    let mut visited = BTreeSet::new();
    let mut handoff_count = 0usize;
    let mut main_count = 0usize;

    while let Some((rva, depth)) = queue.pop_front() {
        if depth > STARTUP_SCAN_MAX_DEPTH || !visited.insert(rva) {
            continue;
        }
        let Some(window) = decode_startup_window(pe, raw, rva, 96, 768) else {
            continue;
        };
        let mut pending_ptrs: Vec<PendingCodePtr> = Vec::new();
        for insn in window {
            if main_count < STARTUP_MAIN_CANDIDATE_LIMIT {
                pending_ptrs.extend(extract_code_pointer_loads(pe, &insn));
                if pending_ptrs.len() > STARTUP_PENDING_PTR_LIMIT {
                    pending_ptrs.drain(
                        0..pending_ptrs
                            .len()
                            .saturating_sub(STARTUP_PENDING_PTR_LIMIT / 2),
                    );
                }
            }

            if depth == 0 && handoff_count < STARTUP_HANDOFF_LIMIT {
                for edge in extract_startup_edges(pe, &insn) {
                    if !is_plausible_startup_target(pe, raw, edge.target_rva) {
                        continue;
                    }
                    if !seen_rvas.insert((edge.target_rva, edge.via)) {
                        continue;
                    }
                    let section_name = pe
                        .rva_to_section(edge.target_rva)
                        .map(|section| section.name.clone())
                        .unwrap_or_default();
                    out.push(PeStartupRoutine {
                        kind: "Startup Handoff".to_owned(),
                        source: format!("{} @ depth {}", edge.via, depth),
                        rva: edge.target_rva,
                        va: pe.image_base + edge.target_rva as u64,
                        section_name,
                        note: edge.note.clone(),
                    });
                    handoff_count += 1;
                    if depth < STARTUP_SCAN_MAX_DEPTH {
                        queue.push_back((edge.target_rva, depth + 1));
                    }
                }
            }

            if main_count < STARTUP_MAIN_CANDIDATE_LIMIT
                && is_call_or_jmp(insn.instr.mnemonic())
                && !pending_ptrs.is_empty()
            {
                for ptr in pending_ptrs.drain(..) {
                    if main_count >= STARTUP_MAIN_CANDIDATE_LIMIT {
                        break;
                    }
                    if !is_plausible_startup_target(pe, raw, ptr.target_rva) {
                        continue;
                    }
                    if seen_rvas.insert((ptr.target_rva, "real-main")) {
                        let section_name = pe
                            .rva_to_section(ptr.target_rva)
                            .map(|section| section.name.clone())
                            .unwrap_or_default();
                        out.push(PeStartupRoutine {
                            kind: "Real Main Candidate".to_owned(),
                            source: format!("{} callback depth {}", ptr.source, depth),
                            rva: ptr.target_rva,
                            va: pe.image_base + ptr.target_rva as u64,
                            section_name,
                            note: "startup code passes this executable address as a callback or main routine".to_owned(),
                        });
                        main_count += 1;
                    }
                }
            }
        }
    }

    out
}

fn startup_kind_priority(kind: &str) -> u8 {
    match kind {
        "PE Entry Point" => 0,
        "TLS Callback" => 1,
        "Real Main Candidate" => 2,
        "Startup Handoff" => 3,
        "Startup Chain" => 4,
        "XL Startup" => 5,
        _ => 6,
    }
}

#[derive(Clone, Debug)]
struct StartupInsn {
    instr: iced_x86::Instruction,
}

fn decode_startup_window(
    pe: &PeFile,
    raw: &[u8],
    start_rva: u32,
    max_insns: usize,
    max_bytes: usize,
) -> Option<Vec<StartupInsn>> {
    if start_rva == 0 || !pe.rva_to_section(start_rva)?.is_executable() {
        return None;
    }
    let backed = pe.rva_bytes(raw, start_rva)?;
    let chunk = &backed[..backed.len().min(max_bytes)];
    let mut decoder = Decoder::with_ip(
        pe.arch,
        chunk,
        pe.image_base.checked_add(start_rva as u64)?,
        DecoderOptions::NONE,
    );
    let mut insn = iced_x86::Instruction::default();
    let mut out = Vec::new();
    let mut count = 0usize;
    while decoder.can_decode() && count < max_insns {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() || insn.len() == 0 {
            break;
        }
        out.push(StartupInsn { instr: insn });
        count += 1;
        if matches!(insn.mnemonic(), Mnemonic::Ret | Mnemonic::Retf) {
            break;
        }
    }
    Some(out)
}

fn extract_startup_edges(pe: &PeFile, insn: &StartupInsn) -> Vec<StartupEdge> {
    let Some(target_rva) = branch_target_rva(pe, &insn.instr) else {
        return Vec::new();
    };
    let Some(section) = pe.rva_to_section(target_rva) else {
        return Vec::new();
    };
    if !section.is_executable() {
        return Vec::new();
    }
    let (via, note) = if matches!(insn.instr.mnemonic(), Mnemonic::Call) {
        (
            "direct call",
            "entry/startup code calls deeper internal initialization".to_owned(),
        )
    } else if matches!(insn.instr.mnemonic(), Mnemonic::Jmp) {
        (
            "direct jump",
            "entry/startup code tail-jumps into deeper internal initialization".to_owned(),
        )
    } else {
        return Vec::new();
    };
    vec![StartupEdge {
        target_rva,
        via,
        note,
    }]
}

fn extract_code_pointer_loads(pe: &PeFile, insn: &StartupInsn) -> Vec<PendingCodePtr> {
    let mut out = Vec::new();
    let mnemonic = insn.instr.mnemonic();
    match mnemonic {
        Mnemonic::Lea => {
            if let Some(target_rva) = memory_target_rva(pe, &insn.instr) {
                out.push(PendingCodePtr {
                    target_rva,
                    source: "lea",
                });
            }
        }
        Mnemonic::Mov => {
            if let Some(target_rva) = immediate_target_rva(pe, &insn.instr) {
                out.push(PendingCodePtr {
                    target_rva,
                    source: "mov",
                });
            }
        }
        Mnemonic::Push => {
            if let Some(target_rva) = immediate_target_rva(pe, &insn.instr) {
                out.push(PendingCodePtr {
                    target_rva,
                    source: "push",
                });
            }
        }
        _ => {}
    }
    out.retain(|item| {
        pe.rva_to_section(item.target_rva)
            .is_some_and(|section| section.is_executable())
    });
    out
}

fn branch_target_rva(pe: &PeFile, instr: &iced_x86::Instruction) -> Option<u32> {
    match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            pe.va_to_rva(instr.near_branch_target())
        }
        _ => None,
    }
}

fn immediate_target_rva(pe: &PeFile, instr: &iced_x86::Instruction) -> Option<u32> {
    for kind in [instr.op0_kind(), instr.op1_kind()] {
        let value = match kind {
            OpKind::Immediate8 => instr.immediate8() as u64,
            OpKind::Immediate16 => instr.immediate16() as u64,
            OpKind::Immediate32 | OpKind::Immediate32to64 => instr.immediate32() as u64,
            OpKind::Immediate64 => instr.immediate64(),
            _ => continue,
        };
        if let Some(rva) = pe.va_to_rva(value) {
            return Some(rva);
        }
    }
    None
}

fn is_plausible_startup_target(pe: &PeFile, raw: &[u8], rva: u32) -> bool {
    if rva == 0 || rva == pe.entry_point || rva & 1 != 0 {
        return false;
    }
    let Some(section) = pe.rva_to_section(rva) else {
        return false;
    };
    if !section.is_executable() {
        return false;
    }
    let Some(off) = pe.rva_to_offset(rva) else {
        return false;
    };
    if off >= raw.len() {
        return false;
    }

    let first = raw[off];
    if matches!(first, 0x00 | 0x90 | 0xCC | 0xC2 | 0xC3 | 0xCA | 0xCB)
        || (first == 0x0F && raw.get(off + 1).is_some_and(|b| *b == 0x0B))
    {
        return false;
    }

    let end = off.saturating_add(16).min(raw.len());
    let chunk = &raw[off..end];
    let mut decoder = Decoder::with_ip(
        pe.arch,
        chunk,
        pe.image_base + rva as u64,
        DecoderOptions::NONE,
    );
    let mut instr = iced_x86::Instruction::default();
    decoder.decode_out(&mut instr);
    !instr.is_invalid() && instr.len() > 0
}

fn memory_target_rva(pe: &PeFile, instr: &iced_x86::Instruction) -> Option<u32> {
    if instr.op1_kind() != OpKind::Memory {
        return None;
    }
    if matches!(instr.memory_base(), Register::RIP | Register::EIP) {
        let addr = instr.ip_rel_memory_address();
        return pe.va_to_rva(addr);
    }
    None
}

fn is_call_or_jmp(mnemonic: Mnemonic) -> bool {
    matches!(mnemonic, Mnemonic::Call | Mnemonic::Jmp)
}

/// Validate each link without recursion, separating V2 epilog metadata from
/// the descending prologue codes shared by V1 and V2.
#[cfg(test)]
pub(in crate::formats::pe) fn validate_unwind_chain(
    pe: &PeFile,
    raw: &[u8],
    begin: u32,
    end: u32,
    unwind: u32,
) -> Option<()> {
    validate_unwind_bounded(pe, raw, begin, end, unwind, &mut 16_384)
}
