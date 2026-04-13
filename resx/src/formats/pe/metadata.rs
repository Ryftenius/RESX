use super::constants::{
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_DIRECTORY_ENTRY_TLS,
};
use super::types::{
    read_cstr, read_u16, read_u32, read_u64, PeClrInfo, PeCodeViewInfo, PeDebugEntry, PeDebugInfo,
    PeFile, PeLoadConfigInfo, PeRuntimeFunctionInfo, PeStartupRoutine, PeTlsCallback, PeTlsInfo,
};
use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use std::collections::{BTreeSet, VecDeque};

pub fn read_debug_info(pe: &PeFile, raw: &[u8]) -> PeDebugInfo {
    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_DEBUG);
    if dir_rva == 0 || dir_size < 28 {
        return PeDebugInfo::default();
    }

    let mut entries = Vec::new();
    let mut codeview = None;
    let mut off = match pe.rva_to_offset(dir_rva) {
        Some(v) => v,
        None => return PeDebugInfo::default(),
    };
    let end = off.saturating_add(dir_size as usize).min(raw.len());
    while off + 28 <= end {
        let debug_type = read_u32(raw, off + 12);
        let size_of_data = read_u32(raw, off + 16);
        let ptr_to_raw = read_u32(raw, off + 24) as usize;
        entries.push(PeDebugEntry {
            debug_type,
            size_of_data,
        });
        if debug_type == 2 && codeview.is_none() && ptr_to_raw + size_of_data as usize <= raw.len()
        {
            codeview = parse_codeview_info(&raw[ptr_to_raw..ptr_to_raw + size_of_data as usize]);
        }
        off += 28;
    }

    PeDebugInfo { entries, codeview }
}

pub fn read_clr_info(pe: &PeFile, raw: &[u8]) -> Option<PeClrInfo> {
    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if dir_rva == 0 || dir_size < 0x18 {
        return None;
    }
    let off = pe.rva_to_offset(dir_rva)?;
    if off + 0x18 > raw.len() {
        return None;
    }

    let major_runtime_version = read_u16(raw, off + 4);
    let minor_runtime_version = read_u16(raw, off + 6);
    let metadata_rva = read_u32(raw, off + 8);
    let metadata_size = read_u32(raw, off + 12);
    let flags = read_u32(raw, off + 16);
    let entry_point_token_or_rva = read_u32(raw, off + 20);
    let metadata_version = read_clr_metadata_version(pe, raw, metadata_rva).unwrap_or_default();

    Some(PeClrInfo {
        major_runtime_version,
        minor_runtime_version,
        metadata_rva,
        metadata_size,
        flags,
        entry_point_token_or_rva,
        metadata_version,
    })
}

pub fn read_load_config(pe: &PeFile, raw: &[u8]) -> Option<PeLoadConfigInfo> {
    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG);
    if dir_rva == 0 || dir_size < 4 {
        return None;
    }
    let off = pe.rva_to_offset(dir_rva)?;
    if off + 4 > raw.len() {
        return None;
    }

    let size = read_u32(raw, off);
    if size == 0 {
        return None;
    }

    // Offsets are taken from IMAGE_LOAD_CONFIG_DIRECTORY32/64 in the local Windows SDK.
    let (
        security_cookie_off,
        se_handler_count_off,
        guard_cf_count_off,
        guard_flags_off,
        guard_eh_count_off,
        guard_xfg_check_off,
    ) = if pe.arch == 64 {
        (88usize, 104usize, 136usize, 144usize, 272usize, 280usize)
    } else {
        (60usize, 68usize, 84usize, 88usize, 168usize, 172usize)
    };

    Some(PeLoadConfigInfo {
        size,
        security_cookie: read_load_config_value(raw, off, size, security_cookie_off, pe.arch),
        se_handler_count: read_load_config_value(raw, off, size, se_handler_count_off, pe.arch),
        guard_cf_function_count: read_load_config_value(
            raw,
            off,
            size,
            guard_cf_count_off,
            pe.arch,
        ),
        guard_flags: read_load_config_u32(raw, off, size, guard_flags_off),
        guard_eh_continuation_count: read_load_config_value(
            raw,
            off,
            size,
            guard_eh_count_off,
            pe.arch,
        ),
        guard_xfg_check_function_pointer: read_load_config_value(
            raw,
            off,
            size,
            guard_xfg_check_off,
            pe.arch,
        ),
    })
}

pub fn read_runtime_function(
    pe: &PeFile,
    raw: &[u8],
    target_rva: u32,
) -> Option<PeRuntimeFunctionInfo> {
    if pe.arch != 64 {
        return None;
    }

    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if dir_rva == 0 || dir_size < 12 {
        return None;
    }
    let mut off = pe.rva_to_offset(dir_rva)?;
    let end = off.checked_add(dir_size as usize)?.min(raw.len());

    while off + 12 <= end {
        let begin_rva = read_u32(raw, off);
        let end_rva = read_u32(raw, off + 4);
        let unwind_info_rva = read_u32(raw, off + 8);
        if begin_rva <= target_rva && target_rva < end_rva {
            return parse_unwind_info(pe, raw, begin_rva, end_rva, unwind_info_rva);
        }
        off += 12;
    }

    None
}

pub fn read_tls_info(pe: &PeFile, raw: &[u8]) -> Option<PeTlsInfo> {
    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_TLS);
    let min_size = if pe.arch == 64 { 40usize } else { 24usize };
    if dir_rva == 0 || dir_size < min_size as u32 {
        return None;
    }
    let off = pe.rva_to_offset(dir_rva)?;
    if off + min_size > raw.len() {
        return None;
    }

    let read_ptr = |offset: usize| -> u64 {
        if pe.arch == 64 {
            read_u64(raw, off + offset)
        } else {
            read_u32(raw, off + offset) as u64
        }
    };

    let address_of_callbacks = read_ptr(if pe.arch == 64 { 24 } else { 12 });

    let callbacks = parse_tls_callbacks(pe, raw, address_of_callbacks);
    Some(PeTlsInfo { callbacks })
}

pub fn find_startup_routines(pe: &PeFile, raw: &[u8]) -> Vec<PeStartupRoutine> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();

    if seen.insert((pe.entry_point, "pe-entry".to_owned())) {
        let section_name = pe
            .rva_to_section(pe.entry_point)
            .map(|section| section.name.clone())
            .unwrap_or_default();
        out.push(PeStartupRoutine {
            kind: "PE Entry Point".to_owned(),
            source: "AddressOfEntryPoint".to_owned(),
            rva: pe.entry_point,
            va: pe.image_base + pe.entry_point as u64,
            section_name,
            note: "loader transfers control here after image initialization".to_owned(),
        });
    }

    if let Some(tls) = read_tls_info(pe, raw) {
        for callback in tls.callbacks {
            if seen.insert((callback.rva, "tls-callback".to_owned())) {
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
                    note: "invoked by the loader before the normal entry point".to_owned(),
                });
            }
        }
    }

    let ptr_width = if pe.arch == 64 { 8usize } else { 4usize };
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
        while off + ptr_width <= end && hits < 32 {
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
            if !target_section.is_executable() {
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
                    "{} pointer at +0x{:X} targets executable startup code",
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

    out.sort_by_key(|entry| (startup_kind_priority(&entry.kind), entry.rva));
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

fn find_real_entry_candidates(pe: &PeFile, raw: &[u8]) -> Vec<PeStartupRoutine> {
    let mut out = Vec::new();
    let mut seen_rvas = BTreeSet::new();
    let mut queue = VecDeque::from([(pe.entry_point, 0usize)]);
    let mut visited = BTreeSet::new();

    while let Some((rva, depth)) = queue.pop_front() {
        if depth > 4 || !visited.insert(rva) {
            continue;
        }
        let Some(window) = decode_startup_window(pe, raw, rva, 128, 1024) else {
            continue;
        };
        let mut pending_ptrs: Vec<PendingCodePtr> = Vec::new();
        for insn in window {
            pending_ptrs.extend(extract_code_pointer_loads(pe, &insn));
            if pending_ptrs.len() > 16 {
                pending_ptrs.drain(0..pending_ptrs.len().saturating_sub(4));
            }

            for edge in extract_startup_edges(pe, &insn) {
                if seen_rvas.insert((edge.target_rva, edge.via)) {
                    let section_name = pe
                        .rva_to_section(edge.target_rva)
                        .map(|section| section.name.clone())
                        .unwrap_or_default();
                    out.push(PeStartupRoutine {
                        kind: if depth == 0 {
                            "Startup Handoff".to_owned()
                        } else {
                            "Startup Chain".to_owned()
                        },
                        source: format!("{} @ depth {}", edge.via, depth),
                        rva: edge.target_rva,
                        va: pe.image_base + edge.target_rva as u64,
                        section_name,
                        note: edge.note.clone(),
                    });
                }
                if depth < 4 {
                    queue.push_back((edge.target_rva, depth + 1));
                }
            }

            if is_call_or_jmp(insn.instr.mnemonic()) && !pending_ptrs.is_empty() {
                for ptr in pending_ptrs.drain(..) {
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
                    }
                    if depth < 4 {
                        queue.push_back((ptr.target_rva, depth + 1));
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
    let file_off = pe.rva_to_offset(start_rva)?;
    let end = file_off.saturating_add(max_bytes).min(raw.len());
    let chunk = &raw[file_off..end];
    let mut decoder = Decoder::with_ip(
        pe.arch,
        chunk,
        pe.image_base + start_rva as u64,
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
            } else if let Some(target_rva) = memory_target_rva(pe, &insn.instr) {
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
        if let Some(rva) = pe
            .va_to_rva(value)
            .or_else(|| pe.rva_to_section(value as u32).map(|_| value as u32))
        {
            return Some(rva);
        }
    }
    None
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

fn parse_unwind_info(
    pe: &PeFile,
    raw: &[u8],
    begin_rva: u32,
    end_rva: u32,
    unwind_info_rva: u32,
) -> Option<PeRuntimeFunctionInfo> {
    let off = pe.rva_to_offset(unwind_info_rva)?;
    if off + 4 > raw.len() {
        return None;
    }

    let b0 = raw[off];
    let unwind_version = b0 & 0x7;
    let unwind_flags = b0 >> 3;
    let prolog_size = raw[off + 1];
    let unwind_code_count = raw[off + 2];
    let frame = raw[off + 3];
    let frame_register = frame & 0x0F;
    let frame_offset = frame >> 4;

    let codes_size = (unwind_code_count as usize) * 2;
    let aligned_codes_size = (codes_size + 3) & !3;
    let handler_field_off = off + 4 + aligned_codes_size;

    let exception_handler_rva = if unwind_flags & 0x3 != 0 && handler_field_off + 4 <= raw.len() {
        read_u32(raw, handler_field_off)
    } else {
        0
    };

    Some(PeRuntimeFunctionInfo {
        begin_rva,
        end_rva,
        unwind_info_rva,
        unwind_version,
        unwind_flags,
        prolog_size,
        unwind_code_count,
        frame_register,
        frame_offset,
        exception_handler_rva,
    })
}

fn parse_codeview_info(raw: &[u8]) -> Option<PeCodeViewInfo> {
    if raw.len() < 24 || &raw[..4] != b"RSDS" {
        return None;
    }

    let guid = format!(
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        raw[7], raw[6], raw[5], raw[4], raw[9], raw[8], raw[11], raw[10], raw[12], raw[13],
        raw[14], raw[15], raw[16], raw[17], raw[18], raw[19],
    );
    let age = read_u32(raw, 20);
    let pdb_path = read_cstr(raw, 24);
    let pdb_name = pdb_path.rsplit(['\\', '/']).next().unwrap_or("").to_owned();
    Some(PeCodeViewInfo {
        pdb_path,
        pdb_name,
        guid_age: format!("{}{}", guid, age),
    })
}

fn read_clr_metadata_version(pe: &PeFile, raw: &[u8], metadata_rva: u32) -> Option<String> {
    let off = pe.rva_to_offset(metadata_rva)?;
    if off + 16 > raw.len() || &raw[off..off + 4] != b"BSJB" {
        return None;
    }
    let version_len = read_u32(raw, off + 12) as usize;
    if off + 16 + version_len > raw.len() {
        return None;
    }
    Some(
        String::from_utf8_lossy(&raw[off + 16..off + 16 + version_len])
            .trim_matches(char::from(0))
            .trim()
            .to_owned(),
    )
}

fn read_load_config_u32(raw: &[u8], off: usize, size: u32, field_off: usize) -> u32 {
    if field_off + 4 > size as usize || off + field_off + 4 > raw.len() {
        0
    } else {
        read_u32(raw, off + field_off)
    }
}

fn read_load_config_value(raw: &[u8], off: usize, size: u32, field_off: usize, arch: u32) -> u64 {
    let width = if arch == 64 { 8 } else { 4 };
    if field_off + width > size as usize || off + field_off + width > raw.len() {
        0
    } else if arch == 64 {
        read_u64(raw, off + field_off)
    } else {
        read_u32(raw, off + field_off) as u64
    }
}

fn parse_tls_callbacks(pe: &PeFile, raw: &[u8], callbacks_va: u64) -> Vec<PeTlsCallback> {
    let Some(callbacks_rva) = pe.va_to_rva(callbacks_va) else {
        return Vec::new();
    };
    let Some(mut off) = pe.rva_to_offset(callbacks_rva) else {
        return Vec::new();
    };
    let width = if pe.arch == 64 { 8usize } else { 4usize };
    let mut callbacks = Vec::new();
    let mut seen = BTreeSet::new();

    for _ in 0..64 {
        if off + width > raw.len() {
            break;
        }
        let va = if width == 8 {
            read_u64(raw, off)
        } else {
            read_u32(raw, off) as u64
        };
        if va == 0 {
            break;
        }
        off += width;
        let Some(rva) = pe.va_to_rva(va) else {
            continue;
        };
        if !seen.insert(rva) {
            continue;
        }
        callbacks.push(PeTlsCallback { va, rva });
    }

    callbacks
}

fn is_xl_like_section(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with(".crt")
        || lower.starts_with("crt")
        || lower.starts_with(".xl")
        || lower.starts_with("xl")
        || lower.contains("$xl")
}
