use super::constants::{
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DIRECTORY_ENTRY_EXCEPTION, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_DIRECTORY_ENTRY_TLS,
};
use super::types::{
    read_cstr, read_u16, read_u32, read_u64, PeChainedRuntimeFunction, PeClrInfo, PeCodeViewInfo,
    PeDataPointer, PeDataString, PeDataSummary, PeDebugEntry, PeDebugInfo, PeEpilogScope, PeFile,
    PeLoadConfigInfo, PeRuntimeFunctionInfo, PeSavedRegister, PeStartupRoutine, PeTlsCallback,
    PeTlsInfo, PeUnwindOperation, PeVTable,
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

pub fn read_runtime_functions(pe: &PeFile, raw: &[u8]) -> Vec<PeRuntimeFunctionInfo> {
    if pe.arch != 64 {
        return Vec::new();
    }

    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if dir_rva == 0 || dir_size < 12 {
        return Vec::new();
    }
    let Some(mut off) = pe.rva_to_offset(dir_rva) else {
        return Vec::new();
    };
    let end = off.saturating_add(dir_size as usize).min(raw.len());
    let mut out = Vec::new();
    while off + 12 <= end {
        let begin_rva = read_u32(raw, off);
        let end_rva = read_u32(raw, off + 4);
        let unwind_info_rva = read_u32(raw, off + 8);
        if begin_rva != 0 && end_rva > begin_rva {
            if let Some(info) = parse_unwind_info(pe, raw, begin_rva, end_rva, unwind_info_rva) {
                out.push(info);
            }
        }
        off += 12;
    }
    out
}

pub fn read_data_summary(pe: &PeFile, raw: &[u8]) -> PeDataSummary {
    let runtime_functions = read_runtime_functions(pe, raw);
    let strings = read_data_strings(pe, raw, 256);
    let pointers = read_data_pointers(pe, raw, 512);
    let vtables = read_vtables_from_pointers(pe, &pointers, 128);
    PeDataSummary {
        strings,
        vtables,
        pointers,
        runtime_functions,
    }
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

fn read_data_strings(pe: &PeFile, raw: &[u8], limit: usize) -> Vec<PeDataString> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for section in pe
        .sections
        .iter()
        .filter(|section| is_data_section(&section.name))
    {
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(raw.len());
        let mut off = start;
        while off < end && out.len() < limit {
            if let Some((value, consumed)) = read_ascii_string_at(raw, off, end) {
                let rva = section.virtual_address + (off - start) as u32;
                if seen.insert((rva, "ascii")) {
                    out.push(PeDataString {
                        rva,
                        section_name: section.name.clone(),
                        encoding: "ascii".to_owned(),
                        value,
                    });
                }
                off += consumed.max(1);
                continue;
            }
            if let Some((value, consumed)) = read_utf16_string_at(raw, off, end) {
                let rva = section.virtual_address + (off - start) as u32;
                if seen.insert((rva, "utf16")) {
                    out.push(PeDataString {
                        rva,
                        section_name: section.name.clone(),
                        encoding: "utf16".to_owned(),
                        value,
                    });
                }
                off += consumed.max(2);
                continue;
            }
            off += 1;
        }
    }
    out
}

fn read_data_pointers(pe: &PeFile, raw: &[u8], limit: usize) -> Vec<PeDataPointer> {
    let ptr_width = if pe.arch == 64 { 8usize } else { 4usize };
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for section in pe
        .sections
        .iter()
        .filter(|section| is_data_section(&section.name))
    {
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(raw.len());
        let mut off = start;
        while off + ptr_width <= end && out.len() < limit {
            let value = if ptr_width == 8 {
                read_u64(raw, off)
            } else {
                read_u32(raw, off) as u64
            };
            let site_rva = section.virtual_address + (off - start) as u32;
            if let Some(target_rva) = pe.va_to_rva(value) {
                if let Some(target_section) = pe.rva_to_section(target_rva) {
                    if seen.insert(site_rva) {
                        out.push(PeDataPointer {
                            rva: site_rva,
                            target_rva,
                            section_name: section.name.clone(),
                            target_section_name: target_section.name.clone(),
                            kind: if target_section.is_executable() {
                                "code".to_owned()
                            } else {
                                "data".to_owned()
                            },
                        });
                    }
                }
            }
            off += ptr_width;
        }
    }
    out
}

fn read_vtables_from_pointers(
    pe: &PeFile,
    pointers: &[PeDataPointer],
    limit: usize,
) -> Vec<PeVTable> {
    let ptr_width = if pe.arch == 64 { 8u32 } else { 4u32 };
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx < pointers.len() && out.len() < limit {
        if pointers[idx].kind != "code" {
            idx += 1;
            continue;
        }
        let start = idx;
        let mut entries = vec![pointers[idx].target_rva];
        idx += 1;
        while idx < pointers.len()
            && pointers[idx].kind == "code"
            && pointers[idx].section_name == pointers[start].section_name
            && pointers[idx].rva == pointers[idx - 1].rva.saturating_add(ptr_width)
            && entries.len() < 256
        {
            entries.push(pointers[idx].target_rva);
            idx += 1;
        }
        if entries.len() >= 2 {
            out.push(PeVTable {
                rva: pointers[start].rva,
                section_name: pointers[start].section_name.clone(),
                entries,
            });
        }
    }
    out
}

fn is_data_section(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        ".rdata"
            | "rdata"
            | ".data"
            | "data"
            | ".pdata"
            | "pdata"
            | ".xdata"
            | "xdata"
            | ".idata"
            | "idata"
    )
}

fn read_ascii_string_at(raw: &[u8], off: usize, end: usize) -> Option<(String, usize)> {
    let mut pos = off;
    while pos < end && matches!(raw[pos], 0x20..=0x7E | b'\t' | b'\r' | b'\n') {
        pos += 1;
    }
    let len = pos.saturating_sub(off);
    if len < 4 || pos >= end || raw[pos] != 0 {
        return None;
    }
    let text = String::from_utf8_lossy(&raw[off..pos]).to_string();
    let alpha = text.bytes().filter(|b| b.is_ascii_alphabetic()).count();
    if alpha < 2 {
        return None;
    }
    Some((text, len + 1))
}

fn read_utf16_string_at(raw: &[u8], off: usize, end: usize) -> Option<(String, usize)> {
    let mut units = Vec::new();
    let mut pos = off;
    while pos + 1 < end {
        let unit = u16::from_le_bytes([raw[pos], raw[pos + 1]]);
        if unit == 0 {
            break;
        }
        if !(0x20..=0x7E).contains(&unit) && !matches!(unit, 9 | 10 | 13) {
            break;
        }
        units.push(unit);
        pos += 2;
    }
    if units.len() < 4 || pos + 1 >= end || raw[pos] != 0 || raw[pos + 1] != 0 {
        return None;
    }
    let text = String::from_utf16(&units).ok()?;
    let alpha = text.bytes().filter(|b| b.is_ascii_alphabetic()).count();
    if alpha < 2 {
        return None;
    }
    Some((text, (pos + 2) - off))
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
    let (unwind_operations, stack_alloc_size, saved_registers) =
        parse_unwind_operations(raw, off + 4, unwind_code_count);
    let chained_parent = if unwind_flags & 0x4 != 0 && handler_field_off + 12 <= raw.len() {
        Some(PeChainedRuntimeFunction {
            begin_rva: read_u32(raw, handler_field_off),
            end_rva: read_u32(raw, handler_field_off + 4),
            unwind_info_rva: read_u32(raw, handler_field_off + 8),
        })
    } else {
        None
    };
    let exception_handler_rva =
        if unwind_flags & 0x3 != 0 && unwind_flags & 0x4 == 0 && handler_field_off + 4 <= raw.len()
        {
            read_u32(raw, handler_field_off)
        } else {
            0
        };
    let handler_data_rva = if exception_handler_rva != 0 {
        unwind_info_rva
            .saturating_add(4)
            .saturating_add(aligned_codes_size as u32)
            .saturating_add(4)
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
        handler_data_rva,
        stack_alloc_size,
        saved_registers,
        unwind_operations,
        chained_parent,
        epilog_scopes: infer_epilog_scopes(raw, pe, begin_rva, end_rva),
    })
}

fn parse_unwind_operations(
    raw: &[u8],
    codes_off: usize,
    count: u8,
) -> (Vec<PeUnwindOperation>, u32, Vec<PeSavedRegister>) {
    let mut ops = Vec::new();
    let mut saved = Vec::new();
    let mut stack_alloc = 0u32;
    let mut idx = 0usize;
    while idx < count as usize {
        let off = codes_off + idx * 2;
        if off + 2 > raw.len() {
            break;
        }
        let code_offset = raw[off];
        let b = raw[off + 1];
        let uwop = b & 0x0F;
        let info = b >> 4;
        let mut stack_offset = 0u32;
        let mut extra_slots = 0usize;
        let (name, description) = match uwop {
            0 => {
                saved.push(PeSavedRegister {
                    register: unwind_reg_name(info).to_owned(),
                    stack_offset: stack_alloc,
                    prolog_offset: code_offset,
                });
                (
                    "UWOP_PUSH_NONVOL",
                    format!("push {}", unwind_reg_name(info)),
                )
            }
            1 => {
                if info == 0 {
                    let extra = read_u16(raw, off + 2) as u32 * 8;
                    stack_alloc = stack_alloc.saturating_add(extra);
                    stack_offset = extra;
                    extra_slots = 1;
                    ("UWOP_ALLOC_LARGE", format!("alloc large 0x{:X}", extra))
                } else {
                    let extra = read_u32(raw, off + 2);
                    stack_alloc = stack_alloc.saturating_add(extra);
                    stack_offset = extra;
                    extra_slots = 2;
                    ("UWOP_ALLOC_LARGE", format!("alloc large 0x{:X}", extra))
                }
            }
            2 => {
                let extra = (info as u32) * 8 + 8;
                stack_alloc = stack_alloc.saturating_add(extra);
                stack_offset = extra;
                ("UWOP_ALLOC_SMALL", format!("alloc small 0x{:X}", extra))
            }
            3 => ("UWOP_SET_FPREG", "establish frame pointer".to_owned()),
            4 | 5 => {
                let scale = if uwop == 4 { 8 } else { 1 };
                let slots = if uwop == 4 { 1 } else { 2 };
                let extra = if uwop == 4 {
                    read_u16(raw, off + 2) as u32 * scale
                } else {
                    read_u32(raw, off + 2) * scale
                };
                saved.push(PeSavedRegister {
                    register: unwind_reg_name(info).to_owned(),
                    stack_offset: extra,
                    prolog_offset: code_offset,
                });
                stack_offset = extra;
                extra_slots = slots;
                (
                    if uwop == 4 {
                        "UWOP_SAVE_NONVOL"
                    } else {
                        "UWOP_SAVE_NONVOL_FAR"
                    },
                    format!("save {} at stack+0x{:X}", unwind_reg_name(info), extra),
                )
            }
            8 | 9 => {
                let scale = if uwop == 8 { 16 } else { 1 };
                let slots = if uwop == 8 { 1 } else { 2 };
                let extra = if uwop == 8 {
                    read_u16(raw, off + 2) as u32 * scale
                } else {
                    read_u32(raw, off + 2) * scale
                };
                stack_offset = extra;
                extra_slots = slots;
                (
                    if uwop == 8 {
                        "UWOP_SAVE_XMM128"
                    } else {
                        "UWOP_SAVE_XMM128_FAR"
                    },
                    format!("save xmm{} at stack+0x{:X}", info, extra),
                )
            }
            10 => (
                "UWOP_PUSH_MACHFRAME",
                if info == 0 {
                    "push machine frame".to_owned()
                } else {
                    "push machine frame with error code".to_owned()
                },
            ),
            _ => ("UWOP_UNKNOWN", format!("unknown unwind op {}", uwop)),
        };
        ops.push(PeUnwindOperation {
            code_offset,
            op: name.to_owned(),
            info,
            stack_offset,
            description,
        });
        idx += 1 + extra_slots;
    }
    (ops, stack_alloc, saved)
}

fn infer_epilog_scopes(
    raw: &[u8],
    pe: &PeFile,
    begin_rva: u32,
    end_rva: u32,
) -> Vec<PeEpilogScope> {
    let Some(start) = pe.rva_to_offset(begin_rva) else {
        return Vec::new();
    };
    let Some(end) = pe.rva_to_offset(end_rva.saturating_sub(1)).map(|v| v + 1) else {
        return Vec::new();
    };
    let end = end.min(raw.len());
    if start >= end {
        return Vec::new();
    }
    let window_start = end.saturating_sub(32).max(start);
    let mut scopes = Vec::new();
    for (off, b) in raw.iter().enumerate().take(end).skip(window_start) {
        if *b == 0xC3 || *b == 0xC2 || *b == 0xCB || *b == 0xCA {
            let rva = begin_rva.saturating_add((off - start) as u32);
            scopes.push(PeEpilogScope {
                start_offset: rva.saturating_sub(begin_rva),
                end_offset: rva.saturating_sub(begin_rva).saturating_add(1),
                source: "ret-scan".to_owned(),
            });
        }
    }
    scopes
}

fn unwind_reg_name(reg: u8) -> &'static str {
    match reg {
        0 => "rax",
        1 => "rcx",
        2 => "rdx",
        3 => "rbx",
        4 => "rsp",
        5 => "rbp",
        6 => "rsi",
        7 => "rdi",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "r13",
        14 => "r14",
        15 => "r15",
        _ => "unknown",
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::pe::{PeAnomaly, PeSection, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ};

    fn startup_test_pe(entry_point: u32) -> PeFile {
        PeFile {
            arch: 64,
            machine: 0x8664,
            timestamp: 0,
            coff_characteristics: 0,
            major_linker_version: 0,
            minor_linker_version: 0,
            image_base: 0x1800_0000,
            entry_point,
            size_of_image: 0xA000,
            size_of_headers: 0x400,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            checksum: 0,
            subsystem: 3,
            dll_characteristics: 0,
            sections: vec![PeSection {
                name: ".text".to_owned(),
                virtual_address: 0x1000,
                virtual_size: 0x9000,
                raw_offset: 0,
                raw_size: 0x9000,
                characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                entropy: 0.0,
            }],
            data_dirs: vec![(0, 0); 16],
            anomalies: Vec::<PeAnomaly>::new(),
        }
    }

    fn put(raw: &mut [u8], rva: u32, bytes: &[u8]) {
        let off = rva.saturating_sub(0x1000) as usize;
        raw[off..off + bytes.len()].copy_from_slice(bytes);
    }

    #[test]
    fn startup_routines_do_not_export_recursive_branch_chains() {
        let pe = startup_test_pe(0x1000);
        let mut raw = vec![0xCC; 0x9000];
        put(&mut raw, 0x1000, &[0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3]);
        put(&mut raw, 0x2000, &[0xE8, 0xFB, 0x0F, 0x00, 0x00, 0xC3]);
        put(&mut raw, 0x3000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);

        let routines = find_startup_routines(&pe, &raw);

        assert!(routines
            .iter()
            .any(|entry| entry.kind == "PE Entry Point" && entry.rva == 0x1000));
        assert_eq!(
            routines
                .iter()
                .filter(|entry| entry.kind == "Startup Handoff")
                .count(),
            1
        );
        assert!(!routines.iter().any(|entry| entry.kind == "Startup Chain"));
    }

    #[test]
    fn startup_routines_reject_raw_rva_immediates_as_main_candidates() {
        let pe = startup_test_pe(0x1000);
        let mut raw = vec![0xCC; 0x9000];
        put(
            &mut raw,
            0x1000,
            &[
                0x48, 0xB8, 0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xE8, 0xF1, 0x0F, 0x00,
                0x00, 0xC3,
            ],
        );
        put(&mut raw, 0x2000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);
        put(&mut raw, 0x8000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);

        let routines = find_startup_routines(&pe, &raw);

        assert!(!routines
            .iter()
            .any(|entry| entry.kind == "Real Main Candidate" && entry.rva == 0x8000));
    }

    #[test]
    fn startup_routines_accept_full_va_code_pointer_candidates() {
        let pe = startup_test_pe(0x1000);
        let mut raw = vec![0xCC; 0x9000];
        let mut entry = vec![0x48, 0xB8];
        entry.extend_from_slice(&(pe.image_base + 0x3000).to_le_bytes());
        entry.extend_from_slice(&[0xE8, 0xF1, 0x0F, 0x00, 0x00, 0xC3]);
        put(&mut raw, 0x1000, &entry);
        put(&mut raw, 0x2000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);
        put(&mut raw, 0x3000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);

        let routines = find_startup_routines(&pe, &raw);

        assert!(routines
            .iter()
            .any(|entry| entry.kind == "Real Main Candidate" && entry.rva == 0x3000));
    }

    #[test]
    fn startup_routines_reject_odd_code_pointer_candidates() {
        let pe = startup_test_pe(0x1000);
        let mut raw = vec![0xCC; 0x9000];
        let mut entry = vec![0x48, 0xB8];
        entry.extend_from_slice(&(pe.image_base + 0x3001).to_le_bytes());
        entry.extend_from_slice(&[0xE8, 0xF1, 0x0F, 0x00, 0x00, 0xC3]);
        put(&mut raw, 0x1000, &entry);
        put(&mut raw, 0x2000, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);
        put(&mut raw, 0x3001, &[0x48, 0x83, 0xEC, 0x28, 0xC3]);

        let routines = find_startup_routines(&pe, &raw);

        assert!(!routines
            .iter()
            .any(|entry| entry.kind == "Real Main Candidate" && entry.rva == 0x3001));
    }
}
