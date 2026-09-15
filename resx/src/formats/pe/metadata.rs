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
use std::collections::{BTreeMap, BTreeSet, VecDeque};

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
    if pe.rva_slice(raw, dir_rva, dir_size as usize).is_none() {
        return PeDebugInfo::default();
    }
    let end = off + (dir_size as usize).min(super::types::MAX_PE_ENTRIES * 28);
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
    pe.rva_slice(raw, dir_rva, 0x18)?;

    let major_runtime_version = read_u16(raw, off + 4);
    let minor_runtime_version = read_u16(raw, off + 6);
    let metadata_rva = read_u32(raw, off + 8);
    let metadata_size = read_u32(raw, off + 12);
    pe.rva_slice(raw, metadata_rva, metadata_size as usize)?;
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
    pe.rva_slice(raw, dir_rva, 4)?;

    let size = read_u32(raw, off);
    if size < 4 || size > dir_size || pe.rva_slice(raw, dir_rva, size as usize).is_none() {
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
    if pe.machine != 0x8664 {
        return None;
    }

    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if dir_rva == 0 || dir_size < 12 {
        return None;
    }
    let mut off = pe.rva_to_offset(dir_rva)?;
    pe.rva_slice(raw, dir_rva, dir_size as usize)?;
    let end = off.checked_add((dir_size as usize).min(super::types::MAX_PE_ENTRIES * 12))?;

    while off + 12 <= end {
        let begin_rva = read_u32(raw, off);
        let end_rva = read_u32(raw, off + 4);
        let unwind_info_rva = read_u32(raw, off + 8);
        if begin_rva <= target_rva && target_rva < end_rva {
            return parse_unwind_info(pe, raw, begin_rva, end_rva, unwind_info_rva, &mut 16_384);
        }
        off += 12;
    }

    None
}

pub fn read_runtime_functions(pe: &PeFile, raw: &[u8]) -> Vec<PeRuntimeFunctionInfo> {
    if pe.machine != 0x8664 {
        return Vec::new();
    }

    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if dir_rva == 0 || dir_size < 12 {
        return Vec::new();
    }
    let Some(mut off) = pe.rva_to_offset(dir_rva) else {
        return Vec::new();
    };
    if pe.rva_slice(raw, dir_rva, dir_size as usize).is_none() {
        return Vec::new();
    }
    let end = off + (dir_size as usize).min(super::types::MAX_PE_ENTRIES * 12);
    let mut out = Vec::new();
    let mut unwind_budget = 2_000_000usize;
    while off + 12 <= end {
        let begin_rva = read_u32(raw, off);
        let end_rva = read_u32(raw, off + 4);
        let unwind_info_rva = read_u32(raw, off + 8);
        if begin_rva != 0 && end_rva > begin_rva {
            if let Some(info) = parse_unwind_info(
                pe,
                raw,
                begin_rva,
                end_rva,
                unwind_info_rva,
                &mut unwind_budget,
            ) {
                out.push(info);
            }
        }
        if unwind_budget == 0 {
            break;
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
    pe.rva_slice(raw, dir_rva, min_size)?;

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
            // Only attempt a string at the beginning of a printable run. Retrying
            // every suffix of an overlong run makes scanning quadratic.
            let ascii_start =
                off == start || !matches!(raw[off - 1], 0x20..=0x7E | b'\t' | b'\r' | b'\n');
            if let Some((value, consumed)) = ascii_start
                .then(|| read_ascii_string_at(raw, off, end))
                .flatten()
            {
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
            let utf16_start =
                off < start + 2 || !matches!(read_u16(raw, off - 2), 0x20..=0x7E | 9 | 10 | 13);
            if let Some((value, consumed)) = utf16_start
                .then(|| read_utf16_string_at(raw, off, end))
                .flatten()
            {
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
    let end = end.min(off.saturating_add(super::types::MAX_PE_STRING));
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
    let end = end.min(off.saturating_add(super::types::MAX_PE_STRING * 2));
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

mod startup;
pub use startup::find_startup_routines;
#[cfg(test)]
pub(in crate::formats::pe) use startup::validate_unwind_chain;

fn validate_unwind_bounded(
    pe: &PeFile,
    raw: &[u8],
    begin: u32,
    end: u32,
    unwind: u32,
    budget: &mut usize,
) -> Option<()> {
    validate_unwind_storage(pe, raw, begin, end, unwind, budget).ok()
}

#[derive(Debug, PartialEq)]
enum UnwindFailure {
    Invalid,
    Unavailable,
    Inconsistent,
}

fn unwind_bytes<'a>(
    pe: &PeFile,
    raw: &'a [u8],
    rva: u32,
    size: usize,
) -> Result<&'a [u8], UnwindFailure> {
    pe.rva_slice(raw, rva, size).ok_or_else(|| {
        if super::validation::mapped(pe, rva, size as u32) {
            UnwindFailure::Unavailable
        } else {
            UnwindFailure::Invalid
        }
    })
}

fn validate_unwind_storage(
    pe: &PeFile,
    raw: &[u8],
    mut begin: u32,
    mut end: u32,
    mut unwind: u32,
    budget: &mut usize,
) -> Result<(), UnwindFailure> {
    use UnwindFailure::Invalid;
    if pe.machine != 0x8664 {
        return Err(Invalid);
    }
    let mut visited = BTreeSet::new();
    let mut inconsistent = false;
    for _ in 0..32 {
        *budget = budget.checked_sub(1).ok_or(Invalid)?;
        if !visited.insert(unwind) || unwind == 0 || unwind & 3 != 0 || end <= begin {
            return Err(Invalid);
        }
        if !super::validation::mapped(pe, begin, end - begin) {
            return Err(Invalid);
        }
        let header = unwind_bytes(pe, raw, unwind, 4)?;
        let version = header[0] & 7;
        let flags = header[0] >> 3;
        if !matches!(version, 1 | 2) || flags & !7 != 0 || flags & 4 != 0 && flags & 3 != 0 {
            return Err(Invalid);
        }
        if u32::from(header[1]) > end - begin {
            inconsistent = true;
        }
        let count = header[2] as usize;
        if count > *budget {
            *budget = 0;
            return Err(Invalid);
        }
        *budget -= count;
        let aligned = (count * 2 + 3) & !3;
        let suffix = if flags & 4 != 0 {
            12
        } else if flags & 3 != 0 {
            4
        } else {
            0
        };
        let record = unwind_bytes(pe, raw, unwind, 4 + aligned + suffix)?;
        let mut index = if version == 2 {
            epilog_prefix(&record[4..4 + count * 2], end - begin)
                .ok_or(Invalid)?
                .0
        } else {
            0
        };
        let mut previous_offset = u8::MAX;
        let mut stack_bytes = 0u32;
        while index < count {
            let offset = record[4 + index * 2];
            let op = record[5 + index * 2] & 15;
            let info = record[5 + index * 2] >> 4;
            if offset > header[1] || offset > previous_offset {
                inconsistent = true;
            }
            previous_offset = offset;
            let extra = match (op, info) {
                (0 | 2 | 3, _) => 0,
                (1, 0) | (4 | 8, _) => 1,
                (1, 1) | (5 | 9, _) => 2,
                (10, 0 | 1) => 0,
                _ => return Err(Invalid),
            };
            if index + 1 + extra > count {
                return Err(Invalid);
            }
            let allocation = match op {
                0 => 8,
                1 if info == 0 => u32::from(read_u16(record, 6 + index * 2)) * 8,
                1 => read_u32(record, 6 + index * 2),
                2 => u32::from(info) * 8 + 8,
                10 => {
                    if info == 0 {
                        40
                    } else {
                        48
                    }
                }
                _ => 0,
            };
            stack_bytes = stack_bytes.checked_add(allocation).ok_or(Invalid)?;
            index += 1 + extra;
        }
        if flags & 4 == 0 {
            if flags & 3 != 0 {
                let handler = read_u32(record, 4 + aligned);
                unwind_bytes(pe, raw, handler, 1)?;
                if !pe
                    .rva_to_section(handler)
                    .is_some_and(|s| s.is_executable())
                {
                    return Err(Invalid);
                }
            }
            return if inconsistent {
                Err(UnwindFailure::Inconsistent)
            } else {
                Ok(())
            };
        }
        begin = read_u32(record, 4 + aligned);
        end = read_u32(record, 8 + aligned);
        unwind = read_u32(record, 12 + aligned);
    }
    Err(Invalid)
}

/// V2 begins with UWOP_EPILOG(size, flags), followed by 12-bit distances from
/// function end. A zero distance is alignment padding; flag 1 also describes
/// the final epilog. These entries are not prologue offsets.
fn epilog_prefix(codes: &[u8], function_size: u32) -> Option<(usize, Vec<PeEpilogScope>)> {
    if !codes.len().is_multiple_of(2) {
        return None;
    }
    if codes.len() < 2 || codes[1] & 15 != 6 {
        return Some((0, Vec::new()));
    }
    let size = u32::from(codes[0]);
    let flags = codes[1] >> 4;
    if size == 0 || size > function_size || flags > 1 {
        return None;
    }
    let mut scopes = Vec::new();
    let mut distances = BTreeSet::new();
    let mut add = |distance: u32| -> Option<()> {
        if distance < size || distance > function_size || !distances.insert(distance) {
            return None;
        }
        let start = function_size.checked_sub(distance)?;
        scopes.push(PeEpilogScope {
            start_offset: start,
            end_offset: start.checked_add(size)?,
            source: "unwind-v2-epilog-metadata".into(),
        });
        Some(())
    };
    if flags & 1 != 0 {
        add(size)?;
    }
    let mut index = 1;
    let mut padding = false;
    while index * 2 < codes.len() && codes[index * 2 + 1] & 15 == 6 {
        let distance = u32::from(codes[index * 2]) | (u32::from(codes[index * 2 + 1] >> 4) << 8);
        if distance == 0 {
            padding = true;
        } else {
            if padding {
                return None;
            }
            add(distance)?;
        }
        index += 1;
    }
    if scopes.is_empty() {
        return None;
    }
    Some((index, scopes))
}

pub(super) fn metadata_anomalies(pe: &PeFile, raw: &[u8]) -> Vec<super::types::PeAnomaly> {
    let mut out = Vec::new();
    let (tls_rva, tls_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_TLS);
    if tls_rva != 0 {
        let width = if pe.arch == 64 { 8 } else { 4 };
        let minimum = if width == 8 { 40 } else { 24 };
        let mut invalid = false;
        let mut terminated = false;
        if let Some(directory) = pe
            .rva_slice(raw, tls_rva, minimum)
            .filter(|_| tls_size as usize >= minimum)
        {
            let table_va = if width == 8 {
                read_u64(directory, 24)
            } else {
                u64::from(read_u32(directory, 12))
            };
            if table_va == 0 {
                terminated = true;
            } else if let Some(table) = pe
                .va_to_rva(table_va)
                .and_then(|rva| pe.rva_bytes(raw, rva))
            {
                for slot in table.chunks_exact(width).take(64) {
                    let va = if width == 8 {
                        read_u64(slot, 0)
                    } else {
                        u64::from(read_u32(slot, 0))
                    };
                    if va == 0 {
                        terminated = true;
                        break;
                    }
                    if pe.va_to_rva(va).is_none_or(|rva| {
                        !pe.rva_to_section(rva).is_some_and(|s| s.is_executable())
                            || pe.rva_slice(raw, rva, 1).is_none()
                    }) {
                        invalid = true;
                    }
                }
            } else {
                invalid = true;
            }
        } else {
            invalid = true;
        }
        if invalid || !terminated {
            out.push(super::types::anomaly("warn", "tls-validation", "TLS contains invalid callback references or lacks a terminator within the 64-slot budget; recovery is incomplete".into()));
        }
    }
    let (rva, size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_EXCEPTION);
    if rva != 0 {
        if pe.machine != 0x8664 {
            out.push(super::types::anomaly(
                "info",
                "unwind-unsupported",
                "Exception records are not decoded as x64 unwind data on this machine type".into(),
            ));
        } else if let Some(table) = pe.rva_slice(raw, rva, size as usize) {
            let count = table.len() / 12;
            let mut budget = 2_000_000usize;
            let mut non_code_storage = 0usize;
            let mut unavailable = 0usize;
            let mut inconsistent = 0usize;
            let mut invalid_reasons = BTreeMap::<&'static str, (usize, Vec<u32>)>::new();
            let invalid = table
                .as_chunks::<12>()
                .0
                .iter()
                .take(super::types::MAX_PE_ENTRIES)
                .filter(|record| {
                    let begin = read_u32(*record, 0);
                    let end = read_u32(*record, 4);
                    if end > begin
                        && super::validation::mapped(pe, begin, end - begin)
                        && (!pe
                            .rva_to_section(begin)
                            .is_some_and(|section| section.is_executable())
                            || pe.rva_slice(raw, begin, (end - begin) as usize).is_none())
                    {
                        non_code_storage += 1;
                    }
                    match validate_unwind_storage(
                        pe,
                        raw,
                        read_u32(*record, 0),
                        read_u32(*record, 4),
                        read_u32(*record, 8),
                        &mut budget,
                    ) {
                        Ok(()) => false,
                        Err(UnwindFailure::Unavailable) => {
                            unavailable += 1;
                            false
                        }
                        Err(UnwindFailure::Invalid) => {
                            let reason = if end <= begin {
                                "begin-greater-than-or-equal-to-end"
                            } else if !super::validation::mapped(pe, begin, end - begin) {
                                "function-range-outside-image"
                            } else if read_u32(*record, 8) == 0 || read_u32(*record, 8) & 3 != 0 {
                                "invalid-unwind-rva-or-alignment"
                            } else if let Some(header) = pe.rva_slice(raw, read_u32(*record, 8), 4)
                            {
                                let version = header[0] & 7;
                                let flags = header[0] >> 3;
                                if !matches!(version, 1 | 2)
                                    || flags & !7 != 0
                                    || flags & 4 != 0 && flags & 3 != 0
                                {
                                    "invalid-version-or-flags"
                                } else {
                                    "malformed-codes-chain-or-handler"
                                }
                            } else {
                                "unwind-rva-outside-observed-file-bytes"
                            };
                            let item = invalid_reasons.entry(reason).or_default();
                            item.0 += 1;
                            if item.1.len() < 3 {
                                item.1.push(begin);
                            }
                            true
                        }
                        Err(UnwindFailure::Inconsistent) => {
                            inconsistent += 1;
                            false
                        }
                    }
                })
                .count();
            if invalid != 0 || table.len() % 12 != 0 || count > super::types::MAX_PE_ENTRIES {
                let categories = invalid_reasons
                    .iter()
                    .map(|(reason, (count, examples))| {
                        format!(
                            "{reason}={count} examples=[{}]",
                            examples
                                .iter()
                                .map(|rva| format!("0x{rva:08X}"))
                                .collect::<Vec<_>>()
                                .join(",")
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("; ");
                out.push(super::types::anomaly("warn", "unwind-validation", format!("{invalid} x64 records failed validation; declared records={count}, limit={}; categories: {categories}. Rejected records are not recovered.", super::types::MAX_PE_ENTRIES)));
            }
            if unavailable != 0 {
                out.push(super::types::anomaly("info", "unwind-unavailable", format!("{unavailable} x64 records reference mapped metadata or handler bytes unavailable on disk; contents unknown, not recovered. Runtime bytes require fresh validation")));
            }
            if inconsistent != 0 {
                out.push(super::types::anomaly("warn", "unwind-semantics", format!("{inconsistent} x64 records have bounded, non-circular structure but inconsistent prologue lengths or code offsets. These records are not recovered as trustworthy unwind metadata")));
            }
            if non_code_storage != 0 {
                out.push(super::types::anomaly("info", "runtime-function-storage", format!("{non_code_storage} runtime-function ranges occupy non-executable or non-file-backed storage. Metadata does not establish executable bytes; runtime evidence is required")));
            }
            if budget == 0 {
                out.push(super::types::anomaly(
                    "warn",
                    "unwind-budget",
                    "Aggregate unwind validation budget exhausted; recovery is incomplete".into(),
                ));
            }
        }
    }
    out
}

fn parse_unwind_info(
    pe: &PeFile,
    raw: &[u8],
    begin_rva: u32,
    end_rva: u32,
    unwind_info_rva: u32,
    budget: &mut usize,
) -> Option<PeRuntimeFunctionInfo> {
    validate_unwind_bounded(pe, raw, begin_rva, end_rva, unwind_info_rva, budget)?;
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
    let (epilog_count, epilog_scopes) = if unwind_version == 2 {
        epilog_prefix(
            &raw[off + 4..off + 4 + codes_size],
            end_rva.checked_sub(begin_rva)?,
        )?
    } else {
        (0, Vec::new())
    };
    let (mut unwind_operations, stack_alloc_size, saved_registers) = parse_unwind_operations(
        raw,
        off + 4 + epilog_count * 2,
        unwind_code_count - epilog_count as u8,
    );
    let mut epilog_operations = Vec::new();
    for index in 0..epilog_count {
        let offset = off + 4 + index * 2;
        epilog_operations.push(PeUnwindOperation {
            code_offset: raw[offset],
            op: "UWOP_EPILOG".into(),
            info: raw[offset + 1] >> 4,
            stack_offset: 0,
            description: if index == 0 {
                format!(
                    "epilog size 0x{:X}, flags 0x{:X}",
                    raw[offset],
                    raw[offset + 1] >> 4
                )
            } else {
                format!(
                    "epilog distance from function end 0x{:X}",
                    u32::from(raw[offset]) | (u32::from(raw[offset + 1] >> 4) << 8)
                )
            },
        });
    }
    epilog_operations.append(&mut unwind_operations);
    let unwind_operations = epilog_operations;
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
        epilog_scopes,
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
        let required = match uwop {
            1 if info == 0 => 1,
            1 => 2,
            4 | 8 => 1,
            5 | 9 => 2,
            _ => 0,
        };
        if idx + 1 + required > count as usize {
            break;
        }
        let (name, description) = match uwop {
            0 => {
                saved.push(PeSavedRegister {
                    register: unwind_reg_name(info).to_owned(),
                    stack_offset: stack_alloc,
                    prolog_offset: code_offset,
                });
                stack_alloc = stack_alloc.saturating_add(8);
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
            10 => {
                stack_alloc = stack_alloc.saturating_add(if info == 0 { 40 } else { 48 });
                (
                    "UWOP_PUSH_MACHFRAME",
                    if info == 0 {
                        "push machine frame".to_owned()
                    } else {
                        "push machine frame with error code".to_owned()
                    },
                )
            }
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

#[cfg(test)]
mod unwind_stack_contracts {
    #[test]
    fn version_two_epilog_prefix_separates_size_flags_and_distances() {
        // Same encoding shape as installed ntdll's V2 records; zero is padding.
        let (count, scopes) = super::epilog_prefix(&[7, 0x16, 0x12, 0x06, 7, 0x32], 0x70).unwrap();
        assert_eq!(count, 2);
        assert_eq!((scopes[0].start_offset, scopes[0].end_offset), (0x69, 0x70));
        assert_eq!((scopes[1].start_offset, scopes[1].end_offset), (0x5e, 0x65));
        let (_, scopes) = super::epilog_prefix(&[4, 0x06, 0xe4, 0x16, 0x0b, 0x03], 0x383).unwrap();
        assert_eq!(
            (scopes[0].start_offset, scopes[0].end_offset),
            (0x19f, 0x1a3)
        );
        assert!(super::epilog_prefix(&[1, 0x16, 0, 0x06, 2, 0x02], 0xaf).is_some());
    }
    #[test]
    fn version_two_rejects_bad_epilog_extent_flags_duplicates_and_padding() {
        for bytes in [
            &[0, 0x16][..],
            &[8, 0x26],
            &[8, 0x06],
            &[8, 0x06, 4, 0x06],
            &[8, 0x16, 8, 0x06],
            &[8, 0x16, 0, 0x06, 9, 0x06],
            &[8, 0x06, 0xff, 0xf6],
            &[8],
        ] {
            assert!(super::epilog_prefix(bytes, 0x100).is_none(), "{bytes:?}");
        }
    }
    #[test]
    fn pushed_register_offset_precedes_the_unwind_pop() {
        let (_, total, saved) = super::parse_unwind_operations(&[4, 0x32, 1, 0x30], 0, 2);
        assert_eq!(total, 40);
        assert_eq!(saved[0].register, "rbx");
        assert_eq!(saved[0].stack_offset, 32);
    }

    #[test]
    fn machine_frame_contributes_its_full_stack_size() {
        assert_eq!(super::parse_unwind_operations(&[0, 0x0a], 0, 1).1, 40);
        assert_eq!(super::parse_unwind_operations(&[0, 0x1a], 0, 1).1, 48);
    }
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
    if version_len > super::types::MAX_PE_STRING
        || pe.rva_slice(raw, metadata_rva, 16 + version_len).is_none()
    {
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
    let Some(region) = pe.rva_bytes(raw, callbacks_rva) else {
        return Vec::new();
    };
    let end = off + region.len();
    let mut callbacks = Vec::new();
    for _ in 0..64 {
        if off + width > end {
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
        if !pe
            .rva_to_section(rva)
            .is_some_and(|section| section.is_executable())
            || pe.rva_slice(raw, rva, 1).is_none()
        {
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
mod tests;
