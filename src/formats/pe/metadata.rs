use super::constants::{
    IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR, IMAGE_DIRECTORY_ENTRY_DEBUG,
    IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG,
};
use super::types::{
    read_cstr, read_u16, read_u32, read_u64, PeClrInfo, PeCodeViewInfo, PeDebugEntry, PeDebugInfo,
    PeFile, PeLoadConfigInfo,
};

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

    let (security_cookie_off, se_handler_count_off, guard_cf_count_off, guard_flags_off) =
        if pe.arch == 64 {
            (88usize, 104usize, 136usize, 144usize)
        } else {
            (60usize, 68usize, 84usize, 88usize)
        };
    let (guard_eh_count_off, guard_xfg_check_off) = if pe.arch == 64 {
        (264usize, 272usize)
    } else {
        (168usize, 172usize)
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
