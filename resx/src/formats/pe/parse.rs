use super::types::{anomaly, read_u16, read_u32, read_u64, PeError, PeFile, PeSection};

pub fn parse_pe(raw: &[u8]) -> Result<PeFile, PeError> {
    if raw.len() > super::types::MAX_PE_BYTES {
        return Err(PeError("PE exceeds the 512 MiB analysis limit".to_owned()));
    }
    if raw.len() < 64 {
        return Err(PeError("File too small to be a PE".to_owned()));
    }
    if &raw[0..2] != b"MZ" {
        return Err(PeError("Not a PE file (no MZ header)".to_owned()));
    }

    let e_lfanew = read_u32(raw, 0x3C) as usize;
    if e_lfanew > raw.len().saturating_sub(4) {
        return Err(PeError("e_lfanew out of bounds".to_owned()));
    }
    if &raw[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(PeError("Missing PE signature".to_owned()));
    }

    let mut anomalies = Vec::new();
    if e_lfanew < 0x40 {
        anomalies.push(anomaly(
            "warn",
            "header",
            format!("e_lfanew is unusually small: 0x{:X}", e_lfanew),
        ));
    }

    let coff_off = e_lfanew + 4;
    if coff_off + 20 > raw.len() {
        return Err(PeError("COFF header out of bounds".to_owned()));
    }

    let machine = read_u16(raw, coff_off);
    let timestamp = read_u32(raw, coff_off + 4);
    let coff_characteristics = read_u16(raw, coff_off + 18);
    let num_sections = read_u16(raw, coff_off + 2) as usize;
    let opt_hdr_size = read_u16(raw, coff_off + 16) as usize;

    if num_sections == 0 || num_sections > 96 {
        return Err(PeError(format!(
            "Unsupported section count: {num_sections} (expected 1..=96)"
        )));
    }

    let opt_hdr_off = coff_off + 20;
    if opt_hdr_size < 2
        || opt_hdr_off
            .checked_add(opt_hdr_size)
            .is_none_or(|end| end > raw.len())
    {
        return Err(PeError("Optional header out of bounds".to_owned()));
    }

    let pe_magic = read_u16(raw, opt_hdr_off);
    let major_linker_version = raw.get(opt_hdr_off + 2).copied().unwrap_or_default();
    let minor_linker_version = raw.get(opt_hdr_off + 3).copied().unwrap_or_default();
    let (
        arch,
        image_base,
        num_data_dirs,
        data_dir_off,
        entry_point,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
    ) = match pe_magic {
        0x020B => {
            if opt_hdr_size < 112 {
                return Err(PeError("PE32+ optional header too small".to_owned()));
            }
            (
                64u32,
                read_u64(raw, opt_hdr_off + 24),
                read_u32(raw, opt_hdr_off + 108) as usize,
                opt_hdr_off + 112,
                read_u32(raw, opt_hdr_off + 16),
                read_u32(raw, opt_hdr_off + 32),
                read_u32(raw, opt_hdr_off + 36),
                read_u32(raw, opt_hdr_off + 56),
                read_u32(raw, opt_hdr_off + 60),
                read_u32(raw, opt_hdr_off + 64),
                read_u16(raw, opt_hdr_off + 68),
                read_u16(raw, opt_hdr_off + 70),
            )
        }
        0x010B => {
            if opt_hdr_size < 96 {
                return Err(PeError("PE32 optional header too small".to_owned()));
            }
            (
                32u32,
                read_u32(raw, opt_hdr_off + 28) as u64,
                read_u32(raw, opt_hdr_off + 92) as usize,
                opt_hdr_off + 96,
                read_u32(raw, opt_hdr_off + 16),
                read_u32(raw, opt_hdr_off + 32),
                read_u32(raw, opt_hdr_off + 36),
                read_u32(raw, opt_hdr_off + 56),
                read_u32(raw, opt_hdr_off + 60),
                read_u32(raw, opt_hdr_off + 64),
                read_u16(raw, opt_hdr_off + 68),
                read_u16(raw, opt_hdr_off + 70),
            )
        }
        _ => return Err(PeError(format!("Unknown PE magic: 0x{:04X}", pe_magic))),
    };

    if (matches!(machine, 0x8664 | 0xAA64) && arch != 64)
        || (matches!(machine, 0x014C | 0x01C4) && arch != 32)
    {
        return Err(PeError(
            "Machine and optional-header bitness disagree".to_owned(),
        ));
    }
    if image_base.checked_add(u64::from(size_of_image)).is_none() {
        return Err(PeError("Image VA range overflows".to_owned()));
    }
    if image_base.checked_add(u64::from(size_of_headers)).is_none() {
        return Err(PeError("Header VA range overflows".to_owned()));
    }

    if file_alignment == 0 {
        anomalies.push(anomaly(
            "high",
            "alignment",
            "file alignment is zero".to_owned(),
        ));
    }
    if section_alignment == 0 {
        anomalies.push(anomaly(
            "high",
            "alignment",
            "section alignment is zero".to_owned(),
        ));
    }
    if size_of_headers == 0 || size_of_headers as usize > raw.len() {
        anomalies.push(anomaly(
            "warn",
            "headers",
            format!("SizeOfHeaders is suspicious: 0x{:X}", size_of_headers),
        ));
    }
    if size_of_image < size_of_headers {
        anomalies.push(anomaly(
            "warn",
            "image-size",
            format!(
                "SizeOfImage (0x{:X}) is smaller than SizeOfHeaders (0x{:X})",
                size_of_image, size_of_headers
            ),
        ));
    }

    let mut data_dirs = Vec::new();
    let max_dd = num_data_dirs.min(16);
    for i in 0..max_dd {
        let off = data_dir_off + i * 8;
        if off + 8 > opt_hdr_off + opt_hdr_size {
            anomalies.push(anomaly(
                "warn",
                "data-directory",
                format!("data directory {} extends beyond optional header", i),
            ));
            break;
        }
        let rva = read_u32(raw, off);
        let sz = read_u32(raw, off + 4);
        data_dirs.push((rva, sz));
    }
    while data_dirs.len() < 16 {
        data_dirs.push((0, 0));
    }

    let sections_off = opt_hdr_off + opt_hdr_size;
    if sections_off
        .checked_add(num_sections * 40)
        .is_none_or(|end| end > raw.len())
    {
        return Err(PeError("Declared section table is truncated".to_owned()));
    }
    let mut sections = Vec::with_capacity(num_sections);
    let mut raw_ranges: Vec<(u32, u32, String)> = Vec::new();
    let mut entropy_budget = raw.len();
    for i in 0..num_sections {
        let s = sections_off + i * 40;
        if s + 40 > raw.len() {
            anomalies.push(anomaly(
                "warn",
                "section-header",
                format!("section header {} is truncated", i),
            ));
            break;
        }

        let name = parse_section_name(&raw[s..s + 8]);
        let virtual_size = read_u32(raw, s + 8);
        let virtual_address = read_u32(raw, s + 12);
        let raw_size = read_u32(raw, s + 16);
        let raw_offset = read_u32(raw, s + 20);
        let characteristics = read_u32(raw, s + 36);

        if virtual_address
            .checked_add(virtual_size.max(raw_size))
            .is_none()
            || raw_offset.checked_add(raw_size).is_none()
        {
            return Err(PeError(format!("Section {name} range overflows")));
        }
        if image_base
            .checked_add(u64::from(virtual_address) + u64::from(virtual_size.max(raw_size)))
            .is_none()
        {
            return Err(PeError(format!("Section {name} VA range overflows")));
        }

        if raw_size != 0 {
            let end = raw_offset.saturating_add(raw_size);
            if end as usize > raw.len() {
                anomalies.push(anomaly(
                    "warn",
                    "section-bounds",
                    format!(
                        "section {} raw range 0x{:X}-0x{:X} exceeds file size 0x{:X}",
                        name,
                        raw_offset,
                        end,
                        raw.len()
                    ),
                ));
            } else {
                raw_ranges.push((raw_offset, end, name.clone()));
            }
        }
        if virtual_address == 0 && name != ".text" {
            anomalies.push(anomaly(
                "info",
                "section-rva",
                format!("section {} starts at RVA 0", name),
            ));
        }
        if virtual_size == 0 && raw_size != 0 {
            anomalies.push(anomaly(
                "info",
                "section-size",
                format!(
                    "section {} has zero virtual size but non-zero raw size",
                    name
                ),
            ));
        }

        let entropy = if raw_size as usize <= entropy_budget {
            entropy_budget -= raw_size as usize;
            calc_entropy(raw, raw_offset as usize, raw_size as usize)
        } else {
            anomalies.push(anomaly(
                "warn",
                "entropy-budget",
                format!(
                    "Section {name} exceeds the aggregate entropy byte budget; entropy unavailable"
                ),
            ));
            f64::NAN
        };
        sections.push(PeSection {
            name,
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics,
            entropy,
        });
    }

    raw_ranges.sort_by_key(|(start, _, _)| *start);
    for pair in raw_ranges.windows(2) {
        let (a_start, a_end, a_name) = &pair[0];
        let (b_start, _, b_name) = &pair[1];
        if b_start < a_end {
            anomalies.push(anomaly(
                "warn",
                "section-overlap",
                format!(
                    "raw sections {} and {} overlap (0x{:X}-0x{:X})",
                    a_name, b_name, a_start, a_end
                ),
            ));
        }
    }

    let mut pe = PeFile {
        arch,
        machine,
        timestamp,
        coff_characteristics,
        major_linker_version,
        minor_linker_version,
        image_base,
        entry_point,
        size_of_image,
        size_of_headers,
        section_alignment,
        file_alignment,
        checksum,
        subsystem,
        dll_characteristics,
        sections,
        data_dirs,
        anomalies,
    };

    // A directory address is not authorization to read across adjacent regions.
    // The certificate table uniquely uses file offsets, not RVAs.
    for index in 0..pe.data_dirs.len() {
        let (address, size) = pe.data_dirs[index];
        if address == 0 && size == 0 {
            continue;
        }
        // IMAGE_DIRECTORY_ENTRY_GLOBALPTR describes a single RVA with size zero.
        if index == 8 && address != 0 && size == 0 && pe.rva_slice(raw, address, 1).is_some() {
            continue;
        }
        let valid = address != 0
            && size != 0
            && if index == 4 {
                address % 8 == 0
                    && (address as usize)
                        .checked_add(size as usize)
                        .is_some_and(|end| end <= raw.len())
            } else {
                address.checked_add(size).is_some()
                    && pe.rva_slice(raw, address, size as usize).is_some()
            };
        if !valid {
            // A loader-mapped range with missing disk bytes is unavailable,
            // not an out-of-image pointer. Never traverse its zero-fill as
            // though it were observed metadata. An exception table may be
            // populated by startup code; loader-consumed directories still
            // require validation before RESX permits a launch.
            let unavailable = index != 4
                && address != 0
                && size != 0
                && super::validation::mapped(&pe, address, size);
            let deferred_exception = unavailable
                && index == 3
                && pe.machine == 0x8664
                && address % 4 == 0
                && size % 12 == 0
                && size / 12 <= super::types::MAX_PE_ENTRIES as u32;
            pe.anomalies.push(anomaly(
                if deferred_exception { "info" } else { "high" },
                if unavailable { "data-directory-unavailable" } else { "data-directory" },
                if unavailable {
                    format!("Directory {index} at RVA 0x{address:X}, size 0x{size:X}, is mapped but not fully file-backed; contents unknown and traversal disabled. Runtime bytes require fresh validation")
                } else {
                    format!("Directory {index} has an invalid range; traversal disabled")
                },
            ));
            pe.data_dirs[index] = (0, 0);
        }
    }
    let mut virtual_ranges: Vec<_> = pe
        .sections
        .iter()
        .map(|s| {
            (
                s.virtual_address,
                s.virtual_address + s.virtual_size.max(s.raw_size),
            )
        })
        .collect();
    virtual_ranges.sort_unstable();
    if virtual_ranges.windows(2).any(|pair| pair[1].0 < pair[0].1) {
        pe.anomalies.push(anomaly(
            "high",
            "virtual-overlap",
            "Overlapping virtual sections; ambiguous RVA mappings are rejected".to_owned(),
        ));
    }
    if num_data_dirs > 16 {
        pe.anomalies.push(anomaly(
            "warn",
            "data-directory",
            "Extra nonstandard data directories are not interpreted".to_owned(),
        ));
    }

    pe.anomalies
        .extend(super::metadata::metadata_anomalies(&pe, raw));
    pe.anomalies.extend(super::validation::check(&pe, raw));
    if pe.entry_point != 0 && pe.rva_to_section(pe.entry_point).is_none() {
        let mut pe = pe;
        pe.anomalies.push(anomaly(
            "warn",
            "entry-point",
            format!(
                "entry point RVA 0x{:08X} does not fall inside any section",
                pe.entry_point
            ),
        ));
        return Ok(pe);
    }

    Ok(pe)
}

fn parse_section_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

fn calc_entropy(raw: &[u8], offset: usize, size: usize) -> f64 {
    if size == 0 || offset >= raw.len() {
        return 0.0;
    }
    let end = offset.saturating_add(size).min(raw.len());
    let slice = &raw[offset..end];
    if slice.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in slice {
        counts[b as usize] += 1;
    }

    let len = slice.len() as f64;
    let mut entropy = 0.0f64;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
}

#[cfg(test)]
mod section_name_tests {
    #[test]
    fn section_names_preserve_spaces_and_stop_at_nul_only() {
        assert_eq!(super::parse_section_name(b"        "), "        ");
        assert_eq!(super::parse_section_name(b" .text  "), " .text  ");
        assert_eq!(super::parse_section_name(b".text\0xx"), ".text");
    }

    fn image_with_directory(index: usize, rva: u32, size: u32) -> Vec<u8> {
        let mut raw = vec![0u8; 0x400];
        raw[..2].copy_from_slice(b"MZ");
        raw[0x3c..0x40].copy_from_slice(&0x80u32.to_le_bytes());
        raw[0x80..0x84].copy_from_slice(b"PE\0\0");
        raw[0x84..0x86].copy_from_slice(&0x8664u16.to_le_bytes());
        raw[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
        raw[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
        raw[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
        for (offset, value) in [
            (32, 0x1000u32),
            (36, 0x200),
            (56, 0x2000),
            (60, 0x200),
            (108, 16),
        ] {
            raw[0x98 + offset..0x9c + offset].copy_from_slice(&value.to_le_bytes());
        }
        let directory = 0x108 + index * 8;
        raw[directory..directory + 4].copy_from_slice(&rva.to_le_bytes());
        raw[directory + 4..directory + 8].copy_from_slice(&size.to_le_bytes());
        for (offset, value) in [
            (8, 0x1000u32),
            (12, 0x1000),
            (16, 0x200),
            (20, 0x200),
            (36, 0x60000020),
        ] {
            raw[0x188 + offset..0x18c + offset].copy_from_slice(&value.to_le_bytes());
        }
        raw
    }

    fn exercise_all_readers(raw: &[u8]) {
        if let Ok(pe) = super::parse_pe(raw) {
            let _ = crate::formats::pe::read_exports(&pe, raw);
            let _ = crate::formats::pe::read_imports(&pe, raw);
            let _ = crate::formats::pe::read_debug_info(&pe, raw);
            let _ = crate::formats::pe::read_load_config(&pe, raw);
            let _ = crate::formats::pe::read_runtime_functions(&pe, raw);
            let _ = crate::formats::pe::read_data_summary(&pe, raw);
            let _ = crate::formats::pe::read_tls_info(&pe, raw);
            let _ = crate::formats::pe::find_startup_routines(&pe, raw);
            let _ = super::super::validation::check(&pe, raw);
        }
    }

    #[test]
    fn deterministic_hostile_pe_mutations_never_panic_any_reader() {
        let original = image_with_directory(0, 0, 0);
        for end in 0..=original.len() {
            exercise_all_readers(&original[..end]);
        }
        for offset in 0..original.len() {
            for value in [0, 0xff] {
                let mut changed = original.clone();
                changed[offset] = value;
                exercise_all_readers(&changed);
            }
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..2048 {
            let mut changed = original.clone();
            for _ in 0..16 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                let offset = state as usize % changed.len();
                changed[offset] = (state >> 24) as u8;
            }
            exercise_all_readers(&changed);
        }
    }

    #[test]
    fn missing_exception_bytes_are_unknown_and_never_parsed_as_zeros() {
        let raw = image_with_directory(3, 0x1500, 12);
        let pe = super::parse_pe(&raw).unwrap();
        assert!(!pe.header_corruption_detected());
        assert_eq!(pe.data_dir(3), (0, 0));
        assert!(pe
            .anomalies
            .iter()
            .any(|a| a.kind == "data-directory-unavailable"));
        assert!(crate::formats::pe::read_runtime_functions(&pe, &raw).is_empty());
    }

    #[test]
    fn invalid_or_loader_consumed_directories_remain_blocking() {
        for (index, rva, size) in [
            (3, 0x1ffc, 12),
            (3, u32::MAX - 3, 12),
            (3, 0x1500, 13),
            (3, 0x1501, 12),
            (1, 0x1500, 20),
            (9, 0x1500, 40),
            (4, 0x1500, 12),
        ] {
            let pe = super::parse_pe(&image_with_directory(index, rva, size)).unwrap();
            assert!(
                pe.header_corruption_detected(),
                "directory {index}: {rva:x}+{size:x}"
            );
            assert_eq!(pe.data_dir(index), (0, 0));
        }
    }
}
