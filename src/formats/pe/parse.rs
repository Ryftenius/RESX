use super::types::{anomaly, read_u16, read_u32, read_u64, PeError, PeFile, PeSection};

pub fn parse_pe(raw: &[u8]) -> Result<PeFile, PeError> {
    if raw.len() < 64 {
        return Err(PeError("File too small to be a PE".to_owned()));
    }
    if &raw[0..2] != b"MZ" {
        return Err(PeError("Not a PE file (no MZ header)".to_owned()));
    }

    let e_lfanew = read_u32(raw, 0x3C) as usize;
    if e_lfanew + 4 > raw.len() {
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

    if num_sections == 0 {
        anomalies.push(anomaly(
            "high",
            "section-count",
            "PE has zero sections".to_owned(),
        ));
    } else if num_sections > 96 {
        anomalies.push(anomaly(
            "warn",
            "section-count",
            format!("PE has an unusually high section count: {}", num_sections),
        ));
    }

    let opt_hdr_off = coff_off + 20;
    if opt_hdr_off + 2 > raw.len() {
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
            if opt_hdr_off + 112 > raw.len() {
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
            if opt_hdr_off + 96 > raw.len() {
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

    let arch = match machine {
        0x8664 | 0xAA64 => 64,
        _ => {
            if arch == 64 {
                64
            } else {
                32
            }
        }
    };

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
        if off + 8 > raw.len() {
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
    let mut sections = Vec::with_capacity(num_sections);
    let mut raw_ranges: Vec<(u32, u32, String)> = Vec::new();
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

        let entropy = calc_entropy(raw, raw_offset as usize, raw_size as usize);
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

    let pe = PeFile {
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
    String::from_utf8_lossy(&bytes[..end]).trim().to_owned()
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
