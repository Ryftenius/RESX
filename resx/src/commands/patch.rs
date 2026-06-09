use std::io::Write;
use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use crate::core::search::find_dll_path;
use crate::formats::pe::{parse_pe, PeFile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressSource {
    Rva,
    Va,
    FileOffset,
}

#[derive(Debug, Clone, Copy)]
struct ResolvedPatchAddress {
    rva: u32,
    file_offset: usize,
    source: AddressSource,
}

#[derive(Debug, Serialize)]
struct PatchReport {
    image: String,
    source_path: String,
    output_path: Option<String>,
    dry_run: bool,
    in_place: bool,
    address: PatchAddressReport,
    bytes: PatchBytesReport,
    write: PatchWriteReport,
    checksum: PatchChecksumReport,
    notes: Vec<String>,
}

#[derive(Debug, Serialize)]
struct PatchAddressReport {
    input: String,
    source: String,
    rva: String,
    va: String,
    file_offset: String,
    section: String,
}

#[derive(Debug, Serialize)]
struct PatchBytesReport {
    length: usize,
    expected: Option<String>,
    original: String,
    replacement: String,
    changed: bool,
}

#[derive(Debug, Serialize)]
struct PatchWriteReport {
    performed: bool,
    overwrite: bool,
}

#[derive(Debug, Serialize)]
struct PatchChecksumReport {
    requested: bool,
    updated: bool,
    old: String,
    new: Option<String>,
}

pub fn run(
    dll_arg: &str,
    func_arg: &str,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    if dll_arg.is_empty() {
        return Err("Use `resx patch <image> --at <addr> --patch-bytes <hex>`".to_owned());
    }

    let address_spec = if !cfg.at_rva.is_empty() {
        cfg.at_rva.as_str()
    } else if !func_arg.is_empty() {
        func_arg
    } else {
        return Err("patch requires --at <addr> or `resx patch <image> <addr> <hex>`".to_owned());
    };

    let patch_spec = patch_bytes_spec(func_arg, cfg)?;
    let patch_bytes = parse_hex_bytes(&patch_spec)?;
    let expected_bytes = if cfg.patch_expect.trim().is_empty() {
        None
    } else {
        Some(parse_hex_bytes(&cfg.patch_expect)?)
    };
    if let Some(expected) = expected_bytes.as_ref() {
        if expected.len() != patch_bytes.len() {
            return Err(format!(
                "--expect length ({}) must match --patch-bytes length ({})",
                expected.len(),
                patch_bytes.len()
            ));
        }
    }

    if cfg.patch_in_place && !cfg.patch_out.is_empty() {
        return Err("use either --in-place or --patch-out, not both".to_owned());
    }

    let dll_path = find_dll_path(dll_arg, cfg)?;
    let image = dll_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let mut raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let address = resolve_patch_address(address_spec, &pe)?;
    let section = pe
        .rva_to_section(address.rva)
        .ok_or_else(|| format!("RVA 0x{:08X}: not in any section", address.rva))?;

    let patch_end = address
        .file_offset
        .checked_add(patch_bytes.len())
        .ok_or_else(|| "patch range overflowed file offset math".to_owned())?;
    if patch_end > raw.len() {
        return Err(format!(
            "patch range file:0x{:X}..0x{:X} extends past end of file 0x{:X}",
            address.file_offset,
            patch_end,
            raw.len()
        ));
    }

    let section_raw_start = section.raw_offset as usize;
    let section_raw_end = section_raw_start.saturating_add(section.raw_size as usize);
    if section.raw_size == 0
        || address.file_offset < section_raw_start
        || patch_end > section_raw_end
    {
        return Err(format!(
            "patch range file:0x{:X}..0x{:X} crosses raw bounds for section {}",
            address.file_offset, patch_end, section.name
        ));
    }

    let original = raw[address.file_offset..patch_end].to_vec();
    if let Some(expected) = expected_bytes.as_ref() {
        if expected.as_slice() != original.as_slice() {
            return Err(format!(
                "--expect mismatch at file:0x{:X}: expected {}, found {}",
                address.file_offset,
                format_hex_bytes(expected),
                format_hex_bytes(&original)
            ));
        }
    }

    raw[address.file_offset..patch_end].copy_from_slice(&patch_bytes);

    let mut notes = vec![
        "byte patching only; instruction assembly, code caves, relocation edits, and section growth are not performed".to_owned(),
        "patching invalidates Authenticode signatures on signed images".to_owned(),
    ];

    let old_checksum = pe.checksum;
    let mut new_checksum = None;
    if cfg.patch_update_checksum {
        let checksum_offset = checksum_field_offset(&raw)
            .ok_or_else(|| "could not locate PE optional-header checksum field".to_owned())?;
        let checksum = compute_pe_checksum(&raw)?;
        raw[checksum_offset..checksum_offset + 4].copy_from_slice(&checksum.to_le_bytes());
        new_checksum = Some(checksum);
    } else {
        notes
            .push("PE checksum was not recalculated; use --update-checksum when needed".to_owned());
    }

    let output_path = target_output_path(&dll_path, cfg);
    let write_performed = !cfg.patch_dry_run;
    if write_performed {
        let target = output_path
            .as_ref()
            .ok_or_else(|| "internal error: missing patch output path".to_owned())?;
        if !cfg.patch_in_place && target.exists() && !cfg.patch_overwrite {
            return Err(format!(
                "output file already exists: {}; use --overwrite or choose --patch-out",
                target.display()
            ));
        }
        std::fs::write(target, &raw).map_err(|e| format!("write patched image: {}", e))?;
    }

    let report = PatchReport {
        image,
        source_path: dll_path.display().to_string(),
        output_path: output_path.as_ref().map(|path| path.display().to_string()),
        dry_run: cfg.patch_dry_run,
        in_place: cfg.patch_in_place,
        address: PatchAddressReport {
            input: address_spec.to_owned(),
            source: address_source_name(address.source).to_owned(),
            rva: format!("0x{:08X}", address.rva),
            va: format!("0x{:X}", pe.image_base + address.rva as u64),
            file_offset: format!("0x{:08X}", address.file_offset),
            section: section.name.clone(),
        },
        bytes: PatchBytesReport {
            length: patch_bytes.len(),
            expected: expected_bytes.as_ref().map(|bytes| format_hex_bytes(bytes)),
            original: format_hex_bytes(&original),
            replacement: format_hex_bytes(&patch_bytes),
            changed: original != patch_bytes,
        },
        write: PatchWriteReport {
            performed: write_performed,
            overwrite: cfg.patch_overwrite || cfg.patch_in_place,
        },
        checksum: PatchChecksumReport {
            requested: cfg.patch_update_checksum,
            updated: new_checksum.is_some(),
            old: format!("0x{old_checksum:08X}"),
            new: new_checksum.map(|value| format!("0x{value:08X}")),
        },
        notes,
    };

    if cfg.json {
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&versioned_object("patch", &report)).unwrap_or_default()
        )
        .ok();
        return Ok(());
    }

    print_patch_report(&report, w, c);
    Ok(())
}

fn patch_bytes_spec(func_arg: &str, cfg: &Config) -> Result<String, String> {
    if !cfg.patch_bytes.trim().is_empty() {
        let mut pieces = vec![cfg.patch_bytes.clone()];
        if !cfg.at_rva.is_empty() && !func_arg.trim().is_empty() {
            pieces.push(func_arg.to_owned());
        }
        pieces.extend(cfg.extra_diff_images.iter().cloned());
        return Ok(pieces.join(" "));
    }
    if !cfg.at_rva.is_empty() && !func_arg.trim().is_empty() {
        let mut pieces = vec![func_arg.to_owned()];
        pieces.extend(cfg.extra_diff_images.iter().cloned());
        return Ok(pieces.join(" "));
    }
    Err("patch requires --patch-bytes <hex>".to_owned())
}

fn print_patch_report(report: &PatchReport, w: &mut dyn Write, c: &Colors) {
    writeln!(w, "{}", c.bold(&format!("Patch: {}", report.image))).ok();
    writeln!(
        w,
        "  target : {} {} ({}, {}, section {})",
        report.address.source,
        report.address.input,
        report.address.rva,
        report.address.file_offset,
        report.address.section
    )
    .ok();
    writeln!(
        w,
        "  bytes  : {} -> {}",
        c.dim(&report.bytes.original),
        c.b_yellow(&report.bytes.replacement)
    )
    .ok();
    if let Some(expected) = report.bytes.expected.as_ref() {
        writeln!(w, "  expect : {}", expected).ok();
    }
    if report.dry_run {
        writeln!(w, "  write  : {}", c.warn("dry-run; no file written")).ok();
    } else if let Some(output) = report.output_path.as_ref() {
        writeln!(w, "  write  : {}", c.ok(output)).ok();
    }
    if report.checksum.updated {
        if let Some(new) = report.checksum.new.as_ref() {
            writeln!(w, "  cksum  : {} -> {}", report.checksum.old, c.ok(new)).ok();
        }
    } else {
        writeln!(w, "  cksum  : {}", c.dim("unchanged")).ok();
    }
    for note in &report.notes {
        writeln!(w, "  note   : {}", c.dim(note)).ok();
    }
}

fn target_output_path(source: &Path, cfg: &Config) -> Option<PathBuf> {
    if cfg.patch_in_place {
        return Some(source.to_path_buf());
    }
    if !cfg.patch_out.is_empty() {
        return Some(PathBuf::from(&cfg.patch_out));
    }
    Some(default_patch_path(source))
}

fn default_patch_path(source: &Path) -> PathBuf {
    let stem = source
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = source.extension().map(|value| value.to_string_lossy());
    let file_name = match ext {
        Some(ext) if !ext.is_empty() => format!("{stem}.patched.{ext}"),
        _ => format!("{stem}.patched"),
    };
    source.with_file_name(file_name)
}

fn resolve_patch_address(raw: &str, pe: &PeFile) -> Result<ResolvedPatchAddress, String> {
    let (forced_source, value_text) = split_address_source_prefix(raw);
    let value =
        parse_u64_literal(value_text).ok_or_else(|| format!("invalid patch address: {}", raw))?;

    if let Some(source) = forced_source {
        return resolve_forced_address(raw, value, source, pe);
    }

    if let Some(rva) = pe.va_to_rva(value) {
        return address_from_rva(rva, AddressSource::Va, pe);
    }

    if let Ok(rva) = u32::try_from(value) {
        if pe.rva_to_section(rva).is_some() {
            return address_from_rva(rva, AddressSource::Rva, pe);
        }
    }

    if let Some(rva) = pe.file_offset_to_rva(value) {
        let file_offset = usize::try_from(value)
            .map_err(|_| format!("file offset 0x{value:X}: too large for this host"))?;
        return Ok(ResolvedPatchAddress {
            rva,
            file_offset,
            source: AddressSource::FileOffset,
        });
    }

    Err(format!(
        "address `{raw}` did not map to a PE VA, RVA, or file offset"
    ))
}

fn resolve_forced_address(
    raw: &str,
    value: u64,
    source: AddressSource,
    pe: &PeFile,
) -> Result<ResolvedPatchAddress, String> {
    match source {
        AddressSource::Rva => {
            let rva =
                u32::try_from(value).map_err(|_| format!("RVA `{raw}` is larger than 32 bits"))?;
            if pe.rva_to_section(rva).is_none() {
                return Err(format!("RVA 0x{rva:08X}: not in any section"));
            }
            address_from_rva(rva, source, pe)
        }
        AddressSource::Va => {
            let rva = pe
                .va_to_rva(value)
                .ok_or_else(|| format!("VA 0x{value:X}: not in this image"))?;
            address_from_rva(rva, source, pe)
        }
        AddressSource::FileOffset => {
            let rva = pe
                .file_offset_to_rva(value)
                .ok_or_else(|| format!("file offset 0x{value:X}: not in any section"))?;
            let file_offset = usize::try_from(value)
                .map_err(|_| format!("file offset 0x{value:X}: too large for this host"))?;
            Ok(ResolvedPatchAddress {
                rva,
                file_offset,
                source,
            })
        }
    }
}

fn address_from_rva(
    rva: u32,
    source: AddressSource,
    pe: &PeFile,
) -> Result<ResolvedPatchAddress, String> {
    let file_offset = pe
        .rva_to_offset(rva)
        .ok_or_else(|| format!("RVA 0x{rva:08X}: not backed by raw file data"))?;
    Ok(ResolvedPatchAddress {
        rva,
        file_offset,
        source,
    })
}

fn split_address_source_prefix(raw: &str) -> (Option<AddressSource>, &str) {
    let trimmed = raw.trim();
    let Some((prefix, value)) = trimmed.split_once(':') else {
        return (None, trimmed);
    };
    let source = match prefix.to_ascii_lowercase().as_str() {
        "rva" => AddressSource::Rva,
        "va" => AddressSource::Va,
        "fo" | "file" | "offset" | "fileoff" | "file-offset" => AddressSource::FileOffset,
        _ => return (None, trimmed),
    };
    (Some(source), value.trim())
}

fn address_source_name(source: AddressSource) -> &'static str {
    match source {
        AddressSource::Rva => "rva",
        AddressSource::Va => "va",
        AddressSource::FileOffset => "file-offset",
    }
}

fn parse_u64_literal(raw: &str) -> Option<u64> {
    let value = raw.trim().trim_end_matches(',');
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .or_else(|| value.strip_suffix('h'))
        .or_else(|| value.strip_suffix('H'));
    if let Some(hex) = hex {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u64>().ok()
    }
}

fn parse_hex_bytes(raw: &str) -> Result<Vec<u8>, String> {
    let mut normalized = raw
        .trim()
        .replace("\\x", " ")
        .replace("\\X", " ")
        .replace("0x", " ")
        .replace("0X", " ");
    for sep in [',', ';', ':', '-', '_', '\r', '\n', '\t'] {
        normalized = normalized.replace(sep, " ");
    }

    let mut out = Vec::new();
    for token in normalized.split_whitespace() {
        if token.is_empty() {
            continue;
        }
        if !token.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(format!("invalid hex byte token `{token}`"));
        }
        if token.len() <= 2 {
            out.push(
                u8::from_str_radix(token, 16)
                    .map_err(|_| format!("invalid hex byte token `{token}`"))?,
            );
            continue;
        }
        if token.len() % 2 != 0 {
            return Err(format!("hex byte string `{token}` has odd length"));
        }
        let mut idx = 0;
        while idx < token.len() {
            let byte = &token[idx..idx + 2];
            out.push(
                u8::from_str_radix(byte, 16)
                    .map_err(|_| format!("invalid hex byte token `{byte}`"))?,
            );
            idx += 2;
        }
    }

    if out.is_empty() {
        return Err("patch byte string is empty".to_owned());
    }
    Ok(out)
}

fn format_hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(" ")
}

fn checksum_field_offset(raw: &[u8]) -> Option<usize> {
    let pe_offset = read_u32(raw, 0x3C)? as usize;
    let signature_end = pe_offset.checked_add(4)?;
    if raw.get(pe_offset..signature_end)? != b"PE\0\0" {
        return None;
    }
    let optional_header = pe_offset.checked_add(24)?;
    let checksum_offset = optional_header.checked_add(64)?;
    let checksum_end = checksum_offset.checked_add(4)?;
    raw.get(checksum_offset..checksum_end)?;
    Some(checksum_offset)
}

fn compute_pe_checksum(raw: &[u8]) -> Result<u32, String> {
    let checksum_offset = checksum_field_offset(raw)
        .ok_or_else(|| "could not locate PE optional-header checksum field".to_owned())?;
    let mut sum = 0u64;
    let mut idx = 0usize;
    while idx + 1 < raw.len() {
        if idx == checksum_offset || idx == checksum_offset + 2 {
            idx += 2;
            continue;
        }
        let word = u16::from_le_bytes([raw[idx], raw[idx + 1]]) as u64;
        sum = (sum & 0xFFFF) + word + (sum >> 16);
        idx += 2;
    }
    if idx < raw.len() {
        sum = (sum & 0xFFFF) + raw[idx] as u64 + (sum >> 16);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    Ok((sum as u32).wrapping_add(raw.len() as u32))
}

fn read_u32(raw: &[u8], offset: usize) -> Option<u32> {
    let bytes = raw.get(offset..offset + 4)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{
        default_patch_path, format_hex_bytes, parse_hex_bytes, resolve_patch_address, AddressSource,
    };
    use crate::formats::pe::{PeAnomaly, PeFile, PeSection};

    fn sample_pe() -> PeFile {
        PeFile {
            arch: 64,
            machine: 0x8664,
            timestamp: 0,
            coff_characteristics: 0,
            major_linker_version: 0,
            minor_linker_version: 0,
            image_base: 0x1_8000_0000,
            entry_point: 0x1200,
            size_of_image: 0x3000,
            size_of_headers: 0x400,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            checksum: 0,
            subsystem: 3,
            dll_characteristics: 0,
            sections: vec![PeSection {
                name: ".text".to_owned(),
                virtual_address: 0x1000,
                virtual_size: 0x600,
                raw_offset: 0x400,
                raw_size: 0x800,
                characteristics: 0,
                entropy: 0.0,
            }],
            data_dirs: vec![(0, 0); 16],
            anomalies: Vec::<PeAnomaly>::new(),
        }
    }

    #[test]
    fn parse_hex_bytes_accepts_common_re_forms() {
        for raw in ["90 90 CC", "9090CC", "0x90,0x90,0xCC", "\\x90\\x90\\xCC"] {
            let bytes = parse_hex_bytes(raw).unwrap();
            assert_eq!(bytes, vec![0x90, 0x90, 0xCC], "{raw}");
        }
    }

    #[test]
    fn parse_hex_bytes_rejects_odd_dense_strings() {
        assert!(parse_hex_bytes("909").is_err());
    }

    #[test]
    fn format_hex_bytes_uses_operator_readable_spacing() {
        assert_eq!(format_hex_bytes(&[0x40, 0x55, 0xCC]), "40 55 CC");
    }

    #[test]
    fn resolve_patch_address_accepts_rva_va_and_file_offset() {
        let pe = sample_pe();

        let rva = resolve_patch_address("0x1200", &pe).unwrap();
        assert_eq!(rva.rva, 0x1200);
        assert_eq!(rva.file_offset, 0x600);
        assert_eq!(rva.source, AddressSource::Rva);

        let va = resolve_patch_address("0x180001200", &pe).unwrap();
        assert_eq!(va.rva, 0x1200);
        assert_eq!(va.file_offset, 0x600);
        assert_eq!(va.source, AddressSource::Va);

        let file = resolve_patch_address("file:0x600", &pe).unwrap();
        assert_eq!(file.rva, 0x1200);
        assert_eq!(file.file_offset, 0x600);
        assert_eq!(file.source, AddressSource::FileOffset);
    }

    #[test]
    fn resolve_patch_address_falls_back_to_file_offset_when_rva_is_unmapped() {
        let pe = sample_pe();
        let file = resolve_patch_address("0x600", &pe).unwrap();
        assert_eq!(file.rva, 0x1200);
        assert_eq!(file.file_offset, 0x600);
        assert_eq!(file.source, AddressSource::FileOffset);
    }

    #[test]
    fn default_patch_path_inserts_patched_before_extension() {
        let path = default_patch_path(Path::new(r"C:\work\sample.dll"));
        assert_eq!(
            path.file_name().unwrap().to_string_lossy(),
            "sample.patched.dll"
        );
    }
}
