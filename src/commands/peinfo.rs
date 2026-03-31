use std::ffi::OsStr;
use std::io::Write;

use serde::Serialize;

use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::output::{print_pe_anomalies, print_sections, StageProgress};
use crate::core::search::find_dll_path;
use crate::formats::metadata::{query_file_metadata, FileMetadata};
use crate::formats::pe::{parse_pe, read_exports, read_imports, PeAnomaly, PeSection};

#[derive(Serialize)]
struct PeInfoJson {
    path: String,
    file_name: String,
    file_size: u64,
    arch: String,
    machine: String,
    timestamp: String,
    image_base: String,
    entry_point: String,
    size_of_image: String,
    size_of_headers: String,
    section_alignment: String,
    file_alignment: String,
    checksum: String,
    subsystem: String,
    dll_characteristics: String,
    coff_characteristics: String,
    header_corrupt: bool,
    export_count: usize,
    import_dll_count: usize,
    import_count: usize,
    names: NameJson,
    signer: SignerJson,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sections: Vec<SectionJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    anomalies: Vec<AnomalyJson>,
}

#[derive(Serialize)]
struct NameJson {
    #[serde(skip_serializing_if = "String::is_empty")]
    product_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    file_description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    company_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    original_filename: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    internal_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    known_names: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    file_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    product_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    comments: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    legal_copyright: String,
}

#[derive(Serialize)]
struct SignerJson {
    status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    subject: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    issuer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    thumbprint: String,
}

#[derive(Serialize)]
struct SectionJson {
    name: String,
    rva: String,
    virtual_size: String,
    raw_size: String,
    tag: String,
    protection: String,
    expected: String,
    entropy: f64,
    #[serde(skip_serializing_if = "String::is_empty")]
    note: String,
}

#[derive(Serialize)]
struct AnomalyJson {
    severity: String,
    kind: String,
    detail: String,
}

pub fn run(dll_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let mut progress = StageProgress::new(6, !cfg.quiet && !cfg.json, c.on);
    if !cfg.quiet && !cfg.json {
        writeln!(
            w,
            "{}",
            c.info(&format!("Collecting PE info for '{}'...", dll_arg))
        )
        .ok();
    }

    let dll_path = find_dll_path(dll_arg, cfg)?;
    progress.tick("locating target image");
    let dll_path_str = dll_path.to_string_lossy().to_string();
    let file_name = dll_path
        .file_name()
        .unwrap_or_else(|| OsStr::new(""))
        .to_string_lossy()
        .to_string();
    let raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    progress.tick("reading image");
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    progress.tick("parsing PE headers");
    let exports = read_exports(&pe, &raw);
    progress.tick("reading export table");
    let imports = read_imports(&pe, &raw);
    progress.tick("reading import table");
    let import_count: usize = imports.iter().map(|d| d.entries.len()).sum();
    let metadata = query_file_metadata(&dll_path_str).unwrap_or_default();
    progress.tick("querying file metadata");
    progress.finish();
    let known_names = collect_known_names(&file_name, &metadata);

    if cfg.json {
        let out = PeInfoJson {
            path: dll_path_str,
            file_name,
            file_size: raw.len() as u64,
            arch: format!("x{}", pe.arch),
            machine: machine_name(pe.machine).to_owned(),
            timestamp: format!("0x{:08X}", pe.timestamp),
            image_base: format!("0x{:016X}", pe.image_base),
            entry_point: format!("0x{:08X}", pe.entry_point),
            size_of_image: format!("0x{:08X}", pe.size_of_image),
            size_of_headers: format!("0x{:08X}", pe.size_of_headers),
            section_alignment: format!("0x{:08X}", pe.section_alignment),
            file_alignment: format!("0x{:08X}", pe.file_alignment),
            checksum: format!("0x{:08X}", pe.checksum),
            subsystem: format!("0x{:04X}", pe.subsystem),
            dll_characteristics: format!("0x{:04X}", pe.dll_characteristics),
            coff_characteristics: format!("0x{:04X}", pe.coff_characteristics),
            header_corrupt: pe.header_corruption_detected(),
            export_count: exports.len(),
            import_dll_count: imports.len(),
            import_count,
            names: NameJson {
                product_name: metadata.product_name.clone(),
                file_description: metadata.file_description.clone(),
                company_name: metadata.company_name.clone(),
                original_filename: metadata.original_filename.clone(),
                internal_name: metadata.internal_name.clone(),
                known_names,
                file_version: metadata.file_version.clone(),
                product_version: metadata.product_version.clone(),
                comments: metadata.comments.clone(),
                legal_copyright: metadata.legal_copyright.clone(),
            },
            signer: SignerJson {
                status: blank_as_unknown(&metadata.signature_status),
                subject: metadata.signer_subject.clone(),
                issuer: metadata.signer_issuer.clone(),
                thumbprint: metadata.signer_thumbprint.clone(),
            },
            sections: pe.sections.iter().map(to_section_json).collect(),
            anomalies: pe.anomalies.iter().map(to_anomaly_json).collect(),
        };
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_default()
        )
        .ok();
        return Ok(());
    }

    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_yellow("General PE Info:"))).ok();
    print_kv(w, c, "Path", &dll_path_str);
    print_kv(w, c, "FileName", &file_name);
    print_kv(w, c, "FileSize", &format!("{} bytes", raw.len()));
    print_kv(w, c, "Arch", &format!("x{}", pe.arch));
    print_kv(w, c, "Machine", machine_name(pe.machine));
    print_kv(w, c, "Timestamp", &format!("0x{:08X}", pe.timestamp));
    print_kv(w, c, "ImageBase", &format!("0x{:016X}", pe.image_base));
    print_kv(w, c, "EntryPoint", &format!("0x{:08X}", pe.entry_point));
    print_kv(w, c, "SizeOfImage", &format!("0x{:08X}", pe.size_of_image));
    print_kv(
        w,
        c,
        "SizeOfHeaders",
        &format!("0x{:08X}", pe.size_of_headers),
    );
    print_kv(
        w,
        c,
        "SectionAlignment",
        &format!("0x{:08X}", pe.section_alignment),
    );
    print_kv(
        w,
        c,
        "FileAlignment",
        &format!("0x{:08X}", pe.file_alignment),
    );
    print_kv(w, c, "Checksum", &format!("0x{:08X}", pe.checksum));
    print_kv(w, c, "Subsystem", &format!("0x{:04X}", pe.subsystem));
    print_kv(
        w,
        c,
        "DLLCharacteristics",
        &format!("0x{:04X}", pe.dll_characteristics),
    );
    print_kv(
        w,
        c,
        "COFFCharacteristics",
        &format!("0x{:04X}", pe.coff_characteristics),
    );
    print_kv(w, c, "Exports", &exports.len().to_string());
    print_kv(w, c, "ImportDLLs", &imports.len().to_string());
    print_kv(w, c, "Imports", &import_count.to_string());

    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_blue("Names / Version:"))).ok();
    print_optional_kv(w, c, "ProductName", &metadata.product_name);
    print_optional_kv(w, c, "FileDescription", &metadata.file_description);
    print_optional_kv(w, c, "CompanyName", &metadata.company_name);
    print_optional_kv(w, c, "OriginalFilename", &metadata.original_filename);
    print_optional_kv(w, c, "InternalName", &metadata.internal_name);
    if !known_names.is_empty() {
        print_kv(w, c, "KnownNames", &known_names.join(", "));
    }
    print_optional_kv(w, c, "FileVersion", &metadata.file_version);
    print_optional_kv(w, c, "ProductVersion", &metadata.product_version);
    print_optional_kv(w, c, "Comments", &metadata.comments);
    print_optional_kv(w, c, "Copyright", &metadata.legal_copyright);

    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_mag("Signer / Authenticode:"))).ok();
    print_kv(
        w,
        c,
        "Status",
        &blank_as_unknown(&metadata.signature_status),
    );
    print_optional_kv(w, c, "Subject", &metadata.signer_subject);
    print_optional_kv(w, c, "Issuer", &metadata.signer_issuer);
    print_optional_kv(w, c, "Thumbprint", &metadata.signer_thumbprint);

    print_sections(w, &pe, c);
    print_pe_anomalies(w, &pe.anomalies, c);
    Ok(())
}

fn print_kv(w: &mut dyn Write, c: &Colors, key: &str, value: &str) {
    writeln!(w, "  {:<18} {}", c.bold(key), value).ok();
}

fn print_optional_kv(w: &mut dyn Write, c: &Colors, key: &str, value: &str) {
    if !value.trim().is_empty() {
        print_kv(w, c, key, value);
    }
}

fn blank_as_unknown(value: &str) -> String {
    if value.trim().is_empty() {
        "Unknown".to_owned()
    } else {
        value.to_owned()
    }
}

fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014C => "I386",
        0x8664 => "AMD64",
        0xAA64 => "ARM64",
        0x01C4 => "ARMNT",
        _ => "Unknown",
    }
}

fn collect_known_names(file_name: &str, meta: &FileMetadata) -> Vec<String> {
    let mut out = Vec::new();
    for candidate in [file_name, &meta.original_filename, &meta.internal_name] {
        let trimmed = candidate.trim();
        if !trimmed.is_empty() && !out.iter().any(|v: &String| v.eq_ignore_ascii_case(trimmed)) {
            out.push(trimmed.to_owned());
        }
    }
    out
}

fn to_section_json(section: &PeSection) -> SectionJson {
    SectionJson {
        name: section.name.clone(),
        rva: format!("0x{:08X}", section.virtual_address),
        virtual_size: format!("0x{:08X}", section.virtual_size),
        raw_size: format!("0x{:08X}", section.raw_size),
        tag: section.protection_string(),
        protection: section.protection_name(),
        expected: section.normal_expectation_name().to_owned(),
        entropy: section.entropy,
        note: section.unusual_protection_reason().unwrap_or_default(),
    }
}

fn to_anomaly_json(anomaly: &PeAnomaly) -> AnomalyJson {
    AnomalyJson {
        severity: anomaly.severity.clone(),
        kind: anomaly.kind.clone(),
        detail: anomaly.detail.clone(),
    }
}
