use std::collections::{BTreeSet, VecDeque};
use std::io::Write;
use std::path::{Path, PathBuf};

use rayon::prelude::*;
use serde::Serialize;

use crate::analysis::discovery::discover_functions;
use crate::analysis::indirect::analyze_indirect_flow;
use crate::analysis::symbols::display_symbol_name;
use crate::analysis::symbols::SymbolIndex;
use crate::core::config::{Cli, Config};
use crate::formats::pe::{
    find_startup_routines, parse_pe, read_data_summary, read_debug_info, read_exports,
    read_imports, read_load_config, Export, ImportDll, PeFile,
};

#[derive(Serialize)]
struct ScanEnvelope {
    tool: &'static str,
    schema_version: u32,
    kind: &'static str,
    root: String,
    files_seen: usize,
    files_reported: usize,
    results: Vec<ImageScanReport>,
}

#[derive(Serialize)]
struct ImageScanReport {
    path: String,
    name: String,
    kind: String,
    arch: String,
    size_bytes: u64,
    entry_point: String,
    exports: usize,
    imports: usize,
    runtime_functions: usize,
    discovered_functions: usize,
    function_sources: Vec<FunctionSourceReport>,
    indirect_edges: usize,
    indirect_tables: usize,
    risk_score: u32,
    risk_imports: Vec<RiskImportReport>,
    candidates: Vec<FuzzCandidateReport>,
    input_surfaces: Vec<String>,
    fuzz_manifest: Vec<FuzzManifestEntry>,
    anomalies: Vec<String>,
    pdb_name: String,
}

#[derive(Serialize, Clone)]
struct RiskImportReport {
    dll: String,
    name: String,
    category: String,
}

#[derive(Serialize, Clone)]
struct FuzzCandidateReport {
    name: String,
    rva: String,
    source: String,
    score: u32,
    input_surface: String,
    harness_kind: String,
    suggested_invocation: String,
    confidence: String,
    reasons: Vec<String>,
}

#[derive(Serialize, Clone)]
struct FunctionSourceReport {
    source: String,
    count: usize,
}

#[derive(Serialize, Clone)]
struct FuzzManifestEntry {
    image: String,
    function: String,
    rva: String,
    harness_kind: String,
    input_surface: String,
    seed_hint: String,
}

pub fn run(cli: &Cli, w: &mut dyn Write) -> Result<(), String> {
    let root = cli
        .scan_root
        .as_deref()
        .ok_or_else(|| "Use `resx scan <path> [--jsonl]`".to_owned())?;
    let root = PathBuf::from(root);
    let extensions = parse_extensions(&cli.scan_extensions);
    let max_file_bytes = cli.max_file_mb.saturating_mul(1024 * 1024);
    let paths = collect_image_paths(&root, &extensions, cli.max_files, max_file_bytes)?;
    let cfg = Config::from_cli(cli, false);

    let mut results: Vec<ImageScanReport> = paths
        .par_iter()
        .filter_map(|path| scan_one(path, cli.max_candidates, &cfg).ok())
        .collect();
    results.sort_by(|a, b| {
        b.risk_score
            .cmp(&a.risk_score)
            .then_with(|| a.path.cmp(&b.path))
    });

    if cli.jsonl {
        for result in &results {
            let line = serde_json::to_string(result).map_err(|e| format!("json: {}", e))?;
            writeln!(w, "{}", line).ok();
        }
        return Ok(());
    }

    let envelope = ScanEnvelope {
        tool: "resx",
        schema_version: 1,
        kind: "scan",
        root: root.display().to_string(),
        files_seen: paths.len(),
        files_reported: results.len(),
        results,
    };
    let json = serde_json::to_string_pretty(&envelope).map_err(|e| format!("json: {}", e))?;
    writeln!(w, "{}", json).ok();
    Ok(())
}

fn scan_one(path: &Path, max_candidates: usize, cfg: &Config) -> Result<ImageScanReport, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read '{}': {}", path.display(), e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let exports = read_exports(&pe, &raw);
    let imports = read_imports(&pe, &raw);
    let debug = read_debug_info(&pe, &raw);
    let data_summary = read_data_summary(&pe, &raw);
    let runtime_functions = data_summary.runtime_functions.len();
    let startup_routines = find_startup_routines(&pe, &raw);
    let symbol_index = SymbolIndex::from_exports_and_pdb(&exports, &[], pe.image_base);
    let function_discovery = discover_functions(
        &raw,
        &pe,
        &exports,
        &symbol_index,
        &[],
        &startup_routines,
        cfg,
    );
    let indirect = analyze_indirect_flow(
        &pe,
        &imports,
        &data_summary,
        &[],
        read_load_config(&pe, &raw).as_ref(),
    );
    let risk_imports = collect_risk_imports(&imports);
    let candidates = select_candidates(path, &pe, &exports, &imports, max_candidates);
    let input_surfaces = classify_input_surfaces(&risk_imports, &candidates);
    let fuzz_manifest = candidates
        .iter()
        .map(|candidate| FuzzManifestEntry {
            image: path.display().to_string(),
            function: candidate.name.clone(),
            rva: candidate.rva.clone(),
            harness_kind: candidate.harness_kind.clone(),
            input_surface: candidate.input_surface.clone(),
            seed_hint: candidate
                .reasons
                .first()
                .cloned()
                .unwrap_or_else(|| "binary input".to_owned()),
        })
        .collect::<Vec<_>>();
    let risk_score = image_risk_score(path, &pe, &risk_imports, &candidates);

    Ok(ImageScanReport {
        path: path.display().to_string(),
        name: file_name(path),
        kind: image_kind(path, &pe),
        arch: format!("x{}", pe.arch),
        size_bytes: raw.len() as u64,
        entry_point: hex32(pe.entry_point),
        exports: exports.len(),
        imports: imports.iter().map(|dll| dll.entries.len()).sum(),
        runtime_functions,
        discovered_functions: function_discovery.stats.total,
        function_sources: source_counts(&function_discovery),
        indirect_edges: indirect.edges.len(),
        indirect_tables: indirect.tables.len(),
        risk_score,
        risk_imports,
        candidates,
        input_surfaces,
        fuzz_manifest,
        anomalies: pe
            .anomalies
            .iter()
            .map(|a| format!("{}:{}:{}", a.severity, a.kind, a.detail))
            .collect(),
        pdb_name: debug
            .codeview
            .as_ref()
            .map(|cv| cv.pdb_name.clone())
            .unwrap_or_default(),
    })
}

fn collect_image_paths(
    root: &Path,
    extensions: &BTreeSet<String>,
    max_files: usize,
    max_file_bytes: u64,
) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    let mut queue = VecDeque::new();
    queue.push_back(root.to_path_buf());

    while let Some(path) = queue.pop_front() {
        if out.len() >= max_files {
            break;
        }
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        if meta.is_dir() {
            let Ok(entries) = std::fs::read_dir(&path) else {
                continue;
            };
            for entry in entries.flatten() {
                queue.push_back(entry.path());
            }
            continue;
        }
        if !meta.is_file() || meta.len() > max_file_bytes {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        if extensions.contains(&ext) {
            out.push(path);
        }
    }

    Ok(out)
}

fn select_candidates(
    path: &Path,
    pe: &PeFile,
    exports: &[Export],
    imports: &[ImportDll],
    max_candidates: usize,
) -> Vec<FuzzCandidateReport> {
    let mut out = Vec::new();
    let driver = is_driver(path, pe);

    if pe.entry_point != 0 {
        out.push(FuzzCandidateReport {
            name: "entry_point".to_owned(),
            rva: hex32(pe.entry_point),
            source: "entry_point".to_owned(),
            score: if driver { 25 } else { 10 },
            input_surface: if driver {
                "driver-startup".to_owned()
            } else {
                "process-startup".to_owned()
            },
            harness_kind: if driver {
                "driver-entry harness".to_owned()
            } else {
                "process harness".to_owned()
            },
            suggested_invocation: "load image and invoke startup path with guarded environment"
                .to_owned(),
            confidence: "medium".to_owned(),
            reasons: if driver {
                vec!["driver startup path".to_owned()]
            } else {
                vec!["process/module startup path".to_owned()]
            },
        });
    }

    for export in exports {
        let (score, reasons) = score_function_name(&export.name, driver);
        if score == 0 {
            continue;
        }
        out.push(FuzzCandidateReport {
            name: display_symbol_name(&export.name),
            rva: hex32(export.rva),
            source: "export".to_owned(),
            score,
            input_surface: candidate_surface(&export.name, driver),
            harness_kind: candidate_harness(&export.name, driver),
            suggested_invocation: candidate_invocation(&export.name, driver),
            confidence: if score >= 35 { "high" } else { "medium" }.to_owned(),
            reasons,
        });
    }

    if out.len() <= 1 && !exports.is_empty() {
        for export in exports
            .iter()
            .take(max_candidates.saturating_sub(out.len()))
        {
            out.push(FuzzCandidateReport {
                name: display_symbol_name(&export.name),
                rva: hex32(export.rva),
                source: "export".to_owned(),
                score: 1,
                input_surface: candidate_surface(&export.name, driver),
                harness_kind: candidate_harness(&export.name, driver),
                suggested_invocation: candidate_invocation(&export.name, driver),
                confidence: "low".to_owned(),
                reasons: vec!["exported entry point".to_owned()],
            });
        }
    }

    if imports.iter().any(imports_device_io) {
        for candidate in &mut out {
            if candidate.source == "entry_point" {
                candidate.score += 10;
                candidate
                    .reasons
                    .push("image imports device I/O APIs".to_owned());
            }
        }
    }

    out.sort_by(|a, b| b.score.cmp(&a.score).then_with(|| a.name.cmp(&b.name)));
    out.truncate(max_candidates);
    out
}

fn source_counts(
    discovery: &crate::analysis::discovery::FunctionDiscoveryReport,
) -> Vec<FunctionSourceReport> {
    let mut counts = std::collections::BTreeMap::new();
    for function in &discovery.functions {
        *counts.entry(function.source.clone()).or_insert(0usize) += 1;
    }
    counts
        .into_iter()
        .map(|(source, count)| FunctionSourceReport { source, count })
        .collect()
}

fn classify_input_surfaces(
    risk_imports: &[RiskImportReport],
    candidates: &[FuzzCandidateReport],
) -> Vec<String> {
    let mut out = std::collections::BTreeSet::new();
    for risk in risk_imports {
        out.insert(risk.category.clone());
    }
    for candidate in candidates {
        out.insert(candidate.input_surface.clone());
    }
    out.into_iter().collect()
}

fn candidate_surface(name: &str, driver: bool) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.contains("ioctl") || lower.contains("devicecontrol") {
        "ioctl".to_owned()
    } else if lower.contains("parse") || lower.contains("decode") || lower.contains("deserialize") {
        "structured-input".to_owned()
    } else if lower.contains("packet") || lower.contains("message") || lower.contains("http") {
        "network-or-message".to_owned()
    } else if driver {
        "kernel-entry".to_owned()
    } else {
        "export-call".to_owned()
    }
}

fn candidate_harness(name: &str, driver: bool) -> String {
    match candidate_surface(name, driver).as_str() {
        "ioctl" => "ioctl harness".to_owned(),
        "structured-input" => "buffer parser harness".to_owned(),
        "network-or-message" => "message corpus harness".to_owned(),
        "kernel-entry" => "driver dispatch harness".to_owned(),
        _ => "export harness".to_owned(),
    }
}

fn candidate_invocation(name: &str, driver: bool) -> String {
    match candidate_surface(name, driver).as_str() {
        "ioctl" => "open device, mutate IOCTL code and input/output buffers".to_owned(),
        "structured-input" => "call export with mutable byte buffer and size arguments".to_owned(),
        "network-or-message" => "feed corpus bytes as packet/message payload".to_owned(),
        "kernel-entry" => "invoke dispatch routine with synthetic IRP/request context".to_owned(),
        _ => format!("resolve export {name} and call with guarded fuzz arguments"),
    }
}

fn collect_risk_imports(imports: &[ImportDll]) -> Vec<RiskImportReport> {
    let mut out = Vec::new();
    for dll in imports {
        for entry in &dll.entries {
            if let Some(category) = risk_import_category(&entry.name) {
                out.push(RiskImportReport {
                    dll: dll.dll.clone(),
                    name: entry.name.clone(),
                    category: category.to_owned(),
                });
            }
        }
    }
    out.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then_with(|| a.dll.cmp(&b.dll))
            .then_with(|| a.name.cmp(&b.name))
    });
    out.dedup_by(|a, b| a.dll == b.dll && a.name == b.name);
    out
}

fn risk_import_category(name: &str) -> Option<&'static str> {
    let lower = name.to_ascii_lowercase();
    [
        ("deviceiocontrol", "ioctl"),
        ("ntdeviceiocontrolfile", "ioctl"),
        ("zwdeviceiocontrolfile", "ioctl"),
        ("iocreatedevice", "driver-device"),
        ("iocreatesymboliclink", "driver-device"),
        ("wdfdevicecreate", "driver-device"),
        ("probeforread", "kernel-user-buffer"),
        ("probeforwrite", "kernel-user-buffer"),
        ("mmmapiospace", "kernel-memory"),
        ("memcpy", "memory-copy"),
        ("strcpy", "string-copy"),
        ("wcscpy", "string-copy"),
        ("recv", "network-input"),
        ("wsarecv", "network-input"),
        ("internetreadfile", "network-input"),
        ("readfile", "file-input"),
        ("cryptdecodeobject", "parser"),
        ("cert", "parser"),
        ("rtldecompressbuffer", "decompression"),
        ("bcryptdecrypt", "crypto"),
        ("cryptdecrypt", "crypto"),
        ("regqueryvalue", "registry"),
        ("zwqueryvaluekey", "registry"),
    ]
    .iter()
    .find_map(|(needle, category)| lower.contains(needle).then_some(*category))
}

fn score_function_name(name: &str, driver: bool) -> (u32, Vec<String>) {
    let lower = name.to_ascii_lowercase();
    let mut score = 0u32;
    let mut reasons = Vec::new();

    for (needle, value, reason) in [
        ("devicecontrol", 35, "device I/O dispatch"),
        ("ioctl", 35, "IOCTL path"),
        ("dispatch", 20, "dispatch routine"),
        ("irp", 20, "IRP routine"),
        ("parse", 18, "parser-like name"),
        ("decode", 18, "decoder-like name"),
        ("deserialize", 18, "deserializer-like name"),
        ("decompress", 18, "decompression path"),
        ("packet", 14, "packet handling"),
        ("message", 12, "message handling"),
        ("tlv", 12, "structured input"),
        ("asn", 12, "structured input"),
        ("rpc", 12, "RPC-facing path"),
        ("http", 10, "network-facing path"),
        ("read", 8, "input read path"),
        ("write", 8, "input write path"),
        ("copy", 8, "copy boundary"),
    ] {
        if lower.contains(needle) {
            score += value;
            reasons.push(reason.to_owned());
        }
    }

    if driver {
        for (needle, value, reason) in [
            ("driverentry", 25, "driver entry"),
            ("adddevice", 20, "PnP add-device path"),
            ("evt", 10, "WDF event callback"),
        ] {
            if lower.contains(needle) {
                score += value;
                reasons.push(reason.to_owned());
            }
        }
    }

    reasons.sort();
    reasons.dedup();
    (score, reasons)
}

fn image_risk_score(
    path: &Path,
    pe: &PeFile,
    risk_imports: &[RiskImportReport],
    candidates: &[FuzzCandidateReport],
) -> u32 {
    let mut score = 0u32;
    if is_driver(path, pe) {
        score += 25;
    }
    score += risk_imports.len().min(20) as u32 * 3;
    score += candidates.iter().map(|c| c.score).max().unwrap_or(0);
    score += pe
        .sections
        .iter()
        .filter(|section| section.unusual_protection_reason().is_some())
        .count() as u32
        * 5;
    if pe.header_corruption_detected() {
        score += 10;
    }
    score
}

fn parse_extensions(raw: &str) -> BTreeSet<String> {
    raw.split(',')
        .map(|item| item.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|item| !item.is_empty())
        .collect()
}

fn image_kind(path: &Path, pe: &PeFile) -> String {
    if is_driver(path, pe) {
        "driver".to_owned()
    } else if path
        .extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("dll"))
    {
        "dll".to_owned()
    } else {
        "exe".to_owned()
    }
}

fn is_driver(path: &Path, pe: &PeFile) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("sys"))
        || pe.subsystem == 1
}

fn imports_device_io(dll: &ImportDll) -> bool {
    dll.entries.iter().any(|entry| {
        matches!(
            risk_import_category(&entry.name),
            Some("ioctl" | "driver-device")
        )
    })
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string()
}

fn hex32(value: u32) -> String {
    format!("0x{:08X}", value)
}
