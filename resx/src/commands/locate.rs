use std::io::Write;
use std::path::{Path, PathBuf};

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use rayon::prelude::*;

use crate::analysis::thunk::follow_jmp_thunk;
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_items;
use crate::core::output::ProgressBar;
use crate::core::priority::{matcher, merged_priority_dirs, PriorityMatcher};
use crate::formats::pdb::load_pdb_symbol;
use crate::formats::pe::{parse_pe, read_exports};

#[derive(Debug)]
pub struct LocateResult {
    pub dll: String,
    pub dll_path: String,
    pub name: String,
    pub ordinal: u32,
    pub rva: u32,
    pub source: String,
    pub is_stub: bool,
    pub stub_dll: String,
    pub stub_fn: String,
    pub from_pdb: bool,
    pub is_kernel: bool,
    pub is_syscall_stub: bool,
    pub syscall_number: Option<u32>,
    pub kernel_component: String,
    pub kernel_symbol: String,
}

pub fn run(func_name: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let deep = cfg.locate_deep;
    let show_all = true;
    let priority = matcher(cfg);

    if !cfg.quiet {
        let mode = if deep {
            "exports and symbols"
        } else {
            "exports"
        };
        writeln!(
            w,
            "{}",
            c.info(&format!(
                "Searching for '{}' across system DLLs via {}...",
                func_name, mode
            ))
        )
        .ok();
    }

    let mut search_roots: Vec<(PathBuf, bool)> = merged_priority_dirs(cfg)
        .into_iter()
        .map(|dir| (dir, true))
        .collect();
    for p in &cfg.extra_paths {
        search_roots.push((PathBuf::from(p), false));
    }
    for p in &cfg.scan_dirs {
        search_roots.push((PathBuf::from(p), false));
    }

    let mut results: Vec<LocateResult> = Vec::new();
    let tiers = collect_search_tiers(&search_roots, &priority);
    let mut matched_paths = std::collections::HashSet::new();

    stream_export_hits(
        &tiers,
        func_name,
        show_all,
        cfg,
        c,
        w,
        &mut results,
        &mut matched_paths,
    )?;

    if deep && !cfg.no_pdb && (show_all || results.is_empty()) {
        let remaining = collect_remaining_tiers(&tiers, &matched_paths);
        stream_symbol_hits(
            &remaining,
            func_name,
            show_all,
            cfg,
            c,
            w,
            &mut results,
            &mut matched_paths,
        )?;
    }

    for dll_arg in &cfg.scan_dlls {
        if let Ok(path) = PathBuf::from(dll_arg).canonicalize() {
            let key = path_key(&path);
            if matched_paths.insert(key) {
                collect_explicit_image_hits(&path, func_name, deep, cfg, &mut results);
            }
        }
    }

    annotate_syscall_targets(&mut results);

    print_locate_results(func_name, deep, &results, cfg, w, c)
}

fn print_locate_results(
    func_name: &str,
    _deep: bool,
    results: &[LocateResult],
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    if results.is_empty() {
        writeln!(
            w,
            "{}",
            c.warn(&format!(
                "'{}' not found in the priority set or included scan targets",
                func_name
            ))
        )
        .ok();
        return Ok(());
    }

    if cfg.json {
        use serde_json::json;
        let j: Vec<_> = results
            .iter()
            .map(|r| {
                json!({
                    "dll":      r.dll,
                    "dll_path": r.dll_path,
                    "name":     r.name,
                    "ordinal":  r.ordinal,
                    "rva":      format!("0x{:08X}", r.rva),
                    "source":   r.source,
                    "from_pdb": r.from_pdb,
                    "kernel":   r.is_kernel,
                    "syscall_stub": r.is_syscall_stub,
                    "syscall_number": r.syscall_number.map(|n| format!("0x{:X}", n)),
                    "kernel_component": r.kernel_component,
                    "kernel_symbol": r.kernel_symbol,
                    "stub":     r.is_stub,
                    "stub_dll": r.stub_dll,
                    "stub_fn":  r.stub_fn,
                })
            })
            .collect();
        let out = serde_json::to_string_pretty(&versioned_items("matches", j)).unwrap_or_default();
        writeln!(w, "{}", out).ok();
    } else {
        writeln!(w).ok();
        writeln!(
            w,
            "{}",
            c.bold(&c.b_yellow(&format!("Locations of '{}':", func_name)))
        )
        .ok();
        for r in results {
            print_locate_result(w, c, r);
        }
        let hint =
            "use --include-dir / --include-image or edit `resx priority` to widen the search";
        writeln!(
            w,
            "{}",
            c.dim(&format!("  {} result(s)  |  {}", results.len(), hint))
        )
        .ok();
    }
    Ok(())
}

fn collect_search_tiers(
    search_roots: &[(PathBuf, bool)],
    priority: &PriorityMatcher,
) -> Vec<Vec<PathBuf>> {
    let mut seen = std::collections::HashSet::new();
    let mut all_paths: Vec<PathBuf> = Vec::new();
    for (dir, enforce_priority) in search_roots {
        if let Ok(v) = glob_system_binaries(dir, priority, *enforce_priority) {
            for path in v {
                let key = path_key(&path);
                if seen.insert(key) {
                    all_paths.push(path);
                }
            }
        }
    }
    all_paths.sort_by(|a, b| {
        path_priority_key(a, priority)
            .cmp(&path_priority_key(b, priority))
            .then_with(|| a.file_name().cmp(&b.file_name()))
    });

    let mut tiers: Vec<Vec<PathBuf>> = Vec::new();
    let mut current_key: Option<(u8, u8, u16)> = None;
    for path in all_paths {
        let key = path_priority_key(&path, priority);
        if current_key != Some(key) {
            tiers.push(Vec::new());
            current_key = Some(key);
        }
        if let Some(tier) = tiers.last_mut() {
            tier.push(path);
        }
    }
    tiers
}

fn collect_remaining_tiers(
    tiers: &[Vec<PathBuf>],
    matched_paths: &std::collections::HashSet<String>,
) -> Vec<Vec<PathBuf>> {
    tiers
        .iter()
        .map(|tier| {
            tier.iter()
                .filter(|path| !matched_paths.contains(&path_key(path)))
                .cloned()
                .collect::<Vec<_>>()
        })
        .filter(|tier| !tier.is_empty())
        .collect()
}

fn path_priority_key(path: &Path, priority: &PriorityMatcher) -> (u8, u8, u16) {
    let ext_rank = match path
        .extension()
        .and_then(|e| e.to_str())
        .map(|s| s.to_ascii_lowercase())
    {
        Some(ext) if ext == "dll" => 0,
        Some(ext) if ext == "sys" => 1,
        Some(ext) if ext == "exe" => 2,
        _ => 3,
    };
    let lower = path.to_string_lossy().to_ascii_lowercase();
    let dir_rank = if lower.contains("\\system32\\") {
        0
    } else if lower.contains("\\syswow64\\") {
        1
    } else if lower.contains("\\drivers\\") {
        2
    } else {
        3
    };
    let file_rank = priority.filename_rank(path);
    (dir_rank, ext_rank, file_rank)
}

fn collect_explicit_image_hits(
    path: &Path,
    func_name: &str,
    deep: bool,
    cfg: &Config,
    results: &mut Vec<LocateResult>,
) {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(_) => return,
    };
    let pe = match parse_pe(&raw) {
        Ok(pe) => pe,
        Err(_) => return,
    };
    let exports = read_exports(&pe, &raw);
    for e in &exports {
        if e.name != func_name {
            continue;
        }
        let mut res = LocateResult {
            dll: path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            dll_path: path.to_string_lossy().to_string(),
            name: e.name.clone(),
            ordinal: e.ordinal,
            rva: e.rva,
            source: "export".to_owned(),
            is_stub: false,
            stub_dll: String::new(),
            stub_fn: String::new(),
            from_pdb: false,
            is_kernel: is_kernel_image(path),
            is_syscall_stub: false,
            syscall_number: None,
            kernel_component: String::new(),
            kernel_symbol: String::new(),
        };
        if let Some(thunk) = follow_jmp_thunk(&raw, &pe, e.rva) {
            if let (Some(dll), Some(func)) = (thunk.iat_dll(), thunk.iat_func()) {
                res.is_stub = true;
                res.stub_dll = dll.to_owned();
                res.stub_fn = func.to_owned();
            }
        }
        if let Some(stub) = detect_syscall_stub(&raw, &pe, e.rva) {
            res.is_syscall_stub = true;
            res.syscall_number = stub.syscall_number;
        }
        results.push(res);
    }
    if deep && !cfg.no_pdb {
        let path_str = path.to_string_lossy().to_string();
        if let Some(rva) = load_pdb_symbol(
            &path_str,
            func_name,
            &cfg.sym_path,
            &cfg.sym_server,
            &cfg.pdb_file,
            pe.image_base,
            cfg.verbose,
            cfg.reload,
        ) {
            results.push(LocateResult {
                dll: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                dll_path: path_str,
                name: func_name.to_owned(),
                ordinal: 0,
                rva,
                source: "symbol".to_owned(),
                is_stub: false,
                stub_dll: String::new(),
                stub_fn: String::new(),
                from_pdb: true,
                is_kernel: is_kernel_image(path),
                is_syscall_stub: false,
                syscall_number: detect_syscall_stub(&raw, &pe, rva).and_then(|s| s.syscall_number),
                kernel_component: String::new(),
                kernel_symbol: String::new(),
            });
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn stream_export_hits(
    tiers: &[Vec<PathBuf>],
    func_name: &str,
    show_all: bool,
    cfg: &Config,
    c: &Colors,
    _w: &mut dyn Write,
    results: &mut Vec<LocateResult>,
    matched_paths: &mut std::collections::HashSet<String>,
) -> Result<(), String> {
    let total: usize = tiers.iter().map(|tier| tier.len()).sum();
    let pb = ProgressBar::new(total, c.on && !cfg.quiet, c.on);
    for tier in tiers {
        let mut tier_hits = scan_export_bucket(tier, func_name, &pb);
        tier_hits.sort_by(|a, b| {
            a.dll_path
                .to_ascii_lowercase()
                .cmp(&b.dll_path.to_ascii_lowercase())
        });
        for hit in tier_hits {
            matched_paths.insert(path_key(Path::new(&hit.dll_path)));
            results.push(hit);
        }
        if !show_all && !results.is_empty() {
            break;
        }
    }
    pb.finish();
    Ok(())
}

fn scan_export_bucket(
    all_paths: &[PathBuf],
    func_name: &str,
    pb: &ProgressBar,
) -> Vec<LocateResult> {
    all_paths
        .par_iter()
        .flat_map_iter(|dll_path| {
            let label = dll_path.file_name().unwrap_or_default().to_string_lossy();
            let raw = match std::fs::read(dll_path) {
                Ok(r) => r,
                Err(_) => {
                    pb.tick(&label);
                    return Vec::new();
                }
            };
            let pe = match parse_pe(&raw) {
                Ok(p) => p,
                Err(_) => {
                    pb.tick(&label);
                    return Vec::new();
                }
            };
            let exports = read_exports(&pe, &raw);
            let mut hits = Vec::new();
            for e in &exports {
                if e.name != func_name {
                    continue;
                }

                let mut res = LocateResult {
                    dll: dll_path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string(),
                    dll_path: dll_path.to_string_lossy().to_string(),
                    name: e.name.clone(),
                    ordinal: e.ordinal,
                    rva: e.rva,
                    source: "export".to_owned(),
                    is_stub: false,
                    stub_dll: String::new(),
                    stub_fn: String::new(),
                    from_pdb: false,
                    is_kernel: is_kernel_image(dll_path),
                    is_syscall_stub: false,
                    syscall_number: None,
                    kernel_component: String::new(),
                    kernel_symbol: String::new(),
                };

                if let Some(thunk) = follow_jmp_thunk(&raw, &pe, e.rva) {
                    if let (Some(dll), Some(func)) = (thunk.iat_dll(), thunk.iat_func()) {
                        res.is_stub = true;
                        res.stub_dll = dll.to_owned();
                        res.stub_fn = func.to_owned();
                    }
                }
                if let Some(stub) = detect_syscall_stub(&raw, &pe, e.rva) {
                    res.is_syscall_stub = true;
                    res.syscall_number = stub.syscall_number;
                }
                hits.push(res);
            }
            pb.tick(&label);
            hits
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn stream_symbol_hits(
    tiers: &[Vec<PathBuf>],
    func_name: &str,
    show_all: bool,
    cfg: &Config,
    c: &Colors,
    _w: &mut dyn Write,
    results: &mut Vec<LocateResult>,
    matched_paths: &mut std::collections::HashSet<String>,
) -> Result<(), String> {
    let total: usize = tiers.iter().map(|tier| tier.len()).sum();
    let pb = ProgressBar::new(total, c.on && !cfg.quiet, c.on);
    for tier in tiers {
        let before = results.len();
        let mut tier_hits = scan_symbol_bucket(tier, func_name, cfg, &pb);
        tier_hits.sort_by(|a, b| {
            a.dll_path
                .to_ascii_lowercase()
                .cmp(&b.dll_path.to_ascii_lowercase())
        });
        for hit in tier_hits {
            matched_paths.insert(path_key(Path::new(&hit.dll_path)));
            results.push(hit);
        }
        if !show_all && results.len() > before {
            break;
        }
    }
    pb.finish();
    Ok(())
}

fn scan_symbol_bucket(
    all_paths: &[PathBuf],
    func_name: &str,
    cfg: &Config,
    pb: &ProgressBar,
) -> Vec<LocateResult> {
    all_paths
        .par_iter()
        .filter_map(|dll_path| {
            let label = dll_path.file_name().unwrap_or_default().to_string_lossy();
            let raw = match std::fs::read(dll_path) {
                Ok(r) => r,
                Err(_) => {
                    pb.tick(&label);
                    return None;
                }
            };
            let pe = match parse_pe(&raw) {
                Ok(p) => p,
                Err(_) => {
                    pb.tick(&label);
                    return None;
                }
            };
            let dll_path_str = dll_path.to_string_lossy().to_string();
            let rva = load_pdb_symbol(
                &dll_path_str,
                func_name,
                &cfg.sym_path,
                &cfg.sym_server,
                &cfg.pdb_file,
                pe.image_base,
                cfg.verbose,
                cfg.reload,
            );
            pb.tick(&label);
            rva.map(|rva| LocateResult {
                dll: dll_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string(),
                dll_path: dll_path_str,
                name: func_name.to_owned(),
                ordinal: 0,
                rva,
                source: "symbol".to_owned(),
                is_stub: false,
                stub_dll: String::new(),
                stub_fn: String::new(),
                from_pdb: true,
                is_kernel: is_kernel_image(dll_path),
                is_syscall_stub: false,
                syscall_number: detect_syscall_stub(&raw, &pe, rva).and_then(|s| {
                    if s.is_syscall_stub {
                        s.syscall_number
                    } else {
                        None
                    }
                }),
                kernel_component: String::new(),
                kernel_symbol: String::new(),
            })
        })
        .collect()
}

fn print_locate_result(w: &mut dyn Write, c: &Colors, r: &LocateResult) {
    let mut tags: Vec<String> = Vec::new();
    if r.from_pdb {
        tags.push(c.dim("[symbols]"));
    }
    if r.is_kernel {
        tags.push(c.dim("[kernel]"));
    }
    if r.is_syscall_stub {
        let mut label = if let Some(num) = r.syscall_number {
            format!("[syscall-stub #0x{:X}]", num)
        } else {
            "[syscall-stub]".to_owned()
        };
        if !r.kernel_component.is_empty() && !r.kernel_symbol.is_empty() {
            label.push_str(&format!(" -> {}!{}", r.kernel_component, r.kernel_symbol));
        }
        tags.push(c.dim(&label));
    }
    let source = if tags.is_empty() {
        String::new()
    } else {
        format!("  {}", tags.join(" "))
    };
    let stub = if r.is_stub {
        c.dim(&format!("  → {}!{}  [stub]", r.stub_dll, r.stub_fn))
    } else {
        String::new()
    };
    let ordinal = if r.from_pdb {
        "ord:-".to_owned()
    } else {
        format!("ord:{}", r.ordinal)
    };
    writeln!(
        w,
        "  {}  {}!{}  {}  RVA:0x{:08X}{}{}",
        c.dim(&r.dll_path),
        c.cyan(&r.dll),
        c.b_yellow(&r.name),
        ordinal,
        r.rva,
        source,
        stub
    )
    .ok();
}

fn path_key(path: &Path) -> String {
    path.to_string_lossy().to_ascii_lowercase()
}

fn glob_system_binaries(
    dir: &PathBuf,
    priority: &PriorityMatcher,
    enforce_priority: bool,
) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut files = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let matches = path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| {
                e.eq_ignore_ascii_case("dll")
                    || e.eq_ignore_ascii_case("exe")
                    || e.eq_ignore_ascii_case("sys")
            })
            .unwrap_or(false);
        if matches {
            if enforce_priority && !priority.is_priority_path(&path) {
                continue;
            }
            files.push(path);
        }
    }
    Ok(files)
}

#[derive(Debug, Clone, Copy)]
struct SyscallStubInfo {
    is_syscall_stub: bool,
    syscall_number: Option<u32>,
}

fn detect_syscall_stub(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    start_rva: u32,
) -> Option<SyscallStubInfo> {
    let off = pe.rva_to_offset(start_rva)?;
    if off >= raw.len() {
        return None;
    }

    let max_len = raw.len().saturating_sub(off).min(32);
    let chunk = &raw[off..off + max_len];
    let ip = pe.image_base + start_rva as u64;
    let mut decoder = Decoder::with_ip(pe.arch, chunk, ip, DecoderOptions::NONE);
    let mut instr = iced_x86::Instruction::default();
    let mut syscall_number = None;

    for _ in 0..6 {
        if !decoder.can_decode() {
            break;
        }
        decoder.decode_out(&mut instr);
        match instr.mnemonic() {
            Mnemonic::Mov if instr.op_count() >= 2 && instr.op0_kind() == OpKind::Register => {
                let dst = instr.op0_register();
                if matches!(
                    dst,
                    Register::EAX | Register::RAX | Register::AX | Register::AL
                ) {
                    syscall_number = match instr.op1_kind() {
                        OpKind::Immediate8 => Some(instr.immediate8to32() as u32),
                        OpKind::Immediate16 => Some(instr.immediate16() as u32),
                        OpKind::Immediate32 => Some(instr.immediate32()),
                        OpKind::Immediate32to64 => Some(instr.immediate32to64() as u32),
                        OpKind::Immediate64 => Some(instr.immediate64() as u32),
                        _ => syscall_number,
                    };
                }
            }
            Mnemonic::Syscall | Mnemonic::Sysenter => {
                return Some(SyscallStubInfo {
                    is_syscall_stub: true,
                    syscall_number,
                });
            }
            Mnemonic::Int if instr.immediate8() == 0x2E => {
                return Some(SyscallStubInfo {
                    is_syscall_stub: true,
                    syscall_number,
                });
            }
            Mnemonic::Ret => break,
            _ => {}
        }
    }

    None
}

fn annotate_syscall_targets(results: &mut [LocateResult]) {
    let kernel_hits: Vec<(String, String)> = results
        .iter()
        .filter(|r| r.is_kernel)
        .map(|r| (r.dll.clone(), r.name.clone()))
        .collect();

    for result in results.iter_mut().filter(|r| r.is_syscall_stub) {
        let candidates = kernel_name_candidates(&result.name);
        if let Some((dll, name)) = kernel_hits.iter().find(|(_, hit_name)| {
            candidates
                .iter()
                .any(|candidate| hit_name.eq_ignore_ascii_case(candidate))
        }) {
            result.kernel_component = dll.clone();
            result.kernel_symbol = name.clone();
        }
    }
}

fn kernel_name_candidates(name: &str) -> Vec<String> {
    let mut out = vec![name.to_owned()];
    if let Some(rest) = name.strip_prefix("Nt") {
        out.push(format!("Zw{}", rest));
    } else if let Some(rest) = name.strip_prefix("Zw") {
        out.push(format!("Nt{}", rest));
    }
    out
}

fn is_kernel_image(path: &Path) -> bool {
    let file = path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or_default();
    let lower_file = file.to_ascii_lowercase();
    if lower_file.ends_with(".sys") {
        return true;
    }
    matches!(
        lower_file.as_str(),
        "ntoskrnl.exe"
            | "ntkrnlmp.exe"
            | "ntkrnlpa.exe"
            | "ntkrpamp.exe"
            | "win32kbase.sys"
            | "win32kfull.sys"
            | "win32k.sys"
    ) || path
        .to_string_lossy()
        .to_ascii_lowercase()
        .contains("\\system32\\drivers\\")
}
