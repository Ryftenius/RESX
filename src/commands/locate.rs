use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};
use rayon::prelude::*;

use crate::analysis::thunk::follow_jmp_thunk;
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::output::ProgressBar;
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
    let deep = cfg.locate_deep || cfg.locate_all_deep;
    let show_all = cfg.locate_all || cfg.locate_all_deep;

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

    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    let mut search_dirs: Vec<PathBuf> = vec![
        PathBuf::from(&windir).join("System32"),
        PathBuf::from(&windir).join("SysWOW64"),
        PathBuf::from(&windir).join("System32").join("drivers"),
    ];
    for p in &cfg.extra_paths {
        search_dirs.push(PathBuf::from(p));
    }

    let mut results: Vec<LocateResult> = Vec::new();
    let tiers = collect_search_tiers(&search_dirs);
    let (priority_tiers, deferred_tiers) = split_priority_tiers(&tiers);
    let mut matched_paths = std::collections::HashSet::new();

    let priority_started = Instant::now();
    stream_export_hits(
        &priority_tiers,
        func_name,
        show_all,
        cfg,
        c,
        w,
        &mut results,
        &mut matched_paths,
    )?;

    let mut priority_symbol_files = 0usize;
    if deep && !cfg.no_pdb && (show_all || results.is_empty()) {
        let remaining = collect_remaining_tiers(&priority_tiers, &matched_paths);
        priority_symbol_files = count_tier_paths(&remaining);
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
    let priority_elapsed = priority_started.elapsed();

    if show_all && !deferred_tiers.is_empty() {
        let priority_export_files = count_tier_paths(&priority_tiers);
        let deferred_export_files = count_tier_paths(&deferred_tiers);
        let deferred_symbol_files = if deep && priority_export_files > 0 {
            deferred_export_files.saturating_mul(priority_symbol_files) / priority_export_files
        } else {
            0
        };
        if !prompt_to_continue_deferred_scan(
            func_name,
            deep,
            priority_export_files,
            priority_symbol_files,
            deferred_export_files,
            deferred_symbol_files,
            priority_elapsed,
            cfg,
            w,
            c,
        )? {
            annotate_syscall_targets(&mut results);
            return print_locate_results(func_name, deep, &results, cfg, w, c);
        }
    }

    stream_export_hits(
        &deferred_tiers,
        func_name,
        show_all,
        cfg,
        c,
        w,
        &mut results,
        &mut matched_paths,
    )?;

    if deep && !cfg.no_pdb && show_all {
        let remaining = collect_remaining_tiers(&deferred_tiers, &matched_paths);
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

    annotate_syscall_targets(&mut results);

    print_locate_results(func_name, deep, &results, cfg, w, c)
}

fn print_locate_results(
    func_name: &str,
    deep: bool,
    results: &[LocateResult],
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    if results.is_empty() {
        writeln!(
            w,
            "{}",
            c.warn(&format!("'{}' not found in any system DLL", func_name))
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
        let out = serde_json::to_string_pretty(&j).unwrap_or_default();
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
        let hint = if deep {
            "use --locate-all-sym to show all DLLs"
        } else {
            "use --locate-all to show all DLLs"
        };
        writeln!(
            w,
            "{}",
            c.dim(&format!("  {} result(s)  |  {}", results.len(), hint))
        )
        .ok();
    }
    Ok(())
}

fn collect_search_tiers(search_dirs: &[PathBuf]) -> Vec<Vec<PathBuf>> {
    let mut seen = std::collections::HashSet::new();
    let mut all_paths: Vec<PathBuf> = Vec::new();
    for dir in search_dirs {
        if let Ok(v) = glob_system_binaries(dir) {
            for path in v {
                let key = path_key(&path);
                if seen.insert(key) {
                    all_paths.push(path);
                }
            }
        }
    }
    all_paths.sort_by(|a, b| {
        path_priority_key(a)
            .cmp(&path_priority_key(b))
            .then_with(|| a.file_name().cmp(&b.file_name()))
    });

    let mut tiers: Vec<Vec<PathBuf>> = Vec::new();
    let mut current_key: Option<(u8, u8, u16)> = None;
    for path in all_paths {
        let key = path_priority_key(&path);
        if current_key != Some(key) {
            tiers.push(Vec::new());
            current_key = Some(key);
        }
        tiers.last_mut().unwrap().push(path);
    }
    tiers
}

fn split_priority_tiers(tiers: &[Vec<PathBuf>]) -> (Vec<Vec<PathBuf>>, Vec<Vec<PathBuf>>) {
    let split_at = tiers
        .iter()
        .position(|tier| !tier.is_empty() && !is_priority_path(&tier[0]))
        .unwrap_or(tiers.len());
    (tiers[..split_at].to_vec(), tiers[split_at..].to_vec())
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

fn count_tier_paths(tiers: &[Vec<PathBuf>]) -> usize {
    tiers.iter().map(|tier| tier.len()).sum()
}

fn path_priority_key(path: &Path) -> (u8, u8, u16) {
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
    let file_rank = filename_priority_rank(path);
    (dir_rank, ext_rank, file_rank)
}

fn is_priority_path(path: &Path) -> bool {
    filename_priority_rank(path) < non_priority_rank_base()
}

fn filename_priority_rank(path: &Path) -> u16 {
    let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
        return 999;
    };
    let lower = file_name.to_ascii_lowercase();

    if let Some((idx, _)) = EXACT_SEARCH_PRIORITY
        .iter()
        .enumerate()
        .find(|(_, name)| lower == **name)
    {
        return idx as u16;
    }

    let family_base = EXACT_SEARCH_PRIORITY.len() as u16;
    if let Some((idx, _)) = PREFIX_SEARCH_PRIORITY
        .iter()
        .enumerate()
        .find(|(_, prefix)| lower.starts_with(**prefix))
    {
        return family_base + idx as u16;
    }

    non_priority_rank_base()
}

fn non_priority_rank_base() -> u16 {
    EXACT_SEARCH_PRIORITY.len() as u16 + PREFIX_SEARCH_PRIORITY.len() as u16 + 100
}

#[allow(clippy::too_many_arguments)]
fn prompt_to_continue_deferred_scan(
    func_name: &str,
    deep: bool,
    priority_export_files: usize,
    priority_symbol_files: usize,
    deferred_export_files: usize,
    deferred_symbol_files: usize,
    priority_elapsed: std::time::Duration,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<bool, String> {
    if cfg.json
        || cfg.quiet
        || !std::io::stdin().is_terminal()
        || !std::io::stderr().is_terminal()
        || deferred_export_files == 0
    {
        return Ok(true);
    }

    let estimate = estimate_remaining_duration(
        priority_elapsed,
        priority_export_files + priority_symbol_files,
        deferred_export_files + deferred_symbol_files,
    );

    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_mag("Priority Search Complete:"))).ok();
    writeln!(w, "  {} {}", c.dim("Target   :"), c.cyan(func_name)).ok();
    writeln!(
        w,
        "  {} {}",
        c.dim("Next     :"),
        c.dim(if deep {
            "remaining System32 / SysWOW64 / driver images (exports + symbols)"
        } else {
            "remaining System32 / SysWOW64 / driver images (exports)"
        })
    )
    .ok();
    writeln!(
        w,
        "  {} {}",
        c.dim("Exports  :"),
        c.cyan(&deferred_export_files.to_string())
    )
    .ok();
    if deep {
        writeln!(
            w,
            "  {} {}",
            c.dim("Symbols  :"),
            c.cyan(&format!("~{}", deferred_symbol_files))
        )
        .ok();
    }
    writeln!(
        w,
        "  {} {}",
        c.dim("Estimate :"),
        c.cyan(&format_duration(estimate))
    )
    .ok();
    eprint!("\nContinue beyond the priority DLL set? [y/N]: ");
    let _ = std::io::stderr().flush();
    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| format!("read prompt response: {}", e))?;
    let answer = answer.trim();
    Ok(matches!(answer, "y" | "Y" | "yes" | "YES" | "Yes"))
}

fn estimate_remaining_duration(
    elapsed: std::time::Duration,
    processed_units: usize,
    remaining_units: usize,
) -> std::time::Duration {
    if processed_units == 0 || remaining_units == 0 {
        return std::time::Duration::ZERO;
    }
    let nanos_per_unit = elapsed.as_nanos() / processed_units as u128;
    let remaining_nanos = nanos_per_unit.saturating_mul(remaining_units as u128);
    let capped = remaining_nanos.min(u64::MAX as u128);
    std::time::Duration::from_nanos(capped as u64)
}

fn format_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs < 60 {
        format!("~{}s", secs.max(1))
    } else if secs < 3600 {
        format!("~{}m {}s", secs / 60, secs % 60)
    } else {
        format!("~{}h {}m", secs / 3600, (secs % 3600) / 60)
    }
}

const EXACT_SEARCH_PRIORITY: &[&str] = &[
    "ntoskrnl.exe",
    "ntdll.dll",
    "kernelbase.dll",
    "kernel32.dll",
    "advapi32.dll",
    "user32.dll",
    "gdi32.dll",
    "gdi32full.dll",
    "combase.dll",
    "ole32.dll",
    "oleaut32.dll",
    "rpcrt4.dll",
    "ucrtbase.dll",
    "msvcrt.dll",
    "vcruntime140.dll",
    "vcruntime140_1.dll",
    "ws2_32.dll",
    "winhttp.dll",
    "wininet.dll",
    "sechost.dll",
    "secur32.dll",
    "sspicli.dll",
    "crypt32.dll",
    "cryptbase.dll",
    "bcrypt.dll",
    "bcryptprimitives.dll",
    "ncrypt.dll",
    "psapi.dll",
    "dbghelp.dll",
    "dbgcore.dll",
    "shlwapi.dll",
    "shell32.dll",
    "iphlpapi.dll",
    "dnsapi.dll",
    "wevtapi.dll",
    "tdh.dll",
    "advpack.dll",
    "setupapi.dll",
    "cfgmgr32.dll",
    "wintrust.dll",
    "urlmon.dll",
    "winmm.dll",
    "imm32.dll",
    "version.dll",
];

const PREFIX_SEARCH_PRIORITY: &[&str] = &[
    "api-ms-win-",
    "ext-ms-win-",
    "com",
    "ole",
    "rpc",
    "bcrypt",
    "crypt",
    "ncrypt",
    "winhttp",
    "wininet",
    "secur",
    "sspi",
    "wevt",
    "tdh",
    "evt",
    "psapi",
    "dbg",
    "setup",
    "cfgmgr",
    "wdf",
    "mf",
    "dx",
    "d3d",
];

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

fn glob_system_binaries(dir: &PathBuf) -> Result<Vec<PathBuf>, std::io::Error> {
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
            Mnemonic::Int => {
                if instr.immediate8() == 0x2E {
                    return Some(SyscallStubInfo {
                        is_syscall_stub: true,
                        syscall_number,
                    });
                }
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
