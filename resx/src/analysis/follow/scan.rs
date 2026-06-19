use std::collections::hash_map::DefaultHasher;
use std::collections::HashSet;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::analysis::thunk::{follow_jmp_thunk, ThunkResolution};
use crate::core::config::Config;
use crate::core::priority::{default_priority_dirs, matcher_from_lists};
use crate::core::search::image_name_candidates;
use crate::formats::pe::{
    attribute_to_func, import_slot_map_by_va, parse_pe, read_exports, read_runtime_functions,
    PeRuntimeFunctionInfo,
};

const REVERSE_CALL_INDEX_VERSION: u32 = 3;

#[derive(Debug, Clone)]
pub struct FollowScanConfig {
    pub extra_paths: Vec<String>,
    pub priority_dirs: Vec<String>,
    pub priority_names: Vec<String>,
    pub priority_prefixes: Vec<String>,
    pub priority_regexes: Vec<String>,
    pub no_cwd: bool,
    pub no_path_env: bool,
    pub scan_dirs: Vec<String>,
    pub scan_dlls: Vec<String>,
    pub no_system: bool,
    pub scan_exe: bool,
    pub include: String,
    pub scope_file: String,
    pub exclude: String,
    pub max_dll_bytes: u64,
    pub workers: usize,
    pub arch: String,
    pub depth: usize,
    pub max_callers: usize,
    pub max_total: usize,
    pub filter_dll: String,
    pub show_rva: bool,
    pub show_site: bool,
    pub quiet: bool,
    pub reload: bool,
    pub hostile: bool,
}

impl FollowScanConfig {
    pub fn from_config(cfg: &Config) -> Self {
        Self {
            extra_paths: cfg.extra_paths.clone(),
            priority_dirs: cfg.priority_dirs.clone(),
            priority_names: cfg.priority_names.clone(),
            priority_prefixes: cfg.priority_prefixes.clone(),
            priority_regexes: cfg.priority_regexes.clone(),
            no_cwd: cfg.no_cwd,
            no_path_env: cfg.no_path,
            scan_dirs: cfg.scan_dirs.clone(),
            scan_dlls: cfg.scan_dlls.clone(),
            no_system: cfg.no_system,
            scan_exe: cfg.scan_exe,
            include: cfg.include.clone(),
            scope_file: cfg.scope_file.clone(),
            exclude: cfg.exclude.clone(),
            max_dll_bytes: cfg.max_dll_mb * 1024 * 1024,
            workers: cfg.workers,
            arch: cfg.arch.clone(),
            depth: cfg.depth,
            max_callers: cfg.max_callers,
            max_total: cfg.max_total,
            filter_dll: cfg.filter_dll.clone(),
            show_rva: cfg.show_rva,
            show_site: cfg.show_site,
            quiet: cfg.quiet,
            reload: cfg.reload,
            hostile: cfg.hostile,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSite {
    pub rva: u32,
    pub pattern: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Caller {
    pub func: crate::analysis::follow::trace::FuncRef,
    pub sites: Vec<CallSite>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via_wrapper: Option<String>,
}

/// A named export that is purely a single-JMP stub (thunk) wrapping another target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrapperEntry {
    /// Export name of the wrapper function in this image.
    pub name: String,
    /// RVA of the wrapper function in this image.
    pub rva: u32,
    /// What the wrapper ultimately resolves to.
    pub resolves_to: WrapperTarget,
}

/// The target a wrapper export resolves to.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum WrapperTarget {
    /// Resolves to another function inside the same image.
    Direct { target_rva: u32 },
    /// Resolves to an IAT import (dll_base is lowercase, no extension).
    Import { dll_base: String, func: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseCallIndex {
    #[serde(default)]
    pub index_version: u32,
    pub source_path: String,
    pub file_len: u64,
    pub modified_secs: u64,
    pub modified_nanos: u32,
    pub arch: u32,
    pub image_base: u64,
    pub dll_name: String,
    pub dll_base_lower: String,
    pub dll_path_str: String,
    pub direct: std::collections::HashMap<u32, Vec<Caller>>,
    pub imports: std::collections::HashMap<String, Vec<Caller>>,
    /// Exports in this image that are single-JMP wrappers around another target.
    #[serde(default)]
    pub wrappers: Vec<WrapperEntry>,
}

pub struct ScanImage {
    pub path: PathBuf,
    index: OnceLock<Option<Arc<ReverseCallIndex>>>,
}

struct ScanImageData {
    raw: Vec<u8>,
    pe: crate::formats::pe::PeFile,
    exports: Vec<crate::formats::pe::Export>,
    runtime_functions: Vec<PeRuntimeFunctionInfo>,
    instruction_boundaries: HashSet<u32>,
    dll_name: String,
    dll_base_lower: String,
    dll_path_str: String,
}

impl ScanImage {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            index: OnceLock::new(),
        }
    }

    pub fn index(&self, cfg: &FollowScanConfig) -> Option<&Arc<ReverseCallIndex>> {
        self.index
            .get_or_init(|| load_or_build_index(&self.path, cfg).map(Arc::new))
            .as_ref()
    }
}

fn normalize_dll_base(path_or_name: &str) -> String {
    path_or_name
        .rsplit(&['/', '\\'][..])
        .next()
        .unwrap_or(path_or_name)
        .trim_end_matches(".dll")
        .trim_end_matches(".DLL")
        .to_lowercase()
}

fn owner_func_for_site(
    site_rva: u32,
    data: &ScanImageData,
) -> (u32, crate::analysis::follow::trace::FuncRef) {
    if let Some(runtime) = runtime_for_site(data, site_rva) {
        let export = data
            .exports
            .iter()
            .find(|e| e.rva == runtime.begin_rva)
            .or_else(|| {
                data.exports
                    .iter()
                    .filter(|e| e.rva >= runtime.begin_rva && e.rva < runtime.end_rva)
                    .min_by_key(|e| e.rva)
            });
        let (name, is_internal) = export
            .map(|e| (e.name.clone(), false))
            .unwrap_or_else(|| (format!("sub_{:08X}", runtime.begin_rva), true));
        return (
            runtime.begin_rva,
            crate::analysis::follow::trace::FuncRef::new(
                data.dll_name.clone(),
                data.dll_path_str.clone(),
                name,
                runtime.begin_rva,
                data.pe.image_base + runtime.begin_rva as u64,
                is_internal,
            ),
        );
    }

    if let Some(e) = attribute_to_func(site_rva, &data.exports) {
        (
            e.rva,
            crate::analysis::follow::trace::FuncRef::new(
                data.dll_name.clone(),
                data.dll_path_str.clone(),
                e.name.clone(),
                e.rva,
                data.pe.image_base + e.rva as u64,
                false,
            ),
        )
    } else {
        (
            site_rva,
            crate::analysis::follow::trace::FuncRef::new(
                data.dll_name.clone(),
                data.dll_path_str.clone(),
                format!("sub_{:08X}", site_rva),
                site_rva,
                data.pe.image_base + site_rva as u64,
                true,
            ),
        )
    }
}

fn runtime_for_site(data: &ScanImageData, site_rva: u32) -> Option<&PeRuntimeFunctionInfo> {
    let idx = data
        .runtime_functions
        .partition_point(|runtime| runtime.begin_rva <= site_rva);
    if idx == 0 {
        return None;
    }
    let runtime = &data.runtime_functions[idx - 1];
    (site_rva < runtime.end_rva).then_some(runtime)
}

fn is_decoded_instruction_boundary(data: &ScanImageData, site_rva: u32) -> bool {
    if data.pe.arch != 64 {
        return true;
    }
    data.instruction_boundaries.contains(&site_rva)
}

fn push_indexed_site(
    bucket: &mut std::collections::HashMap<u32, Caller>,
    site: CallSite,
    data: &ScanImageData,
) {
    let (owner_rva, func) = owner_func_for_site(site.rva, data);
    let entry = bucket.entry(owner_rva).or_insert_with(|| Caller {
        func,
        sites: Vec::new(),
        via_wrapper: None,
    });
    entry.sites.push(site);
}

fn direct_target_rva(pe: &crate::formats::pe::PeFile, target_va: u64) -> Option<u32> {
    let delta = target_va.checked_sub(pe.image_base)?;
    let rva = u32::try_from(delta).ok()?;
    pe.rva_to_offset(rva)?;
    Some(rva)
}

fn build_reverse_index(data: &ScanImageData, meta: &SourceMeta, hostile: bool) -> ReverseCallIndex {
    let mut direct: std::collections::HashMap<u32, std::collections::HashMap<u32, Caller>> =
        std::collections::HashMap::new();
    let mut imports: std::collections::HashMap<String, std::collections::HashMap<u32, Caller>> =
        std::collections::HashMap::new();
    let import_slots = import_slot_map_by_va(&data.pe, &data.raw);
    let has_wdf_runtime = import_slots
        .values()
        .any(|(dll_base, func)| dll_base.contains("wdf") || func.starts_with("Wdf"));

    for s in &data.pe.sections {
        if s.characteristics & (SCN_CODE | SCN_EXEC) == 0 {
            continue;
        }
        if s.raw_offset == 0 || s.raw_size == 0 {
            continue;
        }
        let start = s.raw_offset as usize;
        let end = (start + s.raw_size as usize).min(data.raw.len());
        if start >= end {
            continue;
        }
        let sec = &data.raw[start..end];
        let sec_va_base = data.pe.image_base + s.virtual_address as u64;

        // Fast scan for common call/jmp encodings, validated against decoded
        // x64 runtime-function boundaries to avoid matching bytes inside
        // immediates, padding, or data mixed into executable sections.
        for i in 0..sec.len().saturating_sub(5) {
            let site_rva = s.virtual_address + i as u32;
            let b0 = sec[i];
            let b1 = sec.get(i + 1).copied().unwrap_or(0);
            if (b0 == 0xFF && (b1 == 0x15 || b1 == 0x25)) && i + 6 <= sec.len() {
                if !is_decoded_instruction_boundary(data, site_rva) {
                    continue;
                }
                let slot_va = if data.pe.arch == 64 {
                    let rel32 = i32::from_le_bytes(sec[i + 2..i + 6].try_into().unwrap());
                    let instr_va = sec_va_base + i as u64;
                    (instr_va as i64 + 6 + rel32 as i64) as u64
                } else {
                    u32::from_le_bytes(sec[i + 2..i + 6].try_into().unwrap()) as u64
                };
                if let Some((dll_base, func_name)) = import_slots.get(&slot_va) {
                    push_indexed_site(
                        imports
                            .entry(import_lookup_key(dll_base, func_name))
                            .or_default(),
                        CallSite {
                            rva: site_rva,
                            pattern: if b1 == 0x15 {
                                "CALL [IAT]"
                            } else {
                                "JMP [IAT]"
                            }
                            .to_owned(),
                        },
                        data,
                    );
                }
                continue;
            }

            if (b0 == 0xE8 || b0 == 0xE9) && i + 5 <= sec.len() {
                if !is_decoded_instruction_boundary(data, site_rva) {
                    continue;
                }
                let rel32 = i32::from_le_bytes(sec[i + 1..i + 5].try_into().unwrap());
                let instr_va = sec_va_base + i as u64;
                let target_va = (instr_va as i64 + 5 + rel32 as i64) as u64;
                let Some(target_rva) = direct_target_rva(&data.pe, target_va) else {
                    continue;
                };
                push_indexed_site(
                    direct.entry(target_rva).or_default(),
                    CallSite {
                        rva: site_rva,
                        pattern: if b0 == 0xE8 {
                            "CALL rel32"
                        } else {
                            "JMP rel32 (tail)"
                        }
                        .to_owned(),
                    },
                    data,
                );
            }
        }

        if has_wdf_runtime && data.pe.arch == 64 {
            index_wdf_table_calls(sec, sec_va_base, data, &mut imports);
        }

        if hostile {
            use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
            let mut decoder =
                Decoder::with_ip(data.pe.arch, sec, sec_va_base, DecoderOptions::NONE);
            while decoder.can_decode() {
                let instr = decoder.decode();
                if instr.len() == 0 {
                    break;
                }
                let m = instr.mnemonic();
                if !matches!(m, Mnemonic::Call | Mnemonic::Jmp)
                    || instr.op0_kind() != OpKind::Register
                {
                    continue;
                }
                let site_rva = instr.ip().wrapping_sub(data.pe.image_base) as u32;
                let reg = format!("{:?}", instr.op0_register().full_register()).to_lowercase();
                push_indexed_site(
                    direct.entry(site_rva).or_default(),
                    CallSite {
                        rva: site_rva,
                        pattern: if m == Mnemonic::Call {
                            format!("CALL {reg}")
                        } else {
                            format!("JMP {reg}")
                        },
                    },
                    data,
                );
            }
        }
    } // end for s in &data.pe.sections

    let direct = direct
        .into_iter()
        .map(|(rva, grouped)| {
            let mut callers: Vec<Caller> = grouped.into_values().collect();
            callers.sort_by(|a, b| a.func.key().cmp(b.func.key()));
            (rva, callers)
        })
        .collect();

    let imports = imports
        .into_iter()
        .map(|(key, grouped)| {
            let mut callers: Vec<Caller> = grouped.into_values().collect();
            callers.sort_by(|a, b| a.func.key().cmp(b.func.key()));
            (key, callers)
        })
        .collect();

    // Wrapper detection: scan every named export for a single-JMP stub.
    // Always-on — not gated on `hostile` — because detecting callers via wrappers
    // is a fundamental capability independent of aggressive tracing.
    let mut wrappers: Vec<WrapperEntry> = Vec::new();
    for export in &data.exports {
        if export.name.is_empty() || export.rva == 0 {
            continue;
        }
        let Some(res) = follow_jmp_thunk(&data.raw, &data.pe, export.rva) else {
            continue;
        };
        let target = match res {
            ThunkResolution::Iat { dll, func, .. } => WrapperTarget::Import {
                dll_base: normalize_dll_base(&dll),
                func,
            },
            ThunkResolution::Chain {
                ref final_target, ..
            } => match final_target.as_ref() {
                ThunkResolution::Iat { dll, func, .. } => WrapperTarget::Import {
                    dll_base: normalize_dll_base(dll),
                    func: func.clone(),
                },
                ThunkResolution::Direct { target_rva } => {
                    if *target_rva != export.rva {
                        WrapperTarget::Direct {
                            target_rva: *target_rva,
                        }
                    } else {
                        continue;
                    }
                }
                _ => continue,
            },
            ThunkResolution::Direct { target_rva } => {
                if target_rva != export.rva {
                    WrapperTarget::Direct { target_rva }
                } else {
                    continue;
                }
            }
            ThunkResolution::IatUnresolved { .. } => continue,
        };
        wrappers.push(WrapperEntry {
            name: export.name.clone(),
            rva: export.rva,
            resolves_to: target,
        });
    }

    ReverseCallIndex {
        index_version: REVERSE_CALL_INDEX_VERSION,
        source_path: meta.path.clone(),
        file_len: meta.file_len,
        modified_secs: meta.modified_secs,
        modified_nanos: meta.modified_nanos,
        arch: data.pe.arch,
        image_base: data.pe.image_base,
        dll_name: data.dll_name.clone(),
        dll_base_lower: data.dll_base_lower.clone(),
        dll_path_str: data.dll_path_str.clone(),
        direct,
        imports,
        wrappers,
    }
}

fn index_wdf_table_calls(
    sec: &[u8],
    sec_va_base: u64,
    data: &ScanImageData,
    imports: &mut std::collections::HashMap<String, std::collections::HashMap<u32, Caller>>,
) {
    use iced_x86::{Decoder, DecoderOptions, Instruction, Mnemonic, OpKind, Register};

    let mut decoder = Decoder::with_ip(data.pe.arch, sec, sec_va_base, DecoderOptions::NONE);
    let mut insns = Vec::new();
    while decoder.can_decode() {
        let instr = decoder.decode();
        if instr.len() == 0 {
            break;
        }
        insns.push(instr);
    }

    for (idx, instr) in insns.iter().enumerate() {
        if instr.mnemonic() != Mnemonic::Call {
            continue;
        }
        let reg = if instr.op0_kind() == OpKind::Register {
            instr.op0_register()
        } else if instr.op0_kind() == OpKind::Memory {
            // MSVC CFG/XFG guarded indirect calls dispatch through this helper after
            // loading the real target into RAX.
            Register::RAX
        } else {
            continue;
        };
        let Some((func_name, offset)) = resolve_wdf_table_register_call(&insns, idx, reg) else {
            continue;
        };
        let site_rva = instr.ip().wrapping_sub(data.pe.image_base) as u32;
        push_indexed_site(
            imports
                .entry(import_lookup_key("wdf", func_name))
                .or_default(),
            CallSite {
                rva: site_rva,
                pattern: format!("CALL WDF[0x{offset:X}]"),
            },
            data,
        );
    }

    fn resolve_wdf_table_register_call(
        insns: &[Instruction],
        call_idx: usize,
        reg: Register,
    ) -> Option<(&'static str, u64)> {
        let full = reg.full_register();
        let scan_start = call_idx.saturating_sub(96);
        for table_idx in (scan_start..call_idx).rev() {
            let table_load = &insns[table_idx];
            if table_load.mnemonic() != Mnemonic::Mov
                || table_load.op_count() < 2
                || table_load.op0_kind() != OpKind::Register
                || table_load.op0_register().full_register() != full
                || table_load.op1_kind() != OpKind::Memory
                || table_load.memory_base().full_register() != full
                || table_load.memory_index() != Register::None
            {
                continue;
            }

            let offset = table_load.memory_displacement64();
            let Some(func) = crate::analysis::wdf::function_from_offset(offset, 8) else {
                continue;
            };
            let found_table_root = insns[scan_start..table_idx]
                .iter()
                .rev()
                .take(24)
                .any(|insn| {
                    insn.mnemonic() == Mnemonic::Mov
                        && insn.op_count() >= 2
                        && insn.op0_kind() == OpKind::Register
                        && insn.op0_register().full_register() == full
                        && insn.op1_kind() == OpKind::Memory
                        && matches!(insn.memory_base(), Register::RIP | Register::EIP)
                });
            if found_table_root {
                return Some((func.name, offset));
            }
        }
        None
    }
}

pub fn system_dirs(cfg: &FollowScanConfig) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    dirs.extend(cfg.priority_dirs.iter().map(PathBuf::from));
    if !cfg.no_system {
        dirs.extend(default_priority_dirs());
    }
    let mut seen = std::collections::HashSet::new();
    dirs.retain(|dir| seen.insert(dir.to_string_lossy().to_ascii_lowercase()));
    dirs
}

pub fn find_target_dll(name: &str, cfg: &FollowScanConfig) -> Result<PathBuf, String> {
    if name.contains('/') || name.contains('\\') {
        let p = PathBuf::from(name);
        if p.exists() {
            return p.canonicalize().map_err(|e| e.to_string());
        }
        return Err(format!("not found: {}", name));
    }
    let bases = image_name_candidates(name);

    let mut dirs: Vec<PathBuf> = cfg.extra_paths.iter().map(PathBuf::from).collect();
    if !cfg.no_cwd {
        if let Ok(d) = std::env::current_dir() {
            dirs.push(d);
        }
    }
    dirs.extend(system_dirs(cfg));
    if !cfg.no_path_env {
        if let Ok(path) = std::env::var("PATH") {
            for p in std::env::split_paths(&path) {
                if !p.as_os_str().is_empty() {
                    dirs.push(p);
                }
            }
        }
    }

    for dir in &dirs {
        for base in &bases {
            let c = dir.join(base);
            if c.exists() {
                return c.canonicalize().map_err(|e| e.to_string());
            }
        }
    }
    Err(format!(
        "'{}' not found in priority dirs, System32, or PATH; use --priority to edit the priority config, --path, or provide full path",
        name
    ))
}

pub fn build_scan_list(cfg: &FollowScanConfig, target_dll: &Path) -> Vec<PathBuf> {
    if is_external_driver_target(target_dll) && cfg.scan_dirs.is_empty() && cfg.scan_dlls.is_empty()
    {
        return vec![target_dll.to_path_buf()];
    }

    let exts: Vec<&str> = if cfg.scan_exe {
        vec!["dll", "sys", "exe"]
    } else {
        vec!["dll", "sys"]
    };
    let mut seen = std::collections::HashSet::new();
    let mut paths = Vec::new();
    let priority = matcher_from_lists(
        cfg.priority_names.clone(),
        cfg.priority_prefixes.clone(),
        cfg.priority_regexes.clone(),
    );

    let add_dir = |dir: &Path,
                   paths: &mut Vec<PathBuf>,
                   seen: &mut std::collections::HashSet<String>,
                   exts: &[&str],
                   cfg: &FollowScanConfig,
                   enforce_priority: bool,
                   apply_scope_file: bool| {
        let Ok(entries) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in entries.flatten() {
            let p = entry.path();
            let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !exts.iter().any(|e| e.eq_ignore_ascii_case(ext)) {
                continue;
            }

            let abs = match p.canonicalize() {
                Ok(a) => a,
                Err(_) => continue,
            };
            let low = abs.to_string_lossy().to_lowercase();
            if seen.contains(&low) {
                continue;
            }

            if cfg.max_dll_bytes > 0 {
                if let Ok(m) = abs.metadata() {
                    if m.len() > cfg.max_dll_bytes {
                        continue;
                    }
                }
            }

            let base = abs.file_name().unwrap_or_default().to_string_lossy();
            if !cfg.include.is_empty() && !glob_match(&cfg.include, &base) {
                continue;
            }
            if apply_scope_file && !cfg.scope_file.is_empty() && !glob_match(&cfg.scope_file, &base)
            {
                continue;
            }
            if !cfg.exclude.is_empty() && glob_match(&cfg.exclude, &base) {
                continue;
            }
            if enforce_priority && !priority.is_priority_path(&abs) {
                continue;
            }

            seen.insert(low);
            paths.push(abs);
        }
    };

    for dir in system_dirs(cfg) {
        add_dir(&dir, &mut paths, &mut seen, &exts, cfg, true, false);
    }
    for dir in cfg.scan_dirs.iter().map(PathBuf::from) {
        add_dir(&dir, &mut paths, &mut seen, &exts, cfg, false, true);
    }
    for dll_arg in &cfg.scan_dlls {
        if let Ok(p) = find_target_dll(dll_arg, cfg) {
            let low = p.to_string_lossy().to_lowercase();
            if seen.insert(low) {
                paths.push(p);
            }
        }
    }

    let target_low = target_dll.to_string_lossy().to_lowercase();
    if !paths
        .iter()
        .any(|p| p.to_string_lossy().to_lowercase() == target_low)
    {
        paths.push(target_dll.to_path_buf());
    }
    paths.sort();
    paths
}

fn is_external_driver_target(target: &Path) -> bool {
    let is_sys = target
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|ext| ext.eq_ignore_ascii_case("sys"))
        .unwrap_or(false);
    if !is_sys {
        return false;
    }

    let lower = target.to_string_lossy().to_ascii_lowercase();
    !(lower.contains("\\windows\\system32\\")
        || lower.contains("\\windows\\sysnative\\")
        || lower.contains("\\windows\\syswow64\\")
        || lower.contains("\\windows\\system32\\drivers\\"))
}

fn glob_match(pattern: &str, name: &str) -> bool {
    let p: Vec<char> = pattern.to_lowercase().chars().collect();
    let n: Vec<char> = name.to_lowercase().chars().collect();
    glob_inner(&p, &n)
}

fn glob_inner(p: &[char], n: &[char]) -> bool {
    match (p.first(), n.first()) {
        (None, None) => true,
        (Some(&'*'), _) => glob_inner(&p[1..], n) || (!n.is_empty() && glob_inner(p, &n[1..])),
        (Some(&'?'), Some(_)) => glob_inner(&p[1..], &n[1..]),
        (Some(a), Some(b)) if a == b => glob_inner(&p[1..], &n[1..]),
        _ => false,
    }
}

pub fn import_lookup_key(dll_base: &str, func_name: &str) -> String {
    let mut key = String::with_capacity(dll_base.len() + 1 + func_name.len());
    key.push_str(dll_base);
    key.push('!');
    key.push_str(func_name);
    key
}

const SCN_CODE: u32 = 0x0000_0020;
const SCN_EXEC: u32 = 0x2000_0000;

#[derive(Debug, Clone)]
struct SourceMeta {
    path: String,
    file_len: u64,
    modified_secs: u64,
    modified_nanos: u32,
}

fn read_source_meta(path: &Path) -> Option<SourceMeta> {
    let metadata = path.metadata().ok()?;
    let modified = metadata.modified().ok()?;
    let modified = modified.duration_since(UNIX_EPOCH).ok()?;
    Some(SourceMeta {
        path: path.to_string_lossy().to_string(),
        file_len: metadata.len(),
        modified_secs: modified.as_secs(),
        modified_nanos: modified.subsec_nanos(),
    })
}

fn load_scan_data(path: &Path) -> Option<ScanImageData> {
    let raw = std::fs::read(path).ok()?;
    let pe = parse_pe(&raw).ok()?;
    let exports = read_exports(&pe, &raw);
    let runtime_functions = read_runtime_functions(&pe, &raw);
    let instruction_boundaries = collect_instruction_boundaries(&pe, &raw, &runtime_functions);
    let dll_name = path.file_name()?.to_string_lossy().to_string();
    let dll_base_lower = normalize_dll_base(&dll_name);
    let dll_path_str = path.to_string_lossy().to_string();
    Some(ScanImageData {
        raw,
        pe,
        exports,
        runtime_functions,
        instruction_boundaries,
        dll_name,
        dll_base_lower,
        dll_path_str,
    })
}

fn collect_instruction_boundaries(
    pe: &crate::formats::pe::PeFile,
    raw: &[u8],
    runtime_functions: &[PeRuntimeFunctionInfo],
) -> HashSet<u32> {
    let mut out = HashSet::new();
    if pe.arch != 64 {
        return out;
    }

    use iced_x86::{Decoder, DecoderOptions};
    for runtime in runtime_functions {
        let Some(start) = pe.rva_to_offset(runtime.begin_rva) else {
            continue;
        };
        let Some(end) = pe
            .rva_to_offset(runtime.end_rva.saturating_sub(1))
            .map(|off| off + 1)
        else {
            continue;
        };
        if start >= end || end > raw.len() {
            continue;
        }

        let mut decoder = Decoder::with_ip(
            pe.arch,
            &raw[start..end],
            pe.image_base + runtime.begin_rva as u64,
            DecoderOptions::NONE,
        );
        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.len() == 0 {
                break;
            }
            out.insert(instr.ip().wrapping_sub(pe.image_base) as u32);
        }
    }
    out
}

fn load_or_build_index(path: &Path, cfg: &FollowScanConfig) -> Option<ReverseCallIndex> {
    let meta = read_source_meta(path)?;
    if !cfg.reload {
        if let Some(cached) = load_index_from_cache(path, &meta) {
            return Some(cached);
        }
    }

    let data = load_scan_data(path)?;
    let index = build_reverse_index(&data, &meta, cfg.hostile);
    if !cfg.reload {
        let _ = write_index_to_cache(path, &index);
    }
    Some(index)
}

fn load_index_from_cache(path: &Path, meta: &SourceMeta) -> Option<ReverseCallIndex> {
    let cache_path = cache_path_for_image(path);
    let bytes = std::fs::read(cache_path).ok()?;
    let cached: ReverseCallIndex = serde_json::from_slice(&bytes).ok()?;
    if cached.index_version == REVERSE_CALL_INDEX_VERSION
        && cached.source_path.eq_ignore_ascii_case(&meta.path)
        && cached.file_len == meta.file_len
        && cached.modified_secs == meta.modified_secs
        && cached.modified_nanos == meta.modified_nanos
    {
        Some(cached)
    } else {
        None
    }
}

fn write_index_to_cache(path: &Path, index: &ReverseCallIndex) -> Result<(), String> {
    let cache_path = cache_path_for_image(path);
    if let Some(parent) = cache_path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let bytes = serde_json::to_vec(index).map_err(|e| e.to_string())?;
    std::fs::write(cache_path, bytes).map_err(|e| e.to_string())
}

fn cache_path_for_image(path: &Path) -> PathBuf {
    let canonical = path
        .canonicalize()
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_ascii_lowercase();
    let mut hasher = DefaultHasher::new();
    canonical.hash(&mut hasher);
    let stem = path.file_name().and_then(|n| n.to_str()).unwrap_or("image");
    follow_cache_root().join(format!("{}.{:016x}.json", stem, hasher.finish()))
}

fn follow_cache_root() -> PathBuf {
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        return PathBuf::from(local).join("resx").join("follow-index");
    }
    std::env::temp_dir().join("resx").join("follow-index")
}
