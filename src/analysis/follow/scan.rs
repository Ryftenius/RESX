use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use crate::core::config::Config;
use crate::core::priority::{default_priority_dirs, matcher_from_lists};
use crate::formats::pe::{
    attribute_to_func, parse_pe, read_cstr, read_exports, read_u32, read_u64,
};

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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReverseCallIndex {
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
}

pub struct ScanImage {
    pub path: PathBuf,
    index: OnceLock<Option<Arc<ReverseCallIndex>>>,
}

struct ScanImageData {
    raw: Vec<u8>,
    pe: crate::formats::pe::PeFile,
    exports: Vec<crate::formats::pe::Export>,
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

fn read_import_slots(
    pe: &crate::formats::pe::PeFile,
    raw: &[u8],
) -> std::collections::HashMap<u64, (String, String)> {
    let mut slots = std::collections::HashMap::new();
    let (dir_rva, _) = pe.data_dir(1);
    if dir_rva == 0 {
        return slots;
    }
    let Some(mut off) = pe.rva_to_offset(dir_rva) else {
        return slots;
    };
    let ptr_size = if pe.arch == 64 { 8u32 } else { 4u32 };
    let ord_flag_64 = 1u64 << 63;
    let ord_flag_32 = 1u64 << 31;

    loop {
        if off + 20 > raw.len() {
            break;
        }
        let ilt_rva = read_u32(raw, off);
        let name_rva = read_u32(raw, off + 12);
        let iat_rva = read_u32(raw, off + 16);
        off += 20;
        if name_rva == 0 && ilt_rva == 0 {
            break;
        }

        let Some(name_off) = pe.rva_to_offset(name_rva) else {
            continue;
        };
        let dll_name = read_cstr(raw, name_off);
        let dll_base = normalize_dll_base(&dll_name);
        let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let Some(mut ilt_off) = pe.rva_to_offset(thunk_rva) else {
            continue;
        };

        let mut slot_idx = 0u32;
        loop {
            let thunk = if pe.arch == 64 {
                let v = read_u64(raw, ilt_off);
                ilt_off += 8;
                v
            } else {
                let v = read_u32(raw, ilt_off) as u64;
                ilt_off += 4;
                v
            };
            if thunk == 0 {
                break;
            }

            let is_ord = (pe.arch == 64 && thunk & ord_flag_64 != 0)
                || (pe.arch == 32 && thunk & ord_flag_32 != 0);
            let func_name = if is_ord {
                format!("#{}", thunk & 0xFFFF)
            } else {
                let hint_rva = (thunk & 0x7FFF_FFFF) as u32;
                match pe.rva_to_offset(hint_rva) {
                    Some(ho) => read_cstr(raw, ho + 2),
                    None => format!("ord_{}", thunk & 0xFFFF),
                }
            };

            let slot_va = pe.image_base + (iat_rva + slot_idx * ptr_size) as u64;
            slots.insert(slot_va, (dll_base.clone(), func_name));
            slot_idx += 1;
        }
    }

    slots
}

fn owner_func_for_site(
    site_rva: u32,
    data: &ScanImageData,
) -> (u32, crate::analysis::follow::trace::FuncRef) {
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

fn push_indexed_site(
    bucket: &mut std::collections::HashMap<u32, Caller>,
    site: CallSite,
    data: &ScanImageData,
) {
    let (owner_rva, func) = owner_func_for_site(site.rva, data);
    let entry = bucket.entry(owner_rva).or_insert_with(|| Caller {
        func,
        sites: Vec::new(),
    });
    entry.sites.push(site);
}

fn direct_target_rva(pe: &crate::formats::pe::PeFile, target_va: u64) -> Option<u32> {
    let delta = target_va.checked_sub(pe.image_base)?;
    let rva = u32::try_from(delta).ok()?;
    pe.rva_to_offset(rva)?;
    Some(rva)
}

fn build_reverse_index(data: &ScanImageData, meta: &SourceMeta) -> ReverseCallIndex {
    let mut direct: std::collections::HashMap<u32, std::collections::HashMap<u32, Caller>> =
        std::collections::HashMap::new();
    let mut imports: std::collections::HashMap<String, std::collections::HashMap<u32, Caller>> =
        std::collections::HashMap::new();
    let import_slots = read_import_slots(&data.pe, &data.raw);

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

        for i in 0..sec.len().saturating_sub(5) {
            let b0 = sec[i];
            let b1 = sec.get(i + 1).copied().unwrap_or(0);
            if (b0 == 0xFF && (b1 == 0x15 || b1 == 0x25)) && i + 6 <= sec.len() {
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
                            rva: s.virtual_address + i as u32,
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
                let rel32 = i32::from_le_bytes(sec[i + 1..i + 5].try_into().unwrap());
                let instr_va = sec_va_base + i as u64;
                let target_va = (instr_va as i64 + 5 + rel32 as i64) as u64;
                let Some(target_rva) = direct_target_rva(&data.pe, target_va) else {
                    continue;
                };
                push_indexed_site(
                    direct.entry(target_rva).or_default(),
                    CallSite {
                        rva: s.virtual_address + i as u32,
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
    }

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

    ReverseCallIndex {
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
    let base = if Path::new(name).extension().is_none() {
        format!("{}.dll", name)
    } else {
        name.to_owned()
    };

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
        let c = dir.join(&base);
        if c.exists() {
            return c.canonicalize().map_err(|e| e.to_string());
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
    let dll_name = path.file_name()?.to_string_lossy().to_string();
    let dll_base_lower = normalize_dll_base(&dll_name);
    let dll_path_str = path.to_string_lossy().to_string();
    Some(ScanImageData {
        raw,
        pe,
        exports,
        dll_name,
        dll_base_lower,
        dll_path_str,
    })
}

fn load_or_build_index(path: &Path, cfg: &FollowScanConfig) -> Option<ReverseCallIndex> {
    let meta = read_source_meta(path)?;
    if !cfg.reload {
        if let Some(cached) = load_index_from_cache(path, &meta) {
            return Some(cached);
        }
    }

    let data = load_scan_data(path)?;
    let index = build_reverse_index(&data, &meta);
    if !cfg.reload {
        let _ = write_index_to_cache(path, &index);
    }
    Some(index)
}

fn load_index_from_cache(path: &Path, meta: &SourceMeta) -> Option<ReverseCallIndex> {
    let cache_path = cache_path_for_image(path);
    let bytes = std::fs::read(cache_path).ok()?;
    let cached: ReverseCallIndex = serde_json::from_slice(&bytes).ok()?;
    if cached.source_path.eq_ignore_ascii_case(&meta.path)
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
