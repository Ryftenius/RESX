use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

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
        }
    }
}

#[derive(Debug, Clone)]
pub struct CallSite {
    pub rva: u32,
    pub pattern: String,
}

#[derive(Debug, Clone)]
pub struct Caller {
    pub func: crate::analysis::follow::trace::FuncRef,
    pub sites: Vec<CallSite>,
}

pub struct ScanImage {
    pub path: PathBuf,
    data: OnceLock<Option<Arc<ScanImageData>>>,
    index: OnceLock<Option<Arc<ReverseCallIndex>>>,
}

pub struct ScanImageData {
    pub raw: Vec<u8>,
    pub pe: crate::formats::pe::PeFile,
    pub exports: Vec<crate::formats::pe::Export>,
    pub dll_name: String,
    pub dll_base_lower: String,
    pub dll_path_str: String,
}

struct IndexedCaller {
    func: crate::analysis::follow::trace::FuncRef,
    sites: Vec<CallSite>,
}

struct ReverseCallIndex {
    direct: std::collections::HashMap<u64, Vec<IndexedCaller>>,
    imports: std::collections::HashMap<String, Vec<IndexedCaller>>,
}

impl ScanImage {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            data: OnceLock::new(),
            index: OnceLock::new(),
        }
    }

    pub fn data(&self) -> Option<&Arc<ScanImageData>> {
        self.data
            .get_or_init(|| {
                let raw = std::fs::read(&self.path).ok()?;
                let pe = parse_pe(&raw).ok()?;
                let exports = read_exports(&pe, &raw);
                let dll_name = self
                    .path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let dll_base_lower = dll_name.to_lowercase();
                let dll_path_str = self.path.to_string_lossy().to_string();
                Some(Arc::new(ScanImageData {
                    raw,
                    pe,
                    exports,
                    dll_name,
                    dll_base_lower,
                    dll_path_str,
                }))
            })
            .as_ref()
    }

    fn index(&self) -> Option<&Arc<ReverseCallIndex>> {
        self.index
            .get_or_init(|| {
                let data = self.data()?;
                Some(Arc::new(build_reverse_index(data)))
            })
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
    bucket: &mut std::collections::HashMap<u32, IndexedCaller>,
    site: CallSite,
    data: &ScanImageData,
) {
    let (owner_rva, func) = owner_func_for_site(site.rva, data);
    let entry = bucket.entry(owner_rva).or_insert_with(|| IndexedCaller {
        func,
        sites: Vec::new(),
    });
    entry.sites.push(site);
}

fn build_reverse_index(data: &ScanImageData) -> ReverseCallIndex {
    let mut direct: std::collections::HashMap<u64, std::collections::HashMap<u32, IndexedCaller>> =
        std::collections::HashMap::new();
    let mut imports: std::collections::HashMap<
        String,
        std::collections::HashMap<u32, IndexedCaller>,
    > = std::collections::HashMap::new();
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

        if data.pe.arch == 64 {
            for i in 0..sec.len().saturating_sub(5) {
                let b0 = sec[i];
                let b1 = sec.get(i + 1).copied().unwrap_or(0);
                if (b0 == 0xFF && (b1 == 0x15 || b1 == 0x25)) && i + 6 <= sec.len() {
                    let rel32 = i32::from_le_bytes(sec[i + 2..i + 6].try_into().unwrap());
                    let instr_va = sec_va_base + i as u64;
                    let slot_va = (instr_va as i64 + 6 + rel32 as i64) as u64;
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
                    push_indexed_site(
                        direct.entry(target_va).or_default(),
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
        } else {
            for i in 0..sec.len().saturating_sub(5) {
                let b0 = sec[i];
                let b1 = sec.get(i + 1).copied().unwrap_or(0);
                if (b0 == 0xFF && (b1 == 0x15 || b1 == 0x25)) && i + 6 <= sec.len() {
                    let slot_va = u32::from_le_bytes(sec[i + 2..i + 6].try_into().unwrap()) as u64;
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
                    push_indexed_site(
                        direct.entry(target_va).or_default(),
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
    }

    let direct = direct
        .into_iter()
        .map(|(va, grouped)| {
            let mut callers: Vec<IndexedCaller> = grouped.into_values().collect();
            callers.sort_by(|a, b| a.func.key().cmp(b.func.key()));
            (va, callers)
        })
        .collect();

    let imports = imports
        .into_iter()
        .map(|(key, grouped)| {
            let mut callers: Vec<IndexedCaller> = grouped.into_values().collect();
            callers.sort_by(|a, b| a.func.key().cmp(b.func.key()));
            (key, callers)
        })
        .collect();

    ReverseCallIndex { direct, imports }
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
        vec!["dll", "exe"]
    } else {
        vec!["dll"]
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
                   enforce_priority: bool| {
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
        add_dir(&dir, &mut paths, &mut seen, &exts, cfg, true);
    }
    for dir in cfg.scan_dirs.iter().map(PathBuf::from) {
        add_dir(&dir, &mut paths, &mut seen, &exts, cfg, false);
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

const SCN_CODE: u32 = 0x0000_0020;
const SCN_EXEC: u32 = 0x2000_0000;

pub fn scan_image_for_callers(
    image: &ScanImage,
    target: &crate::analysis::follow::trace::FuncRef,
    target_arch: u32,
    cfg: &FollowScanConfig,
) -> Vec<Caller> {
    let Some(data) = image.data() else {
        return Vec::new();
    };
    let Some(index) = image.index() else {
        return Vec::new();
    };
    let pe = &data.pe;

    let arch_match = match cfg.arch.as_str() {
        "x86" | "32" => pe.arch == 32,
        "x64" | "64" => pe.arch == 64,
        _ => target_arch == 0 || pe.arch == target_arch,
    };
    if !arch_match {
        return Vec::new();
    }

    let dll_base = &data.dll_base_lower;
    let is_same_dll = dll_base == &target.dll_base;

    let callers = if is_same_dll {
        index.direct.get(&target.va)
    } else {
        index
            .imports
            .get(&import_lookup_key(&target.dll_base, &target.name))
    };

    callers
        .map(|matches| {
            matches
                .iter()
                .map(|entry| Caller {
                    func: entry.func.clone(),
                    sites: entry.sites.clone(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn import_lookup_key(dll_base: &str, func_name: &str) -> String {
    let mut key = String::with_capacity(dll_base.len() + 1 + func_name.len());
    key.push_str(dll_base);
    key.push('!');
    key.push_str(func_name);
    key
}
