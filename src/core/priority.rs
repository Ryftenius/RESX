use std::path::{Path, PathBuf};

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::core::config::Config;

pub const EXACT_SEARCH_PRIORITY: &[&str] = &[
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

pub const PREFIX_SEARCH_PRIORITY: &[&str] = &[
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PriorityFileConfig {
    #[serde(default)]
    pub priority_dirs: Vec<String>,
    #[serde(default)]
    pub exact_names: Vec<String>,
    #[serde(default)]
    pub prefixes: Vec<String>,
    #[serde(default)]
    pub regexes: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct PriorityMatcher {
    exact_names: Vec<String>,
    prefixes: Vec<String>,
    regexes: Vec<Regex>,
}

impl PriorityMatcher {
    pub fn is_priority_path(&self, path: &Path) -> bool {
        self.filename_rank(path) < self.non_priority_rank_base()
    }

    pub fn filename_rank(&self, path: &Path) -> u16 {
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            return 999;
        };
        let lower = file_name.to_ascii_lowercase();

        if let Some((idx, _)) = self
            .exact_names
            .iter()
            .enumerate()
            .find(|(_, name)| lower == **name)
        {
            return idx as u16;
        }

        let family_base = self.exact_names.len() as u16;
        if let Some((idx, _)) = self
            .prefixes
            .iter()
            .enumerate()
            .find(|(_, prefix)| lower.starts_with(prefix.as_str()))
        {
            return family_base + idx as u16;
        }

        let regex_base = family_base + self.prefixes.len() as u16;
        if let Some((idx, _)) = self
            .regexes
            .iter()
            .enumerate()
            .find(|(_, regex)| regex.is_match(&lower))
        {
            return regex_base + idx as u16;
        }

        self.non_priority_rank_base()
    }

    pub fn non_priority_rank_base(&self) -> u16 {
        self.exact_names.len() as u16 + self.prefixes.len() as u16 + self.regexes.len() as u16 + 100
    }
}

pub fn system_root() -> String {
    std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned())
}

pub fn default_priority_dirs() -> Vec<PathBuf> {
    let windir = system_root();
    vec![
        PathBuf::from(&windir).join("System32"),
        PathBuf::from(&windir).join("SysWOW64"),
        PathBuf::from(&windir).join("System32").join("drivers"),
    ]
}

pub fn extended_system_search_dirs() -> Vec<PathBuf> {
    let windir = system_root();
    vec![
        PathBuf::from(&windir).join("System32"),
        PathBuf::from(&windir).join("SysWOW64"),
        PathBuf::from(&windir).join("Sysnative"),
        PathBuf::from(&windir),
        PathBuf::from(&windir).join("WinSxS"),
        PathBuf::from(&windir).join("System32").join("drivers"),
    ]
}

pub fn matcher(cfg: &Config) -> PriorityMatcher {
    matcher_from_lists(
        cfg.priority_names.clone(),
        cfg.priority_prefixes.clone(),
        cfg.priority_regexes.clone(),
    )
}

pub fn built_in_priority_names() -> Vec<String> {
    EXACT_SEARCH_PRIORITY
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

pub fn built_in_priority_prefixes() -> Vec<String> {
    PREFIX_SEARCH_PRIORITY
        .iter()
        .map(|s| (*s).to_owned())
        .collect()
}

pub fn matcher_from_lists(
    exact_names: Vec<String>,
    prefixes: Vec<String>,
    regexes: Vec<String>,
) -> PriorityMatcher {
    let regexes = regexes
        .iter()
        .filter_map(|pattern| Regex::new(pattern).ok())
        .collect();
    PriorityMatcher {
        exact_names,
        prefixes,
        regexes,
    }
}

pub fn merged_priority_dirs(cfg: &Config) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = cfg.priority_dirs.iter().map(PathBuf::from).collect();
    dirs.extend(default_priority_dirs());
    dedup_dirs(dirs)
}

pub fn global_lookup_dirs(cfg: &Config) -> Vec<PathBuf> {
    let mut dirs = merged_priority_dirs(cfg);
    dirs.extend(cfg.extra_paths.iter().map(PathBuf::from));

    if !cfg.no_cwd {
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd);
        }
    }

    if !cfg.no_system {
        dirs.extend(extended_system_search_dirs());
    }

    if !cfg.no_path {
        if let Ok(path_env) = std::env::var("PATH") {
            dirs.extend(std::env::split_paths(&path_env).filter(|p| !p.as_os_str().is_empty()));
        }
    }

    dedup_dirs(dirs)
}

pub fn load_priority_file() -> PriorityFileConfig {
    let path = priority_config_path();
    let Ok(raw) = std::fs::read_to_string(path) else {
        return PriorityFileConfig::default();
    };
    serde_json::from_str(&raw).unwrap_or_default()
}

pub fn ensure_priority_file() -> Result<PathBuf, String> {
    let path = priority_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("create priority config dir: {}", e))?;
    }
    if !path.exists() {
        let template = serde_json::to_string_pretty(&PriorityFileConfig {
            priority_dirs: vec![r"C:\Symbols\System".to_owned()],
            exact_names: vec!["mydriver.sys".to_owned()],
            prefixes: vec!["myco-".to_owned()],
            regexes: vec!["^nt.*\\.dll$".to_owned()],
        })
        .map_err(|e| format!("serialize priority config: {}", e))?;
        std::fs::write(&path, format!("{}\n", template))
            .map_err(|e| format!("write priority config: {}", e))?;
    }
    Ok(path)
}

pub fn open_priority_file() -> Result<PathBuf, String> {
    let path = ensure_priority_file()?;
    std::process::Command::new("notepad.exe")
        .arg(&path)
        .spawn()
        .map_err(|e| format!("open priority config: {}", e))?;
    Ok(path)
}

pub fn priority_config_path() -> PathBuf {
    let base = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .or_else(|| std::env::current_dir().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    base.join("RESX").join("priority.json")
}

fn dedup_dirs(dirs: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    for dir in dirs {
        let key = dir.to_string_lossy().to_ascii_lowercase();
        if key.is_empty() || !seen.insert(key) {
            continue;
        }
        out.push(dir);
    }
    out
}
