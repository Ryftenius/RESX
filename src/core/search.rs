use std::path::{Path, PathBuf};

use crate::core::config::Config;

pub fn system_search_paths() -> Vec<PathBuf> {
    let windir = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned());
    vec![
        PathBuf::from(&windir).join("System32"),
        PathBuf::from(&windir).join("SysWOW64"),
        PathBuf::from(&windir).join("Sysnative"),
        PathBuf::from(&windir),
        PathBuf::from(&windir).join("WinSxS"),
        PathBuf::from(&windir).join("System32").join("drivers"),
    ]
}

pub fn find_dll_path(name: &str, cfg: &Config) -> Result<PathBuf, String> {
    if name.contains('/') || name.contains('\\') {
        let p = PathBuf::from(name);
        if p.exists() {
            return p.canonicalize().map_err(|e| e.to_string());
        }
        return Err(format!("file not found: {}", name));
    }

    let base = if Path::new(name).extension().is_none() {
        format!("{}.dll", name)
    } else {
        name.to_owned()
    };

    let mut dirs: Vec<PathBuf> = Vec::new();

    for p in &cfg.extra_paths {
        dirs.push(PathBuf::from(p));
    }

    if !cfg.no_cwd {
        if let Ok(cwd) = std::env::current_dir() {
            dirs.push(cwd);
        }
    }

    if !cfg.no_system {
        dirs.extend(system_search_paths());
    }

    if !cfg.no_path {
        if let Ok(path_env) = std::env::var("PATH") {
            for p in std::env::split_paths(&path_env) {
                if !p.as_os_str().is_empty() {
                    dirs.push(p);
                }
            }
        }
    }

    for dir in &dirs {
        let candidate = dir.join(&base);
        if candidate.exists() {
            return candidate.canonicalize().map_err(|e| e.to_string());
        }
    }

    Err(format!(
        "'{}' not found in any search path\n  searched: system32, SysWOW64, Sysnative, WinSxS, System32\\drivers, CWD, PATH\n  use --path <dir> to add a custom search location, or provide a full path",
        name
    ))
}
