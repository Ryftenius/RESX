use std::path::{Path, PathBuf};

use crate::core::config::Config;
use crate::core::priority::global_lookup_dirs;

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

    let dirs = global_lookup_dirs(cfg);

    for dir in &dirs {
        let candidate = dir.join(&base);
        if candidate.exists() {
            return candidate.canonicalize().map_err(|e| e.to_string());
        }
    }

    Err(format!(
        "'{}' not found in any search path\n  searched: priority dirs, system paths, CWD, PATH\n  use --priority-dir <dir> or --path <dir> to add custom search locations, or provide a full path",
        name
    ))
}
