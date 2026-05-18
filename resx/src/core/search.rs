use std::path::{Path, PathBuf};

use crate::core::config::Config;
use crate::core::priority::global_lookup_dirs;

pub fn image_name_candidates(name: &str) -> Vec<String> {
    if Path::new(name).extension().is_some() {
        return vec![name.to_owned()];
    }

    let lower = name.to_ascii_lowercase();
    let extensions: &[&str] = if lower == "ntoskrnl" || lower.starts_with("ntkrnl") {
        &["exe", "sys", "dll"]
    } else if lower.starts_with("win32k") {
        &["sys", "dll", "exe"]
    } else {
        &["dll", "exe", "sys"]
    };

    extensions
        .iter()
        .map(|ext| format!("{}.{}", name, ext))
        .collect()
}

pub fn find_dll_path(name: &str, cfg: &Config) -> Result<PathBuf, String> {
    if name.contains('/') || name.contains('\\') {
        let p = PathBuf::from(name);
        if p.exists() {
            return p.canonicalize().map_err(|e| e.to_string());
        }
        return Err(format!("file not found: {}", name));
    }

    let candidates = image_name_candidates(name);
    let dirs = global_lookup_dirs(cfg);

    for dir in &dirs {
        for base in &candidates {
            let candidate = dir.join(base);
            if candidate.exists() {
                return candidate.canonicalize().map_err(|e| e.to_string());
            }
        }
    }

    Err(format!(
        "'{}' not found in any search path\n  searched: priority dirs, system paths, CWD, PATH\n  use --priority-dir <dir> or --path <dir> to add custom search locations, or provide a full path",
        name
    ))
}

#[cfg(test)]
mod tests {
    use super::image_name_candidates;

    #[test]
    fn extensionless_win32k_prefers_sys() {
        assert_eq!(
            image_name_candidates("win32kfull"),
            vec![
                "win32kfull.sys".to_owned(),
                "win32kfull.dll".to_owned(),
                "win32kfull.exe".to_owned()
            ]
        );
    }

    #[test]
    fn extensionless_ntoskrnl_prefers_exe() {
        assert_eq!(
            image_name_candidates("ntoskrnl"),
            vec![
                "ntoskrnl.exe".to_owned(),
                "ntoskrnl.sys".to_owned(),
                "ntoskrnl.dll".to_owned()
            ]
        );
    }

    #[test]
    fn extensionless_user_mode_defaults_to_dll() {
        assert_eq!(image_name_candidates("user32")[0], "user32.dll");
    }
}
