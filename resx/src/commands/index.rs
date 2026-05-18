use std::collections::BTreeSet;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::analysis::diff::{new_corpus_index, profile_image_for_index, IndexSkip};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;

pub fn run(root_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    if root_arg.is_empty() {
        return Err("Use `resx index <dir-or-image> --db <file>`".to_owned());
    }

    let root = PathBuf::from(root_arg);
    let extensions = parse_extensions(&cfg.scan_extensions);
    let max_bytes = cfg.max_file_mb.saturating_mul(1024 * 1024);
    let (paths, mut skipped) = collect_image_paths(&root, &extensions, cfg.max_files, max_bytes);
    let mut index = new_corpus_index(&root, cfg);
    index.skipped.append(&mut skipped);

    for path in paths {
        match profile_image_for_index(&path, cfg) {
            Ok(image) => index.images.push(image),
            Err(err) => index.skipped.push(IndexSkip {
                path: path.to_string_lossy().to_string(),
                reason: err,
            }),
        }
    }

    let db_path = PathBuf::from(&cfg.corpus_db);
    let json = serde_json::to_string_pretty(&index)
        .map_err(|e| format!("serialize corpus index '{}': {}", db_path.display(), e))?;
    std::fs::write(&db_path, json)
        .map_err(|e| format!("write corpus index '{}': {}", db_path.display(), e))?;

    if cfg.json {
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&versioned_object("index", &index)).unwrap_or_default()
        )
        .ok();
    } else {
        render_text(
            w,
            &index.root,
            &db_path,
            index.images.len(),
            index.skipped.len(),
            c,
        );
    }
    Ok(())
}

fn render_text(
    w: &mut dyn Write,
    root: &str,
    db_path: &Path,
    indexed: usize,
    skipped: usize,
    c: &Colors,
) {
    writeln!(w, "{}", c.bold(&c.b_blue("Corpus Index"))).ok();
    writeln!(w, "{}  {}", c.dim("Root :"), root).ok();
    writeln!(w, "{}  {}", c.dim("DB   :"), db_path.display()).ok();
    writeln!(w, "{}  {}", c.dim("Images:"), indexed).ok();
    if skipped > 0 {
        writeln!(w, "{}  {}", c.dim("Skipped:"), skipped).ok();
    }
}

fn collect_image_paths(
    root: &Path,
    extensions: &BTreeSet<String>,
    max_files: usize,
    max_bytes: u64,
) -> (Vec<PathBuf>, Vec<IndexSkip>) {
    let mut out = Vec::new();
    let mut skipped = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(path) = stack.pop() {
        if out.len() >= max_files.max(1) {
            break;
        }
        let metadata = match std::fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(err) => {
                skipped.push(IndexSkip {
                    path: path.to_string_lossy().to_string(),
                    reason: err.to_string(),
                });
                continue;
            }
        };
        if metadata.is_dir() {
            let entries = match std::fs::read_dir(&path) {
                Ok(entries) => entries,
                Err(err) => {
                    skipped.push(IndexSkip {
                        path: path.to_string_lossy().to_string(),
                        reason: err.to_string(),
                    });
                    continue;
                }
            };
            for entry in entries.flatten() {
                stack.push(entry.path());
            }
            continue;
        }
        if !metadata.is_file() {
            continue;
        }
        let ext = path
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default()
            .trim_start_matches('.')
            .to_ascii_lowercase();
        if !extensions.contains(&ext) {
            continue;
        }
        if max_bytes > 0 && metadata.len() > max_bytes {
            skipped.push(IndexSkip {
                path: path.to_string_lossy().to_string(),
                reason: format!(
                    "file is larger than --max-file-mb ({} bytes)",
                    metadata.len()
                ),
            });
            continue;
        }
        out.push(path);
    }
    out.sort();
    (out, skipped)
}

fn parse_extensions(raw: &str) -> BTreeSet<String> {
    raw.split(',')
        .map(|ext| ext.trim().trim_start_matches('.').to_ascii_lowercase())
        .filter(|ext| !ext.is_empty())
        .collect()
}
