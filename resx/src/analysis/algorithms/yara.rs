use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub file: String,
    pub strings: Vec<YaraStringMatch>,
    pub metadata: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize)]
pub struct YaraStringMatch {
    pub identifier: String,
    pub offset: u64,
    pub rva: Option<u32>,
    pub section: Option<String>,
    pub data: String,
}

pub fn scan_file(target: &str, rule_files: &[String]) -> Result<Vec<YaraMatch>, String> {
    if rule_files.is_empty() {
        return Ok(Vec::new());
    }
    let rule_files = expand_rule_inputs(rule_files)?;
    let target = std::fs::canonicalize(target).map_err(|e| e.to_string())?;
    if !target.is_file() {
        return Err("YARA target must be one regular file".into());
    }
    let target_bytes = std::fs::read(&target).map_err(|e| e.to_string())?;
    let pe = crate::formats::pe::parse_pe(&target_bytes).ok();

    let yara = find_yara_binary()
        .ok_or_else(|| "YARA executable not found (looked for yara64.exe/yara.exe)".to_owned())?;
    let mut out: Vec<YaraMatch> = Vec::new();
    let started = std::time::Instant::now();
    let mut remaining_output = 1024 * 1024;

    for rule_file in rule_files {
        let rule_file = std::fs::canonicalize(&rule_file).map_err(|e| e.to_string())?;
        let metadata = rule_file.metadata().map_err(|e| e.to_string())?;
        if !metadata.is_file() || metadata.len() > 16 * 1024 * 1024 {
            return Err("YARA rules require regular files no larger than 16 MiB".into());
        }
        let remaining_time = std::time::Duration::from_secs(30)
            .checked_sub(started.elapsed())
            .ok_or("YARA aggregate wall-time budget exceeded")?;
        let output = crate::core::process::capture(
            Command::new(&yara)
                .arg("-s")
                .arg("-m")
                .arg("-g")
                .arg("-e")
                .arg(&rule_file)
                .arg(&target),
            remaining_time,
            remaining_output,
        )?;
        remaining_output = remaining_output
            .checked_sub(output.stdout.len() + output.stderr.len())
            .ok_or("YARA aggregate output budget exceeded")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let msg = if !stderr.is_empty() { stderr } else { stdout };
            return Err(format!(
                "YARA scan failed for {}: {}",
                rule_file.display(),
                msg
            ));
        }

        let mut current: Option<usize> = None;
        for line in std::str::from_utf8(&output.stdout)
            .map_err(|_| "YARA returned invalid UTF-8")?
            .lines()
        {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if let Some(string_match) = parse_string_line(trimmed) {
                let Some(index) = current else {
                    return Err("YARA emitted string evidence before a rule match".into());
                };
                let mut string_match = string_match;
                if let Some(pe) = &pe {
                    if let Some(section) = pe.sections.iter().find(|s| {
                        string_match.offset >= s.raw_offset as u64
                            && string_match.offset < (s.raw_offset as u64 + s.raw_size as u64)
                    }) {
                        string_match.rva = Some(
                            section.virtual_address
                                + (string_match.offset - section.raw_offset as u64) as u32,
                        );
                        string_match.section = Some(section.name.clone());
                    }
                }
                out[index].strings.push(string_match);
                continue;
            }
            if let Some((key, value)) = parse_metadata_line(trimmed) {
                let Some(index) = current else {
                    return Err("YARA emitted metadata before a rule match".into());
                };
                out[index].metadata.push((key, value));
                continue;
            }
            let found = parse_match_line(trimmed);
            if found.rule.is_empty()
                || found.file.is_empty()
                || found.rule.len() > 128
                || !found
                    .rule
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_')
            {
                return Err("Malformed YARA match output".into());
            }
            out.push(found);
            current = Some(out.len() - 1);
            if out.len() > 8192 {
                return Err("YARA aggregate match budget exceeded".into());
            }
        }
    }

    Ok(out)
}

fn expand_rule_inputs(inputs: &[String]) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    for input in inputs {
        let path = std::fs::canonicalize(input).map_err(|e| format!("YARA input {input}: {e}"))?;
        if path.is_dir() {
            let mut entries = std::fs::read_dir(&path)
                .map_err(|e| e.to_string())?
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            entries.sort_by_key(|e| e.path());
            for entry in entries {
                let p = entry.path();
                if p.is_file()
                    && p.extension()
                        .and_then(|v| v.to_str())
                        .is_some_and(|v| matches!(v.to_ascii_lowercase().as_str(), "yar" | "yara"))
                {
                    out.push(p);
                }
            }
        } else if path
            .extension()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.eq_ignore_ascii_case("json"))
        {
            let bytes = std::fs::read(&path).map_err(|e| e.to_string())?;
            if bytes.len() > 1024 * 1024 {
                return Err("YARA saved configuration exceeds 1 MiB".into());
            }
            let configured: Vec<String> = serde_json::from_slice(&bytes)
                .map_err(|e| format!("invalid YARA configuration: {e}"))?;
            let base = path.parent().unwrap_or(Path::new("."));
            for configured_path in configured {
                let p = PathBuf::from(&configured_path);
                out.push(if p.is_absolute() { p } else { base.join(p) });
            }
        } else {
            out.push(path);
        }
        if out.len() > 64 {
            return Err("At most 64 expanded YARA rule files are supported".into());
        }
    }
    Ok(out)
}

fn parse_match_line(line: &str) -> YaraMatch {
    let (head, mut rest) = line.split_once(char::is_whitespace).unwrap_or((line, ""));
    let (namespace, rule) = head.split_once(':').map_or_else(
        || (String::new(), head.to_owned()),
        |(namespace, rule)| (namespace.to_owned(), rule.to_owned()),
    );
    let mut tags = Vec::new();
    let mut metadata = Vec::new();
    rest = rest.trim_start();
    while let Some(body) = rest.strip_prefix('[') {
        let Some(end) = body.find(']') else { break };
        let item = body[..end].trim();
        if let Some((key, value)) = item.split_once('=') {
            metadata.push((key.trim().to_owned(), value.trim().to_owned()));
        } else if !item.is_empty() {
            tags.extend(
                item.split(',')
                    .map(str::trim)
                    .filter(|v| !v.is_empty())
                    .map(str::to_owned),
            );
        }
        rest = body[end + 1..].trim_start();
    }
    let file = rest.to_owned();

    YaraMatch {
        rule,
        namespace,
        tags,
        file,
        strings: Vec::new(),
        metadata,
    }
}

fn parse_string_line(line: &str) -> Option<YaraStringMatch> {
    let line = line.trim_start();
    let (offset, rest) = line.split_once(':')?;
    let offset = u64::from_str_radix(offset.trim_start_matches("0x"), 16).ok()?;
    let (identifier, data) = rest.split_once(':')?;
    if !identifier.trim().starts_with('$') {
        return None;
    }
    Some(YaraStringMatch {
        identifier: identifier.trim().to_owned(),
        offset,
        rva: None,
        section: None,
        data: data.trim().chars().take(512).collect(),
    })
}
fn parse_metadata_line(line: &str) -> Option<(String, String)> {
    let line = line.trim();
    if line.starts_with("0x") || line.starts_with('$') {
        return None;
    }
    let (key, value) = line.split_once('=')?;
    let key = key.trim();
    if key.is_empty() || key.chars().any(char::is_whitespace) {
        return None;
    }
    Some((key.to_owned(), value.trim().chars().take(512).collect()))
}

fn find_yara_binary() -> Option<PathBuf> {
    let candidates = [
        r"C:\Program Files\YARA\yara64.exe",
        r"C:\Program Files\YARA\yara.exe",
    ];

    for candidate in candidates {
        let path = Path::new(candidate);
        if path.exists() {
            return Some(path.to_path_buf());
        }
    }

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in std::env::split_paths(&path_var) {
            for name in ["yara64.exe", "yara.exe"] {
                let candidate = dir.join(name);
                if candidate.exists() {
                    return Some(candidate);
                }
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn match_paths_preserve_spaces() {
        let result = parse_match_line(r"SampleRule C:\sample folder\input.exe");
        assert_eq!(result.rule, "SampleRule");
        assert_eq!(result.file, r"C:\sample folder\input.exe");
    }
}
