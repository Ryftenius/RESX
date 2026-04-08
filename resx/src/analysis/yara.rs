use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone)]
pub struct YaraMatch {
    pub rule: String,
    pub namespace: String,
    pub tags: Vec<String>,
    pub file: String,
}

pub fn scan_file(target: &str, rule_files: &[String]) -> Result<Vec<YaraMatch>, String> {
    if rule_files.is_empty() {
        return Ok(Vec::new());
    }

    let yara = find_yara_binary()
        .ok_or_else(|| "YARA executable not found (looked for yara64.exe/yara.exe)".to_owned())?;
    let mut out = Vec::new();

    for rule_file in rule_files {
        let output = Command::new(&yara)
            .arg(rule_file)
            .arg(target)
            .output()
            .map_err(|e| format!("run {}: {}", yara.display(), e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let msg = if !stderr.is_empty() { stderr } else { stdout };
            return Err(format!("YARA scan failed for {}: {}", rule_file, msg));
        }

        for line in String::from_utf8_lossy(&output.stdout).lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            out.push(parse_match_line(trimmed));
        }
    }

    Ok(out)
}

fn parse_match_line(line: &str) -> YaraMatch {
    let mut parts = line.split_whitespace();
    let head = parts.next().unwrap_or_default();
    let file = parts.next().unwrap_or_default().to_owned();

    let (namespace, rule, tags) = if let Some((ns, rest)) = head.split_once(':') {
        let (rule, tags) = split_tags(rest);
        (ns.to_owned(), rule, tags)
    } else {
        let (rule, tags) = split_tags(head);
        (String::new(), rule, tags)
    };

    YaraMatch {
        rule,
        namespace,
        tags,
        file,
    }
}

fn split_tags(head: &str) -> (String, Vec<String>) {
    if let Some((rule, tags)) = head.split_once('[') {
        let tags = tags
            .trim_end_matches(']')
            .split(',')
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .collect();
        (rule.to_owned(), tags)
    } else {
        (head.to_owned(), Vec::new())
    }
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
