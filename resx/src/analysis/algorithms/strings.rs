use serde::Serialize;

use crate::formats::pe::PeFile;

#[derive(Debug, Clone, Serialize)]
pub struct StringFinding {
    pub rva: Option<String>,
    pub file_offset: String,
    pub section: String,
    pub encoding: String,
    pub value: String,
    pub tags: Vec<String>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringsReport {
    pub image: String,
    pub min_len: usize,
    pub scanned_bytes: usize,
    pub total: usize,
    pub filtered_out: usize,
    pub filters: StringFilters,
    pub strings: Vec<StringFinding>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StringFilters {
    pub encoding: String,
    pub interesting_only: bool,
    pub match_text: Option<String>,
    pub tag: Option<String>,
    pub plausible_utf16_only: bool,
}

#[derive(Debug, Clone)]
pub struct StringsOptions {
    pub min_len: usize,
    pub limit: usize,
    pub ascii: bool,
    pub wide: bool,
    pub interesting_only: bool,
    pub match_text: Option<String>,
    pub tag: Option<String>,
    pub plausible_utf16_only: bool,
}

impl Default for StringsOptions {
    fn default() -> Self {
        Self {
            min_len: 5,
            limit: 500,
            ascii: true,
            wide: true,
            interesting_only: false,
            match_text: None,
            tag: None,
            plausible_utf16_only: true,
        }
    }
}

pub fn analyze_strings(
    image: &str,
    pe: Option<&PeFile>,
    raw: &[u8],
    options: &StringsOptions,
) -> StringsReport {
    let scan = super::text::scan(raw, options.min_len, options.ascii, options.wide);
    let mut strings: Vec<_> = scan
        .strings
        .into_iter()
        .map(|entry| {
            let mut result = finding(pe, raw, entry.offset, entry.encoding, entry.value);
            result.truncated = entry.truncated;
            result
        })
        .collect();
    let unfiltered = strings.len();
    if options.plausible_utf16_only {
        strings.retain(|entry| entry.encoding != "utf16le" || plausible_utf16(&entry.value));
    }
    if options.interesting_only {
        strings.retain(|entry| !entry.tags.is_empty());
    }
    if let Some(text) = options.match_text.as_deref() {
        let text = text.to_ascii_lowercase();
        strings.retain(|entry| entry.value.to_ascii_lowercase().contains(&text));
    }
    if let Some(tag) = options.tag.as_deref() {
        strings.retain(|entry| {
            entry
                .tags
                .iter()
                .any(|value| value.eq_ignore_ascii_case(tag))
        });
    }
    let total = strings.len();
    let limit = if options.limit == 0 {
        super::text::MAX_STRINGS
    } else {
        options.limit.min(super::text::MAX_STRINGS)
    };
    let truncated = scan.truncated || strings.len() > limit;
    strings.truncate(limit);
    StringsReport {
        image: image.into(),
        min_len: options.min_len.clamp(1, super::text::MAX_STRING),
        scanned_bytes: scan.scanned_bytes,
        total,
        filtered_out: unfiltered.saturating_sub(total),
        filters: StringFilters {
            encoding: match (options.ascii, options.wide) {
                (true, true) => "both",
                (true, false) => "ascii",
                (false, true) => "utf16le",
                (false, false) => "none",
            }
            .to_owned(),
            interesting_only: options.interesting_only,
            match_text: options.match_text.clone(),
            tag: options.tag.clone(),
            plausible_utf16_only: options.plausible_utf16_only,
        },
        strings,
        truncated,
    }
}

fn finding(
    pe: Option<&PeFile>,
    raw: &[u8],
    file_offset: usize,
    encoding: &str,
    value: String,
) -> StringFinding {
    let rva = pe.and_then(|pe| pe.file_offset_to_rva(file_offset as u64));
    let section = pe
        .and_then(|pe| rva.and_then(|rva| pe.rva_to_section(rva).map(|s| s.name.clone())))
        .unwrap_or_else(|| "-".to_owned());
    let tags = classify_string(&value);
    let file_offset = file_offset.min(raw.len());
    StringFinding {
        rva: rva.map(|value| format!("0x{:08X}", value)),
        file_offset: format!("0x{:08X}", file_offset),
        section,
        encoding: encoding.to_owned(),
        value,
        tags,
        truncated: false,
    }
}

pub fn classify_string(value: &str) -> Vec<String> {
    let lower = value.to_ascii_lowercase();
    let mut tags = Vec::new();
    if lower.contains("\\device\\") || lower.contains("\\dosdevices\\") || lower.contains("\\??\\")
    {
        tags.push("device-path".to_owned());
    }
    if lower.contains("\\registry\\") || lower.contains("currentcontrolset") {
        tags.push("registry".to_owned());
    }
    if lower.contains(".dll") || lower.contains(".sys") || lower.contains(".exe") {
        tags.push("module-path".to_owned());
    }
    if looks_like_api(value) {
        tags.push("api-name".to_owned());
    }
    if looks_like_base64(value) {
        tags.push("base64-like".to_owned());
    }
    if lower.contains("pyinstaller")
        || lower.contains("python")
        || lower.contains("pyz")
        || lower.contains(".pyc")
    {
        tags.push("python-packaging".to_owned());
    }
    if lower.contains("upx")
        || lower.contains("vmprotect")
        || lower.contains("themida")
        || lower.contains("enigma")
    {
        tags.push("protector-marker".to_owned());
    }
    if lower.contains("ioctl") || lower.contains("deviceiocontrol") {
        tags.push("ioctl".to_owned());
    }
    if looks_like_success_marker(value) {
        tags.push("success-marker".to_owned());
    }
    if looks_like_ctf_flag(value) {
        tags.push("flag-candidate".to_owned());
    }
    tags.sort();
    tags.dedup();
    tags
}

fn plausible_utf16(value: &str) -> bool {
    let mut characters = 0usize;
    let mut ascii_wordlike = 0usize;
    let mut alphanumeric = 0usize;
    for ch in value.chars() {
        characters += 1;
        if ch.is_alphanumeric() {
            alphanumeric += 1;
            if ch.is_ascii() {
                ascii_wordlike += 1;
            }
        } else if ch.is_ascii() && (ch.is_whitespace() || "._-:/\\()[]{}@#$%+,&'\"!?=".contains(ch))
        {
            ascii_wordlike += 1;
        }
    }
    characters != 0 && alphanumeric != 0 && ascii_wordlike.saturating_mul(100) / characters >= 70
}

fn looks_like_success_marker(value: &str) -> bool {
    let trimmed = value.trim();
    let upper = trimmed.to_ascii_uppercase();
    (4..=96).contains(&trimmed.len())
        && trimmed
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && (upper.ends_with("_OK")
            || upper.ends_with("_SUCCESS")
            || upper == "SUCCESS"
            || upper == "PASS")
}

fn looks_like_ctf_flag(value: &str) -> bool {
    let trimmed = value.trim();
    let Some(open) = trimmed.find('{') else {
        return false;
    };
    let Some(close) = trimmed.rfind('}') else {
        return false;
    };
    open >= 3
        && close >= open + 5
        && close == trimmed.len() - 1
        && trimmed[..open]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
        && trimmed[open + 1..close].bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'_' | b'-' | b'.' | b':' | b'@' | b'!' | b'?' | b'$')
        })
        && trimmed[open + 1..close]
            .bytes()
            .any(|byte| byte.is_ascii_alphanumeric())
}

fn looks_like_api(value: &str) -> bool {
    let value = value.trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_');
    if !(4..=96).contains(&value.len()) {
        return false;
    }
    const PREFIXES: &[&str] = &[
        "Nt",
        "Zw",
        "Rtl",
        "Ldr",
        "Io",
        "Ke",
        "Ex",
        "Ps",
        "Ob",
        "Mm",
        "Wdf",
        "Wpp",
        "Etw",
        "Get",
        "Set",
        "Create",
        "Open",
        "Close",
        "Read",
        "Write",
        "DeviceIoControl",
    ];
    PREFIXES.iter().any(|prefix| value.starts_with(prefix))
}

fn looks_like_base64(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.len() < 16 || !trimmed.len().is_multiple_of(4) {
        return false;
    }
    let valid = trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='));
    let alpha = trimmed.bytes().filter(|b| b.is_ascii_alphabetic()).count();
    valid && alpha >= trimmed.len() / 2
}

#[cfg(test)]
mod classification_tests {
    use super::*;

    #[test]
    fn success_markers_are_not_mislabeled_as_ctf_flags() {
        assert_eq!(classify_string("TARGET_OK"), vec!["success-marker"]);
        assert!(classify_string("flag{known-good}").contains(&"flag-candidate".to_owned()));
    }

    #[test]
    fn implausible_utf16_noise_is_filtered_but_paths_survive() {
        assert!(plausible_utf16(r"C:\\Windows\\System32"));
        assert!(!plausible_utf16("♠♣♥♦☃☂"));
    }
}
