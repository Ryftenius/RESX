use std::collections::BTreeSet;

use serde::Serialize;

use crate::analysis::disasm::Instruction;
use crate::formats::pe::ImportDll;

#[derive(Debug, Clone, Serialize)]
pub struct IntelliFinding {
    pub category: String,
    pub rule: String,
    pub source: String,
    pub value: String,
    pub file_offset: Option<usize>,
    pub encoding: Option<String>,
    pub status: String,
}

pub fn analyze_image(
    raw: &[u8],
    imports: &[ImportDll],
    insns: Option<&[Instruction]>,
) -> Vec<IntelliFinding> {
    let strings = crate::analysis::text::scan(raw, 6, true, true);
    let mut findings = Vec::new();
    findings.extend(scan_strings(&strings.strings));
    if strings.truncated {
        findings.push(finding("coverage", "string-budget", "analyzer", "String scan reached its byte, count, length or text budget; omitted bytes remain unknown"));
    }
    findings.extend(scan_imports(imports));
    if let Some(insns) = insns {
        findings.extend(scan_instructions(insns));
    }
    if findings.len() >= 8192 {
        findings.truncate(8191);
        findings.push(finding(
            "coverage",
            "finding-budget",
            "analyzer",
            "Finding limit reached; remaining candidates omitted",
        ));
    }
    dedup_findings(findings)
}

fn scan_strings(strings: &[crate::analysis::text::Text]) -> Vec<IntelliFinding> {
    let mut findings = Vec::new();
    for entry in strings {
        if findings.len() >= 8192 {
            break;
        }
        let start = findings.len();
        let s = &entry.value;
        let lower = s.to_ascii_lowercase();
        if contains_ipv4(s) {
            findings.push(finding("network", "ipv4", "string", s));
        }
        if lower.contains("http://") || lower.contains("https://") {
            findings.push(finding("network", "url", "string", s));
        }
        if lower.contains("ws://") || lower.contains("wss://") {
            findings.push(finding("network", "websocket", "string", s));
        }
        if contains_domain(s) {
            findings.push(finding("network", "domain", "string", s));
        }
        if contains_host_port(s) {
            findings.push(finding("network", "host-port", "string", s));
        }
        if lower.contains("proxy") || lower.contains("socks4") || lower.contains("socks5") {
            findings.push(finding("network", "proxy", "string", s));
        }
        if is_discord_token(s) || lower.contains("discord token") {
            findings.push(finding("credential", "discord-token", "string", s));
        }
        if is_roblox_cookie(s) || lower.contains("roblosecurity") {
            findings.push(finding("credential", "roblox-cookie", "string", s));
        }
        if looks_like_windows_path(s) {
            findings.push(finding("filesystem", "filepath", "string", s));
        }
        if contains_any(
            &lower,
            &[
                "sessionserver.mojang.com",
                "api.minecraftservices.com",
                "textures.minecraft.net",
                "yggdrasil",
                "joinserver",
                "hasjoined",
                "minecraft",
            ],
        ) {
            findings.push(finding("ttp", "minecraft-session", "string", s));
        }
        if contains_any(
            &lower,
            &[
                "encrypt", "decrypt", "aes", "rsa", "chacha", "bcrypt", "crypt",
            ],
        ) {
            findings.push(finding("crypto", "encrypt-decrypt", "string", s));
        }
        if contains_any(
            &lower,
            &[
                "stream",
                "fstream",
                "stringstream",
                "istream",
                "ostream",
                "pipe",
            ],
        ) {
            findings.push(finding("io", "stream", "string", s));
        }
        for result in &mut findings[start..] {
            result.file_offset = Some(entry.offset);
            result.encoding = Some(entry.encoding.into());
            if entry.truncated {
                result.status = "truncated-string-candidate".into();
            }
        }
    }
    findings
}

fn scan_imports(imports: &[ImportDll]) -> Vec<IntelliFinding> {
    let mut findings = Vec::new();
    for dll in imports.iter().take(4096) {
        let dll_lower = dll.dll.to_ascii_lowercase();
        if matches!(
            dll_lower.as_str(),
            "ws2_32.dll" | "winhttp.dll" | "wininet.dll" | "urlmon.dll" | "iphlpapi.dll"
        ) {
            findings.push(finding("network", "network-stack", "import-dll", &dll.dll));
        }
        if matches!(
            dll_lower.as_str(),
            "crypt32.dll" | "bcrypt.dll" | "ncrypt.dll"
        ) {
            findings.push(finding("crypto", "crypto-stack", "import-dll", &dll.dll));
        }
        for entry in &dll.entries {
            if findings.len() >= 8192 {
                return findings;
            }
            let name = entry.name.as_str();
            let lower = name.to_ascii_lowercase();
            if let Some(spec) = super::apis::lookup(&dll.dll, name) {
                findings.push(finding(spec.category, "known-api-import", "import", name));
            }
            if lower.contains("stream")
                || lower.contains("file")
                || lower.contains("readfile")
                || lower.contains("writefile")
            {
                findings.push(finding("io", "stream-file-api", "import", name));
            }
            if lower.contains("createprocess")
                || lower.contains("winexec")
                || lower.contains("shellexecute")
            {
                findings.push(finding("execution", "process-launch", "import", name));
            }
        }
    }
    findings
}

fn scan_instructions(insns: &[Instruction]) -> Vec<IntelliFinding> {
    let mut findings = Vec::new();
    for insn in insns.iter().take(65536) {
        if findings.len() >= 8192 {
            break;
        }
        let text = if insn.comment.is_empty() {
            insn.text.clone()
        } else {
            format!("{} {}", insn.text, insn.comment)
        };
        let lower = text.to_ascii_lowercase();
        if contains_any(
            &lower,
            &[
                "encrypt", "decrypt", "aes", "rsa", "chacha", "bcrypt", "crypt",
            ],
        ) {
            findings.push(finding("crypto", "crypto-code-ref", "instruction", &text));
        }
        if contains_any(
            &lower,
            &[
                "stream",
                "fstream",
                "stringstream",
                "istream",
                "ostream",
                "pipe",
            ],
        ) {
            findings.push(finding("io", "stream-code-ref", "instruction", &text));
        }
        if lower.contains("http://")
            || lower.contains("https://")
            || lower.contains("ws://")
            || lower.contains("wss://")
            || contains_host_port(&text)
            || contains_ipv4(&text)
        {
            findings.push(finding("network", "network-code-ref", "instruction", &text));
        }
    }
    findings
}

fn dedup_findings(findings: Vec<IntelliFinding>) -> Vec<IntelliFinding> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for finding in findings {
        let key = format!(
            "{}|{}|{}|{}|{:?}|{:?}",
            finding.category,
            finding.rule,
            finding.source,
            finding.value.to_ascii_lowercase(),
            finding.file_offset,
            finding.encoding
        );
        if seen.insert(key) {
            out.push(finding);
            if out.len() == 8192 {
                break;
            }
        }
    }
    out
}

fn finding(category: &str, rule: &str, source: &str, value: &str) -> IntelliFinding {
    IntelliFinding {
        category: category.to_owned(),
        rule: rule.to_owned(),
        source: source.to_owned(),
        value: value.to_owned(),
        file_offset: None,
        encoding: None,
        status: "static-candidate; execution, purpose and reachability unobserved".into(),
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}

fn contains_ipv4(text: &str) -> bool {
    split_tokens(text).into_iter().any(is_ipv4_token)
}

fn contains_domain(text: &str) -> bool {
    split_tokens(text).into_iter().any(is_domain_token)
}

fn contains_host_port(text: &str) -> bool {
    split_tokens(text).into_iter().any(is_host_port_token)
}

fn split_tokens(text: &str) -> Vec<&str> {
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '"' | '\'' | '<' | '>' | '(' | ')' | '[' | ']' | '{' | '}' | ',' | ';'
            )
    })
    .filter(|part| !part.is_empty())
    .collect()
}

fn is_ipv4_token(token: &str) -> bool {
    let token = token.trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | ',' | ';'));
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 4 {
        return false;
    }
    parts.iter().all(|part| {
        !part.is_empty()
            && part.len() <= 3
            && part.chars().all(|c| c.is_ascii_digit())
            && part.parse::<u8>().is_ok()
    })
}

fn is_domain_token(token: &str) -> bool {
    let token = token
        .trim_matches(|c: char| matches!(c, '"' | '\'' | '(' | ')' | ',' | ';'))
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .split('/')
        .next()
        .unwrap_or("");
    if token.is_empty() || !token.contains('.') || is_ipv4_token(token) {
        return false;
    }
    let labels: Vec<&str> = token.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    let tld = labels.last().copied().unwrap_or("");
    token.len() <= 253
        && (2..=63).contains(&tld.len())
        && tld.bytes().all(|b| b.is_ascii_alphabetic())
        && labels.iter().all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        })
}

fn is_host_port_token(token: &str) -> bool {
    let token = token.trim_matches(|c: char| ",;()[]{}".contains(c));
    let Some((host, port)) = token.rsplit_once(':') else {
        return false;
    };
    let host = host
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("ws://")
        .trim_start_matches("wss://")
        .split('/')
        .next()
        .unwrap_or("");
    if !port.bytes().all(|b| b.is_ascii_digit()) || !matches!(port.parse::<u16>(), Ok(1..=65535)) {
        return false;
    }
    host.trim_matches(['[', ']'])
        .parse::<std::net::IpAddr>()
        .is_ok()
        || is_domain_token(host)
}

fn is_discord_token(text: &str) -> bool {
    split_tokens(text).into_iter().any(|token| {
        let parts: Vec<&str> = token.split('.').collect();
        if parts.len() != 3 {
            return false;
        }
        is_base64ish(parts[0])
            && parts[0].len() == 24
            && is_base64ish(parts[1])
            && parts[1].len() == 6
            && is_base64ish(parts[2])
            && (25..=110).contains(&parts[2].len())
    })
}

fn is_roblox_cookie(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("_|warning:-do-not-share-this.") || lower.contains(".roblosecurity")
}

fn looks_like_windows_path(text: &str) -> bool {
    split_tokens(text).into_iter().any(|token| {
        let token = token.trim_matches(|c: char| "\"'(),;".contains(c));
        token.len() > 3
            && token.as_bytes()[1] == b':'
            && token.as_bytes()[2] == b'\\'
            && token.as_bytes()[0].is_ascii_alphabetic()
    })
}

fn is_base64ish(text: &str) -> bool {
    !text.is_empty()
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::pe::ImportEntry;
    #[test]
    fn unrelated_imports_are_not_network_or_crypto_operations() {
        let imports: Vec<_> = [
            ("kernel32.dll", "ConnectNamedPipe"),
            ("user32.dll", "SendMessageW"),
            ("advapi32.dll", "RegCloseKey"),
            ("not-crypto.dll", "BCryptDecrypt"),
        ]
        .into_iter()
        .map(|(dll, name)| ImportDll {
            dll: dll.into(),
            entries: vec![ImportEntry {
                name: name.into(),
                ordinal: 0,
                hint: 0,
                by_ord: false,
                slot_rva: 0,
            }],
        })
        .collect();
        let findings = scan_imports(&imports);
        assert!(!findings
            .iter()
            .any(|f| matches!(f.category.as_str(), "network" | "crypto")));
        assert!(findings
            .iter()
            .any(|f| f.category == "ipc" && f.value == "ConnectNamedPipe"));
    }
    #[test]
    fn port_ranges_and_domain_grammar_are_checked() {
        assert!(is_host_port_token("127.0.0.1:1"));
        assert!(is_host_port_token("[::1]:443"));
        assert!(!is_host_port_token("fixture.invalid:65536"));
        assert!(!is_host_port_token("fixture.invalid:0"));
        assert!(is_domain_token("fixture.invalid"));
        assert!(!is_domain_token("-invalid.example"));
    }
    #[test]
    fn repeated_literals_preserve_distinct_source_offsets() {
        let findings = analyze_image(
            b"https://fixture.invalid/a\0https://fixture.invalid/a\0",
            &[],
            None,
        );
        let urls: Vec<_> = findings
            .iter()
            .filter(|f| f.rule == "url" && f.encoding.as_deref() == Some("ascii"))
            .collect();
        assert_eq!(urls.len(), 2);
        assert_ne!(urls[0].file_offset, urls[1].file_offset);
    }
}
