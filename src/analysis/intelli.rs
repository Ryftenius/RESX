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
}

pub fn analyze_image(
    raw: &[u8],
    imports: &[ImportDll],
    insns: Option<&[Instruction]>,
) -> Vec<IntelliFinding> {
    let strings = extract_ascii_strings(raw, 6);
    let mut findings = Vec::new();
    findings.extend(scan_strings(&strings));
    findings.extend(scan_imports(imports));
    if let Some(insns) = insns {
        findings.extend(scan_instructions(insns));
    }
    dedup_findings(findings)
}

fn scan_strings(strings: &[String]) -> Vec<IntelliFinding> {
    let mut findings = Vec::new();
    for s in strings {
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
    }
    findings
}

fn scan_imports(imports: &[ImportDll]) -> Vec<IntelliFinding> {
    let mut findings = Vec::new();
    for dll in imports {
        let dll_lower = dll.dll.to_ascii_lowercase();
        if matches!(
            dll_lower.as_str(),
            "ws2_32.dll" | "winhttp.dll" | "wininet.dll" | "urlmon.dll" | "iphlpapi.dll"
        ) {
            findings.push(finding("network", "network-stack", "import-dll", &dll.dll));
        }
        if matches!(
            dll_lower.as_str(),
            "crypt32.dll" | "bcrypt.dll" | "ncrypt.dll" | "advapi32.dll"
        ) {
            findings.push(finding("crypto", "crypto-stack", "import-dll", &dll.dll));
        }
        for entry in &dll.entries {
            let name = entry.name.as_str();
            let lower = name.to_ascii_lowercase();
            if lower.contains("socket")
                || lower.starts_with("wsa")
                || lower.contains("connect")
                || lower.contains("send")
                || lower.contains("recv")
                || lower.contains("winhttp")
                || lower.contains("internet")
            {
                findings.push(finding("network", "network-api", "import", name));
            }
            if lower.contains("crypt")
                || lower.contains("bcrypt")
                || lower.contains("decrypt")
                || lower.contains("encrypt")
                || lower.contains("protectdata")
            {
                findings.push(finding("crypto", "crypto-api", "import", name));
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
    for insn in insns {
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

fn extract_ascii_strings(raw: &[u8], min_len: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in raw {
        if (0x20..=0x7e).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                out.push(String::from_utf8_lossy(&cur).into_owned());
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len {
        out.push(String::from_utf8_lossy(&cur).into_owned());
    }
    out
}

fn dedup_findings(findings: Vec<IntelliFinding>) -> Vec<IntelliFinding> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for finding in findings {
        let key = format!(
            "{}|{}|{}|{}",
            finding.category,
            finding.rule,
            finding.source,
            finding.value.to_ascii_lowercase()
        );
        if seen.insert(key) {
            out.push(finding);
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
    let token = token.trim_matches(|c: char| ".:/\\-_".contains(c));
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
        .trim_matches(|c: char| ".:/\\-_".contains(c))
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
    let allowed = [
        "com", "net", "org", "io", "gg", "xyz", "ru", "cc", "me", "app", "dev", "site", "co",
        "top", "info", "biz",
    ];
    allowed.contains(&tld.to_ascii_lowercase().as_str())
        && labels.iter().all(|label| {
            !label.is_empty() && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
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
    if port.len() < 2 || port.len() > 5 || !port.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    host.contains('.') && (is_ipv4_token(host) || is_domain_token(host))
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
