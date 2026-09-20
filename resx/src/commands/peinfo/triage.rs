use crate::formats::pe::PeFile;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct TriageFinding {
    pub severity: String,
    pub confidence: String,
    pub kind: String,
    pub title: String,
    pub evidence: Vec<String>,
    pub interpretation: String,
}

pub fn assess(pe: &PeFile) -> Vec<TriageFinding> {
    let mut findings = Vec::new();
    for section in &pe.sections {
        let code_like = section.is_executable()
            || matches!(section.name.to_ascii_lowercase().as_str(), ".text" | "text");
        let threshold = if code_like { 7.15 } else { 7.70 };
        if section.raw_size < 4096 || section.entropy < threshold {
            continue;
        }
        let near_maximal = section.entropy >= 7.70;
        findings.push(TriageFinding {
            severity: if near_maximal { "warn" } else { "info" }.to_owned(),
            confidence: "high".to_owned(),
            kind: if code_like { "high-entropy-code-section" } else { "high-entropy-section" }.to_owned(),
            title: format!("{} section {} has {:.3} bits/byte entropy", if code_like { "Code" } else { "Data" }, if section.name.is_empty() { "<unnamed>" } else { &section.name }, section.entropy),
            evidence: vec![format!("RVA 0x{:08X}, raw size 0x{:X}, declared protection {}{}", section.virtual_address, section.raw_size, section.protection_string(), if code_like && !section.is_executable() { "; code-designated section is not executable in its section flags" } else { "" })],
            interpretation: if near_maximal && code_like {
                "Near-maximal executable entropy is consistent with packed, encrypted, or heavily obfuscated code; entropy alone does not identify a protector or prove execution."
            } else if near_maximal {
                "Near-maximal entropy in a large data section is consistent with compressed or encrypted content; entropy alone does not establish its purpose."
            } else {
                "Elevated executable entropy can indicate compression or obfuscation, but may also occur in ordinary optimized code."
            }.to_owned(),
        });
    }
    findings
}
