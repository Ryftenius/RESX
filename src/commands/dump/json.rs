use serde::Serialize;

use crate::analysis::edr::EdrCheckResult;
use crate::analysis::explain::ExplainResult;
use crate::analysis::intelli::IntelliFinding;
use crate::analysis::yara::YaraMatch;
use crate::formats::pe::{PeAnomaly, PeSection};

#[derive(Serialize)]
pub(crate) struct InsnJson {
    pub(crate) rva: String,
    pub(crate) va: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) rebased_va: String,
    pub(crate) bytes: String,
    pub(crate) text: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) comment: String,
}

#[derive(Serialize)]
pub(crate) struct FuncResult {
    pub(crate) dll: String,
    pub(crate) dll_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) function: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) rva: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) va: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) rebased_va: String,
    pub(crate) image_base: String,
    pub(crate) arch: String,
    pub(crate) entry_point: String,
    pub(crate) size_of_image: String,
    pub(crate) size_of_headers: String,
    pub(crate) section_alignment: String,
    pub(crate) file_alignment: String,
    pub(crate) checksum: String,
    pub(crate) subsystem: String,
    pub(crate) dll_characteristics: String,
    pub(crate) header_corrupt: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) pe_anomalies: Vec<PeAnomalyJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) sections: Vec<PeSectionJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) yara_matches: Vec<YaraJson>,
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub(crate) size_bytes: usize,
    #[serde(skip_serializing_if = "is_zero_usize")]
    pub(crate) insn_count: usize,
    pub(crate) pdb_loaded: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) followed_jmp: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) instructions: Vec<InsnJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) xrefs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) strings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) intelli_findings: Vec<IntelliFinding>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) recomp: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) cfg: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) hook_indicators: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) edrchk: Option<EdrJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) api_calls: Vec<ApiCallJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) explain: Option<ExplainResult>,
}

#[derive(Serialize)]
pub(crate) struct EdrJson {
    pub(crate) in_memory_available: bool,
    pub(crate) blocked_by_policy: bool,
    pub(crate) loaded_for_check: bool,
    pub(crate) compared_len: usize,
    pub(crate) modified: bool,
    pub(crate) diff_offsets: Vec<usize>,
    pub(crate) disk_bytes: String,
    pub(crate) memory_bytes: String,
}

#[derive(Serialize)]
pub(crate) struct PeSectionJson {
    pub(crate) name: String,
    pub(crate) rva: String,
    pub(crate) virtual_size: String,
    pub(crate) raw_offset: String,
    pub(crate) raw_size: String,
    pub(crate) protections: String,
    pub(crate) expected: String,
    pub(crate) entropy: f64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) note: String,
}

#[derive(Serialize)]
pub(crate) struct PeAnomalyJson {
    pub(crate) severity: String,
    pub(crate) kind: String,
    pub(crate) detail: String,
}

#[derive(Serialize)]
pub(crate) struct ApiCallJson {
    pub(crate) rva: String,
    pub(crate) kind: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) target_rva: String,
    pub(crate) label: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) dll: String,
    pub(crate) is_import: bool,
    pub(crate) is_indirect: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) indirect_method: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) switch_cases: Vec<u32>,
}

#[derive(Serialize)]
pub(crate) struct YaraJson {
    pub(crate) rule: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) namespace: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) tags: Vec<String>,
    pub(crate) file: String,
}

pub(crate) fn to_edr_json(edr: &EdrCheckResult) -> EdrJson {
    EdrJson {
        in_memory_available: edr.in_memory_available,
        blocked_by_policy: edr.blocked_by_policy,
        loaded_for_check: edr.loaded_from_memory,
        compared_len: edr.compared_len,
        modified: edr.modified,
        diff_offsets: edr.diff_offsets.clone(),
        disk_bytes: hex_bytes(&edr.disk_bytes),
        memory_bytes: hex_bytes(&edr.memory_bytes),
    }
}

pub(crate) fn to_section_json(section: &PeSection) -> PeSectionJson {
    PeSectionJson {
        name: section.name.clone(),
        rva: format!("0x{:08X}", section.virtual_address),
        virtual_size: format!("0x{:08X}", section.virtual_size),
        raw_offset: format!("0x{:08X}", section.raw_offset),
        raw_size: format!("0x{:08X}", section.raw_size),
        protections: section.protection_string(),
        expected: section.normal_expectation().to_owned(),
        entropy: section.entropy,
        note: section.unusual_protection_reason().unwrap_or_default(),
    }
}

pub(crate) fn to_anomaly_json(anomaly: &PeAnomaly) -> PeAnomalyJson {
    PeAnomalyJson {
        severity: anomaly.severity.clone(),
        kind: anomaly.kind.clone(),
        detail: anomaly.detail.clone(),
    }
}

pub(crate) fn to_yara_json(m: &YaraMatch) -> YaraJson {
    YaraJson {
        rule: m.rule.clone(),
        namespace: m.namespace.clone(),
        tags: m.tags.clone(),
        file: m.file.clone(),
    }
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_zero_usize(value: &usize) -> bool {
    *value == 0
}
