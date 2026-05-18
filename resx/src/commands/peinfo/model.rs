use serde::Serialize;

use crate::formats::pe::{
    PeAnomaly, PeDataSummary, PeDebugInfo, PeLoadConfigInfo, PeSection, PeStartupRoutine,
};

#[derive(Serialize)]
pub struct PeInfoJson {
    pub path: String,
    pub file_name: String,
    pub file_size: u64,
    pub image_kind: String,
    pub arch: String,
    pub machine: String,
    pub linker_version: String,
    pub timestamp: String,
    pub image_base: String,
    pub entry_point: String,
    pub size_of_image: String,
    pub size_of_headers: String,
    pub section_alignment: String,
    pub file_alignment: String,
    pub checksum: String,
    pub subsystem: String,
    pub subsystem_name: String,
    pub dll_characteristics: String,
    pub coff_characteristics: String,
    pub header_corrupt: bool,
    pub export_count: usize,
    pub import_dll_count: usize,
    pub import_count: usize,
    pub analysis: AnalysisJson,
    pub debug: DebugJson,
    pub mitigations: MitigationsJson,
    pub data: DataSummaryJson,
    pub names: NameJson,
    pub signer: SignerJson,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub startup_routines: Vec<StartupRoutineJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub sections: Vec<SectionJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub anomalies: Vec<AnomalyJson>,
}

#[derive(Serialize)]
pub struct NameJson {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub product_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file_description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub company_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub original_filename: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub internal_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub known_names: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub file_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub product_version: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub comments: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub legal_copyright: String,
}

#[derive(Serialize)]
pub struct SignerJson {
    pub status: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub subject: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub issuer: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub thumbprint: String,
}

#[derive(Serialize)]
pub struct StartupRoutineJson {
    pub kind: String,
    pub source: String,
    pub rva: String,
    pub va: String,
    pub section: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Serialize)]
pub struct SectionJson {
    pub name: String,
    pub rva: String,
    pub virtual_size: String,
    pub raw_size: String,
    pub tag: String,
    pub protection: String,
    pub expected: String,
    pub entropy: f64,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub note: String,
}

#[derive(Serialize)]
pub struct AnomalyJson {
    pub severity: String,
    pub kind: String,
    pub detail: String,
}

#[derive(Serialize)]
pub struct AnalysisJson {
    pub platform: String,
    pub runtime: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub likely_languages: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub likely_toolchains: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub likely_components: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub packers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub clr_metadata_version: String,
}

#[derive(Serialize)]
pub struct DebugJson {
    pub has_debug_directory: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub debug_types: Vec<String>,
    pub has_codeview: bool,
    pub debug_stripped: bool,
    pub line_numbers_stripped: bool,
    pub local_symbols_stripped: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pdb_path: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pdb_name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub pdb_guid_age: String,
}

#[derive(Serialize)]
pub struct MitigationsJson {
    pub reloc_stripped: bool,
    pub aslr: bool,
    pub high_entropy_va: bool,
    pub nx_compat: bool,
    pub no_seh: bool,
    pub seh_available: bool,
    pub force_integrity: bool,
    pub appcontainer: bool,
    pub wdm_driver: bool,
    pub cfg: bool,
    pub cfg_instrumented: bool,
    pub cfg_w_instrumented: bool,
    pub cfg_function_table: bool,
    pub xfg: bool,
    pub retpoline: bool,
    pub rf_instrumented: bool,
    pub rf_enabled: bool,
    pub rf_strict: bool,
    pub cet_eh_continuation: bool,
    pub cast_guard: bool,
    pub memcpy_guard: bool,
    pub delay_load_iat_protected: bool,
    pub security_cookie: bool,
    pub safe_seh: bool,
    pub se_handler_count: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub veh_imports: Vec<String>,
}

#[derive(Serialize)]
pub struct DataSummaryJson {
    pub string_count: usize,
    pub vtable_count: usize,
    pub pointer_count: usize,
    pub unwind_count: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<DataStringJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub vtables: Vec<VTableJson>,
}

#[derive(Serialize)]
pub struct DataStringJson {
    pub rva: String,
    pub section: String,
    pub encoding: String,
    pub value: String,
}

#[derive(Serialize)]
pub struct VTableJson {
    pub rva: String,
    pub section: String,
    pub entries: Vec<String>,
}

pub struct BuildAssessment {
    pub platform: String,
    pub runtime: String,
    pub likely_languages: Vec<String>,
    pub likely_toolchains: Vec<String>,
    pub likely_components: Vec<String>,
    pub packers: Vec<String>,
    pub evidence: Vec<String>,
}

#[derive(Default)]
pub struct Candidate {
    pub score: i32,
    pub evidence: Vec<String>,
}

pub fn to_section_json(section: &PeSection) -> SectionJson {
    SectionJson {
        name: section.name.clone(),
        rva: format!("0x{:08X}", section.virtual_address),
        virtual_size: format!("0x{:08X}", section.virtual_size),
        raw_size: format!("0x{:08X}", section.raw_size),
        tag: section.protection_string(),
        protection: section.protection_name(),
        expected: section.normal_expectation_name().to_owned(),
        entropy: section.entropy,
        note: section.unusual_protection_reason().unwrap_or_default(),
    }
}

pub fn to_anomaly_json(anomaly: &PeAnomaly) -> AnomalyJson {
    AnomalyJson {
        severity: anomaly.severity.clone(),
        kind: anomaly.kind.clone(),
        detail: anomaly.detail.clone(),
    }
}

pub fn to_startup_json(entry: &PeStartupRoutine) -> StartupRoutineJson {
    StartupRoutineJson {
        kind: entry.kind.clone(),
        source: entry.source.clone(),
        rva: format!("0x{:08X}", entry.rva),
        va: format!("0x{:016X}", entry.va),
        section: entry.section_name.clone(),
        note: entry.note.clone(),
    }
}

pub fn to_data_summary_json(summary: &PeDataSummary) -> DataSummaryJson {
    DataSummaryJson {
        string_count: summary.strings.len(),
        vtable_count: summary.vtables.len(),
        pointer_count: summary.pointers.len(),
        unwind_count: summary.runtime_functions.len(),
        strings: summary
            .strings
            .iter()
            .take(64)
            .map(|s| DataStringJson {
                rva: format!("0x{:08X}", s.rva),
                section: s.section_name.clone(),
                encoding: s.encoding.clone(),
                value: s.value.clone(),
            })
            .collect(),
        vtables: summary
            .vtables
            .iter()
            .take(64)
            .map(|v| VTableJson {
                rva: format!("0x{:08X}", v.rva),
                section: v.section_name.clone(),
                entries: v
                    .entries
                    .iter()
                    .take(32)
                    .map(|rva| format!("0x{:08X}", rva))
                    .collect(),
            })
            .collect(),
    }
}

pub fn debug_types(debug: &PeDebugInfo) -> Vec<String> {
    debug
        .entries
        .iter()
        .map(|entry| format!("{}({} bytes)", entry.type_name(), entry.size_of_data))
        .collect()
}

pub fn safe_seh(
    pe_arch: u32,
    dll_characteristics: u16,
    load_config: Option<&PeLoadConfigInfo>,
) -> bool {
    pe_arch == 32
        && dll_characteristics & crate::formats::pe::IMAGE_DLLCHARACTERISTICS_NO_SEH == 0
        && load_config.is_some_and(|v| v.se_handler_count != 0)
}
