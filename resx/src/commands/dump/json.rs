use serde::Serialize;

use crate::analysis::discovery::FunctionDiscoveryReport;
use crate::analysis::edr::EdrCheckResult;
use crate::analysis::explain::ExplainResult;
use crate::analysis::indirect::IndirectFlowReport;
use crate::analysis::intelli::IntelliFinding;
use crate::analysis::ir::TypedIrSummary;
use crate::analysis::recursive_cfg::RecursiveCfg;
use crate::analysis::yara::YaraMatch;
use crate::formats::pe::{PeAnomaly, PeDataSummary, PeSection, PeStartupRoutine};

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
    pub(crate) startup_routines: Vec<StartupRoutineJson>,
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
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub(crate) is_import_slot: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) import_target_dll: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) import_target_name: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) instructions: Vec<InsnJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) xrefs: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) strings: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<PeDataSummaryJson>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) function_discovery: Option<FunctionDiscoveryReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recursive_cfg: Option<RecursiveCfg>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) typed_ir: Option<TypedIrSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) indirect_flow: Option<IndirectFlowReport>,
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
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) api_call_tree: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) current_syscall: Option<SyscallJson>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) syscall: Option<SyscallJson>,
}

#[derive(Serialize)]
pub(crate) struct SyscallJson {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) service_number: Option<String>,
    pub(crate) kernel_module: String,
    pub(crate) kernel_symbol: String,
    pub(crate) kernel_rva: String,
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

#[derive(Serialize)]
pub(crate) struct StartupRoutineJson {
    pub(crate) kind: String,
    pub(crate) source: String,
    pub(crate) rva: String,
    pub(crate) va: String,
    pub(crate) section: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) note: String,
}

#[derive(Serialize)]
pub(crate) struct PeDataSummaryJson {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) strings: Vec<PeDataStringJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) vtables: Vec<PeVTableJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) pointers: Vec<PeDataPointerJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) unwind: Vec<PeRuntimeFunctionJson>,
}

#[derive(Serialize)]
pub(crate) struct PeDataStringJson {
    pub(crate) rva: String,
    pub(crate) section: String,
    pub(crate) encoding: String,
    pub(crate) value: String,
}

#[derive(Serialize)]
pub(crate) struct PeVTableJson {
    pub(crate) rva: String,
    pub(crate) section: String,
    pub(crate) entries: Vec<String>,
}

#[derive(Serialize)]
pub(crate) struct PeDataPointerJson {
    pub(crate) rva: String,
    pub(crate) target_rva: String,
    pub(crate) section: String,
    pub(crate) target_section: String,
    pub(crate) kind: String,
}

#[derive(Serialize)]
pub(crate) struct PeRuntimeFunctionJson {
    pub(crate) begin_rva: String,
    pub(crate) end_rva: String,
    pub(crate) unwind_info_rva: String,
    pub(crate) prolog_size: u8,
    pub(crate) unwind_codes: u8,
    pub(crate) flags: String,
    pub(crate) stack_alloc_size: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) unwind_operations: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) saved_registers: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) exception_handler_rva: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) handler_data_rva: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub(crate) chained_parent: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub(crate) epilog_scopes: Vec<String>,
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

pub(crate) fn to_startup_json(entry: &PeStartupRoutine) -> StartupRoutineJson {
    StartupRoutineJson {
        kind: entry.kind.clone(),
        source: entry.source.clone(),
        rva: format!("0x{:08X}", entry.rva),
        va: format!("0x{:016X}", entry.va),
        section: entry.section_name.clone(),
        note: entry.note.clone(),
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

pub(crate) fn to_data_summary_json(summary: &PeDataSummary) -> PeDataSummaryJson {
    PeDataSummaryJson {
        strings: summary
            .strings
            .iter()
            .map(|s| PeDataStringJson {
                rva: format!("0x{:08X}", s.rva),
                section: s.section_name.clone(),
                encoding: s.encoding.clone(),
                value: s.value.clone(),
            })
            .collect(),
        vtables: summary
            .vtables
            .iter()
            .map(|v| PeVTableJson {
                rva: format!("0x{:08X}", v.rva),
                section: v.section_name.clone(),
                entries: v
                    .entries
                    .iter()
                    .map(|rva| format!("0x{:08X}", rva))
                    .collect(),
            })
            .collect(),
        pointers: summary
            .pointers
            .iter()
            .map(|p| PeDataPointerJson {
                rva: format!("0x{:08X}", p.rva),
                target_rva: format!("0x{:08X}", p.target_rva),
                section: p.section_name.clone(),
                target_section: p.target_section_name.clone(),
                kind: p.kind.clone(),
            })
            .collect(),
        unwind: summary
            .runtime_functions
            .iter()
            .map(|u| PeRuntimeFunctionJson {
                begin_rva: format!("0x{:08X}", u.begin_rva),
                end_rva: format!("0x{:08X}", u.end_rva),
                unwind_info_rva: format!("0x{:08X}", u.unwind_info_rva),
                prolog_size: u.prolog_size,
                unwind_codes: u.unwind_code_count,
                flags: format!("0x{:X}", u.unwind_flags),
                stack_alloc_size: format!("0x{:X}", u.stack_alloc_size),
                unwind_operations: u
                    .unwind_operations
                    .iter()
                    .map(|op| {
                        if op.stack_offset == 0 {
                            format!(
                                "{}@+0x{:X}/info{}: {}",
                                op.op, op.code_offset, op.info, op.description
                            )
                        } else {
                            format!(
                                "{}@+0x{:X}/info{}: {} [stack+0x{:X}]",
                                op.op, op.code_offset, op.info, op.description, op.stack_offset
                            )
                        }
                    })
                    .collect(),
                saved_registers: u
                    .saved_registers
                    .iter()
                    .map(|reg| {
                        format!(
                            "{} stack+0x{:X} prolog+0x{:X}",
                            reg.register, reg.stack_offset, reg.prolog_offset
                        )
                    })
                    .collect(),
                exception_handler_rva: if u.exception_handler_rva == 0 {
                    String::new()
                } else {
                    format!("0x{:08X}", u.exception_handler_rva)
                },
                handler_data_rva: if u.handler_data_rva == 0 {
                    String::new()
                } else {
                    format!("0x{:08X}", u.handler_data_rva)
                },
                chained_parent: u
                    .chained_parent
                    .as_ref()
                    .map(|parent| {
                        format!(
                            "0x{:08X}..0x{:08X} unwind=0x{:08X}",
                            parent.begin_rva, parent.end_rva, parent.unwind_info_rva
                        )
                    })
                    .unwrap_or_default(),
                epilog_scopes: u
                    .epilog_scopes
                    .iter()
                    .map(|scope| {
                        format!(
                            "0x{:X}..0x{:X} {}",
                            scope.start_offset, scope.end_offset, scope.source
                        )
                    })
                    .collect(),
            })
            .collect(),
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
