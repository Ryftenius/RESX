use std::collections::BTreeSet;

use serde::Serialize;

use crate::analysis::disasm::ApiCall;
use crate::formats::pe::{ImportDll, PeDataSummary, PeFile, PeLoadConfigInfo};

#[derive(Debug, Clone, Default, Serialize)]
pub struct IndirectFlowReport {
    pub edges: Vec<IndirectEdge>,
    pub tables: Vec<IndirectTable>,
    pub mitigations: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndirectEdge {
    pub site_rva: String,
    pub kind: String,
    pub target_rva: String,
    pub target: String,
    pub source: String,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IndirectTable {
    pub rva: String,
    pub kind: String,
    pub entries: Vec<String>,
    pub confidence: String,
}

pub fn analyze_indirect_flow(
    pe: &PeFile,
    imports: &[ImportDll],
    data: &PeDataSummary,
    api_calls: &[ApiCall],
    load_config: Option<&PeLoadConfigInfo>,
) -> IndirectFlowReport {
    let mut report = IndirectFlowReport::default();
    let mut seen_edges = BTreeSet::new();

    for call in api_calls.iter().filter(|call| call.is_indirect) {
        let key = (call.rva, call.target_rva, call.label.clone());
        if !seen_edges.insert(key) {
            continue;
        }
        let target = if call.dll.is_empty() {
            call.label.clone()
        } else {
            format!("{}!{}", call.dll, call.label)
        };
        report.edges.push(IndirectEdge {
            site_rva: hex32(call.rva),
            kind: call.kind.clone(),
            target_rva: if call.target_rva == 0 {
                String::new()
            } else {
                hex32(call.target_rva)
            },
            target,
            source: call
                .indirect_method
                .clone()
                .unwrap_or_else(|| "indirect operand".to_owned()),
            confidence: if call.target_rva == 0 && !call.is_import {
                "low"
            } else {
                "high"
            }
            .to_owned(),
        });
    }

    for vtable in &data.vtables {
        report.tables.push(IndirectTable {
            rva: hex32(vtable.rva),
            kind: "vtable".to_owned(),
            entries: vtable.entries.iter().map(|rva| hex32(*rva)).collect(),
            confidence: "medium".to_owned(),
        });
    }

    for pointer in data.pointers.iter().filter(|ptr| ptr.kind == "code") {
        let key = (pointer.rva, pointer.target_rva, "data-pointer".to_owned());
        if !seen_edges.insert(key) {
            continue;
        }
        report.edges.push(IndirectEdge {
            site_rva: hex32(pointer.rva),
            kind: "data-pointer".to_owned(),
            target_rva: hex32(pointer.target_rva),
            target: format!("sub_{:08X}", pointer.target_rva),
            source: pointer.section_name.clone(),
            confidence: "medium".to_owned(),
        });
    }

    for dll in imports {
        for entry in &dll.entries {
            report.edges.push(IndirectEdge {
                site_rva: hex32(entry.slot_rva),
                kind: "iat-slot".to_owned(),
                target_rva: String::new(),
                target: if entry.by_ord {
                    format!("{}!#{}", dll.dll, entry.ordinal)
                } else {
                    format!("{}!{}", dll.dll, entry.name)
                },
                source: ".idata".to_owned(),
                confidence: "high".to_owned(),
            });
        }
    }

    if let Some(load) = load_config {
        if load.guard_cf_function_count > 0 || load.guard_flags != 0 {
            report.mitigations.push(format!(
                "CFG guard flags=0x{:X} functions={}",
                load.guard_flags, load.guard_cf_function_count
            ));
        }
        if load.guard_eh_continuation_count > 0 {
            report.mitigations.push(format!(
                "GuardEH continuations={}",
                load.guard_eh_continuation_count
            ));
        }
        if load.guard_xfg_check_function_pointer != 0 {
            report.mitigations.push(format!(
                "XFG check pointer=0x{:X}",
                load.guard_xfg_check_function_pointer
            ));
        }
    }

    report.edges.sort_by(|a, b| {
        a.site_rva
            .cmp(&b.site_rva)
            .then_with(|| a.kind.cmp(&b.kind))
            .then_with(|| a.target.cmp(&b.target))
    });
    report
        .edges
        .dedup_by(|a, b| a.site_rva == b.site_rva && a.kind == b.kind && a.target == b.target);
    report.tables.sort_by(|a, b| a.rva.cmp(&b.rva));
    if report.tables.is_empty() && report.edges.is_empty() {
        report
            .notes
            .push("no indirect tables or indirect call sites were recovered".to_owned());
    }
    if !pe
        .sections
        .iter()
        .any(|section| section.name.eq_ignore_ascii_case(".pdata"))
    {
        report
            .notes
            .push("no .pdata section; indirect recovery relies on local decode bounds".to_owned());
    }
    report
}

fn hex32(value: u32) -> String {
    format!("0x{:08X}", value)
}
