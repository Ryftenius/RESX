//! Describe conflicting decodes without assigning intent to unusual machine code.
use crate::analysis::disasm::Instruction;
use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Serialize)]
pub struct DecodeConflict {
    pub source_rva: u32,
    pub target_rva: u32,
    pub covering_instruction_rva: u32,
    pub covering_bytes: String,
    pub covering_text: String,
    pub alternative_text: String,
    pub kind: &'static str,
}

#[derive(Debug, Serialize)]
pub struct DecodeConflicts {
    pub findings: Vec<DecodeConflict>,
    pub report_limit: usize,
    pub analysis_truncated: bool,
    pub scope: &'static str,
}

pub fn inspect(insns: &[Instruction], arch: u32) -> DecodeConflicts {
    const LIMIT: usize = 64;
    const SCAN: usize = 16384;
    let map: BTreeMap<_, _> = insns.iter().take(SCAN).map(|i| (i.rva, i)).collect();
    let mut result = DecodeConflicts {
        findings: Vec::new(),
        report_limit: LIMIT,
        analysis_truncated: insns.len() > SCAN,
        scope: "decoded function window; alternate streams outside captured bytes are unresolved",
    };
    for row in map.values() {
        let mut targets = vec![(row.rva, "overlapping-decoded-instructions")];
        if row.is_call || row.is_jmp || row.is_jcc {
            let ins = &row.iced;
            if matches!(
                ins.op0_kind(),
                iced_x86::OpKind::NearBranch16
                    | iced_x86::OpKind::NearBranch32
                    | iced_x86::OpKind::NearBranch64
            ) {
                if let Some(target) = ins
                    .near_branch_target()
                    .checked_sub(row.va.saturating_sub(row.rva as u64))
                    .and_then(|v| u32::try_from(v).ok())
                {
                    targets.push((target, "branch-into-instruction"));
                }
            }
        }
        for (target, kind) in targets {
            for (_, covering) in map.range(target.saturating_sub(14)..target) {
                let offset = (target - covering.rva) as usize;
                if offset >= covering.bytes.len() {
                    continue;
                }
                if result.findings.iter().any(|f| {
                    f.source_rva == row.rva
                        && f.target_rva == target
                        && f.covering_instruction_rva == covering.rva
                }) {
                    continue;
                }
                if result.findings.len() == LIMIT {
                    result.analysis_truncated = true;
                    return result;
                }
                let mut decoder = Decoder::with_ip(
                    arch,
                    &covering.bytes[offset..],
                    covering.va + offset as u64,
                    DecoderOptions::NONE,
                );
                let decoded = decoder.decode();
                let mut alternative = String::new();
                if decoded.is_invalid() {
                    alternative.push_str("incomplete/invalid in available bytes");
                } else {
                    IntelFormatter::new().format(&decoded, &mut alternative);
                }
                result.findings.push(DecodeConflict {
                    source_rva: row.rva,
                    target_rva: target,
                    covering_instruction_rva: covering.rva,
                    covering_bytes: covering
                        .bytes
                        .iter()
                        .map(|b| format!("{b:02X}"))
                        .collect::<Vec<_>>()
                        .join(" "),
                    covering_text: covering.text.clone(),
                    alternative_text: alternative,
                    kind,
                });
            }
        }
    }
    result
}

/// Attach bounded evidence to the same instruction rows used by text and JSON.
pub fn annotate(insns: &mut [Instruction], report: &DecodeConflicts) {
    let mut notes = BTreeMap::<u32, Vec<String>>::new();
    for finding in &report.findings {
        let row = notes.entry(finding.source_rva).or_default();
        if row.len() < 4 {
            row.push(format!(
                "alternate stream 0x{:08x} overlaps instruction at 0x{:08x}",
                finding.target_rva, finding.covering_instruction_rva
            ));
        }
    }
    for ins in insns {
        if let Some(row) = notes.get(&ins.rva) {
            if !ins.comment.is_empty() {
                ins.comment.push_str("; ");
            }
            ins.comment.push_str(&row.join("; "));
        }
    }
}
