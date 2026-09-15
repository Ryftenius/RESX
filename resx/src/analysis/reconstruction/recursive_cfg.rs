use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::Mnemonic;
use serde::Serialize;

use crate::analysis::disasm::{disassemble_at, is_ret, Instruction};
use crate::analysis::ir::{summarize_typed_ir, IrOp};
use crate::analysis::symbols::SymbolIndex;
use crate::core::config::Config;
use crate::formats::pe::{read_runtime_function, Export, PeFile};

#[derive(Debug, Clone, Default, Serialize)]
pub struct RecursiveCfg {
    pub entry_rva: String,
    pub function_end_rva: String,
    pub confidence: String,
    pub blocks: Vec<RecursiveBlock>,
    pub edges: Vec<RecursiveEdge>,
    pub discovered_targets: Vec<String>,
    pub unresolved_indirect: Vec<String>,
    pub ir: Vec<IrOp>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecursiveBlock {
    pub id: String,
    pub start_rva: String,
    pub end_rva: String,
    pub insn_count: usize,
    pub confidence: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RecursiveEdge {
    pub from: String,
    pub to: String,
    pub kind: String,
    pub confidence: String,
    pub detail: String,
}

pub struct RecursiveCfgRequest<'a> {
    pub raw: &'a [u8],
    pub pe: &'a PeFile,
    pub start_rva: u32,
    pub arch: u32,
    pub image_base: u64,
    pub exports: &'a [Export],
    pub symbols: Option<&'a SymbolIndex>,
    pub cfg: &'a Config,
    pub prototype: &'a str,
}

pub fn recover_recursive_cfg(request: RecursiveCfgRequest<'_>) -> RecursiveCfg {
    let RecursiveCfgRequest {
        raw,
        pe,
        start_rva,
        arch,
        image_base,
        exports,
        symbols,
        cfg,
        prototype,
    } = request;
    let runtime = read_runtime_function(pe, raw, start_rva);
    let function_end_rva = runtime
        .as_ref()
        .map(|r| r.end_rva)
        .unwrap_or_else(|| section_end(pe, start_rva).unwrap_or(start_rva.saturating_add(0x1000)));
    let decode_limit = function_end_rva.saturating_sub(start_rva).max(1);
    let mut queue = VecDeque::from([start_rva]);
    let mut seen = BTreeSet::new();
    let mut block_map: BTreeMap<u32, Vec<Instruction>> = BTreeMap::new();
    let mut edges = Vec::new();
    let mut discovered_targets = BTreeSet::new();
    let mut unresolved_indirect = BTreeSet::new();
    let mut notes = Vec::new();
    let mut all_insns = Vec::new();

    while let Some(block_start) = queue.pop_front() {
        if !seen.insert(block_start) || seen.len() > cfg.max_total.max(64) {
            continue;
        }
        if !same_function_range(start_rva, function_end_rva, block_start) {
            discovered_targets.insert(block_start);
            continue;
        }
        let Some(file_off) = pe.rva_to_offset(block_start) else {
            notes.push(format!(
                "block {} is not mapped to file bytes",
                hex32(block_start)
            ));
            continue;
        };

        let mut local_cfg = cfg.clone();
        local_cfg.max_bytes = decode_limit.min(cfg.max_bytes.max(512) as u32) as usize;
        local_cfg.max_insns = cfg.max_insns.clamp(64, 2048);
        let Ok(linear) = disassemble_at(
            raw,
            pe,
            file_off,
            block_start,
            arch,
            image_base,
            exports,
            symbols,
            &local_cfg,
        ) else {
            notes.push(format!("failed to decode block {}", hex32(block_start)));
            continue;
        };

        let mut block = Vec::new();
        for insn in linear {
            if !same_function_range(start_rva, function_end_rva, insn.rva) {
                break;
            }
            let stop = terminates_block(&insn);
            block.push(insn);
            if stop {
                break;
            }
        }
        if block.is_empty() {
            continue;
        }

        let last = block.last().cloned().unwrap();
        let from = block_id(block_start);
        for edge in block_edges(&block, image_base) {
            match edge.target_rva {
                Some(target) if same_function_range(start_rva, function_end_rva, target) => {
                    queue.push_back(target);
                    discovered_targets.insert(target);
                    edges.push(RecursiveEdge {
                        from: from.clone(),
                        to: block_id(target),
                        kind: edge.kind,
                        confidence: edge.confidence,
                        detail: edge.detail,
                    });
                }
                Some(target) => {
                    discovered_targets.insert(target);
                    edges.push(RecursiveEdge {
                        from: from.clone(),
                        to: format!("sub_{:08X}", target),
                        kind: edge.kind,
                        confidence: "medium".to_owned(),
                        detail: format!("outside current function: {}", edge.detail),
                    });
                }
                None => {
                    if edge.kind == "indirect" {
                        unresolved_indirect.insert(hex32(last.rva));
                    }
                    edges.push(RecursiveEdge {
                        from: from.clone(),
                        to: String::new(),
                        kind: edge.kind,
                        confidence: edge.confidence,
                        detail: edge.detail,
                    });
                }
            }
        }
        all_insns.extend(block.iter().cloned());
        block_map.insert(block_start, block);
    }

    let blocks = block_map
        .iter()
        .map(|(start, insns)| {
            let end = insns.last().map(|i| i.rva).unwrap_or(*start);
            RecursiveBlock {
                id: block_id(*start),
                start_rva: hex32(*start),
                end_rva: hex32(end),
                insn_count: insns.len(),
                confidence: if runtime.is_some() { "high" } else { "medium" }.to_owned(),
            }
        })
        .collect::<Vec<_>>();
    let ir = summarize_typed_ir(&all_insns, image_base, symbols, prototype).ops;
    if runtime.is_none() {
        notes.push(
            "recursive CFG used section/max-byte bounds because .pdata did not bound this function"
                .to_owned(),
        );
    }
    if !unresolved_indirect.is_empty() {
        notes.push(
            "one or more indirect branches require data-flow or runtime state to resolve"
                .to_owned(),
        );
    }

    RecursiveCfg {
        entry_rva: hex32(start_rva),
        function_end_rva: hex32(function_end_rva),
        confidence: if runtime.is_some() { "high" } else { "medium" }.to_owned(),
        blocks,
        edges,
        discovered_targets: discovered_targets.into_iter().map(hex32).collect(),
        unresolved_indirect: unresolved_indirect.into_iter().collect(),
        ir,
        notes,
    }
}

#[derive(Debug)]
struct EdgeCandidate {
    target_rva: Option<u32>,
    kind: String,
    confidence: String,
    detail: String,
}

fn block_edges(block: &[Instruction], image_base: u64) -> Vec<EdgeCandidate> {
    let Some(last) = block.last() else {
        return Vec::new();
    };
    let mut edges = Vec::new();
    if last.is_jcc {
        if last.call_target != 0 {
            edges.push(EdgeCandidate {
                target_rva: Some(last.call_target.wrapping_sub(image_base) as u32),
                kind: "taken".to_owned(),
                confidence: "high".to_owned(),
                detail: last.mnemonic.clone(),
            });
        }
        edges.push(EdgeCandidate {
            target_rva: next_rva(last),
            kind: "fallthrough".to_owned(),
            confidence: "high".to_owned(),
            detail: "conditional fallthrough".to_owned(),
        });
    } else if last.is_jmp {
        if last.call_target != 0 {
            edges.push(EdgeCandidate {
                target_rva: Some(last.call_target.wrapping_sub(image_base) as u32),
                kind: "jump".to_owned(),
                confidence: "high".to_owned(),
                detail: last.comment.clone(),
            });
        } else {
            edges.push(EdgeCandidate {
                target_rva: None,
                kind: "indirect".to_owned(),
                confidence: "low".to_owned(),
                detail: format!("indirect jump via {}", last.operands),
            });
        }
    } else if is_ret(last.iced.mnemonic()) {
        edges.push(EdgeCandidate {
            target_rva: None,
            kind: "return".to_owned(),
            confidence: "high".to_owned(),
            detail: "function return".to_owned(),
        });
    } else if matches!(
        last.iced.mnemonic(),
        Mnemonic::Int | Mnemonic::Syscall | Mnemonic::Sysenter
    ) {
        edges.push(EdgeCandidate {
            target_rva: None,
            kind: "terminal".to_owned(),
            confidence: "medium".to_owned(),
            detail: last.mnemonic.clone(),
        });
    } else {
        edges.push(EdgeCandidate {
            target_rva: next_rva(last),
            kind: "fallthrough".to_owned(),
            confidence: "medium".to_owned(),
            detail: "linear fallthrough".to_owned(),
        });
    }
    edges
}

fn terminates_block(insn: &Instruction) -> bool {
    insn.is_jmp || insn.is_jcc || is_ret(insn.iced.mnemonic())
}

fn next_rva(insn: &Instruction) -> Option<u32> {
    Some(insn.rva.saturating_add(insn.bytes.len() as u32))
}

fn same_function_range(start: u32, end: u32, rva: u32) -> bool {
    rva >= start && rva < end
}

fn section_end(pe: &PeFile, rva: u32) -> Option<u32> {
    pe.rva_to_section(rva).map(|section| {
        section
            .virtual_address
            .saturating_add(section.virtual_size.max(section.raw_size))
    })
}

fn block_id(rva: u32) -> String {
    format!("block_{:08X}", rva)
}

fn hex32(value: u32) -> String {
    format!("0x{:08X}", value)
}
