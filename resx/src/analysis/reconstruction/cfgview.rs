use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::disasm::{is_ret, Instruction};
use crate::core::color::Colors;

#[derive(Debug, Clone)]
pub struct BlockEdge {
    pub kind: &'static str,
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct BasicBlock {
    pub start_rva: u32,
    pub end_rva: u32,
    pub insns: Vec<Instruction>,
    pub edges: Vec<BlockEdge>,
}

#[derive(Debug, Clone)]
pub struct RecoveredIndirectEdge {
    pub jump_rva: u32,
    pub label: String,
}

#[allow(dead_code)]
pub fn build_basic_blocks(insns: &[Instruction], image_base: u64) -> Vec<BasicBlock> {
    build_basic_blocks_with_edges(insns, image_base, &[])
}

pub fn build_basic_blocks_with_edges(
    insns: &[Instruction],
    image_base: u64,
    recovered_edges: &[RecoveredIndirectEdge],
) -> Vec<BasicBlock> {
    if insns.is_empty() {
        return Vec::new();
    }

    let mut leaders = BTreeSet::new();
    let mut by_rva = BTreeMap::new();
    leaders.insert(insns[0].rva);

    for (idx, insn) in insns.iter().enumerate() {
        by_rva.insert(insn.rva, idx);
    }

    for (idx, insn) in insns.iter().enumerate() {
        if (insn.is_jmp || insn.is_jcc) && insn.call_target != 0 {
            leaders.insert(insn.call_target.wrapping_sub(image_base) as u32);
        }
        let architectural_next = next_rva(insn);
        if (insn.is_jmp || insn.is_jcc || is_ret(insn.iced.mnemonic()))
            && architectural_next.is_some_and(|rva| by_rva.contains_key(&rva))
        {
            leaders.insert(architectural_next.unwrap());
        }
        if let Some(next) = insns.get(idx + 1) {
            if architectural_next != Some(next.rva) {
                leaders.insert(next.rva);
                if architectural_next.is_some_and(|rva| by_rva.contains_key(&rva)) {
                    leaders.insert(architectural_next.unwrap());
                }
            }
        }
    }

    let leader_list: Vec<u32> = leaders.into_iter().collect();
    let mut blocks = Vec::new();

    for (pos, start_rva) in leader_list.iter().enumerate() {
        let Some(&start_idx) = by_rva.get(start_rva) else {
            continue;
        };
        let next_leader = leader_list.get(pos + 1).copied();
        let mut end_idx = start_idx;
        while end_idx + 1 < insns.len() {
            if Some(insns[end_idx + 1].rva) == next_leader {
                break;
            }
            if next_rva(&insns[end_idx]) != Some(insns[end_idx + 1].rva) {
                break;
            }
            end_idx += 1;
        }

        let block_insns = insns[start_idx..=end_idx].to_vec();
        let last = &block_insns[block_insns.len() - 1];
        let mut edges = Vec::new();

        if last.is_jcc {
            if last.call_target != 0 {
                let target_rva = last.call_target.wrapping_sub(image_base) as u32;
                edges.push(BlockEdge {
                    kind: "taken",
                    label: edge_label(last, Some(target_rva)),
                });
            }
            if let Some(fallthrough) = next_rva(last).filter(|rva| by_rva.contains_key(rva)) {
                edges.push(BlockEdge {
                    kind: "fallthrough",
                    label: format!("fallthrough -> block_{:08X}", fallthrough),
                });
            }
        } else if last.is_jmp {
            if last.call_target != 0 {
                let target_rva = last.call_target.wrapping_sub(image_base) as u32;
                edges.push(BlockEdge {
                    kind: "jump",
                    label: edge_label(last, Some(target_rva)),
                });
            } else {
                let mut recovered = false;
                for edge in recovered_edges
                    .iter()
                    .filter(|edge| edge.jump_rva == last.rva)
                {
                    edges.push(BlockEdge {
                        kind: "switch",
                        label: edge.label.clone(),
                    });
                    recovered = true;
                }
                if !recovered {
                    edges.push(BlockEdge {
                        kind: "jump",
                        label: format!("indirect jump via {}", last.operands),
                    });
                }
            }
        } else if is_ret(last.iced.mnemonic()) {
            edges.push(BlockEdge {
                kind: "exit",
                label: "return".to_owned(),
            });
        } else if let Some(next_rva) = next_rva(last).filter(|rva| by_rva.contains_key(rva)) {
            edges.push(BlockEdge {
                kind: "fallthrough",
                label: format!("fallthrough -> block_{:08X}", next_rva),
            });
        } else {
            edges.push(BlockEdge {
                kind: "exit",
                label: "exit".to_owned(),
            });
        }

        blocks.push(BasicBlock {
            start_rva: *start_rva,
            end_rva: last.rva,
            insns: block_insns,
            edges,
        });
    }

    blocks
}

fn next_rva(insn: &Instruction) -> Option<u32> {
    insn.rva.checked_add(insn.bytes.len() as u32)
}

// Compatibility entry points. Report consumers can render already-built blocks
// through presentation::cfg without repeating CFG construction.
pub fn render_cfg_text(insns: &[Instruction], image_base: u64) -> String {
    render_cfg_text_with_edges(insns, image_base, &[])
}

pub fn render_cfg_text_with_edges(
    insns: &[Instruction],
    image_base: u64,
    recovered_edges: &[RecoveredIndirectEdge],
) -> String {
    crate::presentation::cfg::render_blocks_text(&build_basic_blocks_with_edges(
        insns,
        image_base,
        recovered_edges,
    ))
}

pub fn render_cfg_colored(insns: &[Instruction], image_base: u64, c: &Colors) -> String {
    render_cfg_colored_with_edges(insns, image_base, c, &[])
}

pub fn render_cfg_colored_with_edges(
    insns: &[Instruction],
    image_base: u64,
    c: &Colors,
    recovered_edges: &[RecoveredIndirectEdge],
) -> String {
    crate::presentation::cfg::render_blocks_colored(
        &build_basic_blocks_with_edges(insns, image_base, recovered_edges),
        c,
    )
}

pub fn detect_static_hook_indicators(
    insns: &[Instruction],
    entry_thunk: Option<&crate::analysis::thunk::ThunkResolution>,
) -> Vec<String> {
    let mut findings = Vec::new();

    if let Some(thunk) = entry_thunk {
        findings.push(format!("entry thunk: {}", thunk.desc()));
    }

    if let Some(first) = insns.first() {
        let m = first.iced.mnemonic();
        if first.is_jmp && entry_thunk.is_none() {
            findings.push(format!("entry jump/trampoline at RVA 0x{:08X}", first.rva));
        } else if m == iced_x86::Mnemonic::Call {
            findings.push(format!("entry call trampoline at RVA 0x{:08X}", first.rva));
        }
    }

    findings
}

fn edge_label(insn: &Instruction, target_rva: Option<u32>) -> String {
    if let Some(target_rva) = target_rva {
        if insn.comment.is_empty() {
            format!("{} -> block_{:08X}", insn.mnemonic, target_rva)
        } else {
            format!(
                "{} -> block_{:08X} ({})",
                insn.mnemonic, target_rva, insn.comment
            )
        }
    } else if insn.comment.is_empty() {
        insn.mnemonic.clone()
    } else {
        format!("{} ({})", insn.mnemonic, insn.comment)
    }
}

#[cfg(test)]
mod tests {
    use iced_x86::{Decoder, DecoderOptions, OpKind};

    use super::*;
    use crate::analysis::disasm::{is_jcc, is_jmp};

    const IMAGE_BASE: u64 = 0x140000000;

    fn decode(rva: u32, bytes: &[u8]) -> Instruction {
        let mut decoder =
            Decoder::with_ip(64, bytes, IMAGE_BASE + rva as u64, DecoderOptions::NONE);
        let iced = decoder.decode();
        let mnemonic = iced.mnemonic();
        let call_target = match iced.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                iced.near_branch_target()
            }
            _ => 0,
        };
        Instruction {
            block_start: rva,
            rva,
            va: IMAGE_BASE + rva as u64,
            file_off: 0,
            bytes: bytes.to_vec(),
            text: format!("{:?}", mnemonic),
            mnemonic: format!("{:?}", mnemonic),
            operands: String::new(),
            iced,
            comment: String::new(),
            is_call: mnemonic == iced_x86::Mnemonic::Call,
            is_jmp: is_jmp(mnemonic),
            is_jcc: is_jcc(mnemonic),
            call_target,
        }
    }

    #[test]
    fn overlapping_streams_keep_architectural_fallthrough() {
        let insns = vec![
            decode(0x118B, &[0x85, 0xC9]),
            decode(0x118D, &[0x74, 0x04]),
            decode(0x118F, &[0xEB, 0x00]),
            decode(
                0x1191,
                &[0x49, 0xBB, 0xE8, 0xE8, 0xFF, 0xFF, 0xFF, 0xEB, 0x01, 0x90],
            ),
            decode(0x1193, &[0xE8, 0xE8, 0xFF, 0xFF, 0xFF]),
            decode(0x1198, &[0xEB, 0x01]),
            decode(0x119B, &[0x48, 0x83, 0xC4, 0x28]),
            decode(0x119F, &[0xC3]),
        ];

        let blocks = build_basic_blocks(&insns, IMAGE_BASE);
        let outer = blocks
            .iter()
            .find(|block| block.start_rva == 0x1191)
            .expect("outer carrier block");
        assert_eq!(outer.insns.len(), 1);
        assert_eq!(outer.insns[0].rva, 0x1191);
        assert_eq!(outer.edges.len(), 1);
        assert!(outer.edges[0].label.contains("block_0000119B"));
        assert!(!outer.edges[0].label.contains("block_00001193"));

        let nested = blocks
            .iter()
            .find(|block| block.start_rva == 0x1193)
            .expect("nested call block");
        assert_eq!(
            nested.insns.iter().map(|insn| insn.rva).collect::<Vec<_>>(),
            vec![0x1193, 0x1198]
        );
        assert!(nested.edges[0].label.contains("block_0000119B"));
    }
}
