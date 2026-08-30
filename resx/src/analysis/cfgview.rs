use std::collections::{BTreeMap, BTreeSet};

use crate::analysis::disasm::{is_ret, Instruction};
use crate::core::color::Colors;
use crate::core::output::{apply_insn_color, highlight_symbolic_text};

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

#[allow(dead_code)]
pub fn render_cfg_text(insns: &[Instruction], image_base: u64) -> String {
    render_cfg_text_with_edges(insns, image_base, &[])
}

pub fn render_cfg_text_with_edges(
    insns: &[Instruction],
    image_base: u64,
    recovered_edges: &[RecoveredIndirectEdge],
) -> String {
    let blocks = build_basic_blocks_with_edges(insns, image_base, recovered_edges);
    if blocks.is_empty() {
        return "(no basic blocks)\n".to_owned();
    }

    let mut out = String::new();
    out.push_str(&format!("  blocks: {}\n", blocks.len()));
    out.push_str(&format!("  entry : block_{:08X}\n\n", blocks[0].start_rva));

    for (idx, block) in blocks.iter().enumerate() {
        out.push_str(&format!(
            "block_{:08X}:  [{} insn]  range 0x{:08X}..0x{:08X}\n",
            block.start_rva,
            block.insns.len(),
            block.start_rva,
            block.end_rva
        ));

        for insn in &block.insns {
            let bytes = insn
                .bytes
                .iter()
                .map(|b| format!("{:02X}", b))
                .collect::<Vec<_>>()
                .join(" ");
            if insn.comment.is_empty() {
                out.push_str(&format!(
                    "    0x{:08X}  {:<26}  {}\n",
                    insn.rva, bytes, insn.text
                ));
            } else {
                out.push_str(&format!(
                    "    0x{:08X}  {:<26}  {}  ; {}\n",
                    insn.rva, bytes, insn.text, insn.comment
                ));
            }
        }

        out.push_str("    edges:\n");
        for edge in &block.edges {
            out.push_str(&format!("      [{}] {}\n", edge.kind, edge.label));
        }

        if idx + 1 < blocks.len() {
            out.push('\n');
        }
    }

    out
}

/// Classify a block by its exit edges so we can pick a header color.
fn block_kind(block: &BasicBlock) -> &'static str {
    for e in &block.edges {
        if e.kind == "exit" {
            return "exit";
        }
    }
    let has_taken = block.edges.iter().any(|e| e.kind == "taken");
    let has_fallthrough = block.edges.iter().any(|e| e.kind == "fallthrough");
    if has_taken && has_fallthrough {
        return "branch";
    }
    if block.edges.iter().any(|e| e.kind == "jump") {
        return "jump";
    }
    "normal"
}

/// Colored terminal rendering.  Plain `render_cfg_text` is kept for JSON.
pub fn render_cfg_colored(insns: &[Instruction], image_base: u64, c: &Colors) -> String {
    render_cfg_colored_with_edges(insns, image_base, c, &[])
}

pub fn render_cfg_colored_with_edges(
    insns: &[Instruction],
    image_base: u64,
    c: &Colors,
    recovered_edges: &[RecoveredIndirectEdge],
) -> String {
    let blocks = build_basic_blocks_with_edges(insns, image_base, recovered_edges);
    if blocks.is_empty() {
        return c.dim("(no basic blocks)\n").to_owned();
    }

    let mut out = String::new();
    out.push_str(&format!(
        "  {}  {}\n",
        c.dim("blocks:"),
        c.b_white(&blocks.len().to_string()),
    ));
    out.push_str(&format!(
        "  {}  {}\n\n",
        c.dim("entry :"),
        c.green(&format!("block_{:08X}", blocks[0].start_rva)),
    ));

    for (idx, block) in blocks.iter().enumerate() {
        // Pick a header color based on what the block does.
        let kind = if idx == 0 { "entry" } else { block_kind(block) };
        let header_name = format!("block_{:08X}", block.start_rva);
        let tag = match kind {
            "entry" => format!("{}  {}", c.bold(&c.green(&header_name)), c.dim("[entry]")),
            "exit" => format!("{}  {}", c.bold(&c.b_red(&header_name)), c.dim("[exit]")),
            "branch" => format!(
                "{}  {}",
                c.bold(&c.b_yellow(&header_name)),
                c.dim("[branch]")
            ),
            "jump" => format!("{}  {}", c.bold(&c.yellow(&header_name)), c.dim("[jump]")),
            _ => c.bold(&c.b_cyan(&header_name)).to_string(),
        };
        let stats = c.dim(&format!(
            "  [{} insn]  range 0x{:08X}..0x{:08X}",
            block.insns.len(),
            block.start_rva,
            block.end_rva,
        ));
        out.push_str(&format!("{}:{}\n", tag, stats));

        // Instructions
        for insn in &block.insns {
            let rva = c.dim(&c.cyan(&format!("0x{:08X}", insn.rva)));
            let bytes = {
                let raw = insn
                    .bytes
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ");
                c.dim(&format!("{:<26}", raw))
            };
            let mnemonic = apply_insn_color(insn, &format!("{:<10}", insn.mnemonic), c);
            let operands = highlight_symbolic_text(&insn.operands, c);
            if insn.comment.is_empty() {
                out.push_str(&format!(
                    "    {}  {}  {} {}\n",
                    rva, bytes, mnemonic, operands
                ));
            } else {
                let comment = format!(
                    "{}{}",
                    c.dim("; "),
                    highlight_symbolic_text(&insn.comment, c)
                );
                out.push_str(&format!(
                    "    {}  {}  {} {}  {}\n",
                    rva, bytes, mnemonic, operands, comment,
                ));
            }
        }

        // Edges
        out.push_str(&format!("    {}\n", c.dim("edges:")));
        for edge in &block.edges {
            let badge = match edge.kind {
                "taken" => c.bold(&c.green(&format!("[{}]", edge.kind))),
                "fallthrough" => c.bold(&c.b_blue(&format!("[{}]", edge.kind))),
                "jump" => c.bold(&c.yellow(&format!("[{}]", edge.kind))),
                "switch" => c.bold(&c.magenta(&format!("[{}]", edge.kind))),
                "exit" => c.bold(&c.b_red(&format!("[{}]", edge.kind))),
                other => c.dim(&format!("[{}]", other)),
            };
            out.push_str(&format!("      {} {}\n", badge, c.dim(&edge.label)));
        }

        if idx + 1 < blocks.len() {
            out.push('\n');
        }
    }

    out
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
