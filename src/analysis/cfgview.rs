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
        if (insn.is_jmp || insn.is_jcc) && insn.call_target != 0 {
            leaders.insert(insn.call_target.wrapping_sub(image_base) as u32);
        }
        if (insn.is_jmp || insn.is_jcc || is_ret(insn.iced.mnemonic())) && idx + 1 < insns.len() {
            leaders.insert(insns[idx + 1].rva);
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
            if end_idx + 1 < insns.len() {
                let fallthrough = insns[end_idx + 1].rva;
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
        } else if end_idx + 1 < insns.len() {
            let next_rva = insns[end_idx + 1].rva;
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
            let text = c.b_white(&insn.text);
            if insn.comment.is_empty() {
                out.push_str(&format!("    {}  {}  {}\n", rva, bytes, text));
            } else {
                out.push_str(&format!(
                    "    {}  {}  {}  {}\n",
                    rva,
                    bytes,
                    text,
                    c.green(&format!("; {}", insn.comment)),
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
