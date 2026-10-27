//! CFG presentation over completed basic blocks. No traversal or image lookup.
use crate::analysis::cfgview::BasicBlock;
use crate::core::color::Colors;
use crate::core::output::{apply_insn_color, highlight_symbolic_text};

pub fn render_blocks_text(blocks: &[BasicBlock]) -> String {
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

pub fn render_blocks_colored(blocks: &[BasicBlock], c: &Colors) -> String {
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
