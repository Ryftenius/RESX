use super::*;

pub(super) fn render_cfg_diff(
    report: &CfgDiffReport,
    cfg: &Config,
    c: &Colors,
) -> Result<String, String> {
    let format = cfg.cfg_diff_format.to_ascii_lowercase();
    if cfg.json || format == "json" {
        return serde_json::to_string_pretty(&versioned_object("cfg_diff", report))
            .map_err(|e| format!("serialize cfg diff: {e}"));
    }
    match format.as_str() {
        "text" | "" => Ok(render_cfg_diff_text(report, c)),
        "dot" | "graphviz" => Ok(render_cfg_diff_dot(report)),
        other => Err(format!(
            "unsupported --cfg-diff-format `{other}`; use text, json, or dot"
        )),
    }
}

fn render_cfg_diff_text(report: &CfgDiffReport, c: &Colors) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n{}\n\n",
        c.bold(&c.b_blue("CFG Diff")),
        c.dim("--------")
    ));
    out.push_str(&format!("{}\n", c.bold("Summary")));
    out.push_str(&format!(
        "  {:<9} {}!{}  ->  {}!{}\n",
        "Function:",
        report.left_image.name,
        report.left_function.name,
        report.right_image.name,
        report.right_function.name
    ));
    out.push_str(&format!(
        "  {:<9} {} -> {}\n",
        "RVA:", report.left_function.rva, report.right_function.rva
    ));
    out.push_str(&format!(
        "  {:<9} {} matched, {} exact, {} changed, {} left-only, {} right-only\n",
        "Blocks:",
        report.summary.matched_blocks,
        report.summary.exact_blocks,
        report.summary.changed_blocks,
        report.summary.left_only_blocks,
        report.summary.right_only_blocks
    ));
    out.push_str(&format!(
        "  {:<9} {}   coverage left {}% / right {}%\n\n",
        "Score:",
        score_color(report.summary.score, c),
        report.summary.left_block_coverage,
        report.summary.right_block_coverage
    ));
    out.push_str(&format!("{}\n", c.bold("Legend")));
    out.push_str("  == exact normalized block match      ~= similar block\n");
    out.push_str("  != changed/weak block pair           -- left-only      ++ right-only\n\n");

    for (idx, block) in report.blocks.iter().enumerate() {
        if idx > 0 {
            out.push_str(&format!("{}\n", c.dim(&"-".repeat(96))));
        }
        render_cfg_block_pair(&mut out, block, c);
    }

    if !report.notes.is_empty() {
        out.push('\n');
        out.push_str(&format!("{}\n", c.bold("Notes")));
        for note in &report.notes {
            out.push_str(&format!("  {}\n", c.dim(note)));
        }
    }
    out.trim_end().to_owned()
}

fn render_cfg_block_pair(out: &mut String, block: &CfgBlockDiff, c: &Colors) {
    let status = cfg_block_status(&block.tier);
    let score = score_or_dash(block.score);
    let left_header = block_summary(block.left.as_ref(), "left");
    let right_header = block_summary(block.right.as_ref(), "right");
    out.push_str(&format!(
        "{}  score {}  {}  |  {}\n",
        cfg_status_color(status, &block.tier, c),
        if block.score == 0 {
            c.dim(&score)
        } else {
            score_color(block.score, c)
        },
        c.b_white(&left_header),
        c.b_white(&right_header)
    ));
    out.push_str(&format!(
        "  {} ops {}  apis {}  const {}  edges {}\n",
        c.dim("signals:"),
        signal_bar(block.evidence.op_score, c),
        signal_bar(block.evidence.api_score, c),
        signal_bar(block.evidence.constant_score, c),
        signal_bar(block.evidence.edge_score, c)
    ));

    let left_edges = block
        .left
        .as_ref()
        .map(|b| format!("edges: {}", compact_edges(b)))
        .unwrap_or_else(|| "edges: -".to_owned());
    let right_edges = block
        .right
        .as_ref()
        .map(|b| format!("edges: {}", compact_edges(b)))
        .unwrap_or_else(|| "edges: -".to_owned());
    out.push_str(&format!(
        "  {} {}\n",
        c.dim("left :"),
        highlight_symbolic_text(&left_edges, c)
    ));
    out.push_str(&format!(
        "  {} {}\n",
        c.dim("right:"),
        highlight_symbolic_text(&right_edges, c)
    ));

    let left_lines = block
        .left
        .as_ref()
        .map(|b| b.lines.as_slice())
        .unwrap_or(&[]);
    let right_lines = block
        .right
        .as_ref()
        .map(|b| b.lines.as_slice())
        .unwrap_or(&[]);
    let max_lines = left_lines.len().max(right_lines.len()).min(12);
    if max_lines > 0 {
        out.push_str(&format!("  {}\n", c.bold("code")));
    }
    for idx in 0..max_lines {
        let left = left_lines.get(idx).map(String::as_str).unwrap_or("");
        let right = right_lines.get(idx).map(String::as_str).unwrap_or("");
        if !left.is_empty() {
            out.push_str(&format!(
                "    {} {}\n",
                c.dim("L"),
                style_code_cell(left, c)
            ));
        }
        if !right.is_empty() {
            out.push_str(&format!(
                "    {} {}\n",
                c.dim("R"),
                style_code_cell(right, c)
            ));
        }
    }
    if left_lines.len().max(right_lines.len()) > max_lines {
        let left_more = left_lines.len().saturating_sub(max_lines);
        let right_more = right_lines.len().saturating_sub(max_lines);
        out.push_str(&format!(
            "    {}\n",
            c.dim(&format!(
                "... {left_more} more left instruction(s), {right_more} more right instruction(s)"
            ))
        ));
    }
    if !block.evidence.notes.is_empty() {
        out.push_str(&format!(
            "  {} {}\n",
            c.dim("evidence:"),
            c.yellow(&block.evidence.notes.join("; "))
        ));
    }
}

fn render_cfg_diff_dot(report: &CfgDiffReport) -> String {
    let mut out = String::new();
    out.push_str("digraph cfg_diff {\n");
    out.push_str("  rankdir=LR;\n");
    out.push_str("  node [shape=box, fontname=\"Consolas\"];\n");
    out.push_str("  subgraph cluster_left {\n");
    out.push_str(&format!(
        "    label=\"left: {}\";\n",
        dot_escape(&report.left_function.name)
    ));
    for block in report.blocks.iter().filter_map(|diff| diff.left.as_ref()) {
        out.push_str(&format!(
            "    L{} [label=\"{}\", color=\"{}\"];\n",
            dot_id(&block.rva),
            dot_escape(&format!("{}\\n{} insn", block.rva, block.insn_count)),
            dot_color_for_block(report, &block.rva)
        ));
    }
    out.push_str("  }\n");
    out.push_str("  subgraph cluster_right {\n");
    out.push_str(&format!(
        "    label=\"right: {}\";\n",
        dot_escape(&report.right_function.name)
    ));
    for block in report.blocks.iter().filter_map(|diff| diff.right.as_ref()) {
        out.push_str(&format!(
            "    R{} [label=\"{}\", color=\"{}\"];\n",
            dot_id(&block.rva),
            dot_escape(&format!("{}\\n{} insn", block.rva, block.insn_count)),
            dot_color_for_block(report, &block.rva)
        ));
    }
    out.push_str("  }\n");
    for diff in &report.blocks {
        if let (Some(left), Some(right)) = (&diff.left, &diff.right) {
            out.push_str(&format!(
                "  L{} -> R{} [style=dashed, label=\"{}\", color=\"gray50\"];\n",
                dot_id(&left.rva),
                dot_id(&right.rva),
                diff.score
            ));
        }
        if let Some(left) = &diff.left {
            for edge in &left.edges {
                if let Some(target) = edge_target_rva(edge) {
                    out.push_str(&format!(
                        "  L{} -> L{} [color=\"gray60\"];\n",
                        dot_id(&left.rva),
                        dot_id(&target)
                    ));
                }
            }
        }
        if let Some(right) = &diff.right {
            for edge in &right.edges {
                if let Some(target) = edge_target_rva(edge) {
                    out.push_str(&format!(
                        "  R{} -> R{} [color=\"gray60\"];\n",
                        dot_id(&right.rva),
                        dot_id(&target)
                    ));
                }
            }
        }
    }
    out.push_str("}\n");
    out
}
