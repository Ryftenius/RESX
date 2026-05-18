use std::io::Write;

use crate::analysis::diff::{
    diff_function_cfg, diff_images, diff_many_images, CfgBlockDiff, CfgBlockRef, CfgDiffReport,
    CfgDiffRequest, DiffReport, DiffRequest, FunctionMatch, FunctionRef, MultiDiffReport,
    MultiDiffRequest,
};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use crate::core::output::highlight_symbolic_text;
use crate::core::search::find_dll_path;

pub fn run(
    left_arg: &str,
    right_arg: &str,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    let left_path = find_dll_path(left_arg, cfg)?;
    let right_path = find_dll_path(right_arg, cfg)?;
    let mut diff_paths = vec![left_path, right_path];
    for arg in &cfg.extra_diff_images {
        diff_paths.push(find_dll_path(arg, cfg)?);
    }

    if !cfg.cfg_diff_target.is_empty() && diff_paths.len() != 2 {
        return Err(
            "CFG diff targets are pair-specific; use exactly two images with --show-cfg-diff"
                .to_owned(),
        );
    }

    if !cfg.quiet && !cfg.json {
        if diff_paths.len() == 2 {
            writeln!(
                w,
                "{}",
                c.info(&format!(
                    "Diffing {} <-> {}",
                    diff_paths[0].display(),
                    diff_paths[1].display()
                ))
            )
            .ok();
        } else {
            writeln!(
                w,
                "{}",
                c.info(&format!(
                    "Diffing {} images as an all-pairs structural matrix",
                    diff_paths.len()
                ))
            )
            .ok();
        }
    }

    if !cfg.cfg_diff_target.is_empty() {
        let report = diff_function_cfg(CfgDiffRequest {
            left_path: &diff_paths[0],
            right_path: &diff_paths[1],
            target: &cfg.cfg_diff_target,
            cfg,
        })?;
        let rendered = render_cfg_diff(&report, cfg, c)?;
        if cfg.cfg_diff_out.is_empty() {
            writeln!(w, "{rendered}").ok();
        } else {
            std::fs::write(&cfg.cfg_diff_out, rendered)
                .map_err(|e| format!("write CFG diff '{}': {}", cfg.cfg_diff_out, e))?;
            if !cfg.quiet {
                writeln!(w, "{}", c.ok(&format!("wrote {}", cfg.cfg_diff_out))).ok();
            }
        }
        return Ok(());
    }

    if diff_paths.len() > 2 {
        let report = diff_many_images(MultiDiffRequest {
            paths: &diff_paths,
            cfg,
        })?;
        if cfg.json {
            writeln!(
                w,
                "{}",
                serde_json::to_string_pretty(&versioned_object("diff_matrix", &report))
                    .unwrap_or_default()
            )
            .ok();
        } else {
            render_multi_text(w, &report, c);
            emit_multi_heatmap(&report, cfg, w, c)?;
        }
        return Ok(());
    }

    let report = diff_images(DiffRequest {
        left_path: &diff_paths[0],
        right_path: &diff_paths[1],
        cfg,
    })?;

    if cfg.json {
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&versioned_object("diff", &report)).unwrap_or_default()
        )
        .ok();
    } else {
        render_text(w, &report, c);
        emit_heatmap(&report, cfg, w, c)?;
    }
    Ok(())
}

fn emit_heatmap(
    report: &DiffReport,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    if !cfg.diff_graph {
        return Ok(());
    }
    let rendered = render_heatmap_output(report, cfg, c)?;
    write_optional_graph_output(rendered, &cfg.diff_graph_out, cfg.quiet, w, c)
}

fn emit_multi_heatmap(
    report: &MultiDiffReport,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    if !cfg.diff_graph {
        return Ok(());
    }
    let format = cfg.diff_graph_format.to_ascii_lowercase();
    let rendered = match format.as_str() {
        "text" | "" => render_multi_heatmap_text(report, c),
        "dot" | "graphviz" => render_multi_heatmap_dot(report),
        "json" => serde_json::to_string_pretty(&versioned_object("diff_matrix_heatmap", report))
            .map_err(|e| format!("serialize multi diff heatmap: {e}"))?,
        other => {
            return Err(format!(
                "unsupported --diff-graph-format `{other}`; use text, json, or dot"
            ))
        }
    };
    write_optional_graph_output(rendered, &cfg.diff_graph_out, cfg.quiet, w, c)
}

fn render_heatmap_output(report: &DiffReport, cfg: &Config, c: &Colors) -> Result<String, String> {
    let format = cfg.diff_graph_format.to_ascii_lowercase();
    match format.as_str() {
        "text" | "" => Ok(render_heatmap_text(report, c)),
        "dot" | "graphviz" => Ok(render_heatmap_dot(report)),
        "json" => serde_json::to_string_pretty(&versioned_object("diff_heatmap", &report.heatmap))
            .map_err(|e| format!("serialize diff heatmap: {e}")),
        other => Err(format!(
            "unsupported --diff-graph-format `{other}`; use text, json, or dot"
        )),
    }
    .map(|rendered| {
        if rendered.is_empty() {
            c.dim("(empty heatmap)")
        } else {
            rendered
        }
    })
}

fn write_optional_graph_output(
    rendered: String,
    out_file: &str,
    quiet: bool,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    if out_file.is_empty() {
        writeln!(w, "{rendered}").ok();
    } else {
        std::fs::write(out_file, rendered)
            .map_err(|e| format!("write diff graph '{}': {}", out_file, e))?;
        if !quiet {
            writeln!(w, "{}", c.ok(&format!("wrote {out_file}"))).ok();
        }
    }
    Ok(())
}

fn render_cfg_diff(report: &CfgDiffReport, cfg: &Config, c: &Colors) -> Result<String, String> {
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

fn render_text(w: &mut dyn Write, report: &DiffReport, c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_blue("Structural Diff"))).ok();
    writeln!(w, "{}", c.dim("----------------")).ok();
    writeln!(w).ok();

    writeln!(
        w,
        "{}  {} ({}, {} functions)",
        c.dim("Left :"),
        c.cyan(&report.left.name),
        report.left.arch,
        report.left.profiled_functions
    )
    .ok();
    writeln!(w, "{}  {}", c.dim("Path :"), report.left.path).ok();
    writeln!(
        w,
        "{}  {} ({}, {} functions)",
        c.dim("Right:"),
        c.cyan(&report.right.name),
        report.right.arch,
        report.right.profiled_functions
    )
    .ok();
    writeln!(w, "{}  {}", c.dim("Path :"), report.right.path).ok();
    writeln!(w).ok();

    writeln!(
        w,
        "{}  {}",
        c.dim("Similarity :"),
        score_color(report.summary.similarity_score, c)
    )
    .ok();
    if report.summary.noisy_matches > 0 {
        writeln!(
            w,
            "{}  {}  ({} noisy matches filtered)",
            c.dim("Unique     :"),
            score_color(report.summary.unique_similarity_score, c),
            report.summary.noisy_matches
        )
        .ok();
    }
    writeln!(
        w,
        "{}  left {}% / right {}%",
        c.dim("Coverage   :"),
        report.summary.left_function_coverage,
        report.summary.right_function_coverage
    )
    .ok();
    writeln!(
        w,
        "{}  {} matched  |  {} exact  {} strong  {} changed  {} weak",
        c.dim("Functions  :"),
        report.summary.matched_functions,
        report.summary.exact_matches,
        report.summary.strong_matches,
        report.summary.changed_matches,
        report.summary.weak_matches
    )
    .ok();
    writeln!(
        w,
        "{}  {} left-only  |  {} right-only",
        c.dim("Unmatched  :"),
        report.summary.left_only_functions,
        report.summary.right_only_functions
    )
    .ok();

    if !report.changed_clusters.is_empty() {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold(&c.b_yellow("Changed Clusters"))).ok();
        for cluster in report.changed_clusters.iter().take(12) {
            let score = if cluster.average_score == 0 {
                "-".to_owned()
            } else {
                format!("{}", cluster.average_score)
            };
            writeln!(
                w,
                "  {} {} {}..{}  funcs:{}  avg:{}",
                c.cyan(&cluster.kind),
                c.dim(&cluster.section),
                cluster.start_rva,
                cluster.end_rva,
                cluster.functions,
                score
            )
            .ok();
            for example in cluster.examples.iter().take(3) {
                writeln!(w, "    {}", c.dim(&highlight_symbolic_text(example, c))).ok();
            }
        }
    }

    let changed = report
        .matches
        .iter()
        .filter(|m| matches!(m.tier.as_str(), "changed" | "weak"))
        .take(16)
        .collect::<Vec<_>>();
    if !changed.is_empty() {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold(&c.b_mag("Changed Matches"))).ok();
        for m in changed {
            print_match(w, m, c);
        }
    }

    let mut strong = report
        .matches
        .iter()
        .filter(|m| matches!(m.tier.as_str(), "exact" | "strong"))
        .collect::<Vec<_>>();
    strong.sort_by(|a, b| {
        match_noise_rank(a.left.noise || a.right.noise)
            .cmp(&match_noise_rank(b.left.noise || b.right.noise))
            .then_with(|| match_name_rank(&a.left.name).cmp(&match_name_rank(&b.left.name)))
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| a.left.rva.cmp(&b.left.rva))
    });
    if !strong.is_empty() {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold(&c.b_cyan("Top Matches"))).ok();
        for m in strong.iter().take(8) {
            print_match(w, m, c);
        }
    }

    if !report.left_only.is_empty() {
        print_unmatched(w, "Left Only", &report.left_only, c);
    }
    if !report.right_only.is_empty() {
        print_unmatched(w, "Right Only", &report.right_only, c);
    }

    if has_metadata_delta(report) {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold(&c.b_blue("Metadata Delta"))).ok();
        print_delta(
            w,
            "exports - left only",
            &report.metadata.left_only_exports,
            c,
        );
        print_delta(
            w,
            "exports - right only",
            &report.metadata.right_only_exports,
            c,
        );
        print_delta(
            w,
            "imports - left only",
            &report.metadata.left_only_imports,
            c,
        );
        print_delta(
            w,
            "imports - right only",
            &report.metadata.right_only_imports,
            c,
        );
        print_delta(
            w,
            "strings - left only",
            &report.metadata.left_only_strings,
            c,
        );
        print_delta(
            w,
            "strings - right only",
            &report.metadata.right_only_strings,
            c,
        );
    }

    if !report.signature_hints.stable_semantic_hashes.is_empty() {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold(&c.b_cyan("Signature Hints"))).ok();
        for hash in report.signature_hints.stable_semantic_hashes.iter().take(8) {
            writeln!(w, "  {}", c.dim(hash)).ok();
        }
    }

    if !report.notes.is_empty() {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold("Notes")).ok();
        for note in &report.notes {
            writeln!(w, "  {}", c.dim(note)).ok();
        }
    }
}

fn render_multi_text(w: &mut dyn Write, report: &MultiDiffReport, c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_blue("Structural Diff Matrix"))).ok();
    writeln!(w, "{}", c.dim("----------------------")).ok();
    writeln!(w).ok();

    writeln!(w, "{}", c.bold("Images")).ok();
    for (idx, image) in report.images.iter().enumerate() {
        writeln!(
            w,
            "  {:>2}. {}  {}  {} functions  {}",
            idx + 1,
            c.cyan(&image.name),
            image.arch,
            image.profiled_functions,
            c.dim(&image.path)
        )
        .ok();
    }

    writeln!(w).ok();
    writeln!(w, "{}", c.bold("All-Pairs Summary")).ok();
    writeln!(
        w,
        "  {:<9} {:>5} {:>5} {:>11} {:>8} {:>8} {:>10}  images",
        "pair", "score", "uniq", "coverage", "matched", "changed", "unmatched"
    )
    .ok();
    for pair in &report.pairs {
        writeln!(
            w,
            "  {:<9} {:>5} {:>5} {:>4}%/{:<4}% {:>8} {:>8} {:>4}/{:<5}  {} <-> {}",
            format!("{}<->{}", pair.left_index + 1, pair.right_index + 1),
            score_color(pair.summary.similarity_score, c),
            score_color(pair.summary.unique_similarity_score, c),
            pair.summary.left_function_coverage,
            pair.summary.right_function_coverage,
            pair.summary.matched_functions,
            pair.summary.changed_matches + pair.summary.weak_matches,
            pair.summary.left_only_functions,
            pair.summary.right_only_functions,
            c.cyan(&pair.left.name),
            c.cyan(&pair.right.name),
        )
        .ok();
    }

    let mut interesting = report
        .pairs
        .iter()
        .filter(|pair| {
            pair.summary.changed_matches > 0
                || pair.summary.weak_matches > 0
                || pair.summary.left_only_functions > 0
                || pair.summary.right_only_functions > 0
        })
        .collect::<Vec<_>>();
    interesting.sort_by(|a, b| {
        a.summary
            .unique_similarity_score
            .cmp(&b.summary.unique_similarity_score)
            .then_with(|| a.summary.similarity_score.cmp(&b.summary.similarity_score))
    });
    if !interesting.is_empty() {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold(&c.b_mag("Most Divergent Pairs"))).ok();
        for pair in interesting.iter().take(8) {
            let hottest = pair
                .heatmap
                .hotspots
                .first()
                .map(|hotspot| format!("{} heat {}", hotspot.kind, hotspot.heat))
                .unwrap_or_else(|| "no hotspots".to_owned());
            writeln!(
                w,
                "  {} <-> {}  score {} unique {}  {}",
                c.cyan(&pair.left.name),
                c.cyan(&pair.right.name),
                score_color(pair.summary.similarity_score, c),
                score_color(pair.summary.unique_similarity_score, c),
                c.dim(&hottest)
            )
            .ok();
        }
    }

    if !report.notes.is_empty() {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold("Notes")).ok();
        for note in report.notes.iter().take(12) {
            writeln!(w, "  {}", c.dim(note)).ok();
        }
    }
}

fn render_heatmap_text(report: &DiffReport, c: &Colors) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!("{}\n", c.bold(&c.b_mag("Code-Structure Heatmap"))));
    out.push_str(&format!("{}\n", c.dim("----------------------")));
    out.push_str(&format!(
        "  {} {} <-> {}\n",
        c.dim("Images:"),
        c.cyan(&report.left.name),
        c.cyan(&report.right.name)
    ));
    out.push_str(&format!(
        "  {} cfg {}  blocks {}  ops {}  apis {}  const {}  size {}  name {}\n",
        c.dim("Signals:"),
        signal_bar(report.heatmap.signal_averages.cfg_score, c),
        signal_bar(report.heatmap.signal_averages.block_score, c),
        signal_bar(report.heatmap.signal_averages.opcode_score, c),
        signal_bar(report.heatmap.signal_averages.api_score, c),
        signal_bar(report.heatmap.signal_averages.constant_score, c),
        signal_bar(report.heatmap.signal_averages.size_score, c),
        signal_bar(report.heatmap.signal_averages.name_score, c),
    ));

    if !report.heatmap.section_entropy.is_empty() {
        out.push('\n');
        out.push_str(&format!("{}\n", c.bold("Section Entropy Basis")));
        out.push_str(&format!(
            "  {:<10} {:>8} {:>8} {:>8} {:>6} {:<11} {}\n",
            "section", "left", "right", "delta", "heat", "prot", "note"
        ));
        for section in report.heatmap.section_entropy.iter().take(12) {
            out.push_str(&format!(
                "  {:<10} {:>8} {:>8} {:>8} {:>6} {:<11} {}\n",
                section.section,
                fmt_opt_entropy(section.left_entropy),
                fmt_opt_entropy(section.right_entropy),
                fmt_opt_entropy(section.entropy_delta),
                heat_color(section.heat, c),
                section.protection,
                c.dim(&section.note)
            ));
        }
    }

    if !report.heatmap.hotspots.is_empty() {
        out.push('\n');
        out.push_str(&format!("{}\n", c.bold("Control/Code Hotspots")));
        for hotspot in report.heatmap.hotspots.iter().take(18) {
            let right = if hotspot.right_name.is_empty() {
                c.dim("<none>")
            } else {
                highlight_symbolic_text(&hotspot.right_name, c)
            };
            let left = if hotspot.left_name.is_empty() {
                c.dim("<none>")
            } else {
                highlight_symbolic_text(&hotspot.left_name, c)
            };
            out.push_str(&format!(
                "  [{}] {}  {} {} -> {} {}  {}\n",
                heat_color(hotspot.heat, c),
                c.cyan(&hotspot.kind),
                hotspot.left_rva,
                left,
                hotspot.right_rva,
                right,
                c.dim(&hotspot.section)
            ));
            if let Some(signals) = &hotspot.signals {
                out.push_str(&format!("      {}\n", format_evidence_signals(signals, c)));
            }
            for note in hotspot.notes.iter().take(2) {
                out.push_str(&format!("      {}\n", c.dim(note)));
            }
        }
    }

    for note in &report.heatmap.notes {
        out.push_str(&format!("  {}\n", c.dim(note)));
    }
    out.trim_end().to_owned()
}

fn render_multi_heatmap_text(report: &MultiDiffReport, c: &Colors) -> String {
    let mut out = String::new();
    out.push('\n');
    out.push_str(&format!(
        "{}\n",
        c.bold(&c.b_mag("Code-Structure Heatmap Matrix"))
    ));
    out.push_str(&format!("{}\n", c.dim("-----------------------------")));
    for pair in &report.pairs {
        let max_heat = pair
            .heatmap
            .hotspots
            .first()
            .map(|hotspot| hotspot.heat)
            .unwrap_or(0);
        out.push_str(&format!(
            "  {:<9} score {} unique {} hottest {}  {} <-> {}\n",
            format!("{}<->{}", pair.left_index + 1, pair.right_index + 1),
            score_color(pair.summary.similarity_score, c),
            score_color(pair.summary.unique_similarity_score, c),
            heat_color(max_heat, c),
            c.cyan(&pair.left.name),
            c.cyan(&pair.right.name)
        ));
    }

    let mut hotspots = report
        .pairs
        .iter()
        .flat_map(|pair| {
            pair.heatmap
                .hotspots
                .iter()
                .take(4)
                .map(move |hotspot| (pair, hotspot))
        })
        .collect::<Vec<_>>();
    hotspots.sort_by(|a, b| {
        b.1.heat
            .cmp(&a.1.heat)
            .then_with(|| a.0.left.name.cmp(&b.0.left.name))
    });
    if !hotspots.is_empty() {
        out.push('\n');
        out.push_str(&format!("{}\n", c.bold("Top Hotspots")));
        for (pair, hotspot) in hotspots.iter().take(18) {
            let left = if hotspot.left_name.is_empty() {
                c.dim("<none>")
            } else {
                highlight_symbolic_text(&hotspot.left_name, c)
            };
            let right = if hotspot.right_name.is_empty() {
                c.dim("<none>")
            } else {
                highlight_symbolic_text(&hotspot.right_name, c)
            };
            out.push_str(&format!(
                "  [{}] {}<->{} {}  {} -> {}\n",
                heat_color(hotspot.heat, c),
                pair.left_index + 1,
                pair.right_index + 1,
                c.cyan(&hotspot.kind),
                left,
                right
            ));
        }
    }
    out.trim_end().to_owned()
}

fn render_heatmap_dot(report: &DiffReport) -> String {
    let mut out = String::new();
    out.push_str("digraph diff_heatmap {\n");
    out.push_str("  rankdir=LR;\n");
    out.push_str("  node [shape=box, fontname=\"Consolas\"];\n");
    out.push_str(&format!(
        "  L [label=\"left: {}\", style=filled, fillcolor=\"gray95\"];\n",
        dot_escape(&report.left.name)
    ));
    out.push_str(&format!(
        "  R [label=\"right: {}\", style=filled, fillcolor=\"gray95\"];\n",
        dot_escape(&report.right.name)
    ));
    for (idx, hotspot) in report.heatmap.hotspots.iter().take(32).enumerate() {
        out.push_str(&format!(
            "  H{} [label=\"{}\\nheat {} score {}\\n{} -> {}\", style=filled, fillcolor=\"{}\"];\n",
            idx,
            dot_escape(&hotspot.kind),
            hotspot.heat,
            hotspot.score,
            dot_escape(&hotspot.left_name),
            dot_escape(&hotspot.right_name),
            dot_heat_color(hotspot.heat)
        ));
        out.push_str(&format!("  L -> H{} [color=\"gray55\"];\n", idx));
        out.push_str(&format!("  H{} -> R [color=\"gray55\"];\n", idx));
    }
    for section in report.heatmap.section_entropy.iter().take(16) {
        let section_id = dot_name_id(&section.section);
        out.push_str(&format!(
            "  S{} [label=\"{}\\nentropy delta {}\\nheat {}\", shape=note, style=filled, fillcolor=\"{}\"];\n",
            section_id,
            dot_escape(&section.section),
            section
                .entropy_delta
                .map(|v| format!("{v:.3}"))
                .unwrap_or_else(|| "-".to_owned()),
            section.heat,
            dot_heat_color(section.heat)
        ));
        out.push_str(&format!(
            "  S{} -> R [style=dotted, color=\"gray60\"];\n",
            section_id
        ));
    }
    out.push_str("}\n");
    out
}

fn render_multi_heatmap_dot(report: &MultiDiffReport) -> String {
    let mut out = String::new();
    out.push_str("graph diff_heatmap_matrix {\n");
    out.push_str("  layout=neato;\n");
    out.push_str("  node [shape=box, fontname=\"Consolas\"];\n");
    for (idx, image) in report.images.iter().enumerate() {
        out.push_str(&format!(
            "  I{} [label=\"{}\\n{} functions\", style=filled, fillcolor=\"gray95\"];\n",
            idx,
            dot_escape(&image.name),
            image.profiled_functions
        ));
    }
    for pair in &report.pairs {
        let heat = pair
            .heatmap
            .hotspots
            .first()
            .map(|hotspot| hotspot.heat)
            .unwrap_or_else(|| 100u8.saturating_sub(pair.summary.similarity_score));
        out.push_str(&format!(
            "  I{} -- I{} [label=\"score {} / heat {}\", color=\"{}\", penwidth={}];\n",
            pair.left_index,
            pair.right_index,
            pair.summary.similarity_score,
            heat,
            dot_heat_color(heat),
            1 + (heat as usize / 25)
        ));
    }
    out.push_str("}\n");
    out
}

/*
#[derive(Clone)]
struct VisualFn<'a> {
    f: &'a FunctionRef,
    y: f64,
    h: f64,
    heat: u8,
    score: Option<u8>,
    side: &'static str,
    track: usize,
}

const STRUCTURE_TRACKS: usize = 30;

fn render_structure_html(report: &DiffReport) -> String {
    let svg = render_structure_svg(report);
    format!(
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>RESX Code Structure Atlas - {left} vs {right}</title>
<style>
  body {{ margin: 0; background: #000; color: #e6edf3; font-family: "Cascadia Code", "JetBrains Mono", Consolas, monospace; }}
  .wrap {{ padding: 18px; background: #000; }}
  .hint {{ color: #9ba3ad; margin: 0 0 12px 0; font-size: 13px; line-height: 1.45; max-width: 1280px; }}
  svg {{ width: 100%; height: auto; background: #000; border: 1px solid #202020; }}
</style>
</head>
<body>
<div class="wrap">
<p class="hint">RVA rises from top to bottom. Function blocks are laid over PE sections; gray arcs are intra-image code-flow edges; cross-image edges show structural matches. Red/orange areas are where the images diverge.</p>
{svg}
</div>
</body>
</html>
"#,
        left = html_escape(&report.left.name),
        right = html_escape(&report.right.name),
        svg = svg
    )
}

fn render_structure_svg(report: &DiffReport) -> String {
    let width = 1920.0;
    let top = 132.0;
    let plot_h = 1480.0;
    let bottom = 96.0;
    let height = top + plot_h + bottom;
    let left_x = 220.0;
    let right_x = 1200.0;
    let lane_w = 500.0;
    let heat_w = 20.0;

    let left_functions = collect_left_functions(report);
    let right_functions = collect_right_functions(report);
    let (min_rva, max_rva) = structure_span(report, &left_functions, &right_functions);
    let map_y = |rva: u32| -> f64 {
        top + ((rva.saturating_sub(min_rva) as f64 / max_rva.saturating_sub(min_rva).max(1) as f64)
            * plot_h)
    };

    let mut left_scores = BTreeMap::new();
    let mut right_scores = BTreeMap::new();
    for m in &report.matches {
        left_scores.insert(m.left.rva.clone(), m.score);
        right_scores.insert(m.right.rva.clone(), m.score);
    }

    let left_visuals = pack_visual_tracks(
        left_functions
            .iter()
            .map(|f| visual_fn(f, "left", left_scores.get(&f.rva).copied(), &map_y))
            .collect::<Vec<_>>(),
        STRUCTURE_TRACKS,
    );
    let right_visuals = pack_visual_tracks(
        right_functions
            .iter()
            .map(|f| visual_fn(f, "right", right_scores.get(&f.rva).copied(), &map_y))
            .collect::<Vec<_>>(),
        STRUCTURE_TRACKS,
    );

    let left_by_rva = left_visuals
        .iter()
        .map(|vf| (vf.f.rva.clone(), vf))
        .collect::<BTreeMap<_, _>>();
    let right_by_rva = right_visuals
        .iter()
        .map(|vf| (vf.f.rva.clone(), vf))
        .collect::<BTreeMap<_, _>>();

    let mut out = String::new();
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {:.0} {:.0}\" role=\"img\" aria-label=\"RESX code structure atlas\" style=\"background:#000;font-family:'Cascadia Code','JetBrains Mono',Consolas,monospace\">\n",
        width, height
    ));
    out.push_str(&format!(
        "<rect width=\"{:.0}\" height=\"{:.0}\" fill=\"#000\"/>\n",
        width, height
    ));
    out.push_str(&format!(
        "<text x=\"40\" y=\"42\" fill=\"#f8f8f8\" font-size=\"25\" font-weight=\"700\">RESX Code Structure Atlas</text>\n\
         <text x=\"40\" y=\"73\" fill=\"#9ba3ad\" font-size=\"13\">{} vs {} | similarity {} | unique {} | RVA 0x{:08X}..0x{:08X}</text>\n",
        xml_escape(&report.left.name),
        xml_escape(&report.right.name),
        report.summary.similarity_score,
        report.summary.unique_similarity_score,
        min_rva,
        max_rva
    ));

    render_legend(&mut out, width - 440.0, 30.0);
    render_axis(&mut out, 112.0, top, plot_h, min_rva, max_rva);
    render_axis(&mut out, width - 112.0, top, plot_h, min_rva, max_rva);

    render_image_lane(
        &mut out,
        &report.left.name,
        &report.left.sections,
        left_x,
        top,
        lane_w,
        plot_h,
        min_rva,
        max_rva,
        true,
    );
    render_image_lane(
        &mut out,
        &report.right.name,
        &report.right.sections,
        right_x,
        top,
        lane_w,
        plot_h,
        min_rva,
        max_rva,
        false,
    );

    render_heat_strip(
        &mut out,
        &left_visuals,
        left_x - heat_w - 12.0,
        top,
        heat_w,
        plot_h,
    );
    render_heat_strip(
        &mut out,
        &right_visuals,
        right_x + lane_w + 12.0,
        top,
        heat_w,
        plot_h,
    );
    render_internal_edges(&mut out, &left_visuals, &left_by_rva, left_x, lane_w, true);
    render_internal_edges(
        &mut out,
        &right_visuals,
        &right_by_rva,
        right_x,
        lane_w,
        false,
    );
    render_match_edges(
        &mut out,
        report,
        &left_by_rva,
        &right_by_rva,
        left_x,
        right_x,
        lane_w,
    );
    render_function_blocks(&mut out, &left_visuals, left_x, lane_w, true);
    render_function_blocks(&mut out, &right_visuals, right_x, lane_w, false);
    render_hotspot_labels(
        &mut out,
        report,
        &left_by_rva,
        &right_by_rva,
        left_x,
        right_x,
        lane_w,
    );

    let entry = parse_hex_u32(&report.left.entry_point).unwrap_or(0);
    if entry >= min_rva && entry <= max_rva {
        let y = map_y(entry);
        out.push_str(&format!(
            "<line x1=\"142\" y1=\"{y:.1}\" x2=\"1778\" y2=\"{y:.1}\" stroke=\"#58a6ff\" stroke-width=\"1\" stroke-dasharray=\"6 8\" opacity=\"0.42\"/>\
             <text x=\"40\" y=\"{label_y:.1}\" fill=\"#58a6ff\" font-size=\"11\">entry {}</text>\n",
            xml_escape(&report.left.entry_point),
            y = y,
            label_y = y - 4.0
        ));
    }

    out.push_str(&format!(
        "<text x=\"40\" y=\"{:.0}\" fill=\"#9ba3ad\" font-size=\"12\">green/cyan = same structure, amber = changed, red/blue = one-sided code; vertical heat strips summarize divergence by RVA bin. Hover blocks for function names.</text>\n",
        height - 34.0
    ));
    out.push_str("</svg>\n");
    out
}

fn render_multi_structure_html(report: &MultiDiffReport) -> String {
    let svg = render_multi_structure_svg(report);
    format!(
        r#"<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>RESX Multi Diff Matrix</title>
<style>body{{margin:0;background:#000;color:#e6edf3;font-family:"Cascadia Code","JetBrains Mono",Consolas,monospace}}.wrap{{padding:18px;background:#000}}svg{{width:100%;height:auto;background:#000;border:1px solid #202020}}</style>
</head><body><div class="wrap">{svg}</div></body></html>
"#
    )
}

fn render_multi_structure_svg(report: &MultiDiffReport) -> String {
    let node_count = report.images.len().max(1);
    let width = 1180.0;
    let height = 760.0;
    let cx = width / 2.0;
    let cy = height / 2.0 + 28.0;
    let radius = 230.0;
    let mut points = Vec::new();
    for idx in 0..node_count {
        let angle =
            -std::f64::consts::FRAC_PI_2 + (idx as f64 / node_count as f64) * std::f64::consts::TAU;
        points.push((cx + radius * angle.cos(), cy + radius * angle.sin()));
    }
    let mut out = String::new();
    out.push_str(&format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 {:.0} {:.0}\" role=\"img\" aria-label=\"RESX multi-image structure matrix\">\n",
        width, height
    ));
    out.push_str("<rect width=\"100%\" height=\"100%\" fill=\"#000\"/>\n");
    out.push_str("<text x=\"34\" y=\"44\" fill=\"#f8f8f8\" font-size=\"25\" font-weight=\"700\" font-family=\"Cascadia Code, JetBrains Mono, Consolas, monospace\">RESX Multi-Image Structure Matrix</text>\n");
    out.push_str("<text x=\"34\" y=\"72\" fill=\"#9ba3ad\" font-size=\"14\" font-family=\"Cascadia Code, JetBrains Mono, Consolas, monospace\">Edges are colored by structural divergence; thicker/hotter edges indicate images that differ more.</text>\n");
    for pair in &report.pairs {
        let (x1, y1) = points[pair.left_index];
        let (x2, y2) = points[pair.right_index];
        let heat = 100u8.saturating_sub(pair.summary.unique_similarity_score);
        out.push_str(&format!(
            "<line x1=\"{x1:.1}\" y1=\"{y1:.1}\" x2=\"{x2:.1}\" y2=\"{y2:.1}\" stroke=\"{}\" stroke-width=\"{:.1}\" opacity=\"0.72\"/>\
             <text x=\"{:.1}\" y=\"{:.1}\" fill=\"#c9d1d9\" font-size=\"12\" text-anchor=\"middle\">{}</text>\n",
            svg_heat_color(heat),
            1.5 + heat as f64 / 18.0,
            (x1 + x2) / 2.0,
            (y1 + y2) / 2.0,
            pair.summary.unique_similarity_score
        ));
    }
    for (idx, image) in report.images.iter().enumerate() {
        let (x, y) = points[idx];
        out.push_str(&format!(
            "<circle cx=\"{x:.1}\" cy=\"{y:.1}\" r=\"62\" fill=\"#050505\" stroke=\"#58a6ff\" stroke-width=\"1.4\"/>\
             <text x=\"{x:.1}\" y=\"{:.1}\" fill=\"#f8f8f8\" font-size=\"14\" font-weight=\"700\" text-anchor=\"middle\" font-family=\"Cascadia Code, JetBrains Mono, Consolas, monospace\">{}</text>\
             <text x=\"{x:.1}\" y=\"{:.1}\" fill=\"#9ba3ad\" font-size=\"12\" text-anchor=\"middle\" font-family=\"Cascadia Code, JetBrains Mono, Consolas, monospace\">{} funcs</text>\n",
            y - 4.0,
            xml_escape(&image.name),
            y + 16.0,
            image.profiled_functions
        ));
    }
    out.push_str("</svg>\n");
    out
}

*/
fn print_match(w: &mut dyn Write, m: &FunctionMatch, c: &Colors) {
    writeln!(
        w,
        "  [{}] {}  {} {} -> {} {}",
        score_color(m.score, c),
        tier_color(&m.tier, c),
        m.left.rva,
        highlight_symbolic_text(&m.left.name, c),
        m.right.rva,
        highlight_symbolic_text(&m.right.name, c)
    )
    .ok();
    writeln!(w, "      {}", format_evidence_signals(&m.evidence, c)).ok();
    if !m.evidence.shared_apis.is_empty() {
        writeln!(
            w,
            "      {} {}",
            c.dim("shared APIs:"),
            highlight_symbolic_text(
                &m.evidence
                    .shared_apis
                    .iter()
                    .take(4)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
                c
            )
        )
        .ok();
    }
    for note in m.evidence.notes.iter().take(2) {
        writeln!(w, "      {}", c.dim(note)).ok();
    }
}

fn print_unmatched(w: &mut dyn Write, title: &str, items: &[FunctionRef], c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_red(title))).ok();
    for f in items.iter().take(16) {
        writeln!(
            w,
            "  {} {}  [{} insn, {} blocks, {}]",
            f.rva,
            highlight_symbolic_text(&f.name, c),
            f.insn_count,
            f.block_count,
            if f.noise {
                c.dim(&format!("{}, {}", f.section, f.noise_reason))
            } else {
                c.dim(&f.section)
            }
        )
        .ok();
    }
    if items.len() > 16 {
        writeln!(w, "  {}", c.dim(&format!("... {} more", items.len() - 16))).ok();
    }
}

fn print_delta(w: &mut dyn Write, label: &str, items: &[String], c: &Colors) {
    if items.is_empty() {
        return;
    }
    writeln!(w, "  {}:", c.dim(label)).ok();
    for item in items.iter().take(8) {
        writeln!(w, "    {}", highlight_symbolic_text(item, c)).ok();
    }
    if items.len() > 8 {
        writeln!(w, "    {}", c.dim(&format!("... {} more", items.len() - 8))).ok();
    }
}

fn has_metadata_delta(report: &DiffReport) -> bool {
    !report.metadata.left_only_exports.is_empty()
        || !report.metadata.right_only_exports.is_empty()
        || !report.metadata.left_only_imports.is_empty()
        || !report.metadata.right_only_imports.is_empty()
        || !report.metadata.left_only_strings.is_empty()
        || !report.metadata.right_only_strings.is_empty()
}

fn block_summary(block: Option<&CfgBlockRef>, side: &str) -> String {
    match block {
        Some(block) => format!(
            "block_{}  {}..{}  {} insn",
            block.rva.trim_start_matches("0x"),
            block.rva,
            block.end_rva,
            block.insn_count
        ),
        None => format!("<not present on {side}>"),
    }
}

fn compact_edges(block: &CfgBlockRef) -> String {
    if block.edges.is_empty() {
        "-".to_owned()
    } else {
        block
            .edges
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn style_code_cell(cell: &str, c: &Colors) -> String {
    let visible = cell.trim_end();
    if visible.is_empty() {
        return cell.to_owned();
    }
    let padding = &cell[visible.len()..];
    let Some((addr, rest)) = visible.split_once(' ') else {
        return format!("{}{}", c.b_white(visible), padding);
    };
    let rest = rest.trim_start();
    let mnemonic = rest.split_whitespace().next().unwrap_or_default();
    let rest_tail = rest
        .strip_prefix(mnemonic)
        .map(str::trim_start)
        .unwrap_or_default();
    let mnemonic_colored = match mnemonic.to_ascii_lowercase().as_str() {
        "call" => c.b_cyan(mnemonic),
        "jmp" | "ja" | "jae" | "jb" | "jbe" | "je" | "jne" | "jg" | "jge" | "jl" | "jle" => {
            c.b_yellow(mnemonic)
        }
        "ret" | "retf" => c.green(mnemonic),
        "cmp" | "test" => c.yellow(mnemonic),
        "mov" | "lea" => c.cyan(mnemonic),
        _ => c.b_white(mnemonic),
    };
    if rest_tail.is_empty() {
        format!("{} {}{}", c.dim(addr), mnemonic_colored, padding)
    } else {
        format!(
            "{} {} {}{}",
            c.dim(addr),
            mnemonic_colored,
            rest_tail,
            padding
        )
    }
}

fn cfg_block_status(tier: &str) -> &'static str {
    match tier {
        "exact" => "== exact",
        "similar" => "~= similar",
        "changed" => "!= changed",
        "weak" => "!= weak",
        "left-only" => "-- left-only",
        "right-only" => "++ right-only",
        _ => "?? unknown",
    }
}

fn score_or_dash(score: u8) -> String {
    if score == 0 {
        " --".to_owned()
    } else {
        format!("{score:>3}")
    }
}

fn dot_color_for_block(report: &CfgDiffReport, rva: &str) -> &'static str {
    report
        .blocks
        .iter()
        .find(|diff| {
            diff.left.as_ref().is_some_and(|b| b.rva == rva)
                || diff.right.as_ref().is_some_and(|b| b.rva == rva)
        })
        .map(|diff| match diff.tier.as_str() {
            "exact" => "green4",
            "similar" => "deepskyblue4",
            "changed" | "weak" => "goldenrod",
            "left-only" => "firebrick",
            "right-only" => "royalblue",
            _ => "gray50",
        })
        .unwrap_or("gray50")
}

fn dot_id(rva: &str) -> String {
    rva.trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|c| c.is_ascii_hexdigit())
        .collect()
}

fn dot_escape(raw: &str) -> String {
    raw.replace('\\', "\\\\").replace('"', "\\\"")
}

fn edge_target_rva(edge: &str) -> Option<String> {
    let idx = edge.find("block_")?;
    let start = idx + "block_".len();
    let hex = edge.get(start..start + 8)?;
    hex.chars()
        .all(|c| c.is_ascii_hexdigit())
        .then(|| format!("0x{hex}"))
}

/*
fn collect_left_functions(report: &DiffReport) -> Vec<&FunctionRef> {
    let mut functions = report
        .matches
        .iter()
        .map(|m| &m.left)
        .chain(report.left_only.iter())
        .collect::<Vec<_>>();
    functions.sort_by_key(|f| parse_hex_u32(&f.rva).unwrap_or(0));
    functions
}

fn collect_right_functions(report: &DiffReport) -> Vec<&FunctionRef> {
    let mut functions = report
        .matches
        .iter()
        .map(|m| &m.right)
        .chain(report.right_only.iter())
        .collect::<Vec<_>>();
    functions.sort_by_key(|f| parse_hex_u32(&f.rva).unwrap_or(0));
    functions
}

fn visual_fn<'a>(
    f: &'a FunctionRef,
    side: &'static str,
    score: Option<u8>,
    map_y: &impl Fn(u32) -> f64,
) -> VisualFn<'a> {
    let rva = parse_hex_u32(&f.rva).unwrap_or(0);
    let end = rva.saturating_add(f.size_bytes.max(1) as u32);
    let y = map_y(rva);
    let h = (map_y(end) - y).abs().max(2.6).min(18.0);
    let heat = score.map(|s| 100u8.saturating_sub(s)).unwrap_or(100);
    VisualFn {
        f,
        y,
        h,
        heat,
        score,
        side,
        track: 0,
    }
}

fn pack_visual_tracks<'a>(mut visuals: Vec<VisualFn<'a>>, tracks: usize) -> Vec<VisualFn<'a>> {
    let track_count = tracks.max(1);
    visuals.sort_by(|a, b| {
        a.y.total_cmp(&b.y)
            .then_with(|| b.h.total_cmp(&a.h))
            .then_with(|| a.f.rva.cmp(&b.f.rva))
    });
    let mut occupied_until = vec![f64::NEG_INFINITY; track_count];
    for vf in &mut visuals {
        let preferred = occupied_until
            .iter()
            .enumerate()
            .find(|(_, until)| **until <= vf.y - 1.0)
            .map(|(idx, _)| idx)
            .unwrap_or_else(|| {
                occupied_until
                    .iter()
                    .enumerate()
                    .min_by(|a, b| a.1.total_cmp(b.1))
                    .map(|(idx, _)| idx)
                    .unwrap_or(0)
            });
        vf.track = preferred;
        occupied_until[preferred] = vf.y + vf.h + 1.2;
    }
    visuals.sort_by_key(|vf| parse_hex_u32(&vf.f.rva).unwrap_or(0));
    visuals
}

fn structure_span(
    report: &DiffReport,
    left_functions: &[&FunctionRef],
    right_functions: &[&FunctionRef],
) -> (u32, u32) {
    let mut min_rva = u32::MAX;
    let mut max_rva = 0u32;
    for section in report
        .left
        .sections
        .iter()
        .chain(report.right.sections.iter())
        .filter(|section| section.executable)
    {
        if let Some(rva) = parse_hex_u32(&section.rva) {
            min_rva = min_rva.min(rva);
            max_rva = max_rva.max(rva.saturating_add(section.virtual_size.max(section.raw_size)));
        }
    }
    for f in left_functions.iter().chain(right_functions.iter()) {
        if let Some(rva) = parse_hex_u32(&f.rva) {
            min_rva = min_rva.min(rva);
            max_rva = max_rva.max(rva.saturating_add(f.size_bytes.max(1) as u32));
        }
    }
    if min_rva == u32::MAX || max_rva <= min_rva {
        (0, 1)
    } else {
        (min_rva, max_rva)
    }
}

fn render_legend(out: &mut String, x: f64, y: f64) {
    let items = [
        ("exact", "#2ea043"),
        ("similar", "#1f9cf0"),
        ("changed", "#d29922"),
        ("one-sided", "#f85149"),
        ("flow edge", "#8b949e"),
    ];
    out.push_str(&format!(
        "<g font-size=\"12\" fill=\"#d0d7de\"><text x=\"{x:.1}\" y=\"{y:.1}\" fill=\"#f8f8f8\" font-weight=\"700\">legend</text>\n"
    ));
    for (idx, (label, color)) in items.iter().enumerate() {
        let yy = y + 22.0 + idx as f64 * 18.0;
        out.push_str(&format!(
            "<rect x=\"{x:.1}\" y=\"{:.1}\" width=\"28\" height=\"10\" rx=\"2\" fill=\"{color}\"/>\
             <text x=\"{:.1}\" y=\"{:.1}\">{}</text>\n",
            yy - 9.0,
            x + 36.0,
            yy,
            xml_escape(label)
        ));
    }
    out.push_str("</g>\n");
}

fn render_axis(out: &mut String, x: f64, top: f64, plot_h: f64, min_rva: u32, max_rva: u32) {
    out.push_str(&format!(
        "<line x1=\"{x:.1}\" y1=\"{top:.1}\" x2=\"{x:.1}\" y2=\"{:.1}\" stroke=\"#262626\" stroke-width=\"1\"/>\n",
        top + plot_h
    ));
    for idx in 0..=8 {
        let t = idx as f64 / 8.0;
        let rva = min_rva as f64 + (max_rva.saturating_sub(min_rva) as f64 * t);
        let y = top + plot_h * t;
        out.push_str(&format!(
            "<line x1=\"{:.1}\" y1=\"{y:.1}\" x2=\"{:.1}\" y2=\"{y:.1}\" stroke=\"#262626\"/>\
             <text x=\"{:.1}\" y=\"{:.1}\" fill=\"#9ba3ad\" font-size=\"10\" text-anchor=\"middle\">0x{:X}</text>\n",
            x - 5.0,
            x + 5.0,
            x,
            y - 6.0,
            rva as u32
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn render_image_lane(
    out: &mut String,
    name: &str,
    sections: &[SectionEntropy],
    x: f64,
    top: f64,
    lane_w: f64,
    plot_h: f64,
    min_rva: u32,
    max_rva: u32,
    left: bool,
) {
    out.push_str(&format!(
        "<text x=\"{:.1}\" y=\"{:.1}\" fill=\"#f8f8f8\" font-size=\"16\" font-weight=\"700\" text-anchor=\"{}\">{}</text>\n",
        if left { x } else { x + lane_w },
        top - 24.0,
        if left { "start" } else { "end" },
        xml_escape(name)
    ));
    out.push_str(&format!(
        "<rect x=\"{x:.1}\" y=\"{top:.1}\" width=\"{lane_w:.1}\" height=\"{plot_h:.1}\" fill=\"#030303\" stroke=\"#242424\"/>\n"
    ));
    let span = max_rva.saturating_sub(min_rva).max(1) as f64;
    for section in sections {
        let Some(rva) = parse_hex_u32(&section.rva) else {
            continue;
        };
        let end = rva.saturating_add(section.virtual_size.max(section.raw_size));
        if end < min_rva || rva > max_rva {
            continue;
        }
        let y = top + (rva.saturating_sub(min_rva) as f64 / span) * plot_h;
        let h =
            (((end.min(max_rva)).saturating_sub(rva.max(min_rva)) as f64 / span) * plot_h).max(3.0);
        let fill = if section.executable {
            "#07111d"
        } else {
            "#050505"
        };
        out.push_str(&format!(
            "<rect x=\"{x:.1}\" y=\"{y:.1}\" width=\"{lane_w:.1}\" height=\"{h:.1}\" fill=\"{fill}\" opacity=\"0.82\"/>\
             <text x=\"{:.1}\" y=\"{:.1}\" fill=\"#727985\" font-size=\"10\" text-anchor=\"{}\">{} {:.3}</text>\n",
            if left { x + 6.0 } else { x + lane_w - 6.0 },
            y + 14.0,
            if left { "start" } else { "end" },
            xml_escape(&section.name),
            section.entropy
        ));
    }
}

fn render_heat_strip(
    out: &mut String,
    visuals: &[VisualFn<'_>],
    x: f64,
    top: f64,
    heat_w: f64,
    plot_h: f64,
) {
    const BINS: usize = 96;
    let mut bins = [0u8; BINS];
    for vf in visuals {
        let idx = (((vf.y - top) / plot_h) * BINS as f64).floor() as isize;
        let idx = idx.clamp(0, BINS as isize - 1) as usize;
        bins[idx] = bins[idx].max(vf.heat);
    }
    let bin_h = plot_h / BINS as f64;
    out.push_str(&format!(
        "<rect x=\"{x:.1}\" y=\"{top:.1}\" width=\"{heat_w:.1}\" height=\"{plot_h:.1}\" fill=\"#050505\" stroke=\"#242424\"/>\n"
    ));
    for (idx, heat) in bins.iter().enumerate() {
        if *heat == 0 {
            continue;
        }
        out.push_str(&format!(
            "<rect x=\"{x:.1}\" y=\"{:.1}\" width=\"{heat_w:.1}\" height=\"{:.1}\" fill=\"{}\" opacity=\"0.88\"/>\n",
            top + idx as f64 * bin_h,
            bin_h.max(1.0),
            svg_heat_color(*heat)
        ));
    }
}

fn render_internal_edges(
    out: &mut String,
    visuals: &[VisualFn<'_>],
    by_rva: &BTreeMap<String, &VisualFn<'_>>,
    lane_x: f64,
    lane_w: f64,
    left: bool,
) {
    let mut emitted = 0usize;
    for vf in visuals
        .iter()
        .filter(|vf| !vf.f.noise && vf.f.internal_targets.len() <= 8)
    {
        for target in vf.f.internal_targets.iter().take(3) {
            let Some(to) = by_rva.get(target) else {
                continue;
            };
            let y1 = vf.y + vf.h / 2.0;
            let y2 = to.y + to.h / 2.0;
            if (y1 - y2).abs() < 6.0 {
                continue;
            }
            let edge_x = if left {
                lane_x + lane_w + 34.0
            } else {
                lane_x - 34.0
            };
            let inner_x = if left { lane_x + lane_w } else { lane_x };
            out.push_str(&format!(
                "<path d=\"M {inner_x:.1} {y1:.1} C {edge_x:.1} {y1:.1}, {edge_x:.1} {y2:.1}, {inner_x:.1} {y2:.1}\" fill=\"none\" stroke=\"#8b949e\" stroke-width=\"0.75\" opacity=\"0.12\"/>\n"
            ));
            emitted += 1;
            if emitted >= 64 {
                return;
            }
        }
    }
}

fn render_match_edges(
    out: &mut String,
    report: &DiffReport,
    left_by_rva: &BTreeMap<String, &VisualFn<'_>>,
    right_by_rva: &BTreeMap<String, &VisualFn<'_>>,
    left_x: f64,
    right_x: f64,
    lane_w: f64,
) {
    let mut matches = report.matches.iter().collect::<Vec<_>>();
    matches.sort_by_key(|m| parse_hex_u32(&m.left.rva).unwrap_or(0));
    let mut stable_seen = 0usize;
    let mut strong_seen = 0usize;
    for m in matches {
        if m.score >= 95 {
            stable_seen += 1;
            if stable_seen % 16 != 0 {
                continue;
            }
        } else if m.score >= 85 {
            strong_seen += 1;
            if strong_seen % 5 != 0 {
                continue;
            }
        }
        let (Some(left), Some(right)) =
            (left_by_rva.get(&m.left.rva), right_by_rva.get(&m.right.rva))
        else {
            continue;
        };
        let y1 = left.y + left.h / 2.0;
        let y2 = right.y + right.h / 2.0;
        let opacity = if m.score >= 95 {
            0.10
        } else if m.score >= 90 {
            0.16
        } else if m.score >= 75 {
            0.42
        } else {
            0.72
        };
        let stroke_w = if m.score >= 95 {
            0.7
        } else if m.score >= 90 {
            0.9
        } else if m.score >= 75 {
            1.5
        } else {
            2.8
        };
        out.push_str(&format!(
            "<path d=\"M {:.1} {:.1} C {:.1} {:.1}, {:.1} {:.1}, {:.1} {:.1}\" fill=\"none\" stroke=\"{}\" stroke-width=\"{stroke_w:.1}\" opacity=\"{opacity:.2}\"/>\n",
            left_x + lane_w,
            y1,
            left_x + lane_w + 180.0,
            y1,
            right_x - 180.0,
            y2,
            right_x,
            y2,
            svg_score_color(m.score)
        ));
    }
}

fn render_function_blocks(
    out: &mut String,
    visuals: &[VisualFn<'_>],
    lane_x: f64,
    lane_w: f64,
    left: bool,
) {
    let pitch = (lane_w - 28.0) / STRUCTURE_TRACKS as f64;
    let block_w = (pitch - 2.0).clamp(5.0, 13.0);
    for vf in visuals {
        let score = vf.score.unwrap_or(0);
        let fill = if vf.score.is_some() {
            svg_score_color(score)
        } else if vf.side == "left" {
            "#f85149"
        } else {
            "#58a6ff"
        };
        let x = if left {
            lane_x + 12.0 + vf.track as f64 * pitch
        } else {
            lane_x + lane_w - 12.0 - ((vf.track + 1) as f64 * pitch)
        };
        let opacity = if vf.f.noise {
            0.24
        } else if vf.score.is_some_and(|score| score >= 95) {
            0.58
        } else {
            0.92
        };
        out.push_str(&format!(
            "<rect x=\"{x:.1}\" y=\"{:.1}\" width=\"{block_w:.1}\" height=\"{:.1}\" rx=\"1.5\" fill=\"{fill}\" opacity=\"{opacity:.2}\">\
             <title>{} {} | {} insn | {} blocks | score {}</title></rect>\n",
            vf.y,
            vf.h,
            xml_escape(&vf.f.rva),
            xml_escape(&vf.f.name),
            vf.f.insn_count,
            vf.f.block_count,
            vf.score
                .map(|s| s.to_string())
                .unwrap_or_else(|| "one-sided".to_owned())
        ));
    }
}

fn render_hotspot_labels(
    out: &mut String,
    report: &DiffReport,
    left_by_rva: &BTreeMap<String, &VisualFn<'_>>,
    right_by_rva: &BTreeMap<String, &VisualFn<'_>>,
    left_x: f64,
    right_x: f64,
    lane_w: f64,
) {
    let mut left_rows = Vec::new();
    let mut right_rows = Vec::new();
    for hotspot in report.heatmap.hotspots.iter().take(28) {
        if !hotspot.left_rva.is_empty() {
            if let Some(vf) = left_by_rva.get(&hotspot.left_rva) {
                left_rows.push((vf.y, hotspot.left_name.clone(), hotspot.heat));
            }
        }
        if !hotspot.right_rva.is_empty() {
            if let Some(vf) = right_by_rva.get(&hotspot.right_rva) {
                right_rows.push((vf.y, hotspot.right_name.clone(), hotspot.heat));
            }
        }
    }
    emit_label_column(
        out,
        left_rows,
        left_x - 42.0,
        left_x + 4.0,
        "end",
        136.0,
        1592.0,
    );
    emit_label_column(
        out,
        right_rows,
        right_x + lane_w + 42.0,
        right_x + lane_w - 4.0,
        "start",
        136.0,
        1592.0,
    );
}

fn emit_label_column(
    out: &mut String,
    mut rows: Vec<(f64, String, u8)>,
    label_x: f64,
    connector_x: f64,
    anchor: &str,
    top: f64,
    bottom: f64,
) {
    rows.sort_by(|a, b| {
        b.2.cmp(&a.2)
            .then_with(|| a.0.total_cmp(&b.0))
            .then_with(|| a.1.cmp(&b.1))
    });
    rows.truncate(14);
    rows.sort_by(|a, b| a.0.total_cmp(&b.0));
    let mut last_y = top - 18.0;
    for (orig_y, name, heat) in rows {
        let y = orig_y.max(last_y + 18.0);
        if y > bottom {
            break;
        }
        let label = short_label(&name, 24);
        let text_w = label.chars().count() as f64 * 7.0 + 10.0;
        let rect_x = if anchor == "end" {
            label_x - text_w
        } else {
            label_x - 4.0
        };
        out.push_str(&format!(
            "<line x1=\"{connector_x:.1}\" y1=\"{orig_y:.1}\" x2=\"{label_x:.1}\" y2=\"{y:.1}\" stroke=\"{}\" stroke-width=\"0.7\" opacity=\"0.38\"/>\
             <rect x=\"{rect_x:.1}\" y=\"{:.1}\" width=\"{text_w:.1}\" height=\"15\" rx=\"2\" fill=\"#000\" opacity=\"0.78\"/>\
             <text x=\"{label_x:.1}\" y=\"{:.1}\" fill=\"{}\" font-size=\"10\" text-anchor=\"{anchor}\">{}</text>\n",
            svg_heat_color(heat),
            y - 11.5,
            y,
            svg_heat_color(heat),
            xml_escape(&label)
        ));
        last_y = y;
    }
}

fn svg_score_color(score: u8) -> &'static str {
    match score {
        95..=100 => "#2ea043",
        80..=94 => "#1f9cf0",
        65..=79 => "#d29922",
        50..=64 => "#f97316",
        _ => "#f85149",
    }
}

fn svg_heat_color(heat: u8) -> &'static str {
    match heat {
        75..=100 => "#f85149",
        50..=74 => "#f97316",
        25..=49 => "#d29922",
        1..=24 => "#3fb950",
        _ => "#30363d",
    }
}

fn short_label(value: &str, max: usize) -> String {
    let mut chars = value.chars().collect::<Vec<_>>();
    if chars.len() <= max {
        return value.to_owned();
    }
    chars.truncate(max.saturating_sub(3));
    chars.extend("...".chars());
    chars.into_iter().collect()
}

fn parse_hex_u32(raw: &str) -> Option<u32> {
    let s = raw.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(hex, 16).ok()
}

fn xml_escape(raw: &str) -> String {
    raw.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn html_escape(raw: &str) -> String {
    xml_escape(raw)
}

*/
fn tier_color(tier: &str, c: &Colors) -> String {
    match tier {
        "exact" => c.green(tier),
        "strong" | "similar" => c.cyan(tier),
        "changed" | "weak" => c.yellow(tier),
        "left-only" => c.b_red(tier),
        "right-only" => c.b_blue(tier),
        _ => c.dim(tier),
    }
}

fn cfg_status_color(status: &str, tier: &str, c: &Colors) -> String {
    match tier {
        "exact" => c.green(status),
        "similar" => c.cyan(status),
        "changed" | "weak" => c.yellow(status),
        "left-only" => c.b_red(status),
        "right-only" => c.b_blue(status),
        _ => c.dim(status),
    }
}

fn score_color(score: u8, c: &Colors) -> String {
    let raw = format!("{score:>3}");
    match score {
        90..=100 => c.green(&raw),
        75..=89 => c.cyan(&raw),
        60..=74 => c.yellow(&raw),
        _ => c.b_red(&raw),
    }
}

fn heat_color(heat: u8, c: &Colors) -> String {
    let raw = format!("{heat:>3}");
    match heat {
        75..=100 => c.b_red(&raw),
        50..=74 => c.yellow(&raw),
        25..=49 => c.cyan(&raw),
        _ => c.green(&raw),
    }
}

fn signal_bar(score: u8, c: &Colors) -> String {
    let filled = (score as usize * 8 + 50) / 100;
    let raw = format!(
        "{:>3} [{}{}]",
        score,
        "#".repeat(filled),
        ".".repeat(8 - filled)
    );
    match score {
        90..=100 => c.green(&raw),
        75..=89 => c.cyan(&raw),
        55..=74 => c.yellow(&raw),
        _ => c.b_red(&raw),
    }
}

fn format_evidence_signals(evidence: &crate::analysis::diff::MatchEvidence, c: &Colors) -> String {
    [
        ("cfg", evidence.cfg_score),
        ("blocks", evidence.block_score),
        ("ops", evidence.opcode_score),
        ("apis", evidence.api_score),
        ("const", evidence.constant_score),
        ("size", evidence.size_score),
        ("name", evidence.name_score),
    ]
    .into_iter()
    .map(|(label, score)| format!("{} {}", c.dim(label), signal_bar(score, c)))
    .collect::<Vec<_>>()
    .join("  ")
}

fn fmt_opt_entropy(value: Option<f64>) -> String {
    value
        .map(|value| format!("{value:.3}"))
        .unwrap_or_else(|| "-".to_owned())
}

fn dot_heat_color(heat: u8) -> &'static str {
    match heat {
        75..=100 => "firebrick1",
        50..=74 => "gold",
        25..=49 => "lightskyblue",
        _ => "palegreen",
    }
}

fn dot_name_id(raw: &str) -> String {
    let mut out = raw
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '_' })
        .collect::<String>();
    if out.is_empty() || out.chars().next().is_some_and(|ch| ch.is_ascii_digit()) {
        out.insert(0, 'n');
    }
    out
}

fn match_noise_rank(noise: bool) -> u8 {
    if noise {
        1
    } else {
        0
    }
}

fn match_name_rank(name: &str) -> u8 {
    let tail = name
        .rsplit(['!', ':'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('_');
    if tail.starts_with("sub_") || tail.starts_with("fn_") {
        1
    } else {
        0
    }
}
