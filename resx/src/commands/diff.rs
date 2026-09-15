mod cfg;
mod heatmap;
mod text;

use cfg::*;
use heatmap::*;
use text::*;

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
