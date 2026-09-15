use super::*;

pub(super) fn render_heatmap_text(report: &DiffReport, c: &Colors) -> String {
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

pub(super) fn render_multi_heatmap_text(report: &MultiDiffReport, c: &Colors) -> String {
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

pub(super) fn render_heatmap_dot(report: &DiffReport) -> String {
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

pub(super) fn render_multi_heatmap_dot(report: &MultiDiffReport) -> String {
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
