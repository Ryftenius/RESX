use super::*;

pub(super) fn render_text(w: &mut dyn Write, report: &DiffReport, c: &Colors) {
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

pub(super) fn render_multi_text(w: &mut dyn Write, report: &MultiDiffReport, c: &Colors) {
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
