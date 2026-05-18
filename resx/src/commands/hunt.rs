use std::io::Write;
use std::path::PathBuf;

use crate::analysis::diff::{hunt_corpus, CorpusIndex, HuntCandidate, HuntReport};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use crate::core::search::find_dll_path;

pub fn run(sample_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    if sample_arg.is_empty() {
        return Err("Use `resx hunt <sample> --db <file>`".to_owned());
    }
    let sample_path = find_dll_path(sample_arg, cfg)?;
    let db_path = PathBuf::from(&cfg.corpus_db);
    let raw = std::fs::read_to_string(&db_path)
        .map_err(|e| format!("read corpus index '{}': {}", db_path.display(), e))?;
    let index: CorpusIndex = serde_json::from_str(&raw)
        .map_err(|e| format!("parse corpus index '{}': {}", db_path.display(), e))?;

    let report = hunt_corpus(&sample_path, &index, cfg)?;
    if cfg.json {
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&versioned_object("hunt", &report)).unwrap_or_default()
        )
        .ok();
    } else {
        render_text(w, &report, c);
    }
    Ok(())
}

fn render_text(w: &mut dyn Write, report: &HuntReport, c: &Colors) {
    writeln!(w, "{}", c.bold(&c.b_blue("Corpus Hunt"))).ok();
    writeln!(w, "{}  {}", c.dim("Sample:"), report.sample.path).ok();
    writeln!(w, "{}  {}", c.dim("Index :"), report.index_root).ok();
    writeln!(w, "{}  {}", c.dim("Images:"), report.indexed_images).ok();
    writeln!(w).ok();

    if report.candidates.is_empty() {
        writeln!(w, "{}", c.dim("No candidates met the threshold.")).ok();
        return;
    }

    for candidate in &report.candidates {
        print_candidate(w, candidate, c);
    }

    if !report.notes.is_empty() {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold("Notes")).ok();
        for note in &report.notes {
            writeln!(w, "  {}", c.dim(note)).ok();
        }
    }
}

fn print_candidate(w: &mut dyn Write, candidate: &HuntCandidate, c: &Colors) {
    writeln!(
        w,
        "{}. [{}] {}  {}",
        candidate.rank,
        score_color(candidate.score, c),
        c.cyan(&candidate.name),
        c.dim(&candidate.path)
    )
    .ok();
    writeln!(
        w,
        "   unique {} | metadata {} | coverage left {}% / right {}% | matches {}",
        score_color(candidate.unique_score, c),
        candidate.metadata_score,
        candidate.left_coverage,
        candidate.right_coverage,
        candidate.matched_functions
    )
    .ok();
    if !candidate.family_tags.is_empty() {
        writeln!(w, "   tags: {}", c.dim(&candidate.family_tags.join(", "))).ok();
    }
    for m in candidate.top_matches.iter().take(5) {
        writeln!(
            w,
            "   [{}] {} {} -> {}",
            score_color(m.score, c),
            c.dim(&m.tier),
            m.sample.name,
            m.candidate.name
        )
        .ok();
    }
    if !candidate.signature_hints.stable_semantic_hashes.is_empty() {
        let hashes = candidate
            .signature_hints
            .stable_semantic_hashes
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join(", ");
        writeln!(w, "   stable: {}", c.dim(&hashes)).ok();
    }
    writeln!(w).ok();
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
