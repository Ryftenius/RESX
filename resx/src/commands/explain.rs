use std::io::Write;

use crate::analysis::explain::{explain_symbol, ExplainMode, ExplainResult};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;

pub fn run(term: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let query = term.trim();
    if query.is_empty() {
        return Err("Specify a symbol or prefix to explain".to_owned());
    }

    let result = explain_symbol(query, config_mode(cfg));
    if cfg.json {
        let out = serde_json::to_string_pretty(&versioned_object("explain", &result)).unwrap_or_default();
        writeln!(w, "{}", out).ok();
    } else {
        print_explain_text(w, &result, c, false);
    }
    Ok(())
}

pub fn print_explain_text(w: &mut dyn Write, result: &ExplainResult, c: &Colors, compact: bool) {
    writeln!(w).ok();
    writeln!(
        w,
        "{}",
        c.bold(&c.b_mag(&format!("Explain: {}", result.query)))
    )
    .ok();

    if compact {
        writeln!(w, "  {} {}", c.bold("Summary:"), result.summary).ok();
    } else {
        writeln!(w, "  {} {}", c.bold("Mode:"), result.mode).ok();
        writeln!(w, "  {} {}", c.bold("Summary:"), result.summary).ok();
    }

    if let Some(prefix) = result.prefix.as_ref() {
        writeln!(
            w,
            "  {} {}  {}",
            c.bold("Prefix:"),
            c.b_cyan(&prefix.key),
            c.dim(&format!("({})", prefix.title))
        )
        .ok();
        writeln!(w, "    {}", prefix.summary).ok();
    }

    if !result.remainder.is_empty() {
        writeln!(w, "  {} {}", c.bold("Body:"), c.b_white(&result.remainder)).ok();
    }

    for chunk in &result.chunks {
        writeln!(
            w,
            "    {} {:<18} {}",
            c.dim(&format!("[{}]", chunk.kind)),
            chunk.token,
            chunk.meaning
        )
        .ok();
    }

    if !result.notes.is_empty() {
        writeln!(w, "  {}", c.bold("Notes:")).ok();
        for note in &result.notes {
            writeln!(w, "    {}", c.dim(note)).ok();
        }
    }
}

pub fn config_mode(cfg: &Config) -> ExplainMode {
    if cfg.explain_prefix {
        ExplainMode::Prefix
    } else if cfg.explain_api {
        ExplainMode::Api
    } else {
        ExplainMode::Auto
    }
}
