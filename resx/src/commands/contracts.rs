use crate::core::{config::Config, json::versioned_object};
use std::io::Write;

pub fn run(cfg: &Config, category: &str, output: &mut dyn Write) -> Result<(), String> {
    let raw = crate::core::input::read_image(&cfg.dll).map_err(|e| e.to_string())?;
    let pe = crate::formats::pe::parse_pe(&raw).map_err(|e| e.to_string())?;
    if category == "strings" {
        let strings = crate::analysis::strings::analyze_strings(
            &cfg.dll,
            Some(&pe),
            &raw,
            &crate::analysis::strings::StringsOptions {
                min_len: cfg.strings_min_len,
                limit: cfg.strings_limit,
                ascii: matches!(cfg.strings_encoding.as_str(), "ascii" | "both"),
                wide: matches!(cfg.strings_encoding.as_str(), "utf16le" | "both"),
                interesting_only: cfg.strings_interesting,
                match_text: (!cfg.strings_match.is_empty()).then(|| cfg.strings_match.clone()),
                tag: (!cfg.strings_tag.is_empty()).then(|| cfg.strings_tag.clone()),
                plausible_utf16_only: !cfg.strings_raw_wide,
            },
        );
        if cfg.verbose && !cfg.quiet {
            eprintln!(
                "RESX: strings: scanned={} bytes, matched={}, returned={}, filtered={}, truncated={}",
                strings.scanned_bytes,
                strings.total,
                strings.strings.len(),
                strings.filtered_out,
                strings.truncated
            );
            eprintln!("RESX: text candidates retain exact offsets and encoding; presence does not prove behavior");
        }
        if !cfg.json {
            let colors = crate::core::color::Colors::new(cfg.color);
            writeln!(output, "{}", colors.heading("String evidence")).map_err(|e| e.to_string())?;
            writeln!(
                output,
                "  scanned={} matched={} returned={} filtered={} truncated={}",
                strings.scanned_bytes,
                strings.total,
                strings.strings.len(),
                strings.filtered_out,
                strings.truncated
            )
            .map_err(|e| e.to_string())?;
            writeln!(
                output,
                "  {:<10} {:<10} {:<9} {:<24} Text",
                "RVA", "File", "Encoding", "Tags"
            )
            .map_err(|e| e.to_string())?;
            for finding in &strings.strings {
                let mut text = finding.value.chars().take(160).collect::<String>();
                if finding.value.chars().count() > 160 {
                    text.push('…');
                }
                writeln!(
                    output,
                    "  {:<10} {:<10} {:<9} {:<24} {}",
                    colors.address(finding.rva.as_deref().unwrap_or("-")),
                    finding.file_offset,
                    finding.encoding,
                    if finding.tags.is_empty() {
                        "-".to_owned()
                    } else {
                        finding.tags.join(",")
                    },
                    colors.value(&text)
                )
                .map_err(|e| e.to_string())?;
            }
            return Ok(());
        }
        return writeln!(
            output,
            "{}",
            serde_json::to_string_pretty(&versioned_object("strings", &strings))
                .map_err(|e| e.to_string())?
        )
        .map_err(|e| e.to_string());
    }
    let mut report = crate::analysis::driver::analyze_contracts(&pe, &raw);
    if category != "contracts" {
        if let Some(calls) = report["calls"].as_array_mut() {
            calls.retain(|c| c["category"] == category);
        }
        report["flows"] = crate::analysis::contract_flows::summarize(&report);
    }
    report["image_sha256"] = serde_json::json!(crate::core::hash::sha256(&raw)?);
    report["image"] = serde_json::json!(cfg.dll);
    report["evidence_status"] = serde_json::json!("static; no target execution");
    if cfg.verbose && !cfg.quiet {
        let calls = report["calls"].as_array().map(Vec::as_slice).unwrap_or(&[]);
        let unknown = calls
            .iter()
            .filter_map(|c| c["arguments"].as_array())
            .flatten()
            .filter(|a| a["value"]["kind"] == "unknown")
            .count();
        eprintln!("RESX: {category}: machine=0x{:04X}, input={} bytes, decoded={}, calls={}, unknown_arguments={unknown}", pe.machine, raw.len(), report["decoded_instructions"],calls.len());
        eprintln!("RESX: coverage: {}", report["coverage"]);
        for limit in report["limitations"].as_array().into_iter().flatten() {
            if let Some(limit) = limit.as_str() {
                eprintln!("RESX: limitation: {limit}");
            }
        }
    }
    if category == "network" {
        report["indicators"] =
            serde_json::json!(crate::analysis::intelli::analyze_image(&raw, &[], None)
                .into_iter()
                .filter(|v| v.category == "network")
                .collect::<Vec<_>>());
    }
    writeln!(
        output,
        "{}",
        serde_json::to_string_pretty(&versioned_object(category, &report))
            .map_err(|e| e.to_string())?
    )
    .map_err(|e| e.to_string())
}
