use std::io::Write;

use crate::analysis::behavior::analyze_image_with_headers;
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use crate::core::search::find_dll_path;
use crate::formats::pe::{parse_pe, read_imports};

pub fn run(dll_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    if dll_arg.is_empty() {
        return Err("Use `resx behavior <image>`".to_owned());
    }

    let dll_path = find_dll_path(dll_arg, cfg)?;
    let image = dll_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let raw = crate::core::input::read_image(&dll_path).map_err(|e| format!("read file: {}", e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let imports = read_imports(&pe, &raw);
    let headers = crate::analysis::headers::configured(cfg.argument_headers());
    let report = analyze_image_with_headers(&image, &pe, &raw, &imports, headers.as_deref());

    if cfg.json {
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&versioned_object("behavior", &report))
                .unwrap_or_default()
        )
        .ok();
        return Ok(());
    }

    writeln!(
        w,
        "{}",
        c.bold(&format!(
            "Behavior triage: {} ({} finding{})",
            report.image,
            report.finding_count,
            if report.finding_count == 1 { "" } else { "s" }
        ))
    )
    .ok();
    if !report.api_resolution.is_empty() {
        writeln!(
            w,
            "{} {}",
            c.bold("Dynamic API resolution:"),
            report.api_resolution
        )
        .ok();
    }
    for (rva, signature) in &report.api_signatures {
        writeln!(w, "  0x{rva:08X}  {}", signature.call).ok();
    }
    if report.findings.is_empty() {
        writeln!(w, "{}", c.dim("No static behavior signals found.")).ok();
        return Ok(());
    }

    render_findings(w, c, &report.findings, cfg.verbose);

    if !report.resolved_apis.is_empty() {
        writeln!(w).ok();
        writeln!(
            w,
            "{}",
            c.bold(&format!(
                "Dynamically resolved APIs ({}):",
                report.resolved_apis.len()
            ))
        )
        .ok();
        for resolved in &report.resolved_apis {
            let calls = match resolved.call_sites.len() {
                0 => String::new(),
                n => format!(", {n} call site{}", if n == 1 { "" } else { "s" }),
            };
            writeln!(
                w,
                "  0x{:08X}  {}  {}",
                resolved.site,
                c.cyan(&resolved.target()),
                c.dim(&format!("[{}{calls}]", resolved.describe()))
            )
            .ok();
        }
    }

    Ok(())
}

fn render_findings(
    w: &mut dyn Write,
    c: &Colors,
    findings: &[crate::analysis::behavior::BehaviorFinding],
    verbose: bool,
) {
    // Preserve first-seen order and keep distinct severities/details separate.
    let mut groups: Vec<Vec<&crate::analysis::behavior::BehaviorFinding>> = Vec::new();
    let mut positions = std::collections::HashMap::new();
    for finding in findings {
        let key = (
            &finding.category,
            &finding.rule,
            &finding.severity,
            &finding.confidence,
            &finding.detail,
            &finding.source,
        );
        let next = groups.len();
        let position = *positions.entry(key).or_insert(next);
        if position == groups.len() {
            groups.push(Vec::new());
        }
        groups[position].push(finding);
    }
    let mut collapsed = false;
    for group in groups {
        if !verbose && group.len() > 3 {
            collapsed = true;
            let finding = group[0];
            writeln!(
                w,
                "{} {} {} {}",
                severity_color(c, &finding.severity),
                c.bold(&finding.category),
                finding.rule,
                c.dim(&format!(
                    "({}; {} occurrences)",
                    finding.confidence,
                    group.len()
                ))
            )
            .ok();
            writeln!(w, "  {}", finding.detail).ok();
            let examples = group
                .iter()
                .take(3)
                .map(|f| f.rva.as_deref().unwrap_or("-"))
                .collect::<Vec<_>>()
                .join(", ");
            writeln!(w, "  Example RVAs: {examples} (+{} more)", group.len() - 3).ok();
            for item in finding.evidence.iter().take(4) {
                writeln!(w, "  {}", c.dim(item)).ok();
            }
        } else {
            for finding in group {
                let rva = finding.rva.as_deref().unwrap_or("-");
                writeln!(
                    w,
                    "{} {} {} {}",
                    severity_color(c, &finding.severity),
                    c.bold(&finding.category),
                    finding.rule,
                    c.dim(&format!("({} @ {})", finding.confidence, rva))
                )
                .ok();
                writeln!(w, "  {}", finding.detail).ok();
                let limit = if verbose { usize::MAX } else { 4 };
                for item in finding.evidence.iter().take(limit) {
                    writeln!(w, "  {}", c.dim(item)).ok();
                }
            }
        }
    }
    if collapsed {
        writeln!(w, "\nRepeated findings collapsed; use --verbose for every occurrence or --json for structured evidence.").ok();
    }
}

fn severity_color(c: &Colors, severity: &str) -> String {
    c.severity_tag(severity)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repetitive_findings_are_bounded_but_verbose_retains_all_evidence() {
        let findings: Vec<_> = (0..100)
            .map(|i| crate::analysis::behavior::BehaviorFinding {
                category: "anti-debug".into(),
                rule: "int3-breakpoint".into(),
                severity: "low".into(),
                confidence: "medium".into(),
                source: "instruction".into(),
                rva: Some(format!("0x{i:08X}")),
                detail: "INT3 present".into(),
                evidence: (0..6).map(|n| format!("evidence-{n}")).collect(),
            })
            .collect();
        let render = |findings: &[_], verbose| {
            let mut out = Vec::new();
            render_findings(&mut out, &Colors::new(false), findings, verbose);
            String::from_utf8(out).unwrap()
        };
        let compact = render(&findings, false);
        assert_eq!(compact.matches("int3-breakpoint").count(), 1);
        assert!(compact.contains("100 occurrences"));
        assert!(compact.contains("+97 more"));
        assert!(!compact.contains("0x00000063"));
        assert!(compact.contains("--verbose"));
        let full = render(&findings, true);
        assert_eq!(full.matches("int3-breakpoint").count(), 100);
        assert!(full.contains("0x00000063"));
        assert!(full.contains("evidence-5"));
        assert_eq!(
            render(&findings[..3], false)
                .matches("int3-breakpoint")
                .count(),
            3
        );
        let mut distinct = findings;
        distinct[99].severity = "high".into();
        let split = render(&distinct, false);
        assert_eq!(split.matches("int3-breakpoint").count(), 2);
        assert!(split.contains("99 occurrences"));
        assert!(split.contains("0x00000063"));
    }
}
