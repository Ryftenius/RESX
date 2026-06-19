use std::io::Write;

use crate::analysis::behavior::analyze_image;
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
    let raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let imports = read_imports(&pe, &raw);
    let report = analyze_image(&image, &pe, &raw, &imports);

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
    if report.findings.is_empty() {
        writeln!(w, "{}", c.dim("No static behavior signals found.")).ok();
        return Ok(());
    }

    for finding in &report.findings {
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
        for item in finding.evidence.iter().take(4) {
            writeln!(w, "  {}", c.dim(item)).ok();
        }
    }

    Ok(())
}

fn severity_color(c: &Colors, severity: &str) -> String {
    match severity {
        "high" => c.b_red("[high]"),
        "medium" => c.b_yellow("[medium]"),
        "low" => c.dim("[low]"),
        _ => format!("[{}]", severity),
    }
}
