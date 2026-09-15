use crate::core::{
    color::Colors, config::Config, hash::sha256, json::versioned_object, search::find_dll_path,
};
use crate::formats::pe::{parse_pe, PeAnomaly};
use serde_json::{json, Value};
use std::io::Write;

const REPORT_LIMIT: usize = 256;

fn findings(anomalies: &[PeAnomaly]) -> Vec<Value> {
    anomalies
        .iter()
        .take(REPORT_LIMIT)
        .map(|anomaly| {
            json!({
                "severity": anomaly.severity,
                "kind": anomaly.kind,
                "detail": anomaly.detail,
            })
        })
        .collect()
}

pub fn run(
    image: &str,
    cfg: &Config,
    output: &mut dyn Write,
    colors: &Colors,
) -> Result<(), String> {
    let path = find_dll_path(image, cfg)?;
    let raw = crate::core::input::read_image(&path).map_err(|error| error.to_string())?;
    let pe = parse_pe(&raw).map_err(|error| error.0)?;
    let reported = findings(&pe.anomalies);
    let report = json!({
        "image": path,
        "image_sha256": sha256(&raw)?,
        "file_bytes": raw.len(),
        "architecture": format!("x{}", pe.arch),
        "header_corrupt": pe.header_corruption_detected(),
        "finding_count": pe.anomalies.len(),
        "report_limit": REPORT_LIMIT,
        "report_truncated": pe.anomalies.len() > reported.len(),
        "findings": reported,
    });

    if cfg.json {
        serde_json::to_writer_pretty(&mut *output, &versioned_object("pechk", &report))
            .map_err(|error| error.to_string())?;
        writeln!(output).map_err(|error| error.to_string())?;
        return Ok(());
    }

    writeln!(output, "{}", colors.heading("PE validation")).map_err(|error| error.to_string())?;
    writeln!(
        output,
        "  Image: {}\n  SHA-256: {}\n  Findings: {}",
        path.display(),
        report["image_sha256"].as_str().unwrap_or("unavailable"),
        pe.anomalies.len()
    )
    .map_err(|error| error.to_string())?;
    if pe.anomalies.is_empty() {
        writeln!(output, "  {} no structural PE anomalies", colors.ok("✓"))
            .map_err(|error| error.to_string())?;
    }
    for anomaly in pe.anomalies.iter().take(REPORT_LIMIT) {
        let marker = match anomaly.severity.to_ascii_lowercase().as_str() {
            "error" | "critical" => colors.b_red("ERROR"),
            "warning" | "warn" => colors.b_yellow("WARN"),
            _ => colors.b_cyan("INFO"),
        };
        writeln!(
            output,
            "  [{}] {}: {}",
            marker, anomaly.kind, anomaly.detail
        )
        .map_err(|error| error.to_string())?;
    }
    if pe.anomalies.len() > REPORT_LIMIT {
        writeln!(
            output,
            "  ... {} additional finding(s); use --json for the bounded structured report",
            pe.anomalies.len() - REPORT_LIMIT
        )
        .map_err(|error| error.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{findings, REPORT_LIMIT};
    use crate::formats::pe::PeAnomaly;

    #[test]
    fn structured_findings_are_bounded() {
        let anomalies = (0..REPORT_LIMIT + 10)
            .map(|index| PeAnomaly {
                severity: "warning".into(),
                kind: format!("kind-{index}"),
                detail: "bounded".into(),
            })
            .collect::<Vec<_>>();
        assert_eq!(findings(&anomalies).len(), REPORT_LIMIT);
    }
}
