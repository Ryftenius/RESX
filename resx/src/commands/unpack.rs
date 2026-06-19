use std::io::Write;

use crate::analysis::unpack::{
    analyze_image, CodeWindow, ImportRebuildCandidate, OepCandidate, UnpackFinding, VmCandidate,
    VmSketch,
};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use crate::core::search::find_dll_path;
use crate::formats::pe::{parse_pe, read_imports};

pub fn run(dll_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    if dll_arg.is_empty() {
        return Err("Use `resx unpack <image>`".to_owned());
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
            serde_json::to_string_pretty(&versioned_object("unpack", &report)).unwrap_or_default()
        )
        .ok();
        return Ok(());
    }

    writeln!(w, "{}", c.bold(&format!("Unpack triage: {}", report.image))).ok();
    writeln!(w, "  {}", c.dim(&report.summary)).ok();
    writeln!(
        w,
        "  {}",
        c.dim("static analysis only; reports unpacking and VM-lifting leads, not a rebuilt binary")
    )
    .ok();

    print_findings(w, c, "Protector / packing hints", &report.protector_hints);
    print_oep(w, c, &report.oep_candidates);
    print_findings(w, c, "Import rebuild hints", &report.import_rebuild_hints);
    print_vm(w, c, &report.vm_candidates);
    print_layer2_windows(w, c, &report.layer2.oep_windows);
    print_import_plan(w, c, &report.layer2.import_plan);
    print_vm_sketches(w, c, &report.layer2.vm_sketches);

    if !report.next_steps.is_empty() {
        writeln!(w, "\n{}", c.bold("Next steps")).ok();
        for step in &report.next_steps {
            writeln!(w, "  {}", step).ok();
        }
    }

    Ok(())
}

fn print_findings(w: &mut dyn Write, c: &Colors, title: &str, findings: &[UnpackFinding]) {
    writeln!(w, "\n{}", c.bold(title)).ok();
    if findings.is_empty() {
        writeln!(w, "  {}", c.dim("none")).ok();
        return;
    }
    for finding in findings {
        writeln!(
            w,
            "  {} {} {}",
            confidence_color(c, &finding.confidence),
            c.bold(&finding.rule),
            finding.detail
        )
        .ok();
        for item in finding.evidence.iter().take(5) {
            writeln!(w, "    {}", c.dim(item)).ok();
        }
    }
}

fn print_oep(w: &mut dyn Write, c: &Colors, candidates: &[OepCandidate]) {
    writeln!(w, "\n{}", c.bold("OEP / handoff candidates")).ok();
    if candidates.is_empty() {
        writeln!(w, "  {}", c.dim("none")).ok();
        return;
    }
    for cand in candidates.iter().take(12) {
        writeln!(
            w,
            "  {} {} {}",
            confidence_color(c, &cand.confidence),
            c.bold(&cand.rva),
            cand.reason
        )
        .ok();
        for item in cand.evidence.iter().take(4) {
            writeln!(w, "    {}", c.dim(item)).ok();
        }
    }
}

fn print_vm(w: &mut dyn Write, c: &Colors, candidates: &[VmCandidate]) {
    writeln!(w, "\n{}", c.bold("VM lifting candidates")).ok();
    if candidates.is_empty() {
        writeln!(w, "  {}", c.dim("none")).ok();
        return;
    }
    for cand in candidates.iter().take(16) {
        writeln!(
            w,
            "  {} {} {} {}",
            confidence_color(c, &cand.confidence),
            c.bold(&cand.rva),
            cand.kind,
            cand.reason
        )
        .ok();
        for item in cand.evidence.iter().take(3) {
            writeln!(w, "    {}", c.dim(item)).ok();
        }
    }
}

fn print_layer2_windows(w: &mut dyn Write, c: &Colors, windows: &[CodeWindow]) {
    writeln!(w, "\n{}", c.bold("Layer 2: OEP windows")).ok();
    if windows.is_empty() {
        writeln!(w, "  {}", c.dim("none")).ok();
        return;
    }
    for window in windows.iter().take(4) {
        writeln!(
            w,
            "  {} {} bytes in {}",
            c.bold(&window.rva),
            window.instructions.len(),
            window.section
        )
        .ok();
        for line in window.instructions.iter().take(6) {
            writeln!(w, "    {}", line).ok();
        }
        if !window.control_flow.is_empty() {
            writeln!(
                w,
                "    {} {}",
                c.dim("control-flow:"),
                window
                    .control_flow
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(" | ")
            )
            .ok();
        }
    }
}

fn print_import_plan(w: &mut dyn Write, c: &Colors, plan: &[ImportRebuildCandidate]) {
    writeln!(w, "\n{}", c.bold("Layer 2: import rebuild plan")).ok();
    if plan.is_empty() {
        writeln!(w, "  {}", c.dim("none")).ok();
        return;
    }
    for item in plan.iter().take(12) {
        let name = match (item.dll.is_empty(), item.api.is_empty()) {
            (false, false) => format!("{}!{}", item.dll, item.api),
            (false, true) => item.dll.clone(),
            (true, false) => item.api.clone(),
            (true, true) => "-".to_owned(),
        };
        writeln!(
            w,
            "  {} {} {}",
            confidence_color(c, &item.confidence),
            c.bold(&item.source),
            name
        )
        .ok();
        for evidence in item.evidence.iter().take(2) {
            writeln!(w, "    {}", c.dim(evidence)).ok();
        }
    }
}

fn print_vm_sketches(w: &mut dyn Write, c: &Colors, sketches: &[VmSketch]) {
    writeln!(w, "\n{}", c.bold("Layer 2: VM sketches")).ok();
    if sketches.is_empty() {
        writeln!(w, "  {}", c.dim("none")).ok();
        return;
    }
    for sketch in sketches.iter().take(6) {
        writeln!(
            w,
            "  {} {} score {}",
            c.bold(&sketch.rva),
            sketch.kind,
            sketch.score
        )
        .ok();
        if !sketch.registers.is_empty() {
            writeln!(
                w,
                "    {} {}",
                c.dim("registers:"),
                sketch
                    .registers
                    .iter()
                    .take(8)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .ok();
        }
        if !sketch.mnemonics.is_empty() {
            writeln!(
                w,
                "    {} {}",
                c.dim("mnemonics:"),
                sketch
                    .mnemonics
                    .iter()
                    .take(10)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            )
            .ok();
        }
        for line in sketch.instructions.iter().take(4) {
            writeln!(w, "    {}", line).ok();
        }
    }
}

fn confidence_color(c: &Colors, confidence: &str) -> String {
    match confidence {
        "high" => c.b_red("[high]"),
        "medium" => c.b_yellow("[medium]"),
        "low" => c.dim("[low]"),
        _ => format!("[{}]", confidence),
    }
}
