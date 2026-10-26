use super::*;

pub(super) fn route(code: &IoctlCodeCandidate) -> &'static str {
    if code.evidence_status.starts_with("static-api-") {
        return "API call";
    }
    let external = code
        .request_channels
        .iter()
        .any(|s| s == "IRP_MJ_DEVICE_CONTROL" || s == "KMDF EvtIoDeviceControl");
    let internal = code
        .request_channels
        .iter()
        .any(|s| s == "IRP_MJ_INTERNAL_DEVICE_CONTROL" || s == "KMDF EvtIoInternalDeviceControl");
    match (external, internal) {
        (true, true) => "ext+int",
        (true, false) => "external",
        (false, true) => "internal",
        _ => "unknown",
    }
}

pub(super) fn render(w: &mut dyn Write, c: &Colors, report: &IoctlReport, verbose: bool) {
    let device_types: std::collections::BTreeSet<_> = report
        .codes
        .iter()
        .map(|code| {
            format!(
                "{} {}",
                code.device_type,
                code.device_type_name.trim_start_matches("FILE_DEVICE_")
            )
        })
        .collect();
    if !device_types.is_empty() {
        writeln!(
            w,
            "Device types: {}",
            device_types.into_iter().collect::<Vec<_>>().join(", ")
        )
        .ok();
    }
    writeln!(
        w,
        "Route: external = DeviceIoControl; internal = kernel-only device control."
    )
    .ok();
    if !report.devices.endpoints.is_empty() {
        writeln!(
            w,
            "Device IDs are static candidates, not proven per-code targets; '-' = unresolved."
        )
        .ok();
    }
    if !report.devices.endpoints.is_empty() {
        writeln!(w, "\n{}", c.bold("Device endpoints — static declarations")).ok();
        let rows: Vec<_> = report
            .devices
            .endpoints
            .iter()
            .map(|e| {
                vec![
                    e.id.clone(),
                    e.device_name
                        .clone()
                        .unwrap_or_else(|| "unnamed/unknown".into()),
                    if e.aliases.is_empty() {
                        "?".into()
                    } else {
                        e.aliases.join(", ")
                    },
                    match e.secure_open {
                        Some(true) => "yes",
                        Some(false) => "no",
                        None => "?",
                    }
                    .into(),
                    if e.driver_entry_object {
                        "entry object"
                    } else {
                        "unresolved"
                    }
                    .into(),
                    e.creation_rva.clone(),
                ]
            })
            .collect();
        crate::core::table::print(
            w,
            &[
                "ID",
                "NT device name",
                "Symbolic links",
                "Secure open",
                "Driver binding",
                "Create RVA",
            ],
            &rows,
            c,
        );
        let security: Vec<_> = report
            .devices
            .endpoints
            .iter()
            .map(|e| {
                vec![
                    e.id.clone(),
                    e.default_sddl.clone().unwrap_or_else(|| "unknown".into()),
                    e.security_source.clone(),
                ]
            })
            .collect();
        crate::core::table::print(
            w,
            &["ID", "Declared SDDL", "Source / limitation"],
            &security,
            c,
        );
    } else {
        writeln!(w, "Static device mapping: unresolved.").ok();
        if report.live_security.is_none() {
            writeln!(w, "Use --device-security PATH to inspect a live endpoint.").ok();
        }
    }
    if verbose && !report.devices.symbolic_links.is_empty() {
        let links: Vec<_> = report
            .devices
            .symbolic_links
            .iter()
            .map(|l| {
                vec![
                    l.alias.clone().unwrap_or_else(|| "?".into()),
                    l.target.clone().unwrap_or_else(|| "?".into()),
                    l.site_rva.clone(),
                ]
            })
            .collect();
        crate::core::table::print(w, &["Declared link", "Target", "Site RVA"], &links, c);
    }
    if let Some(live) = &report.live_security {
        render_live(w, c, live, verbose);
    }
    if verbose {
        let rows: Vec<_> = report
            .codes
            .iter()
            .map(|code| {
                vec![
                    code.code.clone(),
                    code.owner_rva.clone(),
                    code.site_rva.clone(),
                    code.handler_rva.clone().unwrap_or_else(|| "?".into()),
                    code.user_accessibility.clone(),
                ]
            })
            .collect();
        crate::core::table::print(
            w,
            &[
                "Code",
                "Dispatch root",
                "Code evidence RVA",
                "Table handler",
                "User reachability",
            ],
            &rows,
            c,
        );
    }
}

fn failure(code: u32) -> &'static str {
    match code {
        2 | 3 => "not found",
        5 => "access denied",
        50 => "not supported",
        _ => "failed",
    }
}

fn render_live(
    w: &mut dyn Write,
    c: &Colors,
    live: &crate::analysis::driver::devices::LiveSecurity,
    verbose: bool,
) {
    writeln!(
        w,
        "\n{}: {}",
        c.bold("Live device security"),
        live.requested_path
    )
    .ok();
    if let Some(sddl) = &live.sddl {
        writeln!(w, "  SDDL: {sddl}").ok();
    } else if let Some(error) = &live.error {
        if let Some(code) = error
            .strip_prefix("READ_CONTROL open failed: Win32 ")
            .and_then(|code| code.parse::<u32>().ok())
        {
            writeln!(w, "  SDDL: unavailable — {} (READ_CONTROL).", failure(code)).ok();
        } else {
            writeln!(w, "  SDDL: unavailable.").ok();
            if !verbose {
                writeln!(w, "  Diagnostic: {error}").ok();
            }
        }
    } else {
        writeln!(w, "  SDDL: unavailable.").ok();
    }
    if !live.token.is_empty() {
        let token = if live.token.starts_with("linked non-elevated") {
            "linked non-elevated token"
        } else {
            match live.token_elevated {
                Some(false) => "current non-elevated token",
                Some(true) => "current elevated token",
                None => "current token (elevation unknown)",
            }
        };
        let integrity = match live.token_integrity_rid {
            Some(0) => "untrusted",
            Some(0x1000) => "low",
            Some(0x2000) => "medium",
            Some(0x2100) => "medium-plus",
            Some(0x3000) => "high",
            Some(0x4000) => "system",
            _ => "unknown",
        };
        writeln!(
            w,
            "  User-access test token: {token}; {integrity} integrity."
        )
        .ok();
    }
    let probes: Vec<_> = live
        .user_open_probes
        .iter()
        .map(|p| {
            let access = match p.access {
                0 => "ANY",
                1 => "READ",
                2 => "WRITE",
                3 => "READ+WRITE",
                _ => "unknown",
            };
            let result = match (p.opened, p.dacl_allowed) {
                (Some(true), _) => "opened",
                (Some(false), _) => p.win32_error.map(failure).unwrap_or("open failed"),
                (None, Some(true)) => "DACL allows (open untested)",
                (None, Some(false)) => "DACL denies (open untested)",
                _ => "unknown",
            };
            format!("{access}: {result}")
        })
        .collect();
    writeln!(
        w,
        "  Access: {}.",
        if probes.is_empty() {
            "unknown (no usable probe result)".into()
        } else {
            probes.join("; ")
        }
    )
    .ok();
    for (label, value) in [
        ("Object", &live.object_name),
        ("DOS target", &live.dos_target),
    ] {
        if let Some(value) = value {
            if verbose || value != &live.requested_path {
                writeln!(w, "  {label}: {value}").ok();
            }
        }
    }
    if live.matched_endpoint_ids.is_empty() {
        writeln!(w, "  Image association: unverified.").ok();
    } else {
        writeln!(
            w,
            "  Static name matches: {} (image identity unverified).",
            live.matched_endpoint_ids.join(", ")
        )
        .ok();
    }
    writeln!(
        w,
        "  Open checks only; IOCTL execution is untested.{}",
        if verbose { "" } else { " Details: --verbose." }
    )
    .ok();
    if verbose {
        if !live.descriptor_source.is_empty() {
            writeln!(w, "  Descriptor source: {}", live.descriptor_source).ok();
        }
        if let Some(error) = &live.error {
            writeln!(w, "  Diagnostic: {error}").ok();
        }
        if let Some(rid) = live.token_integrity_rid {
            writeln!(w, "  Integrity RID: 0x{rid:X}").ok();
        }
        for probe in &live.user_open_probes {
            if let Some(error) = probe.win32_error {
                writeln!(w, "  Probe access={}: Win32 {error}", probe.access).ok();
            }
        }
        for note in &live.limitations {
            writeln!(w, "  - {note}").ok();
        }
    }
}
