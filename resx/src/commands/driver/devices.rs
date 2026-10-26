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
    writeln!(w,"Route: external = user DeviceIoControl channel; internal = kernel internal-device-control channel. Neither establishes a successful request.").ok();
    writeln!(w,"Device IDs are candidates sharing the recovered DRIVER_OBJECT, not proven per-code targets. '-' means unresolved.").ok();
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
        writeln!(w,"No device creation arguments recovered; effective SDDL and device routing remain unknown. Use --device-security PATH for an explicit live endpoint lookup.").ok();
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
        writeln!(
            w,
            "\n{}",
            c.bold("Live endpoint security and access evidence")
        )
        .ok();
        let rows = vec![
            vec!["Requested endpoint".into(), live.requested_path.clone()],
            vec![
                "Object name".into(),
                live.object_name.clone().unwrap_or_else(|| "unknown".into()),
            ],
            vec![
                "DOS mapping".into(),
                live.dos_target
                    .clone()
                    .unwrap_or_else(|| "not resolved/applicable".into()),
            ],
            vec![
                "Static name matches".into(),
                if live.matched_endpoint_ids.is_empty() {
                    "none; no association with this image established".into()
                } else {
                    live.matched_endpoint_ids.join(", ")
                },
            ],
            vec![
                "Token tested".into(),
                format!(
                    "{}; elevated={:?}; integrity RID={:?}",
                    live.token, live.token_elevated, live.token_integrity_rid
                ),
            ],
            vec![
                "SDDL (owner/group/DACL)".into(),
                live.sddl.clone().unwrap_or_else(|| "unknown".into()),
            ],
            vec!["Descriptor source".into(), live.descriptor_source.clone()],
        ];
        crate::core::table::print(w, &["Property", "Observed value"], &rows, c);
        let probes: Vec<_> = live
            .user_open_probes
            .iter()
            .map(|p| {
                vec![
                    match p.access {
                        0 => "ANY (no data right)",
                        1 => "READ",
                        2 => "WRITE",
                        3 => "READ+WRITE",
                        _ => "unknown",
                    }
                    .into(),
                    match (p.opened, p.dacl_allowed) {
                        (Some(true), _) => "opened",
                        (Some(false), _) => "open failed",
                        (None, Some(true)) => "DACL allows",
                        (None, Some(false)) => "DACL denies",
                        _ => "unknown",
                    }
                    .into(),
                    p.win32_error
                        .map(|e| e.to_string())
                        .unwrap_or_else(|| "-".into()),
                ]
            })
            .collect();
        crate::core::table::print(
            w,
            &[
                "IOCTL access-bit profile",
                "Non-elevated access evidence",
                "Win32 error",
            ],
            &probes,
            c,
        );
        if let Some(error) = &live.error {
            crate::core::table::print(w, &["Observation error"], &[vec![error.clone()]], c);
        }
        for note in &live.limitations {
            crate::core::table::print(w, &["Live evidence limit"], &[vec![note.clone()]], c);
        }
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
