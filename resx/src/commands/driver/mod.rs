use crate::analysis::driver::{
    DriverReport, IoctlCallEvidence, IoctlReport, IoctlValue, MajorFunctionAssignment,
};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use std::io::Write;

pub fn run(
    cfg: &Config,
    ioctls_only: bool,
    output: &mut dyn Write,
    colors: &Colors,
) -> Result<(), String> {
    let path = crate::core::search::find_dll_path(&cfg.dll, cfg)?;
    let raw = crate::core::input::read_image(&path).map_err(|error| error.to_string())?;
    let pe = crate::formats::pe::parse_pe(&raw).map_err(|error| error.to_string())?;
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let imports = crate::formats::pe::read_imports(&pe, &raw);
    let report = crate::analysis::driver::analyze_driver(&name, &pe, &raw, &imports);

    if cfg.json {
        let value = if ioctls_only {
            versioned_object("ioctl", &report.ioctl)
        } else {
            versioned_object("driver", &report)
        };
        writeln!(
            output,
            "{}",
            serde_json::to_string_pretty(&value).map_err(|e| e.to_string())?
        )
        .map_err(|e| e.to_string())?;
    } else if ioctls_only {
        render_ioctl(output, colors, &report.ioctl, cfg.verbose);
    } else {
        render_driver(output, colors, &report, cfg.verbose);
    }
    Ok(())
}

fn render_driver(w: &mut dyn Write, c: &Colors, report: &DriverReport, verbose: bool) {
    writeln!(w, "{}", c.bold("Driver analysis")).ok();
    crate::core::table::print(
        w,
        &["Field", "Value"],
        &[
            vec!["Image".into(), report.image.clone()],
            vec!["Architecture".into(), format!("{}-bit", report.arch)],
            vec!["Classification".into(), report.classification.clone()],
            vec![
                "Hypervisor".into(),
                report.hypervisor.classification.clone(),
            ],
            vec![
                "MajorFunction entries".into(),
                report.major_functions.len().to_string(),
            ],
            vec!["IOCTL codes".into(), report.ioctl.codes.len().to_string()],
            vec![
                "Request call sites".into(),
                report.ioctl.call_sites.len().to_string(),
            ],
        ],
        c,
    );

    if !report.hypervisor.instruction_evidence.is_empty()
        || !report.hypervisor.register_evidence.is_empty()
        || !report.hypervisor.interface_imports.is_empty()
    {
        writeln!(w, "\n{}", c.bold("Hypervisor capability evidence")).ok();
        let evidence_rows: Vec<_> = report
            .hypervisor
            .instruction_evidence
            .iter()
            .chain(&report.hypervisor.register_evidence)
            .flat_map(|item| {
                item.sites.iter().map(move |site| {
                    vec![
                        item.vendor.clone(),
                        item.capability.clone(),
                        site.rva.clone(),
                        site.owner.clone(),
                        site.instruction.clone(),
                    ]
                })
            })
            .collect();
        if !evidence_rows.is_empty() {
            crate::core::table::print(
                w,
                &["Vendor", "Capability", "RVA", "Owner", "Instruction"],
                &evidence_rows,
                c,
            );
        }
        let import_rows: Vec<_> = report
            .hypervisor
            .interface_imports
            .iter()
            .map(|item| {
                vec![
                    item.capability.clone(),
                    item.api.clone(),
                    item.slot_rva.clone(),
                ]
            })
            .collect();
        if !import_rows.is_empty() {
            writeln!(w, "\n{}", c.bold("Hypervisor interfaces")).ok();
            crate::core::table::print(
                w,
                &["Capability", "Imported API", "IAT RVA"],
                &import_rows,
                c,
            );
        }
    }

    if !report.capabilities.is_empty() {
        writeln!(w, "\n{}", c.bold("Driver capabilities")).ok();
        let rows: Vec<_> = report
            .capabilities
            .iter()
            .flat_map(|item| {
                if item.references.is_empty() {
                    vec![vec![
                        item.capability.clone(),
                        item.confidence.clone(),
                        item.apis.join(", "),
                    ]]
                } else {
                    item.references
                        .iter()
                        .map(|reference| {
                            vec![
                                item.capability.clone(),
                                item.confidence.clone(),
                                format!(
                                    "{} {} {}",
                                    reference.rva, reference.owner, reference.instruction
                                ),
                            ]
                        })
                        .collect()
                }
            })
            .collect();
        crate::core::table::print(w, &["Capability", "Evidence basis", "References"], &rows, c);
    }

    if !report.major_functions.is_empty() {
        writeln!(w, "\n{}", c.bold("MajorFunction table")).ok();
        render_major_functions(w, c, &report.major_functions);
    }
    if !report.ioctl.codes.is_empty() || !report.ioctl.call_sites.is_empty() {
        writeln!(w).ok();
        render_ioctl(w, c, &report.ioctl, verbose);
    }

    let mut api_rows = Vec::new();
    for hit in report
        .device_apis
        .iter()
        .chain(&report.symbolic_link_apis)
        .chain(&report.registry_apis)
        .chain(&report.callback_apis)
    {
        api_rows.push(vec![
            hit.kind.clone(),
            hit.dll.clone(),
            hit.name.clone(),
            hit.slot_rva.clone(),
        ]);
    }
    if !api_rows.is_empty() {
        writeln!(w, "\n{}", c.bold("Driver APIs")).ok();
        crate::core::table::print(w, &["Kind", "DLL", "API", "IAT RVA"], &api_rows, c);
    }
    let _ = verbose;
}

fn render_major_functions(w: &mut dyn Write, c: &Colors, entries: &[MajorFunctionAssignment]) {
    let rows: Vec<_> = entries
        .iter()
        .map(|entry| {
            vec![
                entry.major_index.to_string(),
                entry.major_name.clone(),
                entry.site_rva.clone(),
                entry.target_rva.clone(),
            ]
        })
        .collect();
    crate::core::table::print(
        w,
        &["Index", "Major function", "Store RVA", "Target RVA"],
        &rows,
        c,
    );
}

pub fn render_flow_contracts(
    w: &mut dyn Write,
    c: &Colors,
    report: &DriverReport,
    max_entries: usize,
) {
    if !report.major_functions.is_empty() {
        writeln!(w, "\n{}", c.bold("Recovered driver dispatch contracts")).ok();
        let rows: Vec<_> = report
            .major_functions
            .iter()
            .take(max_entries)
            .map(|entry| {
                vec![
                    entry.major_name.clone(),
                    entry.site_rva.clone(),
                    entry.target_rva.clone(),
                ]
            })
            .collect();
        crate::core::table::print(w, &["Major function", "Store RVA", "Target RVA"], &rows, c);
    }
    if !report.ioctl.codes.is_empty() {
        let rows: Vec<_> = report
            .ioctl
            .codes
            .iter()
            .take(max_entries)
            .map(|code| {
                vec![
                    code.code.clone(),
                    code.function.clone(),
                    code.site_rva.clone(),
                ]
            })
            .collect();
        writeln!(w, "\n{}", c.bold("Recovered IOCTL contracts")).ok();
        crate::core::table::print(w, &["Code", "Function", "Evidence RVA"], &rows, c);
    }
}

fn render_ioctl(w: &mut dyn Write, c: &Colors, report: &IoctlReport, verbose: bool) {
    writeln!(w, "{}", c.bold("IOCTL and NDIS recovery")).ok();
    writeln!(w, "{}  {}", c.dim("Image:"), report.image).ok();
    writeln!(w, "{}  {}", c.dim("Result:"), report.summary).ok();

    let rows: Vec<_> = report
        .codes
        .iter()
        .map(|code| {
            let numeric = u32::from_str_radix(code.code.trim_start_matches("0x"), 16).ok();
            let call = numeric.and_then(|value| {
                report
                    .call_sites
                    .iter()
                    .find(|call| call.ioctl_code == Some(value))
            });
            vec![
                code.code.clone(),
                code.function.clone(),
                short_access(&code.access).into(),
                short_method(&code.method).into(),
                call.map(|call| argument(call, "input_length"))
                    .unwrap_or_else(|| "?".into()),
                call.map(|call| argument(call, "output_length"))
                    .unwrap_or_else(|| "?".into()),
                code.site_rva.clone(),
            ]
        })
        .collect();
    if !rows.is_empty() {
        writeln!(w, "\n{}", c.bold("Decoded IOCTL codes")).ok();
        crate::core::table::print(
            w,
            &[
                "Code", "Function", "Access", "Method", "Input", "Output", "Site RVA",
            ],
            &rows,
            c,
        );
    }

    let ndis_rows: Vec<_> = report
        .call_sites
        .iter()
        .filter_map(|call| {
            let request = call.ndis_request.as_ref()?;
            Some(vec![
                call.api.clone(),
                format!("0x{:08X}", request.oid?),
                request.operation.into(),
                request.revision.to_string(),
                request.declared_size.to_string(),
                argument(call, "oid_request"),
                format!("0x{:08X}", call.site_rva),
            ])
        })
        .collect();
    if !ndis_rows.is_empty() {
        writeln!(w, "\n{}", c.bold("Validated NDIS OID requests")).ok();
        crate::core::table::print(
            w,
            &[
                "API",
                "OID",
                "Operation",
                "Rev",
                "Size",
                "Request",
                "Site RVA",
            ],
            &ndis_rows,
            c,
        );
    }

    let malformed_ndis = report
        .call_sites
        .iter()
        .filter(|call| call.category == "ndis" && call.ndis_request.is_none())
        .count();
    if malformed_ndis != 0 {
        writeln!(
            w,
            "\nRejected {} NDIS call site{} with an unsupported or incomplete request layout.",
            malformed_ndis,
            if malformed_ndis == 1 { "" } else { "s" }
        )
        .ok();
    }

    if !report.call_sites.is_empty() {
        writeln!(w, "\n{}", c.bold("Recovered call arguments")).ok();
        render_call_arguments(w, c, &report.call_sites, verbose);
    }

    let _ = verbose;
}

fn render_call_arguments(
    w: &mut dyn Write,
    c: &Colors,
    calls: &[IoctlCallEvidence],
    verbose: bool,
) {
    for (index, call) in calls.iter().enumerate() {
        if index != 0 {
            writeln!(w).ok();
        }
        let request = call
            .ioctl_code
            .map(|code| format!("IOCTL 0x{code:08X}"))
            .or_else(|| call.ndis_oid.map(|oid| format!("OID 0x{oid:08X}")))
            .unwrap_or_else(|| "request layout unresolved".into());
        writeln!(
            w,
            "{}  {}  {}",
            c.bold(&call.owner_name),
            c.dim("->"),
            c.bold(&call.api),
        )
        .ok();
        writeln!(
            w,
            "{}  {}",
            c.dim(&format!("call RVA 0x{:08X}", call.site_rva)),
            request
        )
        .ok();
        writeln!(
            w,
            "{}",
            call.reconstructed_call
                .lines()
                .map(|line| format!("  {line}"))
                .collect::<Vec<_>>()
                .join("\n")
        )
        .ok();

        if call.category == "ioctl" {
            let rows = vec![
                vec!["Handle".into(), argument(call, "handle")],
                vec![
                    "Input".into(),
                    buffer_argument(call, "input_buffer", "input_length"),
                ],
                vec![
                    "Output".into(),
                    buffer_argument(call, "output_buffer", "output_length"),
                ],
                vec!["Bytes returned".into(), argument(call, "bytes_returned")],
                vec!["Overlapped".into(), argument(call, "overlapped")],
            ];
            crate::core::table::print(w, &["Argument", "Recovered value"], &rows, c);
        } else {
            let mut rows: Vec<Vec<String>> = call
                .arguments
                .iter()
                .map(|argument| vec![argument.name.clone(), value(&argument.value)])
                .collect();
            if let Some(request) = &call.ndis_request {
                rows.extend(
                    request
                        .fields
                        .iter()
                        .map(|field| vec![field.name.clone(), value(&field.value)]),
                );
            }
            crate::core::table::print(w, &["Argument", "Recovered value"], &rows, c);
        }

        for buffer in ["input", "output"] {
            let field_rows: Vec<_> = call
                .buffer_fields
                .iter()
                .filter(|field| field.buffer == buffer)
                .map(|field| {
                    vec![
                        format!("0x{:X}", field.offset),
                        c_integer_type(field.width).into(),
                        value(&field.value),
                    ]
                })
                .collect();
            if !field_rows.is_empty() {
                writeln!(w, "{}", c.bold(&format!("Recovered {buffer} fields"))).ok();
                crate::core::table::print(w, &["Offset", "Type", "Value"], &field_rows, c);
            }
        }

        if verbose {
            writeln!(w, "  {}", c.dim(&call.status)).ok();
            if let Some(evidence) = &call.oid_evidence {
                writeln!(w, "  {}", c.dim(evidence)).ok();
            }
        }
    }
}

fn c_integer_type(width: usize) -> &'static str {
    match width {
        1 => "uint8_t",
        2 => "uint16_t",
        4 => "uint32_t",
        8 => "uint64_t",
        _ => "bytes",
    }
}

fn buffer_argument(call: &IoctlCallEvidence, buffer: &str, length: &str) -> String {
    format!(
        "{} ({} bytes)",
        argument(call, buffer),
        argument(call, length)
    )
}

fn short_access(access: &str) -> &str {
    match access {
        "FILE_ANY_ACCESS" => "Any",
        "FILE_READ_ACCESS" => "Read",
        "FILE_WRITE_ACCESS" => "Write",
        "FILE_READ_WRITE_ACCESS" => "Read+Write",
        _ => access,
    }
}

fn short_method(method: &str) -> &str {
    method.strip_prefix("METHOD_").unwrap_or(method)
}

fn argument(call: &IoctlCallEvidence, name: &str) -> String {
    call.arguments
        .iter()
        .find(|argument| argument.name == name)
        .map(|argument| value(&argument.value))
        .unwrap_or_else(|| "?".into())
}

fn value(value: &IoctlValue) -> String {
    match value {
        IoctlValue::Unknown => "?".into(),
        IoctlValue::FunctionArgument { index, .. } => format!("arg{index}"),
        IoctlValue::Symbolic { expression, .. } => expression.clone(),
        IoctlValue::Constant { value, .. } => value.to_string(),
        IoctlValue::ImageAddress { rva, .. } => format!("image+0x{rva:X}"),
        IoctlValue::StackAddress { offset, .. } => frame_offset(*offset),
        IoctlValue::ImageMemory { rva, .. } => format!("[image+0x{rva:X}]"),
        IoctlValue::Import { dll, name } => format!("{dll}!{name}"),
        IoctlValue::ApiResult { api, path, .. } => path
            .as_ref()
            .map(|path| format!("{api}({path})"))
            .unwrap_or_else(|| format!("{api} result")),
        IoctlValue::ApiOutput { api, argument, .. } => format!("{api}.{argument}"),
    }
}

fn frame_offset(offset: i64) -> String {
    if offset < 0 {
        format!("frame[-0x{:X}]", offset.unsigned_abs())
    } else {
        format!("frame[+0x{offset:X}]")
    }
}
