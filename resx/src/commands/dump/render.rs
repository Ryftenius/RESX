//! Render completed reports. No sessions, image bytes, providers or analysis calls.
use super::*;
use crate::analysis::inspection::FunctionReport;

pub(super) struct FunctionView<'a> {
    pub report: FunctionReport<'a>,
    pub pe: &'a PeFile,
    pub dll_name: String,
    pub dll_path_str: String,
    pub resolved_name: String,
    pub target_rva: u32,
    pub image_base: u64,
    pub arch_str: String,
    pub rebase: Option<u64>,
    pub startup_routines: &'a [PeStartupRoutine],
    pub yara_matches: Vec<crate::analysis::yara::YaraMatch>,
    pub function_discovery: Option<crate::analysis::discovery::FunctionDiscoveryReport>,
    pub pdb_loaded: bool,
    pub pdb_count: usize,
    pub bytes_read: usize,
    pub export_count: usize,
    pub import_count: usize,
    pub followed_desc: String,
    pub import_slot_target: Option<(String, String)>,
    pub func_size_bytes: usize,
    pub recovered_switch: Option<RecoveredSwitchDispatch>,
    pub switch_semantics: Option<SwitchSemanticInfo>,
    pub recovered_cfg_edges: Vec<RecoveredIndirectEdge>,
    pub hook_indicators: Vec<String>,
    pub xrefs: Vec<String>,
    pub edr_result: Option<EdrCheckResult>,
    pub call_tree: Option<super::callmap::ApiCallTree>,
    pub api_call_tree: String,
    pub telemetry: Option<super::callmap::telemetry::TelemetryReport>,
    pub current_syscall: Option<super::callmap::SyscallCallDetails>,
    pub call_syscalls: Vec<Option<super::callmap::SyscallCallDetails>>,
    pub cfg_blocks: Vec<crate::analysis::cfgview::BasicBlock>,
}

pub(super) fn render_text(
    view: FunctionView<'_>,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    let FunctionView {
        report,
        dll_name,
        resolved_name,
        target_rva,
        image_base,
        rebase,
        yara_matches,
        pdb_count,
        bytes_read,
        export_count,
        import_count,
        func_size_bytes,
        recovered_switch,
        switch_semantics,
        recovered_cfg_edges,
        hook_indicators,
        xrefs,
        edr_result,
        call_tree,
        telemetry,
        cfg_blocks,
        ..
    } = view;
    let FunctionReport {
        instructions: insns,
        strings: str_refs,
        signature,
        decode_conflicts,
        intelli: intelli_findings,
        recomp: recomp_str,
        flow_contracts,
        ..
    } = report;
    let signature = signature.expect("dump requests a signature");
    let decode_conflicts = decode_conflicts.expect("dump requests decode conflicts");
    let compact_calls = cfg.no_disassembly && cfg.funcs_depth > 0 && !cfg.verbose;
    let want_hookchk = cfg.hookchk || cfg.edrchk;
    let want_intelli = cfg.intelli;
    let want_cfg = cfg.cfg_view.eq_ignore_ascii_case("text");
    writeln!(w).ok();
    let mut title = format!("{}!{}  [RVA 0x{:08X}", dll_name, resolved_name, target_rva);
    if let Some(base) = rebase {
        title.push_str(&format!(", REBASE 0x{:X}", base + target_rva as u64));
    } else {
        title.push_str(&format!(", VA 0x{:X}", image_base + target_rva as u64));
    }
    title.push(']');
    writeln!(w, "{}", c.bold(&c.b_yellow(&title))).ok();
    if !compact_calls {
        if let Some(base) = rebase {
            writeln!(
                w,
                "{}",
                c.dim(&format!(
                    "  Base0/RVA: 0x{:08X}  |  PE-VA: 0x{:X}  |  Rebased-VA: 0x{:X}",
                    target_rva,
                    image_base + target_rva as u64,
                    base + target_rva as u64
                ))
            )
            .ok();
        } else {
            writeln!(
                w,
                "{}",
                c.dim(&format!(
                    "  Base0/RVA: 0x{:08X}  |  VA: 0x{:X}",
                    target_rva,
                    image_base + target_rva as u64
                ))
            )
            .ok();
        }
        writeln!(
            w,
            "  {}",
            c.b_blue(&format!(
                "Signature [{}]: {}",
                signature.source, signature.prototype
            ))
        )
        .ok();
    }
    if cfg.verbose && signature.source != "pdb" {
        writeln!(
            w,
            "  {}",
            c.dim(&format!(
                "{}; tentative; visited={} truncated={} unresolved-flow={}",
                signature.calling_convention,
                signature.instructions_visited,
                signature.analysis_truncated,
                signature.unresolved_flow
            ))
        )
        .ok();
    }
    if cfg.verbose {
        for param in &signature.parameters {
            writeln!(
                w,
                "  {}",
                c.dim(&format!(
                    "param_{} {}: {} read={} write={} evidence={:X?}",
                    param.index + 1,
                    param.location,
                    param.inferred_type,
                    param.pointer_read,
                    param.pointer_write,
                    param.evidence_rvas
                ))
            )
            .ok();
        }
    }
    if cfg.verbose && !decode_conflicts.findings.is_empty() {
        writeln!(
            w,
            "  {}",
            c.b_yellow(&format!(
                "Overlapping decode streams: {} finding(s), {} shown",
                decode_conflicts.findings.len(),
                decode_conflicts.findings.len().min(16)
            ))
        )
        .ok();
    }
    for conflict in decode_conflicts
        .findings
        .iter()
        .take(if cfg.verbose { 16 } else { 0 })
    {
        writeln!(
            w,
            "  {}",
            c.b_yellow(&format!(
                "[INFO] {}: stream 0x{:08x} enters 0x{:08x} inside stream instruction 0x{:08x}",
                conflict.kind,
                conflict.source_rva,
                conflict.target_rva,
                conflict.covering_instruction_rva
            ))
        )
        .ok();
        writeln!(
            w,
            "    {} | {} | alternate: {}",
            conflict.covering_bytes, conflict.covering_text, conflict.alternative_text
        )
        .ok();
    }
    if cfg.verbose && decode_conflicts.analysis_truncated {
        writeln!(
            w,
            "  {}",
            c.b_yellow("[WARN] overlapping-stream analysis/report budget reached")
        )
        .ok();
    }
    if !cfg.no_disassembly {
        print_insns(w, &insns, cfg, c);
    }
    if cfg.verbose {
        writeln!(
            w,
            "{}",
            c.info(&format!(
                "~{} instructions, ~{} bytes",
                insns.len(),
                func_size_bytes
            ))
        )
        .ok();
    }

    if let Some(dispatch) = recovered_switch.as_ref() {
        print_switch_map(w, dispatch, switch_semantics.as_ref(), c);
    }
    if let Some(edr) = &edr_result {
        print_edr_report(w, edr, c);
    }
    if want_hookchk {
        writeln!(w).ok();
        writeln!(w, "{}", c.bold(&c.b_mag("Hook Indicators:"))).ok();
        if hook_indicators.is_empty() {
            writeln!(w, "{}", c.dim("  (none detected)")).ok();
        } else {
            for finding in &hook_indicators {
                writeln!(w, "  {}", c.warn(finding)).ok();
            }
        }
    }
    if cfg.show_xrefs {
        writeln!(w, "{}", c.bold("\nCross References:")).ok();
        if xrefs.is_empty() {
            writeln!(w, "{}", c.dim("  (none)")).ok();
        }
        for r in &xrefs {
            writeln!(w, "  {}", c.cyan(r)).ok();
        }
    }
    if cfg.show_strings {
        writeln!(w, "{}", c.bold("\nString References:")).ok();
        if str_refs.is_empty() {
            writeln!(w, "{}", c.dim("  (none)")).ok();
        }
        for r in &str_refs {
            writeln!(w, "  {}", c.green(r)).ok();
        }
    }
    if cfg.funcs_depth > 0 {
        if let Some(tree) = &call_tree {
            print_api_calls(w, tree, &resolved_name, c, cfg);
        }
        if let Some(driver_report) = &flow_contracts {
            super::super::driver::render_flow_contracts(w, c, driver_report, cfg.max_subcalls);
        }
    }
    if let Some(report) = &telemetry {
        super::callmap::telemetry::print_report(w, report, c, cfg.verbose);
    }
    if want_intelli {
        print_intelli_findings(w, &intelli_findings, c);
    }
    if cfg.recomp {
        writeln!(w).ok();
        print_c_recomp(w, &recomp_str, c);
    }
    if want_cfg {
        writeln!(w, "\n{}", c.bold(&c.b_blue("Control Flow Graph:"))).ok();
        let colored = crate::presentation::cfg::render_blocks_colored(&cfg_blocks, c);
        write!(w, "{}", colored).ok();
        if !colored.ends_with('\n') {
            writeln!(w).ok();
        }
    }
    if cfg.verbose {
        let disassembled_bytes: usize = insns.iter().map(|i| i.bytes.len()).sum();
        writeln!(w).ok();
        writeln!(w, "{}", c.bold(&c.b_blue("Extension:"))).ok();
        writeln!(w, "  {:<20} {}", c.bold("FilesRead"), 1).ok();
        writeln!(w, "  {:<20} {}", c.bold("BytesRead"), bytes_read).ok();
        writeln!(
            w,
            "  {:<20} {}",
            c.bold("BytesDisassembled"),
            disassembled_bytes
        )
        .ok();
        writeln!(w, "  {:<20} {}", c.bold("InstructionsDecoded"), insns.len()).ok();
        writeln!(w, "  {:<20} {}", c.bold("ExportsScanned"), export_count).ok();
        writeln!(w, "  {:<20} {}", c.bold("ImportsScanned"), import_count).ok();
        writeln!(w, "  {:<20} {}", c.bold("PdbSymbolsLoaded"), pdb_count).ok();
        if !cfg.yara.is_empty() {
            writeln!(w, "  {:<20} {}", c.bold("YaraRules"), cfg.yara.len()).ok();
            writeln!(w, "  {:<20} {}", c.bold("YaraMatches"), yara_matches.len()).ok();
        }
        if cfg.show_xrefs {
            writeln!(w, "  {:<20} {}", c.bold("CrossReferences"), xrefs.len()).ok();
        }
        if cfg.show_strings {
            writeln!(w, "  {:<20} {}", c.bold("StringRefs"), str_refs.len()).ok();
        }
        if want_intelli {
            writeln!(
                w,
                "  {:<20} {}",
                c.bold("IntelliFindings"),
                intelli_findings.len()
            )
            .ok();
        }
        if want_cfg {
            writeln!(
                w,
                "  {:<20} {}",
                c.bold("RecoveredCfgEdges"),
                recovered_cfg_edges.len()
            )
            .ok();
        }
    }
    Ok(())
}

/// Materialize the owning JSON model before serialization, ending all session
/// borrows so the command can release its analysis cache at this boundary.
pub(super) fn into_json(view: FunctionView<'_>, cfg: &Config) -> FuncResult {
    let FunctionView {
        report,
        pe,
        dll_name,
        dll_path_str,
        resolved_name,
        target_rva,
        image_base,
        arch_str,
        rebase,
        startup_routines,
        yara_matches,
        function_discovery,
        pdb_loaded,
        pdb_count,
        followed_desc,
        import_slot_target,
        func_size_bytes,
        hook_indicators,
        xrefs,
        edr_result,
        call_tree,
        api_call_tree,
        telemetry,
        current_syscall,
        call_syscalls,
        cfg_blocks,
        ..
    } = view;
    let FunctionReport {
        instructions: insns,
        calls: api_calls,
        arguments: signatures,
        strings: str_refs,
        data: data_summary,
        signature,
        decode_conflicts,
        typed_ir: typed_ir_summary,
        recursive_cfg,
        indirect_flow,
        intelli: intelli_findings,
        recomp: recomp_str,
        ..
    } = report;
    let want_cfg = cfg.cfg_view.eq_ignore_ascii_case("text");
    FuncResult {
        dll: dll_name,
        dll_path: dll_path_str,
        function: resolved_name,
        rva: format!("0x{:08X}", target_rva),
        va: format!("0x{:016X}", image_base + target_rva as u64),
        rebased_va: rebase
            .map(|base| format!("0x{:016X}", base + target_rva as u64))
            .unwrap_or_default(),
        image_base: format!("0x{:016X}", image_base),
        arch: arch_str,
        entry_point: format!("0x{:08X}", pe.entry_point),
        size_of_image: format!("0x{:08X}", pe.size_of_image),
        size_of_headers: format!("0x{:08X}", pe.size_of_headers),
        section_alignment: format!("0x{:08X}", pe.section_alignment),
        file_alignment: format!("0x{:08X}", pe.file_alignment),
        checksum: format!("0x{:08X}", pe.checksum),
        subsystem: format!("0x{:04X}", pe.subsystem),
        dll_characteristics: format!("0x{:04X}", pe.dll_characteristics),
        header_corrupt: pe.header_corruption_detected(),
        pe_anomalies: pe.anomalies.iter().map(to_anomaly_json).collect(),
        startup_routines: startup_routines.iter().map(to_startup_json).collect(),
        sections: pe.sections.iter().map(to_section_json).collect(),
        yara_matches: yara_matches.iter().map(to_yara_json).collect(),
        size_bytes: func_size_bytes,
        insn_count: insns.len(),
        pdb_loaded: pdb_loaded || pdb_count > 0,
        followed_jmp: followed_desc,
        is_import_slot: import_slot_target.is_some(),
        import_target_dll: import_slot_target
            .as_ref()
            .map(|(dll, _)| dll.clone())
            .unwrap_or_default(),
        import_target_name: import_slot_target
            .as_ref()
            .map(|(_, name)| name.clone())
            .unwrap_or_default(),
        instructions: insns
            .iter()
            .map(|i| InsnJson {
                block_start: format!("0x{:08x}", i.block_start),
                rva: format!("0x{:08x}", i.rva),
                va: format!("0x{:016x}", i.va),
                rebased_va: rebase
                    .map(|base| format!("0x{:016x}", base + i.rva as u64))
                    .unwrap_or_default(),
                bytes: i
                    .bytes
                    .iter()
                    .map(|b| format!("{:02x}", b))
                    .collect::<Vec<_>>()
                    .join(" "),
                text: i.text.clone(),
                comment: i.comment.clone(),
            })
            .collect(),
        xrefs,
        strings: str_refs,
        data: data_summary.map(to_data_summary_json),
        function_discovery,
        recursive_cfg,
        typed_ir: typed_ir_summary,
        signature,
        decode_conflicts,
        indirect_flow,
        intelli_findings,
        recomp: recomp_str,
        cfg: if want_cfg {
            crate::presentation::cfg::render_blocks_text(&cfg_blocks)
        } else {
            String::new()
        },
        hook_indicators,
        edrchk: edr_result.as_ref().map(to_edr_json),
        api_calls: api_calls
            .iter()
            .zip(call_syscalls)
            .filter(|(ac, _)| call_tree.as_ref().is_none_or(|tree| tree.keeps_root(ac)))
            .map(|(ac, syscall)| {
                let syscall = syscall.map(|details| self::json::SyscallJson {
                    service_number: details.service_number.map(|n| format!("0x{:X}", n)),
                    kernel_module: details.kernel_module,
                    kernel_symbol: details.kernel_symbol,
                    kernel_rva: format!("0x{:08X}", details.kernel_rva),
                });
                ApiCallJson {
                    signature: signatures.get(&ac.rva).cloned(),
                    rva: format!("0x{:08X}", ac.rva),
                    kind: ac.kind.clone(),
                    target_rva: if ac.target_rva != 0 {
                        format!("0x{:08X}", ac.target_rva)
                    } else {
                        String::new()
                    },
                    label: ac.label.clone(),
                    dll: ac.dll.clone(),
                    is_import: ac.is_import,
                    is_indirect: ac.is_indirect,
                    indirect_method: ac.indirect_method.clone(),
                    switch_cases: ac.switch_cases.clone(),
                    dynamic: ac.dynamic.clone(),
                    resolves: ac.resolves.clone(),
                    syscall,
                }
            })
            .collect(),
        api_call_tree,
        telemetry,
        current_syscall: current_syscall.map(|details| self::json::SyscallJson {
            service_number: details.service_number.map(|n| format!("0x{:X}", n)),
            kernel_module: details.kernel_module,
            kernel_symbol: details.kernel_symbol,
            kernel_rva: format!("0x{:08X}", details.kernel_rva),
        }),
    }
}

pub(super) fn write_json(result: &FuncResult, w: &mut dyn Write) -> Result<(), String> {
    let json = serde_json::to_string_pretty(&versioned_object("dump", result)).unwrap_or_default();
    writeln!(w, "{}", json).ok();
    Ok(())
}
