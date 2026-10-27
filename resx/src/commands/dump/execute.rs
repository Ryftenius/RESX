use super::request::DumpRequest;
use super::*;
use crate::analysis::inspection::{
    decode_function, inspect_function, inspect_image, FunctionRequest,
};

pub fn run(
    dll_arg: &str,
    func_arg: &str,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    let (dll_arg, func_arg) = split_qualified_target(dll_arg, func_arg)?;
    run_with_chain(dll_arg, func_arg, cfg, w, c, &mut Vec::new())
}

fn split_qualified_target<'a>(
    image: &'a str,
    function: &'a str,
) -> Result<(&'a str, &'a str), String> {
    if !function.is_empty() {
        return Ok((image, function));
    }
    let Some((image, function)) = image.rsplit_once('!') else {
        return Ok((image, function));
    };
    if image.is_empty() || function.is_empty() {
        return Err("Use `resx dump <image>!<function>` with both names present".to_owned());
    }
    Ok((image, function))
}

pub(super) fn enter_follow_chain(
    chain: &mut Vec<(String, String)>,
    dll: &str,
    symbol: &str,
) -> Result<(), String> {
    let key = (dll.to_ascii_lowercase(), symbol.to_owned());
    if chain.len() >= 16 || chain.contains(&key) {
        return Err("Cross-image follow cycle or 16-image traversal limit reached".into());
    }
    chain.push(key);
    Ok(())
}

fn run_with_chain(
    dll_arg: &str,
    func_arg: &str,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
    chain: &mut Vec<(String, String)>,
) -> Result<(), String> {
    if !chain.is_empty() && !crate::core::input::is_safe_basename(dll_arg) {
        return Err("Embedded module reference is not a plain filename".to_owned());
    }
    enter_follow_chain(chain, dll_arg, func_arg)?;
    if !cfg.cfg_view.is_empty() && !cfg.cfg_view.eq_ignore_ascii_case("text") {
        return Err(format!(
            "unsupported --cfg format '{}'; use 'text'",
            cfg.cfg_view
        ));
    }

    let only_metadata = func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0;
    let mut request = DumpRequest::from_config(cfg, only_metadata);
    let want_recomp = cfg.recomp || !cfg.c_out.is_empty();
    let want_cfg = cfg.cfg_view.eq_ignore_ascii_case("text");
    let want_hookchk = cfg.hookchk || cfg.edrchk;
    let compact_calls = cfg.no_disassembly && cfg.funcs_depth > 0 && !cfg.verbose;
    let mut progress = StageProgress::new(
        count_dump_steps(cfg, only_metadata, want_recomp),
        !cfg.quiet && !cfg.json && !cfg.verbose && !compact_calls,
        c.on,
    );

    let dll_path = find_dll_path(dll_arg, cfg)?;
    progress.tick("locating target image");
    let dll_name = dll_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();

    if cfg.verbose && !cfg.quiet && !cfg.json {
        writeln!(w, "{}", c.ok(&format!("Found: {}", dll_path_str))).ok();
    }

    let raw = crate::core::input::read_image(&dll_path).map_err(|e| format!("read file: {}", e))?;
    progress.tick("reading image");

    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let exports_provider = crate::providers::exports::SystemExports::discover();
    let session =
        crate::analysis::session::AnalysisSession::with_exports(&pe, &raw, &exports_provider);
    let analysis = session.image();
    progress.tick("parsing PE headers");
    let pe_arch = pe.arch;
    let arch = cfg.effective_arch(pe_arch);
    let arch_str = format!("x{}", arch);
    let image_base = pe.image_base;
    let rebase = cfg.rebase_addr()?;

    if cfg.verbose && !cfg.quiet && !cfg.json {
        let mut line = format!(
            "Architecture: {}  |  ImageBase: 0x{:X}",
            arch_str, image_base
        );
        if let Some(base) = rebase {
            line.push_str(&format!("  |  Rebase: 0x{:X}", base));
        }
        writeln!(w, "{}", c.info(&line)).ok();
    }

    let exports = analysis.exports();
    progress.tick("reading export table");
    if cfg.verbose && !cfg.quiet && !cfg.json && !exports.is_empty() {
        writeln!(w, "{}", c.info(&format!("Exports: {}", exports.len()))).ok();
    }

    let pdb_symbols = if cfg.no_pdb {
        Vec::new()
    } else {
        match load_pdb_symbols(
            &dll_path_str,
            &cfg.sym_path,
            &cfg.sym_server,
            &cfg.pdb_file,
            cfg.verbose,
            cfg.reload,
        ) {
            Ok(symbols) => symbols,
            Err(err) => {
                if cfg.verbose && !cfg.quiet && !cfg.json {
                    writeln!(
                        w,
                        "{}",
                        c.dim(&format!("PDB symbol enumeration unavailable: {}", err))
                    )
                    .ok();
                }
                Vec::new()
            }
        }
    };
    if !cfg.no_pdb {
        progress.tick("loading symbols");
    }
    let symbol_index = SymbolIndex::from_exports_and_pdb(exports, &pdb_symbols, image_base);
    let imports = analysis.imports();
    progress.tick("reading import table");
    let import_count: usize = imports.iter().map(|dll| dll.entries.len()).sum();
    let startup_routines = analysis.startup_routines();
    let image_report = inspect_image(
        &session,
        request.image,
        &symbol_index,
        &pdb_symbols,
        request.options.max_total,
    );
    let function_discovery = image_report.discovery;
    let yara_matches = if cfg.yara.is_empty() {
        Vec::new()
    } else {
        scan_file(&dll_path_str, &cfg.yara)?
    };
    if !cfg.yara.is_empty() {
        progress.tick("running YARA rules");
    }

    if cfg.show_eat {
        print_eat(w, exports, &dll_name, c);
    }

    if cfg.show_iat {
        print_iat(w, imports, &dll_name, c);
    }

    if cfg.sections && !cfg.json {
        print_sections(w, &pe, c);
    }

    if cfg.pechk && !cfg.json {
        print_pe_anomalies(w, &pe.anomalies, c);
    }

    if !cfg.yara.is_empty() && !cfg.json {
        print_yara_matches(w, &yara_matches, c);
    }

    let metadata_intelli = image_report.intelli;
    if request.image.intelli {
        if !cfg.json {
            print_intelli_findings(w, &metadata_intelli, c);
        }
        progress.tick("running Intelli triage");
    }

    if only_metadata {
        progress.finish();
        if cfg.json {
            let result = FuncResult {
                dll: dll_name,
                dll_path: dll_path_str,
                function: String::new(),
                rva: String::new(),
                va: String::new(),
                rebased_va: String::new(),
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
                size_bytes: 0,
                insn_count: 0,
                pdb_loaded: !pdb_symbols.is_empty(),
                followed_jmp: String::new(),
                is_import_slot: false,
                import_target_dll: String::new(),
                import_target_name: String::new(),
                instructions: Vec::new(),
                xrefs: Vec::new(),
                strings: Vec::new(),
                data: image_report.data.map(to_data_summary_json),
                function_discovery,
                recursive_cfg: None,
                typed_ir: None,
                signature: None,
                decode_conflicts: None,
                indirect_flow: image_report.indirect_flow,
                intelli_findings: metadata_intelli,
                recomp: String::new(),
                cfg: String::new(),
                hook_indicators: Vec::new(),
                edrchk: None,
                api_calls: Vec::new(),
                api_call_tree: String::new(),
                current_syscall: None,
            };
            drop(session);
            super::render::write_json(&result, w)?;
        }
        return Ok(());
    }

    // Target resolution can write a permanent address/name line to stdout.
    // Erase the transient stderr line before that output advances the cursor.
    progress.finish();
    let (target_rva, mut resolved_name, pdb_loaded) = match resolve_function(
        func_arg,
        exports,
        &pdb_symbols,
        &pe,
        &raw,
        &dll_path_str,
        image_base,
        cfg,
        w,
        c,
    ) {
        Ok(found) => found,
        Err(err) => {
            progress.finish();
            return Err(err);
        }
    };
    progress.tick("resolving target");

    if cfg.show_xrefs
        && target_rva == 0
        && crate::analysis::wdf::function_by_name(&resolved_name).is_some()
    {
        let mut xrefs = find_xrefs(
            &raw,
            &pe,
            exports,
            Some(&symbol_index),
            target_rva,
            &resolved_name,
        );
        let exact_wdf = format!("WDF!{resolved_name}");
        xrefs.retain(|line| line.contains(&exact_wdf));
        xrefs.sort();
        xrefs.dedup();
        progress.tick("collecting cross references");
        progress.finish();
        if cfg.json {
            writeln!(
                w,
                "{}",
                serde_json::json!({
                    "schema": "resx.dump",
                    "version": 1,
                    "target": resolved_name,
                    "xrefs": xrefs,
                })
            )
            .ok();
        } else {
            writeln!(w, "{}", c.bold("\nCross References:")).ok();
            if xrefs.is_empty() {
                writeln!(w, "{}", c.dim("  (none)")).ok();
            }
            for r in &xrefs {
                writeln!(w, "  {}", c.cyan(r)).ok();
            }
        }
        return Ok(());
    }

    let import_slot_target = resolve_iat_slot(&pe, &raw, target_rva);
    if import_slot_target.is_none()
        && !pe
            .rva_to_section(target_rva)
            .is_some_and(|section| section.is_executable())
    {
        let bytes = pe.rva_bytes(&raw, target_rva).ok_or_else(|| {
            format!("RVA 0x{target_rva:08X} has no unambiguous file-backed region")
        })?;
        let bytes = &bytes[..bytes.len().min(cfg.max_bytes).min(256)];
        let mut xrefs = if cfg.show_xrefs {
            find_xrefs(
                &raw,
                &pe,
                exports,
                Some(&symbol_index),
                target_rva,
                &resolved_name,
            )
        } else {
            Vec::new()
        };
        xrefs.sort();
        xrefs.dedup();
        progress.finish();
        if cfg.json {
            let result = serde_json::json!({
                "dll": dll_name, "dll_path": dll_path_str,
                "symbol": resolved_name, "target_kind": "data",
                "xrefs": xrefs,
                "rva": format!("0x{target_rva:08X}"),
                "va": format!("0x{:016X}", image_base + u64::from(target_rva)),
                "instructions": [], "insn_count": 0, "is_import_slot": false,
                "bytes": hex_bytes(bytes),
                "note": "Non-executable file-backed object. Object length and type are unknown; bytes are a bounded preview, not a recovered function.",
                "pe_anomalies": pe.anomalies.iter().map(to_anomaly_json).collect::<Vec<_>>()
            });
            writeln!(
                w,
                "{}",
                serde_json::to_string_pretty(&versioned_object("dump", &result))
                    .map_err(|e| e.to_string())?
            )
            .ok();
        } else {
            writeln!(w, "{resolved_name} [data RVA 0x{target_rva:08X}]\n{}\nNon-executable object; length and type unknown.", hex_bytes(bytes)).ok();
            for reference in &xrefs {
                writeln!(w, "  {reference}").ok();
            }
        }
        return Ok(());
    }
    if cfg.show_xrefs || import_slot_target.is_some() {
        if let Some((import_dll, import_name)) = import_slot_target.as_ref() {
            let mut xrefs = find_xrefs(
                &raw,
                &pe,
                exports,
                Some(&symbol_index),
                target_rva,
                &resolved_name,
            );
            xrefs.sort();
            xrefs.dedup();
            progress.tick("collecting cross references");
            progress.finish();

            if cfg.json {
                let result = FuncResult {
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
                    size_bytes: 0,
                    insn_count: 0,
                    pdb_loaded: pdb_loaded || !pdb_symbols.is_empty(),
                    followed_jmp: String::new(),
                    is_import_slot: true,
                    import_target_dll: import_dll.clone(),
                    import_target_name: import_name.clone(),
                    instructions: Vec::new(),
                    xrefs,
                    strings: Vec::new(),
                    data: None,
                    function_discovery,
                    recursive_cfg: None,
                    typed_ir: None,
                    signature: None,
                    decode_conflicts: None,
                    indirect_flow: None,
                    intelli_findings: Vec::new(),
                    recomp: String::new(),
                    cfg: String::new(),
                    hook_indicators: Vec::new(),
                    edrchk: None,
                    api_calls: Vec::new(),
                    api_call_tree: String::new(),
                    current_syscall: None,
                };
                let json = serde_json::to_string_pretty(&versioned_object("dump", &result))
                    .unwrap_or_default();
                writeln!(w, "{}", json).ok();
            } else {
                writeln!(
                    w,
                    "\n{}",
                    c.bold(&format!(
                        "{}!{}  [IAT RVA 0x{:08X}, VA 0x{:X}]",
                        import_dll,
                        import_name,
                        target_rva,
                        image_base + target_rva as u64
                    ))
                )
                .ok();
                writeln!(w, "{}", c.bold("\nCross References:")).ok();
                if xrefs.is_empty() {
                    writeln!(w, "{}", c.dim("  (none)")).ok();
                }
                for r in &xrefs {
                    writeln!(w, "  {}", c.cyan(r)).ok();
                }
            }
            return Ok(());
        }
    }

    let mut file_off = pe
        .rva_to_offset(target_rva)
        .ok_or_else(|| format!("RVA 0x{:08X}: not in any section", target_rva))?;
    let mut target_rva = target_rva;

    if !cfg.quiet && !cfg.json {
        if let Some(note) = managed_metadata_disassembly_note(&pe, &raw, target_rva) {
            writeln!(w, "{}", c.warn(&note)).ok();
        }
    }

    let mut followed_desc = String::new();
    let entry_thunk = follow_jmp_thunk(&raw, &pe, target_rva);

    if cfg.follow_jmp {
        if let Some(res) = entry_thunk.as_ref() {
            match &res {
                ThunkResolution::Iat { dll, func, .. } if !dll.is_empty() => {
                    if !cfg.quiet && !cfg.json {
                        writeln!(w).ok();
                        let title = format!(
                            "{}!{}  [RVA 0x{:08X}]  — STUB",
                            dll_name, resolved_name, target_rva
                        );
                        writeln!(w, "{}", c.bold(&c.b_yellow(&title))).ok();
                        if let Ok(stub_insns) = disassemble_at(
                            &raw,
                            &pe,
                            file_off,
                            target_rva,
                            arch,
                            image_base,
                            exports,
                            Some(&symbol_index),
                            cfg,
                        ) {
                            print_insns(w, &stub_insns, cfg, c);
                        }
                        writeln!(
                            w,
                            "{}",
                            c.warn(&format!(
                                "STUB  {}!{}  →  {}!{}",
                                dll_name, resolved_name, dll, func
                            ))
                        )
                        .ok();
                        writeln!(w, "{}", c.info(&format!("Auto-following into {}...", dll))).ok();
                    }
                    let new_cfg = cfg.clone();
                    return run_with_chain(dll, func, &new_cfg, w, c, chain);
                }
                ThunkResolution::Direct {
                    target_rva: new_rva,
                } => {
                    followed_desc = res.desc();
                    target_rva = *new_rva;
                    file_off = pe
                        .rva_to_offset(target_rva)
                        .ok_or_else(|| format!("RVA 0x{:08X}: not in any section", target_rva))?;
                    if !cfg.quiet && !cfg.json {
                        writeln!(w, "{}", c.info(&format!("Following: {}", res.desc()))).ok();
                    }
                }
                ThunkResolution::IatUnresolved { .. } => {
                    followed_desc = res.desc();
                    if !cfg.quiet && !cfg.json {
                        writeln!(
                            w,
                            "{}",
                            c.warn(&format!("Unresolved thunk: {}", res.desc()))
                        )
                        .ok();
                    }
                }
                ThunkResolution::Chain {
                    ref final_target, ..
                } => {
                    followed_desc = res.desc();
                    match final_target.as_ref() {
                        ThunkResolution::Iat { dll, func, .. } if !dll.is_empty() => {
                            if !cfg.quiet && !cfg.json {
                                writeln!(w, "{}", c.info(&format!("Thunk chain: {}", res.desc())))
                                    .ok();
                            }
                            let new_cfg = cfg.clone();
                            return run_with_chain(dll, func, &new_cfg, w, c, chain);
                        }
                        ThunkResolution::Direct {
                            target_rva: new_rva,
                        } => {
                            target_rva = *new_rva;
                            file_off = pe.rva_to_offset(target_rva).ok_or_else(|| {
                                format!("RVA 0x{:08X}: not in any section", target_rva)
                            })?;
                            if !cfg.quiet && !cfg.json {
                                writeln!(
                                    w,
                                    "{}",
                                    c.info(&format!("Following chain: {}", res.desc()))
                                )
                                .ok();
                            }
                        }
                        _ => {
                            if !cfg.quiet && !cfg.json {
                                writeln!(w, "{}", c.info(&format!("Thunk chain: {}", res.desc())))
                                    .ok();
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    }

    if !cfg.at_rva.is_empty() {
        resolved_name = best_symbol_name_for_rva(&symbol_index, image_base, target_rva)
            .unwrap_or(resolved_name);
    }
    let header_index = crate::providers::headers::configured(cfg.argument_headers());
    request.function.arguments = header_index.is_some();
    request.function.dynamic_resolution = request.function.calls || request.function.arguments;
    let function_request = FunctionRequest {
        rva: target_rva,
        name: &resolved_name,
        image_name: &dll_name,
        arch,
        options: request.options,
        reports: request.function,
        ssa: cfg.ssa,
        annotate_conflicts: cfg.verbose,
    };
    let insns = decode_function(&session, &function_request, &symbol_index)
        .map_err(|e| format!("disassembly: {}", e))?;
    progress.tick("disassembling function");

    let edr_result = if cfg.edrchk {
        let max_len = insns
            .iter()
            .take(8)
            .map(|i| i.bytes.len())
            .sum::<usize>()
            .clamp(16, 64);
        Some(check_prologue(
            &dll_path_str,
            target_rva,
            &raw[file_off..],
            max_len,
            cfg.unsafe_map_image,
        )?)
    } else {
        None
    };
    if cfg.edrchk {
        progress.tick("checking in-memory prologue");
    }

    let func_size_bytes = if insns.is_empty() {
        0
    } else {
        let last = insns.last().unwrap();
        (last.rva - insns[0].rva) as usize + last.bytes.len()
    };
    let recovered_switch =
        recover_local_switch_dispatch(&insns, &raw, &pe, &symbol_index, image_base);
    let recovered_cfg_edges = recovered_switch
        .as_ref()
        .map(|dispatch| to_cfg_edges(&insns, &dispatch.targets))
        .unwrap_or_default();
    // API calls synthesised from the switch-dispatch targets (merged later).
    let switch_api_calls: Vec<ApiCall> = recovered_switch
        .as_ref()
        .map(|dispatch| switch_dispatch_to_api_calls(&insns, dispatch))
        .unwrap_or_default();

    let switch_semantics = recovered_switch
        .as_ref()
        .and_then(|_| load_switch_semantics(&resolved_name));

    let mut hook_indicators = if want_hookchk {
        detect_static_hook_indicators(&insns, entry_thunk.as_ref())
    } else {
        Vec::new()
    };
    if let Some(edr) = &edr_result {
        if edr.modified {
            hook_indicators.push(format!(
                "in-memory prologue differs from disk at {} offset(s)",
                edr.diff_offsets.len()
            ));
        }
    }
    let xrefs = if cfg.show_xrefs {
        let mut x = find_xrefs(
            &raw,
            &pe,
            exports,
            Some(&symbol_index),
            target_rva,
            &resolved_name,
        );
        x.extend(startup_xrefs_for_target(
            startup_routines,
            target_rva,
            &resolved_name,
        ));
        x.sort();
        x.dedup();
        progress.tick("collecting cross references");
        x
    } else {
        Vec::new()
    };

    let report = inspect_function(
        &session,
        &function_request,
        &symbol_index,
        header_index.as_deref(),
        insns,
        &switch_api_calls,
    );
    if request.function.strings {
        progress.tick("finding string references");
    }
    if request.function.calls || request.function.arguments {
        progress.tick("building API call map");
    }
    if request.function.intelli {
        progress.tick("running Intelli triage");
    }
    if request.function.recomp {
        progress.tick("reconstructing C output");
    }
    let insns = &report.instructions;
    let api_calls = &report.calls;
    let call_tree = if request.call_tree {
        Some(build_api_call_tree(
            api_calls,
            insns,
            &resolved_name,
            &dll_name,
            &session,
            header_index.as_deref(),
            &symbol_index,
            arch,
            image_base,
            cfg,
            target_rva,
        ))
    } else {
        None
    };
    let api_call_tree = call_tree
        .as_ref()
        .map(|tree| render_api_call_tree(tree, cfg))
        .unwrap_or_default();
    let current_syscall = synthetic_syscall_api_call(insns, &resolved_name, &dll_name)
        .and_then(|call| resolve_syscall_call_details(&call, insns, cfg));
    let call_syscalls: Vec<_> = api_calls
        .iter()
        .map(|call| {
            if request.call_syscalls && call_tree.as_ref().is_none_or(|tree| tree.keeps_root(call))
            {
                resolve_syscall_call_details(call, insns, cfg)
            } else {
                None
            }
        })
        .collect();
    if !cfg.c_out.is_empty() {
        std::fs::write(&cfg.c_out, &report.recomp)
            .map_err(|e| format!("write C output '{}': {}", cfg.c_out, e))?;
        if !cfg.quiet && !cfg.json {
            writeln!(
                w,
                "{}",
                c.ok(&format!("Wrote C reconstruction to {}", cfg.c_out))
            )
            .ok();
        }
    }

    let cfg_blocks = if want_cfg {
        let blocks = crate::analysis::cfgview::build_basic_blocks_with_edges(
            insns,
            image_base,
            &recovered_cfg_edges,
        );
        progress.tick("building control-flow graph");
        blocks
    } else {
        Vec::new()
    };

    progress.finish();
    let view = super::render::FunctionView {
        report,
        pe: &pe,
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
        pdb_count: pdb_symbols.len(),
        bytes_read: raw.len(),
        export_count: exports.len(),
        import_count,
        followed_desc,
        import_slot_target,
        func_size_bytes,
        recovered_switch,
        switch_semantics,
        recovered_cfg_edges,
        hook_indicators,
        xrefs,
        edr_result,
        call_tree,
        api_call_tree,
        current_syscall,
        call_syscalls,
        cfg_blocks,
    };
    if cfg.json {
        let result = super::render::into_json(view, cfg);
        drop(session);
        super::render::write_json(&result, w)
    } else {
        super::render::render_text(view, cfg, w, c)
    }
}

#[cfg(test)]
mod target_syntax_tests {
    use super::split_qualified_target;

    #[test]
    fn splits_bang_qualified_target_when_function_is_omitted() {
        assert_eq!(
            split_qualified_target("ntdll.dll!NtTerminateProcess", "").unwrap(),
            ("ntdll.dll", "NtTerminateProcess")
        );
    }

    #[test]
    fn explicit_function_takes_precedence() {
        assert_eq!(
            split_qualified_target("ntdll.dll", "NtTerminateProcess").unwrap(),
            ("ntdll.dll", "NtTerminateProcess")
        );
    }

    #[test]
    fn rejects_incomplete_bang_qualified_target() {
        assert!(split_qualified_target("ntdll.dll!", "").is_err());
    }
}
