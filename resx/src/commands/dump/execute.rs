use super::*;

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
    enter_follow_chain(chain, dll_arg, func_arg)?;
    if !cfg.cfg_view.is_empty() && !cfg.cfg_view.eq_ignore_ascii_case("text") {
        return Err(format!(
            "unsupported --cfg format '{}'; use 'text'",
            cfg.cfg_view
        ));
    }

    let only_metadata = func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0;
    let want_recomp = cfg.recomp || !cfg.c_out.is_empty();
    let want_cfg = cfg.cfg_view.eq_ignore_ascii_case("text");
    let want_hookchk = cfg.hookchk || cfg.edrchk;
    let want_intelli = cfg.intelli;
    let mut progress = StageProgress::new(
        count_dump_steps(cfg, only_metadata, want_recomp),
        !cfg.quiet && !cfg.json,
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

    if cfg.verbose && !cfg.quiet {
        writeln!(w, "{}", c.ok(&format!("Found: {}", dll_path_str))).ok();
    }

    let raw = crate::core::input::read_image(&dll_path).map_err(|e| format!("read file: {}", e))?;
    progress.tick("reading image");

    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    progress.tick("parsing PE headers");
    let pe_arch = pe.arch;
    let arch = cfg.effective_arch(pe_arch);
    let arch_str = format!("x{}", arch);
    let image_base = pe.image_base;
    let rebase = cfg.rebase_addr()?;

    if cfg.verbose && !cfg.quiet {
        let mut line = format!(
            "Architecture: {}  |  ImageBase: 0x{:X}",
            arch_str, image_base
        );
        if let Some(base) = rebase {
            line.push_str(&format!("  |  Rebase: 0x{:X}", base));
        }
        writeln!(w, "{}", c.info(&line)).ok();
    }

    let exports = read_exports(&pe, &raw);
    progress.tick("reading export table");
    if cfg.verbose && !cfg.quiet && !exports.is_empty() {
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
                if cfg.verbose && !cfg.quiet {
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
    let symbol_index = SymbolIndex::from_exports_and_pdb(&exports, &pdb_symbols, image_base);
    let imports = read_imports(&pe, &raw);
    progress.tick("reading import table");
    let import_count: usize = imports.iter().map(|dll| dll.entries.len()).sum();
    let startup_routines = find_startup_routines(&pe, &raw);
    let load_config = read_load_config(&pe, &raw);
    let function_discovery = if cfg.json {
        Some(discover_functions(
            &raw,
            &pe,
            &exports,
            &symbol_index,
            &pdb_symbols,
            &startup_routines,
            cfg,
        ))
    } else {
        None
    };
    let yara_matches = if cfg.yara.is_empty() {
        Vec::new()
    } else {
        scan_file(&dll_path_str, &cfg.yara)?
    };
    if !cfg.yara.is_empty() {
        progress.tick("running YARA rules");
    }

    if cfg.show_eat {
        print_eat(w, &exports, &dll_name, c);
    }

    if cfg.show_iat {
        print_iat(w, &imports, &dll_name, c);
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

    let metadata_intelli = if want_intelli && only_metadata {
        let findings = analyze_image(&raw, &imports, None);
        if !cfg.json {
            print_intelli_findings(w, &findings, c);
        }
        progress.tick("running Intelli triage");
        findings
    } else {
        Vec::new()
    };

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
                data: Some(to_data_summary_json(&read_data_summary(&pe, &raw))),
                function_discovery,
                recursive_cfg: None,
                typed_ir: None,
                indirect_flow: Some(analyze_indirect_flow(
                    &pe,
                    &imports,
                    &read_data_summary(&pe, &raw),
                    &[],
                    load_config.as_ref(),
                )),
                intelli_findings: metadata_intelli,
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
        }
        return Ok(());
    }

    let (target_rva, mut resolved_name, pdb_loaded) = match resolve_function(
        func_arg,
        &exports,
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
            &exports,
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
                &exports,
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
                &exports,
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
                    pdb_loaded,
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
                    if !cfg.quiet {
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
                            &exports,
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
                    if !cfg.quiet {
                        writeln!(w, "{}", c.info(&format!("Following: {}", res.desc()))).ok();
                    }
                }
                ThunkResolution::IatUnresolved { .. } => {
                    followed_desc = res.desc();
                    if !cfg.quiet {
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
                            if !cfg.quiet {
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
                            if !cfg.quiet {
                                writeln!(
                                    w,
                                    "{}",
                                    c.info(&format!("Following chain: {}", res.desc()))
                                )
                                .ok();
                            }
                        }
                        _ => {
                            if !cfg.quiet {
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

    let linear_insns = disassemble_at(
        &raw,
        &pe,
        file_off,
        target_rva,
        arch,
        image_base,
        &exports,
        Some(&symbol_index),
        cfg,
    )
    .map_err(|e| format!("disassembly: {}", e))?;
    let insns = recover_reachable_function_insns(
        &raw,
        &pe,
        target_rva,
        arch,
        image_base,
        &exports,
        Some(&symbol_index),
        cfg,
    )
    .filter(|recovered| recovered.len() > linear_insns.len())
    .unwrap_or(linear_insns);
    progress.tick("disassembling function");

    if !cfg.at_rva.is_empty() {
        resolved_name = best_symbol_name_for_rva(&symbol_index, image_base, target_rva)
            .unwrap_or(resolved_name);
    }
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
            &exports,
            Some(&symbol_index),
            target_rva,
            &resolved_name,
        );
        x.extend(startup_xrefs_for_target(
            &startup_routines,
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

    let str_refs = if cfg.show_strings {
        let s = find_string_refs(&raw, &pe, &insns);
        progress.tick("finding string references");
        s
    } else {
        Vec::new()
    };
    let data_summary = if cfg.json || cfg.show_strings {
        Some(read_data_summary(&pe, &raw))
    } else {
        None
    };

    let api_calls = if cfg.funcs_depth > 0 {
        let mut calls =
            collect_api_calls(&insns, &pe, &raw, &symbol_index, image_base, cfg.hostile);

        // Merge switch-dispatch targets.  First drop any unresolved register-indirect
        // entry at the same JMP site (they are superseded by the resolved targets).
        let switch_jmp_rvas: std::collections::HashSet<u32> =
            switch_api_calls.iter().map(|c| c.rva).collect();
        if !switch_jmp_rvas.is_empty() {
            calls.retain(|c| {
                !(c.is_indirect && c.target_rva == 0 && switch_jmp_rvas.contains(&c.rva))
            });
        }
        calls.extend(switch_api_calls.iter().cloned());
        calls.sort_by_key(|c| c.rva);
        progress.tick("building API call map");
        calls
    } else {
        Vec::new()
    };
    let api_call_tree = if cfg.funcs_depth > 0 {
        render_api_call_tree(
            &api_calls,
            &insns,
            &resolved_name,
            &dll_name,
            &raw,
            &pe,
            &symbol_index,
            &exports,
            arch,
            image_base,
            cfg,
            target_rva,
        )
    } else {
        String::new()
    };
    let current_syscall = synthetic_syscall_api_call(&insns, &resolved_name, &dll_name)
        .and_then(|call| resolve_syscall_call_details(&call, &insns, cfg));
    let prototype = symbol_index
        .exact(image_base + target_rva as u64)
        .map(|sym| sym.type_name)
        .unwrap_or_default();
    let typed_ir_summary = if cfg.json {
        Some(summarize_typed_ir(
            &insns,
            image_base,
            Some(&symbol_index),
            &prototype,
        ))
    } else {
        None
    };
    let recursive_cfg = if cfg.json || want_cfg {
        Some(recover_recursive_cfg(RecursiveCfgRequest {
            raw: &raw,
            pe: &pe,
            start_rva: target_rva,
            arch,
            image_base,
            exports: &exports,
            symbols: Some(&symbol_index),
            cfg,
            prototype: &prototype,
        }))
    } else {
        None
    };
    let indirect_flow = if cfg.json {
        data_summary.as_ref().map(|data| {
            analyze_indirect_flow(&pe, &imports, data, &api_calls, load_config.as_ref())
        })
    } else {
        None
    };

    let intelli_findings = if want_intelli {
        let findings = analyze_image(&raw, &imports, Some(&insns));
        progress.tick("running Intelli triage");
        findings
    } else {
        Vec::new()
    };

    let recomp_str = if want_recomp {
        let runtime_function = read_runtime_function(&pe, &raw, target_rva);
        let exp = Export {
            name: resolved_name.clone(),
            ordinal: 0,
            rva: target_rva,
            forward_to: String::new(),
        };
        let s = recomp_c(
            &insns,
            &exp,
            arch,
            image_base,
            Some(&symbol_index),
            runtime_function.as_ref(),
            cfg,
        );
        progress.tick("reconstructing C output");
        if !cfg.c_out.is_empty() {
            std::fs::write(&cfg.c_out, &s)
                .map_err(|e| format!("write C output '{}': {}", cfg.c_out, e))?;
            if !cfg.quiet {
                writeln!(
                    w,
                    "{}",
                    c.ok(&format!("Wrote C reconstruction to {}", cfg.c_out))
                )
                .ok();
            }
        }
        s
    } else {
        String::new()
    };

    let cfg_text = if want_cfg {
        let plain = render_cfg_text_with_edges(&insns, image_base, &recovered_cfg_edges);
        progress.tick("building control-flow graph");
        plain
    } else {
        String::new()
    };

    progress.finish();
    if !cfg.json {
        writeln!(w).ok();
        let mut title = format!("{}!{}  [RVA 0x{:08X}", dll_name, resolved_name, target_rva);
        if let Some(base) = rebase {
            title.push_str(&format!(", REBASE 0x{:X}", base + target_rva as u64));
        } else {
            title.push_str(&format!(", VA 0x{:X}", image_base + target_rva as u64));
        }
        title.push(']');
        writeln!(w, "{}", c.bold(&c.b_yellow(&title))).ok();
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
            print_api_calls(
                w,
                &api_calls,
                &insns,
                &resolved_name,
                &dll_name,
                c,
                &raw,
                &pe,
                &symbol_index,
                &exports,
                arch,
                image_base,
                cfg,
                target_rva,
            );
            let driver_report =
                crate::analysis::driver::analyze_driver(&dll_name, &pe, &raw, &imports);
            super::super::driver::render_flow_contracts(w, c, &driver_report, cfg.max_subcalls);
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
            let colored =
                render_cfg_colored_with_edges(&insns, image_base, c, &recovered_cfg_edges);
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
            writeln!(w, "  {:<20} {}", c.bold("BytesRead"), raw.len()).ok();
            writeln!(
                w,
                "  {:<20} {}",
                c.bold("BytesDisassembled"),
                disassembled_bytes
            )
            .ok();
            writeln!(w, "  {:<20} {}", c.bold("InstructionsDecoded"), insns.len()).ok();
            writeln!(w, "  {:<20} {}", c.bold("ExportsScanned"), exports.len()).ok();
            writeln!(w, "  {:<20} {}", c.bold("ImportsScanned"), import_count).ok();
            writeln!(
                w,
                "  {:<20} {}",
                c.bold("PdbSymbolsLoaded"),
                pdb_symbols.len()
            )
            .ok();
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
    }
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
            size_bytes: func_size_bytes,
            insn_count: insns.len(),
            pdb_loaded,
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
                    rva: format!("0x{:08X}", i.rva),
                    va: format!("0x{:016X}", i.va),
                    rebased_va: rebase
                        .map(|base| format!("0x{:016X}", base + i.rva as u64))
                        .unwrap_or_default(),
                    bytes: i
                        .bytes
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<Vec<_>>()
                        .join(" "),
                    text: i.text.clone(),
                    comment: i.comment.clone(),
                })
                .collect(),
            xrefs,
            strings: str_refs,
            data: data_summary.as_ref().map(to_data_summary_json),
            function_discovery,
            recursive_cfg,
            typed_ir: typed_ir_summary,
            indirect_flow,
            intelli_findings: if only_metadata {
                metadata_intelli
            } else {
                intelli_findings
            },
            recomp: recomp_str,
            cfg: cfg_text,
            hook_indicators,
            edrchk: edr_result.as_ref().map(to_edr_json),
            api_calls: api_calls
                .iter()
                .map(|ac| {
                    let syscall = resolve_syscall_call_details(ac, &insns, cfg).map(|details| {
                        self::json::SyscallJson {
                            service_number: details.service_number.map(|n| format!("0x{:X}", n)),
                            kernel_module: details.kernel_module,
                            kernel_symbol: details.kernel_symbol,
                            kernel_rva: format!("0x{:08X}", details.kernel_rva),
                        }
                    });
                    ApiCallJson {
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
                        syscall,
                    }
                })
                .collect(),
            api_call_tree,
            current_syscall: current_syscall.map(|details| self::json::SyscallJson {
                service_number: details.service_number.map(|n| format!("0x{:X}", n)),
                kernel_module: details.kernel_module,
                kernel_symbol: details.kernel_symbol,
                kernel_rva: format!("0x{:08X}", details.kernel_rva),
            }),
        };
        let json =
            serde_json::to_string_pretty(&versioned_object("dump", &result)).unwrap_or_default();
        writeln!(w, "{}", json).ok();
    }

    Ok(())
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
