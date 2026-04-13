mod callmap;
mod json;
mod style;
mod switchfmt;

use std::io::Write;
use std::sync::OnceLock;

use self::callmap::{
    best_symbol_name_for_rva, print_api_calls, recover_local_switch_dispatch, render_api_call_tree,
    resolve_syscall_call_details, switch_dispatch_to_api_calls, synthetic_syscall_api_call,
    QsiDispatcher,
};
use self::json::{
    hex_bytes, to_anomaly_json, to_edr_json, to_section_json, to_startup_json, to_yara_json,
    ApiCallJson, FuncResult, InsnJson,
};
use self::switchfmt::{format_case_summary, format_target_symbol_spaced};
use crate::analysis::cfgview::{
    detect_static_hook_indicators, render_cfg_colored_with_edges, render_cfg_text_with_edges,
    RecoveredIndirectEdge,
};
use crate::analysis::disasm::{
    collect_api_calls, disassemble_at, find_string_refs, find_xrefs, ApiCall, Instruction,
};
use crate::analysis::edr::{check_prologue, EdrCheckResult};
use crate::analysis::explain::explain_symbol;
use crate::analysis::intelli::{analyze_image, IntelliFinding};
use crate::analysis::recomp::recomp_c;
use crate::analysis::symbols::SymbolIndex;
use crate::analysis::thunk::{follow_jmp_thunk, ThunkResolution};
use crate::analysis::yara::scan_file;
use crate::commands::explain::{config_mode as explain_mode, print_explain_text};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use crate::core::output::{
    print_c_recomp, print_eat, print_iat, print_insns, print_pe_anomalies, print_sections,
    print_yara_matches, StageProgress,
};
use crate::core::search::find_dll_path;
use crate::formats::pdb::{load_pdb_symbol, load_pdb_symbols};
use crate::formats::pe::{
    find_iat_slots_by_name, find_startup_routines, parse_pe, read_exports, read_imports,
    read_runtime_function, resolve_iat_slot, Export, PeStartupRoutine,
};

#[derive(Debug, Clone)]
struct RecoveredSwitchTarget {
    target_rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
}

#[cfg(test)]
mod tests {
    use super::parse_u32_literal;

    #[test]
    fn parse_u32_literal_accepts_hex_and_decimal_forms() {
        assert_eq!(parse_u32_literal("0x2A"), Some(0x2A));
        assert_eq!(parse_u32_literal("2Ah"), Some(0x2A));
        assert_eq!(parse_u32_literal("42"), Some(42));
        assert_eq!(parse_u32_literal("0x1_000"), Some(0x1000));
    }

    #[test]
    fn parse_u32_literal_rejects_negative_values() {
        assert_eq!(parse_u32_literal("-1"), None);
    }
}

#[derive(Debug, Clone)]
struct RecoveredSwitchDispatch {
    dispatcher: QsiDispatcher,
    targets: Vec<RecoveredSwitchTarget>,
}

#[derive(Debug, Clone)]
struct HeaderPrototype {
    params: Vec<HeaderParam>,
}

#[derive(Debug, Clone)]
struct HeaderParam {
    type_name: String,
    name: String,
}

#[derive(Debug, Clone)]
struct HeaderEnum {
    type_name: String,
    members: std::collections::BTreeMap<u32, String>,
}

#[derive(Debug, Clone)]
struct SwitchSemanticInfo {
    selector_param: HeaderParam,
    selector_enum: HeaderEnum,
    params: Vec<HeaderParam>,
}

pub fn run(
    dll_arg: &str,
    func_arg: &str,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
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

    if !cfg.quiet {
        writeln!(w, "{}", c.ok(&format!("Found: {}", dll_path_str))).ok();
    }

    let raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    progress.tick("reading image");

    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    progress.tick("parsing PE headers");
    let pe_arch = pe.arch;
    let arch = cfg.effective_arch(pe_arch);
    let arch_str = format!("x{}", arch);
    let image_base = pe.image_base;
    let rebase = cfg.rebase_addr()?;

    if !cfg.quiet {
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
    if !cfg.quiet && !exports.is_empty() {
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
                intelli_findings: metadata_intelli,
                recomp: String::new(),
                cfg: String::new(),
                hook_indicators: Vec::new(),
                edrchk: None,
                api_calls: Vec::new(),
                api_call_tree: String::new(),
                current_syscall: None,
                explain: None,
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

    let mut file_off = pe
        .rva_to_offset(target_rva)
        .ok_or_else(|| format!("RVA 0x{:08X}: not in any section", target_rva))?;
    let mut target_rva = target_rva;

    let mut followed_desc = String::new();
    let import_slot_target = resolve_iat_slot(&pe, &raw, target_rva);

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
                    return run(dll, func, &new_cfg, w, c);
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
                _ => {}
            }
        }
    }

    let insns = disassemble_at(
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
    progress.tick("disassembling function");

    if !cfg.at_rva.is_empty() {
        resolved_name = best_symbol_name_for_rva(&symbol_index, image_base, target_rva)
            .unwrap_or(resolved_name);
    }
    let explain_result = if cfg.explain {
        Some(explain_symbol(&resolved_name, explain_mode(cfg)))
    } else {
        None
    };

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

    let api_calls = if cfg.funcs_depth > 0 {
        let mut calls = collect_api_calls(&insns, &pe, &raw, &symbol_index, image_base);

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
    let current_syscall = synthetic_syscall_api_call(&insns, &resolved_name)
        .and_then(|call| resolve_syscall_call_details(&call, &insns, cfg));

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
        if let Some(explain) = explain_result.as_ref() {
            print_explain_text(w, explain, c, true);
        }
        print_insns(w, &insns, cfg, c);
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
            writeln!(w, "{}", c.bold(&c.b_blue("Verbose Work Summary:"))).ok();
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
            explain: explain_result,
        };
        let json =
            serde_json::to_string_pretty(&versioned_object("dump", &result)).unwrap_or_default();
        writeln!(w, "{}", json).ok();
    }

    Ok(())
}

fn count_dump_steps(cfg: &Config, only_metadata: bool, want_recomp: bool) -> usize {
    let mut total = 5usize;
    if !cfg.no_pdb {
        total += 1;
    }
    if !cfg.yara.is_empty() {
        total += 1;
    }
    if !only_metadata {
        total += 2;
        if cfg.edrchk {
            total += 1;
        }
        if cfg.show_xrefs {
            total += 1;
        }
        if cfg.show_strings {
            total += 1;
        }
        if cfg.funcs_depth > 0 {
            total += 1;
        }
        if want_recomp {
            total += 1;
        }
        if cfg.cfg_view.eq_ignore_ascii_case("text") {
            total += 1;
        }
    }
    if cfg.intelli {
        total += 1;
    }
    total
}

fn startup_xrefs_for_target(
    startup_routines: &[PeStartupRoutine],
    target_rva: u32,
    target_name: &str,
) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let target_kind = startup_routines
        .iter()
        .find(|entry| entry.rva == target_rva)
        .map(|entry| entry.kind.to_lowercase())
        .unwrap_or_default();

    let include_context = target_kind.contains("real main")
        || target_kind.contains("startup")
        || target_kind.contains("entry");

    if !include_context {
        return out;
    }

    for entry in startup_routines
        .iter()
        .filter(|entry| entry.rva != target_rva)
    {
        let kind = if entry.kind.contains("TLS") {
            "STARTUP-TLS"
        } else {
            "STARTUP"
        };
        let owner = entry.kind.replace(' ', "_");
        let mut line = format!(
            "{} {} [site 0x{:08X}] -> {} [target 0x{:08X}]",
            kind, owner, entry.rva, target_name, target_rva
        );
        let mut detail = Vec::new();
        if !entry.source.is_empty() {
            detail.push(format!("via {}", entry.source));
        }
        if !entry.note.is_empty() {
            detail.push(entry.note.clone());
        }
        if !detail.is_empty() {
            line.push_str(&format!(" ; {}", detail.join(" | ")));
        }
        if seen.insert(line.clone()) {
            out.push(line);
        }
    }

    out
}

fn to_cfg_edges(
    insns: &[Instruction],
    recovered_switch: &[RecoveredSwitchTarget],
) -> Vec<RecoveredIndirectEdge> {
    let Some(jump_rva) = insns
        .iter()
        .find(|insn| insn.is_jmp && insn.call_target == 0)
        .map(|insn| insn.rva)
    else {
        return Vec::new();
    };
    recovered_switch
        .iter()
        .map(|target| RecoveredIndirectEdge {
            jump_rva,
            label: format!(
                "switch -> block_{:08X} ({})",
                target.target_rva,
                format_case_summary(&target.classes)
            ),
        })
        .collect()
}

fn case_value_lines(classes: &[u32], header_enum: Option<&HeaderEnum>) -> Vec<String> {
    let Some(header_enum) = header_enum else {
        return case_value_lines_plain(classes);
    };
    let mut lines = Vec::new();
    let mut i = 0usize;
    while i < classes.len() {
        let value = classes[i];
        if let Some(name) = header_enum.members.get(&value) {
            lines.push(format!("{} (0x{:X})", name, value));
            i += 1;
        } else {
            let start = value;
            let mut end = start;
            while i + 1 < classes.len() {
                let next = classes[i + 1];
                if next != end + 1 || header_enum.members.contains_key(&next) {
                    break;
                }
                i += 1;
                end = classes[i];
            }
            if start == end {
                lines.push(format!("0x{:02X}", start));
            } else {
                lines.push(format!("0x{:02X}..0x{:02X}", start, end));
            }
            i += 1;
        }
    }
    lines
}

fn case_value_lines_plain(classes: &[u32]) -> Vec<String> {
    let mut lines = Vec::new();
    let mut i = 0usize;
    while i < classes.len() {
        let start = classes[i];
        let mut end = start;
        while i + 1 < classes.len() && classes[i + 1] == end + 1 {
            i += 1;
            end = classes[i];
        }
        if start == end {
            lines.push(format!("0x{:02X}", start));
        } else {
            lines.push(format!("0x{:02X}..0x{:02X}", start, end));
        }
        i += 1;
    }
    lines
}

fn print_switch_map(
    w: &mut dyn Write,
    dispatch: &RecoveredSwitchDispatch,
    semantics: Option<&SwitchSemanticInfo>,
    c: &Colors,
) {
    writeln!(w, "\n{}", c.bold(&c.b_mag("Switch Map"))).ok();
    writeln!(w, "{}", c.dim("----------")).ok();
    writeln!(w).ok();

    if let Some(sem) = semantics {
        writeln!(
            w,
            "{}  {}",
            c.dim("Selector  :"),
            c.cyan(&format!(
                "{} ({})",
                sem.selector_param.name, sem.selector_enum.type_name
            )),
        )
        .ok();
        writeln!(
            w,
            "{}  {}",
            c.dim("Params    :"),
            c.cyan(&sem.params.len().to_string()),
        )
        .ok();
        writeln!(w, "{}", c.dim("Prototype :")).ok();
        let last = sem.params.len().saturating_sub(1);
        for (idx, p) in sem.params.iter().enumerate() {
            let suffix = if idx < last { "," } else { "" };
            writeln!(
                w,
                "    {}{}",
                c.b_white(&format!("{} {}", p.type_name, p.name)),
                c.dim(suffix),
            )
            .ok();
        }
        writeln!(w).ok();
    }

    writeln!(
        w,
        "{}  {}",
        c.dim("Bias      :"),
        c.cyan(&format!("0x{:X}", dispatch.dispatcher.class_bias)),
    )
    .ok();
    writeln!(
        w,
        "{}  {}",
        c.dim("Max       :"),
        c.cyan(&format!("0x{:X}", dispatch.dispatcher.max_index)),
    )
    .ok();
    writeln!(
        w,
        "{}  {}",
        c.dim("Targets   :"),
        c.cyan(&dispatch.targets.len().to_string()),
    )
    .ok();
    writeln!(w).ok();
    writeln!(
        w,
        "{}  {}",
        c.dim("Remap     :"),
        c.cyan(&format!(
            "RVA 0x{:08X}",
            dispatch.dispatcher.index_table_rva
        )),
    )
    .ok();
    writeln!(
        w,
        "{}  {}",
        c.dim("Table     :"),
        c.cyan(&format!(
            "RVA 0x{:08X}",
            dispatch.dispatcher.target_table_rva
        )),
    )
    .ok();

    for target in &dispatch.targets {
        writeln!(w).ok();
        writeln!(w).ok();
        writeln!(
            w,
            "{}  {}",
            c.b_white(&format_target_symbol_spaced(&target.symbol_name)),
            c.dim(&format!("[RVA 0x{:08X}]", target.target_rva)),
        )
        .ok();
        writeln!(w, "{}", c.dim("When :")).ok();
        for line in case_value_lines(&target.classes, semantics.map(|s| &s.selector_enum)) {
            writeln!(w, "    {}", c.cyan(&line)).ok();
        }
    }
    writeln!(w).ok();
}

fn load_switch_semantics(function_name: &str) -> Option<SwitchSemanticInfo> {
    let prototype = load_winternl_prototype(function_name)?;
    let selector_param = prototype.params.first()?.clone();
    let selector_enum = load_winternl_enum(&selector_param.type_name)?;
    Some(SwitchSemanticInfo {
        selector_param,
        selector_enum,
        params: prototype.params,
    })
}

fn load_winternl_text() -> Option<&'static str> {
    static CACHE: OnceLock<Option<String>> = OnceLock::new();
    CACHE
        .get_or_init(|| {
            let path = std::path::Path::new(
                r"C:\Program Files (x86)\Windows Kits\10\Include\10.0.26100.0\um\winternl.h",
            );
            std::fs::read_to_string(path).ok()
        })
        .as_deref()
}

fn load_winternl_prototype(function_name: &str) -> Option<HeaderPrototype> {
    let text = load_winternl_text()?;
    let needle = format!("{} (", function_name);
    let lines: Vec<&str> = text.lines().collect();
    let mut idx = lines.iter().position(|line| line.contains(&needle))?;
    let mut params = Vec::new();
    idx += 1;
    while idx < lines.len() {
        let line = lines[idx].trim();
        idx += 1;
        if line.starts_with(");") {
            break;
        }
        if line.is_empty() {
            continue;
        }
        let cleaned = line.trim_end_matches(',').trim();
        if let Some(param) = parse_header_param(cleaned) {
            params.push(param);
        }
    }
    Some(HeaderPrototype { params })
}

fn parse_header_param(line: &str) -> Option<HeaderParam> {
    let mut tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }
    tokens.retain(|tok| {
        !matches!(
            *tok,
            "IN" | "OUT" | "OPTIONAL" | "_Out_" | "_In_" | "_Inout_" | "__kernel_entry" | "NTAPI"
        )
    });
    let name = tokens.pop()?.trim_end_matches(',').to_owned();
    let type_name = tokens.join(" ");
    if type_name.is_empty() || name.is_empty() {
        return None;
    }
    Some(HeaderParam { type_name, name })
}

fn load_winternl_enum(type_name: &str) -> Option<HeaderEnum> {
    let text = load_winternl_text()?;
    let enum_name = type_name.trim_start_matches("P").trim();
    let needle = format!("typedef enum _{}", enum_name);
    let lines: Vec<&str> = text.lines().collect();
    let mut idx = lines.iter().position(|line| line.contains(&needle))?;
    let mut members = std::collections::BTreeMap::new();
    idx += 1;
    while idx < lines.len() {
        let line = lines[idx].trim();
        idx += 1;
        if line.starts_with("}") {
            break;
        }
        if let Some((name, value)) = parse_enum_member(line) {
            members.insert(value, name);
        }
    }
    if members.is_empty() {
        None
    } else {
        Some(HeaderEnum {
            type_name: enum_name.to_owned(),
            members,
        })
    }
}

fn parse_enum_member(line: &str) -> Option<(String, u32)> {
    let cleaned = line.trim_end_matches(',').trim();
    let (name, value_str) = cleaned.split_once('=')?;
    let name = name.trim().to_owned();
    let value = parse_u32_literal(value_str)?;
    Some((name, value))
}

fn parse_u32_literal(raw: &str) -> Option<u32> {
    let value = raw.trim().trim_end_matches(',');
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    let value = value.trim_start_matches('+').replace('_', "");
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .or_else(|| value.strip_suffix('h'))
        .or_else(|| value.strip_suffix('H'));
    if let Some(hex) = hex {
        u32::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u32>().ok()
    }
}

fn print_intelli_findings(w: &mut dyn Write, findings: &[IntelliFinding], c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_red("Intelli Triage:"))).ok();
    if findings.is_empty() {
        writeln!(w, "{}", c.dim("  (no notable IoC/TTP indicators found)")).ok();
        return;
    }
    for finding in findings {
        writeln!(
            w,
            "  [{}] {} ({}) {}",
            c.b_red(&finding.category),
            c.warn(&finding.rule),
            c.dim(&finding.source),
            c.cyan(&finding.value)
        )
        .ok();
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_function(
    func_arg: &str,
    exports: &[Export],
    pdb_symbols: &[crate::formats::pdb::PdbSymbol],
    pe: &crate::formats::pe::PeFile,
    raw: &[u8],
    dll_path: &str,
    image_base: u64,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(u32, String, bool), String> {
    if !cfg.at_rva.is_empty() {
        let rva = parse_u32_literal(&cfg.at_rva)
            .ok_or_else(|| format!("invalid --at value: {}", cfg.at_rva))?;
        let name = if func_arg.is_empty() {
            format!("fn_0x{:08X}", rva)
        } else {
            func_arg.to_owned()
        };
        return Ok((rva, name, false));
    }

    if cfg.ordinal > 0 {
        for e in exports {
            if e.ordinal == cfg.ordinal {
                return Ok((e.rva, e.name.clone(), false));
            }
        }
        return Err(format!("ordinal {} not found in export table", cfg.ordinal));
    }

    for e in exports {
        if e.name == func_arg {
            if !cfg.quiet {
                writeln!(
                    w,
                    "{}",
                    c.ok(&format!(
                        "{} @ RVA 0x{:08X}  (ord {})",
                        e.name, e.rva, e.ordinal
                    ))
                )
                .ok();
            }
            if !e.forward_to.is_empty() && !cfg.no_follow_fwd {
                return Err(format!(
                    "'{}' is a forwarded export → {}\n  use --no-follow-forward or target the correct DLL",
                    func_arg, e.forward_to
                ));
            }
            return Ok((e.rva, e.name.clone(), false));
        }
    }

    if !cfg.no_pdb {
        if !cfg.quiet {
            writeln!(w, "{}", c.info("Not found in EAT, trying PDB symbols...")).ok();
        }
        if let Some(sym) = find_cached_pdb_symbol(pdb_symbols, func_arg) {
            if !cfg.quiet {
                writeln!(
                    w,
                    "{}",
                    c.ok(&format!(
                        "{} @ RVA 0x{:08X}  (from enumerated PDB symbols)",
                        sym.name, sym.rva
                    ))
                )
                .ok();
            }
            return Ok((sym.rva, sym.name.clone(), true));
        }
        if let Some(rva) = load_pdb_symbol(
            dll_path,
            func_arg,
            &cfg.sym_path,
            &cfg.sym_server,
            &cfg.pdb_file,
            image_base,
            cfg.verbose,
            cfg.reload,
        ) {
            if !cfg.quiet {
                writeln!(
                    w,
                    "{}",
                    c.ok(&format!("{} @ RVA 0x{:08X}  (from PDB)", func_arg, rva))
                )
                .ok();
            }
            return Ok((rva, func_arg.to_owned(), true));
        }
    }

    let iat_slots = find_iat_slots_by_name(pe, raw, func_arg);
    if let Some((slot_rva, dll_name, import_name)) = iat_slots.first() {
        if !cfg.quiet {
            writeln!(
                w,
                "{}",
                c.ok(&format!(
                    "{}!{} @ IAT RVA 0x{:08X}  (from current image imports)",
                    dll_name, import_name, slot_rva
                ))
            )
            .ok();
        }
        return Ok((*slot_rva, import_name.clone(), false));
    }

    writeln!(
        w,
        "\n{} '{}' not found in EAT or PDB symbols",
        c.err_msg(""),
        func_arg
    )
    .ok();
    let lf = func_arg.to_lowercase();
    let suggestions: Vec<&str> = exports
        .iter()
        .filter(|e| e.name.to_lowercase().contains(&lf))
        .take(8)
        .map(|e| e.name.as_str())
        .collect();
    let pdb_suggestions = suggest_cached_pdb_symbols(pdb_symbols, func_arg, 8);
    if !suggestions.is_empty() {
        writeln!(w, "{}", c.warn("Similar exports:")).ok();
        for s in &suggestions {
            writeln!(w, "  {}", c.cyan(s)).ok();
        }
    }
    if !pdb_suggestions.is_empty() {
        writeln!(w, "{}", c.warn("Similar PDB symbols:")).ok();
        for s in &pdb_suggestions {
            writeln!(w, "  {}", c.cyan(s)).ok();
        }
    }
    writeln!(
        w,
        "{}",
        c.dim("  Tip: use --show-eat to list all exports, --ordinal N, or --at <rva>")
    )
    .ok();
    Err(format!("function '{}' not found", func_arg))
}

fn find_cached_pdb_symbol<'a>(
    pdb_symbols: &'a [crate::formats::pdb::PdbSymbol],
    func_arg: &str,
) -> Option<&'a crate::formats::pdb::PdbSymbol> {
    let want = normalize_symbol_name(func_arg);
    pdb_symbols
        .iter()
        .find(|sym| normalize_symbol_name(&sym.name) == want)
}

fn suggest_cached_pdb_symbols(
    pdb_symbols: &[crate::formats::pdb::PdbSymbol],
    func_arg: &str,
    limit: usize,
) -> Vec<String> {
    let want = normalize_symbol_name(func_arg);
    let mut out = Vec::new();
    for sym in pdb_symbols {
        let normalized = normalize_symbol_name(&sym.name);
        if (normalized.contains(&want) || want.contains(&normalized))
            && !out.iter().any(|seen| seen == &sym.name)
        {
            out.push(sym.name.clone());
        }
        if out.len() >= limit {
            break;
        }
    }
    out
}

fn normalize_symbol_name(name: &str) -> String {
    let tail = name.rsplit('!').next().unwrap_or(name);
    let tail = match tail.split_once("$thunk$") {
        Some((base, _)) if !base.is_empty() => base,
        _ => tail,
    };
    let trimmed = tail.trim_start_matches('_');
    let core = match trimmed.rsplit_once('@') {
        Some((base, suffix)) if suffix.chars().all(|ch| ch.is_ascii_digit()) => base,
        _ => trimmed,
    };
    core.to_ascii_lowercase()
}

fn print_edr_report(w: &mut dyn Write, edr: &EdrCheckResult, c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_blue("EDR / Hook Check:"))).ok();
    if !edr.in_memory_available {
        if edr.blocked_by_policy {
            writeln!(
                w,
                "{}",
                c.warn(
                    "Comparison skipped: target image is not already loaded, and on-disk image mapping is disabled by policy"
                )
            )
            .ok();
            writeln!(
                w,
                "{}",
                c.dim("  Use --unsafe-map-image only if you intentionally accept mapping an untrusted image into the current process")
            )
            .ok();
        } else {
            writeln!(
                w,
                "{}",
                c.warn("In-memory image unavailable for comparison")
            )
            .ok();
        }
        return;
    }

    if edr.modified {
        writeln!(
            w,
            "{}",
            c.warn(&format!(
                "Prologue mismatch detected: {} differing byte(s) in first {} byte(s)",
                edr.diff_offsets.len(),
                edr.compared_len
            ))
        )
        .ok();
        writeln!(
            w,
            "{}",
            c.dim(&format!(
                "  Offsets: {}",
                edr.diff_offsets
                    .iter()
                    .map(|o| format!("+0x{:X}", o))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        )
        .ok();
    } else {
        writeln!(
            w,
            "{}",
            c.ok(&format!(
                "No prologue modification detected in first {} byte(s)",
                edr.compared_len
            ))
        )
        .ok();
    }

    writeln!(
        w,
        "{}",
        c.dim(&format!("  Disk: {}", hex_bytes(&edr.disk_bytes)))
    )
    .ok();
    writeln!(
        w,
        "{}",
        c.dim(&format!("  Mem : {}", hex_bytes(&edr.memory_bytes)))
    )
    .ok();
    if edr.loaded_from_memory {
        writeln!(
            w,
            "{}",
            c.warn("  Image was mapped into the current process for comparison")
        )
        .ok();
    }
}
