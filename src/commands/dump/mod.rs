mod json;

use iced_x86::{Mnemonic, OpKind, Register};
use std::io::Write;
use std::sync::OnceLock;

use self::json::{
    hex_bytes, to_anomaly_json, to_edr_json, to_section_json, to_yara_json, ApiCallJson,
    FuncResult, InsnJson,
};
use crate::analysis::cfgview::{
    detect_static_hook_indicators, render_cfg_colored_with_edges, render_cfg_text_with_edges,
    RecoveredIndirectEdge,
};
use crate::analysis::disasm::{
    collect_api_calls, disassemble_at, find_string_refs, find_xrefs, ApiCall, Instruction,
};
use crate::analysis::edr::{check_prologue, EdrCheckResult};
use crate::analysis::intelli::{analyze_image, IntelliFinding};
use crate::analysis::recomp::recomp_c;
use crate::analysis::symbols::SymbolIndex;
use crate::analysis::thunk::{follow_jmp_thunk, ThunkResolution};
use crate::analysis::yara::scan_file;
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::output::{
    print_c_recomp, print_eat, print_iat, print_insns, print_pe_anomalies, print_sections,
    print_yara_matches, StageProgress,
};
use crate::core::search::find_dll_path;
use crate::formats::pdb::{load_pdb_symbol, load_pdb_symbols};
use crate::formats::pe::{parse_pe, read_exports, read_imports, Export};

#[derive(Debug, Clone)]
struct RecoveredSwitchTarget {
    target_rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
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

    if !cfg.quiet {
        writeln!(w, "{}", c.info(&format!("Searching for '{}'...", dll_arg))).ok();
    }
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

    if !cfg.quiet {
        writeln!(w, "{}", c.info("Parsing export table...")).ok();
    }
    let exports = read_exports(&pe, &raw);
    progress.tick("reading export table");
    if !cfg.quiet && !exports.is_empty() {
        writeln!(w, "{}", c.ok(&format!("Found {} exports", exports.len()))).ok();
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
                sections: pe.sections.iter().map(to_section_json).collect(),
                yara_matches: yara_matches.iter().map(to_yara_json).collect(),
                size_bytes: 0,
                insn_count: 0,
                pdb_loaded: !pdb_symbols.is_empty(),
                followed_jmp: String::new(),
                instructions: Vec::new(),
                xrefs: Vec::new(),
                strings: Vec::new(),
                intelli_findings: metadata_intelli,
                recomp: String::new(),
                cfg: String::new(),
                hook_indicators: Vec::new(),
                edrchk: None,
                api_calls: Vec::new(),
            };
            let json = serde_json::to_string_pretty(&result).unwrap_or_default();
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

    if !cfg.no_pdb && !cfg.quiet {
        writeln!(
            w,
            "{}",
            c.info(
                "Symbols: local cache first, then configured paths, then Microsoft symbol server"
            )
        )
        .ok();
    }

    if !cfg.quiet {
        writeln!(
            w,
            "{}",
            c.info(&format!(
                "Disassembling from RVA 0x{:08X} (file offset 0x{:X})...",
                target_rva, file_off
            ))
        )
        .ok();
    }

    let insns = disassemble_at(
        &raw,
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
        print_insns(w, &insns, cfg, c);
        writeln!(
            w,
            "{}",
            c.ok(&format!(
                "Done: {} instructions, ~{} bytes",
                insns.len(),
                func_size_bytes
            ))
        )
        .ok();
    }

    let switch_semantics = recovered_switch
        .as_ref()
        .and_then(|_| load_switch_semantics(&resolved_name));

    if !cfg.json {
        if let Some(dispatch) = recovered_switch.as_ref() {
            print_switch_map(w, dispatch, switch_semantics.as_ref(), c);
        }
    }

    if let Some(edr) = &edr_result {
        print_edr_report(w, edr, c);
    }

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
    if want_hookchk && !cfg.json {
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

    let xrefs = if cfg.show_xrefs {
        let x = find_xrefs(&insns, &exports, image_base);
        if !cfg.json {
            writeln!(w, "{}", c.bold("\nCall Targets (xrefs out):")).ok();
            if x.is_empty() {
                writeln!(w, "{}", c.dim("  (none)")).ok();
            }
            for r in &x {
                writeln!(w, "  {}", c.cyan(r)).ok();
            }
        }
        x
    } else {
        Vec::new()
    };
    if cfg.show_xrefs {
        progress.tick("collecting call targets");
    }

    let str_refs = if cfg.show_strings {
        let s = find_string_refs(&raw, &pe, &insns);
        if !cfg.json {
            writeln!(w, "{}", c.bold("\nString References:")).ok();
            if s.is_empty() {
                writeln!(w, "{}", c.dim("  (none)")).ok();
            }
            for r in &s {
                writeln!(w, "  {}", c.green(r)).ok();
            }
        }
        s
    } else {
        Vec::new()
    };
    if cfg.show_strings {
        progress.tick("finding string references");
    }

    let api_calls = if cfg.funcs_depth > 0 {
        let calls = collect_api_calls(&insns, &pe, &raw, &symbol_index, image_base);
        if !cfg.json {
            print_api_calls(
                w,
                &calls,
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
        progress.tick("building API call map");
        calls
    } else {
        Vec::new()
    };

    let intelli_findings = if want_intelli {
        let findings = analyze_image(&raw, &imports, Some(&insns));
        if !cfg.json {
            print_intelli_findings(w, &findings, c);
        }
        findings
    } else {
        Vec::new()
    };
    if want_intelli && !only_metadata {
        progress.tick("running Intelli triage");
    }

    let recomp_str = if want_recomp {
        let exp = Export {
            name: resolved_name.clone(),
            ordinal: 0,
            rva: target_rva,
            forward_to: String::new(),
        };
        let s = recomp_c(&insns, &exp, arch, image_base, Some(&symbol_index), cfg);
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
        if cfg.recomp && !cfg.json {
            writeln!(w, "\n{}", c.bold(&c.b_mag("C Reconstruction Preview:"))).ok();
            print_c_recomp(w, &s, c);
        }
        s
    } else {
        String::new()
    };
    if want_recomp {
        progress.tick("reconstructing C output");
    }

    let cfg_text = if want_cfg {
        let plain = render_cfg_text_with_edges(&insns, image_base, &recovered_cfg_edges);
        if !cfg.json {
            writeln!(w, "\n{}", c.bold(&c.b_blue("Control Flow Graph:"))).ok();
            let colored =
                render_cfg_colored_with_edges(&insns, image_base, c, &recovered_cfg_edges);
            write!(w, "{}", colored).ok();
            if !colored.ends_with('\n') {
                writeln!(w).ok();
            }
        }
        plain
    } else {
        String::new()
    };
    if want_cfg {
        progress.tick("building control-flow graph");
    }

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
            sections: pe.sections.iter().map(to_section_json).collect(),
            yara_matches: yara_matches.iter().map(to_yara_json).collect(),
            size_bytes: func_size_bytes,
            insn_count: insns.len(),
            pdb_loaded,
            followed_jmp: followed_desc,
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
                .map(|ac| ApiCallJson {
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
                })
                .collect(),
        };
        let json = serde_json::to_string_pretty(&result).unwrap_or_default();
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

/// 5-color DLL palette — excludes b_yellow/yellow (CALL/JMP), b_mag (Nt*/Zw*),
/// and b_white (named internals) so each role stays visually distinct.
fn dll_palette(c: &Colors, idx: usize, s: &str) -> String {
    match idx % 5 {
        0 => c.cyan(s),
        1 => c.green(s),
        2 => c.magenta(s),
        3 => c.b_cyan(s),
        _ => c.b_blue(s),
    }
}

/// True for Nt*/Zw* Windows native-API names (syscall stubs, lowest UM layer).
fn is_nt_api(label: &str) -> bool {
    (label.starts_with("Nt") || label.starts_with("Zw"))
        && label
            .as_bytes()
            .get(2)
            .is_some_and(|b| b.is_ascii_uppercase())
}

/// Color the mnemonic: CALL → b_yellow, JMP → yellow  (matches disasm listing).
fn color_kind(kind: &str, c: &Colors) -> String {
    if kind == "call" {
        c.b_yellow("CALL")
    } else {
        c.yellow("JMP")
    }
}

fn short_dll_name(name: &str) -> &str {
    name.strip_suffix(".dll")
        .or_else(|| name.strip_suffix(".DLL"))
        .unwrap_or(name)
}

/// Colour a call target:
///   Nt*/Zw* (any origin) → b_red    — syscall stub, highest visual priority; tag becomes [syscall]
///   IAT import           → dim(dll.dll!) + palette-color(FuncName), one shade per DLL
///   Named internal       → b_white   — resolved known symbol
///   sub_XXXXXXXX         → yellow    — anonymous, address-only
///   Indirect (call rax)  → dim       — unresolvable
fn color_target(
    call: &ApiCall,
    c: &Colors,
    dll_map: &mut std::collections::HashMap<String, usize>,
) -> String {
    let nt = is_nt_api(&call.label);
    if call.is_import {
        let dll_name = short_dll_name(&call.dll);
        let key = dll_name.to_ascii_lowercase();
        let n = dll_map.len();
        let idx = *dll_map.entry(key).or_insert(n);
        let func = if nt {
            c.b_red(&call.label)
        } else {
            dll_palette(c, idx, &call.label)
        };
        format!("{}{}", c.dim(&format!("{}!", dll_name)), func)
    } else if call.is_indirect {
        c.dim(&call.label)
    } else if nt {
        c.b_red(&call.label)
    } else if call.label.starts_with("sub_") {
        c.yellow(&call.label)
    } else {
        c.b_white(&call.label)
    }
}

#[allow(clippy::too_many_arguments)]
fn print_api_calls(
    w: &mut dyn Write,
    calls: &[ApiCall],
    insns: &[Instruction],
    func_name: &str,
    c: &Colors,
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    symbol_index: &crate::analysis::symbols::SymbolIndex,
    exports: &[Export],
    arch: u32,
    image_base: u64,
    cfg: &Config,
    root_rva: u32,
) {
    writeln!(w).ok();
    writeln!(
        w,
        "{}",
        c.bold(&c.b_cyan(&format!(
            "API Call Map for {}  [{} call site(s)]:",
            func_name,
            calls.len()
        )))
    )
    .ok();

    if calls.is_empty() {
        writeln!(w, "{}", c.dim("  (no CALL/JMP targets found)")).ok();
        return;
    }

    let mut visited = std::collections::HashSet::new();
    visited.insert(root_rva);
    // Shared DLL→color-index map so every level uses the same shade per DLL.
    let mut dll_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let root_image = TraceImageView {
        raw,
        pe,
        symbol_index,
        exports,
        arch,
        image_base,
    };

    print_calls_recursive(
        w,
        calls,
        insns,
        c,
        &root_image,
        cfg,
        0,
        &mut visited,
        &mut dll_map,
        "  ",
    );
}

struct TraceImageView<'a> {
    raw: &'a [u8],
    pe: &'a crate::formats::pe::PeFile,
    symbol_index: &'a crate::analysis::symbols::SymbolIndex,
    exports: &'a [Export],
    arch: u32,
    image_base: u64,
}

struct LoadedTraceImage {
    dll_name: String,
    dll_path: String,
    raw: Vec<u8>,
    pe: crate::formats::pe::PeFile,
    exports: Vec<Export>,
    symbol_index: crate::analysis::symbols::SymbolIndex,
    arch: u32,
    image_base: u64,
}

impl LoadedTraceImage {
    fn as_view(&self) -> TraceImageView<'_> {
        TraceImageView {
            raw: &self.raw,
            pe: &self.pe,
            symbol_index: &self.symbol_index,
            exports: &self.exports,
            arch: self.arch,
            image_base: self.image_base,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn print_calls_recursive(
    w: &mut dyn Write,
    calls: &[ApiCall],
    insns: &[Instruction],
    c: &Colors,
    image: &TraceImageView<'_>,
    cfg: &Config,
    depth: u32,
    visited: &mut std::collections::HashSet<u32>,
    dll_map: &mut std::collections::HashMap<String, usize>,
    line_prefix: &str,
) {
    let last = calls.len().saturating_sub(1);
    for (i, call) in calls.iter().enumerate() {
        let is_last = i == last;
        let branch = if is_last { "└──" } else { "├──" };
        let syscall_target = resolve_syscall_trace_target(call, insns, cfg);

        let can_recurse = !call.is_import
            && !call.is_indirect
            && call.target_rva != 0
            && depth + 1 < cfg.funcs_depth
            && !visited.contains(&call.target_rva);
        let can_recurse_syscall = depth + 1 < cfg.funcs_depth && syscall_target.is_some();

        let nt = is_nt_api(&call.label);
        let tag = match (call.is_import, call.is_indirect, call.kind.as_str(), nt) {
            (true, _, "jmp", true) => c.dim(" [syscall] [tail call]"),
            (true, _, _, true) => c.dim(" [syscall]"),
            (true, _, "jmp", false) => c.dim(" [import · tail call]"),
            (true, _, _, false) => c.dim(" [import]"),
            (_, true, _, _) => c.dim(" [indirect]"),
            (_, _, "jmp", _) => c.dim(" [tail call]"),
            _ => c.dim(" [internal]"),
        };

        let colored_target = color_target(call, c, dll_map);

        writeln!(
            w,
            "{}{} {}  {}  {}{}",
            line_prefix,
            branch,
            c.dim(&format!("0x{:X}", call.rva)),
            color_kind(&call.kind, c),
            colored_target,
            tag,
        )
        .ok();

        if let Some(target) = syscall_target.as_ref() {
            let detail_prefix = format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
            writeln!(
                w,
                "{}{} {}!{}",
                detail_prefix,
                c.dim("kernel:"),
                c.cyan(short_dll_name(&target.image.dll_name)),
                c.b_red(&target.symbol_name),
            )
            .ok();
            if !target.classes.is_empty() {
                let classes = target
                    .classes
                    .iter()
                    .map(|v| format_class_value(*v))
                    .collect::<Vec<_>>()
                    .join("|");
                writeln!(
                    w,
                    "{}{} {}",
                    detail_prefix,
                    c.dim("class :"),
                    c.b_white(&classes)
                )
                .ok();
            }
        }

        if can_recurse {
            if let Some(file_off) = image.pe.rva_to_offset(call.target_rva) {
                visited.insert(call.target_rva);
                let mut sub_cfg = cfg.clone();
                sub_cfg.max_insns = sub_cfg.max_insns.min(300);
                if let Ok(sub_insns) = disassemble_at(
                    image.raw,
                    file_off,
                    call.target_rva,
                    image.arch,
                    image.image_base,
                    image.exports,
                    Some(image.symbol_index),
                    &sub_cfg,
                ) {
                    let sub_calls = collect_api_calls(
                        &sub_insns,
                        image.pe,
                        image.raw,
                        image.symbol_index,
                        image.image_base,
                    );
                    if !sub_calls.is_empty() {
                        let child_prefix =
                            format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
                        print_calls_recursive(
                            w,
                            &sub_calls,
                            &sub_insns,
                            c,
                            image,
                            cfg,
                            depth + 1,
                            visited,
                            dll_map,
                            &child_prefix,
                        );
                    }
                }
            }
        } else if can_recurse_syscall {
            let target = syscall_target.unwrap();
            if let Some(file_off) = target.image.pe.rva_to_offset(target.rva) {
                let mut sub_cfg = cfg.clone();
                sub_cfg.max_insns = sub_cfg.max_insns.min(300);
                if let Ok(sub_insns) = disassemble_at(
                    &target.image.raw,
                    file_off,
                    target.rva,
                    target.image.arch,
                    target.image.image_base,
                    &target.image.exports,
                    Some(&target.image.symbol_index),
                    &sub_cfg,
                ) {
                    let sub_calls = collect_api_calls(
                        &sub_insns,
                        &target.image.pe,
                        &target.image.raw,
                        &target.image.symbol_index,
                        target.image.image_base,
                    );
                    if !sub_calls.is_empty() {
                        let child_prefix =
                            format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
                        let kernel_view = target.image.as_view();
                        print_calls_recursive(
                            w,
                            &sub_calls,
                            &sub_insns,
                            c,
                            &kernel_view,
                            cfg,
                            depth + 1,
                            visited,
                            dll_map,
                            &child_prefix,
                        );
                    }
                }
            }
        }
    }
}

struct SyscallTraceTarget {
    image: LoadedTraceImage,
    rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
}

fn resolve_syscall_trace_target(
    call: &ApiCall,
    insns: &[Instruction],
    cfg: &Config,
) -> Option<SyscallTraceTarget> {
    if !call.is_import || !is_nt_api(&call.label) {
        return None;
    }
    let dll = call.dll.to_ascii_lowercase();
    if !dll.eq("ntdll.dll") && !dll.eq("ntdll") {
        return None;
    }

    for kernel_name in [
        "ntoskrnl.exe",
        "ntkrnlmp.exe",
        "ntkrnlpa.exe",
        "ntkrpamp.exe",
    ] {
        let Some(image) = load_trace_image(kernel_name, cfg) else {
            continue;
        };
        if let Some((rva, symbol_name)) = resolve_kernel_symbol(&image, &call.label, cfg) {
            if let Some(dispatch) = resolve_syscall_dispatch_target(call, insns, &image, rva, cfg) {
                return Some(SyscallTraceTarget {
                    image,
                    rva: dispatch.rva,
                    symbol_name: dispatch.symbol_name,
                    classes: dispatch.classes,
                });
            }
            return Some(SyscallTraceTarget {
                image,
                rva,
                symbol_name,
                classes: Vec::new(),
            });
        }
    }

    None
}

fn load_trace_image(name: &str, cfg: &Config) -> Option<LoadedTraceImage> {
    let dll_path = find_dll_path(name, cfg).ok()?;
    let dll_name = dll_path.file_name()?.to_string_lossy().to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();
    let raw = std::fs::read(&dll_path).ok()?;
    let pe = parse_pe(&raw).ok()?;
    let exports = read_exports(&pe, &raw);
    let pdb_symbols = if cfg.no_pdb {
        Vec::new()
    } else {
        load_pdb_symbols(
            &dll_path_str,
            &cfg.sym_path,
            &cfg.sym_server,
            &cfg.pdb_file,
            cfg.verbose,
            cfg.reload,
        )
        .unwrap_or_default()
    };
    let symbol_index = SymbolIndex::from_exports_and_pdb(&exports, &pdb_symbols, pe.image_base);

    Some(LoadedTraceImage {
        dll_name,
        dll_path: dll_path_str,
        arch: pe.arch,
        image_base: pe.image_base,
        raw,
        pe,
        exports,
        symbol_index,
    })
}

fn resolve_kernel_symbol(
    image: &LoadedTraceImage,
    name: &str,
    cfg: &Config,
) -> Option<(u32, String)> {
    for candidate in kernel_name_candidates(name) {
        if let Some(export) = image
            .exports
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(&candidate))
        {
            return Some((export.rva, export.name.clone()));
        }
        if !cfg.no_pdb {
            if let Some(rva) = load_pdb_symbol(
                &image.dll_path,
                &candidate,
                &cfg.sym_path,
                &cfg.sym_server,
                &cfg.pdb_file,
                image.image_base,
                cfg.verbose,
                cfg.reload,
            ) {
                return Some((rva, candidate));
            }
        }
    }
    None
}

fn kernel_name_candidates(name: &str) -> Vec<String> {
    let mut out = vec![name.to_owned()];
    if let Some(rest) = name.strip_prefix("Nt") {
        out.push(format!("Zw{}", rest));
    } else if let Some(rest) = name.strip_prefix("Zw") {
        out.push(format!("Nt{}", rest));
    }
    out
}

struct SyscallDispatchTarget {
    rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
}

fn resolve_syscall_dispatch_target(
    call: &ApiCall,
    caller_insns: &[Instruction],
    kernel_image: &LoadedTraceImage,
    syscall_rva: u32,
    cfg: &Config,
) -> Option<SyscallDispatchTarget> {
    if !call.label.eq_ignore_ascii_case("NtQuerySystemInformation")
        && !call.label.eq_ignore_ascii_case("ZwQuerySystemInformation")
    {
        return None;
    }

    let class_values =
        infer_immediate_arg_values(caller_insns, call.rva, Register::ECX, Register::RCX);
    if class_values.is_empty() {
        return None;
    }

    let file_off = kernel_image.pe.rva_to_offset(syscall_rva)?;
    let mut sub_cfg = cfg.clone();
    sub_cfg.max_insns = 96;
    let syscall_insns = disassemble_at(
        &kernel_image.raw,
        file_off,
        syscall_rva,
        kernel_image.arch,
        kernel_image.image_base,
        &kernel_image.exports,
        Some(&kernel_image.symbol_index),
        &sub_cfg,
    )
    .ok()?;

    let dispatcher = parse_qsi_dispatcher(&syscall_insns)?;
    let mut resolved: Vec<(u32, String, Vec<u32>)> = Vec::new();
    for &class_value in &class_values {
        if let Some(target_rva) = resolve_dispatch_rva(kernel_image, &dispatcher, class_value) {
            let name = kernel_symbol_name(kernel_image, target_rva);
            if let Some((_, _, classes)) =
                resolved.iter_mut().find(|(rva, _, _)| *rva == target_rva)
            {
                classes.push(class_value);
            } else {
                resolved.push((target_rva, name, vec![class_value]));
            }
        }
    }

    if resolved.is_empty() {
        return None;
    }

    let (rva, symbol_name, classes) = resolved[0].clone();
    Some(SyscallDispatchTarget {
        rva,
        symbol_name,
        classes,
    })
}

#[derive(Debug, Clone, Copy)]
struct QsiDispatcher {
    class_bias: u32,
    max_index: u32,
    index_table_rva: u32,
    target_table_rva: u32,
}

fn parse_qsi_dispatcher(insns: &[Instruction]) -> Option<QsiDispatcher> {
    let mut class_bias = None;
    let mut max_index = None;
    let mut index_table_rva = None;
    let mut target_table_rva = None;
    let mut saw_jump = false;

    for insn in insns {
        let iced = &insn.iced;
        if let Some(bias) = extract_lea_sub_bias(iced) {
            class_bias = Some(bias);
        }
        if iced.mnemonic() == Mnemonic::Cmp
            && iced.op0_kind() == OpKind::Register
            && iced.op0_register() == Register::EAX
        {
            max_index = immediate_value(iced);
        }
        if let Some(index_rva) = extract_index_table_rva(iced) {
            index_table_rva = Some(index_rva);
        }
        if let Some(target_rva) = extract_target_table_rva(iced) {
            target_table_rva = Some(target_rva);
        }
        if iced.mnemonic() == Mnemonic::Jmp && iced.op0_kind() == OpKind::Register {
            saw_jump = true;
        }
    }

    if !saw_jump {
        return None;
    }

    Some(QsiDispatcher {
        class_bias: class_bias?,
        max_index: max_index?,
        index_table_rva: index_table_rva?,
        target_table_rva: target_table_rva?,
    })
}

fn extract_lea_sub_bias(instr: &iced_x86::Instruction) -> Option<u32> {
    if instr.mnemonic() == Mnemonic::Lea
        && instr.op0_kind() == OpKind::Register
        && matches!(instr.op0_register(), Register::EAX | Register::RAX)
        && instr.op1_kind() == OpKind::Memory
        && matches!(instr.memory_base(), Register::RCX | Register::ECX)
        && instr.memory_index() == Register::None
    {
        let disp = instr.memory_displacement64() as i64;
        if disp < 0 {
            return Some((-disp) as u32);
        }
    }
    if instr.mnemonic() == Mnemonic::Sub
        && instr.op0_kind() == OpKind::Register
        && matches!(instr.op0_register(), Register::EAX | Register::RAX)
    {
        return immediate_value(instr);
    }
    None
}

fn extract_index_table_rva(instr: &iced_x86::Instruction) -> Option<u32> {
    if instr.mnemonic() != Mnemonic::Movzx
        || instr.op0_kind() != OpKind::Register
        || instr.op1_kind() != OpKind::Memory
    {
        return None;
    }
    if instr.op0_register() != Register::EAX
        || instr.memory_base() != Register::RCX
        || instr.memory_index() != Register::RAX
    {
        return None;
    }
    Some(instr.memory_displacement64() as u32)
}

fn extract_target_table_rva(instr: &iced_x86::Instruction) -> Option<u32> {
    if instr.mnemonic() != Mnemonic::Mov
        || instr.op0_kind() != OpKind::Register
        || instr.op1_kind() != OpKind::Memory
    {
        return None;
    }
    if instr.memory_base() != Register::RCX
        || instr.memory_index() != Register::RAX
        || instr.memory_index_scale() != 4
    {
        return None;
    }
    Some(instr.memory_displacement64() as u32)
}

fn resolve_dispatch_rva(
    image: &LoadedTraceImage,
    dispatcher: &QsiDispatcher,
    class_value: u32,
) -> Option<u32> {
    let adjusted = class_value.checked_sub(dispatcher.class_bias)?;
    if adjusted > dispatcher.max_index {
        return None;
    }

    let index_off = image
        .pe
        .rva_to_offset(dispatcher.index_table_rva.checked_add(adjusted)?)?;
    let slot_index = *image.raw.get(index_off)? as u32;
    let target_slot_rva = dispatcher
        .target_table_rva
        .checked_add(slot_index.checked_mul(4)?)?;
    let target_off = image.pe.rva_to_offset(target_slot_rva)?;
    let bytes = image.raw.get(target_off..target_off + 4)?;
    let target_rva = u32::from_le_bytes(bytes.try_into().ok()?);
    if target_rva == 0 {
        return None;
    }
    Some(target_rva)
}

fn kernel_symbol_name(image: &LoadedTraceImage, target_rva: u32) -> String {
    let target_va = image.image_base + target_rva as u64;
    if let Some(hit) = image.symbol_index.lookup(target_va) {
        if hit.displacement == 0 {
            return hit.symbol.name;
        }
        return format!("{}+0x{:X}", hit.symbol.name, hit.displacement);
    }
    format!("sub_{:08X}", target_rva)
}

fn infer_immediate_arg_values(
    insns: &[Instruction],
    call_rva: u32,
    arg32: Register,
    arg64: Register,
) -> Vec<u32> {
    let Some(pos) = insns.iter().position(|insn| insn.rva == call_rva) else {
        return Vec::new();
    };
    let mut values = Vec::new();

    for insn in insns[..pos].iter().rev().take(16) {
        match insn.iced.mnemonic() {
            Mnemonic::Mov => {
                if insn.iced.op0_kind() == OpKind::Register {
                    let dst = insn.iced.op0_register();
                    if dst == arg32 || dst == arg64 {
                        if let Some(value) = immediate_value(&insn.iced) {
                            values.push(value);
                        } else {
                            break;
                        }
                    }
                }
            }
            Mnemonic::Xor => {
                if insn.iced.op0_kind() == OpKind::Register
                    && insn.iced.op1_kind() == OpKind::Register
                    && insn.iced.op0_register() == insn.iced.op1_register()
                {
                    let dst = insn.iced.op0_register();
                    if dst == arg32 || dst == arg64 {
                        values.push(0);
                    }
                }
            }
            Mnemonic::Jne
            | Mnemonic::Je
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe => {}
            _ => {}
        }
    }

    values.sort_unstable();
    values.dedup();
    values
}

fn immediate_value(instr: &iced_x86::Instruction) -> Option<u32> {
    match instr.op1_kind() {
        OpKind::Immediate8 => Some(instr.immediate8to32() as u32),
        OpKind::Immediate16 => Some(instr.immediate16() as u32),
        OpKind::Immediate32 => Some(instr.immediate32()),
        OpKind::Immediate32to64 => Some(instr.immediate32to64() as u32),
        OpKind::Immediate64 => Some(instr.immediate64() as u32),
        _ => None,
    }
}

fn format_class_value(value: u32) -> String {
    format!("0x{:X}", value)
}

fn best_symbol_name_for_rva(
    symbol_index: &SymbolIndex,
    image_base: u64,
    rva: u32,
) -> Option<String> {
    let va = image_base + rva as u64;
    let hit = symbol_index.lookup(va)?;
    if hit.displacement == 0 {
        return Some(hit.symbol.name);
    }
    Some(format!("{}+0x{:X}", hit.symbol.name, hit.displacement))
}

fn recover_local_switch_dispatch(
    insns: &[Instruction],
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    symbol_index: &SymbolIndex,
    image_base: u64,
) -> Option<RecoveredSwitchDispatch> {
    let dispatcher = parse_qsi_dispatcher(insns)?;
    let mut grouped: std::collections::BTreeMap<u32, Vec<u32>> = std::collections::BTreeMap::new();

    for class_value in
        dispatcher.class_bias..=dispatcher.class_bias.saturating_add(dispatcher.max_index)
    {
        let Some(target_rva) = resolve_dispatch_rva_local(raw, pe, &dispatcher, class_value) else {
            continue;
        };
        grouped.entry(target_rva).or_default().push(class_value);
    }

    let targets = grouped
        .into_iter()
        .map(|(target_rva, classes)| RecoveredSwitchTarget {
            target_rva,
            symbol_name: best_symbol_name_for_rva(symbol_index, image_base, target_rva)
                .unwrap_or_else(|| format!("sub_{:08X}", target_rva)),
            classes,
        })
        .collect();

    Some(RecoveredSwitchDispatch {
        dispatcher,
        targets,
    })
}

fn resolve_dispatch_rva_local(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    dispatcher: &QsiDispatcher,
    class_value: u32,
) -> Option<u32> {
    let adjusted = class_value.checked_sub(dispatcher.class_bias)?;
    if adjusted > dispatcher.max_index {
        return None;
    }

    let index_off = pe.rva_to_offset(dispatcher.index_table_rva.checked_add(adjusted)?)?;
    let slot_index = *raw.get(index_off)? as u32;
    let target_slot_rva = dispatcher
        .target_table_rva
        .checked_add(slot_index.checked_mul(4)?)?;
    let target_off = pe.rva_to_offset(target_slot_rva)?;
    let bytes = raw.get(target_off..target_off + 4)?;
    let target_rva = u32::from_le_bytes(bytes.try_into().ok()?);
    if target_rva == 0 {
        return None;
    }
    Some(target_rva)
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

fn print_switch_map(
    w: &mut dyn Write,
    dispatch: &RecoveredSwitchDispatch,
    semantics: Option<&SwitchSemanticInfo>,
    c: &Colors,
) {
    writeln!(w, "\n{}", c.bold(&c.b_mag("Switch Map:"))).ok();
    if let Some(sem) = semantics {
        writeln!(
            w,
            "  {} {}",
            c.dim("Selector :"),
            c.cyan(&format!(
                "{} ({})",
                sem.selector_param.name, sem.selector_enum.type_name
            )),
        )
        .ok();
        writeln!(
            w,
            "  {} {}",
            c.dim("Params   :"),
            c.cyan(&sem.params.len().to_string())
        )
        .ok();
        let params = sem
            .params
            .iter()
            .map(|p| format!("{} {}", p.type_name, p.name))
            .collect::<Vec<_>>()
            .join(", ");
        if !params.is_empty() {
            writeln!(w, "  {} {}", c.dim("Prototype:"), c.b_white(&params)).ok();
        }
    }
    writeln!(
        w,
        "  {} {}  {} {}  {} {}",
        c.dim("Bias     :"),
        c.cyan(&format_class_value(dispatch.dispatcher.class_bias)),
        c.dim("Max      :"),
        c.cyan(&format_class_value(dispatch.dispatcher.max_index)),
        c.dim("Targets  :"),
        c.cyan(&dispatch.targets.len().to_string())
    )
    .ok();
    writeln!(
        w,
        "  {} {}",
        c.dim("Remap    :"),
        c.cyan(&format!(
            "RVA 0x{:08X}",
            dispatch.dispatcher.index_table_rva
        )),
    )
    .ok();
    writeln!(
        w,
        "  {} {}",
        c.dim("Table    :"),
        c.cyan(&format!(
            "RVA 0x{:08X}",
            dispatch.dispatcher.target_table_rva
        ))
    )
    .ok();
    writeln!(w).ok();
    for target in &dispatch.targets {
        writeln!(
            w,
            "  {}  {}",
            c.b_white(&target.symbol_name),
            c.dim(&format!("[RVA 0x{:08X}]", target.target_rva))
        )
        .ok();
        let case_text =
            format_case_values_with_names(&target.classes, semantics.map(|s| &s.selector_enum));
        for (idx, line) in wrap_cases(&case_text, 96).iter().enumerate() {
            let prefix = if idx == 0 {
                "    When  : "
            } else {
                "            "
            };
            writeln!(w, "{}{}", prefix, c.cyan(line)).ok();
        }
        writeln!(w).ok();
    }
}

fn format_case_summary(classes: &[u32]) -> String {
    let preview = summarize_case_values(classes, 4);
    format!("{} case(s): {}", classes.len(), preview)
}

fn format_case_values(classes: &[u32]) -> String {
    let mut parts = Vec::new();
    let mut i = 0usize;
    while i < classes.len() {
        let start = classes[i];
        let mut end = start;
        while i + 1 < classes.len() && classes[i + 1] == end + 1 {
            i += 1;
            end = classes[i];
        }
        if start == end {
            parts.push(format_class_value(start));
        } else {
            parts.push(format!(
                "{}..{}",
                format_class_value(start),
                format_class_value(end)
            ));
        }
        i += 1;
    }
    parts.join(", ")
}

fn format_case_values_with_names(classes: &[u32], header_enum: Option<&HeaderEnum>) -> String {
    let Some(header_enum) = header_enum else {
        return format_case_values(classes);
    };

    let mut parts = Vec::new();
    let mut i = 0usize;
    while i < classes.len() {
        let value = classes[i];
        if let Some(name) = header_enum.members.get(&value) {
            parts.push(format!("{} ({})", name, format_class_value(value)));
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
                parts.push(format_class_value(start));
            } else {
                parts.push(format!(
                    "{}..{}",
                    format_class_value(start),
                    format_class_value(end)
                ));
            }
            i += 1;
        }
    }
    parts.join(", ")
}

fn summarize_case_values(classes: &[u32], limit: usize) -> String {
    let values = format_case_values(classes);
    let parts: Vec<&str> = values.split(", ").collect();
    if parts.len() <= limit {
        values
    } else {
        format!(
            "{}, +{} more",
            parts[..limit].join(", "),
            parts.len() - limit
        )
    }
}

fn wrap_cases(s: &str, width: usize) -> Vec<String> {
    if s.len() <= width {
        return vec![s.to_owned()];
    }
    let mut out = Vec::new();
    let mut current = String::new();
    for part in s.split(", ") {
        let candidate_len = if current.is_empty() {
            part.len()
        } else {
            current.len() + 2 + part.len()
        };
        if !current.is_empty() && candidate_len > width {
            out.push(current);
            current = part.to_owned();
        } else {
            if !current.is_empty() {
                current.push_str(", ");
            }
            current.push_str(part);
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
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
    let value = value_str.trim().parse::<u32>().ok()?;
    Some((name, value))
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
    _pe: &crate::formats::pe::PeFile,
    _raw: &[u8],
    dll_path: &str,
    image_base: u64,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(u32, String, bool), String> {
    if !cfg.at_rva.is_empty() {
        let rva_str = cfg.at_rva.trim_start_matches("0x");
        let rva = u32::from_str_radix(rva_str, 16)
            .map_err(|_| format!("invalid --at value: {}", cfg.at_rva))?;
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
