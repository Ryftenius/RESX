use super::*;

pub(super) fn print_intelli_findings(w: &mut dyn Write, findings: &[IntelliFinding], c: &Colors) {
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
        let target = resolve_address_target(
            &cfg.at_rva,
            func_arg,
            exports,
            pdb_symbols,
            pe,
            raw,
            image_base,
        )?;
        if !cfg.quiet && !cfg.json {
            print_address_resolution(w, c, &target);
        }
        return Ok((target.target_rva, target.name, false));
    }

    if cfg.ordinal > 0 {
        for e in exports {
            if e.ordinal == cfg.ordinal {
                return Ok((e.rva, e.name.clone(), false));
            }
        }
        return Err(format!("ordinal {} not found in export table", cfg.ordinal));
    }

    if func_arg.eq_ignore_ascii_case("entry") || func_arg.eq_ignore_ascii_case(&cfg.entry_macro) {
        if pe.entry_point == 0 || pe.rva_to_offset(pe.entry_point).is_none() {
            return Err("the PE entrypoint is absent or not file-backed".to_owned());
        }
        if !cfg.quiet && !cfg.json {
            writeln!(
                w,
                "{}",
                c.info(&format!("entry => RVA 0x{:08X}", pe.entry_point))
            )
            .ok();
        }
        return Ok((pe.entry_point, "entry".to_owned(), false));
    }

    if func_arg.eq_ignore_ascii_case("rentry") || func_arg.eq_ignore_ascii_case(&cfg.rentry_macro) {
        let routines = find_startup_routines(pe, raw);
        let selected = routines
            .iter()
            .find(|routine| routine.kind == "Real Main Candidate")
            .or_else(|| {
                routines.iter().find(|routine| {
                    routine.kind == "Startup Handoff"
                        && routine.source.to_ascii_lowercase().contains("jump")
                })
            });
        let (rva, source) = selected
            .map(|routine| (routine.rva, routine.kind.as_str()))
            .unwrap_or((pe.entry_point, "PE Entry Point"));
        if rva == 0 || pe.rva_to_offset(rva).is_none() {
            return Err("RESX did not recover a file-backed real-entry candidate".to_owned());
        }
        if !cfg.quiet && !cfg.json {
            writeln!(
                w,
                "{}",
                c.info(&format!("rentry => RVA 0x{rva:08X} ({source})"))
            )
            .ok();
        }
        return Ok((rva, "rentry".to_owned(), false));
    }

    for e in exports {
        if e.name == func_arg {
            if !cfg.quiet && !cfg.json {
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

    if looks_like_address_literal(func_arg) {
        let name_hint = if synthetic_rva_literal(func_arg).is_some() {
            func_arg
        } else {
            ""
        };
        let target = resolve_address_target(
            func_arg,
            name_hint,
            exports,
            pdb_symbols,
            pe,
            raw,
            image_base,
        )?;
        if !cfg.quiet && !cfg.json {
            print_address_resolution(w, c, &target);
        }
        return Ok((target.target_rva, target.name, false));
    }

    if !cfg.no_pdb {
        if !cfg.quiet && !cfg.json {
            writeln!(w, "{}", c.info("Not found in EAT; checking PDB symbols")).ok();
        }
        if let Some(sym) = find_cached_pdb_symbol(pdb_symbols, func_arg) {
            if !cfg.quiet && !cfg.json {
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
        w.flush().ok();
        let progress = crate::core::progress::Dots::start(
            !cfg.quiet && !cfg.json && !cfg.verbose && cfg.out_file.is_empty(),
        );
        let resolved = load_pdb_symbol(
            dll_path,
            func_arg,
            &cfg.sym_path,
            &cfg.sym_server,
            &cfg.pdb_file,
            image_base,
            cfg.verbose,
            cfg.reload,
        );
        drop(progress);
        if let Some(rva) = resolved {
            if !cfg.quiet && !cfg.json {
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
        if !cfg.quiet && !cfg.json {
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

    if cfg.show_xrefs {
        if let Some(func) = crate::analysis::wdf::function_by_name(func_arg) {
            if !cfg.quiet && !cfg.json {
                writeln!(
                    w,
                    "{}",
                    c.ok(&format!(
                        "WDF!{} @ WdfFunctions[0x{:X}]  (KMDF function table)",
                        func.name,
                        func.offset(if pe.arch == 64 { 8 } else { 4 })
                    ))
                )
                .ok();
            }
            return Ok((0, func.name.to_owned(), false));
        }
    }

    let search_scope = if cfg.show_xrefs {
        "exports, PDB symbols, address literals, and import/IAT slots"
    } else {
        "exports or PDB symbols"
    };
    writeln!(
        w,
        "\n{} '{}' not found in {}",
        c.err_msg(""),
        func_arg,
        search_scope
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
        if cfg.show_xrefs {
            c.dim("  Tip: `resx iat <image>` shows imported API names; `resx syms <image>` shows PDB names; `resx dump <image> <rva> --xrefs` works for address targets.")
        } else {
            c.dim("  Tip: use --show-eat to list all exports, --ordinal N, or --at <rva>")
        }
    )
    .ok();
    if cfg.show_xrefs {
        Err(format!(
            "ERESOLVE001: target `{}` was not found in exports, PDB symbols, address literals, import/IAT slots, or known KMDF WDF table names\n  Try:\n    resx iat <image> | findstr /i {}\n    resx syms <image> | findstr /i {}\n    resx dump <image> <rva> --xrefs\n  Note: dynamically resolved APIs will not appear as import xrefs unless the resolver callsite is targeted.",
            func_arg, func_arg, func_arg
        ))
    } else {
        Err(format!("function '{}' not found", func_arg))
    }
}
