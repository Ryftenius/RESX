use std::io::Write;

use crate::analysis::reconstruct::{reconstruct_image, render_ascii, PdbInfo};
use crate::analysis::symbols::SymbolIndex;
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use crate::core::search::find_dll_path;
use crate::formats::pdb::load_pdb_symbols;
use crate::formats::pe::{find_startup_routines, parse_pe, read_exports};

pub fn run(dll_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    if dll_arg.is_empty() {
        return Err(
            "Use `resx reconstruct-cfg <dll>` or `resx <dll> --reconstruct-cfg`".to_owned(),
        );
    }

    let dll_path = find_dll_path(dll_arg, cfg)?;
    let dll_name = dll_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();

    if !cfg.quiet && !cfg.json {
        writeln!(
            w,
            "{}",
            c.info(&format!(
                "Reconstructing startup flow for {}...",
                dll_path.display()
            ))
        )
        .ok();
    }

    let raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let arch = cfg.effective_arch(pe.arch);
    let exports = read_exports(&pe, &raw);
    let (pdb_symbols, pdb_info) = if cfg.no_pdb {
        (Vec::new(), PdbInfo::disabled())
    } else {
        match load_pdb_symbols(
            &dll_path_str,
            &cfg.sym_path,
            &cfg.sym_server,
            &cfg.pdb_file,
            cfg.verbose,
            cfg.reload,
        ) {
            Ok(symbols) => {
                let info = PdbInfo::loaded(&symbols);
                (symbols, info)
            }
            Err(err) => {
                if cfg.verbose && !cfg.quiet && !cfg.json {
                    writeln!(w, "{}", c.dim(&format!("PDB symbols unavailable: {}", err))).ok();
                }
                (Vec::new(), PdbInfo::unavailable(err))
            }
        }
    };
    let symbol_index = SymbolIndex::from_exports_and_pdb(&exports, &pdb_symbols, pe.image_base);
    let startup_routines = find_startup_routines(&pe, &raw);

    let report = reconstruct_image(
        &dll_name,
        &dll_path_str,
        &raw,
        &pe,
        &exports,
        &symbol_index,
        &pdb_symbols,
        pdb_info,
        &startup_routines,
        arch,
        cfg,
    );

    if cfg.json {
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&versioned_object("reconstruct_cfg", &report))
                .unwrap_or_default()
        )
        .ok();
    } else {
        write!(w, "{}", render_ascii(&report, c, cfg)).ok();
    }

    Ok(())
}
