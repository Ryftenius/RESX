use std::io::Write;

use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::output::StageProgress;
use crate::core::search::find_dll_path;
use crate::formats::pdb::load_pdb_symbols;

pub fn run(dll_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let mut progress = StageProgress::new(2, !cfg.quiet && !cfg.json, c.on);
    let dll_path = find_dll_path(dll_arg, cfg)?;
    progress.tick("locating target image");
    let dll_name = dll_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();

    let symbols = load_pdb_symbols(
        &dll_path_str,
        &cfg.sym_path,
        &cfg.sym_server,
        &cfg.pdb_file,
        cfg.verbose,
        cfg.reload,
    )?;
    progress.tick("enumerating symbols");
    progress.finish();

    if cfg.json {
        use serde_json::json;
        let out: Vec<_> = symbols
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "rva": format!("0x{:08X}", s.rva),
                    "va": format!("0x{:016X}", s.va),
                    "kind": s.kind,
                    "type_name": s.type_name,
                    "size": s.size,
                })
            })
            .collect();
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&out).unwrap_or_default()
        )
        .ok();
    } else {
        writeln!(w).ok();
        writeln!(
            w,
            "{}",
            c.bold(&c.b_cyan(&format!("Symbols: {} ({} total)", dll_name, symbols.len())))
        )
        .ok();
        for sym in symbols {
            let suffix = if sym.type_name.is_empty() {
                String::new()
            } else {
                format!("  ({})", sym.type_name)
            };
            writeln!(
                w,
                "  0x{:08X}  0x{:016X}  {:<8} {}{}",
                sym.rva,
                sym.va,
                sym.kind,
                c.b_white(&sym.name),
                suffix
            )
            .ok();
        }
    }
    Ok(())
}
