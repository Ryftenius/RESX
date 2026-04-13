use std::io::Write;

use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_items;
use crate::core::output::print_iat;
use crate::core::search::find_dll_path;
use crate::formats::pe::{parse_pe, read_imports};

pub fn run(dll_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let dll_path = find_dll_path(dll_arg, cfg)?;
    let dll_name = dll_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let imps = read_imports(&pe, &raw);

    if cfg.json {
        use serde_json::json;
        let j: Vec<_> = imps
            .iter()
            .map(|d| {
                json!({
                    "dll":     d.dll,
                    "imports": d.entries.iter().map(|e| json!({
                    "name":    e.name,
                    "ordinal": e.ordinal,
                    "hint":    e.hint,
                    "by_ord":  e.by_ord,
                    "slot_rva": format!("0x{:08X}", e.slot_rva),
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        let out = serde_json::to_string_pretty(&versioned_items("imports", j)).unwrap_or_default();
        writeln!(w, "{}", out).ok();
    } else {
        print_iat(w, &imps, &dll_name, c);
    }
    Ok(())
}
