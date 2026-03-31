use std::io::Write;

use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::output::print_eat;
use crate::core::search::find_dll_path;
use crate::formats::pe::{parse_pe, read_exports};

pub fn run(dll_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let dll_path = find_dll_path(dll_arg, cfg)?;
    let _path_str = dll_path.to_string_lossy();
    let dll_name = dll_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let exports = read_exports(&pe, &raw);

    if cfg.json {
        use serde_json::json;
        let j: Vec<_> = exports
            .iter()
            .map(|e| {
                json!({
                    "name":       e.name,
                    "ordinal":    e.ordinal,
                    "rva":        format!("0x{:08X}", e.rva),
                    "forward_to": e.forward_to,
                })
            })
            .collect();
        let out = serde_json::to_string_pretty(&j).unwrap_or_default();
        writeln!(w, "{}", out).ok();
    } else {
        print_eat(w, &exports, &dll_name, c);
    }
    Ok(())
}
