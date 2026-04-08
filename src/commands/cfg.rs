use std::io::Write;

use crate::analysis::cfgview::render_cfg_colored;
use crate::analysis::disasm::disassemble_at;
use crate::analysis::symbols::SymbolIndex;
use crate::analysis::thunk::{follow_jmp_thunk, ThunkResolution};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::search::find_dll_path;
use crate::formats::pdb::load_pdb_symbols;
use crate::formats::pe::{parse_pe, read_exports};

pub fn run(
    dll_arg: &str,
    func_arg: &str,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    if func_arg.is_empty() && cfg.at_rva.is_empty() && cfg.ordinal == 0 {
        return Err("cfg requires a function name, --at <rva>, or --ordinal <n>".to_owned());
    }

    let dll_path = find_dll_path(dll_arg, cfg)?;
    let dll_name = dll_path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();
    let raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let arch = cfg.effective_arch(pe.arch);
    let image_base = pe.image_base;
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
    let symbol_index = SymbolIndex::from_exports_and_pdb(&exports, &pdb_symbols, image_base);

    let (mut target_rva, resolved_name, _) = super::dump::resolve_function(
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
    )?;

    let mut followed = String::new();
    if cfg.follow_jmp {
        if let Some(thunk) = follow_jmp_thunk(&raw, &pe, target_rva) {
            match thunk {
                ThunkResolution::Direct {
                    target_rva: new_rva,
                } => {
                    followed = format!("  followed entry thunk: {}\n", new_rva);
                    target_rva = new_rva;
                }
                other => {
                    followed = format!("  entry thunk: {}\n", other.desc());
                }
            }
        }
    }

    let file_off = pe
        .rva_to_offset(target_rva)
        .ok_or_else(|| format!("RVA 0x{:08X}: not in any section", target_rva))?;
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

    writeln!(w).ok();
    writeln!(
        w,
        "{}",
        c.bold(&c.b_blue(&format!("CFG: {}!{}", dll_name, resolved_name)))
    )
    .ok();
    writeln!(
        w,
        "{}",
        c.dim(&format!(
            "  RVA: 0x{:08X}  |  VA: 0x{:X}  |  arch: x{}",
            target_rva,
            image_base + target_rva as u64,
            arch
        ))
    )
    .ok();
    if !followed.is_empty() {
        write!(w, "{}", c.dim(followed.trim_end())).ok();
        writeln!(w).ok();
    }
    let graph = render_cfg_colored(&insns, image_base, c);
    write!(w, "{}", graph).ok();
    if !graph.ends_with('\n') {
        writeln!(w).ok();
    }
    Ok(())
}
