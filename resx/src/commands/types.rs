use std::collections::{HashMap, HashSet};
use std::io::Write;

use serde::Serialize;

use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::output::StageProgress;
use crate::core::search::find_dll_path;
use crate::formats::pdb::{load_pdb_symbols, load_pdb_types, PdbSymbol, PdbTypeInfo};

#[derive(Debug, Clone, Serialize)]
pub struct TypeRefJson {
    pub name: String,
    pub kind: String,
    pub rva: String,
    pub va: String,
    pub size: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeEntryJson {
    pub type_id: u32,
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub symbol_count: usize,
    pub function_count: usize,
    pub data_count: usize,
    pub members: Vec<TypeMemberJson>,
    pub refs: Vec<TypeRefJson>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeMemberJson {
    pub name: String,
    pub offset: String,
    pub kind: String,
    pub type_id: u32,
    pub type_name: String,
    pub size: u64,
}

pub fn run(
    dll_arg: &str,
    query: &str,
    cfg: &Config,
    w: &mut dyn Write,
    c: &Colors,
) -> Result<(), String> {
    let mut progress = StageProgress::new(3, !cfg.quiet && !cfg.json, c.on);
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
    progress.tick("enumerating type-backed symbols");
    let pdb_types = load_pdb_types(
        &dll_path_str,
        &cfg.sym_path,
        &cfg.sym_server,
        &cfg.pdb_file,
        cfg.verbose,
        cfg.reload,
    )?;
    progress.tick("walking pdb type information");
    progress.finish();

    let mut types = build_type_inventory(&symbols, &pdb_types);
    if !query.trim().is_empty() {
        let q = query.trim().to_ascii_lowercase();
        types.retain(|entry| {
            entry.name.eq_ignore_ascii_case(&q)
                || entry.kind.eq_ignore_ascii_case(&q)
                || entry.name.to_ascii_lowercase().contains(&q)
                || entry.members.iter().any(|m| {
                    m.name.to_ascii_lowercase().contains(&q)
                        || m.type_name.to_ascii_lowercase().contains(&q)
                })
                || entry
                    .refs
                    .iter()
                    .any(|r| r.name.to_ascii_lowercase().contains(&q))
        });
    }

    if cfg.json {
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&types).unwrap_or_default()
        )
        .ok();
        return Ok(());
    }

    writeln!(w).ok();
    writeln!(
        w,
        "{}",
        c.bold(&c.b_cyan(&format!("Types: {} ({} total)", dll_name, types.len())))
    )
    .ok();
    for entry in &types {
        writeln!(
            w,
            "  {}  [{} | {} bytes | {} symbol(s), {} function(s), {} data]",
            c.b_white(&entry.name),
            entry.kind,
            entry.size,
            entry.symbol_count,
            entry.function_count,
            entry.data_count
        )
        .ok();
        for m in entry.members.iter().take(16) {
            writeln!(
                w,
                "    +0x{:<4X}  {:<10} {:<24} {}",
                parse_offset_hex(&m.offset),
                m.kind,
                m.type_name,
                m.name
            )
            .ok();
        }
        if entry.members.len() > 16 {
            writeln!(w, "    … {} more member(s)", entry.members.len() - 16).ok();
        }
        for r in entry.refs.iter().take(12) {
            writeln!(
                w,
                "    0x{}  {:<8} {}",
                r.rva.trim_start_matches("0x"),
                r.kind,
                r.name
            )
            .ok();
        }
        if entry.refs.len() > 12 {
            writeln!(w, "    … {} more", entry.refs.len() - 12).ok();
        }
    }
    Ok(())
}

pub fn build_type_inventory(
    symbols: &[PdbSymbol],
    pdb_types: &[PdbTypeInfo],
) -> Vec<TypeEntryJson> {
    if pdb_types.is_empty() {
        return build_symbol_type_inventory(symbols);
    }
    let mut refs_by_type: HashMap<u32, Vec<&PdbSymbol>> = HashMap::new();
    let mut refs_by_name: HashMap<String, Vec<&PdbSymbol>> = HashMap::new();
    for sym in symbols {
        if sym.type_id == 0 {
            let type_name = sym.type_name.trim();
            if !type_name.is_empty() {
                push_type_name_ref(&mut refs_by_name, type_name, sym);
            }
            continue;
        }
        refs_by_type.entry(sym.type_id).or_default().push(sym);
        let type_name = sym.type_name.trim();
        if !type_name.is_empty() {
            push_type_name_ref(&mut refs_by_name, type_name, sym);
        }
    }

    let mut out = pdb_types
        .iter()
        .map(|ty| {
            let refs = collect_type_refs(ty, &refs_by_type, &refs_by_name);
            let function_count = refs.iter().filter(|s| s.kind == "function").count();
            let data_count = refs.iter().filter(|s| s.kind == "data").count();
            let refs = refs
                .into_iter()
                .map(|s| TypeRefJson {
                    name: s.name.clone(),
                    kind: s.kind.clone(),
                    rva: format!("0x{:08X}", s.rva),
                    va: format!("0x{:016X}", s.va),
                    size: s.size,
                })
                .collect::<Vec<_>>();
            TypeEntryJson {
                type_id: ty.type_id,
                name: ty.name.clone(),
                kind: ty.kind.clone(),
                size: ty.size,
                symbol_count: refs.len(),
                function_count,
                data_count,
                members: ty
                    .members
                    .iter()
                    .map(|m| TypeMemberJson {
                        name: m.name.clone(),
                        offset: format!("0x{:X}", m.offset),
                        kind: m.kind.clone(),
                        type_id: m.type_id,
                        type_name: m.type_name.clone(),
                        size: m.size,
                    })
                    .collect(),
                refs,
            }
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.type_id.cmp(&b.type_id)));
    out
}

fn build_symbol_type_inventory(symbols: &[PdbSymbol]) -> Vec<TypeEntryJson> {
    let mut by_name: HashMap<String, Vec<&PdbSymbol>> = HashMap::new();
    for sym in symbols {
        let type_name = sym.type_name.trim();
        if type_name.is_empty() {
            continue;
        }
        by_name.entry(type_name.to_owned()).or_default().push(sym);
    }
    let mut out = by_name
        .into_iter()
        .map(|(name, refs)| {
            let function_count = refs.iter().filter(|s| s.kind == "function").count();
            let data_count = refs.iter().filter(|s| s.kind == "data").count();
            let refs = refs
                .into_iter()
                .map(|s| TypeRefJson {
                    name: s.name.clone(),
                    kind: s.kind.clone(),
                    rva: format!("0x{:08X}", s.rva),
                    va: format!("0x{:016X}", s.va),
                    size: s.size,
                })
                .collect::<Vec<_>>();
            TypeEntryJson {
                type_id: 0,
                name,
                kind: "symbol".to_owned(),
                size: 0,
                symbol_count: refs.len(),
                function_count,
                data_count,
                members: Vec::new(),
                refs,
            }
        })
        .collect::<Vec<_>>();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

fn parse_offset_hex(s: &str) -> u64 {
    u64::from_str_radix(s.trim_start_matches("0x"), 16).unwrap_or(0)
}

fn push_type_name_ref<'a>(
    refs_by_name: &mut HashMap<String, Vec<&'a PdbSymbol>>,
    raw_name: &str,
    sym: &'a PdbSymbol,
) {
    let raw_key = raw_name.trim().to_ascii_lowercase();
    if !raw_key.is_empty() {
        refs_by_name.entry(raw_key).or_default().push(sym);
    }
    let canonical_key = canonical_type_name(raw_name);
    if !canonical_key.is_empty() {
        refs_by_name.entry(canonical_key).or_default().push(sym);
    }
}

fn collect_type_refs<'a>(
    ty: &PdbTypeInfo,
    refs_by_type: &'a HashMap<u32, Vec<&'a PdbSymbol>>,
    refs_by_name: &'a HashMap<String, Vec<&'a PdbSymbol>>,
) -> Vec<&'a PdbSymbol> {
    let mut refs = Vec::new();
    let mut seen = HashSet::new();

    for sym in refs_by_type
        .get(&ty.type_id)
        .into_iter()
        .flatten()
        .copied()
        .chain(
            refs_by_name
                .get(&ty.name.trim().to_ascii_lowercase())
                .into_iter()
                .flatten()
                .copied(),
        )
        .chain(
            refs_by_name
                .get(&canonical_type_name(&ty.name))
                .into_iter()
                .flatten()
                .copied(),
        )
    {
        let key = (
            sym.rva,
            sym.kind.as_str(),
            sym.name.to_ascii_lowercase(),
            sym.type_id,
        );
        if seen.insert(key) {
            refs.push(sym);
        }
    }

    refs
}

fn canonical_type_name(raw: &str) -> String {
    let mut name = raw.trim().to_owned();
    if name.is_empty() {
        return String::new();
    }

    for needle in [
        "const ",
        "volatile ",
        "struct ",
        "class ",
        "union ",
        "enum ",
        "__ptr64 ",
        "__unaligned ",
        "__restrict ",
        "__cdecl ",
        "__stdcall ",
        "__fastcall ",
        "__thiscall ",
        "__vectorcall ",
    ] {
        name = name.replace(needle, "");
    }

    loop {
        let trimmed = name.trim_end();
        let stripped = trimmed
            .strip_suffix('*')
            .or_else(|| trimmed.strip_suffix('&'))
            .map(str::trim_end)
            .map(str::to_owned)
            .or_else(|| strip_array_suffix(trimmed));
        match stripped {
            Some(next) if next != name => name = next,
            _ => break,
        }
    }

    name.trim().to_ascii_lowercase()
}

fn strip_array_suffix(raw: &str) -> Option<String> {
    let close = raw.rfind(']')?;
    if close + 1 != raw.len() {
        return None;
    }
    let open = raw[..close].rfind('[')?;
    Some(raw[..open].trim_end().to_owned())
}
