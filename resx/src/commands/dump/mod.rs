mod execute;
#[cfg(test)]
use execute::enter_follow_chain;
pub use execute::run;

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
    hex_bytes, to_anomaly_json, to_data_summary_json, to_edr_json, to_section_json,
    to_startup_json, to_yara_json, ApiCallJson, FuncResult, InsnJson,
};
use self::switchfmt::{format_case_summary, format_target_symbol_spaced};
use crate::analysis::cfgview::{
    detect_static_hook_indicators, render_cfg_colored_with_edges, render_cfg_text_with_edges,
    RecoveredIndirectEdge,
};
use crate::analysis::disasm::{
    collect_api_calls, disassemble_at, disassemble_at_unbounded, find_string_refs, find_xrefs,
    is_ret, ApiCall, Instruction,
};
use crate::analysis::discovery::discover_functions;
use crate::analysis::edr::{check_prologue, EdrCheckResult};
use crate::analysis::indirect::analyze_indirect_flow;
use crate::analysis::intelli::{analyze_image, IntelliFinding};
use crate::analysis::ir::summarize_typed_ir;
use crate::analysis::recomp::recomp_c;
use crate::analysis::recursive_cfg::{recover_recursive_cfg, RecursiveCfgRequest};
use crate::analysis::symbols::{display_symbol_name, SymbolIndex};
use crate::analysis::thunk::{follow_jmp_thunk, ThunkResolution};
use crate::analysis::yara::scan_file;
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
    find_iat_slots_by_name, find_startup_routines, parse_pe, read_clr_info, read_data_summary,
    read_exports, read_imports, read_load_config, read_runtime_function, resolve_iat_slot, Export,
    PeFile, PeStartupRoutine, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR,
};

#[derive(Debug, Clone)]
struct RecoveredSwitchTarget {
    target_rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AddressSource {
    Rva,
    Va,
    FileOffset,
}

#[derive(Debug, Clone)]
struct ResolvedAddress {
    rva: u32,
    value: u64,
    source: AddressSource,
}

#[derive(Debug, Clone)]
struct ResolvedTarget {
    target_rva: u32,
    input_rva: u32,
    input_value: u64,
    address_source: AddressSource,
    name: String,
}

#[cfg(test)]
mod tests {
    use super::{parse_u32_literal, parse_u64_literal, resolve_address_spec, AddressSource};
    use crate::formats::pe::{PeFile, PeSection, IMAGE_SCN_MEM_EXECUTE};

    #[test]
    fn cross_image_follow_rejects_repeated_identity_and_bounds_aliases() {
        let mut chain = Vec::new();
        super::enter_follow_chain(&mut chain, "a.dll", "Entry").unwrap();
        assert!(super::enter_follow_chain(&mut chain, "A.DLL", "Entry").is_err());
        for index in 1..16 {
            super::enter_follow_chain(&mut chain, &format!("alias{index}"), "Entry").unwrap();
        }
        assert!(super::enter_follow_chain(&mut chain, "another-alias", "Entry").is_err());
    }

    fn sample_pe() -> PeFile {
        PeFile {
            arch: 64,
            machine: 0x8664,
            timestamp: 0,
            coff_characteristics: 0,
            major_linker_version: 0,
            minor_linker_version: 0,
            image_base: 0x1_8000_0000,
            entry_point: 0x1000,
            size_of_image: 0x5000,
            size_of_headers: 0x400,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            checksum: 0,
            subsystem: 0,
            dll_characteristics: 0,
            sections: vec![PeSection {
                name: ".text".to_owned(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0x400,
                raw_size: 0x1000,
                characteristics: IMAGE_SCN_MEM_EXECUTE,
                entropy: 0.0,
            }],
            data_dirs: vec![(0, 0); 16],
            anomalies: Vec::new(),
        }
    }

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

    #[test]
    fn parse_u64_literal_accepts_image_sized_addresses() {
        assert_eq!(parse_u64_literal("0x180001200"), Some(0x180001200));
    }

    #[test]
    fn resolve_address_spec_accepts_rva_va_and_file_offset() {
        let pe = sample_pe();

        let rva = resolve_address_spec("0x1200", &pe).unwrap();
        assert_eq!(rva.rva, 0x1200);
        assert_eq!(rva.source, AddressSource::Rva);

        let va = resolve_address_spec("0x180001200", &pe).unwrap();
        assert_eq!(va.rva, 0x1200);
        assert_eq!(va.source, AddressSource::Va);

        let file = resolve_address_spec("file:0x600", &pe).unwrap();
        assert_eq!(file.rva, 0x1200);
        assert_eq!(file.source, AddressSource::FileOffset);
    }

    #[test]
    fn resolve_address_spec_accepts_synthetic_sub_labels_as_rvas() {
        let pe = sample_pe();

        let sub = resolve_address_spec("sub_00001200", &pe).unwrap();
        assert_eq!(sub.rva, 0x1200);
        assert_eq!(sub.source, AddressSource::Rva);

        let func = resolve_address_spec("fn_0x00001200", &pe).unwrap();
        assert_eq!(func.rva, 0x1200);
        assert_eq!(func.source, AddressSource::Rva);
    }

    #[test]
    fn resolve_address_spec_falls_back_to_file_offset_when_rva_is_unmapped() {
        let pe = sample_pe();
        let file = resolve_address_spec("0x600", &pe).unwrap();
        assert_eq!(file.rva, 0x1200);
        assert_eq!(file.source, AddressSource::FileOffset);
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

const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;

fn managed_metadata_disassembly_note(pe: &PeFile, raw: &[u8], target_rva: u32) -> Option<String> {
    let clr = read_clr_info(pe, raw)?;
    if pe.entry_point != 0 && (clr.flags & COMIMAGE_FLAGS_ILONLY) == 0 {
        return None;
    }

    let (clr_rva, clr_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    let in_clr_header = rva_in_range(target_rva, clr_rva, clr_size);
    let in_metadata = rva_in_range(target_rva, clr.metadata_rva, clr.metadata_size);
    if !in_clr_header && !in_metadata {
        return None;
    }

    let region = if in_clr_header {
        "CLR header"
    } else {
        "CLR metadata"
    };
    Some(format!(
        "RVA 0x{target_rva:08X} is inside the {region} of an IL-only CLR image; native x64 disassembly here is metadata bytes, not executable code (CLR entry token/RVA 0x{:08X}).",
        clr.entry_point_token_or_rva
    ))
}

fn rva_in_range(rva: u32, start: u32, size: u32) -> bool {
    size != 0 && rva >= start && rva < start.saturating_add(size)
}

fn address_source_label(source: AddressSource) -> &'static str {
    match source {
        AddressSource::Rva => "RVA",
        AddressSource::Va => "VA",
        AddressSource::FileOffset => "file offset",
    }
}

fn resolve_address_target(
    raw_spec: &str,
    name_hint: &str,
    exports: &[Export],
    pdb_symbols: &[crate::formats::pdb::PdbSymbol],
    pe: &PeFile,
    raw: &[u8],
    image_base: u64,
) -> Result<ResolvedTarget, String> {
    let address = resolve_address_spec(raw_spec, pe)?;
    let target_rva = read_runtime_function(pe, raw, address.rva)
        .map(|runtime| runtime.begin_rva)
        .unwrap_or(address.rva);
    let name = if !name_hint.is_empty()
        && (synthetic_rva_literal(name_hint).is_some() || !looks_like_address_literal(name_hint))
    {
        name_hint.to_owned()
    } else {
        best_function_name_for_rva(exports, pdb_symbols, image_base, target_rva, address.rva)
    };

    Ok(ResolvedTarget {
        target_rva,
        input_rva: address.rva,
        input_value: address.value,
        address_source: address.source,
        name,
    })
}

fn resolve_address_spec(raw: &str, pe: &PeFile) -> Result<ResolvedAddress, String> {
    let synthetic = synthetic_rva_literal(raw);
    let spec = synthetic.as_deref().unwrap_or(raw);
    let (forced_source, value_text) = split_address_source_prefix(spec);
    let value =
        parse_u64_literal(value_text).ok_or_else(|| format!("invalid --at value: {}", raw))?;

    if let Some(source) = forced_source {
        return resolve_forced_address_source(raw, value, source, pe);
    }

    if let Some(rva) = pe.va_to_rva(value) {
        return Ok(ResolvedAddress {
            rva,
            value,
            source: AddressSource::Va,
        });
    }

    if let Ok(rva) = u32::try_from(value) {
        if pe.rva_to_section(rva).is_some() {
            return Ok(ResolvedAddress {
                rva,
                value,
                source: AddressSource::Rva,
            });
        }
    }

    if let Some(rva) = pe.file_offset_to_rva(value) {
        return Ok(ResolvedAddress {
            rva,
            value,
            source: AddressSource::FileOffset,
        });
    }

    Err(format!(
        "address `{raw}` did not map to a PE VA, RVA, or file offset"
    ))
}

fn resolve_forced_address_source(
    raw: &str,
    value: u64,
    source: AddressSource,
    pe: &PeFile,
) -> Result<ResolvedAddress, String> {
    let rva = match source {
        AddressSource::Rva => {
            let rva =
                u32::try_from(value).map_err(|_| format!("RVA `{raw}` is larger than 32 bits"))?;
            pe.rva_to_section(rva)
                .is_some()
                .then_some(rva)
                .ok_or_else(|| format!("RVA 0x{rva:08X}: not in any section"))?
        }
        AddressSource::Va => pe
            .va_to_rva(value)
            .ok_or_else(|| format!("VA 0x{value:X}: not in this image"))?,
        AddressSource::FileOffset => pe
            .file_offset_to_rva(value)
            .ok_or_else(|| format!("file offset 0x{value:X}: not in any section"))?,
    };

    Ok(ResolvedAddress { rva, value, source })
}

fn split_address_source_prefix(raw: &str) -> (Option<AddressSource>, &str) {
    let trimmed = raw.trim();
    let Some((prefix, value)) = trimmed.split_once(':') else {
        return (None, trimmed);
    };
    let source = match prefix.to_ascii_lowercase().as_str() {
        "rva" => AddressSource::Rva,
        "va" => AddressSource::Va,
        "fo" | "file" | "offset" | "fileoff" | "file-offset" => AddressSource::FileOffset,
        _ => return (None, trimmed),
    };
    (Some(source), value.trim())
}

fn looks_like_address_literal(raw: &str) -> bool {
    if synthetic_rva_literal(raw).is_some() {
        return true;
    }
    let (_, value) = split_address_source_prefix(raw);
    parse_u64_literal(value).is_some()
}

fn synthetic_rva_literal(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    for prefix in ["sub_", "loc_", "fn_0x", "fn_"] {
        if let Some(rest) = strip_prefix_ascii_case(trimmed, prefix) {
            let hex = rest.trim();
            if !hex.is_empty() && hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
                return Some(format!("rva:0x{hex}"));
            }
        }
    }
    None
}

fn strip_prefix_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then(|| &value[prefix.len()..])
}

#[allow(clippy::too_many_arguments)]
fn recover_reachable_function_insns(
    raw: &[u8],
    pe: &PeFile,
    start_rva: u32,
    arch: u32,
    image_base: u64,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    cfg: &Config,
) -> Option<Vec<Instruction>> {
    let section_end = pe
        .rva_to_section(start_rva)
        .map(|section| {
            section
                .virtual_address
                .saturating_add(section.virtual_size.max(section.raw_size))
        })
        .unwrap_or_else(|| start_rva.saturating_add(cfg.max_bytes.max(512) as u32));
    let function_end = read_runtime_function(pe, raw, start_rva)
        .map(|runtime| runtime.end_rva.min(section_end))
        .filter(|end| *end > start_rva)
        .unwrap_or_else(|| {
            start_rva
                .saturating_add(cfg.max_bytes.max(512) as u32)
                .min(section_end)
                .max(start_rva.saturating_add(1))
        });

    let mut queue = std::collections::VecDeque::from([start_rva]);
    let mut seen_blocks = std::collections::BTreeSet::new();
    let mut insn_by_rva = std::collections::BTreeMap::new();
    let max_blocks = cfg.max_total.max(64);
    let instruction_limit = if cfg.max_insns == 0 {
        4096
    } else {
        cfg.max_insns.clamp(1, 4096)
    };

    while let Some(block_start) = queue.pop_front() {
        if seen_blocks.len() >= max_blocks || insn_by_rva.len() >= instruction_limit {
            break;
        }
        if !seen_blocks.insert(block_start)
            || !rva_in_function_window(block_start, start_rva, function_end)
        {
            continue;
        }
        let Some(file_off) = pe.rva_to_offset(block_start) else {
            continue;
        };

        let mut local_cfg = cfg.clone();
        local_cfg.max_bytes = function_end
            .saturating_sub(block_start)
            .max(1)
            .min(cfg.max_bytes.max(512) as u32) as usize;
        local_cfg.max_insns = instruction_limit.saturating_sub(insn_by_rva.len()).max(1);

        let Ok(linear) = disassemble_at_unbounded(
            raw,
            pe,
            file_off,
            block_start,
            arch,
            image_base,
            exports,
            symbols,
            &local_cfg,
        ) else {
            continue;
        };

        let mut block = Vec::new();
        for insn in linear {
            if !rva_in_function_window(insn.rva, start_rva, function_end) {
                break;
            }
            let stop = block_terminator(&insn);
            block.push(insn);
            if stop {
                break;
            }
        }

        if block.is_empty() {
            continue;
        }

        if let Some(last) = block.last_mut() {
            if last.is_jmp {
                if let Some(target) = direct_branch_rva(last, image_base) {
                    if !rva_in_function_window(target, start_rva, function_end) {
                        append_comment(
                            &mut last.comment,
                            &format!("tail call leaves current function for rva 0x{target:08x}"),
                        );
                    }
                }
            }
        }

        enqueue_block_successors(&block, image_base, start_rva, function_end, &mut queue);
        for insn in block {
            if insn_by_rva.len() >= instruction_limit {
                break;
            }
            insn_by_rva.entry(insn.rva).or_insert(insn);
        }
    }

    (insn_by_rva.len() > 1).then(|| insn_by_rva.into_values().collect())
}

fn rva_in_function_window(rva: u32, start_rva: u32, function_end: u32) -> bool {
    rva >= start_rva && rva < function_end
}

fn block_terminator(insn: &Instruction) -> bool {
    insn.is_jcc || insn.is_jmp || is_ret(insn.iced.mnemonic())
}

fn enqueue_block_successors(
    block: &[Instruction],
    image_base: u64,
    start_rva: u32,
    function_end: u32,
    queue: &mut std::collections::VecDeque<u32>,
) {
    let Some(last) = block.last() else {
        return;
    };

    if last.is_jcc {
        if let Some(target) = direct_branch_rva(last, image_base) {
            if rva_in_function_window(target, start_rva, function_end) {
                queue.push_back(target);
            }
        }
        if let Some(fallthrough) = next_insn_rva(last) {
            if rva_in_function_window(fallthrough, start_rva, function_end) {
                queue.push_back(fallthrough);
            }
        }
        return;
    }

    if last.is_jmp {
        if let Some(target) = direct_branch_rva(last, image_base) {
            if rva_in_function_window(target, start_rva, function_end) {
                queue.push_back(target);
            }
        }
    }
}

fn direct_branch_rva(insn: &Instruction, image_base: u64) -> Option<u32> {
    (insn.call_target >= image_base).then(|| insn.call_target.wrapping_sub(image_base) as u32)
}

fn next_insn_rva(insn: &Instruction) -> Option<u32> {
    insn.rva.checked_add(insn.bytes.len() as u32)
}

fn append_comment(comment: &mut String, note: &str) {
    if !comment.is_empty() {
        comment.push_str(" | ");
    }
    comment.push_str(note);
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
    parse_u64_literal(raw).and_then(|value| u32::try_from(value).ok())
}

fn parse_u64_literal(raw: &str) -> Option<u64> {
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
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u64>().ok()
    }
}

mod presentation;
use presentation::print_intelli_findings;
pub(crate) use presentation::resolve_function;

fn print_address_resolution(w: &mut dyn Write, c: &Colors, target: &ResolvedTarget) {
    let source = address_source_label(target.address_source);
    if target.input_rva == target.target_rva {
        writeln!(
            w,
            "{}",
            c.ok(&format!(
                "{source} 0x{:X} -> RVA 0x{:08X}",
                target.input_value, target.target_rva
            ))
        )
        .ok();
    } else {
        writeln!(
            w,
            "{}",
            c.ok(&format!(
                "{source} 0x{:X} -> RVA 0x{:08X}; using containing function 0x{:08X} (+0x{:X})",
                target.input_value,
                target.input_rva,
                target.target_rva,
                target.input_rva.saturating_sub(target.target_rva)
            ))
        )
        .ok();
    }
}

fn best_function_name_for_rva(
    exports: &[Export],
    pdb_symbols: &[crate::formats::pdb::PdbSymbol],
    image_base: u64,
    function_rva: u32,
    input_rva: u32,
) -> String {
    for e in exports {
        if e.rva == function_rva {
            return e.name.clone();
        }
    }

    for sym in pdb_symbols {
        if sym.rva == function_rva {
            return display_symbol_name(&sym.name);
        }
    }

    for sym in pdb_symbols {
        if sym.kind != "function" || sym.size == 0 || sym.rva == 0 {
            continue;
        }
        let sym_size = sym.size.min(u32::MAX as u64) as u32;
        let sym_end = sym.rva.saturating_add(sym_size);
        if input_rva >= sym.rva && input_rva < sym_end {
            let name = display_symbol_name(&sym.name);
            let disp = input_rva.saturating_sub(sym.rva);
            return if disp == 0 {
                name
            } else {
                format!("{name}+0x{disp:X}")
            };
        }
    }

    let va = image_base + function_rva as u64;
    for sym in pdb_symbols {
        if sym.va == va {
            return display_symbol_name(&sym.name);
        }
    }

    format!("fn_0x{function_rva:08X}")
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
