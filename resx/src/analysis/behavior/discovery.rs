use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind};
use serde::Serialize;

use crate::analysis::symbols::{display_symbol_name, SymbolIndex};
use crate::core::config::Config;
use crate::formats::pdb::PdbSymbol;
use crate::formats::pe::{
    read_data_summary, read_runtime_functions, Export, PeFile, PeRuntimeFunctionInfo,
    PeStartupRoutine,
};

#[derive(Debug, Clone, Default, Serialize)]
pub struct FunctionDiscoveryReport {
    pub stats: FunctionDiscoveryStats,
    pub functions: Vec<DiscoveredFunction>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct FunctionDiscoveryStats {
    pub total: usize,
    pub exports: usize,
    pub pdb: usize,
    pub pdata: usize,
    pub startup: usize,
    pub call_targets: usize,
    pub data_pointers: usize,
    pub prologues: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiscoveredFunction {
    pub rva: String,
    pub va: String,
    pub name: String,
    pub size: String,
    pub source: String,
    pub kind: String,
    pub section: String,
    pub prototype: String,
    pub confidence: u8,
    pub reason: String,
    pub flags: Vec<String>,
}

#[derive(Debug, Clone)]
struct FunctionSeed {
    rva: u32,
    name: String,
    size: u64,
    source: String,
    kind: String,
    prototype: String,
    confidence: u8,
    reason: String,
    flags: BTreeSet<String>,
}

pub fn discover_functions(
    raw: &[u8],
    pe: &PeFile,
    exports: &[Export],
    symbol_index: &SymbolIndex,
    pdb_symbols: &[PdbSymbol],
    startup_routines: &[PeStartupRoutine],
    cfg: &Config,
) -> FunctionDiscoveryReport {
    let mut map: BTreeMap<u32, FunctionSeed> = BTreeMap::new();
    let mut stats = FunctionDiscoveryStats::default();

    for export in exports.iter().filter(|e| executable_rva(pe, e.rva)) {
        stats.exports += 1;
        merge_seed(
            &mut map,
            FunctionSeed {
                rva: export.rva,
                name: display_symbol_name(&export.name),
                size: 0,
                source: "export".to_owned(),
                kind: "export".to_owned(),
                prototype: String::new(),
                confidence: 95,
                reason: format!("EAT ordinal {}", export.ordinal),
                flags: BTreeSet::new(),
            },
        );
    }

    for sym in pdb_symbols
        .iter()
        .filter(|s| s.rva != 0 && s.kind == "function" && executable_rva(pe, s.rva))
    {
        stats.pdb += 1;
        merge_seed(
            &mut map,
            FunctionSeed {
                rva: sym.rva,
                name: display_symbol_name(&sym.name),
                size: sym.size,
                source: "pdb".to_owned(),
                kind: "function".to_owned(),
                prototype: sym.type_name.clone(),
                confidence: 98,
                reason: "PDB function symbol".to_owned(),
                flags: BTreeSet::new(),
            },
        );
    }

    for runtime in read_runtime_functions(pe, raw) {
        if !executable_rva(pe, runtime.begin_rva) {
            continue;
        }
        stats.pdata += 1;
        let mut flags = BTreeSet::new();
        flags.insert("unwind".to_owned());
        if runtime.exception_handler_rva != 0 {
            flags.insert("exception-handler".to_owned());
        }
        if runtime.chained_parent.is_some() {
            flags.insert("chained-unwind".to_owned());
        }
        merge_seed(
            &mut map,
            FunctionSeed {
                rva: runtime.begin_rva,
                name: best_name(symbol_index, pe, runtime.begin_rva),
                size: runtime.end_rva.saturating_sub(runtime.begin_rva) as u64,
                source: ".pdata".to_owned(),
                kind: "runtime-function".to_owned(),
                prototype: String::new(),
                confidence: 94,
                reason: format!(
                    ".pdata range 0x{:08X}..0x{:08X}",
                    runtime.begin_rva, runtime.end_rva
                ),
                flags,
            },
        );
    }

    for startup in startup_routines
        .iter()
        .filter(|s| executable_rva(pe, s.rva))
    {
        stats.startup += 1;
        let mut flags = BTreeSet::new();
        flags.insert("startup".to_owned());
        merge_seed(
            &mut map,
            FunctionSeed {
                rva: startup.rva,
                name: best_name(symbol_index, pe, startup.rva),
                size: 0,
                source: startup.source.clone(),
                kind: startup.kind.clone(),
                prototype: String::new(),
                confidence: 90,
                reason: startup.note.clone(),
                flags,
            },
        );
    }

    for target_rva in collect_direct_targets(raw, pe, cfg.max_total.max(256)) {
        stats.call_targets += 1;
        merge_seed(
            &mut map,
            FunctionSeed {
                rva: target_rva,
                name: best_name(symbol_index, pe, target_rva),
                size: 0,
                source: "direct-target".to_owned(),
                kind: "call-target".to_owned(),
                prototype: String::new(),
                confidence: 74,
                reason: "direct CALL/JMP target in executable code".to_owned(),
                flags: BTreeSet::new(),
            },
        );
    }

    let data = read_data_summary(pe, raw);
    for pointer in data.pointers.iter().filter(|p| p.kind == "code") {
        stats.data_pointers += 1;
        let mut flags = BTreeSet::new();
        flags.insert("address-taken".to_owned());
        merge_seed(
            &mut map,
            FunctionSeed {
                rva: pointer.target_rva,
                name: best_name(symbol_index, pe, pointer.target_rva),
                size: 0,
                source: pointer.section_name.clone(),
                kind: "code-pointer".to_owned(),
                prototype: String::new(),
                confidence: 62,
                reason: format!("code pointer at {}", hex32(pointer.rva)),
                flags,
            },
        );
    }

    for prologue in find_prologue_candidates(raw, pe, 256) {
        stats.prologues += 1;
        merge_seed(
            &mut map,
            FunctionSeed {
                rva: prologue,
                name: best_name(symbol_index, pe, prologue),
                size: 0,
                source: "prologue-scan".to_owned(),
                kind: "prologue".to_owned(),
                prototype: String::new(),
                confidence: 45,
                reason: "common function prologue byte pattern".to_owned(),
                flags: BTreeSet::new(),
            },
        );
    }

    let mut functions = map
        .into_values()
        .map(|seed| {
            let section = pe
                .rva_to_section(seed.rva)
                .map(|section| section.name.clone())
                .unwrap_or_default();
            DiscoveredFunction {
                rva: hex32(seed.rva),
                va: hex64(pe.image_base + seed.rva as u64),
                name: seed.name,
                size: if seed.size == 0 {
                    String::new()
                } else {
                    format!("0x{:X}", seed.size)
                },
                source: seed.source,
                kind: seed.kind,
                section,
                prototype: seed.prototype,
                confidence: seed.confidence,
                reason: seed.reason,
                flags: seed.flags.into_iter().collect(),
            }
        })
        .collect::<Vec<_>>();
    functions.sort_by(|a, b| a.rva.cmp(&b.rva));
    stats.total = functions.len();

    let mut notes = Vec::new();
    if stats.pdb == 0 {
        notes.push("PDB function symbols unavailable or disabled".to_owned());
    }
    if stats.pdata == 0 && pe.arch == 64 {
        notes.push("no x64 .pdata runtime functions were recovered".to_owned());
    }
    if stats.prologues > 0 {
        notes.push(
            "prologue hits are low-confidence hints and may include false positives".to_owned(),
        );
    }

    FunctionDiscoveryReport {
        stats,
        functions,
        notes,
    }
}

fn merge_seed(map: &mut BTreeMap<u32, FunctionSeed>, seed: FunctionSeed) {
    map.entry(seed.rva)
        .and_modify(|existing| {
            if seed.confidence > existing.confidence {
                let mut merged_flags = existing.flags.clone();
                merged_flags.extend(seed.flags.iter().cloned());
                *existing = seed.clone();
                existing.flags.extend(merged_flags);
            } else {
                existing.flags.extend(seed.flags.iter().cloned());
                if !seed.source.is_empty() && !existing.flags.contains(&seed.source) {
                    existing.flags.insert(format!("also:{}", seed.source));
                }
                if existing.prototype.is_empty() && !seed.prototype.is_empty() {
                    existing.prototype = seed.prototype.clone();
                }
                if existing.size == 0 && seed.size > 0 {
                    existing.size = seed.size;
                }
            }
        })
        .or_insert(seed);
}

fn collect_direct_targets(raw: &[u8], pe: &PeFile, max_targets: usize) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    let mut queue = VecDeque::new();
    queue.push_back(pe.entry_point);

    for section in pe.sections.iter().filter(|section| section.is_executable()) {
        queue.push_back(section.virtual_address);
    }

    let mut visited = BTreeSet::new();
    while let Some(start_rva) = queue.pop_front() {
        if out.len() >= max_targets || !visited.insert(start_rva) || !executable_rva(pe, start_rva)
        {
            continue;
        }
        let Some(file_off) = pe.rva_to_offset(start_rva) else {
            continue;
        };
        let section_limit = pe
            .rva_to_section(start_rva)
            .map(|section| {
                section
                    .virtual_address
                    .saturating_add(section.virtual_size.max(section.raw_size))
                    .saturating_sub(start_rva) as usize
            })
            .unwrap_or(4096);
        let chunk_len = section_limit
            .min(16 * 1024)
            .min(raw.len().saturating_sub(file_off));
        let mut decoder = Decoder::with_ip(
            pe.arch,
            &raw[file_off..file_off + chunk_len],
            pe.image_base + start_rva as u64,
            DecoderOptions::NONE,
        );
        let mut insn = iced_x86::Instruction::default();
        let mut decoded = 0usize;
        while decoder.can_decode() && decoded < 4096 && out.len() < max_targets {
            decoder.decode_out(&mut insn);
            if insn.is_invalid() || insn.len() == 0 {
                break;
            }
            decoded += 1;
            if matches!(insn.mnemonic(), Mnemonic::Call | Mnemonic::Jmp) {
                if let Some(target_rva) = branch_target_rva(pe, &insn) {
                    if out.insert(target_rva) && visited.len() < max_targets {
                        queue.push_back(target_rva);
                    }
                }
            }
        }
    }
    out
}

fn find_prologue_candidates(raw: &[u8], pe: &PeFile, limit: usize) -> BTreeSet<u32> {
    let mut out = BTreeSet::new();
    for section in pe.sections.iter().filter(|section| section.is_executable()) {
        let start = section.raw_offset as usize;
        let end = start
            .saturating_add(section.raw_size as usize)
            .min(raw.len());
        let mut off = start;
        while off + 4 <= end && out.len() < limit {
            let bytes = &raw[off..end.min(off + 8)];
            let is_x64_frame = bytes.starts_with(&[0x40, 0x53])
                || bytes.starts_with(&[0x48, 0x89, 0x5C])
                || bytes.starts_with(&[0x48, 0x83, 0xEC])
                || bytes.starts_with(&[0x55, 0x48, 0x8B, 0xEC]);
            let is_x86_frame =
                bytes.starts_with(&[0x55, 0x8B, 0xEC]) || bytes.starts_with(&[0x53, 0x56, 0x57]);
            if is_x64_frame || is_x86_frame {
                let rva = section.virtual_address + (off - start) as u32;
                out.insert(rva);
            }
            off += 1;
        }
    }
    out
}

fn branch_target_rva(pe: &PeFile, instr: &iced_x86::Instruction) -> Option<u32> {
    match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            let rva = pe.va_to_rva(instr.near_branch_target())?;
            executable_rva(pe, rva).then_some(rva)
        }
        _ => None,
    }
}

fn executable_rva(pe: &PeFile, rva: u32) -> bool {
    rva != 0
        && pe
            .rva_to_section(rva)
            .is_some_and(|section| section.is_executable())
}

fn best_name(symbol_index: &SymbolIndex, pe: &PeFile, rva: u32) -> String {
    let va = pe.image_base + rva as u64;
    if let Some(hit) = symbol_index.lookup(va) {
        if hit.displacement == 0 {
            return hit.symbol.name;
        }
    }
    format!("sub_{:08X}", rva)
}

fn hex32(value: u32) -> String {
    format!("0x{:08X}", value)
}

fn hex64(value: u64) -> String {
    format!("0x{:016X}", value)
}

#[allow(dead_code)]
fn runtime_size(runtime: &PeRuntimeFunctionInfo) -> u64 {
    runtime.end_rva.saturating_sub(runtime.begin_rva) as u64
}
