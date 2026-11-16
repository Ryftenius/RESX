//! Preserve dump's reachable-function policy independently of presentation.
use super::*;
use crate::analysis::disasm::{
    disassemble_at_unbounded_with_options, disassemble_at_with_options, is_ret,
};
use crate::analysis::options::{DecodeOptions, MAX_FUNCTION_INSNS};
use crate::formats::pe::{read_runtime_function, Export, PeFile};

pub fn decode_function(
    session: &AnalysisSession<'_>,
    request: &FunctionRequest<'_>,
    symbols: &SymbolIndex,
) -> Result<Vec<Instruction>, String> {
    if !matches!(request.arch, 32 | 64) {
        return Err("function analysis requires x86 or x64 decoding".into());
    }
    let facts = session.image();
    let pe = facts.pe();
    let file_off = pe
        .rva_to_offset(request.rva)
        .ok_or_else(|| format!("RVA 0x{:08X}: not in any section", request.rva))?;
    let mut insns = match recover_reachable_function_insns(
        facts.raw(),
        pe,
        request.rva,
        request.arch,
        pe.image_base,
        facts.exports(),
        Some(symbols),
        &request.options,
    ) {
        Some(insns) => insns,
        None => disassemble_at_with_options(
            facts.raw(),
            pe,
            file_off,
            request.rva,
            request.arch,
            pe.image_base,
            facts.exports(),
            Some(symbols),
            &request.options.decode,
        )?,
    };
    crate::analysis::disasm::annotate_syscall_numbers(&mut insns);
    if request.ssa {
        crate::analysis::reconstruction::dataflow::annotate(&mut insns, request.arch);
    }
    Ok(insns)
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
    options: &TraversalOptions,
) -> Option<Vec<Instruction>> {
    let cfg = &options.decode;
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

    let extent_known = read_runtime_function(pe, raw, start_rva).is_some();
    let mut queue = std::collections::VecDeque::from([start_rva]);
    let mut seen_blocks = std::collections::BTreeSet::new();
    let mut insn_by_rva = std::collections::BTreeMap::new();
    let (instruction_limit, max_blocks) = function_budgets(cfg, options.max_total, extent_known);

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

        let mut local_cfg = *cfg;
        local_cfg.max_bytes = function_end
            .saturating_sub(block_start)
            .max(1)
            .min(cfg.max_bytes.max(512) as u32) as usize;
        local_cfg.max_insns = instruction_limit.saturating_sub(insn_by_rva.len()).max(1);

        let Ok(linear) = disassemble_at_unbounded_with_options(
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

/// Instruction and basic-block limits for one function. A function with a known
/// unwind extent is decoded whole unless the caller set an explicit budget; `0`
/// means unlimited. Every case stays within [`MAX_FUNCTION_INSNS`].
fn function_budgets(cfg: &DecodeOptions, max_total: usize, extent_known: bool) -> (usize, usize) {
    let whole = (cfg.whole_function && extent_known) || cfg.max_insns == 0;
    let instructions = if whole {
        MAX_FUNCTION_INSNS
    } else {
        cfg.max_insns.clamp(1, MAX_FUNCTION_INSNS)
    };
    // Every block holds at least one instruction, so the instruction limit also
    // bounds the block count when the block budget does not apply.
    let blocks = if whole || max_total == 0 {
        instructions
    } else {
        max_total.max(64)
    };
    (instructions, blocks)
}

/// Reachable instructions of the function at `start_rva`, bounded by its unwind
/// extent when one exists. `None` when fewer than two instructions decode.
#[allow(clippy::too_many_arguments)]
pub fn decode_reachable_function(
    raw: &[u8],
    pe: &PeFile,
    start_rva: u32,
    arch: u32,
    image_base: u64,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    options: &TraversalOptions,
) -> Option<Vec<Instruction>> {
    if !matches!(arch, 32 | 64) {
        return None;
    }
    let mut insns = recover_reachable_function_insns(
        raw, pe, start_rva, arch, image_base, exports, symbols, options,
    )?;
    crate::analysis::disasm::annotate_syscall_numbers(&mut insns);
    Some(insns)
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
