//! Function bodies for whole-image resolution analysis.
//!
//! x64 bodies come from `.pdata`, with chained unwind fragments folded back into the
//! function that owns them (MSVC shrink-wrapping splits one function across several
//! entries). Leaf functions have no unwind data, and x86 images have none at all, so
//! direct call targets, tail-call targets and code pointers seed further bodies that
//! are decoded by a linear sweep bounded by their forward branches.

use std::collections::{BTreeMap, HashMap, VecDeque};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction, OpKind, Register};

use crate::formats::pe::{read_exports, read_runtime_functions, read_tls_info, PeFile};

/// Upper bound on the bodies one image contributes, so a hostile image cannot make
/// discovery unbounded.
const MAX_FUNCTIONS: usize = 200_000;
/// Instructions decoded for one body without unwind bounds.
const MAX_SWEEP_INSNS: usize = 16_384;

pub(super) struct Function {
    pub rva: u32,
    /// `[start, end)` RVA ranges in address order; more than one for chained fragments.
    pub ranges: Vec<(u32, u32)>,
}

impl Function {
    pub fn contains(&self, rva: u32) -> bool {
        self.ranges
            .iter()
            .any(|&(start, end)| start <= rva && rva < end)
    }
}

pub(super) fn decode(pe: &PeFile, raw: &[u8], function: &Function) -> Vec<Instruction> {
    let mut out = Vec::new();
    for &(start, end) in &function.ranges {
        decode_range(pe, raw, start, end, &mut out);
    }
    out
}

fn decode_range(pe: &PeFile, raw: &[u8], start: u32, end: u32, out: &mut Vec<Instruction>) {
    let Some(bytes) = pe.rva_bytes(raw, start) else {
        return;
    };
    let len = (end.saturating_sub(start) as usize).min(bytes.len());
    let mut decoder = Decoder::with_ip(
        pe.arch,
        &bytes[..len],
        pe.image_base + u64::from(start),
        DecoderOptions::NONE,
    );
    let mut insn = Instruction::default();
    while decoder.can_decode() {
        decoder.decode_out(&mut insn);
        if insn.is_invalid() {
            break;
        }
        out.push(insn);
    }
}

pub(super) fn discover(pe: &PeFile, raw: &[u8]) -> Vec<Function> {
    let mut known: BTreeMap<u32, Function> = BTreeMap::new();

    // Each .pdata entry either begins a function or continues one through its chain.
    let runtime = read_runtime_functions(pe, raw);
    let parents: HashMap<u32, u32> = runtime
        .iter()
        .filter_map(|entry| {
            entry
                .chained_parent
                .as_ref()
                .map(|parent| (entry.begin_rva, parent.begin_rva))
        })
        .collect();
    let root_of = |mut rva: u32| {
        for _ in 0..16 {
            match parents.get(&rva) {
                Some(&parent) if parent != rva => rva = parent,
                _ => break,
            }
        }
        rva
    };
    for entry in &runtime {
        if !is_code(pe, entry.begin_rva) {
            continue;
        }
        let root = root_of(entry.begin_rva);
        known
            .entry(root)
            .or_insert_with(|| Function {
                rva: root,
                ranges: Vec::new(),
            })
            .ranges
            .push((entry.begin_rva, entry.end_rva));
    }
    for function in known.values_mut() {
        function.ranges.sort_unstable();
        function.ranges.dedup();
    }

    let mut seeds: VecDeque<u32> = VecDeque::new();
    seeds.push_back(pe.entry_point);
    seeds.extend(read_exports(pe, raw).iter().map(|export| export.rva));
    if let Some(tls) = read_tls_info(pe, raw) {
        seeds.extend(tls.callbacks.iter().map(|callback| callback.rva));
    }
    let mut scanned: Vec<u32> = known.keys().copied().collect();

    while known.len() < MAX_FUNCTIONS {
        // Bodies decoded so far yield more seeds; seeds yield more bodies.
        if let Some(rva) = scanned.pop() {
            if let Some(function) = known.get(&rva) {
                for insn in decode(pe, raw, function) {
                    for target in code_references(pe, &insn) {
                        if !function.contains(target) {
                            seeds.push_back(target);
                        }
                    }
                }
            }
            continue;
        }
        let Some(seed) = seeds.pop_front() else {
            break;
        };
        if !is_code(pe, seed) || covered(&known, seed) {
            continue;
        }
        let end = sweep_end(pe, raw, seed, &known);
        if end > seed {
            known.insert(
                seed,
                Function {
                    rva: seed,
                    ranges: vec![(seed, end)],
                },
            );
            scanned.push(seed);
        }
    }
    known.into_values().collect()
}

fn is_code(pe: &PeFile, rva: u32) -> bool {
    rva != 0
        && pe
            .rva_to_section(rva)
            .is_some_and(|section| section.is_executable())
}

fn covered(known: &BTreeMap<u32, Function>, rva: u32) -> bool {
    known
        .range(..=rva)
        .next_back()
        .is_some_and(|(_, function)| function.contains(rva))
}

/// Call and tail-call targets plus code addresses taken as data (thread routines,
/// callbacks), as RVAs inside executable sections.
fn code_references(pe: &PeFile, insn: &Instruction) -> Vec<u32> {
    let mut out = Vec::new();
    let to_rva = |va: u64| -> Option<u32> {
        let rva = u32::try_from(va.checked_sub(pe.image_base)?).ok()?;
        is_code(pe, rva).then_some(rva)
    };
    match insn.flow_control() {
        FlowControl::Call | FlowControl::UnconditionalBranch
            if matches!(
                insn.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) =>
        {
            out.extend(to_rva(insn.near_branch_target()));
        }
        _ => {}
    }
    if insn.mnemonic() == iced_x86::Mnemonic::Lea
        && matches!(insn.memory_base(), Register::RIP | Register::EIP)
    {
        out.extend(to_rva(insn.ip_rel_memory_address()));
    }
    if pe.arch == 32 {
        for op in 0..insn.op_count() {
            if insn.op_kind(op) == OpKind::Immediate32 {
                out.extend(to_rva(u64::from(insn.immediate32())));
            }
        }
    }
    out
}

/// End of a body that has no unwind data: the first terminator past every forward
/// branch seen so far, the next known function, or an undecodable byte.
fn sweep_end(pe: &PeFile, raw: &[u8], start: u32, known: &BTreeMap<u32, Function>) -> u32 {
    let Some(bytes) = pe.rva_bytes(raw, start) else {
        return start;
    };
    let next_known = known
        .range(start + 1..)
        .next()
        .map_or(u32::MAX, |(&rva, _)| rva);
    let limit = (next_known.saturating_sub(start) as usize).min(bytes.len());
    let base_va = pe.image_base + u64::from(start);
    let mut decoder = Decoder::with_ip(pe.arch, &bytes[..limit], base_va, DecoderOptions::NONE);
    let mut insn = Instruction::default();
    let mut furthest = base_va;
    let mut count = 0usize;
    while decoder.can_decode() && count < MAX_SWEEP_INSNS {
        decoder.decode_out(&mut insn);
        count += 1;
        if insn.is_invalid() {
            return (insn.ip() - pe.image_base) as u32;
        }
        let next = insn.next_ip();
        let flow = insn.flow_control();
        if matches!(
            flow,
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) && matches!(
            insn.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ) {
            let target = insn.near_branch_target();
            if target > insn.ip() && target - base_va < 0x10000 {
                furthest = furthest.max(target);
            }
        }
        let terminates = matches!(
            flow,
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::Exception
        );
        if terminates && next > furthest {
            return (next - pe.image_base) as u32;
        }
    }
    (decoder.ip() - pe.image_base) as u32
}
