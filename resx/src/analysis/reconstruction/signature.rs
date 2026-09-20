//! Bounded ABI evidence. Inferred prototypes describe observed uses, not source types.
use std::collections::{BTreeMap, VecDeque};

use iced_x86::{FlowControl, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register};
use serde::Serialize;

use crate::analysis::disasm::Instruction;

const MAX_INSTRUCTIONS: usize = 4096;
const MAX_STEPS: usize = 16384;
const MAX_ARGS: usize = 16;

#[derive(Clone, Debug, Serialize)]
pub struct Parameter {
    pub index: usize,
    pub location: String,
    pub inferred_type: String,
    pub pointer_read: bool,
    pub pointer_write: bool,
    pub widths: Vec<usize>,
    pub floating_point: bool,
    pub evidence_rvas: Vec<u32>,
}

#[derive(Debug, Serialize)]
pub struct FunctionSignature {
    pub prototype: String,
    pub source: &'static str,
    pub confidence: &'static str,
    pub calling_convention: &'static str,
    #[serde(rename = "inferred_return_type")]
    pub return_type: String,
    #[serde(rename = "inferred_parameters")]
    pub parameters: Vec<Parameter>,
    pub argument_count_complete: bool,
    pub instructions_visited: usize,
    pub analysis_truncated: bool,
    pub unresolved_flow: bool,
    pub notes: Vec<String>,
}

mod state;
use state::*;

pub fn infer(
    insns: &[Instruction],
    entry: u32,
    arch: u32,
    name: &str,
    pdb: &str,
) -> FunctionSignature {
    let mut params: Vec<_> = (0..MAX_ARGS)
        .map(|index| Parameter {
            index,
            location: if arch == 64 && index < 4 {
                ["RCX/XMM0", "RDX/XMM1", "R8/XMM2", "R9/XMM3"][index].into()
            } else {
                format!(
                    "entry-SP+0x{:X}",
                    if arch == 64 {
                        0x28 + index.saturating_sub(4) * 8
                    } else {
                        4 + index * 4
                    }
                )
            },
            inferred_type: "unknown".into(),
            pointer_read: false,
            pointer_write: false,
            widths: Vec::new(),
            floating_point: false,
            evidence_rvas: Vec::new(),
        })
        .collect();
    let map: BTreeMap<_, _> = insns
        .iter()
        .take(MAX_INSTRUCTIONS)
        .map(|i| (i.rva, i))
        .collect();
    let mut initial = State {
        sp: Some(0),
        ..State::default()
    };
    if arch == 64 {
        for (n, r) in [Register::RCX, Register::RDX, Register::R8, Register::R9]
            .iter()
            .enumerate()
        {
            initial.regs.insert(
                *r,
                Value {
                    origins: 1 << n,
                    ..Value::default()
                },
            );
        }
        for (n, r) in [
            Register::XMM0,
            Register::XMM1,
            Register::XMM2,
            Register::XMM3,
        ]
        .iter()
        .enumerate()
        {
            initial.regs.insert(
                r.full_register(),
                Value {
                    origins: 1 << n,
                    ..Value::default()
                },
            );
        }
    }
    for n in if arch == 64 { 4 } else { 0 }..MAX_ARGS {
        let offset = if arch == 64 {
            0x28 + (n - 4) * 8
        } else {
            4 + n * 4
        };
        initial.stack.insert(
            offset as i64,
            Value {
                origins: 1 << n,
                ..Value::default()
            },
        );
    }
    let mut states = BTreeMap::from([(entry, initial)]);
    let mut queue = VecDeque::from([entry]);
    let mut factory = InstructionInfoFactory::new();
    let mut returns = BTreeMap::new();
    let mut visited = std::collections::BTreeSet::new();
    let mut steps = 0;
    let mut unresolved = false;
    while let Some(rva) = queue.pop_front() {
        if steps == MAX_STEPS {
            break;
        }
        steps += 1;
        let Some(row) = map.get(&rva) else {
            unresolved = true;
            continue;
        };
        visited.insert(rva);
        let ins = &row.iced;
        let mut state = states[&rva].clone();
        let info = factory.info(ins);
        let zero = matches!(
            ins.mnemonic(),
            Mnemonic::Xor | Mnemonic::Sub | Mnemonic::Pxor | Mnemonic::Xorps | Mnemonic::Xorpd
        ) && ins.op0_kind() == OpKind::Register
            && ins.op1_kind() == OpKind::Register
            && ins.op0_register() == ins.op1_register();
        if !zero {
            for used in info.used_registers() {
                if read(used.access()) {
                    let value = reg_value(&state, used.register());
                    let scalar_float = match ins.mnemonic() {
                        Mnemonic::Movss
                        | Mnemonic::Addss
                        | Mnemonic::Subss
                        | Mnemonic::Mulss
                        | Mnemonic::Divss
                        | Mnemonic::Comiss
                        | Mnemonic::Ucomiss => 4,
                        Mnemonic::Movsd
                        | Mnemonic::Addsd
                        | Mnemonic::Subsd
                        | Mnemonic::Mulsd
                        | Mnemonic::Divsd
                        | Mnemonic::Comisd
                        | Mnemonic::Ucomisd => 8,
                        _ => 0,
                    };
                    let float_use = scalar_float > 0 && used.register().is_xmm();
                    record(
                        &mut params,
                        value.origins,
                        if float_use {
                            scalar_float
                        } else if value.origin_width > 0 {
                            value.origin_width.min(used.register().size())
                        } else if ins.mnemonic() == Mnemonic::Lea
                            && ins.op0_register().size() < used.register().size()
                        {
                            ins.op0_register().size()
                        } else {
                            used.register().size()
                        },
                        rva,
                        false,
                        false,
                    );
                    if float_use {
                        for p in &mut params {
                            if value.origins & (1 << p.index) != 0 {
                                p.floating_point = true;
                            }
                        }
                    }
                }
            }
        }
        for mem in info.used_memory() {
            let origins = reg_value(&state, mem.base()).origins;
            record(
                &mut params,
                origins,
                0,
                rva,
                read(mem.access()),
                write(mem.access()),
            );
        }
        let address = stack_address(&state, ins);
        let is_move = matches!(
            ins.mnemonic(),
            Mnemonic::Mov
                | Mnemonic::Movzx
                | Mnemonic::Movsx
                | Mnemonic::Movsxd
                | Mnemonic::Movss
                | Mnemonic::Movsd
                | Mnemonic::Movaps
                | Mnemonic::Movups
        );
        let mut produced = Value::default();
        if ins.op0_kind() == OpKind::Register {
            produced.width = ins.op0_register().size();
            if matches!(
                ins.mnemonic(),
                Mnemonic::Movss
                    | Mnemonic::Addss
                    | Mnemonic::Subss
                    | Mnemonic::Mulss
                    | Mnemonic::Divss
            ) {
                produced.width = 4;
                produced.float = true;
            }
            if matches!(
                ins.mnemonic(),
                Mnemonic::Movsd
                    | Mnemonic::Addsd
                    | Mnemonic::Subsd
                    | Mnemonic::Mulsd
                    | Mnemonic::Divsd
            ) {
                produced.width = 8;
                produced.float = true;
            }
            if is_move && !zero {
                let source = if ins.op1_kind() == OpKind::Register {
                    reg_value(&state, ins.op1_register())
                } else if ins.op1_kind() == OpKind::Memory {
                    address
                        .and_then(|a| state.stack.get(&a).copied())
                        .filter(|v| v.width == 0 || v.width >= ins.memory_size().size())
                        .unwrap_or_default()
                } else {
                    Value::default()
                };
                produced.origins = source.origins;
                produced.origin_width = if source.origin_width > 0 {
                    source.origin_width
                } else if ins.op1_kind() == OpKind::Memory {
                    ins.memory_size().size()
                } else if produced.float {
                    produced.width
                } else {
                    ins.op1_register().size()
                };
                produced.pointer =
                    source.pointer && produced.width == if arch == 64 { 8 } else { 4 };
                produced.stack_addr = source.stack_addr;
                // Extension operations preserve input provenance, but not pointer identity.
                record(
                    &mut params,
                    source.origins,
                    if ins.op1_kind() == OpKind::Memory {
                        ins.memory_size().size()
                    } else if produced.float {
                        produced.width
                    } else {
                        ins.op1_register().size()
                    },
                    rva,
                    false,
                    false,
                );
            }
        }
        if ins.mnemonic() == Mnemonic::Lea && (ins.is_ip_rel_memory_operand() || address.is_some())
        {
            produced.pointer = produced.width == if arch == 64 { 8 } else { 4 };
            produced.stack_addr = address;
        }
        if ins.op0_kind() == OpKind::Memory {
            if let Some(a) = address {
                let size = ins.memory_size().size() as i64;
                state
                    .stack
                    .retain(|k, _| *k >= a.saturating_add(size) || k.saturating_add(8) <= a);
                if is_move && ins.op1_kind() == OpKind::Register && state.stack.len() < 64 {
                    let mut value = reg_value(&state, ins.op1_register());
                    value.width = ins.memory_size().size();
                    state.stack.insert(a, value);
                }
            } else {
                // Unknown stores can alias tracked spills.
                state.stack.clear();
            }
        }
        if (matches!(
            info.op0_access(),
            OpAccess::CondWrite | OpAccess::ReadCondWrite
        ) || matches!(
            ins.mnemonic(),
            Mnemonic::Cmova
                | Mnemonic::Cmovae
                | Mnemonic::Cmovb
                | Mnemonic::Cmovbe
                | Mnemonic::Cmove
                | Mnemonic::Cmovg
                | Mnemonic::Cmovge
                | Mnemonic::Cmovl
                | Mnemonic::Cmovle
                | Mnemonic::Cmovne
                | Mnemonic::Cmovno
                | Mnemonic::Cmovnp
                | Mnemonic::Cmovns
                | Mnemonic::Cmovo
                | Mnemonic::Cmovp
                | Mnemonic::Cmovs
        )) && ins.op0_kind() == OpKind::Register
        {
            let old = reg_value(&state, ins.op0_register());
            produced.origins |= old.origins;
            if old.width != produced.width || old.float != produced.float {
                produced.width = 0;
            }
            produced.pointer &= old.pointer;
            if produced.stack_addr != old.stack_addr {
                produced.stack_addr = None;
            }
        }
        for used in info.used_registers() {
            if write(used.access()) {
                state.regs.remove(&used.register().full_register());
            }
        }
        if ins.op0_kind() == OpKind::Register && write(info.op0_access()) {
            state
                .regs
                .insert(ins.op0_register().full_register(), produced);
        }
        let slot = if arch == 64 { 8 } else { 4 };
        match ins.mnemonic() {
            Mnemonic::Push => state.sp = state.sp.and_then(|s| s.checked_sub(slot)),
            Mnemonic::Pop => state.sp = state.sp.and_then(|s| s.checked_add(slot)),
            Mnemonic::Mov
                if ins.op0_register().full_register() == Register::RBP
                    && ins.op1_register().full_register() == Register::RSP =>
            {
                state.bp = state.sp
            }
            Mnemonic::Add | Mnemonic::Sub
                if ins.op0_register().full_register() == Register::RSP
                    && ins.op1_kind() != OpKind::Register
                    && ins.op1_kind() != OpKind::Memory =>
            {
                let delta = ins.immediate(1) as i64;
                state.sp = state.sp.and_then(|s| {
                    if ins.mnemonic() == Mnemonic::Sub {
                        s.checked_sub(delta)
                    } else {
                        s.checked_add(delta)
                    }
                });
            }
            _ => {
                if info
                    .used_registers()
                    .iter()
                    .any(|r| write(r.access()) && r.register().full_register() == Register::RSP)
                {
                    state.sp = None;
                }
                if info
                    .used_registers()
                    .iter()
                    .any(|r| write(r.access()) && r.register().full_register() == Register::RBP)
                {
                    state.bp = None;
                }
            }
        }
        let next = rva.checked_add(ins.len() as u32);
        let target = ins
            .near_branch_target()
            .checked_sub(row.va.saturating_sub(row.rva as u64))
            .and_then(|r| u32::try_from(r).ok());
        let mut successors = Vec::new();
        match ins.flow_control() {
            FlowControl::Return => {
                let scalar = reg_value(&state, Register::RAX);
                let vector = reg_value(&state, Register::XMM0);
                returns.insert(
                    rva,
                    if vector.float && scalar.width == 0 {
                        vector
                    } else if scalar.width != 0 && vector.width == 0 {
                        scalar
                    } else {
                        Value::default()
                    },
                );
            }
            FlowControl::UnconditionalBranch => successors.extend(target),
            FlowControl::ConditionalBranch => {
                successors.extend(target);
                successors.extend(next);
            }
            FlowControl::Call | FlowControl::IndirectCall => {
                for r in [
                    Register::RAX,
                    Register::RCX,
                    Register::RDX,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                    Register::XMM0,
                    Register::XMM1,
                    Register::XMM2,
                    Register::XMM3,
                    Register::XMM4,
                    Register::XMM5,
                ] {
                    state.regs.remove(&r.full_register());
                }
                state.stack.clear();
                successors.extend(next);
            }
            FlowControl::Next => successors.extend(next),
            _ => unresolved = true,
        }
        for successor in successors {
            if !map.contains_key(&successor) {
                unresolved = true;
                continue;
            }
            if let Some(old) = states.get_mut(&successor) {
                if merge(old, &state) {
                    queue.push_back(successor);
                }
            } else {
                states.insert(successor, state.clone());
                queue.push_back(successor);
            }
        }
    }
    let truncated = insns.len() > MAX_INSTRUCTIONS || steps >= MAX_STEPS;
    let return_value = returns.values().next().copied().filter(|v| {
        returns
            .values()
            .all(|x| x.width == v.width && x.float == v.float && x.pointer == v.pointer)
    });
    let return_type = if unresolved || truncated {
        "unknown".into()
    } else {
        return_value
            .map(|v| {
                if v.pointer {
                    "void *".into()
                } else {
                    type_name(v.width, v.float)
                }
            })
            .unwrap_or_else(|| "unknown".into())
    };
    let last = params.iter().rposition(|p| !p.evidence_rvas.is_empty());
    params.truncate(last.map_or(0, |i| i + 1));
    for p in &mut params {
        p.inferred_type = if p.pointer_write {
            "void *".into()
        } else if p.pointer_read {
            "const void *".into()
        } else if p.widths.len() == 1 {
            type_name(p.widths[0], p.floating_point)
        } else {
            "unknown".into()
        };
    }
    let compact_stack_abi = arch == 64
        && params.len() >= 6
        && params[..4].iter().all(|p| p.evidence_rvas.is_empty())
        && params[4..].iter().all(|p| !p.evidence_rvas.is_empty());
    if compact_stack_abi {
        params.drain(..4);
        for (index, parameter) in params.iter_mut().enumerate() {
            parameter.index = index;
        }
    }
    let convention = if compact_stack_abi {
        "x64 stack-argument ABI candidate"
    } else if arch == 64 {
        "win64 ABI candidate"
    } else {
        "x86 convention unresolved"
    };
    let args = params
        .iter()
        .map(|p| format!("{} arg{}", p.inferred_type, p.index + 1))
        .collect::<Vec<_>>()
        .join(", ");
    let has_pdb = pdb.contains('(') && pdb.contains(')');
    // Contiguous observed stack arguments justify a clean prototype, but
    // static analysis still cannot prove that no trailing argument is unused.
    let argument_count_complete = false;
    FunctionSignature { prototype: if has_pdb { pdb.into() } else { format!("{} {}({}{})", return_type, name, args, if params.is_empty() { "/* arguments unknown */" } else if compact_stack_abi { "" } else { ", /* further arguments unknown */" }) },
        source: if has_pdb { "pdb" } else { "static-abi-inference" }, confidence: if has_pdb { "symbol-derived" } else { "tentative" },
        calling_convention: convention, return_type, parameters: params, argument_count_complete,
        instructions_visited: visited.len(), analysis_truncated: truncated, unresolved_flow: unresolved,
        notes: vec!["Inferred widths describe machine values; signedness, typedefs, aggregates and unused arguments are unresolved. Win64 positional mapping is an ABI hypothesis; x86 register parameters and custom language ABIs are not inferred. Pointer access describes observed instructions, not a complete const qualifier contract.".into()] }
}

fn type_name(width: usize, float: bool) -> String {
    match (width, float) {
        (4, true) => "float".into(),
        (8, true) => "double".into(),
        (1 | 2 | 4 | 8, false) => format!("int{}_t", width * 8),
        _ => "unknown".into(),
    }
}

#[cfg(test)]
mod tests;
