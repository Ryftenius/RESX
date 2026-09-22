//! Small, bounded path-aware annotations for human-readable disassembly.
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use iced_x86::{FlowControl, Mnemonic, OpKind, Register};

use crate::analysis::disasm::Instruction;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Value {
    expr: String,
    stack_addr: Option<i64>,
    constant: Option<u64>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct State {
    sp: Option<i64>,
    regs: BTreeMap<Register, Value>,
    flags: String,
}

pub fn annotate(insns: &mut [Instruction], arch: u32) {
    if arch != 64 || insns.is_empty() {
        return;
    }
    let blocks: BTreeMap<u32, Vec<Instruction>> =
        insns
            .iter()
            .cloned()
            .fold(BTreeMap::new(), |mut blocks, insn| {
                blocks.entry(insn.block_start).or_default().push(insn);
                blocks
            });
    let entry = insns[0].block_start;
    let mut states = BTreeMap::from([(
        entry,
        State {
            sp: Some(0),
            regs: BTreeMap::from([
                (
                    Register::RCX,
                    Value {
                        expr: "arg0".into(),
                        ..Value::default()
                    },
                ),
                (
                    Register::RDX,
                    Value {
                        expr: "arg1".into(),
                        ..Value::default()
                    },
                ),
                (
                    Register::R8,
                    Value {
                        expr: "arg2".into(),
                        ..Value::default()
                    },
                ),
                (
                    Register::R9,
                    Value {
                        expr: "arg3".into(),
                        ..Value::default()
                    },
                ),
            ]),
            ..State::default()
        },
    )]);
    let mut queue = VecDeque::from([entry]);
    let mut notes = BTreeMap::<(u32, u32), BTreeSet<String>>::new();
    let mut steps = 0usize;
    let step_limit = blocks.len().saturating_mul(8).max(32);

    while let Some(block_start) = queue.pop_front() {
        if steps >= step_limit {
            break;
        }
        steps += 1;
        let Some(block) = blocks.get(&block_start) else {
            continue;
        };
        let mut state = states.get(&block_start).cloned().unwrap_or_default();
        for insn in block {
            transfer(
                insn,
                &mut state,
                notes.entry((block_start, insn.rva)).or_default(),
            );
        }
        for successor in successors(block) {
            if !blocks.contains_key(&successor) {
                continue;
            }
            let changed = if let Some(old) = states.get_mut(&successor) {
                merge(old, &state)
            } else {
                states.insert(successor, state.clone());
                true
            };
            if changed {
                queue.push_back(successor);
            }
        }
    }

    for insn in insns {
        let Some(row) = notes.get(&(insn.block_start, insn.rva)) else {
            continue;
        };
        for note in row {
            append_comment(&mut insn.comment, note);
        }
    }
}

fn transfer(insn: &Instruction, state: &mut State, notes: &mut BTreeSet<String>) {
    let iced = &insn.iced;
    let stack = stack_address(state, iced);
    if let Some(offset) = stack {
        notes.insert(format!("{{{}}}", stack_name(offset)));
    }

    match iced.mnemonic() {
        Mnemonic::Lea if iced.op0_kind() == OpKind::Register => {
            let reg = iced.op0_register().full_register();
            let expr = stack
                .map(|offset| format!("&{}", stack_name(offset)))
                .unwrap_or_else(|| effective_address_name(state, iced));
            let value = Value {
                expr: expr.clone(),
                stack_addr: stack,
                constant: None,
            };
            state.regs.insert(reg, value);
            notes.insert(format!("ssa: {}@{:08x} = {expr}", reg_name(reg), insn.rva));
            notes.insert(format!("operation: {expr}"));
        }
        Mnemonic::Mov if iced.op0_kind() == OpKind::Register => {
            let reg = iced.op0_register().full_register();
            let value = source_value(state, iced, stack);
            notes.insert(format!(
                "ssa: {}@{:08x} = {}",
                reg_name(iced.op0_register()),
                insn.rva,
                display_value(&value)
            ));
            state.regs.insert(reg, value);
        }
        Mnemonic::Mov if iced.op0_kind() == OpKind::Memory => {
            let destination = stack
                .map(stack_name)
                .unwrap_or_else(|| memory_name(state, iced));
            let source = if iced.op1_kind() == OpKind::Register {
                state
                    .regs
                    .get(&iced.op1_register().full_register())
                    .map(display_value)
                    .unwrap_or_else(|| reg_name(iced.op1_register()))
            } else {
                "value".to_owned()
            };
            notes.insert(format!("ssa: {destination}@{:08x} = {source}", insn.rva));
            notes.insert(format!("operation: {destination} = {source}"));
        }
        Mnemonic::Add | Mnemonic::Sub | Mnemonic::Imul
            if iced.op0_kind() == OpKind::Register
                && iced.op0_register().full_register() != Register::RSP =>
        {
            let reg = iced.op0_register().full_register();
            let lhs = state
                .regs
                .get(&reg)
                .map(display_value)
                .unwrap_or_else(|| reg_name(reg));
            let rhs = operand_value(state, iced, 1, stack);
            let operator = match iced.mnemonic() {
                Mnemonic::Add => "+",
                Mnemonic::Sub => "-",
                _ => "*",
            };
            let expr = format!("({lhs} {operator} {})", display_value(&rhs));
            state.regs.insert(
                reg,
                Value {
                    expr: expr.clone(),
                    ..Value::default()
                },
            );
            notes.insert(format!("ssa: {}@{:08x} = {expr}", reg_name(reg), insn.rva));
            notes.insert(format!("operation: {expr}"));
        }
        Mnemonic::Idiv => {
            let divisor = operand_value(state, iced, 0, stack);
            let dividend = state
                .regs
                .get(&Register::RAX)
                .map(display_value)
                .unwrap_or_else(|| "rax".into());
            let expr = format!("({dividend} / {})", display_value(&divisor));
            state.regs.insert(
                Register::RAX,
                Value {
                    expr: expr.clone(),
                    ..Value::default()
                },
            );
            state.regs.insert(
                Register::RDX,
                Value {
                    expr: format!("remainder({expr})"),
                    ..Value::default()
                },
            );
            notes.insert(format!("ssa: rax@{:08x} = {expr}", insn.rva));
            notes.insert(format!("operation: {expr}"));
        }
        Mnemonic::Xor
            if iced.op0_kind() == OpKind::Register
                && matches!(iced.op1_kind(), OpKind::Immediate8 | OpKind::Immediate32) =>
        {
            let reg = iced.op0_register().full_register();
            let rhs = iced.immediate(1);
            let constant = state
                .regs
                .get(&reg)
                .and_then(|value| value.constant)
                .map(|lhs| lhs ^ rhs);
            let expr = constant
                .map(|value| format!("0x{value:x}"))
                .unwrap_or_else(|| format!("{} ^ 0x{rhs:x}", reg_name(iced.op0_register())));
            state.regs.insert(
                reg,
                Value {
                    expr: expr.clone(),
                    constant,
                    ..Value::default()
                },
            );
            notes.insert(format!("ssa: {}@{:08x} = {expr}", reg_name(reg), insn.rva));
        }
        Mnemonic::Test
            if iced.op0_kind() == OpKind::Register && iced.op1_kind() == OpKind::Register =>
        {
            let reg = iced.op0_register().full_register();
            let value = state
                .regs
                .get(&reg)
                .map(display_value)
                .unwrap_or_else(|| reg_name(iced.op0_register()));
            state.flags = format!("zf@{:08x}=({value} == 0)", insn.rva);
            notes.insert(format!("ssa: {}", state.flags));
        }
        Mnemonic::Add | Mnemonic::Sub
            if iced.op0_kind() == OpKind::Register
                && iced.op0_register().full_register() == Register::RSP =>
        {
            let delta = iced.immediate(1) as i64;
            state.sp = state.sp.and_then(|sp| {
                if iced.mnemonic() == Mnemonic::Sub {
                    sp.checked_sub(delta)
                } else {
                    sp.checked_add(delta)
                }
            });
            if let Some(sp) = state.sp {
                notes.insert(format!("frame: rsp = entry_sp{}", signed_hex(sp)));
            }
        }
        _ => {}
    }

    match iced.flow_control() {
        FlowControl::ConditionalBranch => {
            let condition = if state.flags.is_empty() {
                format!("{:?}", iced.mnemonic()).to_ascii_lowercase()
            } else {
                state.flags.clone()
            };
            notes.insert(format!("control: branch on {condition}"));
        }
        FlowControl::Call | FlowControl::IndirectCall => {
            notes.insert(format!(
                "control: call; return continues at loc_{:08x}",
                insn.rva.saturating_add(insn.bytes.len() as u32)
            ));
            for reg in [
                Register::RAX,
                Register::RCX,
                Register::RDX,
                Register::R8,
                Register::R9,
                Register::R10,
                Register::R11,
            ] {
                state.regs.remove(&reg);
            }
        }
        FlowControl::Return => {
            notes.insert("control: return to {__return_addr}".to_owned());
        }
        _ => {}
    }
}

fn source_value(state: &State, iced: &iced_x86::Instruction, stack: Option<i64>) -> Value {
    operand_value(state, iced, 1, stack)
}

fn operand_value(
    state: &State,
    iced: &iced_x86::Instruction,
    operand: u32,
    stack: Option<i64>,
) -> Value {
    match iced.op_kind(operand) {
        OpKind::Register => state
            .regs
            .get(&iced.op_register(operand).full_register())
            .cloned()
            .unwrap_or_else(|| Value {
                expr: reg_name(iced.op_register(operand)),
                ..Value::default()
            }),
        OpKind::Memory => Value {
            expr: stack
                .map(stack_name)
                .unwrap_or_else(|| memory_name(state, iced)),
            ..Value::default()
        },
        OpKind::Immediate8 | OpKind::Immediate16 | OpKind::Immediate32 | OpKind::Immediate64 => {
            let constant = iced.immediate(operand);
            Value {
                expr: format!("0x{constant:x}"),
                constant: Some(constant),
                ..Value::default()
            }
        }
        _ => Value {
            expr: "unknown".to_owned(),
            ..Value::default()
        },
    }
}

fn memory_name(state: &State, iced: &iced_x86::Instruction) -> String {
    format!("*({})", effective_address_name(state, iced))
}

fn effective_address_name(state: &State, iced: &iced_x86::Instruction) -> String {
    let base_register = iced.memory_base().full_register();
    let base = state
        .regs
        .get(&base_register)
        .map(display_value)
        .unwrap_or_else(|| reg_name(base_register));
    let index_register = iced.memory_index().full_register();
    let index = (index_register != Register::None).then(|| {
        let value = state
            .regs
            .get(&index_register)
            .map(display_value)
            .unwrap_or_else(|| reg_name(index_register));
        if iced.memory_index_scale() > 1 {
            format!(" + {value}*{}", iced.memory_index_scale())
        } else {
            format!(" + {value}")
        }
    });
    let displacement = iced.memory_displacement64() as i64;
    let displacement = if displacement > 0 {
        format!(" + 0x{displacement:x}")
    } else if displacement < 0 {
        format!(" - 0x{:x}", displacement.unsigned_abs())
    } else {
        String::new()
    };
    format!("{base}{}{displacement}", index.unwrap_or_default())
}

fn stack_address(state: &State, iced: &iced_x86::Instruction) -> Option<i64> {
    if iced.memory_base() == Register::None || iced.memory_index() != Register::None {
        return None;
    }
    let base = match iced.memory_base().full_register() {
        Register::RSP => state.sp,
        reg => state.regs.get(&reg).and_then(|value| value.stack_addr),
    }?;
    base.checked_add(iced.memory_displacement64() as i64)
}

fn stack_name(offset: i64) -> String {
    match offset {
        0 => "__return_addr".to_owned(),
        8..=0x20 => format!("home_{offset:x}"),
        value if value >= 0x28 && (value - 0x28) % 8 == 0 => {
            format!("arg{}", (value - 0x28) / 8 + 1)
        }
        value if value < 0 => format!("var_{:x}", value.unsigned_abs()),
        value => format!("entry_sp+0x{value:x}"),
    }
}

fn signed_hex(value: i64) -> String {
    if value < 0 {
        format!("-0x{:x}", value.unsigned_abs())
    } else {
        format!("+0x{value:x}")
    }
}

fn successors(block: &[Instruction]) -> Vec<u32> {
    let Some(last) = block.last() else {
        return Vec::new();
    };
    let next = last.rva.saturating_add(last.bytes.len() as u32);
    let image_base = last.va.saturating_sub(last.rva as u64);
    let target = (last.call_target >= image_base && last.call_target != 0)
        .then(|| last.call_target.wrapping_sub(image_base) as u32);
    match last.iced.flow_control() {
        FlowControl::ConditionalBranch => target.into_iter().chain([next]).collect(),
        FlowControl::UnconditionalBranch => target.into_iter().collect(),
        FlowControl::Return => Vec::new(),
        _ => vec![next],
    }
}

fn merge(old: &mut State, new: &State) -> bool {
    let before = old.clone();
    if old.sp != new.sp {
        old.sp = None;
    }
    old.regs.retain(|reg, value| {
        let Some(incoming) = new.regs.get(reg) else {
            return false;
        };
        if value != incoming {
            value.expr = "phi".to_owned();
            value.constant = None;
            if value.stack_addr != incoming.stack_addr {
                value.stack_addr = None;
            }
        }
        true
    });
    if old.flags != new.flags {
        old.flags.clear();
    }
    *old != before
}

fn display_value(value: &Value) -> String {
    if value.expr.is_empty() {
        "unknown".to_owned()
    } else {
        value.expr.clone()
    }
}

fn reg_name(reg: Register) -> String {
    format!("{reg:?}").to_ascii_lowercase()
}

fn append_comment(comment: &mut String, note: &str) {
    if comment.contains(note) {
        return;
    }
    if !comment.is_empty() {
        comment.push_str(" | ");
    }
    comment.push_str(note);
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

    fn decode(bytes: &[u8]) -> Vec<Instruction> {
        let mut decoder = Decoder::with_ip(64, bytes, 0x140001000, DecoderOptions::NONE);
        let mut rows = Vec::new();
        while decoder.can_decode() {
            let iced = decoder.decode();
            let offset = (iced.ip() - 0x140001000) as usize;
            let mut text = String::new();
            IntelFormatter::new().format(&iced, &mut text);
            rows.push(Instruction {
                block_start: 0x1000,
                rva: 0x1000 + offset as u32,
                va: iced.ip(),
                file_off: offset as u64,
                bytes: bytes[offset..offset + iced.len()].to_vec(),
                text,
                mnemonic: format!("{:?}", iced.mnemonic()).to_ascii_lowercase(),
                operands: String::new(),
                iced,
                comment: String::new(),
                is_call: false,
                is_jmp: false,
                is_jcc: false,
                call_target: 0,
            });
        }
        rows
    }

    #[test]
    fn stack_aliases_get_return_argument_and_ssa_annotations() {
        let mut rows = decode(&[
            0x48, 0x83, 0xec, 0x68, 0x4c, 0x8d, 0x54, 0x24, 0x68, 0x4d, 0x8b, 0x5a, 0x28, 0xc3,
        ]);
        annotate(&mut rows, 64);
        assert!(rows[1].comment.contains("{__return_addr}"));
        assert!(rows[2].comment.contains("{arg1}"));
        assert!(rows[2].comment.contains("ssa: r11@"));
        assert!(rows[3].comment.contains("return to {__return_addr}"));
    }

    #[test]
    fn recovers_arithmetic_expressions_and_stack_destinations() {
        let mut rows = decode(&[
            0x8b, 0x41, 0x20, // mov eax,[rcx+20h]
            0x03, 0x41, 0x24, // add eax,[rcx+24h]
            0x89, 0x45, 0xb4, // mov [rbp-4Ch],eax
            0x8b, 0x41, 0x20, // mov eax,[rcx+20h]
            0x0f, 0xaf, 0x41, 0x24, // imul eax,[rcx+24h]
            0xc3,
        ]);
        annotate(&mut rows, 64);
        assert!(rows[1]
            .comment
            .contains("operation: (*(arg0 + 0x20) + *(arg0 + 0x24))"));
        assert!(rows[2]
            .comment
            .contains("operation: *(rbp - 0x4c) = (*(arg0 + 0x20) + *(arg0 + 0x24))"));
        assert!(rows[4]
            .comment
            .contains("operation: (*(arg0 + 0x20) * *(arg0 + 0x24))"));
    }
}
