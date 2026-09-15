//! Path-bounded DRIVER_OBJECT assignment recovery under the Windows x64 ABI.
//! These are conditional static stores, not a recovered live dispatch table.
use super::{major_function_name, DecodedInsn, MajorFunctionAssignment, PeFile};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory,
    IntelFormatter, Mnemonic, OpAccess, OpKind, Register,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Driver,
    Code(u32),
    Number(u64),
    Stack(i64),
}

#[derive(Clone)]
struct Work {
    pc: u32,
    regs: BTreeMap<Register, Value>,
    stack: BTreeMap<i64, Value>,
    depth: usize,
    conditional: bool,
    flags: Option<Flags>,
}

#[derive(Clone, Copy)]
struct Flags {
    zero: bool,
    sign: bool,
    carry: bool,
    overflow: bool,
}

fn register(work: &Work, register: Register) -> Option<Value> {
    let value = *work.regs.get(&register.full_register())?;
    if register.size() == 8 {
        Some(value)
    } else if register.size() == 4 {
        if let Value::Number(value) = value {
            Some(Value::Number(value & 0xffff_ffff))
        } else {
            None
        }
    } else {
        None
    }
}

fn operand(work: &Work, instr: &Instruction, index: u32) -> Option<Value> {
    match instr.op_kind(index) {
        OpKind::Register => register(work, instr.op_register(index)),
        OpKind::Immediate32 => Some(Value::Number(u64::from(instr.immediate32()))),
        OpKind::Immediate64 => Some(Value::Number(instr.immediate64())),
        OpKind::Immediate8to32 => Some(Value::Number(instr.immediate8to32() as u32 as u64)),
        OpKind::Immediate8to64 => Some(Value::Number(instr.immediate8to64() as u64)),
        OpKind::Immediate32to64 => Some(Value::Number(instr.immediate32to64() as u64)),
        OpKind::Memory if instr.memory_size().size() == 8 => {
            let (Value::Stack(base), displacement) = address(work, instr)? else {
                return None;
            };
            work.stack.get(&base.checked_add(displacement)?).copied()
        }
        _ => None,
    }
}

fn address(work: &Work, instr: &Instruction) -> Option<(Value, i64)> {
    if instr.is_ip_rel_memory_operand() {
        return None;
    }
    let mut displacement = instr.memory_displacement64() as i64;
    if instr.memory_index() != Register::None {
        let Value::Number(index) = register(work, instr.memory_index())? else {
            return None;
        };
        displacement = displacement.checked_add(
            i64::try_from(index)
                .ok()?
                .checked_mul(i64::from(instr.memory_index_scale()))?,
        )?;
    }
    Some((register(work, instr.memory_base())?, displacement))
}

fn branch(mnemonic: Mnemonic, flags: Flags) -> Option<bool> {
    Some(match mnemonic {
        Mnemonic::Je => flags.zero,
        Mnemonic::Jne => !flags.zero,
        Mnemonic::Ja => !flags.carry && !flags.zero,
        Mnemonic::Jae => !flags.carry,
        Mnemonic::Jb => flags.carry,
        Mnemonic::Jbe => flags.carry || flags.zero,
        Mnemonic::Jg => !flags.zero && flags.sign == flags.overflow,
        Mnemonic::Jge => flags.sign == flags.overflow,
        Mnemonic::Jl => flags.sign != flags.overflow,
        Mnemonic::Jle => flags.zero || flags.sign != flags.overflow,
        Mnemonic::Js => flags.sign,
        Mnemonic::Jns => !flags.sign,
        _ => return None,
    })
}

pub(super) fn recover(
    pe: &PeFile,
    raw: &[u8],
    insns: &[DecodedInsn],
) -> Vec<MajorFunctionAssignment> {
    if pe.machine != 0x8664 || pe.subsystem != 1 {
        return Vec::new();
    }
    let by_rva: BTreeMap<_, _> = insns
        .iter()
        .map(|instruction| (instruction.rva, instruction))
        .collect();
    let mut pending = VecDeque::from([Work {
        pc: pe.entry_point,
        regs: BTreeMap::from([
            (Register::RCX, Value::Driver),
            (Register::RSP, Value::Stack(0)),
        ]),
        stack: BTreeMap::new(),
        depth: 0,
        conditional: false,
        flags: None,
    }]);
    let mut visits: BTreeMap<u32, usize> = BTreeMap::new();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    let mut factory = InstructionInfoFactory::new();
    let mut steps = 0usize;
    while let Some(mut work) = pending.pop_front() {
        while steps < 65_536 {
            steps += 1;
            let visits = visits.entry(work.pc).or_default();
            if *visits >= 64 {
                break;
            }
            *visits += 1;
            // Entry and directly reached helpers may be beyond the linear-scan
            // budget. Decode only the current bounded path location on demand.
            let fallback;
            let decoded = if let Some(decoded) = by_rva.get(&work.pc) {
                *decoded
            } else {
                if !pe
                    .rva_to_section(work.pc)
                    .is_some_and(|section| section.is_executable())
                {
                    break;
                }
                let Some(bytes) = pe.rva_bytes(raw, work.pc) else {
                    break;
                };
                let mut decoder = Decoder::with_ip(
                    64,
                    &bytes[..bytes.len().min(15)],
                    pe.image_base + u64::from(work.pc),
                    DecoderOptions::NONE,
                );
                let instr = decoder.decode();
                if instr.is_invalid() {
                    break;
                }
                let mut text = String::new();
                IntelFormatter::new().format(&instr, &mut text);
                fallback = DecodedInsn {
                    rva: work.pc,
                    owner_rva: work.pc,
                    owner_name: format!("sub_{:08X}", work.pc),
                    instr,
                    text,
                };
                &fallback
            };
            let instr = &decoded.instr;
            let Some(next) = work.pc.checked_add(instr.len() as u32) else {
                break;
            };
            match instr.flow_control() {
                FlowControl::Return | FlowControl::Exception | FlowControl::Interrupt => break,
                FlowControl::UnconditionalBranch => {
                    let Some(target) = pe.va_to_rva(instr.near_branch_target()) else {
                        break;
                    };
                    work.pc = target;
                    continue;
                }
                FlowControl::IndirectBranch => break,
                FlowControl::ConditionalBranch => {
                    let choice = work.flags.and_then(|flags| branch(instr.mnemonic(), flags));
                    let target = pe.va_to_rva(instr.near_branch_target());
                    if choice != Some(false) {
                        if let Some(target) = target {
                            if choice == Some(true) {
                                work.pc = target;
                                continue;
                            }
                            if pending.len() < 256 {
                                let mut taken = work.clone();
                                taken.pc = target;
                                taken.conditional = true;
                                pending.push_back(taken);
                            }
                        }
                    }
                    work.conditional |= choice.is_none();
                    work.pc = next;
                    continue;
                }
                FlowControl::Call | FlowControl::IndirectCall => {
                    let args = [Register::RCX, Register::RDX, Register::R8, Register::R9];
                    if instr.flow_control() == FlowControl::Call
                        && work.depth < 8
                        && pending.len() < 256
                        && args
                            .iter()
                            .any(|reg| register(&work, *reg) == Some(Value::Driver))
                    {
                        if let Some(target) = pe.va_to_rva(instr.near_branch_target()) {
                            let mut regs: BTreeMap<_, _> = args
                                .iter()
                                .filter_map(|reg| {
                                    register(&work, *reg)
                                        .filter(|value| !matches!(value, Value::Stack(_)))
                                        .map(|value| (*reg, value))
                                })
                                .collect();
                            regs.insert(Register::RSP, Value::Stack(0));
                            pending.push_back(Work {
                                pc: target,
                                regs,
                                stack: BTreeMap::new(),
                                depth: work.depth + 1,
                                conditional: work.conditional,
                                flags: None,
                            });
                        }
                    }
                    for reg in [
                        Register::RAX,
                        Register::RCX,
                        Register::RDX,
                        Register::R8,
                        Register::R9,
                        Register::R10,
                        Register::R11,
                    ] {
                        work.regs.remove(&reg);
                    }
                    work.stack.clear();
                    work.flags = None;
                    work.pc = next;
                    continue;
                }
                _ => {}
            }
            let destination = (instr.op_count() != 0 && instr.op0_kind() == OpKind::Register)
                .then(|| instr.op0_register());
            let old_stack = register(&work, Register::RSP);
            let source = if instr.op_count() >= 2 {
                operand(&work, instr, 1)
            } else {
                None
            };
            let left = if instr.op_count() != 0 {
                operand(&work, instr, 0)
            } else {
                None
            };
            let mut value = if instr.mnemonic() == Mnemonic::Mov {
                source
            } else {
                None
            };
            let mut flags = None;
            if instr.mnemonic() == Mnemonic::Lea {
                value = if instr.is_ip_rel_memory_operand() {
                    pe.va_to_rva(instr.ip_rel_memory_address())
                        .filter(|rva| {
                            pe.rva_to_section(*rva).is_some_and(|s| s.is_executable())
                                && pe.rva_to_offset(*rva).is_some()
                        })
                        .map(Value::Code)
                } else {
                    address(&work, instr).and_then(|(base, displacement)| {
                        if let Value::Stack(base) = base {
                            base.checked_add(displacement).map(Value::Stack)
                        } else {
                            None
                        }
                    })
                };
            }
            if instr.mnemonic() == Mnemonic::Xor
                && instr.op0_kind() == OpKind::Register
                && instr.op1_kind() == OpKind::Register
                && instr.op0_register() == instr.op1_register()
            {
                value = Some(Value::Number(0));
                flags = Some(Flags {
                    zero: true,
                    sign: false,
                    carry: false,
                    overflow: false,
                });
            }
            if matches!(
                instr.mnemonic(),
                Mnemonic::Cmp | Mnemonic::Sub | Mnemonic::Add | Mnemonic::Test
            ) {
                if let (Some(Value::Number(left)), Some(Value::Number(right))) = (left, source) {
                    let width = destination.map_or(8, |reg| reg.size());
                    let mask = if width == 4 {
                        u32::MAX as u64
                    } else {
                        u64::MAX
                    };
                    let sign = if width == 4 { 1u64 << 31 } else { 1u64 << 63 };
                    let result = match instr.mnemonic() {
                        Mnemonic::Add => left.wrapping_add(right),
                        Mnemonic::Test => left & right,
                        _ => left.wrapping_sub(right),
                    } & mask;
                    let carry = if instr.mnemonic() == Mnemonic::Add {
                        result < (left & mask)
                    } else if instr.mnemonic() == Mnemonic::Test {
                        false
                    } else {
                        (left & mask) < (right & mask)
                    };
                    let overflow = match instr.mnemonic() {
                        Mnemonic::Add => (!(left ^ right) & (left ^ result) & sign) != 0,
                        Mnemonic::Test => false,
                        _ => ((left ^ right) & (left ^ result) & sign) != 0,
                    };
                    flags = Some(Flags {
                        zero: result == 0,
                        sign: result & sign != 0,
                        carry,
                        overflow,
                    });
                    if matches!(instr.mnemonic(), Mnemonic::Add | Mnemonic::Sub) {
                        value = Some(Value::Number(result));
                    }
                } else if let (Some(Value::Stack(base)), Some(Value::Number(amount))) =
                    (left, source)
                {
                    value = match instr.mnemonic() {
                        Mnemonic::Sub => base.checked_sub(amount as i64).map(Value::Stack),
                        Mnemonic::Add => base.checked_add(amount as i64).map(Value::Stack),
                        _ => None,
                    };
                }
            }
            let writes_memory = factory.info(instr).used_memory().iter().any(|used| {
                matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                )
            });
            if writes_memory && instr.op_count() != 0 && instr.op0_kind() == OpKind::Memory {
                let width = instr.memory_size().size();
                match address(&work, instr) {
                    Some((Value::Driver, offset))
                        if instr.mnemonic() == Mnemonic::Mov && width == 8 =>
                    {
                        if let Some(Value::Code(target)) = source {
                            if (0x70..0x150).contains(&offset) && (offset - 0x70) % 8 == 0 {
                                let index = ((offset - 0x70) / 8) as u32;
                                if seen.insert((work.pc, index, target)) {
                                    out.push(MajorFunctionAssignment { major_index: index, major_name: major_function_name(index).into(),
                                        site_rva: format!("0x{:08X}", work.pc), owner_rva: format!("0x{:08X}", decoded.owner_rva), owner_name: decoded.owner_name.clone(),
                                        instruction: decoded.text.clone(), confidence: "static-entry-ABI-path; runtime-unobserved".into(), target_rva: format!("0x{target:08X}"),
                                        object_origin: format!("Entry RCX DRIVER_OBJECT assumption; x64 ABI; helper depth {}; conditional path {}; assignment may be overwritten later", work.depth, work.conditional) });
                                }
                            }
                        }
                    }
                    Some((Value::Stack(base), offset)) => {
                        if let Some(offset) = base.checked_add(offset) {
                            work.stack.retain(|&start, _| {
                                start.saturating_add(8) <= offset
                                    || start >= offset.saturating_add(width as i64)
                            });
                            if instr.mnemonic() == Mnemonic::Mov
                                && width == 8
                                && work.stack.len() < 256
                            {
                                if let Some(value) = source {
                                    work.stack.insert(offset, value);
                                }
                            }
                        }
                    }
                    _ => work.stack.clear(),
                }
            } else if writes_memory {
                work.stack.clear();
            }
            for used in factory.info(instr).used_registers() {
                if matches!(
                    used.access(),
                    OpAccess::Write
                        | OpAccess::CondWrite
                        | OpAccess::ReadWrite
                        | OpAccess::ReadCondWrite
                ) {
                    work.regs.remove(&used.register().full_register());
                }
            }
            if let Some(reg) = destination {
                if let Some(value) = value {
                    if reg.size() == 8 {
                        work.regs.insert(reg, value);
                    } else if reg.size() == 4 {
                        if let Value::Number(value) = value {
                            work.regs
                                .insert(reg.full_register(), Value::Number(value & 0xffff_ffff));
                        }
                    }
                }
            }
            if matches!(instr.mnemonic(), Mnemonic::Push | Mnemonic::Pop) {
                if let Some(Value::Stack(base)) = old_stack {
                    let width = if instr.op0_kind() == OpKind::Register
                        && instr.op0_register().size() == 2
                    {
                        2
                    } else {
                        8
                    };
                    if let Some(base) = base.checked_add(if instr.mnemonic() == Mnemonic::Push {
                        -width
                    } else {
                        width
                    }) {
                        work.regs.insert(Register::RSP, Value::Stack(base));
                        work.stack.remove(&base);
                    }
                }
            }
            if instr.rflags_modified() != 0 {
                work.flags = flags;
            }
            work.pc = next;
        }
        if steps >= 65_536 {
            break;
        }
    }
    out
}
