//! Bounded request-provenance analysis rooted at registered x64 IRP handlers.
//! A comparison is static evidence, not proof that a request succeeds at runtime.
use super::{access_name, device_type_name, method_name, IoctlCodeCandidate, PeFile};
use iced_x86::{
    Decoder, DecoderOptions, FlowControl, Formatter, Instruction, InstructionInfoFactory,
    IntelFormatter, Mnemonic, OpAccess, OpKind, Register,
};
use serde::Serialize;
mod lengths;
use lengths::Buffer;
pub use lengths::LengthCheck;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

const ROOT_LIMIT: usize = 64;
const ROOT_STEPS: usize = 8192;
const TOTAL_STEPS: usize = 131072;
const PENDING_LIMIT: usize = 128;
const TABLE_LIMIT: u32 = 256;

#[cfg(test)]
mod tests;

#[derive(Clone, Debug)]
pub(super) struct Root {
    pub rva: u32,
    pub reason: String,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Coverage {
    pub architecture_supported: bool,
    pub linear_instruction_limit_reached: bool,
    pub call_limit_reached: bool,
    pub dispatch_discovery_truncated: bool,
    pub dispatch_roots: usize,
    pub analyzed_roots: usize,
    pub decoded_dispatch_instructions: usize,
    pub dispatch_analysis_truncated: bool,
    pub unsupported_indirect_branches: usize,
    pub length_probe_instructions: usize,
    pub length_analysis_truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Index {
    shift: u32,
    mask: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Value {
    Irp,
    IoStack,
    Length(Buffer, usize),
    Local(i64),
    Constant(u64),
    // Original 32-bit request plus a wrapping offset; never a generic integer.
    Code(u32),
    Index(Index),
    Table(u32, Index),
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Condition {
    left: Value,
    right: Value,
    site: u32,
    instruction: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ValidatedTable {
    base: u32,
    index: Index,
    count: u32,
    site: u32,
    instruction: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Flags {
    zero: bool,
    sign: bool,
    carry: bool,
    overflow: bool,
}

fn known_branch(flags: Flags, mnemonic: Mnemonic) -> Option<bool> {
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

fn constant_flags(mnemonic: Mnemonic, left: u64, right: u64, width: usize) -> Option<Flags> {
    if !matches!(width, 4 | 8) {
        return None;
    }
    let mask = if width == 4 {
        u32::MAX as u64
    } else {
        u64::MAX
    };
    let sign = if width == 4 { 1u64 << 31 } else { 1u64 << 63 };
    let result = match mnemonic {
        Mnemonic::Add => left.wrapping_add(right),
        Mnemonic::Sub | Mnemonic::Cmp => left.wrapping_sub(right),
        Mnemonic::Test | Mnemonic::And => left & right,
        Mnemonic::Xor => left ^ right,
        _ => return None,
    } & mask;
    let carry = match mnemonic {
        Mnemonic::Add => result < (left & mask),
        Mnemonic::Sub | Mnemonic::Cmp => (left & mask) < (right & mask),
        _ => false,
    };
    let overflow = match mnemonic {
        Mnemonic::Add => (!(left ^ right) & (left ^ result) & sign) != 0,
        Mnemonic::Sub | Mnemonic::Cmp => ((left ^ right) & (left ^ result) & sign) != 0,
        _ => false,
    };
    Some(Flags {
        zero: result == 0,
        sign: result & sign != 0,
        carry,
        overflow,
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct State {
    pc: u32,
    depth: u8,
    regs: BTreeMap<Register, Value>,
    locals: BTreeMap<i64, (usize, Value)>,
    flags: Option<Condition>,
    known_flags: Option<Flags>,
    bounds: BTreeMap<Index, u32>,
    table: Option<ValidatedTable>,
    equal: Option<u32>,
    excluded: BTreeSet<u32>,
    low: u32,
    high: u32,
    memory_valid: bool,
}

impl State {
    fn entry(pc: u32) -> Self {
        Self {
            pc,
            depth: 0,
            regs: BTreeMap::from([
                (Register::RDX, Value::Irp),
                (Register::RSP, Value::Local(0)),
            ]),
            locals: BTreeMap::new(),
            flags: None,
            known_flags: None,
            bounds: BTreeMap::new(),
            table: None,
            equal: None,
            excluded: BTreeSet::new(),
            low: 0,
            high: u32::MAX,
            memory_valid: true,
        }
    }
    fn reg(&self, reg: Register) -> Option<Value> {
        let value = *self.regs.get(&reg.full_register())?;
        match (reg.size(), value) {
            (8, _) => Some(value),
            (4, Value::Constant(n)) => Some(Value::Constant(n & u32::MAX as u64)),
            (4, Value::Code(_) | Value::Index(_) | Value::Length(_, 4)) => Some(value),
            _ => None,
        }
    }
    fn permits(&self, code: u32) -> bool {
        code >= self.low
            && code <= self.high
            && self.equal.is_none_or(|n| n == code)
            && !self.excluded.contains(&code)
    }
}

fn executable(pe: &PeFile, rva: u32) -> bool {
    pe.rva_to_offset(rva).is_some() && pe.rva_to_section(rva).is_some_and(|s| s.is_executable())
}

fn decode(pe: &PeFile, raw: &[u8], pc: u32) -> Option<Instruction> {
    if !executable(pe, pc) {
        return None;
    }
    let bytes = pe.rva_bytes(raw, pc)?;
    let instr = Decoder::with_ip(
        64,
        &bytes[..bytes.len().min(15)],
        pe.image_base + pc as u64,
        DecoderOptions::NONE,
    )
    .decode();
    (!instr.is_invalid()).then_some(instr)
}

fn immediate(i: &Instruction, op: u32) -> Option<u64> {
    Some(match i.op_kind(op) {
        OpKind::Immediate8 => i.immediate8() as u64,
        OpKind::Immediate8to32 => i.immediate8to32() as u32 as u64,
        OpKind::Immediate8to64 => i.immediate8to64() as u64,
        OpKind::Immediate32 => i.immediate32() as u64,
        OpKind::Immediate32to64 => i.immediate32to64() as u64,
        OpKind::Immediate64 => i.immediate64(),
        _ => return None,
    })
}

fn local_address(s: &State, i: &Instruction) -> Option<i64> {
    if i.is_ip_rel_memory_operand() || i.memory_index() != Register::None {
        return None;
    }
    let Value::Local(base) = s.reg(i.memory_base())? else {
        return None;
    };
    base.checked_add(i.memory_displacement64() as i64)
}

fn table_address(pe: &PeFile, s: &State, i: &Instruction, scale: u32) -> Option<(u32, Index)> {
    if i.memory_index_scale() != scale {
        return None;
    }
    let Value::Index(index) = s.reg(i.memory_index())? else {
        return None;
    };
    let base = if i.memory_base() == Register::None {
        0
    } else {
        let Value::Constant(base) = s.reg(i.memory_base())? else {
            return None;
        };
        base
    };
    let address = base.wrapping_add(i.memory_displacement64());
    let rva = pe.va_to_rva(address)?;
    // Mutable tables can change after this image was written; don't present
    // their disk contents as dispatch evidence.
    let section = pe.rva_to_section(rva)?;
    (section.characteristics & 0x8000_0000 == 0 && !section.is_executable()).then_some((rva, index))
}

fn operand(pe: &PeFile, s: &State, i: &Instruction, op: u32) -> Option<Value> {
    match i.op_kind(op) {
        OpKind::Register => s.reg(i.op_register(op)),
        OpKind::Memory => {
            let width = i.memory_size().size();
            if let Some(offset) = local_address(s, i) {
                let (stored_width, value) = *s.locals.get(&offset)?;
                return (stored_width == width).then_some(value);
            }
            if s.memory_valid && i.memory_index() == Register::None && !i.is_ip_rel_memory_operand()
            {
                match (s.reg(i.memory_base()), i.memory_displacement64(), width) {
                    (Some(Value::Irp), 0xb8, 8) => return Some(Value::IoStack),
                    (Some(Value::IoStack), 0x18, 4) => return Some(Value::Code(0)),
                    (Some(Value::IoStack), 0x10, 4) => {
                        return Some(Value::Length(Buffer::Input, 4))
                    }
                    (Some(Value::IoStack), 0x08, 4) => {
                        return Some(Value::Length(Buffer::Output, 4))
                    }
                    _ => {}
                }
            }
            if width == 4 {
                return table_address(pe, s, i, 4).map(|(base, index)| Value::Table(base, index));
            }
            None
        }
        _ => immediate(i, op).map(Value::Constant),
    }
}

fn comparison_code(condition: &Condition) -> Option<u32> {
    match (condition.left, condition.right) {
        (Value::Code(offset), Value::Constant(n)) | (Value::Constant(n), Value::Code(offset)) => {
            u32::try_from(n).ok().map(|n| n.wrapping_sub(offset))
        }
        _ => None,
    }
}

fn emit(
    out: &mut Vec<IoctlCodeCandidate>,
    root: &Root,
    code: u32,
    condition: &Condition,
    table: Option<(u32, u32)>,
) {
    let site = format!("0x{:08X}", condition.site);
    if out.iter().any(|old| {
        old.owner_rva == format!("0x{:08X}", root.rva)
            && old.code == format!("0x{code:08X}")
            && old.site_rva == site
    }) {
        return;
    }
    let device = code >> 16;
    out.push(IoctlCodeCandidate {
        code: format!("0x{code:08X}"), device_type: format!("0x{device:04X}"), device_type_name: device_type_name(device).into(),
        function: format!("0x{:03X}",(code >> 2)&0xfff), method: method_name(code&3).into(), access: access_name((code>>14)&3).into(),
        site_rva: site, owner_rva: format!("0x{:08X}",root.rva), owner_name: format!("sub_{:08X}",root.rva),
        instruction: condition.instruction.clone(),
        evidence_status: if table.is_some() { "static-request-code-table; execution-unobserved" } else { "static-request-code-comparison; execution-unobserved" }.into(),
        arguments: Some(format!("{}; IoControlCode derived from IRP.CurrentStackLocation; success and access checks unproven",root.reason)),
        handler_rva: table.map(|(_,handler)|format!("0x{handler:08X}")),
        device_object_identity: None, ndis_oid: None, length_checks: Vec::new(),
    });
}

fn refine(s: &mut State, condition: &Condition, mnemonic: Mnemonic, taken: bool) -> bool {
    if matches!(mnemonic, Mnemonic::Je | Mnemonic::Jne) {
        let equality = (mnemonic == Mnemonic::Je) == taken;
        if let Some(code) = comparison_code(condition) {
            if equality {
                if !s.permits(code) {
                    return false;
                }
                s.equal = Some(code);
            } else {
                if s.equal == Some(code) {
                    return false;
                }
                if s.excluded.len() < 256 {
                    s.excluded.insert(code);
                }
            }
        }
        if equality {
            let table = match (condition.left, condition.right) {
                (Value::Table(base, index), Value::Code(0))
                | (Value::Code(0), Value::Table(base, index)) => Some((base, index)),
                _ => None,
            };
            if let Some((base, index)) = table {
                if let Some(&count) = s.bounds.get(&index) {
                    s.table = Some(ValidatedTable {
                        base,
                        index,
                        count,
                        site: condition.site,
                        instruction: condition.instruction.clone(),
                    });
                }
            }
        }
    }
    if let (Value::Index(index), Value::Constant(bound)) = (condition.left, condition.right) {
        let count = match (mnemonic, taken) {
            (Mnemonic::Jb, true) | (Mnemonic::Jae, false) => Some(bound),
            (Mnemonic::Jbe, true) | (Mnemonic::Ja, false) => bound.checked_add(1),
            _ => None,
        };
        if let Some(count) = count.filter(|&n| n <= TABLE_LIMIT as u64) {
            s.bounds
                .entry(index)
                .and_modify(|n| *n = (*n).min(count as u32))
                .or_insert(count as u32);
        }
    }
    if let (Value::Code(0), Value::Constant(bound)) = (condition.left, condition.right) {
        if let Ok(bound) = u32::try_from(bound) {
            match (mnemonic, taken) {
                (Mnemonic::Jb, true) | (Mnemonic::Jae, false) => {
                    if bound == 0 {
                        return false;
                    }
                    s.high = s.high.min(bound - 1);
                }
                (Mnemonic::Jbe, true) | (Mnemonic::Ja, false) => s.high = s.high.min(bound),
                (Mnemonic::Ja, true) | (Mnemonic::Jbe, false) => {
                    if bound == u32::MAX {
                        return false;
                    }
                    s.low = s.low.max(bound + 1);
                }
                (Mnemonic::Jae, true) | (Mnemonic::Jb, false) => s.low = s.low.max(bound),
                _ => {}
            }
        }
    }
    s.low <= s.high && s.equal.is_none_or(|code| s.permits(code))
}

pub(super) fn recover(
    pe: &PeFile,
    raw: &[u8],
    roots: &[Root],
    coverage: &mut Coverage,
) -> Vec<IoctlCodeCandidate> {
    let mut out = Vec::new();
    let mut length_checks: BTreeMap<(u32, u32), Vec<LengthCheck>> = BTreeMap::new();
    coverage.architecture_supported = pe.machine == 0x8664;
    coverage.dispatch_roots = roots.len();
    if pe.machine != 0x8664 {
        return out;
    }
    coverage.dispatch_analysis_truncated |= roots.len() > ROOT_LIMIT;
    let mut factory = InstructionInfoFactory::new();
    for root in roots.iter().take(ROOT_LIMIT) {
        coverage.analyzed_roots += 1;
        let mut pending = VecDeque::from([State::entry(root.rva)]);
        let mut visited: BTreeMap<u32, Vec<State>> = BTreeMap::new();
        let mut steps = 0;
        while let Some(mut s) = pending.pop_front() {
            loop {
                if steps >= ROOT_STEPS || coverage.decoded_dispatch_instructions >= TOTAL_STEPS {
                    coverage.dispatch_analysis_truncated = true;
                    break;
                }
                let states = visited.entry(s.pc).or_default();
                if states.contains(&s) {
                    break;
                }
                if states.len() >= 8 {
                    coverage.dispatch_analysis_truncated = true;
                    break;
                }
                states.push(s.clone());
                steps += 1;
                coverage.decoded_dispatch_instructions += 1;
                let Some(i) = decode(pe, raw, s.pc) else {
                    break;
                };
                let next = s.pc + i.len() as u32;
                match i.flow_control() {
                    FlowControl::Return | FlowControl::Exception | FlowControl::Interrupt => break,
                    FlowControl::IndirectBranch => {
                        coverage.unsupported_indirect_branches += 1;
                        break;
                    }
                    FlowControl::UnconditionalBranch => {
                        let Some(target) = pe.va_to_rva(i.near_branch_target()) else {
                            break;
                        };
                        s.pc = target;
                        continue;
                    }
                    FlowControl::ConditionalBranch => {
                        let condition = s.flags.clone();
                        if let (Some(code), Some(condition)) = (s.equal, condition.as_ref()) {
                            if let Some(check) =
                                lengths::check(pe, raw, &s, &i, condition, coverage)
                            {
                                let checks = length_checks.entry((root.rva, code)).or_default();
                                if !checks.contains(&check) {
                                    if checks.len() < 32 {
                                        checks.push(check);
                                    } else {
                                        coverage.length_analysis_truncated = true;
                                    }
                                }
                            }
                        }
                        let choice = s.known_flags.and_then(|f| known_branch(f, i.mnemonic()));
                        if matches!(i.mnemonic(), Mnemonic::Je | Mnemonic::Jne) {
                            if let Some(condition) = &condition {
                                if let Some(code) =
                                    comparison_code(condition).filter(|&n| s.permits(n))
                                {
                                    emit(&mut out, root, code, condition, None);
                                }
                            }
                        }
                        if let Some(target) = pe.va_to_rva(i.near_branch_target()) {
                            let mut taken = s.clone();
                            taken.pc = target;
                            if choice != Some(false)
                                && condition
                                    .as_ref()
                                    .is_none_or(|c| refine(&mut taken, c, i.mnemonic(), true))
                            {
                                if pending.len() < PENDING_LIMIT {
                                    pending.push_back(taken);
                                } else {
                                    coverage.dispatch_analysis_truncated = true;
                                }
                            }
                        }
                        if choice == Some(true)
                            || condition
                                .as_ref()
                                .is_some_and(|c| !refine(&mut s, c, i.mnemonic(), false))
                        {
                            break;
                        }
                        s.pc = next;
                        continue;
                    }
                    FlowControl::Call | FlowControl::IndirectCall => {
                        let args = [Register::RCX, Register::RDX, Register::R8, Register::R9];
                        let relevant = args.iter().any(|&r| {
                            matches!(
                                s.reg(r),
                                Some(
                                    Value::Irp
                                        | Value::IoStack
                                        | Value::Code(_)
                                        | Value::Length(_, _)
                                )
                            )
                        });
                        if i.flow_control() == FlowControl::Call && relevant {
                            if s.depth < 2 && pending.len() < PENDING_LIMIT {
                                if let Some(target) = pe
                                    .va_to_rva(i.near_branch_target())
                                    .filter(|&r| executable(pe, r))
                                {
                                    let mut child = State::entry(target);
                                    child.regs.clear();
                                    child.regs.insert(Register::RSP, Value::Local(0));
                                    child.depth = s.depth + 1;
                                    for r in args {
                                        if let Some(v) =
                                            s.reg(r).filter(|v| !matches!(v, Value::Local(_)))
                                        {
                                            child.regs.insert(r, v);
                                        }
                                    }
                                    child.equal = s.equal;
                                    child.excluded = s.excluded.clone();
                                    child.low = s.low;
                                    child.high = s.high;
                                    child.memory_valid = s.memory_valid;
                                    pending.push_back(child);
                                }
                            } else {
                                coverage.dispatch_analysis_truncated = true;
                            }
                        }
                        // Calls may mutate IRPs and any escaped locals. Keep
                        // request values already copied into nonvolatile regs.
                        if args.iter().any(|&r| {
                            matches!(
                                s.reg(r),
                                Some(Value::Local(_) | Value::Irp | Value::IoStack)
                            )
                        }) {
                            s.locals.clear();
                        }
                        for r in [
                            Register::RAX,
                            Register::RCX,
                            Register::RDX,
                            Register::R8,
                            Register::R9,
                            Register::R10,
                            Register::R11,
                        ] {
                            s.regs.remove(&r);
                        }
                        s.flags = None;
                        s.known_flags = None;
                        s.pc = next;
                        continue;
                    }
                    _ => {}
                }
                let left = (i.op_count() > 0).then(|| operand(pe, &s, &i, 0)).flatten();
                let right = (i.op_count() > 1).then(|| operand(pe, &s, &i, 1)).flatten();
                let destination = (i.op_count() > 0 && i.op0_kind() == OpKind::Register)
                    .then(|| i.op0_register());
                let width = destination.map_or(i.memory_size().size(), |r| r.size());
                let mut value = None;
                let mut condition = None;
                let mut computed_flags = match (left, right) {
                    (Some(Value::Constant(a)), Some(Value::Constant(b))) => {
                        constant_flags(i.mnemonic(), a, b, width)
                    }
                    _ => None,
                };
                let mut text = String::new();
                IntelFormatter::new().format(&i, &mut text);
                if i.mnemonic() == Mnemonic::Mov {
                    value = right;
                }
                if i.mnemonic() == Mnemonic::Lea {
                    value = if i.is_ip_rel_memory_operand() {
                        Some(Value::Constant(i.ip_rel_memory_address()))
                    } else {
                        local_address(&s, &i).map(Value::Local).or_else(|| {
                            if width == 4 && i.memory_index() == Register::None {
                                if let Some(Value::Code(offset)) = s.reg(i.memory_base()) {
                                    return Some(Value::Code(
                                        offset.wrapping_add(i.memory_displacement64() as u32),
                                    ));
                                }
                            }
                            None
                        })
                    };
                }
                if matches!(i.mnemonic(), Mnemonic::Add | Mnemonic::Sub) {
                    if let (Some(a), Some(Value::Constant(n))) = (left, right) {
                        value = match a {
                            Value::Code(offset) if width == 4 => {
                                Some(Value::Code(if i.mnemonic() == Mnemonic::Sub {
                                    offset.wrapping_sub(n as u32)
                                } else {
                                    offset.wrapping_add(n as u32)
                                }))
                            }
                            Value::Constant(a) => {
                                Some(Value::Constant(if i.mnemonic() == Mnemonic::Sub {
                                    a.wrapping_sub(n)
                                } else {
                                    a.wrapping_add(n)
                                }))
                            }
                            Value::Local(a) => (if i.mnemonic() == Mnemonic::Sub {
                                a.checked_sub(n as i64)
                            } else {
                                a.checked_add(n as i64)
                            })
                            .map(Value::Local),
                            _ => None,
                        };
                        if let Some(Value::Code(offset)) = value {
                            condition = Some(Condition {
                                left: Value::Code(offset),
                                right: Value::Constant(0),
                                site: s.pc,
                                instruction: text.clone(),
                            });
                        }
                    }
                }
                if i.mnemonic() == Mnemonic::Cmp {
                    if let (Some(left), Some(right)) = (left, right) {
                        condition = Some(Condition {
                            left,
                            right,
                            site: s.pc,
                            instruction: text.clone(),
                        });
                    }
                }
                if i.mnemonic() == Mnemonic::Test && left == right {
                    if let Some(Value::Code(offset)) = left {
                        condition = Some(Condition {
                            left: Value::Code(offset),
                            right: Value::Constant(0),
                            site: s.pc,
                            instruction: text.clone(),
                        });
                    }
                }
                if i.mnemonic() == Mnemonic::Xor
                    && i.op0_kind() == OpKind::Register
                    && i.op1_kind() == OpKind::Register
                    && i.op0_register() == i.op1_register()
                {
                    value = Some(Value::Constant(0));
                    computed_flags = Some(Flags {
                        zero: true,
                        sign: false,
                        carry: false,
                        overflow: false,
                    });
                }
                if i.mnemonic() == Mnemonic::Shr && width == 4 {
                    if let (Some(Value::Code(0)), Some(Value::Constant(shift))) = (left, right) {
                        value = Some(Value::Index(Index {
                            shift: (shift as u32) & 31,
                            mask: u32::MAX,
                        }));
                    }
                }
                if i.mnemonic() == Mnemonic::And && width == 4 {
                    if let (Some(Value::Index(index)), Some(Value::Constant(mask))) = (left, right)
                    {
                        value = Some(Value::Index(Index {
                            mask: index.mask & mask as u32,
                            ..index
                        }));
                    }
                }
                if i.mnemonic() == Mnemonic::Mov
                    && i.op1_kind() == OpKind::Memory
                    && i.memory_size().size() == 8
                {
                    if let (Some(validated), Some((handlers, index))) =
                        (s.table.as_ref(), table_address(pe, &s, &i, 8))
                    {
                        if index == validated.index {
                            for slot in 0..validated.count {
                                let code = validated
                                    .base
                                    .checked_add(slot * 4)
                                    .and_then(|r| pe.rva_bytes(raw, r))
                                    .and_then(|b| b.get(..4))
                                    .map(|b| u32::from_le_bytes(b.try_into().unwrap()));
                                let target = handlers
                                    .checked_add(slot * 8)
                                    .and_then(|r| pe.rva_bytes(raw, r))
                                    .and_then(|b| b.get(..8))
                                    .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                                    .and_then(|va| pe.va_to_rva(va));
                                if let (Some(code), Some(target)) = (code, target) {
                                    if (code >> index.shift) & index.mask == slot
                                        && executable(pe, target)
                                        && s.permits(code)
                                    {
                                        emit(
                                            &mut out,
                                            root,
                                            code,
                                            &Condition {
                                                left: Value::Code(0),
                                                right: Value::Constant(code as u64),
                                                site: validated.site,
                                                instruction: validated.instruction.clone(),
                                            },
                                            Some((validated.base, target)),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                let writes = factory.info(&i).used_memory().iter().any(|m| {
                    matches!(
                        m.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    )
                });
                if writes {
                    // PUSH writes an implicit stack slot, not unknown memory.
                    let write = if i.mnemonic() == Mnemonic::Push {
                        match s.reg(Register::RSP) {
                            Some(Value::Local(sp)) => sp
                                .checked_add(i.stack_pointer_increment() as i64)
                                .map(|offset| {
                                    (offset, i.stack_pointer_increment().unsigned_abs() as usize)
                                }),
                            _ => None,
                        }
                    } else {
                        local_address(&s, &i).map(|offset| (offset, i.memory_size().size()))
                    };
                    if let Some((offset, size)) = write {
                        s.locals.retain(|&start, (width, _)| {
                            start.saturating_add(*width as i64) <= offset
                                || start >= offset.saturating_add(size as i64)
                        });
                        if i.mnemonic() == Mnemonic::Mov && s.locals.len() < 128 {
                            if let Some(v) = right {
                                s.locals.insert(offset, (size, v));
                            }
                        }
                    } else {
                        s.locals.clear();
                        let field = match s.reg(i.memory_base()) {
                            Some(Value::Irp) => Some((0xb8u64, 8)),
                            Some(Value::IoStack) => Some((0x08u64, 0x14)),
                            _ => None,
                        };
                        if let Some((offset, size)) = field {
                            let start = i.memory_displacement64();
                            if i.memory_index() != Register::None
                                || (start < offset + size
                                    && start.saturating_add(i.memory_size().size() as u64) > offset)
                            {
                                s.memory_valid = false;
                            }
                        }
                    }
                }
                let old_sp = s.reg(Register::RSP);
                for used in factory.info(&i).used_registers() {
                    if matches!(
                        used.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    ) {
                        s.regs.remove(&used.register().full_register());
                    }
                }
                if let (Some(reg), Some(mut v)) = (destination, value) {
                    if reg.size() == 4 {
                        v = match v {
                            Value::Constant(n) => Value::Constant(n & u32::MAX as u64),
                            Value::Code(_) | Value::Index(_) | Value::Length(_, _) => v,
                            _ => {
                                s.pc = next;
                                continue;
                            }
                        };
                    }
                    if matches!(reg.size(), 4 | 8) {
                        s.regs.insert(reg.full_register(), v);
                    }
                }
                if matches!(i.mnemonic(), Mnemonic::Push | Mnemonic::Pop) {
                    if let Some(Value::Local(sp)) = old_sp {
                        let delta = i.stack_pointer_increment() as i64;
                        if let Some(sp) = sp.checked_add(delta) {
                            s.regs.insert(Register::RSP, Value::Local(sp));
                            s.locals.remove(&sp);
                        }
                    }
                }
                if i.rflags_modified() != 0 {
                    s.flags = condition;
                    s.known_flags = computed_flags;
                }
                s.pc = next;
            }
            if steps >= ROOT_STEPS || coverage.decoded_dispatch_instructions >= TOTAL_STEPS {
                break;
            }
        }
        if coverage.decoded_dispatch_instructions >= TOTAL_STEPS {
            break;
        }
    }
    for candidate in &mut out {
        if let (Ok(root), Ok(code)) = (
            u32::from_str_radix(candidate.owner_rva.trim_start_matches("0x"), 16),
            u32::from_str_radix(candidate.code.trim_start_matches("0x"), 16),
        ) {
            candidate.length_checks = length_checks
                .get(&(root, code))
                .cloned()
                .unwrap_or_default();
        }
    }
    out
}
