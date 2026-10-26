//! Conditional length guards, never a complete or runtime-validated ABI.
use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Buffer {
    Input,
    Output,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LengthCheck {
    pub buffer: String,
    pub relation: String,
    pub bytes: u64,
    pub site_rva: String,
    pub branch_rva: String,
    pub failure_site_rva: String,
    pub failure_status: String,
    pub evidence_status: String,
}

// Only a short straight-line failure edge is accepted. Calls preserve the
// nonvolatile registers, but their return values are unknown. We stop at an
// additional conditional branch: a later failure must not be attributed to
// the original length test when another predicate controls it.
fn failure_edge(
    pe: &PeFile,
    raw: &[u8],
    state: &State,
    pc: u32,
    coverage: &mut Coverage,
) -> Option<(u32, u32)> {
    let mut s = state.clone();
    s.pc = pc;
    let mut factory = InstructionInfoFactory::new();
    for _ in 0..48 {
        if coverage.length_probe_instructions >= 16384 {
            coverage.length_analysis_truncated = true;
            return None;
        }
        coverage.length_probe_instructions += 1;
        let i = decode(pe, raw, s.pc)?;
        let right = (i.op_count() > 1).then(|| operand(pe, &s, &i, 1)).flatten();
        if i.mnemonic() == Mnemonic::Mov
            && i.op0_kind() == OpKind::Memory
            && i.memory_size().size() == 4
            && i.memory_index() == Register::None
            && i.memory_displacement64() == 0x30
            && s.reg(i.memory_base()) == Some(Value::Irp)
        {
            if let Some(Value::Constant(status)) = right {
                if size_failure(status as u32) {
                    return Some((status as u32, s.pc));
                }
            }
        }
        match i.flow_control() {
            FlowControl::Return => {
                return match s.reg(Register::EAX) {
                    Some(Value::Constant(status)) if size_failure(status as u32) => {
                        Some((status as u32, s.pc))
                    }
                    _ => None,
                };
            }
            FlowControl::UnconditionalBranch => {
                s.pc = pe.va_to_rva(i.near_branch_target())?;
                continue;
            }
            FlowControl::Call | FlowControl::IndirectCall => {
                for reg in [
                    Register::RAX,
                    Register::RCX,
                    Register::RDX,
                    Register::R8,
                    Register::R9,
                    Register::R10,
                    Register::R11,
                ] {
                    s.regs.remove(&reg);
                }
                s.locals.clear();
            }
            FlowControl::Next => {
                let value = match i.mnemonic() {
                    Mnemonic::Mov => right,
                    Mnemonic::Xor
                        if i.op0_kind() == OpKind::Register
                            && i.op1_kind() == OpKind::Register
                            && i.op0_register() == i.op1_register() =>
                    {
                        Some(Value::Constant(0))
                    }
                    _ => None,
                };
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
                if i.op0_kind() == OpKind::Register {
                    let reg = i.op0_register();
                    if matches!(reg.size(), 4 | 8) {
                        if let Some(mut value) = value {
                            if reg.size() == 4 {
                                value = match value {
                                    Value::Constant(n) => Value::Constant(n & u32::MAX as u64),
                                    _ => {
                                        s.pc += i.len() as u32;
                                        continue;
                                    }
                                };
                            }
                            s.regs.insert(reg.full_register(), value);
                        }
                    }
                }
                // A saved pointer may have been overwritten; don't reload it.
                if factory.info(&i).used_memory().iter().any(|m| {
                    matches!(
                        m.access(),
                        OpAccess::Write
                            | OpAccess::CondWrite
                            | OpAccess::ReadWrite
                            | OpAccess::ReadCondWrite
                    )
                }) {
                    s.locals.clear();
                }
            }
            _ => return None,
        }
        s.pc = s.pc.checked_add(i.len() as u32)?;
    }
    None
}

fn size_failure(status: u32) -> bool {
    matches!(status, 0xc0000004 | 0xc000000d | 0xc0000023 | 0xc0000206)
}

pub(super) fn check(
    pe: &PeFile,
    raw: &[u8],
    s: &State,
    branch: &Instruction,
    condition: &Condition,
    coverage: &mut Coverage,
) -> Option<LengthCheck> {
    let (buffer, bytes, reversed) = match (condition.left, condition.right) {
        (Value::Length(buffer, _), Value::Constant(bytes)) => (buffer, bytes, false),
        (Value::Constant(bytes), Value::Length(buffer, _)) => (buffer, bytes, true),
        _ => return None,
    };
    let mut relation = match branch.mnemonic() {
        Mnemonic::Je => "==",
        Mnemonic::Jne => "!=",
        Mnemonic::Jb => "<",
        Mnemonic::Jbe => "<=",
        Mnemonic::Ja => ">",
        Mnemonic::Jae => ">=",
        _ => return None,
    };
    if reversed {
        relation = reverse(relation);
    }
    let taken = failure_edge(
        pe,
        raw,
        s,
        pe.va_to_rva(branch.near_branch_target())?,
        coverage,
    );
    let fallthrough = failure_edge(pe, raw, s, s.pc.checked_add(branch.len() as u32)?, coverage);
    let (status, site) = match (taken, fallthrough) {
        (Some(failure), None) => {
            relation = invert(relation);
            failure
        }
        (None, Some(failure)) => failure,
        _ => return None,
    };
    Some(LengthCheck {
        buffer: match buffer { Buffer::Input => "input", Buffer::Output => "output" }.into(),
        relation: relation.into(), bytes,
        site_rva: format!("0x{:08X}", condition.site), branch_rva: format!("0x{:08X}", s.pc),
        failure_site_rva: format!("0x{site:08X}"), failure_status: format!("0x{status:08X}"),
        evidence_status: "static-conditional-length-guard; opposite-edge-sets-or-returns-size-error; not-complete-contract".into(),
    })
}

fn reverse(relation: &str) -> &str {
    match relation {
        "<" => ">",
        "<=" => ">=",
        ">" => "<",
        ">=" => "<=",
        _ => relation,
    }
}
fn invert(relation: &str) -> &str {
    match relation {
        "==" => "!=",
        "!=" => "==",
        "<" => ">=",
        "<=" => ">",
        ">" => "<=",
        _ => "<",
    }
}
