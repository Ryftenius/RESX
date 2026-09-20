use super::*;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct Value {
    pub(super) origins: u16,
    pub(super) origin_width: usize,
    // Only definitely produced return widths survive control-flow joins.
    pub(super) width: usize,
    pub(super) float: bool,
    pub(super) pointer: bool,
    /// Address relative to the entry stack pointer when this value is a
    /// provable stack alias (for example `lea r10, [rsp+68h]`).
    pub(super) stack_addr: Option<i64>,
}

#[derive(Clone, Default, PartialEq, Eq)]
pub(super) struct State {
    pub(super) regs: BTreeMap<Register, Value>,
    pub(super) stack: BTreeMap<i64, Value>,
    pub(super) sp: Option<i64>,
    pub(super) bp: Option<i64>,
}

pub(super) fn read(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Read | OpAccess::CondRead | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}
pub(super) fn write(access: OpAccess) -> bool {
    matches!(
        access,
        OpAccess::Write | OpAccess::CondWrite | OpAccess::ReadWrite | OpAccess::ReadCondWrite
    )
}
pub(super) fn reg_value(state: &State, reg: Register) -> Value {
    state
        .regs
        .get(&reg.full_register())
        .copied()
        .unwrap_or_default()
}
pub(super) fn stack_address(state: &State, ins: &iced_x86::Instruction) -> Option<i64> {
    if ins.memory_index() != Register::None {
        return None;
    }
    let base_reg = ins.memory_base().full_register();
    let base = match base_reg {
        Register::RSP => state.sp,
        Register::RBP => state.bp,
        _ => reg_value(state, base_reg).stack_addr,
    }?;
    base.checked_add(ins.memory_displacement64() as i64)
}
pub(super) fn record(
    params: &mut [Parameter],
    origins: u16,
    width: usize,
    rva: u32,
    rd: bool,
    wr: bool,
) {
    for p in params {
        if origins & (1 << p.index) == 0 {
            continue;
        }
        p.pointer_read |= rd;
        p.pointer_write |= wr;
        if width > 0 && !p.widths.contains(&width) {
            p.widths.push(width);
            p.widths.sort_unstable();
        }
        if p.evidence_rvas.len() < 8 && !p.evidence_rvas.contains(&rva) {
            p.evidence_rvas.push(rva);
        }
    }
}
pub(super) fn merge(old: &mut State, new: &State) -> bool {
    let before = old.clone();
    // Missing values at a join are unknown, never assumed to retain their type.
    let keys: Vec<_> = old.regs.keys().chain(new.regs.keys()).copied().collect();
    for k in keys {
        let a = old.regs.get(&k).copied().unwrap_or_default();
        let b = new.regs.get(&k).copied().unwrap_or_default();
        old.regs.insert(
            k,
            Value {
                origins: a.origins | b.origins,
                origin_width: if a.origin_width == b.origin_width {
                    a.origin_width
                } else {
                    0
                },
                width: if a.width == b.width && a.float == b.float {
                    a.width
                } else {
                    0
                },
                float: a.float && b.float,
                pointer: a.pointer && b.pointer,
                stack_addr: if a.stack_addr == b.stack_addr {
                    a.stack_addr
                } else {
                    None
                },
            },
        );
    }
    old.stack.retain(|k, v| new.stack.get(k) == Some(v));
    if old.sp != new.sp {
        old.sp = None;
    }
    if old.bp != new.bp {
        old.bp = None;
    }
    *old != before
}
