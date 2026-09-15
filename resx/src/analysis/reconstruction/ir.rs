use iced_x86::{Mnemonic, OpKind, Register};
use serde::Serialize;

use crate::analysis::disasm::{is_jcc, is_ret, Instruction};
use crate::analysis::symbols::SymbolIndex;

#[derive(Debug, Clone, Serialize)]
pub struct IrOp {
    pub rva: String,
    pub op: String,
    pub dst: String,
    pub src: Vec<String>,
    pub ty: String,
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct TypedIrSummary {
    pub prototype: String,
    pub param_hints: Vec<TypeHint>,
    pub stack_slots: Vec<StackSlot>,
    pub memory_refs: Vec<MemoryRef>,
    pub ops: Vec<IrOp>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TypeHint {
    pub name: String,
    pub ty: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct StackSlot {
    pub offset: String,
    pub access: String,
    pub width: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemoryRef {
    pub rva: String,
    pub access: String,
    pub base: String,
    pub index: String,
    pub displacement: String,
    pub resolved: String,
}

pub fn summarize_typed_ir(
    insns: &[Instruction],
    image_base: u64,
    symbols: Option<&SymbolIndex>,
    prototype: &str,
) -> TypedIrSummary {
    let mut summary = TypedIrSummary {
        prototype: prototype.to_owned(),
        param_hints: parse_param_hints(prototype),
        stack_slots: Vec::new(),
        memory_refs: Vec::new(),
        ops: Vec::new(),
    };

    for insn in insns {
        if let Some(slot) = stack_slot(insn) {
            if !summary
                .stack_slots
                .iter()
                .any(|existing| existing.offset == slot.offset && existing.access == slot.access)
            {
                summary.stack_slots.push(slot);
            }
        }
        if let Some(memory) = memory_ref(insn, image_base, symbols) {
            summary.memory_refs.push(memory);
        }
        summary.ops.push(ir_op(insn, image_base, symbols));
    }

    summary.stack_slots.sort_by(|a, b| a.offset.cmp(&b.offset));
    summary.memory_refs.sort_by(|a, b| a.rva.cmp(&b.rva));
    summary
}

fn ir_op(insn: &Instruction, image_base: u64, symbols: Option<&SymbolIndex>) -> IrOp {
    let iced = &insn.iced;
    let op = match iced.mnemonic() {
        Mnemonic::Mov | Mnemonic::Movsx | Mnemonic::Movsxd | Mnemonic::Movzx => "assign",
        Mnemonic::Lea => "address",
        Mnemonic::Add | Mnemonic::Sub | Mnemonic::Imul | Mnemonic::Mul => "arith",
        Mnemonic::And | Mnemonic::Or | Mnemonic::Xor | Mnemonic::Not | Mnemonic::Neg => "bit",
        Mnemonic::Cmp | Mnemonic::Test => "compare",
        Mnemonic::Call => "call",
        Mnemonic::Jmp => "jump",
        m if is_jcc(m) => "branch",
        m if is_ret(m) => "return",
        Mnemonic::Push | Mnemonic::Pop => "stack",
        Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Int => "syscall",
        _ => "other",
    }
    .to_owned();

    let dst = if iced.op_count() > 0 {
        operand_text(iced, 0, image_base, symbols)
    } else {
        String::new()
    };
    let src = (1..iced.op_count())
        .map(|idx| operand_text(iced, idx, image_base, symbols))
        .collect::<Vec<_>>();
    let ty = infer_type(iced);
    let detail = if insn.comment.is_empty() {
        insn.text.clone()
    } else {
        format!("{} ; {}", insn.text, insn.comment)
    };

    IrOp {
        rva: hex32(insn.rva),
        op,
        dst,
        src,
        ty,
        detail,
    }
}

fn operand_text(
    instr: &iced_x86::Instruction,
    op_idx: u32,
    image_base: u64,
    symbols: Option<&SymbolIndex>,
) -> String {
    match instr.op_kind(op_idx) {
        OpKind::Register => reg_name(instr.op_register(op_idx)),
        OpKind::Memory => memory_expr(instr, image_base, symbols),
        OpKind::Immediate8 => format!("0x{:X}", instr.immediate8()),
        OpKind::Immediate16 => format!("0x{:X}", instr.immediate16()),
        OpKind::Immediate32 | OpKind::Immediate32to64 => format!("0x{:X}", instr.immediate32()),
        OpKind::Immediate64 => format!("0x{:X}", instr.immediate64()),
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            let target = instr.near_branch_target();
            symbols
                .and_then(|idx| idx.describe(target))
                .unwrap_or_else(|| format!("0x{:X}", target))
        }
        _ => "?".to_owned(),
    }
}

fn memory_expr(
    instr: &iced_x86::Instruction,
    image_base: u64,
    symbols: Option<&SymbolIndex>,
) -> String {
    if let Some(addr) = absolute_memory_address(instr) {
        if let Some(desc) = symbols.and_then(|idx| idx.describe(addr)) {
            return format!("*({})", desc);
        }
        if addr >= image_base {
            return format!("*(image+0x{:X})", addr - image_base);
        }
        return format!("*(0x{:X})", addr);
    }

    let base = reg_name(instr.memory_base());
    let index = reg_name(instr.memory_index());
    let scale = instr.memory_index_scale();
    let disp = instr.memory_displacement64() as i64;
    let mut parts = Vec::new();
    if !base.is_empty() {
        parts.push(base);
    }
    if !index.is_empty() {
        parts.push(if scale > 1 {
            format!("{index}*{scale}")
        } else {
            index
        });
    }
    if disp > 0 {
        parts.push(format!("0x{:X}", disp));
    } else if disp < 0 {
        parts.push(format!("-0x{:X}", (-disp) as u64));
    }
    if parts.is_empty() {
        "*(?)".to_owned()
    } else {
        format!("*({})", parts.join("+"))
    }
}

fn stack_slot(insn: &Instruction) -> Option<StackSlot> {
    let instr = &insn.iced;
    if instr.memory_base().full_register() != Register::RSP
        && instr.memory_base().full_register() != Register::RBP
        && instr.memory_base().full_register() != Register::ESP
        && instr.memory_base().full_register() != Register::EBP
    {
        return None;
    }
    let access = if instr.op0_kind() == OpKind::Memory {
        "write"
    } else {
        "read"
    };
    Some(StackSlot {
        offset: format!(
            "{}+0x{:X}",
            reg_name(instr.memory_base()),
            instr.memory_displacement64()
        ),
        access: access.to_owned(),
        width: instr.memory_size().size() as u32,
    })
}

fn memory_ref(
    insn: &Instruction,
    image_base: u64,
    symbols: Option<&SymbolIndex>,
) -> Option<MemoryRef> {
    let instr = &insn.iced;
    if instr.op_count() == 0 || !uses_memory(instr) {
        return None;
    }
    let access = if instr.op0_kind() == OpKind::Memory {
        "write"
    } else {
        "read"
    };
    let resolved = absolute_memory_address(instr)
        .and_then(|addr| {
            symbols.and_then(|idx| idx.describe(addr)).or_else(|| {
                (addr >= image_base).then(|| format!("image+0x{:X}", addr - image_base))
            })
        })
        .unwrap_or_default();

    Some(MemoryRef {
        rva: hex32(insn.rva),
        access: access.to_owned(),
        base: reg_name(instr.memory_base()),
        index: reg_name(instr.memory_index()),
        displacement: format!("0x{:X}", instr.memory_displacement64()),
        resolved,
    })
}

fn uses_memory(instr: &iced_x86::Instruction) -> bool {
    (0..instr.op_count()).any(|idx| instr.op_kind(idx) == OpKind::Memory)
}

fn infer_type(instr: &iced_x86::Instruction) -> String {
    let width = if uses_memory(instr) {
        instr.memory_size().size() as u32 * 8
    } else if instr.op_count() > 0 && instr.op0_kind() == OpKind::Register {
        register_width(instr.op0_register())
    } else {
        0
    };
    if width == 0 {
        String::new()
    } else {
        format!("u{}", width)
    }
}

fn register_width(reg: Register) -> u32 {
    match reg.full_register() {
        Register::RAX
        | Register::RBX
        | Register::RCX
        | Register::RDX
        | Register::RSI
        | Register::RDI
        | Register::RSP
        | Register::RBP
        | Register::R8
        | Register::R9
        | Register::R10
        | Register::R11
        | Register::R12
        | Register::R13
        | Register::R14
        | Register::R15 => 64,
        Register::EAX
        | Register::EBX
        | Register::ECX
        | Register::EDX
        | Register::ESI
        | Register::EDI
        | Register::ESP
        | Register::EBP
        | Register::R8D
        | Register::R9D
        | Register::R10D
        | Register::R11D
        | Register::R12D
        | Register::R13D
        | Register::R14D
        | Register::R15D => 32,
        _ => 0,
    }
}

fn absolute_memory_address(instr: &iced_x86::Instruction) -> Option<u64> {
    if matches!(instr.memory_base(), Register::RIP | Register::EIP) {
        return Some(instr.ip_rel_memory_address());
    }
    if instr.memory_base() == Register::None && instr.memory_index() == Register::None {
        let disp = instr.memory_displacement64();
        if disp != 0 {
            return Some(disp);
        }
    }
    None
}

fn parse_param_hints(prototype: &str) -> Vec<TypeHint> {
    let Some(open) = prototype.rfind('(') else {
        return Vec::new();
    };
    let Some(close) = prototype.rfind(')') else {
        return Vec::new();
    };
    if close <= open {
        return Vec::new();
    }
    prototype[open + 1..close]
        .split(',')
        .enumerate()
        .filter_map(|(idx, raw)| {
            let ty = raw.trim();
            if ty.is_empty() || ty.eq_ignore_ascii_case("void") {
                return None;
            }
            Some(TypeHint {
                name: format!("param_{}", idx + 1),
                ty: ty.to_owned(),
                source: "pdb-prototype".to_owned(),
            })
        })
        .collect()
}

fn reg_name(reg: Register) -> String {
    if reg == Register::None {
        String::new()
    } else {
        format!("{:?}", reg.full_register()).to_ascii_lowercase()
    }
}

fn hex32(value: u32) -> String {
    format!("0x{:08X}", value)
}
