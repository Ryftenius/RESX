//! Bounded static x64 call-site facts. No target execution or kernel-object lookup.
use super::{DecodedInsn, PeFile};
use crate::formats::pe::{read_imports, read_u32, IMAGE_SCN_MEM_WRITE};
use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
mod ndis;
mod semantic;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Value {
    Unknown,
    FunctionArgument {
        index: u8,
        width: u8,
        origin_rva: u32,
    },
    Symbolic {
        expression: String,
        origin_rva: u32,
    },
    Constant {
        value: u64,
        origin_rva: u32,
    },
    ImageAddress {
        rva: u32,
        origin_rva: u32,
    },
    StackAddress {
        offset: i64,
        origin_rva: u32,
    },
    ImageMemory {
        rva: u32,
        origin_rva: u32,
    },
    Import {
        dll: String,
        name: String,
    },
    ApiResult {
        api: String,
        call_site: u32,
        path: Option<String>,
    },
    ApiOutput {
        api: String,
        call_site: u32,
        argument: String,
    },
}

impl Value {
    fn low_dword(self) -> Self {
        match self {
            Self::Constant { value, origin_rva } => Self::Constant {
                value: value & 0xffff_ffff,
                origin_rva,
            },
            Self::FunctionArgument {
                index, origin_rva, ..
            } => Self::FunctionArgument {
                index,
                width: 4,
                origin_rva,
            },
            Self::Symbolic {
                expression,
                origin_rva,
            } => Self::Symbolic {
                expression,
                origin_rva,
            },
            _ => Self::Unknown,
        }
    }
    pub fn constant(&self) -> Option<u64> {
        if let Self::Constant { value, .. } = self {
            Some(*value)
        } else {
            None
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Argument {
    pub name: String,
    pub value: Value,
}

#[derive(Clone, Debug, Serialize)]
pub struct BufferField {
    pub buffer: String,
    pub offset: u64,
    pub width: usize,
    pub value: Value,
    pub evidence: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct CallEvidence {
    pub category: String,
    pub api: String,
    pub dll: String,
    pub site_rva: u32,
    pub owner_rva: u32,
    pub owner_name: String,
    pub arguments: Vec<Argument>,
    pub buffer_fields: Vec<BufferField>,
    pub ioctl_code: Option<u32>,
    pub device_handle: Value,
    pub kernel_object_identity: Option<String>,
    pub ndis_oid: Option<u32>,
    pub oid_evidence: Option<String>,
    pub ndis_request: Option<ndis::RequestEvidence>,
    pub status: String,
    pub reconstructed_call: String,
    pub details: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stored {
    width: usize,
    value: Value,
}

#[derive(Clone, Default)]
struct State {
    regs: BTreeMap<Register, Value>,
    stack: BTreeMap<i64, Stored>,
    last_compare: Option<(Value, Value)>,
}

impl State {
    fn fresh() -> Self {
        let mut state = Self::default();
        state.regs.insert(
            Register::RSP,
            Value::StackAddress {
                offset: 0,
                origin_rva: 0,
            },
        );
        state
    }

    fn function_entry(owner_rva: u32) -> Self {
        let mut state = Self::fresh();
        for (index, register) in [Register::RCX, Register::RDX, Register::R8, Register::R9]
            .into_iter()
            .enumerate()
        {
            state.regs.insert(
                register,
                Value::FunctionArgument {
                    index: index as u8,
                    width: 8,
                    origin_rva: owner_rva,
                },
            );
        }
        for index in 4..16usize {
            state.stack.insert(
                0x28 + ((index - 4) * 8) as i64,
                Stored {
                    width: 8,
                    value: Value::FunctionArgument {
                        index: index as u8,
                        width: 8,
                        origin_rva: owner_rva,
                    },
                },
            );
        }
        state
    }

    fn intersect(&self, other: &Self) -> Self {
        let regs = self
            .regs
            .iter()
            .filter(|(register, value)| other.regs.get(register) == Some(*value))
            .map(|(register, value)| (*register, value.clone()))
            .collect();
        let stack = self
            .stack
            .iter()
            .filter(|(offset, value)| other.stack.get(offset) == Some(*value))
            .map(|(offset, value)| (*offset, value.clone()))
            .collect();
        let last_compare = (self.last_compare == other.last_compare)
            .then(|| self.last_compare.clone())
            .flatten();
        Self {
            regs,
            stack,
            last_compare,
        }
    }

    fn reg(&self, reg: Register) -> Value {
        let value = self
            .regs
            .get(&reg.full_register())
            .cloned()
            .unwrap_or(Value::Unknown);
        if matches!(reg.size(), 1 | 2) {
            return match value {
                Value::Constant { value, origin_rva } => {
                    let shift = if matches!(
                        reg,
                        Register::AH | Register::BH | Register::CH | Register::DH
                    ) {
                        8
                    } else {
                        0
                    };
                    let mask = if reg.size() == 1 { 0xff } else { 0xffff };
                    Value::Constant {
                        value: (value >> shift) & mask,
                        origin_rva,
                    }
                }
                _ => Value::Unknown,
            };
        }
        if reg.size() == 4 {
            return value.low_dword();
        }
        value
    }

    fn address(&self, pe: &PeFile, instr: &Instruction, site: u32) -> Value {
        if instr.is_ip_rel_memory_operand() {
            return pe
                .va_to_rva(instr.ip_rel_memory_address())
                .map(|rva| Value::ImageAddress {
                    rva,
                    origin_rva: site,
                })
                .unwrap_or(Value::Unknown);
        }
        if instr.memory_index() != Register::None {
            return Value::Unknown;
        }
        if let Value::StackAddress { offset, .. } = self.reg(instr.memory_base()) {
            return offset
                .checked_add(instr.memory_displacement64() as i64)
                .map(|offset| Value::StackAddress {
                    offset,
                    origin_rva: site,
                })
                .unwrap_or(Value::Unknown);
        }
        if let Value::ImageAddress { rva, .. } = self.reg(instr.memory_base()) {
            return i64::from(rva)
                .checked_add(instr.memory_displacement64() as i64)
                .and_then(|rva| u32::try_from(rva).ok())
                .map(|rva| Value::ImageAddress {
                    rva,
                    origin_rva: site,
                })
                .unwrap_or(Value::Unknown);
        }
        Value::Unknown
    }

    fn operand(
        &self,
        pe: &PeFile,
        instr: &Instruction,
        index: u32,
        site: u32,
        imports: &BTreeMap<u32, Value>,
    ) -> Value {
        let scalar = match instr.op_kind(index) {
            OpKind::Register => return self.reg(instr.op_register(index)),
            OpKind::Immediate8 => Some(u64::from(instr.immediate8())),
            OpKind::Immediate16 => Some(u64::from(instr.immediate16())),
            OpKind::Immediate32 => Some(u64::from(instr.immediate32())),
            OpKind::Immediate64 => Some(instr.immediate64()),
            OpKind::Immediate8to64 => Some(instr.immediate8to64() as u64),
            OpKind::Immediate32to64 => Some(instr.immediate32to64() as u64),
            OpKind::Immediate8to32 => Some(instr.immediate8to32() as u32 as u64),
            OpKind::Memory => {
                return match self.address(pe, instr, site) {
                    Value::StackAddress { offset, .. } => self
                        .stack
                        .get(&offset)
                        .filter(|stored| stored.width == instr.memory_size().size())
                        .map(|stored| stored.value.clone())
                        .unwrap_or(Value::Unknown),
                    Value::ImageAddress { rva, .. } => {
                        imports.get(&rva).cloned().unwrap_or(Value::ImageMemory {
                            rva,
                            origin_rva: site,
                        })
                    }
                    _ => Value::Unknown,
                };
            }
            _ => None,
        };
        scalar
            .map(|value| Value::Constant {
                value,
                origin_rva: site,
            })
            .unwrap_or(Value::Unknown)
    }

    fn argument(&self, index: usize, width: usize) -> Value {
        let value = self.argument_full(index, width);
        if matches!(width, 1 | 2 | 4) {
            match value {
                Value::Constant { value, origin_rva } => Value::Constant {
                    value: value & (u64::MAX >> ((8 - width) * 8)),
                    origin_rva,
                },
                Value::FunctionArgument {
                    index, origin_rva, ..
                } => Value::FunctionArgument {
                    index,
                    width: width as u8,
                    origin_rva,
                },
                Value::Symbolic {
                    expression,
                    origin_rva,
                } => Value::Symbolic {
                    expression,
                    origin_rva,
                },
                _ => Value::Unknown,
            }
        } else {
            value
        }
    }

    fn argument_full(&self, index: usize, width: usize) -> Value {
        if index < 4 {
            return self.reg([Register::RCX, Register::RDX, Register::R8, Register::R9][index]);
        }
        let Value::StackAddress { offset, .. } = self.reg(Register::RSP) else {
            return Value::Unknown;
        };
        offset
            .checked_add(0x20 + ((index - 4) * 8) as i64)
            .and_then(|offset| self.stack.get(&offset))
            .filter(|stored| stored.width >= width)
            .map(|stored| stored.value.clone())
            .unwrap_or(Value::Unknown)
    }

    fn step(
        &mut self,
        pe: &PeFile,
        insn: &DecodedInsn,
        imports: &BTreeMap<u32, Value>,
        factory: &mut InstructionInfoFactory,
    ) {
        let instr = &insn.instr;
        let destination = (instr.op_count() != 0 && instr.op0_kind() == OpKind::Register)
            .then(|| instr.op0_register());
        let prior_compare = self.last_compare.clone();
        let next_compare = if instr.mnemonic() == Mnemonic::Cmp && instr.op_count() >= 2 {
            Some((
                self.operand(pe, instr, 0, insn.rva, imports),
                self.operand(pe, instr, 1, insn.rva, imports),
            ))
        } else if instr.rflags_modified() == 0 {
            prior_compare.clone()
        } else {
            None
        };
        let mut result = Value::Unknown;
        if instr.op_count() >= 2 {
            result = match instr.mnemonic() {
                Mnemonic::Mov => self.operand(pe, instr, 1, insn.rva, imports),
                Mnemonic::Lea => self.address(pe, instr, insn.rva),
                Mnemonic::Xor
                    if instr.op0_kind() == OpKind::Register
                        && instr.op1_kind() == OpKind::Register
                        && instr.op0_register() == instr.op1_register() =>
                {
                    Value::Constant {
                        value: 0,
                        origin_rva: insn.rva,
                    }
                }
                Mnemonic::Add | Mnemonic::Sub if destination == Some(Register::RSP) => {
                    match (
                        self.reg(Register::RSP),
                        self.operand(pe, instr, 1, insn.rva, imports).constant(),
                    ) {
                        (Value::StackAddress { offset, .. }, Some(value)) => {
                            let delta = value as i64;
                            let offset = if instr.mnemonic() == Mnemonic::Sub {
                                offset.checked_sub(delta)
                            } else {
                                offset.checked_add(delta)
                            };
                            offset
                                .map(|offset| Value::StackAddress {
                                    offset,
                                    origin_rva: insn.rva,
                                })
                                .unwrap_or(Value::Unknown)
                        }
                        _ => Value::Unknown,
                    }
                }
                Mnemonic::Add | Mnemonic::Sub => destination
                    .map(|register| self.reg(register))
                    .and_then(|left| {
                        symbolic_binary(
                            &left,
                            &self.operand(pe, instr, 1, insn.rva, imports),
                            if instr.mnemonic() == Mnemonic::Add {
                                "+"
                            } else {
                                "-"
                            },
                            insn.rva,
                        )
                    })
                    .unwrap_or(Value::Unknown),
                Mnemonic::Imul if instr.op_count() >= 3 => symbolic_binary(
                    &self.operand(pe, instr, 1, insn.rva, imports),
                    &self.operand(pe, instr, 2, insn.rva, imports),
                    "*",
                    insn.rva,
                )
                .unwrap_or(Value::Unknown),
                Mnemonic::Cmova => prior_compare
                    .as_ref()
                    .and_then(|(left, right)| {
                        let current = destination.map(|register| self.reg(register))?;
                        let source = self.operand(pe, instr, 1, insn.rva, imports);
                        (current == *left && source == *right)
                            .then(|| symbolic_min(&current, &source, insn.rva))
                            .flatten()
                    })
                    .unwrap_or(Value::Unknown),
                _ => Value::Unknown,
            };
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
        // Invalidate every overlapping stack store, including partial writes.
        if writes_memory && instr.op_count() != 0 && instr.op0_kind() == OpKind::Memory {
            if let Value::StackAddress { offset, .. } = self.address(pe, instr, insn.rva) {
                let width = instr.memory_size().size();
                self.stack.retain(|&start, stored| {
                    start.saturating_add(stored.width as i64) <= offset
                        || start >= offset.saturating_add(width as i64)
                });
                if instr.mnemonic() == Mnemonic::Mov
                    && matches!(width, 1 | 2 | 4 | 8)
                    && self.stack.len() < 256
                {
                    self.stack.insert(
                        offset,
                        Stored {
                            width,
                            value: result.clone(),
                        },
                    );
                }
            } else {
                // Unknown aliases can change stack locals passed by address.
                self.stack.clear();
            }
        } else if writes_memory {
            // Implicit stores (including PUSH and string operations) may alias locals.
            self.stack.clear();
        }
        let stack_before = self.reg(Register::RSP);
        for used in factory.info(instr).used_registers() {
            if matches!(
                used.access(),
                OpAccess::Write
                    | OpAccess::CondWrite
                    | OpAccess::ReadWrite
                    | OpAccess::ReadCondWrite
            ) {
                self.regs.remove(&used.register().full_register());
            }
        }
        if let Some(reg) = destination.filter(|reg| reg.size() >= 4) {
            if reg.size() == 4 {
                result = match result {
                    Value::Constant { value, .. } => Value::Constant {
                        value: value & 0xffff_ffff,
                        origin_rva: insn.rva,
                    },
                    Value::FunctionArgument {
                        index, origin_rva, ..
                    } => Value::FunctionArgument {
                        index,
                        width: 4,
                        origin_rva,
                    },
                    Value::Symbolic {
                        expression,
                        origin_rva,
                    } => Value::Symbolic {
                        expression,
                        origin_rva,
                    },
                    _ => Value::Unknown,
                };
            }
            if result != Value::Unknown {
                self.regs.insert(reg.full_register(), result);
            }
        }
        if matches!(instr.mnemonic(), Mnemonic::Push | Mnemonic::Pop) {
            if let Value::StackAddress { offset, .. } = stack_before {
                let width =
                    if instr.op0_kind() == OpKind::Register && instr.op0_register().size() == 2 {
                        2
                    } else {
                        8
                    };
                let delta = if instr.mnemonic() == Mnemonic::Push {
                    -width
                } else {
                    width
                };
                if let Some(offset) = offset.checked_add(delta) {
                    self.regs.insert(
                        Register::RSP,
                        Value::StackAddress {
                            offset,
                            origin_rva: insn.rva,
                        },
                    );
                }
            }
        }
        self.last_compare = next_compare;
    }
}

fn symbolic_text(value: &Value) -> Option<String> {
    match value {
        Value::Constant { value, .. } => Some(value.to_string()),
        Value::FunctionArgument { index, .. } => Some(format!("arg{index}")),
        Value::Symbolic { expression, .. } => Some(expression.clone()),
        _ => None,
    }
}

fn symbolic_binary(left: &Value, right: &Value, operator: &str, site: u32) -> Option<Value> {
    let expression = format!(
        "({} {operator} {})",
        symbolic_text(left)?,
        symbolic_text(right)?
    );
    (expression.len() <= 128).then_some(Value::Symbolic {
        expression,
        origin_rva: site,
    })
}

fn symbolic_min(left: &Value, right: &Value, site: u32) -> Option<Value> {
    let expression = format!(
        "min_u32({}, {})",
        symbolic_text(left)?,
        symbolic_text(right)?
    );
    (expression.len() <= 128).then_some(Value::Symbolic {
        expression,
        origin_rva: site,
    })
}

fn imported_target(
    instr: &Instruction,
    pe: &PeFile,
    state: &State,
    imports: &BTreeMap<u32, Value>,
    by_rva: &BTreeMap<u32, &DecodedInsn>,
) -> Option<(String, String)> {
    let mut current = instr;
    let mut visited = BTreeSet::new();
    for _ in 0..8 {
        let value = if current.op0_kind() == OpKind::Register {
            state.reg(current.op0_register())
        } else if current.is_ip_rel_memory_operand() {
            pe.va_to_rva(current.ip_rel_memory_address())
                .and_then(|rva| imports.get(&rva))
                .cloned()
                .unwrap_or(Value::Unknown)
        } else if matches!(
            current.op0_kind(),
            OpKind::NearBranch64 | OpKind::NearBranch32
        ) {
            let rva = pe.va_to_rva(current.near_branch_target())?;
            if !visited.insert(rva) {
                return None;
            }
            current = &by_rva.get(&rva)?.instr;
            if current.mnemonic() != Mnemonic::Jmp {
                return None;
            }
            continue;
        } else {
            Value::Unknown
        };
        if let Value::Import { dll, name } = value {
            return Some((dll, name));
        }
        return None;
    }
    None
}

fn path_string(pe: &PeFile, raw: &[u8], value: &Value, wide: bool) -> Option<String> {
    let Value::ImageAddress { rva, .. } = value else {
        return None;
    };
    let bytes = pe.rva_bytes(raw, *rva)?;
    if !wide {
        return crate::formats::pe::read_cstr_checked(bytes, 0, 512);
    }
    let mut units = Vec::new();
    for pair in bytes.as_chunks::<2>().0.iter().take(512) {
        let value = u16::from_le_bytes([pair[0], pair[1]]);
        if value == 0 {
            return String::from_utf16(&units).ok();
        }
        units.push(value);
    }
    None
}

fn oid_value(
    pe: &PeFile,
    raw: &[u8],
    state: &State,
    input: &Value,
) -> (Option<u32>, Option<String>) {
    match input {
        Value::StackAddress { offset, .. } => {
            let value = state
                .stack
                .get(offset)
                .filter(|stored| stored.width == 4)
                .and_then(|stored| stored.value.constant())
                .and_then(|value| u32::try_from(value).ok());
            (
                value,
                value.map(|_| "static-stack-store; path execution unobserved".into()),
            )
        }
        Value::ImageAddress { rva, .. }
            if pe
                .rva_to_section(*rva)
                .is_some_and(|s| s.characteristics & IMAGE_SCN_MEM_WRITE == 0) =>
        {
            let value = pe.rva_slice(raw, *rva, 4).map(|bytes| read_u32(bytes, 0));
            (
                value,
                value.map(|_| "read-only disk input; runtime bytes unobserved".into()),
            )
        }
        _ => (None, None),
    }
}

pub(super) fn recover(pe: &PeFile, raw: &[u8], insns: &[DecodedInsn]) -> Vec<CallEvidence> {
    if pe.machine != 0x8664 {
        return Vec::new();
    }
    let imports: BTreeMap<_, _> = read_imports(pe, raw)
        .into_iter()
        .flat_map(|dll| {
            dll.entries.into_iter().map(move |entry| {
                (
                    entry.slot_rva,
                    Value::Import {
                        dll: dll.dll.clone(),
                        name: entry.name,
                    },
                )
            })
        })
        .collect();
    let by_rva: BTreeMap<_, _> = insns.iter().map(|insn| (insn.rva, insn)).collect();
    let resolved_thunks: BTreeSet<_> = insns
        .iter()
        .filter(|insn| insn.instr.flow_control() == FlowControl::Call)
        .filter_map(|insn| pe.va_to_rva(insn.instr.near_branch_target()))
        .filter(|rva| {
            by_rva.get(rva).is_some_and(|insn| {
                insn.instr.mnemonic() == Mnemonic::Jmp
                    && insn.instr.is_ip_rel_memory_operand()
                    && pe
                        .va_to_rva(insn.instr.ip_rel_memory_address())
                        .is_some_and(|slot| imports.contains_key(&slot))
            })
        })
        .collect();
    let mut state = State::fresh();
    let mut next_rva = None;
    let mut current_owner = None;
    let mut forward_states: BTreeMap<u32, State> = BTreeMap::new();
    let mut factory = InstructionInfoFactory::new();
    let mut out = Vec::new();
    for insn in insns {
        if current_owner != Some(insn.owner_rva) || insn.rva == insn.owner_rva {
            state = State::function_entry(insn.owner_rva);
            current_owner = Some(insn.owner_rva);
            next_rva = Some(insn.rva);
            forward_states.retain(|rva, _| *rva >= insn.owner_rva);
        }
        if resolved_thunks.contains(&insn.rva) {
            state = State::fresh();
            next_rva = None;
            continue;
        }
        if let Some(incoming) = forward_states.remove(&insn.rva) {
            state = if next_rva == Some(insn.rva) {
                state.intersect(&incoming)
            } else {
                incoming
            };
        } else if next_rva != Some(insn.rva) {
            state = State::fresh();
        }
        next_rva = insn.rva.checked_add(insn.instr.len() as u32);
        if is_stack_probe_call(insn, pe, &state, &by_rva) {
            // MSVC's x64 stack probe consumes the requested size in RAX and
            // preserves the incoming argument registers. The following
            // `sub rsp, rax` materializes the probed frame.
            continue;
        }
        if insn.instr.flow_control() == FlowControl::UnconditionalBranch
            && matches!(
                insn.instr.op0_kind(),
                OpKind::NearBranch64 | OpKind::NearBranch32
            )
            && imported_target(&insn.instr, pe, &state, &imports, &by_rva).is_none()
        {
            if let Some(target) = pe.va_to_rva(insn.instr.near_branch_target()) {
                if target > insn.rva {
                    forward_states
                        .entry(target)
                        .and_modify(|incoming| *incoming = incoming.intersect(&state))
                        .or_insert_with(|| state.clone());
                }
            }
            state = State::fresh();
            next_rva = None;
            continue;
        }
        if matches!(
            insn.instr.flow_control(),
            FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
        ) {
            let tail = matches!(
                insn.instr.flow_control(),
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
            );
            let target = imported_target(&insn.instr, pe, &state, &imports, &by_rva);
            if tail {
                // A tail transfer retains the caller's return address, unlike
                // the pre-CALL stack layout used by argument_full.
                if let Value::StackAddress { offset, origin_rva } = state.reg(Register::RSP) {
                    if let Some(offset) = offset.checked_add(8) {
                        state
                            .regs
                            .insert(Register::RSP, Value::StackAddress { offset, origin_rva });
                    } else {
                        state.regs.remove(&Register::RSP);
                    }
                }
            }
            let mut return_value = Value::Unknown;
            let mut outputs = Vec::new();
            let mut stack_address_escaped = false;
            if let Some((dll, imported_name)) = target {
                let name = crate::analysis::apis::ordinal_name(&dll, &imported_name)
                    .unwrap_or(&imported_name)
                    .to_owned();
                let library = dll.to_ascii_lowercase();
                let win32 = matches!(library.as_str(), "kernel32.dll" | "kernelbase.dll")
                    || library.starts_with("api-ms-win-core-");
                let native = matches!(library.as_str(), "ntdll.dll" | "ntoskrnl.exe");
                let spec = crate::analysis::apis::lookup(&dll, &name);
                let ndis_call = library == "ndis.sys"
                    && matches!(
                        name.as_str(),
                        "NdisOidRequest"
                            | "NdisDirectOidRequest"
                            | "NdisSynchronousOidRequest"
                            | "NdisFOidRequest"
                            | "NdisFDirectOidRequest"
                            | "NdisFSynchronousOidRequest"
                    );
                let legacy_names: &[&str] = if win32 && name == "DeviceIoControl" {
                    &[
                        "handle",
                        "ioctl",
                        "input_buffer",
                        "input_length",
                        "output_buffer",
                        "output_length",
                        "bytes_returned",
                        "overlapped",
                    ]
                } else if native
                    && matches!(
                        name.as_str(),
                        "NtDeviceIoControlFile" | "ZwDeviceIoControlFile"
                    )
                {
                    &[
                        "handle",
                        "event",
                        "apc_routine",
                        "apc_context",
                        "io_status",
                        "ioctl",
                        "input_buffer",
                        "input_length",
                        "output_buffer",
                        "output_length",
                    ]
                } else if ndis_call {
                    &["ndis_handle", "oid_request"]
                } else {
                    &[]
                };
                let signature: Vec<(&str, usize)> = if let Some(spec) = spec {
                    spec.args.to_vec()
                } else {
                    legacy_names
                        .iter()
                        .map(|name| {
                            (
                                *name,
                                if matches!(*name, "ioctl" | "input_length" | "output_length") {
                                    4
                                } else {
                                    8
                                },
                            )
                        })
                        .collect()
                };
                let names: Vec<_> = signature.iter().map(|(name, _)| *name).collect();
                if !names.is_empty() && out.len() < 1024 {
                    let arguments: Vec<_> = signature
                        .iter()
                        .enumerate()
                        .map(|(index, (name, width))| Argument {
                            name: (*name).into(),
                            value: state.argument(index, *width),
                        })
                        .collect();
                    stack_address_escaped = arguments
                        .iter()
                        .any(|argument| matches!(argument.value, Value::StackAddress { .. }));
                    let get = |name: &str| {
                        arguments
                            .iter()
                            .find(|argument| argument.name == name)
                            .map(|argument| argument.value.clone())
                            .unwrap_or(Value::Unknown)
                    };
                    let code = get("ioctl")
                        .constant()
                        .and_then(|value| u32::try_from(value).ok());
                    // WDK ntddndis.h: IOCTL_NDIS_QUERY_GLOBAL_STATS uses function 0,
                    // FILE_DEVICE_PHYSICAL_NETCARD and METHOD_OUT_DIRECT.
                    let (mut ndis_oid, mut oid_evidence) =
                        if code == Some(0x0017_0002) && get("input_length").constant() == Some(4) {
                            oid_value(pe, raw, &state, &get("input_buffer"))
                        } else {
                            (None, None)
                        };
                    let ndis_request = ndis_call
                        .then(|| ndis::recover(pe, raw, &state, &get("oid_request")))
                        .flatten();
                    if let Some(request) = &ndis_request {
                        ndis_oid = request.oid;
                        oid_evidence = Some("WDK x64 NDIS_OID_REQUEST with validated header and request type; static field provenance; submission unobserved".into());
                    }
                    let mut details = semantic::details(pe, raw, &state, &name, spec, &arguments);
                    details["transfer"] = serde_json::json!(if tail {
                        "import-tail-transfer"
                    } else {
                        "import-call"
                    });
                    details["declared_import"] = serde_json::json!(imported_name);
                    details["provider_identity"] = serde_json::json!(
                        "Expected named-library ABI; actual loaded provider unobserved"
                    );
                    if spec.is_some() {
                        for argument in &arguments {
                            if argument.name.ends_with("_out") {
                                if let Value::StackAddress { offset, .. } = argument.value {
                                    outputs.push((
                                        offset,
                                        Value::ApiOutput {
                                            api: name.clone(),
                                            call_site: insn.rva,
                                            argument: argument.name.clone(),
                                        },
                                    ));
                                }
                            }
                        }
                    }
                    let buffer_fields = recover_buffer_fields(&state, &arguments);
                    let reconstructed_call = reconstruct_call(&name, &arguments);
                    out.push(CallEvidence { category: spec.map(|s|s.category).unwrap_or(if ndis_call {"ndis"} else {"ioctl"}).into(), details, api: name.clone(), dll: dll.clone(), site_rva: insn.rva, owner_rva: insn.owner_rva, owner_name: insn.owner_name.clone(),
                        device_handle: get("handle"), kernel_object_identity: None, ioctl_code: code, ndis_oid, oid_evidence, ndis_request, arguments, buffer_fields,
                        status: "static-x64-call-site; import identity and execution unobserved; kernel object identity requires telemetry".into(), reconstructed_call });
                }
                if spec.is_some_and(|s| s.returns_handle) || is_allocator(&name) {
                    return_value = Value::ApiResult {
                        api: name.clone(),
                        call_site: insn.rva,
                        path: if matches!(
                            name.as_str(),
                            "CreateFileA" | "CreateFileW" | "CreateNamedPipeA" | "CreateNamedPipeW"
                        ) {
                            path_string(pe, raw, &state.argument(0, 8), name.ends_with('W'))
                        } else {
                            None
                        },
                    };
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
                state.regs.remove(&reg);
            }
            state.last_compare = None;
            if stack_address_escaped {
                state.stack.clear();
            } else if let Value::StackAddress { offset, .. } = state.reg(Register::RSP) {
                // A callee owns the return slot and x64 shadow space. Other
                // caller locals remain unreachable unless their address was
                // passed to the call.
                let shadow_end = offset.saturating_add(0x20);
                state.stack.retain(|start, stored| {
                    start.saturating_add(stored.width as i64) <= offset || *start >= shadow_end
                });
            } else {
                state.stack.clear();
            }
            for (offset, value) in outputs {
                state.stack.insert(offset, Stored { width: 8, value });
            }
            if return_value != Value::Unknown {
                state.regs.insert(Register::RAX, return_value);
            }
            if tail {
                state = State::fresh();
                next_rva = None;
            }
            continue;
        }
        state.step(pe, insn, &imports, &mut factory);
        if insn.instr.flow_control() == FlowControl::ConditionalBranch {
            if let Some(target) = pe.va_to_rva(insn.instr.near_branch_target()) {
                if target > insn.rva {
                    forward_states
                        .entry(target)
                        .and_modify(|incoming| *incoming = incoming.intersect(&state))
                        .or_insert_with(|| state.clone());
                }
            }
        } else if insn.instr.flow_control() != FlowControl::Next {
            state = State::fresh();
            next_rva = None;
        }
    }
    out
}

fn is_allocator(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "calloc"
            | "malloc"
            | "realloc"
            | "heapalloc"
            | "localalloc"
            | "globalalloc"
            | "virtualalloc"
            | "virtualalloc2"
    )
}

fn recover_buffer_fields(state: &State, arguments: &[Argument]) -> Vec<BufferField> {
    let get = |name: &str| {
        arguments
            .iter()
            .find(|argument| argument.name == name)
            .map(|argument| &argument.value)
    };
    let mut fields = Vec::new();
    for (buffer_name, length_name) in [
        ("input_buffer", "input_length"),
        ("output_buffer", "output_length"),
    ] {
        let Some(Value::StackAddress { offset: base, .. }) = get(buffer_name) else {
            continue;
        };
        let Some(length) = get(length_name).and_then(Value::constant) else {
            continue;
        };
        if length == 0 || length > 1024 * 1024 {
            continue;
        }
        let Some(end) = base.checked_add(length as i64) else {
            continue;
        };
        for (offset, stored) in state.stack.range(*base..end) {
            let Some(field_end) = offset.checked_add(stored.width as i64) else {
                continue;
            };
            if field_end > end {
                continue;
            }
            fields.push(BufferField {
                buffer: buffer_name.trim_end_matches("_buffer").into(),
                offset: offset.saturating_sub(*base) as u64,
                width: stored.width,
                value: stored.value.clone(),
                evidence: "bounded stack store inside the passed buffer extent",
            });
            if fields.len() == 256 {
                return fields;
            }
        }
    }
    fields
}

fn is_stack_probe_call(
    insn: &DecodedInsn,
    pe: &PeFile,
    state: &State,
    by_rva: &BTreeMap<u32, &DecodedInsn>,
) -> bool {
    if insn.instr.flow_control() != FlowControl::Call
        || !matches!(
            insn.instr.op0_kind(),
            OpKind::NearBranch64 | OpKind::NearBranch32
        )
        || state.reg(Register::RAX).constant().is_none()
    {
        return false;
    }
    let Some(fallthrough) = insn.rva.checked_add(insn.instr.len() as u32) else {
        return false;
    };
    let Some(next) = by_rva.get(&fallthrough) else {
        return false;
    };
    if next.instr.mnemonic() != Mnemonic::Sub
        || next.instr.op0_kind() != OpKind::Register
        || next.instr.op0_register() != Register::RSP
        || next.instr.op1_kind() != OpKind::Register
        || next.instr.op1_register() != Register::RAX
    {
        return false;
    }
    let Some(target) = pe.va_to_rva(insn.instr.near_branch_target()) else {
        return false;
    };
    let Some(first) = by_rva.get(&target) else {
        return false;
    };
    first.instr.mnemonic() == Mnemonic::Sub
        && first.instr.op0_kind() == OpKind::Register
        && first.instr.op0_register() == Register::RSP
}

fn reconstruct_call(api: &str, arguments: &[Argument]) -> String {
    let mut out = format!("{api}(\n");
    for (index, argument) in arguments.iter().enumerate() {
        out.push_str("    ");
        out.push_str(&c_value(&argument.name, &argument.value));
        if index + 1 != arguments.len() {
            out.push(',');
        }
        out.push_str(&format!("  // {}\n", argument.name));
    }
    out.push_str(");");
    out
}

fn c_value(name: &str, value: &Value) -> String {
    match value {
        Value::Unknown => "unknown".into(),
        Value::FunctionArgument { index, .. } => format!("arg{index}"),
        Value::Symbolic { expression, .. } => expression.clone(),
        Value::Constant { value: 0, .. } if is_pointer_argument(name) => "NULL".into(),
        Value::Constant { value, .. } if name == "ioctl" => format!("0x{value:08X}"),
        Value::Constant { value, .. } => value.to_string(),
        Value::ImageAddress { rva, .. } => format!("image_rva_0x{rva:X}"),
        Value::StackAddress { offset, .. } if *offset < 0 => {
            format!("&frame_minus_0x{:X}", offset.unsigned_abs())
        }
        Value::StackAddress { offset, .. } => format!("&frame_plus_0x{offset:X}"),
        Value::ImageMemory { rva, .. } => format!("image_memory_0x{rva:X}"),
        Value::Import { dll, name } => format!("{dll}!{name}"),
        Value::ApiResult { api, path, .. } => path
            .as_ref()
            .map(|path| format!("{api}(\"{}\")", path.escape_default()))
            .unwrap_or_else(|| format!("{api}_result")),
        Value::ApiOutput { api, argument, .. } => format!("{api}_{argument}"),
    }
}

fn is_pointer_argument(name: &str) -> bool {
    !matches!(name, "ioctl" | "input_length" | "output_length")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn function_entry_tracks_register_and_stack_arguments() {
        let state = State::function_entry(0x1234);
        assert_eq!(
            state.argument(0, 8),
            Value::FunctionArgument {
                index: 0,
                width: 8,
                origin_rva: 0x1234
            }
        );
        assert_eq!(
            state.stack.get(&0x28),
            Some(&Stored {
                width: 8,
                value: Value::FunctionArgument {
                    index: 4,
                    width: 8,
                    origin_rva: 0x1234
                }
            })
        );
        assert_eq!(
            state.argument(2, 4),
            Value::FunctionArgument {
                index: 2,
                width: 4,
                origin_rva: 0x1234
            }
        );
    }

    #[test]
    fn symbolic_bounds_and_sizes_remain_bounded_expressions() {
        let argument = Value::FunctionArgument {
            index: 2,
            width: 4,
            origin_rva: 1,
        };
        let cap = Value::Constant {
            value: 64,
            origin_rva: 2,
        };
        let limited = symbolic_min(&argument, &cap, 3).unwrap();
        let record = Value::Constant {
            value: 1496,
            origin_rva: 4,
        };
        let bytes = symbolic_binary(&limited, &record, "*", 5).unwrap();
        let header = Value::Constant {
            value: 16,
            origin_rva: 6,
        };
        assert_eq!(
            symbolic_binary(&bytes, &header, "+", 7),
            Some(Value::Symbolic {
                expression: "((min_u32(arg2, 64) * 1496) + 16)".into(),
                origin_rva: 7,
            })
        );
    }

    #[test]
    fn small_register_reads_require_a_known_full_scalar() {
        let mut state = State::fresh();
        state.regs.insert(
            Register::RAX,
            Value::Constant {
                value: 0x1234_f8ab,
                origin_rva: 9,
            },
        );
        assert_eq!(state.reg(Register::AL).constant(), Some(0xab));
        assert_eq!(state.reg(Register::AH).constant(), Some(0xf8));
        assert_eq!(state.reg(Register::AX).constant(), Some(0xf8ab));
        assert_eq!(state.reg(Register::SP), Value::Unknown);
        state.regs.remove(&Register::RAX);
        assert_eq!(state.reg(Register::AL), Value::Unknown);
    }

    #[test]
    fn dword_arguments_preserve_provenance_and_discard_upper_bits() {
        let mut state = State::fresh();
        state.regs.insert(
            Register::RDX,
            Value::Constant {
                value: 0xffff_ffff_8337_a004,
                origin_rva: 0x1234,
            },
        );
        assert_eq!(
            state.argument(1, 4),
            Value::Constant {
                value: 0x8337_a004,
                origin_rva: 0x1234
            }
        );
        assert_eq!(state.argument(1, 8).constant(), Some(0xffff_ffff_8337_a004));
    }

    #[test]
    fn partial_stack_values_cannot_become_pointer_arguments() {
        let mut state = State::fresh();
        state.stack.insert(
            0x20,
            Stored {
                width: 4,
                value: Value::Constant {
                    value: 32,
                    origin_rva: 1,
                },
            },
        );
        assert_eq!(state.argument(4, 8), Value::Unknown);
        assert_eq!(state.argument(4, 4).constant(), Some(32));
        assert_eq!(state.argument(5, 4), Value::Unknown);
    }
}
