//! Forward symbolic interpretation of one function, in address order.
//!
//! Registers and stack slots carry what a value *is* rather than what it holds: the
//! PEB, a loader-list link, a module base and the PE structures reached from it, a
//! module handle or API pointer returned by a resolver, an address in the image, or
//! bytes derived from image data or encoded immediates. A single linear pass is
//! enough for the resolver shapes compilers emit, because the values a loop works on
//! are set up before the loop body in address order; values at merge points simply
//! come from the fall-through path.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use iced_x86::{
    FlowControl, Instruction, InstructionInfoFactory, Mnemonic, OpAccess, OpKind, Register,
};

use super::hashes::Hints;
use super::image::Function;
use super::strings::{self, How, Want};
use crate::formats::pe::PeFile;

pub(super) const XOR: u8 = 1;
pub(super) const ADD: u8 = 2;
pub(super) const SUB: u8 = 4;

/// Offsets of the structures a resolver walks, for one pointer width.
pub(super) struct Layout {
    pub ptr: i64,
    pub segment: Register,
    pub teb_self: u64,
    pub teb_peb: u64,
    pub peb_image_base: i64,
    pub peb_ldr: i64,
    /// PEB_LDR_DATA list heads, in [`Order`] order.
    pub ldr_lists: [i64; 3],
    /// Offset of each list's link inside LDR_DATA_TABLE_ENTRY.
    pub entry_links: [i64; 3],
    pub entry_dll_base: i64,
    /// FullDllName and BaseDllName.
    pub entry_names: [i64; 2],
    pub string_size: i64,
    pub string_buffer: i64,
    pub nt_export_dir: i64,
    pub nt_import_dir: i64,
    pub args: &'static [Register],
    pub volatile: &'static [Register],
}

pub(super) const X64: Layout = Layout {
    ptr: 8,
    segment: Register::GS,
    teb_self: 0x30,
    teb_peb: 0x60,
    peb_image_base: 0x10,
    peb_ldr: 0x18,
    ldr_lists: [0x10, 0x20, 0x30],
    entry_links: [0, 0x10, 0x20],
    entry_dll_base: 0x30,
    entry_names: [0x48, 0x58],
    string_size: 0x10,
    string_buffer: 8,
    nt_export_dir: 0x88,
    nt_import_dir: 0x90,
    args: &[Register::RCX, Register::RDX, Register::R8, Register::R9],
    volatile: &[
        Register::RAX,
        Register::RCX,
        Register::RDX,
        Register::R8,
        Register::R9,
        Register::R10,
        Register::R11,
    ],
};

pub(super) const X86: Layout = Layout {
    ptr: 4,
    segment: Register::FS,
    teb_self: 0x18,
    teb_peb: 0x30,
    peb_image_base: 0x08,
    peb_ldr: 0x0C,
    ldr_lists: [0x0C, 0x14, 0x1C],
    entry_links: [0, 0x08, 0x10],
    entry_dll_base: 0x18,
    entry_names: [0x24, 0x2C],
    string_size: 8,
    string_buffer: 4,
    nt_export_dir: 0x78,
    nt_import_dir: 0x80,
    args: &[],
    volatile: &[Register::RAX, Register::RCX, Register::RDX],
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Order {
    Load,
    Memory,
    Init,
}

const ORDERS: [Order; 3] = [Order::Load, Order::Memory, Order::Init];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) enum Dir {
    Export,
    Import,
    Any,
}

/// How a module or API name reached the resolver.
#[derive(Clone, Debug, PartialEq)]
pub(super) enum Name {
    Text(String, How),
    Ordinal(u16),
    Hash(u64),
    Param(u8),
    Unknown,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Module {
    /// Returned by GetModuleHandle/LoadLibrary for this name.
    Loader(Name),
    /// Found by walking the loader lists in `finder`, keyed by name or hash.
    Walk {
        finder: u32,
        key: Name,
    },
    SelfImage,
    Param(u8),
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(super) struct ResId {
    pub function: u32,
    pub site: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Via {
    Loader(&'static str),
    /// Export-table walk in the given function (the caller itself when inlined).
    ExportWalk(u32),
    ImportWalk(u32),
}

#[derive(Clone, Debug)]
pub(super) struct Resolution {
    pub site: u32,
    pub via: Via,
    pub module: Module,
    pub name: Name,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub(super) struct Taint {
    pub blobs: Vec<u64>,
    pub ops: u8,
}

impl Taint {
    fn union(&mut self, other: &Taint) {
        for &blob in &other.blobs {
            if !self.blobs.contains(&blob) && self.blobs.len() < 8 {
                self.blobs.push(blob);
            }
        }
        self.ops |= other.ops;
    }
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Val {
    Unknown,
    Const(u64),
    /// A constant combined with a value that is not known: an encoded byte whose key
    /// is opaque.
    Enc(u64, u8),
    /// Derived from image data at these addresses.
    Data(Taint),
    Stack(i64),
    Param(u8),
    Teb,
    Peb,
    Ldr,
    Link(Order),
    Module(Module),
    Lfanew(u32),
    NtHeaders(u32),
    DirRva(Dir, u32),
    Dir(Dir, u32),
    FuncArrayRva(u32),
    FuncArray(u32),
    FuncRva(u32),
    /// An exported function's address, found by walking an export table.
    Export(u32),
    /// The content of an IAT slot.
    Import(u64),
    Api(ResId),
    /// A pointer-sized value loaded from a writable global.
    Global(u64),
}

#[derive(Clone, Debug, PartialEq)]
pub(super) enum Summary {
    /// Returns a resolved API pointer. `params` are the arguments the function reads.
    Api {
        via: Via,
        name_param: Option<u8>,
        module: Module,
        params: u8,
    },
    /// Always returns the pointer from this one resolution.
    Fixed(ResId),
    /// Returns a module base.
    Module {
        finder: u32,
        key_param: Option<u8>,
        loader: bool,
        params: u8,
    },
    /// Always returns this module.
    ModuleValue(Module),
}

#[derive(Clone, Debug, Default)]
pub(super) struct Events {
    pub peb: Option<u32>,
    pub ldr: Option<u32>,
    pub list: Option<u32>,
    pub entry: Option<u32>,
    pub lfanew: Option<u32>,
    pub export_dir: Option<u32>,
    pub import_dir: Option<u32>,
    pub export_fields: Option<u32>,
    pub import_fields: Option<u32>,
    pub list_order: Option<Order>,
    pub walk_origin: Option<Module>,
}

impl Events {
    pub fn module_walk(&self) -> bool {
        self.list.is_some() && (self.entry.is_some() || self.ldr.is_some())
    }

    pub fn export_walk(&self) -> bool {
        self.lfanew.is_some() && self.export_dir.is_some()
    }

    pub fn import_walk(&self) -> bool {
        self.lfanew.is_some() && self.import_dir.is_some() && self.import_fields.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub(super) enum Through {
    Api(ResId),
    Global(u64),
}

#[derive(Clone, Debug, Default)]
pub(super) struct Facts {
    pub events: Events,
    pub resolutions: Vec<Resolution>,
    /// Indirect call or tail-jump sites through a resolved pointer.
    pub through: Vec<(u32, Through)>,
    pub global_api: Vec<(u64, ResId)>,
    pub global_module: Vec<(u64, Module)>,
    pub global_loads: Vec<u64>,
    pub returns: Vec<Val>,
    pub hints: Hints,
    /// Large immediates compared against: hash constants of an inlined walk.
    pub compares: Vec<u64>,
    pub callees: Vec<u32>,
    pub params: u8,
    /// An indirect call through a value that was not resolved.
    pub indirect_unknown: bool,
}

/// Image-wide state the interpreter reads; updated between passes.
pub(super) struct Context<'a> {
    pub pe: &'a PeFile,
    pub raw: &'a [u8],
    pub layout: &'static Layout,
    pub imports: HashMap<u64, (String, String)>,
    /// `jmp [IAT]` stubs, by RVA, to the slot they jump through.
    pub thunks: HashMap<u32, u64>,
    pub guard_dispatch: u64,
    pub guard_check: u64,
    pub summaries: HashMap<u32, Summary>,
    pub global_api: HashMap<u64, ResId>,
    pub global_module: HashMap<u64, Module>,
    pub writable: Vec<(u64, u64)>,
    /// Argument bytes each x86 function pops on return (`ret N`).
    pub ret_pops: HashMap<u32, i64>,
}

impl Context<'_> {
    pub fn is_writable(&self, va: u64) -> bool {
        self.writable
            .iter()
            .any(|&(start, end)| start <= va && va < end)
    }

    fn in_image(&self, va: u64) -> bool {
        va >= self.pe.image_base && va < self.pe.image_base + u64::from(self.pe.size_of_image)
    }
}

#[derive(Clone, Copy, Debug)]
enum Cell {
    Plain(u8),
    Enc(u8),
}

enum Loc {
    Segment(Register, u64),
    Stack(i64, bool),
    Global(u64, bool),
    Field {
        base: Val,
        base_id: u32,
        index: Option<(Val, u32, u32)>,
        disp: i64,
    },
}

#[derive(Clone, Copy)]
enum Loader {
    GetModuleHandle(bool),
    LoadLibrary(bool),
    GetModuleHandleEx(bool),
    LdrModule,
    GetProcAddress,
    LdrGetProcedureAddress,
}

/// The loader API and its argument count, which on x86 is also what it pops.
fn loader_api(name: &str) -> Option<(Loader, i64)> {
    Some(match name {
        "GetModuleHandleA" => (Loader::GetModuleHandle(false), 1),
        "GetModuleHandleW" => (Loader::GetModuleHandle(true), 1),
        "LoadLibraryA" => (Loader::LoadLibrary(false), 1),
        "LoadLibraryW" => (Loader::LoadLibrary(true), 1),
        "LoadLibraryExA" => (Loader::LoadLibrary(false), 3),
        "LoadLibraryExW" => (Loader::LoadLibrary(true), 3),
        "GetModuleHandleExA" => (Loader::GetModuleHandleEx(false), 3),
        "GetModuleHandleExW" => (Loader::GetModuleHandleEx(true), 3),
        "LdrLoadDll" | "LdrGetDllHandle" => (Loader::LdrModule, 4),
        "GetProcAddress" => (Loader::GetProcAddress, 2),
        "LdrGetProcedureAddress" => (Loader::LdrGetProcedureAddress, 4),
        "LdrGetProcedureAddressEx" => (Loader::LdrGetProcedureAddress, 5),
        _ => return None,
    })
}

const REGS: usize = 48;

/// Farther than this from the entry stack pointer is not a stack location; keeping
/// offsets small also keeps every later offset computation free of overflow.
const STACK_LIMIT: i64 = 1 << 24;

fn stack_offset(base: i64, delta: i64) -> Option<i64> {
    base.checked_add(delta)
        .filter(|offset| offset.abs() < STACK_LIMIT)
}

fn stack_value(base: i64, delta: i64) -> Val {
    stack_offset(base, delta).map_or(Val::Unknown, Val::Stack)
}

fn index(reg: Register) -> Option<usize> {
    if reg.is_gpr() {
        Some(reg.full_register().number())
    } else if reg.is_vector_register() {
        let n = reg.full_register().number();
        (n < 32).then_some(16 + n)
    } else {
        None
    }
}

/// Whether a function can take part in resolution on its own: it calls a loader API,
/// reads through FS/GS, or reads `e_lfanew` (`[base+0x3C]`). Others matter only as
/// callers of resolvers or readers of resolved globals, which the fixpoint revisits.
pub(super) fn is_candidate(ctx: &Context<'_>, insns: &[Instruction]) -> bool {
    let loader_slot = |va: u64| {
        ctx.imports
            .get(&va)
            .is_some_and(|(_, name)| loader_api(name).is_some())
    };
    insns.iter().any(|insn| {
        if matches!(insn.memory_segment(), Register::FS | Register::GS)
            && (0..insn.op_count()).any(|op| insn.op_kind(op) == OpKind::Memory)
        {
            return true;
        }
        if (0..insn.op_count()).any(|op| insn.op_kind(op) == OpKind::Memory)
            && insn.memory_base() != Register::None
            && !matches!(
                insn.memory_base(),
                Register::RIP | Register::EIP | Register::RSP | Register::ESP
            )
            && insn.memory_displacement64() == 0x3C
        {
            return true;
        }
        if insn.flow_control() != FlowControl::Call
            && insn.flow_control() != FlowControl::IndirectCall
            && insn.mnemonic() != Mnemonic::Jmp
        {
            return false;
        }
        match insn.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                let rva = insn.near_branch_target().wrapping_sub(ctx.pe.image_base) as u32;
                ctx.thunks.get(&rva).is_some_and(|&slot| loader_slot(slot))
            }
            OpKind::Memory if matches!(insn.memory_base(), Register::RIP | Register::EIP) => {
                loader_slot(insn.ip_rel_memory_address())
            }
            OpKind::Memory if insn.memory_base() == Register::None => {
                loader_slot(insn.memory_displacement64())
            }
            _ => false,
        }
    })
}

/// What the fixpoint needs from a function that is not interpreted: its direct
/// callees, the writable globals it reads, and hash-like arithmetic for hint lookup.
pub(super) fn profile(ctx: &Context<'_>, function: &Function, insns: &[Instruction]) -> Facts {
    let mut facts = Facts::default();
    for insn in insns {
        match insn.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
                if matches!(insn.mnemonic(), Mnemonic::Call | Mnemonic::Jmp) =>
            {
                let rva = insn.near_branch_target().wrapping_sub(ctx.pe.image_base) as u32;
                if !function.contains(rva) && !facts.callees.contains(&rva) {
                    facts.callees.push(rva);
                }
            }
            _ => {}
        }
        let has_memory = (0..insn.op_count()).any(|op| insn.op_kind(op) == OpKind::Memory);
        if has_memory && insn.memory_size().size() as i64 == ctx.layout.ptr {
            let va = match insn.memory_base() {
                Register::RIP | Register::EIP => Some(insn.ip_rel_memory_address()),
                Register::None if insn.memory_index() == Register::None => {
                    Some(insn.memory_displacement64())
                }
                _ => None,
            };
            if let Some(va) = va.filter(|&va| ctx.is_writable(va)) {
                if !facts.global_loads.contains(&va) {
                    facts.global_loads.push(va);
                }
            }
        }
        let immediate = (insn.op_count() >= 2)
            .then(|| insn.op_kind(insn.op_count() - 1))
            .filter(|&kind| Machine::is_imm(kind))
            .map(|_| Machine::unsigned_imm(insn, insn.op_count() - 1));
        let reg32 = insn.op0_kind() == OpKind::Register && insn.op0_register().size() == 4;
        match (insn.mnemonic(), immediate) {
            (Mnemonic::Ror, Some(n)) if reg32 => {
                facts.hints.rotates.insert(n as u32 & 31);
            }
            (Mnemonic::Rol, Some(n)) if reg32 => {
                facts.hints.rotates.insert((32 - (n as u32 & 31)) & 31);
            }
            (Mnemonic::Imul, Some(factor)) => {
                facts.hints.multipliers.insert(factor as u32);
            }
            (Mnemonic::Shl, Some(k)) if (1..31).contains(&k) => {
                facts.hints.multipliers.insert((1u32 << k) + 1);
                facts.hints.multipliers.insert((1u32 << k) - 1);
            }
            (Mnemonic::Mov, Some(seed)) if reg32 && seed > 0xFF && seed <= 0xFFFF_FFFF => {
                facts.hints.seeds.insert(seed as u32);
            }
            (Mnemonic::Crc32, _) => facts.hints.crc = true,
            _ => {}
        }
    }
    facts
}

/// The register and constant a `cmp reg, imm` or `test reg, reg` checks for equality.
fn equality_guard(insn: &Instruction) -> Option<(Register, u64)> {
    if insn.op_count() != 2 || insn.op0_kind() != OpKind::Register {
        return None;
    }
    let reg = insn.op0_register();
    match insn.mnemonic() {
        Mnemonic::Cmp if Machine::is_imm(insn.op1_kind()) => {
            Some((reg, Machine::signed_imm(insn, 1) as u64))
        }
        Mnemonic::Test if insn.op1_kind() == OpKind::Register && insn.op1_register() == reg => {
            Some((reg, 0))
        }
        _ => None,
    }
}

/// Registers at a forward branch, for the block it reaches.
struct Snapshot {
    regs: Vec<Val>,
    ids: Vec<u32>,
    sp: i64,
}

pub(super) fn run(ctx: &Context<'_>, function: &Function, insns: &[Instruction]) -> Facts {
    let mut machine = Machine::new(ctx, function);
    // A block after a return or jump is reached only by branching to it, so it starts
    // from the state at the first branch there, not from an epilogue that popped the
    // registers it relies on.
    let mut branches: HashMap<u64, Snapshot> = HashMap::new();
    let mut after_terminator = false;
    for (i, insn) in insns.iter().enumerate() {
        if after_terminator {
            if let Some(snapshot) = branches.remove(&insn.ip()) {
                machine.regs = snapshot.regs;
                machine.ids = snapshot.ids;
                machine.sp = snapshot.sp;
            }
        }
        machine.step(insn, insns.get(i + 1));
        // `cmp reg, imm` / `test reg, reg` then `je`/`jne`: on the path where they are
        // equal the register holds that constant (lazy-binding stubs test for -1).
        let equal = i
            .checked_sub(1)
            .and_then(|prev| equality_guard(&insns[prev]))
            .filter(|_| matches!(insn.mnemonic(), Mnemonic::Je | Mnemonic::Jne));
        let flow = insn.flow_control();
        if matches!(
            flow,
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) && matches!(
            insn.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ) {
            let target = insn.near_branch_target();
            if target > insn.ip() && !branches.contains_key(&target) && branches.len() < 4096 {
                let mut snapshot = Snapshot {
                    regs: machine.regs.clone(),
                    ids: machine.ids.clone(),
                    sp: machine.sp,
                };
                if let (Some((reg, value)), Mnemonic::Je) = (equal, insn.mnemonic()) {
                    if let Some(slot) = index(reg) {
                        snapshot.regs[slot] = Val::Const(value & machine.mask());
                    }
                }
                branches.insert(target, snapshot);
            }
        }
        // After the target's snapshot: `jne` falls through only when equal.
        if let (Some((reg, value)), Mnemonic::Jne) = (equal, insn.mnemonic()) {
            machine.set(reg, Val::Const(value & machine.mask()), None);
        }
        after_terminator = matches!(
            flow,
            FlowControl::Return
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Interrupt
                | FlowControl::Exception
        );
    }
    machine.facts.params = machine.params;
    machine.facts
}

struct Machine<'c, 'a> {
    ctx: &'c Context<'a>,
    function: &'c Function,
    regs: Vec<Val>,
    ids: Vec<u32>,
    next_id: u32,
    sp: i64,
    slots: HashMap<i64, Val>,
    bytes: BTreeMap<i64, Cell>,
    regions: Vec<(i64, i64, Taint)>,
    buffers: BTreeSet<i64>,
    keys: Vec<u64>,
    origins: HashMap<u32, Module>,
    pushed: i64,
    called: bool,
    params: u8,
    facts: Facts,
    info: InstructionInfoFactory,
}

impl<'c, 'a> Machine<'c, 'a> {
    fn new(ctx: &'c Context<'a>, function: &'c Function) -> Self {
        let mut machine = Machine {
            ctx,
            function,
            regs: vec![Val::Unknown; REGS],
            ids: (0..REGS as u32).collect(),
            next_id: REGS as u32,
            sp: 0,
            slots: HashMap::new(),
            bytes: BTreeMap::new(),
            regions: Vec::new(),
            buffers: BTreeSet::new(),
            keys: Vec::new(),
            origins: HashMap::new(),
            pushed: 0,
            called: false,
            params: 0,
            facts: Facts::default(),
            info: InstructionInfoFactory::new(),
        };
        for (i, &reg) in ctx.layout.args.iter().enumerate() {
            machine.regs[index(reg).unwrap()] = Val::Param(i as u8);
        }
        if ctx.layout.args.is_empty() {
            for i in 0..8 {
                machine.slots.insert(4 + 4 * i, Val::Param(i as u8));
            }
        } else {
            for i in 0..4 {
                machine.slots.insert(0x28 + 8 * i, Val::Param(4 + i as u8));
            }
        }
        machine
    }

    fn fresh(&mut self) -> u32 {
        self.next_id += 1;
        self.next_id
    }

    fn rva(&self, insn: &Instruction) -> u32 {
        (insn.ip() - self.ctx.pe.image_base) as u32
    }

    fn reg(&mut self, reg: Register) -> Val {
        if reg.full_register() == Register::RSP {
            return Val::Stack(self.sp);
        }
        let Some(i) = index(reg) else {
            return Val::Unknown;
        };
        if let Val::Param(p) = self.regs[i] {
            if p < 8 {
                self.params |= 1 << p;
            }
        }
        self.regs[i].clone()
    }

    fn id(&self, reg: Register) -> u32 {
        index(reg).map_or(0, |i| self.ids[i])
    }

    fn set(&mut self, reg: Register, value: Val, id: Option<u32>) {
        if reg.full_register() == Register::RSP {
            if let Val::Stack(d) = value {
                self.sp = d;
            }
            return;
        }
        if let Some(i) = index(reg) {
            let id = id.unwrap_or_else(|| self.fresh());
            self.regs[i] = value;
            self.ids[i] = id;
        }
    }

    fn signed_imm(insn: &Instruction, op: u32) -> i64 {
        match insn.op_kind(op) {
            OpKind::Immediate8 => insn.immediate8() as i8 as i64,
            OpKind::Immediate16 => insn.immediate16() as i16 as i64,
            OpKind::Immediate32 => insn.immediate32() as i32 as i64,
            OpKind::Immediate8to16 => insn.immediate8to16() as i64,
            OpKind::Immediate8to32 => insn.immediate8to32() as i64,
            OpKind::Immediate8to64 => insn.immediate8to64(),
            OpKind::Immediate32to64 => insn.immediate32to64(),
            OpKind::Immediate64 => insn.immediate64() as i64,
            _ => 0,
        }
    }

    fn is_imm(kind: OpKind) -> bool {
        matches!(
            kind,
            OpKind::Immediate8
                | OpKind::Immediate16
                | OpKind::Immediate32
                | OpKind::Immediate64
                | OpKind::Immediate8to16
                | OpKind::Immediate8to32
                | OpKind::Immediate8to64
                | OpKind::Immediate32to64
        )
    }

    /// An immediate as an unsigned value of the destination's width.
    fn unsigned_imm(insn: &Instruction, op: u32) -> u64 {
        let value = Self::signed_imm(insn, op) as u64;
        let width = if insn.op0_kind() == OpKind::Register {
            insn.op0_register().size()
        } else {
            insn.memory_size().size()
        };
        match width {
            1 => value & 0xFF,
            2 => value & 0xFFFF,
            4 => value & 0xFFFF_FFFF,
            _ => value,
        }
    }

    fn operand(&mut self, insn: &Instruction, op: u32) -> (Val, u32) {
        match insn.op_kind(op) {
            OpKind::Register => {
                let reg = insn.op_register(op);
                (self.reg(reg), self.id(reg))
            }
            OpKind::Memory => {
                let value = self.load(insn);
                (value, self.fresh())
            }
            kind if Self::is_imm(kind) => {
                let value = Self::unsigned_imm(insn, op) & self.mask();
                (Val::Const(value), self.fresh())
            }
            _ => (Val::Unknown, self.fresh()),
        }
    }

    fn displacement(&self, insn: &Instruction) -> i64 {
        if self.ctx.layout.ptr == 4 {
            insn.memory_displacement32() as i32 as i64
        } else {
            insn.memory_displacement64() as i64
        }
    }

    fn loc(&mut self, insn: &Instruction) -> Loc {
        let base = insn.memory_base();
        let index_reg = insn.memory_index();
        let indexed = index_reg != Register::None;
        let segment = insn.memory_segment();
        if matches!(segment, Register::FS | Register::GS) && base == Register::None {
            return Loc::Segment(segment, insn.memory_displacement64());
        }
        if matches!(base, Register::RIP | Register::EIP) {
            return Loc::Global(insn.ip_rel_memory_address(), indexed);
        }
        let disp = self.displacement(insn);
        if base == Register::None {
            return Loc::Global(disp as u64 & self.mask(), indexed);
        }
        let base_val = self.reg(base);
        let disp_va = disp as u64 & self.mask();
        match base_val {
            Val::Stack(d) => match stack_offset(d, disp) {
                Some(off) => Loc::Stack(off, indexed),
                None => Loc::Global(u64::MAX, indexed),
            },
            Val::Const(c) if self.ctx.in_image(c) => {
                Loc::Global(c.wrapping_add(disp as u64), indexed)
            }
            // x86 arrays: the image address is the displacement and the register an
            // index, e.g. `mov cl, [eax+0x4151dc]` in a decode loop.
            Val::Const(_) | Val::Unknown | Val::Data(_) if self.ctx.in_image(disp_va) => {
                Loc::Global(disp_va, true)
            }
            _ => {
                let base_id = self.id(base);
                let index = indexed.then(|| {
                    (
                        self.reg(index_reg),
                        self.id(index_reg),
                        insn.memory_index_scale(),
                    )
                });
                Loc::Field {
                    base: base_val,
                    base_id,
                    index,
                    disp,
                }
            }
        }
    }

    fn mask(&self) -> u64 {
        if self.ctx.layout.ptr == 4 {
            0xFFFF_FFFF
        } else {
            u64::MAX
        }
    }

    /// A constant as a signed stack offset of the image's pointer width.
    fn signed(&self, value: u64) -> i64 {
        if self.ctx.layout.ptr == 4 {
            value as u32 as i32 as i64
        } else {
            value as i64
        }
    }

    fn note(slot: &mut Option<u32>, rva: u32) {
        slot.get_or_insert(rva);
    }

    fn load(&mut self, insn: &Instruction) -> Val {
        let size = insn.memory_size().size() as i64;
        let rva = self.rva(insn);
        match self.loc(insn) {
            Loc::Segment(segment, disp) => {
                let layout = self.ctx.layout;
                if segment != layout.segment {
                    Val::Unknown
                } else if disp == layout.teb_peb {
                    Self::note(&mut self.facts.events.peb, rva);
                    Val::Peb
                } else if disp == layout.teb_self {
                    Val::Teb
                } else {
                    Val::Unknown
                }
            }
            Loc::Stack(off, false) => {
                if let Some(value) = self.slots.get(&off) {
                    if let Val::Param(p) = value {
                        self.params |= 1 << p;
                    }
                    return value.clone();
                }
                let mut value = 0u64;
                for i in (0..size.min(8)).rev() {
                    match self.bytes.get(&(off + i)) {
                        Some(Cell::Plain(byte)) => value = value << 8 | u64::from(*byte),
                        _ => return Val::Unknown,
                    }
                }
                Val::Const(value)
            }
            Loc::Stack(off, true) => {
                let mut taint = Taint::default();
                for (start, end, region) in &self.regions {
                    if *start <= off && off < *end {
                        taint.union(region);
                    }
                }
                if taint.blobs.is_empty() {
                    Val::Unknown
                } else {
                    Val::Data(taint)
                }
            }
            Loc::Global(va, indexed) => self.load_global(va, size, indexed),
            Loc::Field {
                base,
                base_id,
                index,
                disp,
            } => self.load_field(rva, base, base_id, index, disp, size),
        }
    }

    fn load_global(&mut self, va: u64, size: i64, indexed: bool) -> Val {
        if !indexed {
            if let Some(&id) = self.ctx.global_api.get(&va) {
                return Val::Api(id);
            }
            if let Some(module) = self.ctx.global_module.get(&va) {
                return Val::Module(module.clone());
            }
            if self.ctx.imports.contains_key(&va) {
                return Val::Import(va);
            }
            if size == self.ctx.layout.ptr && self.ctx.is_writable(va) {
                if !self.facts.global_loads.contains(&va) {
                    self.facts.global_loads.push(va);
                }
                return Val::Global(va);
            }
            // A writable scalar holds a run-time value (an opaque key, a counter),
            // not data a string could be decoded from.
            if size <= 8 && self.ctx.is_writable(va) {
                return Val::Unknown;
            }
        }
        if self.ctx.in_image(va) {
            Val::Data(Taint {
                blobs: vec![va],
                ops: 0,
            })
        } else {
            Val::Unknown
        }
    }

    fn load_field(
        &mut self,
        rva: u32,
        base: Val,
        base_id: u32,
        index: Option<(Val, u32, u32)>,
        disp: i64,
        size: i64,
    ) -> Val {
        let layout = self.ctx.layout;
        let events = &mut self.facts.events;
        match (&base, &index) {
            (Val::Teb, None) if disp as u64 == layout.teb_peb => {
                Self::note(&mut events.peb, rva);
                return Val::Peb;
            }
            (Val::Peb, None) if disp == layout.peb_ldr => {
                Self::note(&mut events.ldr, rva);
                return Val::Ldr;
            }
            (Val::Peb, None) if disp == layout.peb_image_base => {
                return Val::Module(Module::SelfImage);
            }
            (Val::Ldr, None) => {
                if let Some(i) = layout.ldr_lists.iter().position(|&off| off == disp) {
                    Self::note(&mut events.list, rva);
                    events.list_order.get_or_insert(ORDERS[i]);
                    return Val::Link(ORDERS[i]);
                }
                return Val::Unknown;
            }
            (Val::Link(order), None) => {
                if disp == 0 || disp == layout.ptr {
                    Self::note(&mut events.list, rva);
                    return Val::Link(*order);
                }
                let link = layout.entry_links[*order as usize];
                let field = disp + link;
                if field == layout.entry_dll_base {
                    Self::note(&mut events.entry, rva);
                    return Val::Module(Module::Walk {
                        finder: self.function.rva,
                        key: Name::Unknown,
                    });
                }
                if layout
                    .entry_names
                    .iter()
                    .any(|&name| field >= name && field < name + layout.string_size)
                {
                    Self::note(&mut events.entry, rva);
                }
                return Val::Unknown;
            }
            _ => {}
        }

        // PE structures, reached from any base whose identity is tracked.
        let pointer_like = matches!(
            base,
            Val::Module(_) | Val::Param(_) | Val::Unknown | Val::Global(_) | Val::Api(_)
        );
        if index.is_none() && disp == 0x3C && size == 4 && pointer_like {
            Self::note(&mut events.lfanew, rva);
            if let Val::Module(module) = &base {
                self.origins.insert(base_id, module.clone());
            }
            return Val::Lfanew(base_id);
        }
        let dir_at = |disp: i64| {
            if disp == layout.nt_export_dir {
                Some(Dir::Export)
            } else if disp == layout.nt_import_dir {
                Some(Dir::Import)
            } else {
                None
            }
        };
        // NT headers as one register, or as `lfanew + base` in the address.
        let headers = match (&base, &index) {
            (Val::NtHeaders(b), None) => Some((*b, None)),
            (Val::NtHeaders(b), Some((_, _, 8))) if disp == layout.nt_export_dir => {
                Some((*b, Some(Dir::Any)))
            }
            (Val::Lfanew(b), Some((_, id, 1))) if id == b => Some((*b, None)),
            (_, Some((Val::Lfanew(b), _, 1))) if base_id == *b => Some((*b, None)),
            _ => None,
        };
        if let Some((b, forced)) = headers {
            if let Some(dir) = forced.or_else(|| dir_at(disp)) {
                // A generic accessor (`DataDirectory[index]`) does not say which
                // directory it reads, so on its own it is not a walk.
                match dir {
                    Dir::Import => Self::note(&mut events.import_dir, rva),
                    Dir::Export => Self::note(&mut events.export_dir, rva),
                    Dir::Any => {}
                }
                if events.walk_origin.is_none() {
                    events.walk_origin = self.origins.get(&b).cloned();
                }
                return Val::DirRva(dir, b);
            }
            return Val::Unknown;
        }
        // Directory fields, as one register or as `directory rva + base`.
        let directory = match (&base, &index) {
            (Val::Dir(dir, b), None) => Some((*dir, *b)),
            (Val::DirRva(dir, b), Some((_, id, 1))) if id == b => Some((*dir, *b)),
            (_, Some((Val::DirRva(dir, b), _, 1))) if base_id == *b => Some((*dir, *b)),
            _ => None,
        };
        if let Some((dir, b)) = directory {
            match dir {
                Dir::Import if matches!(disp, 0x00 | 0x0C | 0x10) => {
                    Self::note(&mut events.import_fields, rva);
                }
                Dir::Export | Dir::Any if (0x0C..=0x24).contains(&disp) => {
                    Self::note(&mut events.export_fields, rva);
                    if disp == 0x1C {
                        return Val::FuncArrayRva(b);
                    }
                }
                _ => {}
            }
            return Val::Unknown;
        }
        if let (Val::FuncArray(b), Some((_, _, 4))) = (&base, &index) {
            return Val::FuncRva(*b);
        }
        match (&base, &index) {
            (Val::Data(taint), _) => Val::Data(taint.clone()),
            (_, Some((Val::Data(taint), _, _))) => Val::Data(taint.clone()),
            _ => Val::Unknown,
        }
    }

    fn store(&mut self, insn: &Instruction, value: Val) {
        let size = insn.memory_size().size() as i64;
        let ptr = self.ctx.layout.ptr;
        match self.loc(insn) {
            Loc::Stack(off, false) => {
                for i in 0..size {
                    self.bytes.remove(&(off + i));
                }
                match &value {
                    Val::Const(c) => {
                        for i in 0..size.min(8) {
                            self.bytes
                                .insert(off + i, Cell::Plain((c >> (8 * i)) as u8));
                        }
                    }
                    Val::Enc(c, _) => {
                        for i in 0..size.min(8) {
                            self.bytes.insert(off + i, Cell::Enc((c >> (8 * i)) as u8));
                        }
                    }
                    Val::Data(taint) if !taint.blobs.is_empty() => {
                        self.regions.push((off, off + size, taint.clone()));
                    }
                    _ => {}
                }
                self.slots
                    .retain(|&slot, _| slot + ptr <= off || slot >= off + size);
                self.slots.insert(off, value);
            }
            Loc::Stack(off, true) => {
                if let Val::Data(taint) = &value {
                    if !taint.blobs.is_empty() {
                        self.regions.push((off, i64::MAX, taint.clone()));
                    }
                }
            }
            Loc::Global(va, false) if size == ptr => match value {
                Val::Api(id) => self.facts.global_api.push((va, id)),
                Val::Module(module) if module != Module::Unknown => {
                    self.facts.global_module.push((va, module));
                }
                _ => {}
            },
            _ => {}
        }
    }

    fn step(&mut self, insn: &Instruction, next: Option<&Instruction>) {
        let rva = self.rva(insn);
        match insn.mnemonic() {
            Mnemonic::Call => self.call(insn, next, false),
            Mnemonic::Jmp => {
                let outside = match insn.op0_kind() {
                    OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                        let target = insn
                            .near_branch_target()
                            .wrapping_sub(self.ctx.pe.image_base)
                            as u32;
                        !self.function.contains(target)
                    }
                    OpKind::Memory => !insn.memory_index().is_gpr(),
                    _ => true,
                };
                if outside {
                    self.call(insn, next, true);
                }
            }
            Mnemonic::Ret | Mnemonic::Retf => {
                let value = self.reg(Register::RAX);
                if self.facts.returns.len() < 8 && !self.facts.returns.contains(&value) {
                    self.facts.returns.push(value);
                }
            }
            Mnemonic::Push => {
                let (value, _) = self.operand(insn, 0);
                let width = self.ctx.layout.ptr;
                self.sp -= width;
                // Saving callee-saved registers before the first call is the
                // prologue, not an argument.
                let prologue_save = !self.called
                    && insn.op0_kind() == OpKind::Register
                    && matches!(
                        insn.op0_register().full_register(),
                        Register::RBX | Register::RSI | Register::RDI | Register::RBP
                    );
                if !prologue_save {
                    self.pushed += width;
                }
                for i in 0..width {
                    self.bytes.remove(&(self.sp + i));
                }
                self.slots.insert(self.sp, value);
            }
            Mnemonic::Pop => {
                let value = self.slots.get(&self.sp).cloned().unwrap_or(Val::Unknown);
                self.sp += self.ctx.layout.ptr;
                if insn.op0_kind() == OpKind::Register {
                    self.set(insn.op0_register(), value, None);
                }
            }
            Mnemonic::Leave => {
                if let Val::Stack(d) = self.reg(Register::RBP) {
                    self.sp = d;
                }
                let value = self.slots.get(&self.sp).cloned().unwrap_or(Val::Unknown);
                self.sp += self.ctx.layout.ptr;
                self.set(Register::RBP, value, None);
            }
            Mnemonic::Mov | Mnemonic::Movzx | Mnemonic::Movsx | Mnemonic::Movsxd => {
                self.mov(insn);
            }
            Mnemonic::Lea => {
                let value = self.address(insn);
                if let Val::Stack(d) = value {
                    if insn.memory_index() == Register::None {
                        self.buffers.insert(d);
                    }
                }
                self.set(insn.op0_register(), value, None);
            }
            Mnemonic::Xchg
                if insn.op0_kind() == OpKind::Register && insn.op1_kind() == OpKind::Register =>
            {
                let (a, b) = (insn.op0_register(), insn.op1_register());
                let (va, ia) = (self.reg(a), self.id(a));
                let (vb, ib) = (self.reg(b), self.id(b));
                self.set(a, vb, Some(ib));
                self.set(b, va, Some(ia));
            }
            Mnemonic::Cmp => {
                if Self::is_imm(insn.op1_kind()) {
                    let value = Self::unsigned_imm(insn, 1);
                    if value > 0xFFFF && !self.ctx.in_image(value) && self.facts.compares.len() < 64
                    {
                        self.facts.compares.push(value);
                    }
                } else {
                    self.read_operands(insn);
                }
            }
            Mnemonic::Test => self.read_operands(insn),
            Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Xor
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Rol
            | Mnemonic::Ror
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Imul
            | Mnemonic::Not
            | Mnemonic::Neg
            | Mnemonic::Inc
            | Mnemonic::Dec
                if insn.op0_kind() == OpKind::Register =>
            {
                self.alu(insn);
            }
            Mnemonic::Crc32 => {
                self.facts.hints.crc = true;
                self.generic(insn, rva);
            }
            _ => self.generic(insn, rva),
        }
    }

    /// Evaluates operands only for their side effects: comparing against a parameter,
    /// in a register or a stack slot, is a use of it.
    fn read_operands(&mut self, insn: &Instruction) {
        for op in 0..insn.op_count() {
            match insn.op_kind(op) {
                OpKind::Register => {
                    self.reg(insn.op_register(op));
                }
                OpKind::Memory => {
                    self.load(insn);
                }
                _ => {}
            }
        }
    }

    fn mov(&mut self, insn: &Instruction) {
        match insn.op0_kind() {
            OpKind::Register => {
                let (value, id) = self.operand(insn, 1);
                let reg = insn.op0_register();
                let keeps_identity = insn.op1_kind() == OpKind::Register;
                if let Val::Const(c) = value {
                    if reg.size() == 4 && c > 0xFF && c <= 0xFFFF_FFFF && !self.ctx.in_image(c) {
                        self.facts.hints.seeds.insert(c as u32);
                    }
                }
                self.set(reg, value, keeps_identity.then_some(id));
            }
            OpKind::Memory => {
                let (value, _) = self.operand(insn, 1);
                self.store(insn, value);
            }
            _ => {}
        }
    }

    /// The value `lea` computes.
    fn address(&mut self, insn: &Instruction) -> Val {
        let base = insn.memory_base();
        let index_reg = insn.memory_index();
        if matches!(base, Register::RIP | Register::EIP) {
            return Val::Const(insn.ip_rel_memory_address());
        }
        let disp = self.displacement(insn);
        if base == Register::None && index_reg == Register::None {
            return Val::Const(disp as u64 & self.mask());
        }
        let base_val = if base == Register::None {
            Val::Const(0)
        } else {
            self.reg(base)
        };
        if index_reg == Register::None {
            return match base_val {
                Val::Stack(d) => stack_value(d, disp),
                Val::Const(c) => Val::Const(c.wrapping_add(disp as u64) & self.mask()),
                Val::Ldr => self.list_head(disp),
                value if disp == 0 => value,
                _ => Val::Unknown,
            };
        }
        if insn.memory_index_scale() == 1 && disp == 0 {
            let index_val = self.reg(index_reg);
            let (base_id, index_id) = (self.id(base), self.id(index_reg));
            return self.add_values(base_val, base_id, index_val, index_id);
        }
        Val::Unknown
    }

    fn list_head(&mut self, disp: i64) -> Val {
        match self
            .ctx
            .layout
            .ldr_lists
            .iter()
            .position(|&off| off == disp)
        {
            Some(i) => Val::Link(ORDERS[i]),
            None => Val::Unknown,
        }
    }

    fn add_values(&mut self, a: Val, a_id: u32, b: Val, b_id: u32) -> Val {
        match (a, b) {
            (Val::Const(x), Val::Const(y)) => Val::Const(x.wrapping_add(y) & self.mask()),
            (Val::Stack(d), Val::Const(c)) | (Val::Const(c), Val::Stack(d)) => {
                stack_value(d, self.signed(c))
            }
            (Val::Ldr, Val::Const(c)) => self.list_head(c as i64),
            (Val::Lfanew(b), _) if b == b_id => Val::NtHeaders(b),
            (_, Val::Lfanew(b)) if b == a_id => Val::NtHeaders(b),
            (Val::DirRva(dir, b), _) if b == b_id => Val::Dir(dir, b),
            (_, Val::DirRva(dir, b)) if b == a_id => Val::Dir(dir, b),
            (Val::FuncArrayRva(b), _) if b == b_id => Val::FuncArray(b),
            (_, Val::FuncArrayRva(b)) if b == a_id => Val::FuncArray(b),
            (Val::FuncRva(b), _) if b == b_id => Val::Export(b),
            (_, Val::FuncRva(b)) if b == a_id => Val::Export(b),
            (a, b) => Self::mix(a, b, ADD),
        }
    }

    /// Arithmetic on encoded or image-derived data keeps its provenance.
    fn mix(a: Val, b: Val, op: u8) -> Val {
        match (a, b) {
            (Val::Data(mut t), Val::Data(u)) => {
                t.union(&u);
                t.ops |= op;
                Val::Data(t)
            }
            (Val::Data(mut t), _) | (_, Val::Data(mut t)) => {
                t.ops |= op;
                Val::Data(t)
            }
            (Val::Enc(c, ops), _) => Val::Enc(c, ops | op),
            (Val::Const(c), Val::Unknown | Val::Param(_) | Val::Enc(..)) => Val::Enc(c, op),
            _ => Val::Unknown,
        }
    }

    fn alu(&mut self, insn: &Instruction) {
        let reg = insn.op0_register();
        let m = insn.mnemonic();
        if m == Mnemonic::Add
            && reg.full_register() == Register::RSP
            && Self::is_imm(insn.op1_kind())
        {
            // Caller cleanup releases arguments pushed for earlier calls.
            self.pushed = (self.pushed - Self::signed_imm(insn, 1)).max(0);
        }
        let (a, a_id) = (self.reg(reg), self.id(reg));
        let value = match m {
            Mnemonic::Not | Mnemonic::Neg => Self::mix(a, Val::Unknown, XOR),
            Mnemonic::Inc => Self::mix(a, Val::Const(1), ADD),
            Mnemonic::Dec => Self::mix(a, Val::Const(1), SUB),
            _ => {
                let src = if m == Mnemonic::Imul && insn.op_count() == 3 {
                    1
                } else {
                    insn.op_count().saturating_sub(1)
                };
                let same = insn.op_kind(src) == OpKind::Register
                    && insn.op_register(src).full_register() == reg.full_register();
                let (b, b_id) = self.operand(insn, src);
                let immediate =
                    Self::is_imm(insn.op_kind(src)).then(|| Self::unsigned_imm(insn, src));
                if m == Mnemonic::Imul && insn.op_count() == 3 {
                    let factor = Self::unsigned_imm(insn, 2) as u32;
                    self.facts.hints.multipliers.insert(factor);
                    Self::mix(b, Val::Unknown, ADD)
                } else {
                    self.arith(m, a, a_id, b, b_id, same, immediate, reg)
                }
            }
        };
        let width = reg.size();
        let value = match value {
            Val::Const(c) => Val::Const(match width {
                1 => c & 0xFF,
                2 => c & 0xFFFF,
                4 => c & 0xFFFF_FFFF,
                _ => c,
            }),
            other => other,
        };
        self.set(reg, value, None);
    }

    #[allow(clippy::too_many_arguments)]
    fn arith(
        &mut self,
        m: Mnemonic,
        a: Val,
        a_id: u32,
        b: Val,
        b_id: u32,
        same: bool,
        immediate: Option<u64>,
        reg: Register,
    ) -> Val {
        if let Some(imm) = immediate {
            match m {
                Mnemonic::Ror if reg.size() == 4 => {
                    self.facts.hints.rotates.insert(imm as u32 & 31);
                }
                Mnemonic::Rol if reg.size() == 4 => {
                    self.facts
                        .hints
                        .rotates
                        .insert((32 - (imm as u32 & 31)) & 31);
                }
                Mnemonic::Imul => {
                    self.facts.hints.multipliers.insert(imm as u32);
                }
                Mnemonic::Shl if (1..31).contains(&imm) => {
                    self.facts.hints.multipliers.insert((1u32 << imm) + 1);
                    self.facts.hints.multipliers.insert((1u32 << imm) - 1);
                }
                Mnemonic::Xor | Mnemonic::Add | Mnemonic::Sub
                    if imm != 0 && self.keys.len() < 32 && !self.keys.contains(&imm) =>
                {
                    self.keys.push(imm);
                }
                _ => {}
            }
        }
        match m {
            Mnemonic::Xor if same => Val::Const(0),
            Mnemonic::Sub if same => Val::Const(0),
            Mnemonic::Add => match (&a, immediate) {
                (Val::Stack(d), Some(c)) => stack_value(*d, self.signed(c)),
                _ => self.add_values(a, a_id, b, b_id),
            },
            Mnemonic::Sub => match (a, b) {
                (Val::Stack(d), Val::Const(c)) => stack_value(d, self.signed(c).wrapping_neg()),
                (Val::Const(x), Val::Const(y)) => Val::Const(x.wrapping_sub(y)),
                (a, b) => Self::mix(a, b, SUB),
            },
            Mnemonic::Xor => match (a, b) {
                (Val::Const(x), Val::Const(y)) => Val::Const(x ^ y),
                (a, b) => Self::mix(a, b, XOR),
            },
            Mnemonic::And | Mnemonic::Or | Mnemonic::Shl | Mnemonic::Shr => match (a, b) {
                (Val::Const(x), Val::Const(y)) => Val::Const(match m {
                    Mnemonic::And => x & y,
                    Mnemonic::Or => x | y,
                    Mnemonic::Shl => x.wrapping_shl(y as u32),
                    _ => x.wrapping_shr(y as u32),
                }),
                (Val::Stack(d), _) if m == Mnemonic::And => Val::Stack(d),
                (a @ Val::Data(_), _) => a,
                _ => Val::Unknown,
            },
            _ => Self::mix(a, b, XOR),
        }
    }

    /// Everything not modelled: written registers become unknown, or carry the
    /// provenance of what was read (vector decoders are the common case).
    fn generic(&mut self, insn: &Instruction, _rva: u32) {
        let op = match insn.mnemonic() {
            Mnemonic::Pxor
            | Mnemonic::Xorps
            | Mnemonic::Xorpd
            | Mnemonic::Vpxor
            | Mnemonic::Vxorps
            | Mnemonic::Vpxord
            | Mnemonic::Vpxorq => XOR,
            Mnemonic::Paddb
            | Mnemonic::Paddw
            | Mnemonic::Paddd
            | Mnemonic::Vpaddb
            | Mnemonic::Vpaddw
            | Mnemonic::Vpaddd => ADD,
            Mnemonic::Psubb
            | Mnemonic::Psubw
            | Mnemonic::Psubd
            | Mnemonic::Vpsubb
            | Mnemonic::Vpsubw
            | Mnemonic::Vpsubd => SUB,
            _ => 0,
        };
        let info = self.info.info(insn);
        let mut reads = Vec::new();
        let mut writes = Vec::new();
        for used in info.used_registers() {
            let reg = used.register();
            if index(reg).is_none() || reg.full_register() == Register::RSP {
                continue;
            }
            match used.access() {
                OpAccess::Read | OpAccess::CondRead => reads.push(reg),
                OpAccess::Write | OpAccess::CondWrite => writes.push(reg),
                OpAccess::ReadWrite | OpAccess::ReadCondWrite => {
                    reads.push(reg);
                    writes.push(reg);
                }
                _ => {}
            }
        }
        let memory_read = info.used_memory().iter().any(|mem| {
            matches!(
                mem.access(),
                OpAccess::Read | OpAccess::ReadWrite | OpAccess::CondRead
            )
        });
        let memory_write = info.used_memory().iter().any(|mem| {
            matches!(
                mem.access(),
                OpAccess::Write | OpAccess::ReadWrite | OpAccess::CondWrite
            )
        });

        let mut taint = Taint {
            blobs: Vec::new(),
            ops: op,
        };
        let mut encoded = None;
        for reg in reads {
            match self.reg(reg) {
                Val::Data(t) => taint.union(&t),
                Val::Enc(c, ops) => encoded = Some((c, ops)),
                _ => {}
            }
        }
        let has_memory_operand = (0..insn.op_count()).any(|op| insn.op_kind(op) == OpKind::Memory);
        if memory_read && has_memory_operand {
            if let Val::Data(t) = self.load(insn) {
                taint.union(&t);
            }
        }
        let value = if !taint.blobs.is_empty() {
            Val::Data(taint)
        } else if let Some((c, ops)) = encoded {
            Val::Enc(c, ops | op)
        } else {
            Val::Unknown
        };
        if memory_write && has_memory_operand {
            self.store(insn, value.clone());
        }
        for reg in writes {
            self.set(reg, value.clone(), None);
        }
    }

    fn arg(&mut self, i: usize) -> Val {
        let layout = self.ctx.layout;
        if let Some(&reg) = layout.args.get(i) {
            return self.reg(reg);
        }
        let off = if layout.args.is_empty() {
            self.sp + 4 * i as i64
        } else {
            self.sp + 0x20 + 8 * (i as i64 - 4)
        };
        self.slots.get(&off).cloned().unwrap_or(Val::Unknown)
    }

    fn call(&mut self, insn: &Instruction, next: Option<&Instruction>, tail: bool) {
        let site = self.rva(insn);
        self.called = true;
        // Bytes of arguments the callee pops (x86 stdcall), when known.
        let mut pops = None;
        let result = match self.target(insn) {
            Target::Import(slot) => {
                let name = self.ctx.imports.get(&slot).map(|(_, name)| name.clone());
                match name.as_deref().and_then(loader_api) {
                    Some((api, args)) => {
                        pops = Some(args * self.ctx.layout.ptr);
                        self.loader(site, api)
                    }
                    None => {
                        self.helper_fill();
                        Val::Unknown
                    }
                }
            }
            Target::Internal(rva) => {
                if !self.facts.callees.contains(&rva) {
                    self.facts.callees.push(rva);
                }
                pops = self.ctx.ret_pops.get(&rva).copied();
                self.internal(site, rva)
            }
            Target::Value(value) => {
                self.through(site, value, tail);
                Val::Unknown
            }
            Target::Skip => return,
        };
        for &reg in self.ctx.layout.volatile {
            self.set(reg, Val::Unknown, None);
        }
        for i in 16..REGS {
            self.regs[i] = Val::Unknown;
        }
        self.set(Register::RAX, result, None);
        if self.ctx.layout.args.is_empty() {
            // Arguments for a later call may already be pushed, so only what this
            // callee pops is released. Without a known count, the callee is taken to
            // pop everything pushed unless the caller cleans up next.
            let caller_cleans = next.is_some_and(|next| {
                next.mnemonic() == Mnemonic::Add
                    && next.op0_kind() == OpKind::Register
                    && next.op0_register() == Register::ESP
            });
            let released = match pops {
                Some(bytes) => bytes,
                None if caller_cleans => 0,
                None => self.pushed,
            };
            self.sp += released;
            self.pushed = (self.pushed - released).max(0);
            if caller_cleans {
                self.pushed = 0;
            }
        }
        if tail {
            let value = self.reg(Register::RAX);
            if !self.facts.returns.contains(&value) && self.facts.returns.len() < 8 {
                self.facts.returns.push(value);
            }
        }
    }

    fn target(&mut self, insn: &Instruction) -> Target {
        match insn.op0_kind() {
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                let rva = insn
                    .near_branch_target()
                    .wrapping_sub(self.ctx.pe.image_base) as u32;
                match self.ctx.thunks.get(&rva) {
                    Some(&slot) => Target::Import(slot),
                    None => Target::Internal(rva),
                }
            }
            OpKind::Memory => {
                if let Loc::Global(va, false) = self.loc(insn) {
                    if self.ctx.imports.contains_key(&va) {
                        return Target::Import(va);
                    }
                    if va == self.ctx.guard_dispatch {
                        return self.value_target(Register::RAX);
                    }
                    if va == self.ctx.guard_check {
                        return Target::Skip;
                    }
                }
                match self.load(insn) {
                    Val::Import(slot) => Target::Import(slot),
                    value => Target::Value(value),
                }
            }
            OpKind::Register => self.value_target(insn.op0_register()),
            _ => Target::Value(Val::Unknown),
        }
    }

    fn value_target(&mut self, reg: Register) -> Target {
        match self.reg(reg) {
            Val::Import(slot) => Target::Import(slot),
            value => Target::Value(value),
        }
    }

    fn through(&mut self, site: u32, value: Val, tail: bool) {
        let target = match value {
            Val::Api(id) => Some(Through::Api(id)),
            Val::Global(va) => Some(Through::Global(va)),
            Val::Export(b) => {
                let module = self.origins.get(&b).cloned().unwrap_or(Module::Unknown);
                Some(Through::Api(self.inline_walk(site, module)))
            }
            _ if self.facts.events.export_walk() && !tail => {
                let module = self
                    .facts
                    .events
                    .walk_origin
                    .clone()
                    .unwrap_or(Module::Unknown);
                Some(Through::Api(self.inline_walk(site, module)))
            }
            _ => None,
        };
        match target {
            Some(target) => self.facts.through.push((site, target)),
            None if !tail => self.facts.indirect_unknown = true,
            None => {}
        }
    }

    /// A pointer found by an export walk inlined into this function, called here.
    fn inline_walk(&mut self, site: u32, module: Module) -> ResId {
        self.resolve(
            site,
            Via::ExportWalk(self.function.rva),
            module,
            Name::Unknown,
        )
    }

    fn resolve(&mut self, site: u32, via: Via, module: Module, name: Name) -> ResId {
        let id = ResId {
            function: self.function.rva,
            site,
        };
        self.facts.resolutions.retain(|res| res.site != site);
        self.facts.resolutions.push(Resolution {
            site,
            via,
            module,
            name,
        });
        id
    }

    fn loader(&mut self, site: u32, api: Loader) -> Val {
        match api {
            Loader::GetModuleHandle(wide) | Loader::LoadLibrary(wide) => {
                let arg = self.arg(0);
                if matches!(api, Loader::GetModuleHandle(_)) && arg == Val::Const(0) {
                    return Val::Module(Module::SelfImage);
                }
                Val::Module(self.module_from(&arg, wide))
            }
            Loader::GetModuleHandleEx(wide) => {
                let (name, out) = (self.arg(1), self.arg(2));
                let module = self.module_from(&name, wide);
                self.write_out(out, Val::Module(module));
                Val::Unknown
            }
            Loader::LdrModule => {
                let (name, out) = (self.arg(2), self.arg(3));
                let name = self.counted_string(&name, true, Want::Module);
                self.write_out(out, Val::Module(Module::Loader(name)));
                Val::Unknown
            }
            Loader::GetProcAddress => {
                let (handle, name) = (self.arg(0), self.arg(1));
                let module = self.module_of(&handle);
                let name = self.api_name(&name);
                Val::Api(self.resolve(site, Via::Loader("GetProcAddress"), module, name))
            }
            Loader::LdrGetProcedureAddress => {
                let (handle, name, ordinal, out) =
                    (self.arg(0), self.arg(1), self.arg(2), self.arg(3));
                let module = self.module_of(&handle);
                let name = match (name, ordinal) {
                    (Val::Const(0), Val::Const(ordinal)) if ordinal < 0x10000 => {
                        Name::Ordinal(ordinal as u16)
                    }
                    (name, _) => self.counted_string(&name, false, Want::Api),
                };
                let id = self.resolve(site, Via::Loader("LdrGetProcedureAddress"), module, name);
                self.write_out(out, Val::Api(id));
                Val::Unknown
            }
        }
    }

    fn write_out(&mut self, out: Val, value: Val) {
        match out {
            Val::Stack(d) => {
                self.slots.insert(d, value);
            }
            Val::Const(va) if self.ctx.is_writable(va) => match value {
                Val::Api(id) => self.facts.global_api.push((va, id)),
                Val::Module(module) => self.facts.global_module.push((va, module)),
                _ => {}
            },
            _ => {}
        }
    }

    /// The name inside a UNICODE_STRING or ANSI_STRING whose address is `value`.
    fn counted_string(&mut self, value: &Val, wide: bool, want: Want) -> Name {
        match value {
            Val::Stack(d) => {
                let buffer = self
                    .slots
                    .get(&(d + self.ctx.layout.string_buffer))
                    .cloned()
                    .unwrap_or(Val::Unknown);
                self.name_of(&buffer, wide, want)
            }
            Val::Param(p) => Name::Param(*p),
            _ => Name::Unknown,
        }
    }

    fn module_from(&mut self, arg: &Val, wide: bool) -> Module {
        match arg {
            Val::Param(p) => Module::Loader(Name::Param(*p)),
            _ => Module::Loader(self.name_of(arg, wide, Want::Module)),
        }
    }

    fn module_of(&mut self, value: &Val) -> Module {
        match value {
            Val::Module(module) => module.clone(),
            Val::Param(p) => Module::Param(*p),
            _ => Module::Unknown,
        }
    }

    fn api_name(&mut self, value: &Val) -> Name {
        match value {
            Val::Const(c) if *c < 0x10000 => Name::Ordinal(*c as u16),
            _ => self.name_of(value, false, Want::Api),
        }
    }

    fn name_of(&mut self, value: &Val, wide: bool, want: Want) -> Name {
        let ctx = self.ctx;
        match value {
            Val::Param(p) => Name::Param(*p),
            Val::Const(va) if ctx.in_image(*va) => {
                if let Some(text) = strings::literal(ctx.pe, ctx.raw, *va, wide, want) {
                    return Name::Text(text, How::Literal);
                }
                self.crack_blob(*va, want)
            }
            Val::Stack(d) => self.stack_name(*d, wide, want),
            Val::Data(taint) => {
                for &va in &taint.blobs {
                    if let Name::Text(text, how) = self.crack_blob(va, want) {
                        return Name::Text(text, how);
                    }
                }
                Name::Unknown
            }
            _ => Name::Unknown,
        }
    }

    fn crack_blob(&self, va: u64, want: Want) -> Name {
        let ctx = self.ctx;
        let Some(bytes) = u32::try_from(va.wrapping_sub(ctx.pe.image_base))
            .ok()
            .and_then(|rva| ctx.pe.rva_bytes(ctx.raw, rva))
        else {
            return Name::Unknown;
        };
        let bytes = &bytes[..bytes.len().min(256)];
        match strings::crack(bytes, &self.keys, want) {
            Some((text, scheme)) => Name::Text(text, How::Decoded(scheme)),
            None => Name::Unknown,
        }
    }

    /// The name in the stack buffer at `d`: immediates stored there, encoded
    /// immediates, or image data that flowed into it.
    fn stack_name(&mut self, d: i64, wide: bool, want: Want) -> Name {
        let limit = self
            .buffers
            .range(d + 1..)
            .next()
            .copied()
            .unwrap_or(d + 256)
            .min(d + 256);
        let mut plain = Vec::new();
        let mut cipher = Vec::new();
        let mut encoded = false;
        for off in d..limit {
            match self.bytes.get(&off) {
                Some(Cell::Plain(byte)) => {
                    plain.push(*byte);
                    cipher.push(*byte);
                }
                Some(Cell::Enc(byte)) => {
                    encoded = true;
                    cipher.push(*byte);
                }
                None => break,
            }
        }
        if !encoded {
            if let Some(text) = strings::terminated(&plain, wide, want) {
                return Name::Text(text, How::StackString);
            }
        }
        if let Some((text, scheme)) = strings::crack(&cipher, &self.keys, want) {
            return Name::Text(text, How::Decoded(scheme));
        }
        // Data written at the buffer's own start first, then nearer writes; within a
        // write, the lowest address is the start of the source string.
        let mut blobs: Vec<(i64, u64)> = self
            .regions
            .iter()
            .filter(|(start, end, _)| *start < limit && *end > d)
            .flat_map(|(start, _, taint)| {
                let distance = (start - d).abs();
                taint.blobs.iter().map(move |&va| (distance, va))
            })
            .collect();
        blobs.sort_unstable();
        let mut seen = BTreeSet::new();
        blobs.retain(|&(_, va)| seen.insert(va));
        for &(_, va) in &blobs {
            if let name @ Name::Text(..) = self.crack_blob(va, want) {
                return name;
            }
        }
        let ctx = self.ctx;
        for &(_, va) in &blobs {
            if let Some(text) = strings::literal(ctx.pe, ctx.raw, va, wide, want) {
                return Name::Text(text, How::Literal);
            }
        }
        Name::Unknown
    }

    /// A call that is not a resolver: a stack buffer passed with image data or small
    /// constants is assumed to be filled from them (decode helpers, memcpy).
    fn helper_fill(&mut self) {
        let count = 4;
        let args: Vec<Val> = (0..count).map(|i| self.arg(i)).collect();
        let buffers: Vec<i64> = args
            .iter()
            .filter_map(|arg| match arg {
                Val::Stack(d) => Some(*d),
                _ => None,
            })
            .collect();
        if buffers.is_empty() {
            return;
        }
        let mut taint = Taint::default();
        for arg in &args {
            match arg {
                Val::Const(c) if self.ctx.in_image(*c) => taint.union(&Taint {
                    blobs: vec![*c],
                    ops: 0,
                }),
                Val::Const(c) if *c > 0 && *c <= 0xFF => {
                    if !self.keys.contains(c) && self.keys.len() < 32 {
                        self.keys.push(*c);
                    }
                }
                Val::Data(t) => taint.union(t),
                _ => {}
            }
        }
        if !taint.blobs.is_empty() {
            for d in buffers {
                self.regions.push((d, i64::MAX, taint.clone()));
            }
        }
    }

    fn internal(&mut self, site: u32, rva: u32) -> Val {
        let Some(summary) = self.ctx.summaries.get(&rva).cloned() else {
            self.helper_fill();
            return Val::Unknown;
        };
        match summary {
            Summary::Fixed(id) => Val::Api(id),
            Summary::ModuleValue(module) => Val::Module(module),
            Summary::Api {
                via,
                name_param,
                module,
                params,
            } => {
                let args = self.used_args(params);
                let name = match name_param {
                    Some(p) => {
                        let value = self.arg(p as usize);
                        self.key_name(&value, Want::Api)
                    }
                    None => self.walker_name(&args, &via),
                };
                let module = match module {
                    Module::Param(p) => {
                        let value = self.arg(p as usize);
                        self.module_of(&value)
                    }
                    Module::Loader(Name::Param(p)) => {
                        let value = self.arg(p as usize);
                        Module::Loader(self.key_name(&value, Want::Module))
                    }
                    Module::Walk {
                        finder,
                        key: Name::Param(p),
                    } => {
                        let value = self.arg(p as usize);
                        Module::Walk {
                            finder,
                            key: self.key_name(&value, Want::Module),
                        }
                    }
                    Module::Unknown => self.walker_module(&args, &via),
                    module => module,
                };
                Val::Api(self.resolve(site, via, module, name))
            }
            Summary::Module {
                finder,
                key_param,
                loader,
                params,
            } => {
                let key = match key_param {
                    Some(p) => {
                        let value = self.arg(p as usize);
                        self.key_name(&value, Want::Module)
                    }
                    None => {
                        let args = self.used_args(params);
                        args.iter()
                            .map(|arg| self.key_name(arg, Want::Module))
                            .find(|name| !matches!(name, Name::Unknown))
                            .unwrap_or(Name::Unknown)
                    }
                };
                if loader {
                    Val::Module(Module::Loader(key))
                } else {
                    Val::Module(Module::Walk { finder, key })
                }
            }
        }
    }

    fn used_args(&mut self, params: u8) -> Vec<Val> {
        (0..8)
            .filter(|i| params & (1 << i) != 0)
            .map(|i| self.arg(i))
            .collect()
    }

    /// A resolver key: a hash constant, a name, or a parameter forwarded from here.
    fn key_name(&mut self, value: &Val, want: Want) -> Name {
        match value {
            Val::Const(c) if !self.ctx.in_image(*c) && *c > 0xFFFF => Name::Hash(*c),
            Val::Const(c) if !self.ctx.in_image(*c) && want == Want::Api => {
                Name::Ordinal(*c as u16)
            }
            _ => self.name_of(value, false, want),
        }
    }

    /// The API key among a walker's arguments. With two keys and no module argument,
    /// the walker finds the module too; by convention the module key comes first.
    fn walker_name(&mut self, args: &[Val], via: &Via) -> Name {
        let mut keys: Vec<Name> = Vec::new();
        for arg in args {
            if matches!(arg, Val::Module(_)) {
                continue;
            }
            let want = if matches!(via, Via::ImportWalk(_)) && self.is_module_string(arg) {
                continue;
            } else {
                Want::Api
            };
            let name = self.key_name(arg, want);
            if !matches!(name, Name::Unknown) {
                keys.push(name);
            }
        }
        keys.pop().unwrap_or(Name::Unknown)
    }

    fn walker_module(&mut self, args: &[Val], via: &Via) -> Module {
        if let Some(module) = args.iter().find_map(|arg| match arg {
            Val::Module(module) => Some(module.clone()),
            _ => None,
        }) {
            return module;
        }
        if let Via::ImportWalk(_) = via {
            for arg in args {
                if self.is_module_string(arg) {
                    return Module::Loader(self.name_of(arg, false, Want::Module));
                }
            }
        }
        let keys: Vec<Name> = args
            .iter()
            .filter(|arg| matches!(arg, Val::Const(c) if !self.ctx.in_image(*c) && *c > 0xFFFF))
            .map(|arg| match arg {
                Val::Const(c) => Name::Hash(*c),
                _ => Name::Unknown,
            })
            .collect();
        if keys.len() >= 2 {
            let finder = match via {
                Via::ExportWalk(rva) | Via::ImportWalk(rva) => *rva,
                Via::Loader(_) => self.function.rva,
            };
            return Module::Walk {
                finder,
                key: keys[0].clone(),
            };
        }
        Module::Unknown
    }

    fn is_module_string(&mut self, value: &Val) -> bool {
        matches!(
            self.name_of(value, false, Want::Module),
            Name::Text(text, _) if text.to_ascii_lowercase().ends_with(".dll")
        )
    }
}

enum Target {
    Import(u64),
    Internal(u32),
    Value(Val),
    Skip,
}
