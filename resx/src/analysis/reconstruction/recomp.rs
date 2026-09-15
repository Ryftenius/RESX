use iced_x86::{Mnemonic, OpKind, Register};

use crate::analysis::disasm::{is_jcc, Instruction};
use crate::analysis::symbols::SymbolIndex;
use crate::core::known::describe_known_address;
use crate::formats::pe::{Export, PeRuntimeFunctionInfo};

#[derive(Debug, Clone)]
struct RecompPrototype {
    return_type: String,
    calling_convention: String,
    params: Vec<String>,
    raw_type_name: String,
}

fn fmt_op(
    instr: &iced_x86::Instruction,
    op_idx: u32,
    image_base: u64,
    symbols: Option<&SymbolIndex>,
) -> String {
    if op_idx >= instr.op_count() {
        return String::new();
    }
    match instr.op_kind(op_idx) {
        OpKind::Register => format!("{:?}", instr.op_register(op_idx)).to_lowercase(),
        OpKind::Immediate64 => {
            let v = instr.immediate64();
            if let Some(desc) = describe_known_address(v) {
                return desc;
            }
            if v >= image_base {
                if let Some(desc) = symbols.and_then(|idx| idx.describe(v)) {
                    return desc;
                }
            }
            format!("0x{:X}", v)
        }
        OpKind::Immediate32 => {
            let v = instr.immediate32() as u64;
            if let Some(desc) = describe_known_address(v) {
                return desc;
            }
            if v >= image_base {
                if let Some(desc) = symbols.and_then(|idx| idx.describe(v)) {
                    return desc;
                }
            }
            format!("0x{:X}", v)
        }
        OpKind::Immediate8
        | OpKind::Immediate16
        | OpKind::Immediate8to16
        | OpKind::Immediate8to32
        | OpKind::Immediate8to64
        | OpKind::Immediate32to64 => {
            let v = instr.immediate(op_idx);
            if v == 0 {
                "0".to_owned()
            } else if (v as i64) < 0 {
                format!("-0x{:X}", (-(v as i64)) as u64)
            } else {
                format!("0x{:X}", v)
            }
        }
        OpKind::Memory => {
            if let Some(addr) = absolute_memory_address(instr) {
                if let Some(desc) = describe_known_address(addr) {
                    return desc;
                }
                if addr >= image_base {
                    if let Some(desc) = symbols.and_then(|idx| idx.describe(addr)) {
                        return format!("*({})", desc);
                    }
                }
            }
            let base = instr.memory_base();
            let idx = instr.memory_index();
            let scale = instr.memory_index_scale();
            let disp = instr.memory_displacement64() as i64;

            let seg = if instr.memory_segment() != Register::None
                && instr.memory_segment() != Register::DS
            {
                format!("{:?}:", instr.memory_segment()).to_lowercase() + ":"
            } else {
                String::new()
            };

            let base_s = if base != Register::None && base != Register::RIP {
                format!("{:?}", base).to_lowercase()
            } else {
                String::new()
            };

            let idx_s = if idx != Register::None {
                let i = format!("{:?}", idx).to_lowercase();
                if scale > 1 {
                    format!("{}*{}", i, scale)
                } else {
                    i
                }
            } else {
                String::new()
            };

            let disp_s = if disp > 0 {
                format!("+0x{:X}", disp)
            } else if disp < 0 {
                format!("-0x{:X}", (-disp) as u64)
            } else {
                String::new()
            };

            let mut inner = base_s;
            if !idx_s.is_empty() {
                if !inner.is_empty() {
                    inner.push('+');
                }
                inner.push_str(&idx_s);
            }
            inner.push_str(&disp_s);
            if inner.is_empty() {
                inner = "0".to_owned();
            }

            format!("{}*({})", seg, inner)
        }
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            format!("0x{:X}", instr.near_branch_target())
        }
        _ => "?".to_owned(),
    }
}

fn jcc_condition(
    m: Mnemonic,
    prev_cmp: Option<&iced_x86::Instruction>,
    image_base: u64,
    symbols: Option<&SymbolIndex>,
) -> String {
    let Some(cmp_instr) = prev_cmp else {
        return match m {
            Mnemonic::Je => "ZF".to_owned(),
            Mnemonic::Jne => "!ZF".to_owned(),
            Mnemonic::Js => "SF".to_owned(),
            Mnemonic::Jns => "!SF".to_owned(),
            Mnemonic::Jo => "OF".to_owned(),
            Mnemonic::Jno => "!OF".to_owned(),
            _ => format!("{:?}", m),
        };
    };

    let a = fmt_op(cmp_instr, 0, image_base, symbols);
    let b = fmt_op(cmp_instr, 1, image_base, symbols);
    let is_test = cmp_instr.mnemonic() == Mnemonic::Test;
    let test_expr = if a == b {
        a.clone()
    } else {
        format!("({} & {})", a, b)
    };
    match m {
        Mnemonic::Je if is_test => format!("{} == 0", test_expr),
        Mnemonic::Jne if is_test => format!("{} != 0", test_expr),
        Mnemonic::Je => format!("{} == {}", a, b),
        Mnemonic::Jne => format!("{} != {}", a, b),
        Mnemonic::Ja => format!("(unsigned){} > (unsigned){}", a, b),
        Mnemonic::Jae => format!("(unsigned){} >= (unsigned){}", a, b),
        Mnemonic::Jb => format!("(unsigned){} < (unsigned){}", a, b),
        Mnemonic::Jbe => format!("(unsigned){} <= (unsigned){}", a, b),
        Mnemonic::Jg => format!("{} > {}", a, b),
        Mnemonic::Jge => format!("{} >= {}", a, b),
        Mnemonic::Jl => format!("{} < {}", a, b),
        Mnemonic::Jle => format!("{} <= {}", a, b),
        Mnemonic::Js => format!("{} < 0", a),
        Mnemonic::Jns => format!("{} >= 0", a),
        _ => format!("{:?}", m),
    }
}

pub fn recomp_c(
    insns: &[Instruction],
    exp: &Export,
    arch: u32,
    image_base: u64,
    symbols: Option<&SymbolIndex>,
    unwind: Option<&PeRuntimeFunctionInfo>,
    _cfg: &crate::core::config::Config,
) -> String {
    if insns.is_empty() {
        return "// No instructions to reconstruct.".to_owned();
    }

    let mut sb = String::new();
    let mut jump_targets: std::collections::HashSet<u32> = std::collections::HashSet::new();
    let insn_rvas: std::collections::HashSet<u32> = insns.iter().map(|insn| insn.rva).collect();
    for insn in insns {
        if (insn.is_jmp || insn.is_jcc) && insn.call_target != 0 {
            let t_rva = insn.call_target.wrapping_sub(image_base) as u32;
            jump_targets.insert(t_rva);
        }
    }
    for pair in insns.windows(2) {
        let current = &pair[0];
        let expected = current.rva.checked_add(current.bytes.len() as u32);
        if !current.is_jmp
            && !current.is_jcc
            && !crate::analysis::disasm::is_ret(current.iced.mnemonic())
            && expected != Some(pair[1].rva)
            && expected.is_some_and(|rva| insn_rvas.contains(&rva))
        {
            jump_targets.insert(expected.unwrap());
        }
    }

    let (default_cc, param_regs): (&str, &[&str]) = if arch == 64 {
        ("__fastcall", &["rcx", "rdx", "r8", "r9"])
    } else {
        ("__stdcall", &[])
    };
    let prototype = symbols
        .and_then(|idx| idx.exact(image_base + exp.rva as u64))
        .and_then(|sym| parse_pdb_prototype(&sym.type_name, default_cc));

    let mut used_params = 0usize;
    for insn in insns {
        for op_idx in 0..insn.iced.op_count() {
            if insn.iced.op_kind(op_idx) == OpKind::Register {
                let reg_name = format!("{:?}", insn.iced.op_register(op_idx)).to_lowercase();
                for (i, &pr) in param_regs.iter().enumerate() {
                    if reg_name == pr && i >= used_params {
                        used_params = i + 1;
                    }
                }
            }
        }
    }
    if used_params == 0 && arch == 32 {
        used_params = 4;
    }

    let ret_type = prototype
        .as_ref()
        .map(|p| p.return_type.as_str())
        .unwrap_or("NTSTATUS");
    let cc = prototype
        .as_ref()
        .map(|p| p.calling_convention.as_str())
        .unwrap_or(default_cc);

    if let Some(proto) = prototype.as_ref() {
        sb.push_str(&format!("// PDB type: {}\n", proto.raw_type_name));
    }
    if let Some(unwind) = unwind {
        sb.push_str(&format!(
            "// .pdata: range=0x{:08X}-0x{:08X} unwind=0x{:08X} version={} prolog={} unwind_codes={} flags=0x{:X}",
            unwind.begin_rva,
            unwind.end_rva,
            unwind.unwind_info_rva,
            unwind.unwind_version,
            unwind.prolog_size,
            unwind.unwind_code_count,
            unwind.unwind_flags
        ));
        if unwind.frame_register != 0 {
            sb.push_str(&format!(
                " frame_reg={} frame_off={}",
                reg_num_name(unwind.frame_register),
                unwind.frame_offset
            ));
        }
        if unwind.exception_handler_rva != 0 {
            sb.push_str(&format!(" handler=0x{:08X}", unwind.exception_handler_rva));
        }
        sb.push('\n');
    }

    sb.push_str(&format!("{} {} {}(\n", ret_type, cc, exp.name));
    if let Some(proto) = prototype.as_ref() {
        if proto.params.is_empty() {
            sb.push_str("    void\n");
        } else {
            for (i, param) in proto.params.iter().enumerate() {
                let sep = if i + 1 == proto.params.len() { "" } else { "," };
                sb.push_str(&format!("    {}{} \n", param, sep));
            }
        }
    } else if used_params == 0 {
        sb.push_str("    void\n");
    } else {
        for i in 0..used_params {
            let sep = if i + 1 == used_params { "" } else { "," };
            sb.push_str(&format!("    void* param_{}{} \n", i + 1, sep));
        }
    }
    sb.push_str(") {\n");

    let mut prev_cmp: Option<&Instruction> = None;

    for (index, insn) in insns.iter().enumerate() {
        if jump_targets.contains(&insn.rva) {
            sb.push_str(&format!("\nlabel_{:08X}:\n", insn.rva));
        }

        let orig_asm = if insn.comment.is_empty() {
            insn.text.clone()
        } else {
            format!("{}  ; {}", insn.text, insn.comment)
        };

        let a0 = fmt_op(&insn.iced, 0, image_base, symbols);
        let a1 = fmt_op(&insn.iced, 1, image_base, symbols);
        let m = insn.iced.mnemonic();

        let stmt = match m {
            Mnemonic::Mov => format!("{} = {};", a0, a1),
            Mnemonic::Lea => format!("{} = &{};", a0, a1),
            Mnemonic::Xor => {
                if a0 == a1 {
                    format!("{} = 0;", a0)
                } else {
                    format!("{} ^= {};", a0, a1)
                }
            }
            Mnemonic::Add => format!("{} += {};", a0, a1),
            Mnemonic::Sub => format!("{} -= {};", a0, a1),
            Mnemonic::And => format!("{} &= {};", a0, a1),
            Mnemonic::Or => format!("{} |= {};", a0, a1),
            Mnemonic::Shl => format!("{} <<= {};", a0, a1),
            Mnemonic::Shr => format!("{} >>= {};", a0, a1),
            Mnemonic::Sar => format!("{} >>= {};", a0, a1),
            Mnemonic::Not => format!("{} = ~{};", a0, a0),
            Mnemonic::Neg => format!("{} = -{};", a0, a0),
            Mnemonic::Inc => format!("{}++;", a0),
            Mnemonic::Dec => format!("{}--;", a0),
            Mnemonic::Imul | Mnemonic::Mul => {
                if insn.iced.op_count() > 1 {
                    format!("{} *= {};", a0, a1)
                } else {
                    format!("mul({});", a0)
                }
            }
            Mnemonic::Push => format!("PUSH({});", a0),
            Mnemonic::Pop => format!("{} = POP();", a0),
            Mnemonic::Call => {
                if insn.call_target != 0 {
                    let t_rva = insn.call_target.wrapping_sub(image_base) as u32;
                    if insn_rvas.contains(&t_rva) {
                        format!("CALL_LOCAL(label_{:08X});", t_rva)
                    } else if !insn.comment.is_empty() {
                        format!("result = {}();", insn.comment)
                    } else {
                        format!("result = fn_0x{:X}();", insn.call_target)
                    }
                } else if !insn.comment.is_empty() {
                    format!("result = {}();", insn.comment)
                } else {
                    format!("result = {}();", a0)
                }
            }
            _ if crate::analysis::disasm::is_ret(m) => {
                if arch == 64 {
                    "return rax;".to_owned()
                } else {
                    "return eax;".to_owned()
                }
            }
            Mnemonic::Jmp => {
                if insn.call_target != 0 {
                    let t_rva = insn.call_target.wrapping_sub(image_base) as u32;
                    if jump_targets.contains(&t_rva) {
                        format!("goto label_{:08X};", t_rva)
                    } else {
                        format!("return {}();", insn.comment)
                    }
                } else {
                    format!("goto *{};", a0)
                }
            }
            Mnemonic::Cmp | Mnemonic::Test => format!("/* compare {}, {} */", a0, a1),
            Mnemonic::Nop => "/* nop */".to_owned(),
            Mnemonic::Syscall => {
                let reg = if arch == 64 { "rax" } else { "eax" };
                format!("__syscall({});", reg)
            }
            Mnemonic::Int => {
                let imm = insn.iced.immediate(0);
                format!("__interrupt(0x{:X});", imm)
            }
            Mnemonic::Sysenter => "__sysenter();".to_owned(),
            _ if is_jcc(m) => {
                let cond = jcc_condition(m, prev_cmp.map(|c| &c.iced), image_base, symbols);
                if insn.call_target != 0 {
                    let t_rva = insn.call_target.wrapping_sub(image_base) as u32;
                    format!("if ({}) goto label_{:08X};", cond, t_rva)
                } else {
                    format!("if ({}) goto *{};", cond, a0)
                }
            }
            _ => format!("/* {} */", orig_asm),
        };

        if matches!(m, Mnemonic::Cmp | Mnemonic::Test) {
            prev_cmp = Some(insn);
        } else if !is_jcc(m) && !preserves_flags(m) {
            prev_cmp = None;
        }

        const STMT_WIDTH: usize = 52;
        let pad = if stmt.len() < STMT_WIDTH {
            STMT_WIDTH - stmt.len()
        } else {
            0
        };
        sb.push_str(&format!(
            "    {}{}  // {}\n",
            stmt,
            " ".repeat(pad),
            orig_asm
        ));
        if !insn.is_jmp
            && !insn.is_jcc
            && !crate::analysis::disasm::is_ret(m)
            && insns
                .get(index + 1)
                .is_some_and(|next| insn.rva.checked_add(insn.bytes.len() as u32) != Some(next.rva))
        {
            if let Some(target) = insn
                .rva
                .checked_add(insn.bytes.len() as u32)
                .filter(|rva| insn_rvas.contains(rva))
            {
                sb.push_str(&format!(
                    "    goto label_{:08X};  // architectural stream continuation\n",
                    target
                ));
            }
        }
    }

    sb.push_str("}\n");
    sb
}

fn parse_pdb_prototype(type_name: &str, default_cc: &str) -> Option<RecompPrototype> {
    let raw = type_name.trim();
    if raw.is_empty() {
        return None;
    }

    let open = raw.rfind('(')?;
    let close = raw.rfind(')')?;
    if close <= open {
        return None;
    }

    let params_text = raw[open + 1..close].trim();
    let prefix = raw[..open].trim().trim_end_matches('*').trim();
    let (return_type, calling_convention) = split_return_and_cc(prefix, default_cc);
    let params = parse_params(params_text);

    Some(RecompPrototype {
        return_type: if return_type.is_empty() {
            "NTSTATUS".to_owned()
        } else {
            return_type
        },
        calling_convention,
        params,
        raw_type_name: raw.to_owned(),
    })
}

fn split_return_and_cc(prefix: &str, default_cc: &str) -> (String, String) {
    let ccs = [
        "__cdecl",
        "__stdcall",
        "__fastcall",
        "__thiscall",
        "__vectorcall",
    ];
    for cc in ccs {
        if let Some(pos) = prefix.find(cc) {
            let ret = prefix[..pos].trim().trim_matches('(').trim().to_owned();
            return (ret, cc.to_owned());
        }
    }
    (
        prefix.trim().trim_matches('(').trim().to_owned(),
        default_cc.to_owned(),
    )
}

fn parse_params(text: &str) -> Vec<String> {
    let trimmed = text.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("void") {
        return Vec::new();
    }

    trimmed
        .split(',')
        .enumerate()
        .map(|(idx, raw)| {
            let ty = raw.trim().trim_matches('(').trim_matches(')').trim();
            let ty = if ty.is_empty() { "void*" } else { ty };
            format!("{ty} param_{}", idx + 1)
        })
        .collect()
}

fn reg_num_name(reg: u8) -> &'static str {
    match reg {
        1 => "rcx",
        2 => "rdx",
        3 => "rbx",
        4 => "rsp",
        5 => "rbp",
        6 => "rsi",
        7 => "rdi",
        8 => "r8",
        9 => "r9",
        10 => "r10",
        11 => "r11",
        12 => "r12",
        13 => "r13",
        14 => "r14",
        15 => "r15",
        _ => "?",
    }
}

fn preserves_flags(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Mov
            | Mnemonic::Movsx
            | Mnemonic::Movsxd
            | Mnemonic::Movzx
            | Mnemonic::Lea
            | Mnemonic::Push
            | Mnemonic::Pop
            | Mnemonic::Jmp
            | Mnemonic::Nop
    )
}

fn absolute_memory_address(instr: &iced_x86::Instruction) -> Option<u64> {
    if instr.memory_base() == Register::RIP || instr.memory_base() == Register::EIP {
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
