mod api;
mod strings;
mod xrefs;

pub use api::{collect_api_calls, ApiCall};
use api::{
    collect_data_refs, describe_immediate_literals, describe_segment_access, suspicious_flow_note,
};
use strings::describe_string_address;
pub use strings::find_string_refs;
pub use xrefs::find_xrefs;

use iced_x86::{
    Decoder, DecoderOptions, Formatter, GasFormatter, IntelFormatter, MemorySizeOptions, Mnemonic,
    OpKind, Register,
};

use crate::analysis::symbols::SymbolIndex;
use crate::core::config::Config;
use crate::core::known::describe_known_address;
use crate::formats::pe::{Export, PeFile};

#[derive(Debug, Clone)]
pub struct Instruction {
    /// Basic-block entry used to decode this instruction. This disambiguates
    /// valid overlapping instruction streams.
    pub block_start: u32,
    pub rva: u32,
    pub va: u64,
    pub file_off: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub mnemonic: String,
    pub operands: String,
    pub iced: iced_x86::Instruction,
    pub comment: String,
    pub is_call: bool,
    pub is_jmp: bool,
    pub is_jcc: bool,
    pub call_target: u64,
}

pub fn is_ret(m: Mnemonic) -> bool {
    matches!(m, Mnemonic::Ret | Mnemonic::Retf)
        || format!("{:?}", m).to_lowercase().starts_with("ret")
}

pub fn is_jmp(m: Mnemonic) -> bool {
    m == Mnemonic::Jmp
}

pub fn is_jcc(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe
            | Mnemonic::Je
            | Mnemonic::Jne
            | Mnemonic::Jg
            | Mnemonic::Jge
            | Mnemonic::Jl
            | Mnemonic::Jle
            | Mnemonic::Jo
            | Mnemonic::Jno
            | Mnemonic::Js
            | Mnemonic::Jns
            | Mnemonic::Jp
            | Mnemonic::Jnp
            | Mnemonic::Jcxz
            | Mnemonic::Jecxz
            | Mnemonic::Jrcxz
            | Mnemonic::Loop
            | Mnemonic::Loope
            | Mnemonic::Loopne
    )
}

pub fn is_sys(m: Mnemonic) -> bool {
    matches!(
        m,
        Mnemonic::Syscall
            | Mnemonic::Sysenter
            | Mnemonic::Sysexit
            | Mnemonic::Int
            | Mnemonic::Iretq
            | Mnemonic::Iretd
            | Mnemonic::Iret
    )
}

struct SymResolver {
    symbols: SymbolIndex,
}

impl iced_x86::SymbolResolver for SymResolver {
    fn symbol(
        &mut self,
        _instruction: &iced_x86::Instruction,
        _operand: u32,
        _instruction_operand: Option<u32>,
        address: u64,
        _address_size: u32,
    ) -> Option<iced_x86::SymbolResult<'_>> {
        self.symbols
            .exact_name(address)
            .map(|name| iced_x86::SymbolResult::with_str(address, name))
    }
}

fn resolve_call_target(instr: &iced_x86::Instruction) -> u64 {
    if instr.op_count() == 0 {
        return 0;
    }
    match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            instr.near_branch_target()
        }
        OpKind::Immediate64 => instr.immediate64(),
        OpKind::Immediate32 => instr.immediate32() as u64,
        _ => 0,
    }
}

#[allow(clippy::too_many_arguments)]
pub fn disassemble_at(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    file_off: usize,
    start_rva: u32,
    arch: u32,
    image_base: u64,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    cfg: &Config,
) -> Result<Vec<Instruction>, String> {
    disassemble_at_inner(
        raw, pe, file_off, start_rva, arch, image_base, exports, symbols, cfg, true,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn disassemble_at_unbounded(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    file_off: usize,
    start_rva: u32,
    arch: u32,
    image_base: u64,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    cfg: &Config,
) -> Result<Vec<Instruction>, String> {
    disassemble_at_inner(
        raw, pe, file_off, start_rva, arch, image_base, exports, symbols, cfg, false,
    )
}

#[allow(clippy::too_many_arguments)]
fn disassemble_at_inner(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    file_off: usize,
    start_rva: u32,
    arch: u32,
    image_base: u64,
    exports: &[Export],
    symbols: Option<&SymbolIndex>,
    cfg: &Config,
    honor_runtime_bounds: bool,
) -> Result<Vec<Instruction>, String> {
    if file_off >= raw.len() {
        return Err(format!(
            "file offset 0x{:X} out of bounds (file size {})",
            file_off,
            raw.len()
        ));
    }
    if pe.rva_to_offset(start_rva) != Some(file_off)
        || !pe
            .rva_to_section(start_rva)
            .is_some_and(|section| section.is_executable())
    {
        return Err("Disassembly requires an unambiguous executable file-backed RVA".to_owned());
    }
    if !matches!(pe.machine, 0x014C | 0x8664) {
        return Err("Native disassembly currently supports x86 and x64 only".to_owned());
    }

    let runtime_function = honor_runtime_bounds
        .then(|| crate::formats::pe::read_runtime_function(pe, raw, start_rva))
        .flatten();
    let runtime_size = if honor_runtime_bounds {
        runtime_function
            .as_ref()
            .and_then(|func| func.end_rva.checked_sub(start_rva))
            .map(|size| size as usize)
            .filter(|&size| size > 0)
    } else {
        None
    };

    let section_limit = pe.rva_bytes(raw, start_rva).map_or(0, |bytes| bytes.len());

    let decode_len = runtime_size
        .unwrap_or(section_limit)
        .min(section_limit)
        .min(raw.len().saturating_sub(file_off));
    let mut chunk = &raw[file_off..file_off + decode_len];
    let byte_limit = if cfg.max_bytes == 0 {
        1024 * 1024
    } else {
        cfg.max_bytes.min(1024 * 1024)
    };
    chunk = &chunk[..chunk.len().min(byte_limit)];

    let symbol_index = symbols
        .cloned()
        .unwrap_or_else(|| SymbolIndex::from_exports_and_pdb(exports, &[], image_base));
    let ip = image_base + start_rva as u64;

    let mut intel_fmt = IntelFormatter::with_options(
        Some(Box::new(SymResolver {
            symbols: symbol_index.clone(),
        })),
        None,
    );
    let mut gas_fmt = GasFormatter::with_options(
        Some(Box::new(SymResolver {
            symbols: symbol_index.clone(),
        })),
        None,
    );
    configure_formatter(intel_fmt.options_mut());
    configure_formatter(gas_fmt.options_mut());

    let mut decoder = Decoder::with_ip(arch, chunk, ip, DecoderOptions::NONE);
    let mut iced = iced_x86::Instruction::default();

    let est_insns = if cfg.max_insns > 0 {
        cfg.max_insns.min(65_536)
    } else {
        (chunk.len() / 4).clamp(16, 65_536)
    };
    let mut insns: Vec<Instruction> = Vec::with_capacity(est_insns);
    let mut current_rva = start_rva;
    let mut pos = 0usize;
    let mut last_ret_idx: Option<usize> = None;
    let mut padding_after_ret = 0usize;

    while pos < chunk.len() {
        if insns.len()
            >= if cfg.max_insns == 0 {
                65_536
            } else {
                cfg.max_insns.min(65_536)
            }
        {
            break;
        }

        decoder.set_position(pos).ok();
        decoder.set_ip(ip + pos as u64);

        if !decoder.can_decode() {
            break;
        }
        decoder.decode_out(&mut iced);

        let i_len = iced.len();
        if i_len == 0 {
            break;
        }
        let i_bytes: Vec<u8> = chunk[pos..pos + i_len.min(chunk.len() - pos)].to_vec();
        let pc = ip + pos as u64;
        let m = iced.mnemonic();

        let mut text = String::new();
        if cfg.intel_syntax {
            intel_fmt.format(&iced, &mut text);
        } else {
            gas_fmt.format(&iced, &mut text);
        }

        let (mnem, ops) = if let Some(sp) = text.find(' ') {
            (
                text[..sp].to_ascii_lowercase(),
                text[sp + 1..].trim().to_owned(),
            )
        } else {
            (text.to_ascii_lowercase(), String::new())
        };

        let mut comment_parts: Vec<String> = Vec::new();
        let call_target = if m == Mnemonic::Call || is_jmp(m) || is_jcc(m) {
            let tgt = resolve_call_target(&iced);
            if tgt != 0 {
                let t_rva = tgt.wrapping_sub(image_base) as u32;
                let destination = symbol_index
                    .describe(tgt)
                    .unwrap_or_else(|| format!("loc_{t_rva:08x}"));
                if cfg.verbose {
                    let flow = if m == Mnemonic::Call {
                        "call"
                    } else if is_jmp(m) {
                        "jump"
                    } else {
                        "taken"
                    };
                    comment_parts.push(format!(
                        "{flow} to {destination} (rva 0x{t_rva:08x}, va 0x{tgt:x})"
                    ));
                } else {
                    comment_parts.push(format!("→ {destination}"));
                }
                if cfg.verbose && is_jcc(m) {
                    let fallthrough = pc.saturating_add(i_len as u64);
                    let fallthrough_rva = fallthrough.wrapping_sub(image_base) as u32;
                    comment_parts.push(format!(
                        "fallthrough to loc_{fallthrough_rva:08x} (rva 0x{fallthrough_rva:08x}, va 0x{fallthrough:x})"
                    ));
                }
            }
            tgt
        } else {
            0
        };

        for addr in collect_data_refs(&iced) {
            if let Some(desc) = describe_known_address(addr)
                .or_else(|| describe_string_address(raw, pe, image_base, addr))
                .or_else(|| {
                    (addr >= image_base)
                        .then(|| symbol_index.describe(addr))
                        .flatten()
                })
            {
                if !comment_parts
                    .iter()
                    .any(|part| part == &desc || part.strip_prefix("→ ") == Some(desc.as_str()))
                {
                    comment_parts.push(desc);
                }
            }
        }

        if let Some(seg_desc) = describe_segment_access(&iced) {
            if !comment_parts.iter().any(|p| p == &seg_desc) {
                comment_parts.push(seg_desc);
            }
        }
        for literal_desc in describe_immediate_literals(&iced) {
            if !comment_parts.iter().any(|p| p == &literal_desc) {
                comment_parts.push(literal_desc);
            }
        }

        if cfg.hostile {
            if let Some(note) = suspicious_flow_note(&iced) {
                if !comment_parts.iter().any(|p| p == &note) {
                    comment_parts.push(note);
                }
            }
        }

        let comment = comment_parts.join(" | ");
        let is_int3 = i_bytes.len() == 1 && i_bytes[0] == 0xCC;
        let is_all_pad = i_bytes.iter().all(|&b| b == 0xCC || b == 0x90 || b == 0x00);

        let insn = Instruction {
            block_start: start_rva,
            rva: current_rva,
            va: pc,
            file_off: (file_off + pos) as u64,
            bytes: i_bytes,
            text,
            mnemonic: mnem,
            operands: ops,
            iced,
            comment,
            is_call: m == Mnemonic::Call,
            is_jmp: is_jmp(m),
            is_jcc: is_jcc(m),
            call_target,
        };

        insns.push(insn);

        if runtime_size.is_none() && is_ret(m) {
            last_ret_idx = Some(insns.len() - 1);
            padding_after_ret = 0;
        } else if runtime_size.is_none() {
            if let Some(ret_idx) = last_ret_idx {
                if is_all_pad || m == Mnemonic::Nop || is_int3 {
                    padding_after_ret += i_len;
                    if padding_after_ret >= 3 {
                        insns.truncate(ret_idx + 1);
                        break;
                    }
                } else {
                    last_ret_idx = None;
                    padding_after_ret = 0;
                }
            }
        }

        if runtime_size.is_none() && last_ret_idx.is_none() && is_int3 {
            break;
        }

        pos += i_len;
        current_rva += i_len as u32;
    }

    Ok(insns)
}

fn configure_formatter(options: &mut iced_x86::FormatterOptions) {
    options.set_uppercase_mnemonics(false);
    options.set_uppercase_registers(false);
    options.set_uppercase_keywords(false);
    options.set_uppercase_decorators(false);
    options.set_uppercase_prefixes(false);
    options.set_uppercase_hex(false);
    options.set_hex_prefix("0x");
    options.set_hex_suffix("");
    options.set_space_after_operand_separator(true);
    options.set_branch_leading_zeros(false);
    options.set_displacement_leading_zeros(false);
    options.set_memory_size_options(MemorySizeOptions::Always);
}

#[cfg(test)]
mod formatting_tests {
    use super::*;

    #[test]
    fn intel_output_is_lowercase_prefixed_hex() {
        let mut decoder = Decoder::with_ip(
            64,
            &[0x4d, 0x8b, 0x5a, 0x28],
            0x140048399,
            DecoderOptions::NONE,
        );
        let instruction = decoder.decode();
        let mut formatter = IntelFormatter::new();
        configure_formatter(formatter.options_mut());
        let mut text = String::new();
        formatter.format(&instruction, &mut text);
        assert_eq!(text, "mov r11, qword ptr [r10+0x28]");
        assert!(!text.contains('h'));
        assert!(!text.chars().any(|ch| ch.is_ascii_uppercase()));
    }
}
