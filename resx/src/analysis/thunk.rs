use iced_x86::{Decoder, DecoderOptions, Mnemonic, OpKind, Register};

use crate::formats::pe::{resolve_iat_slot, PeFile};

#[derive(Debug, Clone)]
pub enum ThunkResolution {
    Iat {
        dll: String,
        func: String,
        slot_rva: u32,
    },
    IatUnresolved {
        slot_rva: u32,
    },
    Direct {
        target_rva: u32,
    },
    Chain {
        hops: Vec<u32>,
        final_target: Box<ThunkResolution>,
    },
}

impl ThunkResolution {
    pub fn desc(&self) -> String {
        match self {
            ThunkResolution::Iat {
                dll,
                func,
                slot_rva,
            } => {
                format!(
                    "IAT thunk → {}!{}  [slot RVA 0x{:08X}]",
                    dll, func, slot_rva
                )
            }
            ThunkResolution::IatUnresolved { slot_rva } => {
                format!(
                    "IAT thunk @ slot RVA 0x{:08X} (import not resolved)",
                    slot_rva
                )
            }
            ThunkResolution::Direct { target_rva } => {
                format!("JMP rel32 → RVA 0x{:08X}", target_rva)
            }
            ThunkResolution::Chain { hops, final_target } => {
                format!(
                    "thunk chain [{}] → {}",
                    hops.iter()
                        .map(|r| format!("0x{:08X}", r))
                        .collect::<Vec<_>>()
                        .join(" → "),
                    final_target.desc()
                )
            }
        }
    }

    pub fn iat_dll(&self) -> Option<&str> {
        match self {
            ThunkResolution::Iat { dll, .. } => Some(dll),
            ThunkResolution::Chain { final_target, .. } => final_target.iat_dll(),
            _ => None,
        }
    }

    pub fn iat_func(&self) -> Option<&str> {
        match self {
            ThunkResolution::Iat { func, .. } => Some(func),
            ThunkResolution::Chain { final_target, .. } => final_target.iat_func(),
            _ => None,
        }
    }
}

pub fn follow_jmp_thunk(raw: &[u8], pe: &PeFile, start_rva: u32) -> Option<ThunkResolution> {
    follow_jmp_thunk_inner(raw, pe, start_rva, 0, &mut Vec::new())
}

fn follow_jmp_thunk_inner(
    raw: &[u8],
    pe: &PeFile,
    start_rva: u32,
    depth: usize,
    hops: &mut Vec<u32>,
) -> Option<ThunkResolution> {
    if depth >= 8 || hops.contains(&start_rva) {
        return None;
    }

    let off = pe.rva_to_offset(start_rva)?;
    if off >= raw.len() {
        return None;
    }

    let chunk = &raw[off..];
    if chunk.is_empty() {
        return None;
    }

    let ip = pe.image_base + start_rva as u64;
    let mut decoder = Decoder::with_ip(pe.arch, chunk, ip, DecoderOptions::NONE);
    let mut instr = iced_x86::Instruction::default();
    decoder.decode_out(&mut instr);

    if instr.mnemonic() != Mnemonic::Jmp {
        return None;
    }

    hops.push(start_rva);

    let resolved = match instr.op0_kind() {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            let target_va = instr.near_branch_target();
            let target_rva = target_va.wrapping_sub(pe.image_base) as u32;

            // Follow chained JMP stubs inside the image.
            if pe.rva_to_offset(target_rva).is_some() {
                if let Some(next) = follow_jmp_thunk_inner(raw, pe, target_rva, depth + 1, hops) {
                    ThunkResolution::Chain {
                        hops: hops.clone(),
                        final_target: Box::new(next),
                    }
                } else {
                    ThunkResolution::Direct { target_rva }
                }
            } else {
                ThunkResolution::Direct { target_rva }
            }
        }

        OpKind::Memory => {
            let base_reg = instr.memory_base();
            let index_reg = instr.memory_index();
            if index_reg != Register::None {
                return None;
            }
            if instr.memory_segment() != Register::None && instr.memory_segment() != Register::DS {
                return None;
            }

            let slot_va = if pe.arch == 64 && base_reg == Register::RIP {
                instr.ip_rel_memory_address()
            } else if base_reg == Register::None {
                instr.memory_displacement64() as u32 as u64
            } else {
                return None;
            };

            if slot_va == 0 {
                return None;
            }

            let slot_rva = slot_va.wrapping_sub(pe.image_base) as u32;

            match resolve_iat_slot(pe, raw, slot_rva) {
                Some((dll, func)) => ThunkResolution::Iat {
                    dll,
                    func,
                    slot_rva,
                },
                None => ThunkResolution::IatUnresolved { slot_rva },
            }
        }

        _ => return None,
    };

    Some(resolved)
}
