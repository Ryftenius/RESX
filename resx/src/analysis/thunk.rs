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
}

impl ThunkResolution {
    pub fn desc(&self) -> String {
        match self {
            ThunkResolution::Iat {
                dll,
                func,
                slot_rva,
            } => format!(
                "IAT thunk → {}!{}  [slot RVA 0x{:08X}]",
                dll, func, slot_rva
            ),
            ThunkResolution::IatUnresolved { slot_rva } => format!(
                "IAT thunk @ slot RVA 0x{:08X} (import not resolved)",
                slot_rva
            ),
            ThunkResolution::Direct { target_rva } => {
                format!("JMP rel32 → RVA 0x{:08X}", target_rva)
            }
        }
    }

    pub fn iat_dll(&self) -> Option<&str> {
        if let ThunkResolution::Iat { dll, .. } = self {
            Some(dll)
        } else {
            None
        }
    }
    pub fn iat_func(&self) -> Option<&str> {
        if let ThunkResolution::Iat { func, .. } = self {
            Some(func)
        } else {
            None
        }
    }
}

pub fn follow_jmp_thunk(raw: &[u8], pe: &PeFile, start_rva: u32) -> Option<ThunkResolution> {
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

    let op0 = instr.op0_kind();

    match op0 {
        OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
            let target_va = instr.near_branch_target();
            let target_rva = (target_va.wrapping_sub(pe.image_base)) as u32;
            Some(ThunkResolution::Direct { target_rva })
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

            let disp = instr.memory_displacement64() as i64;

            let slot_va = if pe.arch == 64 && base_reg == Register::RIP {
                let next_ip = instr.next_ip();
                (next_ip as i64).wrapping_add(disp) as u64
            } else if base_reg == Register::None {
                disp as u32 as u64
            } else {
                return None;
            };

            if slot_va == 0 {
                return None;
            }
            let slot_rva = slot_va.wrapping_sub(pe.image_base) as u32;

            match resolve_iat_slot(pe, raw, slot_rva) {
                Some((dll, func)) => Some(ThunkResolution::Iat {
                    dll,
                    func,
                    slot_rva,
                }),
                None => Some(ThunkResolution::IatUnresolved { slot_rva }),
            }
        }

        _ => None,
    }
}
