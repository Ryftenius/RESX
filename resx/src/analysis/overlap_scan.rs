//! Bounded, opt-in discovery of calls in branch-targeted decode seams.
use std::collections::{HashSet, VecDeque};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Mnemonic, OpKind, Register};

use crate::formats::pe::PeFile;

const MAX_SEAMS: usize = 4096;
const MAX_ALT_INSNS: usize = 262_144;
const MAX_PRIMARY_INSNS: usize = 4_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeamTarget {
    Direct(u32),
    ImportSlot(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SeamCall {
    pub site_rva: u32,
    pub target: SeamTarget,
    pub is_jump: bool,
}

#[derive(Default)]
pub struct SeamScan {
    pub calls: Vec<SeamCall>,
    pub truncated: bool,
}

fn code_bytes<'a>(pe: &PeFile, raw: &'a [u8], rva: u32) -> Option<&'a [u8]> {
    let section = pe.rva_to_section(rva)?;
    if !section.is_executable() || section.raw_offset == 0 {
        return None;
    }
    pe.rva_bytes(raw, rva)
}

fn branch_rva(pe: &PeFile, target_va: u64) -> Option<u32> {
    let rva = u32::try_from(target_va.checked_sub(pe.image_base)?).ok()?;
    pe.rva_to_section(rva).filter(|s| s.is_executable())?;
    Some(rva)
}

/// Only a decoded branch into the *middle* of a primary instruction can seed
/// another stream. Calls alone are not used as seeds, and arbitrary byte-wise
/// opcode matches are never accepted as alternate call sites.
pub fn scan_seam_calls(raw: &[u8], pe: &PeFile) -> SeamScan {
    let mut result = SeamScan::default();
    if !matches!(pe.machine, 0x14c | 0x8664) {
        return result;
    }
    let import_slots = crate::formats::pe::import_slot_map_by_rva(pe, raw);
    let mut spans = Vec::<(u32, u32)>::new();
    let mut branches = Vec::new();
    let mut primary_count = 0usize;
    for section in &pe.sections {
        if !section.is_executable() || section.raw_offset == 0 || section.raw_size == 0 {
            continue;
        }
        let Some(bytes) = pe.rva_bytes(raw, section.virtual_address) else {
            continue;
        };
        let Some(ip) = pe.image_base.checked_add(section.virtual_address as u64) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(pe.arch, bytes, ip, DecoderOptions::NONE);
        while decoder.can_decode() {
            let instr = decoder.decode();
            let Some(start) = u32::try_from(instr.ip().saturating_sub(pe.image_base)).ok() else {
                break;
            };
            let Some(end) = start.checked_add(instr.len() as u32) else {
                break;
            };
            if instr.len() == 0 || end as u64 > section.virtual_address as u64 + bytes.len() as u64
            {
                break;
            }
            if instr.mnemonic() != Mnemonic::INVALID {
                spans.push((start, end));
            }
            primary_count += 1;
            if primary_count > MAX_PRIMARY_INSNS {
                result.truncated = true;
                return result;
            }
            if matches!(
                instr.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) && matches!(
                instr.op0_kind(),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            ) {
                if let Some(target) = branch_rva(pe, instr.near_branch_target()) {
                    branches.push(target);
                }
            }
        }
    }

    spans.sort_unstable_by_key(|span| span.0);
    spans.dedup_by_key(|span| span.0);
    let mut queue = VecDeque::new();
    let mut seeds = HashSet::new();
    for target in branches {
        let position = spans.partition_point(|span| span.0 <= target);
        if let Some(&(start, end)) = position.checked_sub(1).and_then(|index| spans.get(index)) {
            if start < target
                && target < end
                && code_bytes(pe, raw, target).is_some()
                && seeds.insert(target)
            {
                if seeds.len() > MAX_SEAMS {
                    result.truncated = true;
                    break;
                }
                queue.push_back(target);
            }
        }
    }

    let mut visited = HashSet::new();
    while let Some(rva) = queue.pop_front() {
        if !visited.insert(rva) {
            continue;
        }
        if visited.len() > MAX_ALT_INSNS {
            result.truncated = true;
            break;
        }
        // Once the alternate path joins a primary instruction boundary it is
        // covered by the ordinary image-wide scan.
        if spans.binary_search_by_key(&rva, |span| span.0).is_ok() {
            continue;
        }
        let Some(bytes) = code_bytes(pe, raw, rva) else {
            continue;
        };
        let Some(ip) = pe.image_base.checked_add(rva as u64) else {
            continue;
        };
        let mut decoder = Decoder::with_ip(pe.arch, bytes, ip, DecoderOptions::NONE);
        if !decoder.can_decode() {
            continue;
        }
        let instr = decoder.decode();
        if instr.len() == 0 || instr.len() > bytes.len() || instr.mnemonic() == Mnemonic::INVALID {
            continue;
        }
        let flow = instr.flow_control();
        if matches!(
            flow,
            FlowControl::Call
                | FlowControl::IndirectCall
                | FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
        ) {
            let is_jump = matches!(
                flow,
                FlowControl::UnconditionalBranch | FlowControl::IndirectBranch
            );
            let target = match instr.op0_kind() {
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                    branch_rva(pe, instr.near_branch_target()).map(SeamTarget::Direct)
                }
                OpKind::Memory if instr.is_ip_rel_memory_operand() => pe
                    .va_to_rva(instr.ip_rel_memory_address())
                    .filter(|slot| import_slots.contains_key(slot))
                    .map(SeamTarget::ImportSlot),
                OpKind::Memory
                    if instr.memory_base() == Register::None
                        && instr.memory_index() == Register::None =>
                {
                    pe.va_to_rva(instr.memory_displacement64())
                        .filter(|slot| import_slots.contains_key(slot))
                        .map(SeamTarget::ImportSlot)
                }
                _ => None,
            };
            if let Some(target) = target {
                result.calls.push(SeamCall {
                    site_rva: rva,
                    target,
                    is_jump,
                });
            }
        }
        if matches!(
            flow,
            FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
        ) && matches!(
            instr.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        ) {
            if let Some(target) = branch_rva(pe, instr.near_branch_target()) {
                queue.push_back(target);
            }
        }
        if !matches!(
            flow,
            FlowControl::UnconditionalBranch
                | FlowControl::IndirectBranch
                | FlowControl::Return
                | FlowControl::Exception
                | FlowControl::Interrupt
        ) {
            if let Some(next) = rva.checked_add(instr.len() as u32) {
                queue.push_back(next);
            }
        }
    }
    result.calls.sort_by_key(|call| call.site_rva);
    result.calls.dedup_by_key(|call| call.site_rva);
    result
}
