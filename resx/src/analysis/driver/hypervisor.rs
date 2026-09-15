use super::DecodedInsn;
use crate::formats::pe::ImportDll;
use iced_x86::{Mnemonic, OpKind, Register};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
struct IndicatorAccumulator {
    count: usize,
    sites: Vec<HypervisorSite>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HypervisorReport {
    pub classification: String,
    pub confidence: String,
    pub vendors: Vec<String>,
    pub instruction_evidence: Vec<HypervisorIndicator>,
    pub register_evidence: Vec<HypervisorIndicator>,
    pub interface_imports: Vec<HypervisorImport>,
    pub capabilities: Vec<String>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HypervisorIndicator {
    pub vendor: String,
    pub capability: String,
    pub count: usize,
    pub sites: Vec<HypervisorSite>,
}

#[derive(Debug, Clone, Serialize)]
pub struct HypervisorSite {
    pub rva: String,
    pub owner: String,
    pub instruction: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HypervisorImport {
    pub api: String,
    pub capability: String,
    pub slot_rva: String,
}

pub(super) fn analyze(insns: &[DecodedInsn], imports: &[ImportDll]) -> HypervisorReport {
    let mut instructions: BTreeMap<(String, String), IndicatorAccumulator> = BTreeMap::new();
    let mut registers: BTreeMap<(String, String), IndicatorAccumulator> = BTreeMap::new();

    for (index, insn) in insns.iter().enumerate() {
        if let Some((vendor, capability)) = instruction_capability(insn.instr.mnemonic()) {
            push_site(&mut instructions, vendor, capability, insn);
        }
        match insn.instr.mnemonic() {
            Mnemonic::Rdmsr | Mnemonic::Wrmsr => {
                if let Some(msr) = preceding_register_constant(insns, index, Register::RCX) {
                    if let Some((vendor, capability)) = msr_capability(msr) {
                        push_site(&mut registers, vendor, capability, insn);
                    }
                }
            }
            Mnemonic::Cpuid => {
                if let Some(leaf) = preceding_register_constant(insns, index, Register::RAX) {
                    if leaf == 0x8000_000a {
                        push_site(
                            &mut registers,
                            "AMD",
                            "SVM feature and nested-paging capability query",
                            insn,
                        );
                    }
                }
            }
            Mnemonic::Vmread | Mnemonic::Vmwrite => {
                if let Some(field) = vmcs_field_constant(insns, index) {
                    if let Some(capability) = vmcs_field_capability(field) {
                        push_site(&mut registers, "Intel", capability, insn);
                    }
                }
            }
            _ => {}
        }
        if vmcb_nested_paging_signature(insns, index) {
            push_site(
                &mut registers,
                "AMD",
                "nested paging enabled with VMCB NpEnable/NCr3 setup",
                insn,
            );
        }
    }

    detect_slat_hook_machinery(insns, &mut registers);

    let interface_imports = hypervisor_imports(imports);
    let instruction_evidence = finish_indicators(instructions);
    let register_evidence = finish_indicators(registers);
    let mut vendors = BTreeSet::new();
    for evidence in instruction_evidence.iter().chain(&register_evidence) {
        vendors.insert(evidence.vendor.clone());
    }

    let has_amd_launch = has_capability(&instruction_evidence, "AMD", "guest execution (VMRUN)");
    let has_intel_launch = instruction_evidence.iter().any(|item| {
        item.vendor == "Intel"
            && matches!(
                item.capability.as_str(),
                "guest launch (VMLAUNCH)" | "guest resume (VMRESUME)"
            )
    });
    let has_vmxon = has_capability(&instruction_evidence, "Intel", "VMX activation (VMXON)");
    let has_amd_setup = register_evidence.iter().any(|item| {
        item.vendor == "AMD"
            && matches!(
                item.capability.as_str(),
                "SVM host-save area configuration (VM_HSAVE_PA)"
                    | "SVM lock/disable control (VM_CR)"
            )
    });
    let has_only_guest_interface_instructions = !instruction_evidence.is_empty()
        && instruction_evidence.iter().all(|item| {
            matches!(
                item.capability.as_str(),
                "VMX hypercall (VMCALL)"
                    | "SVM hypercall (VMMCALL)"
                    | "SEV-ES guest exit (VMGEXIT)"
            )
        });

    let (classification, confidence) = match (has_amd_launch, has_intel_launch) {
        (true, true) => (
            "mixed AMD SVM and Intel VMX implementation evidence",
            "high",
        ),
        (true, false) => ("AMD SVM hypervisor implementation evidence", "high"),
        (false, true) if has_vmxon => ("Intel VMX hypervisor implementation evidence", "high"),
        (false, true) => ("Intel VMX guest-control implementation evidence", "high"),
        (false, false) if has_vmxon => ("Intel VMX setup evidence", "medium"),
        (false, false) if has_amd_setup => ("AMD SVM setup evidence", "medium"),
        (false, false)
            if has_only_guest_interface_instructions && !interface_imports.is_empty() =>
        {
            (
                "hypervisor interface consumer with direct guest-call stubs",
                "high",
            )
        }
        (false, false) if !instruction_evidence.is_empty() || !register_evidence.is_empty() => {
            ("virtualization instruction or register evidence", "medium")
        }
        (false, false) if !interface_imports.is_empty() => {
            ("hypervisor interface consumer", "medium")
        }
        _ => ("no hypervisor evidence recovered", "none"),
    };

    let mut capabilities = BTreeSet::new();
    for item in instruction_evidence.iter().chain(&register_evidence) {
        capabilities.insert(format!("{}: {}", item.vendor, item.capability));
    }
    for item in &interface_imports {
        capabilities.insert(format!("Interface: {}", item.capability));
    }

    HypervisorReport {
        classification: classification.into(),
        confidence: confidence.into(),
        vendors: vendors.into_iter().collect(),
        instruction_evidence,
        register_evidence,
        interface_imports,
        capabilities: capabilities.into_iter().collect(),
        limitations: vec![
            "Static instruction evidence does not establish successful VM entry, active virtualization, or a resident hypervisor.".into(),
            "Linear decoding is bounded to executable file-backed bytes; isolated encodings can be unreachable data and remain evidence rather than proof.".into(),
            "INVEPT establishes an EPT invalidation operation. AMD NPT is reported only from matching VMCB NpEnable, ASID, and NCr3 stores; active hardware state still requires runtime evidence.".into(),
            "SLAT hook machinery requires correlated fault/violation handling, root selection, and invalidation evidence. Static recovery does not establish that a hook target was configured or active at runtime.".into(),
            "Imported hypervisor APIs establish an interface dependency, not that the driver implements a hypervisor.".into(),
        ],
    }
}

fn push_site(
    map: &mut BTreeMap<(String, String), IndicatorAccumulator>,
    vendor: &str,
    capability: &str,
    insn: &DecodedInsn,
) {
    let item = map.entry((vendor.into(), capability.into())).or_default();
    item.count = item.count.saturating_add(1);
    if item.sites.len() < 32 {
        item.sites.push(HypervisorSite {
            rva: format!("0x{:08X}", insn.rva),
            owner: insn.owner_name.clone(),
            instruction: insn.text.clone(),
        });
    }
}

fn finish_indicators(
    map: BTreeMap<(String, String), IndicatorAccumulator>,
) -> Vec<HypervisorIndicator> {
    map.into_iter()
        .map(|((vendor, capability), item)| HypervisorIndicator {
            vendor,
            capability,
            count: item.count,
            sites: item.sites,
        })
        .collect()
}

fn has_capability(items: &[HypervisorIndicator], vendor: &str, capability: &str) -> bool {
    items
        .iter()
        .any(|item| item.vendor == vendor && item.capability == capability)
}

fn instruction_capability(mnemonic: Mnemonic) -> Option<(&'static str, &'static str)> {
    Some(match mnemonic {
        Mnemonic::Vmxon => ("Intel", "VMX activation (VMXON)"),
        Mnemonic::Vmxoff => ("Intel", "VMX shutdown (VMXOFF)"),
        Mnemonic::Vmclear => ("Intel", "VMCS initialization (VMCLEAR)"),
        Mnemonic::Vmptrld | Mnemonic::Vmptrst => ("Intel", "VMCS pointer management"),
        Mnemonic::Vmread | Mnemonic::Vmwrite => ("Intel", "VMCS field access"),
        Mnemonic::Vmlaunch => ("Intel", "guest launch (VMLAUNCH)"),
        Mnemonic::Vmresume => ("Intel", "guest resume (VMRESUME)"),
        Mnemonic::Invept => ("Intel", "EPT invalidation (INVEPT)"),
        Mnemonic::Invvpid => ("Intel", "VPID invalidation (INVVPID)"),
        Mnemonic::Vmfunc => ("Intel", "VM function switching (VMFUNC)"),
        Mnemonic::Vmcall => ("Intel", "VMX hypercall (VMCALL)"),
        Mnemonic::Vmrun => ("AMD", "guest execution (VMRUN)"),
        Mnemonic::Vmload | Mnemonic::Vmsave => ("AMD", "VMCB host-state transfer"),
        Mnemonic::Clgi | Mnemonic::Stgi => ("AMD", "global interrupt virtualization"),
        Mnemonic::Invlpga | Mnemonic::Invlpgb => ("AMD", "SVM address-space invalidation"),
        Mnemonic::Skinit => ("AMD", "secure virtual-machine initialization"),
        Mnemonic::Vmmcall => ("AMD", "SVM hypercall (VMMCALL)"),
        Mnemonic::Vmgexit => ("AMD", "SEV-ES guest exit (VMGEXIT)"),
        _ => return None,
    })
}

fn msr_capability(msr: u64) -> Option<(&'static str, &'static str)> {
    match msr {
        0x480..=0x491 => Some(("Intel", "VMX capability/control MSR access")),
        0x3a => Some(("Intel", "IA32_FEATURE_CONTROL access")),
        0xc001_0114 => Some(("AMD", "SVM lock/disable control (VM_CR)")),
        0xc001_0117 => Some(("AMD", "SVM host-save area configuration (VM_HSAVE_PA)")),
        _ => None,
    }
}

fn vmcs_field_capability(field: u64) -> Option<&'static str> {
    match field {
        0x201a => Some("EPT pointer access (VMCS EPTP)"),
        0x2400 => Some("EPT violation guest-physical-address recovery"),
        0x6400 => Some("EPT violation qualification recovery"),
        _ => None,
    }
}

fn vmcs_field_constant(insns: &[DecodedInsn], index: usize) -> Option<u64> {
    let instr = &insns.get(index)?.instr;
    let operand = match instr.mnemonic() {
        Mnemonic::Vmread => 1,
        Mnemonic::Vmwrite => 0,
        _ => return None,
    };
    if instr.op_kind(operand) != OpKind::Register {
        return None;
    }
    preceding_register_constant(insns, index, instr.op_register(operand).full_register())
}

fn detect_slat_hook_machinery(
    insns: &[DecodedInsn],
    registers: &mut BTreeMap<(String, String), IndicatorAccumulator>,
) {
    detect_ept_hook_machinery(insns, registers);
    detect_npt_hook_machinery(insns, registers);
}

fn detect_ept_hook_machinery(
    insns: &[DecodedInsn],
    registers: &mut BTreeMap<(String, String), IndicatorAccumulator>,
) {
    let eptp_read = insns.iter().enumerate().find_map(|(index, insn)| {
        (insn.instr.mnemonic() == Mnemonic::Vmread
            && vmcs_field_constant(insns, index) == Some(0x201a))
        .then_some(insn)
    });
    let eptp_write = insns.iter().enumerate().find_map(|(index, insn)| {
        (insn.instr.mnemonic() == Mnemonic::Vmwrite
            && vmcs_field_constant(insns, index) == Some(0x201a))
        .then_some(insn)
    });
    let invept = insns
        .iter()
        .find(|insn| insn.instr.mnemonic() == Mnemonic::Invept);
    let (Some(eptp_read), Some(eptp_write), Some(invept)) = (eptp_read, eptp_write, invept) else {
        return;
    };

    let mut by_owner: BTreeMap<u32, (Option<&DecodedInsn>, Option<&DecodedInsn>)> = BTreeMap::new();
    for (index, insn) in insns.iter().enumerate() {
        match vmcs_field_constant(insns, index) {
            Some(0x2400) => by_owner.entry(insn.owner_rva).or_default().0 = Some(insn),
            Some(0x6400) => by_owner.entry(insn.owner_rva).or_default().1 = Some(insn),
            _ => {}
        }
    }
    for (owner, (gpa, qualification)) in by_owner {
        let (Some(gpa), Some(qualification)) = (gpa, qualification) else {
            continue;
        };
        if !owner_decodes_ept_access(insns, owner) {
            continue;
        }
        let key = (
            "Intel".to_owned(),
            "EPT SLAT hook machinery (violation-driven page remapping)".to_owned(),
        );
        let item = registers.entry(key).or_default();
        for site in [gpa, qualification, eptp_read, eptp_write, invept] {
            append_site(item, site);
        }
    }
}

fn detect_npt_hook_machinery(
    insns: &[DecodedInsn],
    registers: &mut BTreeMap<(String, String), IndicatorAccumulator>,
) {
    let vmrun = insns
        .iter()
        .find(|insn| insn.instr.mnemonic() == Mnemonic::Vmrun);
    let npt_setup = insns
        .iter()
        .enumerate()
        .find_map(|(index, insn)| vmcb_nested_paging_signature(insns, index).then_some(insn));
    let (Some(vmrun), Some(npt_setup)) = (vmrun, npt_setup) else {
        return;
    };
    let Some(ncr3_displacement) = npt_setup.instr.memory_displacement64().checked_add(0x20) else {
        return;
    };

    let mut by_owner: BTreeMap<u32, Vec<&DecodedInsn>> = BTreeMap::new();
    for insn in insns {
        by_owner.entry(insn.owner_rva).or_default().push(insn);
    }
    for owner_insns in by_owner.values() {
        let Some((fault_state, dynamic_ncr3)) =
            npt_fault_remap_sites(owner_insns, ncr3_displacement)
        else {
            continue;
        };
        let key = (
            "AMD".to_owned(),
            "NPT SLAT hook machinery (nested-page-fault-driven page remapping)".to_owned(),
        );
        let item = registers.entry(key).or_default();
        for site in [fault_state, dynamic_ncr3, npt_setup, vmrun] {
            append_site(item, site);
        }
    }
}

fn append_site(item: &mut IndicatorAccumulator, insn: &DecodedInsn) {
    item.count = item.count.saturating_add(1);
    if item.sites.len() < 32
        && !item
            .sites
            .iter()
            .any(|site| site.rva == format!("0x{:08X}", insn.rva))
    {
        item.sites.push(HypervisorSite {
            rva: format!("0x{:08X}", insn.rva),
            owner: insn.owner_name.clone(),
            instruction: insn.text.clone(),
        });
    }
}

fn instruction_has_immediate(instr: &iced_x86::Instruction, value: u64) -> bool {
    (0..instr.op_count()).any(|operand| immediate(instr, operand) == Some(value))
}

fn owner_decodes_ept_access(insns: &[DecodedInsn], owner: u32) -> bool {
    let owner_insns = insns.iter().filter(|insn| insn.owner_rva == owner);
    let mut page_aligned_gpa = false;
    let mut write_bit = false;
    let mut execute_bit = false;
    for insn in owner_insns {
        let instr = &insn.instr;
        page_aligned_gpa |= instruction_has_immediate(instr, 0xffff_ffff_ffff_f000);
        write_bit |= instr.mnemonic() == Mnemonic::Shr && instruction_has_immediate(instr, 1);
        execute_bit |= instr.mnemonic() == Mnemonic::Shr && instruction_has_immediate(instr, 2);
    }
    page_aligned_gpa && write_bit && execute_bit
}

fn npt_fault_remap_sites<'a>(
    insns: &[&'a DecodedInsn],
    ncr3_displacement: u64,
) -> Option<(&'a DecodedInsn, &'a DecodedInsn)> {
    let mut by_displacement: BTreeMap<u64, &'a DecodedInsn> = BTreeMap::new();
    let mut page_aligned_gpa = false;
    let mut write_bit = false;
    let mut execute_bit = false;
    for insn in insns {
        let instr = &insn.instr;
        if instr.op_kinds().any(|kind| kind == OpKind::Memory) {
            by_displacement
                .entry(instr.memory_displacement64())
                .or_insert(insn);
        }
        page_aligned_gpa |= instruction_has_immediate(instr, 0xffff_ffff_ffff_f000);
        write_bit |= instr.mnemonic() == Mnemonic::And && instruction_has_immediate(instr, 2);
        execute_bit |= instr.mnemonic() == Mnemonic::And && instruction_has_immediate(instr, 0x10);
    }
    if !page_aligned_gpa || !write_bit || !execute_bit {
        return None;
    }
    let dynamic_ncr3 = *by_displacement.get(&ncr3_displacement)?;
    let exit_info1 = ncr3_displacement.checked_sub(0x38)?;
    let exit_info2 = exit_info1.checked_add(8)?;
    let fault_state = *by_displacement.get(&exit_info1)?;
    by_displacement.get(&exit_info2)?;
    Some((fault_state, dynamic_ncr3))
}

fn preceding_register_constant(
    insns: &[DecodedInsn],
    index: usize,
    register: Register,
) -> Option<u64> {
    let owner = insns.get(index)?.owner_rva;
    for candidate in insns[index.saturating_sub(12)..index].iter().rev() {
        if candidate.owner_rva != owner {
            break;
        }
        let instr = &candidate.instr;
        if instr.op_count() == 0
            || instr.op0_kind() != OpKind::Register
            || instr.op0_register().full_register() != register
        {
            continue;
        }
        if instr.mnemonic() != Mnemonic::Mov || instr.op_count() < 2 {
            return None;
        }
        return immediate(instr, 1);
    }
    None
}

fn vmcb_nested_paging_signature(insns: &[DecodedInsn], index: usize) -> bool {
    let Some(candidate) = insns.get(index) else {
        return false;
    };
    let instr = &candidate.instr;
    if instr.mnemonic() != Mnemonic::Or
        || instr.op_count() < 2
        || instr.op0_kind() != OpKind::Memory
        || immediate(instr, 1) != Some(1)
    {
        return false;
    }
    let base = instr.memory_base().full_register();
    if base == Register::None {
        return false;
    }
    let np_enable = instr.memory_displacement64();
    if np_enable < 0x90 {
        return false;
    }
    let Some(asid) = np_enable.checked_sub(0x38) else {
        return false;
    };
    let Some(ncr3) = np_enable.checked_add(0x20) else {
        return false;
    };
    let owner = candidate.owner_rva;
    let start = index.saturating_sub(48);
    let end = (index + 49).min(insns.len());
    let mut has_asid = false;
    let mut has_ncr3 = false;
    for nearby in &insns[start..end] {
        if nearby.owner_rva != owner {
            continue;
        }
        let nearby = &nearby.instr;
        if nearby.mnemonic() != Mnemonic::Mov
            || nearby.op_count() < 2
            || nearby.op0_kind() != OpKind::Memory
            || nearby.memory_base().full_register() != base
        {
            continue;
        }
        let displacement = nearby.memory_displacement64();
        has_asid |= displacement == asid && immediate(nearby, 1) == Some(1);
        has_ncr3 |=
            displacement == ncr3 && matches!(nearby.op1_kind(), OpKind::Register | OpKind::Memory);
    }
    has_asid && has_ncr3
}

fn immediate(instr: &iced_x86::Instruction, operand: u32) -> Option<u64> {
    match instr.op_kind(operand) {
        OpKind::Immediate8 => Some(u64::from(instr.immediate8())),
        OpKind::Immediate16 => Some(u64::from(instr.immediate16())),
        OpKind::Immediate32 => Some(u64::from(instr.immediate32())),
        OpKind::Immediate64 => Some(instr.immediate64()),
        OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
            Some(instr.immediate8to64() as u64)
        }
        OpKind::Immediate32to64 => Some(instr.immediate32to64() as u64),
        _ => None,
    }
}

fn hypervisor_imports(imports: &[ImportDll]) -> Vec<HypervisorImport> {
    let mut out = Vec::new();
    for dll in imports {
        for entry in &dll.entries {
            let lower = entry.name.to_ascii_lowercase();
            let capability = if lower.starts_with("hvl") || lower.contains("hypercall") {
                Some("kernel hypervisor/hypercall interface")
            } else if lower.starts_with("vid") {
                Some("Windows virtualization infrastructure driver interface")
            } else if lower.starts_with("winhv") || lower.starts_with("whv") {
                Some("Windows Hypervisor Platform interface")
            } else if lower.starts_with("vsl") {
                Some("virtual secure mode interface")
            } else {
                None
            };
            if let Some(capability) = capability {
                out.push(HypervisorImport {
                    api: format!("{}!{}", dll.dll, entry.name),
                    capability: capability.into(),
                    slot_rva: format!("0x{:08X}", entry.slot_rva),
                });
            }
        }
    }
    out.sort_by(|left, right| left.api.cmp(&right.api));
    out.dedup_by(|left, right| left.api == right.api && left.slot_rva == right.slot_rva);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use iced_x86::{Decoder, DecoderOptions};

    fn decode(bytes: &[u8], owner_rva: u32) -> Vec<DecodedInsn> {
        let mut decoder = Decoder::with_ip(
            64,
            bytes,
            0x140000000 + u64::from(owner_rva),
            DecoderOptions::NONE,
        );
        let mut insns = Vec::new();
        while decoder.can_decode() {
            let instr = decoder.decode();
            insns.push(DecodedInsn {
                rva: (instr.ip() - 0x140000000) as u32,
                text: format!("{:?}", instr.mnemonic()),
                instr,
                owner_rva,
                owner_name: format!("sub_{owner_rva:08X}"),
            });
        }
        insns
    }

    #[test]
    fn privileged_instruction_families_are_vendor_specific() {
        assert_eq!(
            instruction_capability(Mnemonic::Vmrun),
            Some(("AMD", "guest execution (VMRUN)"))
        );
        assert_eq!(
            instruction_capability(Mnemonic::Invept),
            Some(("Intel", "EPT invalidation (INVEPT)"))
        );
        assert_eq!(instruction_capability(Mnemonic::Cpuid), None);
    }

    #[test]
    fn only_virtualization_specific_msrs_are_classified() {
        assert!(msr_capability(0xc001_0117).is_some());
        assert!(msr_capability(0x480).is_some());
        assert!(msr_capability(0xc000_0080).is_none());
    }

    #[test]
    fn npt_requires_np_enable_asid_and_ncr3_vmcb_fields() {
        let bytes = [
            0x49, 0x83, 0x8d, 0x90, 0x60, 0x00, 0x00, 0x01, // or [r13+6090h],1
            0x41, 0xc7, 0x85, 0x58, 0x60, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // ASID
            0x49, 0x89, 0x9d, 0xb0, 0x60, 0x00, 0x00, // NCr3
        ];
        let mut decoder = Decoder::with_ip(64, &bytes, 0x140001000, DecoderOptions::NONE);
        let mut insns = Vec::new();
        while decoder.can_decode() {
            let instr = decoder.decode();
            insns.push(DecodedInsn {
                rva: (instr.ip() - 0x140000000) as u32,
                text: String::new(),
                instr,
                owner_rva: 0x1000,
                owner_name: "prepare_vmcb".into(),
            });
        }
        assert!(vmcb_nested_paging_signature(&insns, 0));
        insns[2].owner_rva = 0x2000;
        assert!(!vmcb_nested_paging_signature(&insns, 0));
    }

    #[test]
    fn ept_hook_machinery_requires_fault_state_root_switching_and_invalidation() {
        let bytes = [
            0xb8, 0x00, 0x24, 0x00, 0x00, // mov eax,2400h
            0x41, 0x0f, 0x78, 0xc1, // vmread r9,rax
            0xb8, 0x00, 0x64, 0x00, 0x00, // mov eax,6400h
            0x41, 0x0f, 0x78, 0xc0, // vmread r8,rax
            0x48, 0xc7, 0xc0, 0x00, 0xf0, 0xff, 0xff, // mov rax,-1000h
            0x4c, 0x23, 0xc8, // and r9,rax
            0x41, 0xd0, 0xee, // shr r14b,1
            0x40, 0xc0, 0xee, 0x02, // shr sil,2
            0x41, 0xb8, 0x1a, 0x20, 0x00, 0x00, // mov r8d,201ah
            0x44, 0x0f, 0x78, 0xc2, // vmread rdx,r8
            0x44, 0x0f, 0x79, 0xc3, // vmwrite r8,rbx
            0x66, 0x0f, 0x38, 0x80, 0x0a, // invept rcx,[rdx]
        ];
        let insns = decode(&bytes, 0x1000);
        let report = analyze(&insns, &[]);
        assert!(report
            .register_evidence
            .iter()
            .any(|item| item.capability.starts_with("EPT SLAT hook machinery")));

        let without_dynamic_root_write: Vec<_> = insns
            .into_iter()
            .filter(|insn| insn.instr.mnemonic() != Mnemonic::Vmwrite)
            .collect();
        let report = analyze(&without_dynamic_root_write, &[]);
        assert!(!report
            .register_evidence
            .iter()
            .any(|item| item.capability.starts_with("EPT SLAT hook machinery")));
    }

    #[test]
    fn npt_hook_machinery_requires_npf_state_and_dynamic_ncr3_selection() {
        let fault_bytes = [
            0x4c, 0x8b, 0x81, 0x78, 0x60, 0x00, 0x00, // mov r8,[rcx+6078h]
            0x4c, 0x8b, 0x91, 0x80, 0x60, 0x00, 0x00, // mov r10,[rcx+6080h]
            0x49, 0x8b, 0xd0, 0x83, 0xe2, 0x02, // test NPF write bit
            0x49, 0x8b, 0xc0, 0x83, 0xe0, 0x10, // test NPF execute bit
            0x48, 0x8b, 0xf2, // mov rsi,rdx
            0x48, 0xc7, 0xc0, 0x00, 0xf0, 0xff, 0xff, // mov rax,-1000h
            0x48, 0x23, 0xf0, // and rsi,rax
            0x48, 0x39, 0x85, 0xb0, 0x60, 0x00, 0x00, // cmp [rbp+60B0h],rax
        ];
        let setup_bytes = [
            0x49, 0x83, 0x8d, 0x90, 0x60, 0x00, 0x00, 0x01, 0x41, 0xc7, 0x85, 0x58, 0x60, 0x00,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x49, 0x89, 0x9d, 0xb0, 0x60, 0x00, 0x00,
        ];
        let mut insns = decode(&fault_bytes, 0x2000);
        insns.extend(decode(&setup_bytes, 0x3000));
        insns.extend(decode(&[0x0f, 0x01, 0xd8], 0x4000)); // vmrun rax
        let report = analyze(&insns, &[]);
        assert!(report
            .register_evidence
            .iter()
            .any(|item| item.capability.starts_with("NPT SLAT hook machinery")));

        insns.retain(|insn| {
            insn.owner_rva != 0x2000 || insn.instr.memory_displacement64() != 0x60b0
        });
        let report = analyze(&insns, &[]);
        assert!(!report
            .register_evidence
            .iter()
            .any(|item| item.capability.starts_with("NPT SLAT hook machinery")));
    }
}
