use iced_x86::{Decoder, DecoderOptions, Formatter, Mnemonic, OpKind, Register};
use serde::Serialize;

use crate::formats::pe::{read_clr_info, read_tls_info, resolve_iat_slot, ImportDll, PeFile};

const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorFinding {
    pub category: String,
    pub rule: String,
    pub severity: String,
    pub confidence: String,
    pub source: String,
    pub rva: Option<String>,
    pub detail: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BehaviorReport {
    pub image: String,
    pub finding_count: usize,
    pub findings: Vec<BehaviorFinding>,
}

#[derive(Debug, Clone)]
struct ScannedInsn {
    rva: u32,
    mnemonic: Mnemonic,
    text: String,
    instr: iced_x86::Instruction,
    import_call: Option<(String, String)>,
}

pub fn analyze_image(
    image: &str,
    pe: &PeFile,
    raw: &[u8],
    imports: &[ImportDll],
) -> BehaviorReport {
    let mut findings = Vec::new();
    findings.extend(scan_tls(pe, raw));
    findings.extend(scan_sections(pe));
    findings.extend(scan_imports(imports));

    if let Some(managed_finding) = managed_native_scan_suppression(pe, raw) {
        findings.push(managed_finding);
    } else {
        let insns = scan_executable_instructions(pe, raw);
        findings.extend(scan_instruction_signals(&insns));
        findings.extend(scan_syscall_stubs(&insns));
        findings.extend(scan_medium_clusters(&insns));
    }

    findings = dedup_findings(findings);
    findings.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| a.rva.cmp(&b.rva))
    });

    BehaviorReport {
        image: image.to_owned(),
        finding_count: findings.len(),
        findings,
    }
}

fn managed_native_scan_suppression(pe: &PeFile, raw: &[u8]) -> Option<BehaviorFinding> {
    let clr = read_clr_info(pe, raw)?;
    if pe.entry_point != 0 && (clr.flags & COMIMAGE_FLAGS_ILONLY) == 0 {
        return None;
    }

    let (clr_rva, clr_size) = pe.data_dir(crate::formats::pe::IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    Some(finding(
        "managed-runtime",
        "native-instruction-scan-skipped",
        "low",
        "high",
        "clr-header",
        Some(clr_rva),
        "CLR IL-only image: executable section bytes are CLR header/metadata/IL, not a native entrypoint stream",
        vec![
            format!(
                "CLR directory RVA 0x{:08X} size 0x{:X}; native AddressOfEntryPoint 0x{:08X}",
                clr_rva, clr_size, pe.entry_point
            ),
            format!(
                "CLR flags 0x{:08X}; CLR entry token/RVA 0x{:08X}; metadata RVA 0x{:08X} size 0x{:X}",
                clr.flags, clr.entry_point_token_or_rva, clr.metadata_rva, clr.metadata_size
            ),
            "native behavior disassembly suppressed to avoid false x64 anti-analysis findings over IL metadata"
                .to_owned(),
        ],
    ))
}

fn scan_tls(pe: &PeFile, raw: &[u8]) -> Vec<BehaviorFinding> {
    let mut findings = Vec::new();
    if let Some(tls) = read_tls_info(pe, raw) {
        for callback in tls.callbacks {
            findings.push(finding(
                "loader",
                "tls-callback",
                "medium",
                "high",
                "tls-directory",
                Some(callback.rva),
                "TLS callback is invoked by the loader before the normal entry point",
                vec![format!("callback VA 0x{:016X}", callback.va)],
            ));
        }
    }
    findings
}

fn scan_sections(pe: &PeFile) -> Vec<BehaviorFinding> {
    let mut findings = Vec::new();
    for section in &pe.sections {
        let prot = section.protection_string();
        if prot.contains('W') && prot.contains('X') {
            findings.push(finding(
                "jit-selfmod",
                "writable-executable-section",
                "high",
                "high",
                "section-table",
                Some(section.virtual_address),
                format!("section {} is writable and executable", section.name),
                vec![format!(
                    "section {} RVA 0x{:08X} protection {} entropy {:.2}",
                    section.name, section.virtual_address, prot, section.entropy
                )],
            ));
        } else if section.is_executable() && section.entropy >= 7.15 {
            findings.push(finding(
                "packing-loader",
                "high-entropy-executable-section",
                "medium",
                "medium",
                "section-table",
                Some(section.virtual_address),
                format!("section {} is executable and high entropy", section.name),
                vec![format!("entropy {:.2}", section.entropy)],
            ));
        }
    }
    findings
}

fn scan_imports(imports: &[ImportDll]) -> Vec<BehaviorFinding> {
    let mut findings = Vec::new();
    for dll in imports {
        let dll_lower = dll.dll.to_ascii_lowercase();
        for entry in &dll.entries {
            let name_lower = entry.name.to_ascii_lowercase();
            let full = format!("{}!{}", dll.dll, entry.name);
            if is_loader_api(&dll_lower, &name_lower) {
                findings.push(finding(
                    "loader",
                    "dynamic-loader-api",
                    "medium",
                    "high",
                    "import",
                    Some(entry.slot_rva),
                    "dynamic library or procedure resolution API imported",
                    vec![full.clone()],
                ));
            }
            if is_exec_memory_api(&name_lower) {
                findings.push(finding(
                    "jit-selfmod",
                    "executable-memory-api",
                    "medium",
                    "high",
                    "import",
                    Some(entry.slot_rva),
                    "memory allocation/protection API can support unpacking, JIT, or generated code",
                    vec![full.clone()],
                ));
            }
            if is_write_memory_api(&name_lower) {
                findings.push(finding(
                    "injection-loader",
                    "remote-or-process-memory-write-api",
                    "medium",
                    "high",
                    "import",
                    Some(entry.slot_rva),
                    "process memory write API imported",
                    vec![full.clone()],
                ));
            }
            if is_thread_context_api(&name_lower) {
                findings.push(finding(
                    "anti-debug",
                    "thread-context-api",
                    "low",
                    "medium",
                    "import",
                    Some(entry.slot_rva),
                    "thread context API can be used for trap-flag checks or context manipulation",
                    vec![full.clone()],
                ));
            }
        }
    }
    findings
}

fn scan_executable_instructions(pe: &PeFile, raw: &[u8]) -> Vec<ScannedInsn> {
    let mut out = Vec::new();
    for section in &pe.sections {
        if !section.is_executable() || section.raw_size == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        if start >= raw.len() {
            continue;
        }
        let len = (section.raw_size as usize).min(raw.len().saturating_sub(start));
        let bytes = &raw[start..start + len];
        let ip = pe.image_base + section.virtual_address as u64;
        let mut decoder = Decoder::with_ip(pe.arch, bytes, ip, DecoderOptions::NONE);
        let mut formatter = iced_x86::IntelFormatter::new();
        let mut instr = iced_x86::Instruction::default();
        let mut pos = 0usize;
        while pos < bytes.len() {
            decoder.set_position(pos).ok();
            decoder.set_ip(ip + pos as u64);
            if !decoder.can_decode() {
                break;
            }
            decoder.decode_out(&mut instr);
            let len = instr.len();
            if len == 0 || pos + len > bytes.len() {
                break;
            }
            let rva = section.virtual_address + pos as u32;
            let mut text = String::new();
            formatter.format(&instr, &mut text);
            let import_call = resolve_import_call(pe, raw, &instr);
            out.push(ScannedInsn {
                rva,
                mnemonic: instr.mnemonic(),
                text,
                instr,
                import_call,
            });
            pos += len;
        }
    }
    out
}

fn scan_instruction_signals(insns: &[ScannedInsn]) -> Vec<BehaviorFinding> {
    let mut findings = Vec::new();
    for (idx, insn) in insns.iter().enumerate() {
        let m = insn.mnemonic;
        let m_name = format!("{:?}", m).to_ascii_lowercase();
        if m == Mnemonic::Cpuid {
            findings.push(finding(
                "anti-analysis",
                "cpuid-check",
                "medium",
                "high",
                "instruction",
                Some(insn.rva),
                "CPUID instruction can support VM, CPU, or feature probing",
                vec![insn.text.clone()],
            ));
        }
        if matches!(m, Mnemonic::Rdtsc | Mnemonic::Rdtscp) {
            findings.push(finding(
                "anti-analysis",
                "timing-check",
                "medium",
                "high",
                "instruction",
                Some(insn.rva),
                "timestamp instruction can support debugger, emulator, or VM timing checks",
                vec![insn.text.clone()],
            ));
        }
        if matches!(
            m,
            Mnemonic::Sidt | Mnemonic::Sgdt | Mnemonic::Sldt | Mnemonic::Str
        ) {
            findings.push(finding(
                "anti-analysis",
                "descriptor-table-check",
                "medium",
                "high",
                "instruction",
                Some(insn.rva),
                "descriptor-table instruction can support VM or environment checks",
                vec![insn.text.clone()],
            ));
        }
        if m_name == "icebp" || m == Mnemonic::Int && immediate_value(&insn.instr) == Some(0x2D) {
            findings.push(finding(
                "anti-debug",
                "debug-exception-instruction",
                "medium",
                "high",
                "instruction",
                Some(insn.rva),
                "debug-exception instruction can be used to detect debugger behavior",
                vec![insn.text.clone()],
            ));
        }
        if m == Mnemonic::Int3 && is_isolated_int3(insns, idx) {
            findings.push(finding(
                "anti-debug",
                "int3-breakpoint",
                "low",
                "medium",
                "instruction",
                Some(insn.rva),
                "INT3 breakpoint instruction present in executable code",
                vec![insn.text.clone()],
            ));
        }
        if is_segment_probe(&insn.instr) {
            findings.push(finding(
                "loader-anti-debug",
                "teb-peb-segment-access",
                "medium",
                "medium",
                "instruction",
                Some(insn.rva),
                "FS/GS segment access may indicate TEB/PEB probing or loader-list walking",
                vec![insn.text.clone()],
            ));
        }
        if starts_trap_flag_window(insns, idx) {
            findings.push(finding(
                "anti-debug",
                "trap-flag-manipulation",
                "high",
                "medium",
                "instruction-window",
                Some(insn.rva),
                "flag-register save/restore window may manipulate or inspect the trap flag",
                insns[idx..insns.len().min(idx + 8)]
                    .iter()
                    .map(|item| format!("0x{:08X}: {}", item.rva, item.text))
                    .collect(),
            ));
        }
        if let Some((dll, name)) = &insn.import_call {
            let lower = name.to_ascii_lowercase();
            let dll_lower = dll.to_ascii_lowercase();
            if is_exec_memory_api(&lower) {
                findings.push(finding(
                    "jit-selfmod",
                    "executable-memory-callsite",
                    "medium",
                    "high",
                    "callsite",
                    Some(insn.rva),
                    "code calls memory allocation/protection API",
                    vec![format!(
                        "0x{:08X}: {} -> {}!{}",
                        insn.rva, insn.text, dll, name
                    )],
                ));
            }
            if is_loader_api(&dll_lower, &lower) {
                findings.push(finding(
                    "loader",
                    "dynamic-loader-callsite",
                    "medium",
                    "high",
                    "callsite",
                    Some(insn.rva),
                    "code calls dynamic library or procedure resolution API",
                    vec![format!(
                        "0x{:08X}: {} -> {}!{}",
                        insn.rva, insn.text, dll, name
                    )],
                ));
            }
        }
    }
    findings
}

fn scan_syscall_stubs(insns: &[ScannedInsn]) -> Vec<BehaviorFinding> {
    let mut findings = Vec::new();
    for (idx, insn) in insns.iter().enumerate() {
        if !matches!(
            insn.mnemonic,
            Mnemonic::Syscall | Mnemonic::Sysenter | Mnemonic::Int
        ) {
            continue;
        }
        if insn.mnemonic == Mnemonic::Int && immediate_value(&insn.instr) != Some(0x2E) {
            continue;
        }
        let start = syscall_window_start(insns, idx);
        let window = &insns[start..=idx];
        let has_mov_r10_rcx = window.iter().any(is_mov_r10_rcx);
        let syscall_no = window.iter().rev().find_map(mov_eax_imm);
        let rule = if has_mov_r10_rcx || syscall_no.is_some() {
            "syscall-stub-pattern"
        } else {
            "raw-syscall-instruction"
        };
        let mut evidence = window
            .iter()
            .map(|item| format!("0x{:08X}: {}", item.rva, item.text))
            .collect::<Vec<_>>();
        if let Some(num) = syscall_no {
            evidence.push(format!("service number candidate 0x{:X}", num));
        }
        findings.push(finding(
            "syscall",
            rule,
            if rule == "syscall-stub-pattern" {
                "high"
            } else {
                "medium"
            },
            "high",
            "instruction-window",
            Some(insn.rva),
            "direct syscall-like instruction sequence found in executable code",
            evidence,
        ));
    }
    findings
}

fn scan_medium_clusters(insns: &[ScannedInsn]) -> Vec<BehaviorFinding> {
    let mut findings = Vec::new();
    for (idx, insn) in insns.iter().enumerate() {
        let Some((dll, name)) = &insn.import_call else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if !is_exec_memory_api(&lower) {
            continue;
        }
        let end = insns.len().min(idx + 64);
        let tail = &insns[idx + 1..end];
        let writes_memory = tail.iter().any(|item| is_memory_write(&item.instr));
        let indirect_branch = tail.iter().find(|item| is_indirect_branch(&item.instr));
        if writes_memory || indirect_branch.is_some() {
            let mut evidence = vec![format!(
                "0x{:08X}: {} -> {}!{}",
                insn.rva, insn.text, dll, name
            )];
            if writes_memory {
                evidence
                    .push("nearby memory write observed after executable-memory API".to_owned());
            }
            if let Some(branch) = indirect_branch {
                evidence.push(format!("0x{:08X}: {}", branch.rva, branch.text));
            }
            findings.push(finding(
                "jit-selfmod",
                "executable-memory-to-indirect-flow",
                "high",
                "medium",
                "instruction-window",
                Some(insn.rva),
                "executable-memory API appears near memory writes or indirect control flow",
                evidence,
            ));
        }
    }
    findings
}

fn resolve_import_call(
    pe: &PeFile,
    raw: &[u8],
    instr: &iced_x86::Instruction,
) -> Option<(String, String)> {
    if !matches!(instr.mnemonic(), Mnemonic::Call | Mnemonic::Jmp) || instr.op_count() == 0 {
        return None;
    }
    let slot_va = match instr.op0_kind() {
        OpKind::Memory if matches!(instr.memory_base(), Register::RIP | Register::EIP) => {
            instr.ip_rel_memory_address()
        }
        OpKind::Memory
            if instr.memory_base() == Register::None && instr.memory_index() == Register::None =>
        {
            instr.memory_displacement64()
        }
        _ => 0,
    };
    if slot_va < pe.image_base {
        return None;
    }
    let slot_rva = (slot_va - pe.image_base) as u32;
    resolve_iat_slot(pe, raw, slot_rva)
}

fn is_loader_api(dll: &str, name: &str) -> bool {
    name.contains("loadlibrary")
        || name.contains("getprocaddress")
        || name == "ldrloaddll"
        || name == "ldrgetprocedureaddress"
        || name == "ldrgetdllhandle"
        || (dll.contains("ntdll") && name.starts_with("ldr"))
}

fn syscall_window_start(insns: &[ScannedInsn], idx: usize) -> usize {
    let mut start = idx;
    while start > 0 && idx - start < 8 {
        let prev = &insns[start - 1];
        let cur = &insns[start];
        if prev.rva.saturating_add(prev.instr.len() as u32) != cur.rva {
            break;
        }
        start -= 1;
    }
    start
}

fn is_exec_memory_api(name: &str) -> bool {
    matches!(
        name,
        "virtualalloc"
            | "virtualalloc2"
            | "virtualallocex"
            | "virtualprotect"
            | "virtualprotectex"
            | "ntallocatevirtualmemory"
            | "ntprotectvirtualmemory"
            | "zwallocatevirtualmemory"
            | "zwprotectvirtualmemory"
            | "mapviewoffile"
            | "mapviewoffileex"
            | "createmapping"
            | "createfilemappinga"
            | "createfilemappingw"
            | "flushinstructioncache"
    )
}

fn is_write_memory_api(name: &str) -> bool {
    matches!(
        name,
        "writeprocessmemory" | "ntwritevirtualmemory" | "zwwritevirtualmemory"
    )
}

fn is_thread_context_api(name: &str) -> bool {
    matches!(
        name,
        "getthreadcontext" | "setthreadcontext" | "wow64getthreadcontext" | "wow64setthreadcontext"
    )
}

fn starts_trap_flag_window(insns: &[ScannedInsn], idx: usize) -> bool {
    if !matches!(
        insns[idx].mnemonic,
        Mnemonic::Pushf | Mnemonic::Pushfd | Mnemonic::Pushfq | Mnemonic::Lahf
    ) {
        return false;
    }
    let end = insns.len().min(idx + 8);
    insns[idx + 1..end].iter().any(|item| {
        matches!(
            item.mnemonic,
            Mnemonic::Popf | Mnemonic::Popfd | Mnemonic::Popfq | Mnemonic::Sahf
        )
    })
}

fn is_isolated_int3(insns: &[ScannedInsn], idx: usize) -> bool {
    let prev_is_int3 = idx > 0 && insns[idx - 1].mnemonic == Mnemonic::Int3;
    let next_is_int3 = insns
        .get(idx + 1)
        .is_some_and(|item| item.mnemonic == Mnemonic::Int3);
    !prev_is_int3 && !next_is_int3
}

fn is_segment_probe(instr: &iced_x86::Instruction) -> bool {
    matches!(instr.memory_segment(), Register::FS | Register::GS)
}

fn is_mov_r10_rcx(insn: &ScannedInsn) -> bool {
    insn.mnemonic == Mnemonic::Mov
        && insn.instr.op0_kind() == OpKind::Register
        && insn.instr.op1_kind() == OpKind::Register
        && insn.instr.op0_register().full_register() == Register::R10
        && insn.instr.op1_register().full_register() == Register::RCX
}

fn mov_eax_imm(insn: &ScannedInsn) -> Option<u32> {
    if insn.mnemonic != Mnemonic::Mov
        || insn.instr.op0_kind() != OpKind::Register
        || insn.instr.op0_register().full_register() != Register::RAX
    {
        return None;
    }
    match insn.instr.op1_kind() {
        OpKind::Immediate8 => Some(insn.instr.immediate8() as u32),
        OpKind::Immediate16 => Some(insn.instr.immediate16() as u32),
        OpKind::Immediate32 | OpKind::Immediate32to64 => Some(insn.instr.immediate32()),
        _ => None,
    }
}

fn immediate_value(instr: &iced_x86::Instruction) -> Option<u64> {
    match instr.op0_kind() {
        OpKind::Immediate8 => Some(instr.immediate8() as u64),
        OpKind::Immediate16 => Some(instr.immediate16() as u64),
        OpKind::Immediate32 => Some(instr.immediate32() as u64),
        OpKind::Immediate64 => Some(instr.immediate64()),
        _ => None,
    }
}

fn is_memory_write(instr: &iced_x86::Instruction) -> bool {
    instr.op_count() > 0
        && instr.op0_kind() == OpKind::Memory
        && matches!(
            instr.mnemonic(),
            Mnemonic::Mov
                | Mnemonic::Movnti
                | Mnemonic::Xchg
                | Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::Xor
                | Mnemonic::Or
                | Mnemonic::And
                | Mnemonic::Stosb
                | Mnemonic::Stosd
                | Mnemonic::Stosq
                | Mnemonic::Stosw
        )
}

fn is_indirect_branch(instr: &iced_x86::Instruction) -> bool {
    matches!(instr.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
        && instr.op_count() > 0
        && !matches!(
            instr.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
}

#[allow(clippy::too_many_arguments)]
fn finding(
    category: &str,
    rule: &str,
    severity: &str,
    confidence: &str,
    source: &str,
    rva: Option<u32>,
    detail: impl Into<String>,
    evidence: Vec<String>,
) -> BehaviorFinding {
    BehaviorFinding {
        category: category.to_owned(),
        rule: rule.to_owned(),
        severity: severity.to_owned(),
        confidence: confidence.to_owned(),
        source: source.to_owned(),
        rva: rva.map(|value| format!("0x{:08X}", value)),
        detail: detail.into(),
        evidence,
    }
}

fn dedup_findings(findings: Vec<BehaviorFinding>) -> Vec<BehaviorFinding> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for finding in findings {
        let key = format!(
            "{}|{}|{}|{}",
            finding.category,
            finding.rule,
            finding.rva.as_deref().unwrap_or(""),
            finding.evidence.first().map(String::as_str).unwrap_or("")
        );
        if seen.insert(key) {
            out.push(finding);
        }
    }
    out
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}
