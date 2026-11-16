use iced_x86::{Decoder, DecoderOptions, Formatter, Mnemonic, OpKind, Register};
use serde::Serialize;

use crate::formats::pe::{read_clr_info, ImportDll, PeFile};

use crate::analysis::{image::ImageFacts, session::AnalysisSession};

const COMIMAGE_FLAGS_ILONLY: u32 = 0x0000_0001;
const MAX_SCAN_INSTRUCTIONS: usize = 1_000_000;
const MAX_BEHAVIOR_FINDINGS: usize = 8192;

#[derive(Default)]
struct Findings {
    items: Vec<BehaviorFinding>,
    truncated: bool,
}

impl Findings {
    fn push(&mut self, finding: BehaviorFinding) {
        if self.items.len() < MAX_BEHAVIOR_FINDINGS {
            self.items.push(finding);
        } else {
            self.truncated = true;
        }
    }

    fn merge(&mut self, other: Self) {
        self.truncated |= other.truncated;
        self.extend(other.items);
    }

    fn extend(&mut self, items: impl IntoIterator<Item = BehaviorFinding>) {
        for item in items {
            self.push(item);
        }
    }
}

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
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub analysis_limits: Vec<String>,
    #[serde(skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub api_signatures: std::collections::BTreeMap<u32, crate::analysis::headers::CallSignature>,
    pub image: String,
    pub finding_count: usize,
    pub findings: Vec<BehaviorFinding>,
    /// Dynamic API resolution techniques, most suspicious first.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub api_resolution: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resolved_apis: Vec<crate::analysis::resolution::ResolvedApi>,
}

#[derive(Debug, Clone)]
struct ScannedInsn<'a> {
    rva: u32,
    mnemonic: Mnemonic,
    text: String,
    instr: iced_x86::Instruction,
    import_call: Option<(&'a str, &'a str)>,
}

pub fn analyze_image(
    image: &str,
    pe: &PeFile,
    raw: &[u8],
    imports: &[ImportDll],
) -> BehaviorReport {
    analyze_image_with_headers(image, pe, raw, imports, None)
}

pub use crate::providers::legacy::behavior_with_headers as analyze_image_with_headers;

pub fn analyze_in(
    image: &str,
    session: &AnalysisSession<'_>,
    headers: Option<&crate::analysis::headers::HeaderIndex>,
) -> BehaviorReport {
    analyze_with_context(image, session, session.image().imports(), headers)
}

pub(crate) fn analyze_with_context(
    image: &str,
    session: &AnalysisSession<'_>,
    imports: &[ImportDll],
    headers: Option<&crate::analysis::headers::HeaderIndex>,
) -> BehaviorReport {
    let analysis = session.image();
    let pe = analysis.pe();
    let raw = analysis.raw();
    let mut findings = Findings::default();
    let mut api_signatures = std::collections::BTreeMap::new();
    findings.merge(scan_tls(analysis));
    findings.merge(scan_sections(pe));
    findings.merge(scan_imports(imports));

    let mut analysis_limits = Vec::new();
    let mut resolution = None;
    if let Some(managed_finding) = managed_native_scan_suppression(pe, raw) {
        findings.push(managed_finding);
    } else {
        let (insns, limited) = scan_executable_instructions(analysis, MAX_SCAN_INSTRUCTIONS);
        if limited {
            analysis_limits.push(format!(
                "Native instruction scan stopped at {MAX_SCAN_INSTRUCTIONS} instructions"
            ));
        }
        findings.merge(scan_instruction_signals(&insns));
        findings.merge(scan_syscall_stubs(&insns));
        findings.merge(scan_medium_clusters(&insns));
        let resolved = session.resolution();
        resolution = Some(resolved);
        if let Some(headers) = headers {
            let mut arguments = std::collections::HashMap::new();
            let mut visited = std::collections::HashSet::new();
            for insn in &insns {
                let name = resolved
                    .call_target(insn.rva)
                    .and_then(|api| api.api.as_deref())
                    .or_else(|| insn.import_call.map(|(_, name)| name));
                let Some(prototype) = name.and_then(|name| headers.prototype(name)) else {
                    continue;
                };
                if !arguments.contains_key(&insn.rva) {
                    if let Some(body) = resolved.function_containing(pe, raw, insn.rva) {
                        if body.first().is_some_and(|first| visited.insert(first.ip())) {
                            arguments.extend(crate::analysis::resolution::call_arguments_in(
                                analysis,
                                session.exports(),
                                &body,
                            ));
                        }
                    }
                }
                let mut args = arguments.get(&insn.rva).cloned().unwrap_or_default();
                headers.classify_callbacks(prototype, &mut args, pe, raw);
                api_signatures.insert(
                    insn.rva,
                    crate::analysis::headers::CallSignature {
                        declaration: headers.declaration(prototype),
                        call: headers.render_call(
                            prototype,
                            &args,
                            if pe.machine == 0x014c { 4 } else { 8 },
                        ),
                        source: prototype.header.clone(),
                        arguments: args,
                    },
                );
            }
        }
        findings.extend(resolved.techniques.iter().map(|technique| {
            finding(
                "api-resolution",
                &technique.rule,
                &technique.severity,
                &technique.confidence,
                "dataflow",
                technique.rva,
                technique.detail.clone(),
                technique.evidence.clone(),
            )
        }));
    }

    if findings.truncated {
        analysis_limits.push(format!(
            "Behavior findings limited to {MAX_BEHAVIOR_FINDINGS}"
        ));
    }
    let mut findings = dedup_findings(findings.items);
    findings.sort_by(|a, b| {
        severity_rank(&b.severity)
            .cmp(&severity_rank(&a.severity))
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.rule.cmp(&b.rule))
            .then_with(|| a.rva.cmp(&b.rva))
    });

    BehaviorReport {
        analysis_limits,
        api_signatures,
        image: image.to_owned(),
        finding_count: findings.len(),
        findings,
        api_resolution: resolution.map(|r| r.summary.clone()).unwrap_or_default(),
        resolved_apis: resolution.map(|r| r.resolved.clone()).unwrap_or_default(),
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

fn scan_tls(analysis: &ImageFacts<'_>) -> Findings {
    let mut findings = Findings::default();
    if let Some(tls) = analysis.tls() {
        for callback in &tls.callbacks {
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

fn scan_sections(pe: &PeFile) -> Findings {
    let mut findings = Findings::default();
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

fn scan_imports(imports: &[ImportDll]) -> Findings {
    let mut findings = Findings::default();
    for dll in imports {
        let dll_lower = dll.dll.to_ascii_lowercase();
        for entry in &dll.entries {
            let name_lower = entry.name.to_ascii_lowercase();
            let full = format!("{}!{}", dll.dll, entry.name);
            if apis::is_loader_api(&dll_lower, &name_lower) {
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
            if apis::is_executable_memory_api(&name_lower) {
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
            if apis::is_process_memory_write_api(&name_lower) {
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
            if apis::is_thread_context_api(&name_lower) {
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

fn scan_executable_instructions<'a>(
    analysis: &'a ImageFacts<'_>,
    limit: usize,
) -> (Vec<ScannedInsn<'a>>, bool) {
    let pe = analysis.pe();
    let raw = analysis.raw();
    let mut out = Vec::new();
    if !matches!(pe.machine, 0x014c | 0x8664) {
        return (out, false);
    }
    for section in &pe.sections {
        if !section.is_executable() || section.raw_size == 0 {
            continue;
        }
        let Some(bytes) = pe.rva_bytes(raw, section.virtual_address) else {
            continue;
        };
        let Some(ip) = pe
            .image_base
            .checked_add(u64::from(section.virtual_address))
        else {
            continue;
        };
        let mut decoder = Decoder::with_ip(pe.arch, bytes, ip, DecoderOptions::NONE);
        let mut formatter = iced_x86::IntelFormatter::new();
        while decoder.can_decode() {
            if out.len() >= limit {
                return (out, true);
            }
            let instr = decoder.decode();
            let Some(rva) = instr
                .ip()
                .checked_sub(pe.image_base)
                .and_then(|r| u32::try_from(r).ok())
            else {
                break;
            };
            let mut text = String::new();
            formatter.format(&instr, &mut text);
            let import_call = resolve_import_call(analysis, &instr);
            out.push(ScannedInsn {
                rva,
                mnemonic: instr.mnemonic(),
                text,
                instr,
                import_call,
            });
        }
    }
    (out, false)
}

fn scan_instruction_signals(insns: &[ScannedInsn]) -> Findings {
    let mut findings = Findings::default();
    for (idx, insn) in insns.iter().enumerate() {
        if findings.items.len() >= MAX_BEHAVIOR_FINDINGS {
            findings.truncated = true;
            break;
        }
        let m = insn.mnemonic;

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
        if m == Mnemonic::Int1 || m == Mnemonic::Int && immediate_value(&insn.instr) == Some(0x2D) {
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
            if apis::is_executable_memory_api(&lower) {
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
            if apis::is_loader_api(&dll_lower, &lower) {
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

fn scan_syscall_stubs(insns: &[ScannedInsn]) -> Findings {
    let mut findings = Findings::default();
    for (idx, insn) in insns.iter().enumerate() {
        if findings.items.len() >= MAX_BEHAVIOR_FINDINGS {
            findings.truncated = true;
            break;
        }
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

fn scan_medium_clusters(insns: &[ScannedInsn]) -> Findings {
    let mut findings = Findings::default();
    for (idx, insn) in insns.iter().enumerate() {
        if findings.items.len() >= MAX_BEHAVIOR_FINDINGS {
            findings.truncated = true;
            break;
        }
        let Some((dll, name)) = &insn.import_call else {
            continue;
        };
        let lower = name.to_ascii_lowercase();
        if !apis::is_executable_memory_api(&lower) {
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

fn resolve_import_call<'a>(
    analysis: &'a ImageFacts<'_>,
    instr: &iced_x86::Instruction,
) -> Option<(&'a str, &'a str)> {
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
    let slot_rva = u32::try_from(slot_va.checked_sub(analysis.pe().image_base)?).ok()?;
    analysis.import_at_rva(slot_rva)
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
pub mod apis;
pub mod contract_flows;
pub mod discovery;
pub mod intelli;

#[cfg(test)]
mod instruction_tests {
    use super::*;
    use crate::analysis::image::tests::{image, imported_image};

    #[test]
    fn instruction_budget_is_global_across_aliased_sections() {
        let mut pe = image();
        let raw = vec![0x90; 0x400];
        let mut alias = pe.sections[0].clone();
        alias.virtual_address = 0x2000;
        pe.sections.push(alias);
        let facts = ImageFacts::new(&pe, &raw);
        let (insns, limited) = scan_executable_instructions(&facts, 513);
        assert_eq!(insns.len(), 513);
        assert!(limited);
        assert_eq!(insns[512].rva, 0x2000);
        let (insns, limited) = scan_executable_instructions(&facts, 1024);
        assert_eq!(insns.len(), 1024);
        assert!(!limited);
        pe.sections[1].virtual_address = 0x1000;
        assert!(
            scan_executable_instructions(&ImageFacts::new(&pe, &raw), 1024)
                .0
                .is_empty()
        );
    }

    #[test]
    fn finding_limit_is_reported_and_does_not_grow_with_instruction_count() {
        let mut pe = image();
        pe.sections[0].raw_size = 9000;
        pe.sections[0].virtual_size = 9000;
        let raw = vec![0xf1; 0x200 + 9000];
        let facts = ImageFacts::new(&pe, &raw);
        let (insns, _) = scan_executable_instructions(&facts, 9000);
        let findings = scan_instruction_signals(&insns);
        assert_eq!(findings.items.len(), MAX_BEHAVIOR_FINDINGS);
        assert!(findings.truncated);
        let mut merged = Findings::default();
        merged.merge(findings);
        assert!(merged.truncated);
        assert_eq!(merged.items.len(), MAX_BEHAVIOR_FINDINGS);
    }

    #[test]
    fn debug_exception_detection_uses_decoded_instruction_semantics() {
        let pe = image();
        let mut raw = vec![0x90; 0x400];
        // ICEBP, INT 2D, INT 2E, INT3, NOP.
        raw[0x200..0x207].copy_from_slice(&[0xf1, 0xcd, 0x2d, 0xcd, 0x2e, 0xcc, 0x90]);
        let facts = ImageFacts::new(&pe, &raw);
        let (insns, _) = scan_executable_instructions(&facts, MAX_SCAN_INSTRUCTIONS);
        let findings = scan_instruction_signals(&insns);
        let rvas: Vec<_> = findings
            .items
            .iter()
            .filter(|f| f.rule == "debug-exception-instruction")
            .map(|f| f.rva.as_deref())
            .collect();
        assert_eq!(rvas, [Some("0x00001000"), Some("0x00001001")]);
    }

    #[test]
    fn import_addresses_do_not_wrap_into_an_existing_iat_slot() {
        let (pe, raw) = imported_image();
        let facts = ImageFacts::new(&pe, &raw);
        let mut insn = Decoder::with_ip(
            64,
            &[0xff, 0x15, 0, 0, 0, 0],
            pe.image_base + 0x1000,
            DecoderOptions::NONE,
        )
        .decode();
        insn.set_memory_displacement64(pe.image_base + 0x1160);
        assert_eq!(
            resolve_import_call(&facts, &insn),
            Some(("KERNEL32.dll", "Sleep"))
        );
        insn.set_memory_displacement64(pe.image_base + 0x1_0000_1160);
        assert_eq!(resolve_import_call(&facts, &insn), None);
        insn.set_memory_displacement64(pe.image_base - 1);
        assert_eq!(resolve_import_call(&facts, &insn), None);
    }

    #[test]
    fn imports_in_file_headers_remain_resolvable() {
        let (pe, mut raw) = imported_image();
        raw[0x310..0x314].copy_from_slice(&0x180u32.to_le_bytes());
        raw[0x180..0x188].copy_from_slice(&0x11a0u64.to_le_bytes());
        let facts = ImageFacts::new(&pe, &raw);
        let insn = Decoder::with_ip(
            64,
            &[0xff, 0x15, 0, 0, 0, 0],
            pe.image_base + 0x180 - 6,
            DecoderOptions::NONE,
        )
        .decode();
        assert_eq!(
            resolve_import_call(&facts, &insn),
            Some(("KERNEL32.dll", "Sleep"))
        );
    }
}
