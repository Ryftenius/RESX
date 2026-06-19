use std::collections::BTreeSet;

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Mnemonic, OpKind, Register};
use serde::Serialize;

use crate::formats::pe::{ImportDll, PeFile};

#[derive(Debug, Clone, Serialize)]
pub struct UnpackReport {
    pub image: String,
    pub mode: String,
    pub summary: String,
    pub protector_hints: Vec<UnpackFinding>,
    pub oep_candidates: Vec<OepCandidate>,
    pub import_rebuild_hints: Vec<UnpackFinding>,
    pub vm_candidates: Vec<VmCandidate>,
    pub layer2: UnpackLayer2,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnpackFinding {
    pub rule: String,
    pub confidence: String,
    pub detail: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct OepCandidate {
    pub rva: String,
    pub confidence: String,
    pub reason: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VmCandidate {
    pub rva: String,
    pub confidence: String,
    pub kind: String,
    pub reason: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct UnpackLayer2 {
    pub oep_windows: Vec<CodeWindow>,
    pub import_plan: Vec<ImportRebuildCandidate>,
    pub vm_sketches: Vec<VmSketch>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeWindow {
    pub rva: String,
    pub section: String,
    pub bytes_hex: String,
    pub instructions: Vec<String>,
    pub control_flow: Vec<String>,
    pub data_refs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ImportRebuildCandidate {
    pub dll: String,
    pub api: String,
    pub source: String,
    pub confidence: String,
    pub evidence: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VmSketch {
    pub rva: String,
    pub kind: String,
    pub score: u32,
    pub registers: Vec<String>,
    pub mnemonics: Vec<String>,
    pub instructions: Vec<String>,
    pub next_action: String,
}

#[derive(Debug, Default)]
struct SectionSignal {
    exec_count: usize,
    high_entropy_exec: usize,
    writable_exec: usize,
}

#[derive(Debug, Default)]
struct CodeSignal {
    indirect_branches: Vec<u32>,
    push_pop_density: Vec<u32>,
    cpuid_or_timing: Vec<u32>,
}

pub fn analyze_image(image: &str, pe: &PeFile, raw: &[u8], imports: &[ImportDll]) -> UnpackReport {
    let strings = collect_strings(raw, 6, 8192);
    let section_signal = section_signals(pe);
    let code_signal = code_signals(pe, raw);

    let protector_hints = protector_hints(pe, imports, &strings, &section_signal, &code_signal);
    let oep_candidates = oep_candidates(pe, &section_signal, &code_signal);
    let import_rebuild_hints = import_rebuild_hints(imports, &strings);
    let vm_candidates = vm_candidates(pe, &strings, &section_signal, &code_signal);
    let layer2 = layer2(pe, raw, imports, &strings, &oep_candidates, &vm_candidates);
    let next_steps = next_steps(&oep_candidates, &vm_candidates);
    let summary = summarize(
        &protector_hints,
        &oep_candidates,
        &import_rebuild_hints,
        &vm_candidates,
    );

    UnpackReport {
        image: image.to_owned(),
        mode: "static-unpack-triage".to_owned(),
        summary,
        protector_hints,
        oep_candidates,
        import_rebuild_hints,
        vm_candidates,
        layer2,
        next_steps,
    }
}

fn protector_hints(
    pe: &PeFile,
    imports: &[ImportDll],
    strings: &[String],
    section_signal: &SectionSignal,
    code_signal: &CodeSignal,
) -> Vec<UnpackFinding> {
    let mut out = Vec::new();
    let lower_strings = strings
        .iter()
        .map(|s| s.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let section_names = pe
        .sections
        .iter()
        .map(|section| section.name.to_ascii_lowercase())
        .collect::<Vec<_>>();

    if section_names.iter().any(|s| s == "upx0" || s == "upx1")
        || lower_strings.iter().any(|s| s.contains("upx!"))
    {
        out.push(finding(
            "upx-marker",
            "high",
            "UPX section names or strings detected",
            vec!["UPX0/UPX1/upx! marker".to_owned()],
        ));
    }
    if section_names
        .iter()
        .any(|s| s.contains("vmp") || s.contains("themida"))
        || lower_strings
            .iter()
            .any(|s| s.contains("vmprotect") || s.contains("themida"))
    {
        out.push(finding(
            "vmprotect-themida-marker",
            "high",
            "VMProtect/Themida style markers detected",
            vec!["section/string marker".to_owned()],
        ));
    }
    if section_names
        .iter()
        .any(|s| s.contains("enigma") || s.contains("aspack") || s.contains("mpress"))
    {
        out.push(finding(
            "known-packer-section",
            "high",
            "known packer/protector section name detected",
            section_names
                .iter()
                .filter(|s| s.contains("enigma") || s.contains("aspack") || s.contains("mpress"))
                .cloned()
                .collect(),
        ));
    }

    if section_signal.high_entropy_exec > 0 {
        out.push(finding(
            "high-entropy-exec",
            "medium",
            "executable sections with high entropy may contain packed or virtualized code",
            vec![format!(
                "{} executable section(s) over entropy threshold",
                section_signal.high_entropy_exec
            )],
        ));
    }
    if section_signal.writable_exec > 0 {
        out.push(finding(
            "writable-executable",
            "medium",
            "writable executable sections can support unpacking or self-modifying code",
            vec![format!(
                "{} writable executable section(s)",
                section_signal.writable_exec
            )],
        ));
    }

    let import_count: usize = imports.iter().map(|dll| dll.entries.len()).sum();
    if import_count <= 12 && section_signal.exec_count > 0 && section_signal.high_entropy_exec > 0 {
        out.push(finding(
            "sparse-import-surface",
            "medium",
            "sparse imports plus high-entropy executable code is common in packed images",
            vec![format!("{} imports", import_count)],
        ));
    }
    if !code_signal.cpuid_or_timing.is_empty() {
        out.push(finding(
            "anti-analysis-instructions",
            "medium",
            "CPUID/timing instructions may indicate protector anti-analysis checks",
            code_signal
                .cpuid_or_timing
                .iter()
                .take(8)
                .map(|rva| format!("0x{rva:08X}"))
                .collect(),
        ));
    }
    out
}

fn oep_candidates(
    pe: &PeFile,
    section_signal: &SectionSignal,
    code_signal: &CodeSignal,
) -> Vec<OepCandidate> {
    let mut out = Vec::new();
    if pe.entry_point != 0 {
        let mut evidence = vec![format!("AddressOfEntryPoint 0x{:08X}", pe.entry_point)];
        let confidence = if let Some(section) = pe.rva_to_section(pe.entry_point) {
            evidence.push(format!(
                "entry section {} protection {} entropy {:.2}",
                section.name,
                section.protection_string(),
                section.entropy
            ));
            if section.entropy >= 7.15 || section.protection_string().contains('W') {
                "medium"
            } else {
                "high"
            }
        } else {
            "low"
        };
        out.push(OepCandidate {
            rva: format!("0x{:08X}", pe.entry_point),
            confidence: confidence.to_owned(),
            reason: "PE entry point is the first loader-visible execution root".to_owned(),
            evidence,
        });
    }

    for section in pe.sections.iter().filter(|section| section.is_executable()) {
        if section.virtual_address == pe.entry_point {
            continue;
        }
        if (section_signal.high_entropy_exec > 0 || section_signal.writable_exec > 0)
            && section.entropy < 7.15
            && section.raw_size > 0
        {
            out.push(OepCandidate {
                rva: format!("0x{:08X}", section.virtual_address),
                confidence: if section_signal.high_entropy_exec > 0 {
                    "medium"
                } else {
                    "low"
                }
                .to_owned(),
                reason: "start of lower-entropy executable section after possible unpacking stub"
                    .to_owned(),
                evidence: vec![format!(
                    "section {} protection {} entropy {:.2}",
                    section.name,
                    section.protection_string(),
                    section.entropy
                )],
            });
        }
    }

    if section_signal.high_entropy_exec > 0 || section_signal.writable_exec > 0 {
        for rva in code_signal.indirect_branches.iter().take(8) {
            out.push(OepCandidate {
                rva: format!("0x{rva:08X}"),
                confidence: "low".to_owned(),
                reason: "indirect branch site can be an unpacking handoff candidate".to_owned(),
                evidence: vec![
                    "review surrounding writes/protection changes before this branch".to_owned(),
                ],
            });
        }
    }

    out.truncate(16);
    out
}

fn import_rebuild_hints(imports: &[ImportDll], strings: &[String]) -> Vec<UnpackFinding> {
    let mut out = Vec::new();
    let import_names = imports
        .iter()
        .flat_map(|dll| {
            dll.entries
                .iter()
                .map(|entry| entry.name.to_ascii_lowercase())
        })
        .collect::<Vec<_>>();
    for names in [
        (
            "dynamic-loader",
            ["loadlibrary", "getprocaddress", "ldrloaddll"],
        ),
        (
            "memory-protection",
            [
                "virtualprotect",
                "ntprotectvirtualmemory",
                "flushinstructioncache",
            ],
        ),
        (
            "memory-allocation",
            ["virtualalloc", "ntallocatevirtualmemory", "mapviewoffile"],
        ),
    ] {
        let hits = import_names
            .iter()
            .filter(|name| names.1.iter().any(|needle| name.contains(needle)))
            .take(8)
            .cloned()
            .collect::<Vec<_>>();
        if !hits.is_empty() {
            out.push(finding(
                names.0,
                "high",
                "imports suggest runtime import resolution or unpacked-code setup",
                hits,
            ));
        }
    }

    let string_hits = strings
        .iter()
        .filter(|s| {
            s.contains(".dll")
                || s.contains(".DLL")
                || s.contains("kernel32")
                || s.contains("ntdll")
                || s.contains("GetProcAddress")
        })
        .take(10)
        .cloned()
        .collect::<Vec<_>>();
    if !string_hits.is_empty() {
        out.push(finding(
            "import-name-strings",
            "medium",
            "DLL/API strings can help rebuild a runtime-resolved import table",
            string_hits,
        ));
    }

    out
}

fn vm_candidates(
    pe: &PeFile,
    strings: &[String],
    section_signal: &SectionSignal,
    code_signal: &CodeSignal,
) -> Vec<VmCandidate> {
    let mut out = Vec::new();
    let has_vm_strings = strings.iter().any(|s| {
        let lower = s.to_ascii_lowercase();
        lower.contains("vmprotect")
            || lower.contains("themida")
            || lower.contains("virtual machine")
    });
    if has_vm_strings {
        out.push(VmCandidate {
            rva: format!("0x{:08X}", pe.entry_point),
            confidence: "medium".to_owned(),
            kind: "protector-marker".to_owned(),
            reason: "protector strings suggest virtualized code may be present".to_owned(),
            evidence: vec!["VMProtect/Themida/virtual machine string marker".to_owned()],
        });
    }

    let protected_context =
        has_vm_strings || section_signal.high_entropy_exec > 0 || section_signal.writable_exec > 0;
    if protected_context {
        for rva in code_signal.indirect_branches.iter().take(12) {
            out.push(VmCandidate {
                rva: format!("0x{rva:08X}"),
                confidence: "low".to_owned(),
                kind: "dispatcher-or-handler-edge".to_owned(),
                reason:
                    "indirect branch can be a VM dispatcher, handler transition, or opaque dispatch edge"
                        .to_owned(),
                evidence: vec!["trace surrounding block and classify register state".to_owned()],
            });
        }

        for rva in code_signal.push_pop_density.iter().take(8) {
            out.push(VmCandidate {
                rva: format!("0x{rva:08X}"),
                confidence: "low".to_owned(),
                kind: "stack-vm-candidate".to_owned(),
                reason: "dense push/pop window can indicate stack-machine style handlers"
                    .to_owned(),
                evidence: vec!["review local instruction window for handler semantics".to_owned()],
            });
        }
    }

    out.truncate(24);
    out
}

fn next_steps(oep: &[OepCandidate], vm: &[VmCandidate]) -> Vec<String> {
    let mut steps = Vec::new();
    if let Some(first) = oep.first() {
        steps.push(format!(
            "resx dump <image> --at {} --hostile --funcs --strings",
            first.rva
        ));
    }
    if let Some(first) = vm.first() {
        steps.push(format!(
            "resx cfg <image> --at {} --hostile --max-insns 1200",
            first.rva
        ));
    }
    steps.push("Use a sandbox/debugger snapshot at the unpacking handoff to dump the mapped image; RESX currently reports static candidates, not a rebuilt binary.".to_owned());
    steps.push("For VM lifting, start with dispatcher/handler candidates and build handler semantics from bounded traces.".to_owned());
    steps
}

fn summarize(
    protector: &[UnpackFinding],
    oep: &[OepCandidate],
    imports: &[UnpackFinding],
    vm: &[VmCandidate],
) -> String {
    format!(
        "{} protector hint(s), {} OEP candidate(s), {} import-rebuild hint(s), {} VM candidate(s)",
        protector.len(),
        oep.len(),
        imports.len(),
        vm.len()
    )
}

fn layer2(
    pe: &PeFile,
    raw: &[u8],
    imports: &[ImportDll],
    strings: &[String],
    oep: &[OepCandidate],
    vm: &[VmCandidate],
) -> UnpackLayer2 {
    let oep_windows = oep
        .iter()
        .filter_map(|candidate| parse_rva(&candidate.rva))
        .take(8)
        .filter_map(|rva| code_window(pe, raw, rva, 24, 192))
        .collect::<Vec<_>>();
    let import_plan = import_plan(imports, strings);
    let vm_sketches = vm
        .iter()
        .filter_map(|candidate| parse_rva(&candidate.rva).map(|rva| (candidate, rva)))
        .take(12)
        .filter_map(|(candidate, rva)| vm_sketch(pe, raw, candidate, rva))
        .collect::<Vec<_>>();

    let mut notes = vec![
        "layer2 is still offline/static: it extracts review windows and rebuild/lift leads without executing the target".to_owned(),
        "use oep_windows as debugger breakpoints or dump pivots; use vm_sketches as dispatcher/handler triage seeds".to_owned(),
    ];
    if import_plan.is_empty() {
        notes.push(
            "no obvious runtime import rebuild APIs or DLL/API strings were found".to_owned(),
        );
    }

    UnpackLayer2 {
        oep_windows,
        import_plan,
        vm_sketches,
        notes,
    }
}

fn code_window(
    pe: &PeFile,
    raw: &[u8],
    rva: u32,
    max_insns: usize,
    max_bytes: usize,
) -> Option<CodeWindow> {
    let section = pe.rva_to_section(rva)?;
    let file_off = pe.rva_to_offset(rva)?;
    if file_off >= raw.len() {
        return None;
    }
    let section_end_rva = section
        .virtual_address
        .saturating_add(section.virtual_size.max(section.raw_size));
    let section_remaining = section_end_rva.saturating_sub(rva) as usize;
    let decode_len = max_bytes
        .min(section_remaining)
        .min(raw.len().saturating_sub(file_off));
    if decode_len == 0 {
        return None;
    }

    let bytes = &raw[file_off..file_off + decode_len];
    let ip = pe.image_base + rva as u64;
    let mut decoder = Decoder::with_ip(pe.arch, bytes, ip, DecoderOptions::NONE);
    let mut fmt = IntelFormatter::new();
    let mut instructions = Vec::new();
    let mut control_flow = Vec::new();
    let mut data_ref_set = BTreeSet::new();
    let mut consumed = 0usize;

    while decoder.can_decode() && instructions.len() < max_insns {
        let instr = decoder.decode();
        if instr.len() == 0 {
            break;
        }
        consumed = consumed.saturating_add(instr.len());
        let instr_rva = instr.ip().wrapping_sub(pe.image_base) as u32;
        let mut text = String::new();
        fmt.format(&instr, &mut text);
        instructions.push(format!("0x{instr_rva:08X}: {text}"));

        let mnemonic = instr.mnemonic();
        if matches!(mnemonic, Mnemonic::Call | Mnemonic::Jmp) || is_conditional_branch(mnemonic) {
            control_flow.push(format!("0x{instr_rva:08X}: {text}"));
        }
        for addr in data_refs(&instr) {
            if let Some(data_rva) = pe.va_to_rva(addr) {
                data_ref_set.insert(format!("0x{data_rva:08X}"));
            }
        }
        if matches!(mnemonic, Mnemonic::Ret | Mnemonic::Retf) {
            break;
        }
    }

    let bytes_hex = raw[file_off..file_off + consumed.min(decode_len)]
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(" ");

    Some(CodeWindow {
        rva: format!("0x{rva:08X}"),
        section: section.name.clone(),
        bytes_hex,
        instructions,
        control_flow,
        data_refs: data_ref_set.into_iter().collect(),
    })
}

fn import_plan(imports: &[ImportDll], strings: &[String]) -> Vec<ImportRebuildCandidate> {
    let mut out = Vec::new();
    for dll in imports {
        for entry in &dll.entries {
            let lower = entry.name.to_ascii_lowercase();
            let source = if lower.contains("getprocaddress") || lower.contains("ldrgetprocedure") {
                "resolver-api"
            } else if lower.contains("loadlibrary") || lower.contains("ldrloaddll") {
                "loader-api"
            } else if lower.contains("virtualprotect")
                || lower.contains("ntprotectvirtualmemory")
                || lower.contains("flushinstructioncache")
            {
                "code-activation-api"
            } else if lower.contains("virtualalloc")
                || lower.contains("ntallocatevirtualmemory")
                || lower.contains("mapviewoffile")
            {
                "mapped-code-api"
            } else {
                continue;
            };
            out.push(ImportRebuildCandidate {
                dll: dll.dll.clone(),
                api: entry.name.clone(),
                source: source.to_owned(),
                confidence: "high".to_owned(),
                evidence: vec![format!("IAT slot RVA 0x{:08X}", entry.slot_rva)],
            });
        }
    }

    for s in strings.iter().take(8192) {
        let lower = s.to_ascii_lowercase();
        if lower.ends_with(".dll") || lower.contains(".dll") {
            out.push(ImportRebuildCandidate {
                dll: s.clone(),
                api: String::new(),
                source: "embedded-dll-string".to_owned(),
                confidence: "medium".to_owned(),
                evidence: vec!["candidate DLL name string".to_owned()],
            });
        } else if looks_like_api_name(s) {
            out.push(ImportRebuildCandidate {
                dll: String::new(),
                api: s.clone(),
                source: "embedded-api-string".to_owned(),
                confidence: "low".to_owned(),
                evidence: vec!["candidate API name string".to_owned()],
            });
        }
        if out.len() >= 48 {
            break;
        }
    }

    out.truncate(48);
    out
}

fn vm_sketch(pe: &PeFile, raw: &[u8], candidate: &VmCandidate, rva: u32) -> Option<VmSketch> {
    let window = code_window(pe, raw, rva, 32, 256)?;
    let mut regs = BTreeSet::new();
    let mut mnemonics = BTreeSet::new();
    let mut score = 0u32;

    let file_off = pe.rva_to_offset(rva)?;
    let decode_len = 256usize.min(raw.len().saturating_sub(file_off));
    let bytes = &raw[file_off..file_off + decode_len];
    let mut decoder = Decoder::with_ip(
        pe.arch,
        bytes,
        pe.image_base + rva as u64,
        DecoderOptions::NONE,
    );
    while decoder.can_decode() && mnemonics.len() < 24 {
        let instr = decoder.decode();
        if instr.len() == 0 {
            break;
        }
        let mnemonic = instr.mnemonic();
        mnemonics.insert(format!("{:?}", mnemonic).to_ascii_lowercase());
        if is_indirect(&instr) {
            score = score.saturating_add(4);
        }
        if matches!(
            mnemonic,
            Mnemonic::Xor
                | Mnemonic::Add
                | Mnemonic::Sub
                | Mnemonic::Rol
                | Mnemonic::Ror
                | Mnemonic::Shl
                | Mnemonic::Shr
                | Mnemonic::Push
                | Mnemonic::Pop
        ) {
            score = score.saturating_add(1);
        }
        collect_registers(&instr, &mut regs);
        if matches!(mnemonic, Mnemonic::Ret | Mnemonic::Retf) {
            break;
        }
    }

    Some(VmSketch {
        rva: format!("0x{rva:08X}"),
        kind: candidate.kind.clone(),
        score,
        registers: regs.into_iter().collect(),
        mnemonics: mnemonics.into_iter().collect(),
        instructions: window.instructions,
        next_action: "label inputs, trace one iteration, and map opcode/state register writes into handler semantics".to_owned(),
    })
}

fn section_signals(pe: &PeFile) -> SectionSignal {
    let mut signal = SectionSignal::default();
    for section in &pe.sections {
        if section.is_executable() {
            signal.exec_count += 1;
            if section.entropy >= 7.15 {
                signal.high_entropy_exec += 1;
            }
            if section.protection_string().contains('W') {
                signal.writable_exec += 1;
            }
        }
    }
    signal
}

fn code_signals(pe: &PeFile, raw: &[u8]) -> CodeSignal {
    let mut signal = CodeSignal::default();
    for section in &pe.sections {
        if !section.is_executable() || section.raw_size == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        let len = (section.raw_size as usize).min(raw.len().saturating_sub(start));
        if start >= raw.len() || len == 0 {
            continue;
        }
        let bytes = &raw[start..start + len];
        let ip = pe.image_base + section.virtual_address as u64;
        let mut decoder = Decoder::with_ip(pe.arch, bytes, ip, DecoderOptions::NONE);
        let mut window = Vec::<Mnemonic>::new();
        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.len() == 0 {
                break;
            }
            let rva = instr.ip().wrapping_sub(pe.image_base) as u32;
            let m = instr.mnemonic();
            if matches!(m, Mnemonic::Jmp) && is_indirect(&instr) {
                signal.indirect_branches.push(rva);
            }
            if matches!(m, Mnemonic::Cpuid | Mnemonic::Rdtsc | Mnemonic::Rdtscp) {
                signal.cpuid_or_timing.push(rva);
            }
            window.push(m);
            if window.len() > 12 {
                window.remove(0);
            }
            let stack_ops = window
                .iter()
                .filter(|m| {
                    matches!(
                        m,
                        Mnemonic::Push | Mnemonic::Pop | Mnemonic::Pushfq | Mnemonic::Popfq
                    )
                })
                .count();
            if window.len() >= 10 && stack_ops >= 6 {
                signal.push_pop_density.push(rva);
            }
        }
    }
    signal
}

fn is_indirect(instr: &iced_x86::Instruction) -> bool {
    instr.op_count() > 0
        && !matches!(
            instr.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
        && matches!(instr.op0_kind(), OpKind::Register | OpKind::Memory)
}

fn is_conditional_branch(m: Mnemonic) -> bool {
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

fn parse_rva(s: &str) -> Option<u32> {
    let trimmed = s.trim();
    let hex = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u32::from_str_radix(hex, 16).ok()
}

fn data_refs(instr: &iced_x86::Instruction) -> Vec<u64> {
    let mut refs = Vec::new();
    for idx in 0..instr.op_count() {
        let addr = match instr.op_kind(idx) {
            OpKind::Memory => instr.memory_displacement64(),
            OpKind::Immediate64 => instr.immediate64(),
            OpKind::Immediate32 => instr.immediate32() as u64,
            _ => 0,
        };
        if addr != 0 {
            refs.push(addr);
        }
    }
    refs
}

fn collect_registers(instr: &iced_x86::Instruction, regs: &mut BTreeSet<String>) {
    for reg in [
        instr.op0_register(),
        instr.op1_register(),
        instr.op2_register(),
        instr.op3_register(),
        instr.memory_base(),
        instr.memory_index(),
    ] {
        if reg != Register::None {
            regs.insert(format!("{:?}", reg).to_ascii_lowercase());
        }
    }
}

fn looks_like_api_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    if !(4..=96).contains(&bytes.len()) {
        return false;
    }
    let alpha = bytes.iter().filter(|b| b.is_ascii_alphabetic()).count();
    let valid = bytes
        .iter()
        .all(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'@');
    if !(valid && alpha >= 4 && s.chars().next().is_some_and(|ch| ch.is_ascii_uppercase())) {
        return false;
    }
    const API_PREFIXES: &[&str] = &[
        "Get", "Set", "Nt", "Zw", "Rtl", "Ldr", "Virtual", "Load", "Free", "Create", "Open",
        "Close", "Read", "Write", "Map", "Unmap", "Protect", "Alloc", "Heap", "Reg", "Co",
        "WinHttp", "Internet",
    ];
    API_PREFIXES.iter().any(|prefix| s.starts_with(prefix))
        || s.contains("ProcAddress")
        || s.contains("Library")
        || s.contains("Virtual")
}

fn collect_strings(raw: &[u8], min_len: usize, limit: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    for &b in raw.iter().take(8 * 1024 * 1024) {
        if (0x20..=0x7E).contains(&b) {
            cur.push(b);
        } else {
            if cur.len() >= min_len {
                out.push(String::from_utf8_lossy(&cur).into_owned());
                if out.len() >= limit {
                    return out;
                }
            }
            cur.clear();
        }
    }
    if cur.len() >= min_len && out.len() < limit {
        out.push(String::from_utf8_lossy(&cur).into_owned());
    }
    out
}

fn finding(rule: &str, confidence: &str, detail: &str, evidence: Vec<String>) -> UnpackFinding {
    UnpackFinding {
        rule: rule.to_owned(),
        confidence: confidence.to_owned(),
        detail: detail.to_owned(),
        evidence,
    }
}
