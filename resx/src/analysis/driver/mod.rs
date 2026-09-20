use std::collections::{BTreeMap, BTreeSet};

mod calls;
mod capabilities;
mod dispatch;
mod hypervisor;
pub use calls::{
    Argument as IoctlArgument, BufferField as IoctlBufferField, CallEvidence as IoctlCallEvidence,
    Value as IoctlValue,
};
pub use capabilities::{DriverCapability, DriverCapabilityReference};
pub use hypervisor::{HypervisorImport, HypervisorIndicator, HypervisorReport, HypervisorSite};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, Mnemonic, OpKind};
use serde::Serialize;

use crate::formats::pe::{
    read_exports, read_runtime_functions, Export, ImportDll, PeFile, PeRuntimeFunctionInfo,
};

#[derive(Debug, Clone, Serialize)]
pub struct DriverReport {
    pub image: String,
    pub arch: u32,
    pub classification: String,
    pub confidence: String,
    pub framework_indicators: Vec<String>,
    pub device_apis: Vec<ApiHit>,
    pub symbolic_link_apis: Vec<ApiHit>,
    pub registry_apis: Vec<ApiHit>,
    pub callback_apis: Vec<ApiHit>,
    pub capabilities: Vec<DriverCapability>,
    pub hypervisor: HypervisorReport,
    pub major_functions: Vec<MajorFunctionAssignment>,
    pub ioctl: IoctlReport,
    pub interesting_strings: Vec<DriverString>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ApiHit {
    pub dll: String,
    pub name: String,
    pub slot_rva: String,
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct MajorFunctionAssignment {
    pub major_index: u32,
    pub major_name: String,
    pub site_rva: String,
    pub owner_rva: String,
    pub owner_name: String,
    pub instruction: String,
    pub confidence: String,
    pub target_rva: String,
    pub object_origin: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct IoctlReport {
    pub image: String,
    pub summary: String,
    pub dispatch_candidates: Vec<IoctlDispatchCandidate>,
    pub codes: Vec<IoctlCodeCandidate>,
    pub call_sites: Vec<IoctlCallEvidence>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IoctlDispatchCandidate {
    pub owner_rva: String,
    pub owner_name: String,
    pub reason: String,
    pub code_count: usize,
    pub codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct IoctlCodeCandidate {
    pub code: String,
    pub device_type: String,
    pub device_type_name: String,
    pub function: String,
    pub method: String,
    pub access: String,
    pub site_rva: String,
    pub owner_rva: String,
    pub owner_name: String,
    pub instruction: String,
    pub evidence_status: String,
    pub arguments: Option<String>,
    pub device_object_identity: Option<String>,
    pub ndis_oid: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DriverString {
    pub rva: Option<String>,
    pub section: String,
    pub value: String,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone)]
struct DecodedInsn {
    rva: u32,
    text: String,
    instr: iced_x86::Instruction,
    owner_rva: u32,
    owner_name: String,
}

pub fn analyze_contracts(pe: &PeFile, raw: &[u8]) -> serde_json::Value {
    let insns = decode_executable(
        pe,
        raw,
        &read_exports(pe, raw),
        &read_runtime_functions(pe, raw),
    );
    let mut calls = calls::recover(pe, raw, &insns);
    for call in &mut calls {
        if call.category == "io"
            && call.details["strings"].as_array().is_some_and(|strings| {
                strings.iter().any(|s| {
                    s["argument"] == "name"
                        && s["value"]
                            .as_str()
                            .is_some_and(|s| s.to_ascii_lowercase().starts_with("\\\\.\\pipe\\"))
                })
            })
        {
            call.category = "ipc".into();
        }
    }
    let mut report = serde_json::json!({"calls":calls,"decoded_instructions":insns.len(),"coverage":{"architecture_supported":pe.machine==0x8664,"instruction_limit":65536,"call_limit":1024,"instruction_limit_reached":insns.len()==65536,"call_limit_reached":calls.len()==1024},
        "limitations":["Static Windows x64 ABI; facts reset at ambiguous control-flow joins and unknown writes","Named imports and bounded jump thunks are supported; dynamic/API-hashed calls may remain unknown","API output values are conditional on success; object and peer identity require runtime evidence","No network connection, cryptographic operation, IPC peer or C2 role is established by a static call site"]});
    report["flows"] = crate::analysis::contract_flows::summarize(&report);
    report
}

pub fn analyze_driver(image: &str, pe: &PeFile, raw: &[u8], imports: &[ImportDll]) -> DriverReport {
    let exports = read_exports(pe, raw);
    let runtime_functions = read_runtime_functions(pe, raw);
    let insns = decode_executable(pe, raw, &exports, &runtime_functions);
    let api_hits = classify_imports(imports);
    let mut capabilities = capabilities::analyze(imports);
    let hypervisor = hypervisor::analyze(&insns, imports);
    capabilities::add_hypervisor_capabilities(&mut capabilities, &hypervisor);
    let major_functions = major_function_assignments(pe, raw, &insns);
    let ioctl = analyze_ioctls_with_context(image, pe, raw, &insns, &major_functions);
    let interesting_strings = driver_strings(image, pe, raw);
    let (mut classification, mut confidence, framework_indicators) =
        classify_driver(imports, &api_hits, &major_functions);
    if pe.subsystem != 1 {
        classification = "User-mode PE; driver framework is not established".into();
        confidence = "metadata".into();
    }
    let notes = driver_notes(&classification, &api_hits, &major_functions, &ioctl);

    DriverReport {
        image: image.to_owned(),
        arch: pe.arch,
        classification,
        confidence,
        framework_indicators,
        device_apis: api_hits.device_apis,
        symbolic_link_apis: api_hits.symbolic_link_apis,
        registry_apis: api_hits.registry_apis,
        callback_apis: api_hits.callback_apis,
        capabilities,
        hypervisor,
        major_functions,
        ioctl,
        interesting_strings,
        notes,
    }
}

pub fn analyze_ioctls(image: &str, pe: &PeFile, raw: &[u8]) -> IoctlReport {
    let exports = read_exports(pe, raw);
    let runtime_functions = read_runtime_functions(pe, raw);
    let insns = decode_executable(pe, raw, &exports, &runtime_functions);
    let major_functions = major_function_assignments(pe, raw, &insns);
    analyze_ioctls_with_context(image, pe, raw, &insns, &major_functions)
}

fn analyze_ioctls_with_context(
    image: &str,
    pe: &PeFile,
    raw: &[u8],
    insns: &[DecodedInsn],
    major_functions: &[MajorFunctionAssignment],
) -> IoctlReport {
    let call_sites: Vec<_> = calls::recover(pe, raw, insns)
        .into_iter()
        .filter(|call| matches!(call.category.as_str(), "ioctl" | "ndis"))
        .collect();
    let mut seen = BTreeSet::new();
    let mut codes = Vec::new();
    let device_control_owners: BTreeSet<String> = major_functions
        .iter()
        .filter(|item| item.major_index == 14)
        .map(|item| item.target_rva.clone())
        .collect();

    for insn in insns {
        if !is_ioctl_compare_instruction(insn.instr.mnemonic()) {
            continue;
        }
        let owner_rva_text = format!("0x{:08X}", insn.owner_rva);
        let owner_lower = insn.owner_name.to_ascii_lowercase();
        let context_hint = device_control_owners.contains(&owner_rva_text)
            || owner_lower.contains("ioctl")
            || owner_lower.contains("devicecontrol")
            || owner_lower.contains("device_control");
        for value in instruction_immediates(&insn.instr) {
            let Some(decoded) = decode_ioctl(value, context_hint) else {
                continue;
            };
            let key = format!("{}|{}", decoded.code, insn.rva);
            if !seen.insert(key) {
                continue;
            }
            codes.push(IoctlCodeCandidate {
                code: format!("0x{:08X}", decoded.code),
                device_type: format!("0x{:04X}", decoded.device_type),
                device_type_name: device_type_name(decoded.device_type).to_owned(),
                function: format!("0x{:03X}", decoded.function),
                method: method_name(decoded.method).to_owned(),
                access: access_name(decoded.access).to_owned(),
                site_rva: format!("0x{:08X}", insn.rva),
                owner_rva: format!("0x{:08X}", insn.owner_rva),
                owner_name: insn.owner_name.clone(),
                instruction: insn.text.clone(),
                evidence_status: "unverified-immediate-candidate".into(),
                arguments: None,
                device_object_identity: None,
                ndis_oid: None,
            });
        }
    }

    for call in &call_sites {
        let Some(code) = call.ioctl_code else {
            continue;
        };
        let decoded = DecodedIoctl {
            code,
            device_type: code >> 16,
            function: (code >> 2) & 0xfff,
            method: code & 3,
            access: (code >> 14) & 3,
        };
        codes.push(IoctlCodeCandidate {
            code: format!("0x{code:08X}"),
            device_type: format!("0x{:04X}", decoded.device_type),
            device_type_name: device_type_name(decoded.device_type).into(),
            function: format!("0x{:03X}", decoded.function),
            method: method_name(decoded.method).into(),
            access: access_name(decoded.access).into(),
            site_rva: format!("0x{:08X}", call.site_rva),
            owner_rva: format!("0x{:08X}", call.owner_rva),
            owner_name: call.owner_name.clone(),
            instruction: format!("call {}!{}", call.dll, call.api),
            evidence_status: "static-api-argument; execution-unobserved".into(),
            arguments: Some("See call_sites for typed argument values and provenance".into()),
            device_object_identity: None,
            ndis_oid: call.ndis_oid.map(|oid| format!("0x{oid:08X}")),
        });
    }

    let mut by_owner: BTreeMap<(u32, String), Vec<String>> = BTreeMap::new();
    for code in &codes {
        // Calling an IOCTL API does not make the caller a dispatch handler.
        if code.evidence_status != "unverified-immediate-candidate" {
            continue;
        }
        let owner = parse_hex_u32(&code.owner_rva).unwrap_or(0);
        by_owner
            .entry((owner, code.owner_name.clone()))
            .or_default()
            .push(code.code.clone());
    }

    let mut dispatch_candidates = Vec::new();
    for ((owner_rva, owner_name), mut owner_codes) in by_owner {
        owner_codes.sort();
        owner_codes.dedup();
        let owner_rva_text = format!("0x{:08X}", owner_rva);
        let major_match = device_control_owners.contains(&owner_rva_text);
        if owner_codes.len() >= 2
            || major_match
            || owner_name.to_ascii_lowercase().contains("ioctl")
        {
            let reason = if major_match {
                "owner is a statically assigned IRP_MJ_DEVICE_CONTROL target".to_owned()
            } else if owner_codes.len() >= 2 {
                "multiple CTL_CODE-shaped immediates in one function".to_owned()
            } else {
                "function name suggests IOCTL dispatch".to_owned()
            };
            dispatch_candidates.push(IoctlDispatchCandidate {
                owner_rva: owner_rva_text,
                owner_name,
                reason,
                code_count: owner_codes.len(),
                codes: owner_codes,
            });
        }
    }

    let summary = format!(
        "{} IOCTL code candidate(s), {} dispatch candidate(s)",
        codes.len(),
        dispatch_candidates.len()
    );
    IoctlReport {
        image: image.to_owned(),
        summary,
        dispatch_candidates,
        codes,
        call_sites,
        limitations: std::iter::once("x64 call arguments use bounded straight-line facts and ABI assumptions. Linear decode is limited to 65536 instructions; call evidence to 1024 sites. Missing facts and kernel-object identity remain unknown.".into())
            .chain(pe.anomalies.iter().map(|finding| format!("{} [{}]: {}", finding.severity, finding.kind, finding.detail)))
            .collect(),
    }
}

fn decode_executable(
    pe: &PeFile,
    raw: &[u8],
    exports: &[Export],
    runtime_functions: &[PeRuntimeFunctionInfo],
) -> Vec<DecodedInsn> {
    let mut out = Vec::new();
    if !matches!(pe.machine, 0x014c | 0x8664) {
        return out;
    }
    let mut sorted_runtime = runtime_functions.to_vec();
    sorted_runtime.sort_by_key(|function| function.begin_rva);
    let mut sections: Vec<_> = pe.sections.iter().collect();
    sections.sort_by_key(|section| !section.contains_rva(pe.entry_point));
    for section in sections {
        if !section.is_executable() || section.raw_size == 0 {
            continue;
        }
        let Some(bytes) = pe.rva_bytes(raw, section.virtual_address) else {
            continue;
        };
        let ip = pe.image_base + section.virtual_address as u64;
        let mut decoder = Decoder::with_ip(pe.arch, bytes, ip, DecoderOptions::NONE);
        let mut formatter = IntelFormatter::new();
        let mut leaf_export_owner: Option<(u32, String)> = None;
        while decoder.can_decode() {
            if out.len() >= 65_536 {
                return out;
            }
            let instr = decoder.decode();
            if instr.len() == 0 {
                break;
            }
            let rva = instr.ip().wrapping_sub(pe.image_base) as u32;
            let mut owner = owner_for_rva(rva, exports, &sorted_runtime);
            let begins_export = exports
                .iter()
                .find(|export| export.rva == rva && export.forward_to.is_empty());
            if let Some(export) = begins_export {
                leaf_export_owner = Some((export.rva, export.name.clone()));
            } else if owner.0 == rva {
                if let Some(export_owner) = &leaf_export_owner {
                    owner = export_owner.clone();
                }
            } else {
                leaf_export_owner = None;
            }
            let mut text = String::new();
            formatter.format(&instr, &mut text);
            out.push(DecodedInsn {
                rva,
                text,
                instr,
                owner_rva: owner.0,
                owner_name: owner.1,
            });
            if matches!(
                out.last().map(|decoded| decoded.instr.flow_control()),
                Some(
                    FlowControl::Return
                        | FlowControl::UnconditionalBranch
                        | FlowControl::IndirectBranch
                        | FlowControl::Exception
                )
            ) {
                leaf_export_owner = None;
            }
        }
    }
    out
}

fn owner_for_rva(
    rva: u32,
    exports: &[Export],
    runtime_functions: &[PeRuntimeFunctionInfo],
) -> (u32, String) {
    let index = runtime_functions.partition_point(|runtime| runtime.begin_rva <= rva);
    if let Some(runtime) = index
        .checked_sub(1)
        .and_then(|index| runtime_functions.get(index))
        .filter(|runtime| rva < runtime.end_rva)
    {
        let mut canonical_rva = runtime.begin_rva;
        let mut current = runtime;
        let mut visited = BTreeSet::new();
        visited.insert(runtime.begin_rva);
        for _ in 0..8 {
            let Some(parent) = &current.chained_parent else {
                break;
            };
            if !visited.insert(parent.begin_rva) {
                break;
            }
            canonical_rva = parent.begin_rva;
            let Some(parent_record) = runtime_functions.iter().find(|candidate| {
                candidate.begin_rva == parent.begin_rva
                    && candidate.end_rva == parent.end_rva
                    && candidate.unwind_info_rva == parent.unwind_info_rva
            }) else {
                break;
            };
            current = parent_record;
        }
        let name = exports
            .iter()
            .find(|export| export.rva == canonical_rva)
            .map(|export| export.name.clone())
            .unwrap_or_else(|| format!("sub_{canonical_rva:08X}"));
        return (canonical_rva, name);
    }
    if let Some(export) = exports
        .iter()
        .find(|export| export.rva == rva && export.forward_to.is_empty())
    {
        return (export.rva, export.name.clone());
    }
    (rva, format!("sub_{rva:08X}"))
}

#[derive(Default)]
struct ClassifiedImports {
    device_apis: Vec<ApiHit>,
    symbolic_link_apis: Vec<ApiHit>,
    registry_apis: Vec<ApiHit>,
    callback_apis: Vec<ApiHit>,
    framework_indicators: Vec<String>,
}

fn classify_imports(imports: &[ImportDll]) -> ClassifiedImports {
    let mut out = ClassifiedImports::default();
    for dll in imports {
        let dll_lower = dll.dll.to_ascii_lowercase();
        for entry in &dll.entries {
            let name_lower = entry.name.to_ascii_lowercase();
            let hit = ApiHit {
                dll: dll.dll.clone(),
                name: entry.name.clone(),
                slot_rva: format!("0x{:08X}", entry.slot_rva),
                kind: String::new(),
            };
            if dll_lower.contains("wdf") || name_lower.starts_with("wdf") {
                out.framework_indicators
                    .push(format!("KMDF/WDF import {}!{}", dll.dll, entry.name));
            }
            if matches!(
                name_lower.as_str(),
                "iocreatedevice"
                    | "iocreatedevicesecure"
                    | "ioregisterdeviceinterface"
                    | "wdfdevicecreate"
                    | "wdfcontroldeviceinitallocate"
            ) {
                out.device_apis.push(ApiHit {
                    kind: "device-create".to_owned(),
                    ..hit.clone()
                });
            }
            if matches!(
                name_lower.as_str(),
                "iocreatesymboliclink"
                    | "iodeletesymboliclink"
                    | "wdfdevicecreatesymboliclink"
                    | "wdfdevicecreatedeviceinterface"
            ) {
                out.symbolic_link_apis.push(ApiHit {
                    kind: "user-visible-link".to_owned(),
                    ..hit.clone()
                });
            }
            if name_lower.contains("registry")
                || name_lower.starts_with("zwopenkey")
                || name_lower.starts_with("zwqueryvaluekey")
                || name_lower.starts_with("rtlqueryregistry")
            {
                out.registry_apis.push(ApiHit {
                    kind: "registry".to_owned(),
                    ..hit.clone()
                });
            }
            if name_lower.starts_with("psset")
                || name_lower.starts_with("cmregister")
                || name_lower.starts_with("obregister")
                || name_lower.starts_with("ioregister")
                || name_lower.starts_with("fltregister")
                || name_lower.starts_with("etw")
                || name_lower.starts_with("wpp")
                || name_lower.starts_with("wdfinterrupt")
                || name_lower == "wdfioqueuecreate"
            {
                out.callback_apis.push(ApiHit {
                    kind: "callback-or-notification".to_owned(),
                    ..hit
                });
            }
        }
    }
    out.framework_indicators.sort();
    out.framework_indicators.dedup();
    out
}

fn classify_driver(
    imports: &[ImportDll],
    hits: &ClassifiedImports,
    major_functions: &[MajorFunctionAssignment],
) -> (String, String, Vec<String>) {
    let import_names: Vec<String> = imports
        .iter()
        .flat_map(|dll| {
            dll.entries
                .iter()
                .map(|entry| format!("{}!{}", dll.dll, entry.name).to_ascii_lowercase())
        })
        .collect();
    let has_wdf = !hits.framework_indicators.is_empty();
    let has_wdm = import_names.iter().any(|name| {
        name.contains("ntoskrnl")
            && (name.contains("iocreatedevice") || name.contains("iocalldriver"))
    }) || !major_functions.is_empty();

    let mut indicators = hits.framework_indicators.clone();
    if has_wdm {
        indicators.push("WDM-style imports or DRIVER_OBJECT MajorFunction assignments".to_owned());
    }
    if import_names.iter().any(|name| name.contains("driverentry")) {
        indicators.push("DriverEntry-like import/symbol surface".to_owned());
    }

    match (has_wdf, has_wdm) {
        (true, true) => ("mixed WDM/KMDF".to_owned(), "medium".to_owned(), indicators),
        (true, false) => ("KMDF/WDF".to_owned(), "high".to_owned(), indicators),
        (false, true) => ("WDM".to_owned(), "medium".to_owned(), indicators),
        (false, false) => (
            "driver-like PE".to_owned(),
            "low".to_owned(),
            vec!["no strong WDM/KMDF import or dispatch assignment signal".to_owned()],
        ),
    }
}

fn major_function_assignments(
    pe: &PeFile,
    raw: &[u8],
    insns: &[DecodedInsn],
) -> Vec<MajorFunctionAssignment> {
    dispatch::recover(pe, raw, insns)
}

fn is_ioctl_compare_instruction(mnemonic: Mnemonic) -> bool {
    matches!(
        mnemonic,
        Mnemonic::Cmp | Mnemonic::Sub | Mnemonic::Add | Mnemonic::Lea
    )
}

fn instruction_immediates(instr: &iced_x86::Instruction) -> Vec<u32> {
    let mut out = Vec::new();
    for idx in 0..instr.op_count() {
        let value = match instr.op_kind(idx) {
            OpKind::Immediate8 => Some(instr.immediate8() as u32),
            OpKind::Immediate8to16 | OpKind::Immediate8to32 | OpKind::Immediate8to64 => {
                Some(instr.immediate8to32() as u32)
            }
            OpKind::Immediate16 => Some(instr.immediate16() as u32),
            OpKind::Immediate32 | OpKind::Immediate32to64 => Some(instr.immediate32()),
            OpKind::Immediate64 => u32::try_from(instr.immediate64()).ok(),
            _ => None,
        };
        if let Some(value) = value {
            out.push(value);
        }
    }
    out.sort();
    out.dedup();
    out
}

struct DecodedIoctl {
    code: u32,
    device_type: u32,
    function: u32,
    method: u32,
    access: u32,
}

fn decode_ioctl(code: u32, context_hint: bool) -> Option<DecodedIoctl> {
    if code < 0x0001_0000 {
        return None;
    }
    let method = code & 0x3;
    let function = (code >> 2) & 0xFFF;
    let access = (code >> 14) & 0x3;
    let device_type = (code >> 16) & 0xFFFF;
    if function == 0 {
        return None;
    }
    let known_device = matches!(device_type, 0x22 | 0x23 | 0x2D);
    let custom_device = device_type >= 0x8000;
    let vendor_function = (0x800..=0xFFF).contains(&function);
    let plausible = if context_hint {
        known_device || custom_device || device_type != 0
    } else {
        known_device && vendor_function
    };
    plausible.then_some(DecodedIoctl {
        code,
        device_type,
        function,
        method,
        access,
    })
}

fn driver_strings(_image: &str, pe: &PeFile, raw: &[u8]) -> Vec<DriverString> {
    crate::formats::pe::read_data_summary(pe, raw)
        .strings
        .into_iter()
        .take(32)
        .map(|item| DriverString {
            rva: Some(format!("0x{:08X}", item.rva)),
            section: item.section_name,
            value: item.value,
            tags: Vec::new(),
        })
        .collect()
}

fn driver_notes(
    classification: &str,
    hits: &ClassifiedImports,
    major_functions: &[MajorFunctionAssignment],
    ioctl: &IoctlReport,
) -> Vec<String> {
    let mut notes = vec!["Static analysis only. Typed x64 API arguments and supported NDIS query OIDs carry their provenance in ioctl.call_sites. Device paths are API-result provenance, not live kernel-object identity. Decode budget: 65536 instructions; later code may be omitted.".into()];
    if classification.contains("KMDF") {
        notes.push("KMDF drivers often dispatch through WdfFunctions; use `resx callers <driver.sys> WdfIoQueueCreate --show-site` to walk callsites.".to_owned());
    }
    if !major_functions.is_empty() {
        notes.push("MajorFunction stores require entry-argument provenance and a mapped code target. Bounded x64 branches, constant loops, and direct helpers are covered under the entry ABI assumption. Conditional stores may be overwritten; final runtime table and object identity remain unknown.".to_owned());
    }
    if !ioctl.dispatch_candidates.is_empty() {
        notes.push("IOCTL candidates are decoded from CTL_CODE-shaped immediates and grouped by owning function.".to_owned());
    }
    if hits.device_apis.is_empty() && hits.symbolic_link_apis.is_empty() {
        notes.push("No obvious device creation or symbolic-link import was found; this may be filter-only, framework-only, or stripped/indirect.".to_owned());
    }
    notes
}

fn major_function_name(index: u32) -> &'static str {
    match index {
        0 => "IRP_MJ_CREATE",
        1 => "IRP_MJ_CREATE_NAMED_PIPE",
        2 => "IRP_MJ_CLOSE",
        3 => "IRP_MJ_READ",
        4 => "IRP_MJ_WRITE",
        5 => "IRP_MJ_QUERY_INFORMATION",
        6 => "IRP_MJ_SET_INFORMATION",
        7 => "IRP_MJ_QUERY_EA",
        8 => "IRP_MJ_SET_EA",
        9 => "IRP_MJ_FLUSH_BUFFERS",
        10 => "IRP_MJ_QUERY_VOLUME_INFORMATION",
        11 => "IRP_MJ_SET_VOLUME_INFORMATION",
        12 => "IRP_MJ_DIRECTORY_CONTROL",
        13 => "IRP_MJ_FILE_SYSTEM_CONTROL",
        14 => "IRP_MJ_DEVICE_CONTROL",
        15 => "IRP_MJ_INTERNAL_DEVICE_CONTROL",
        16 => "IRP_MJ_SHUTDOWN",
        17 => "IRP_MJ_LOCK_CONTROL",
        18 => "IRP_MJ_CLEANUP",
        19 => "IRP_MJ_CREATE_MAILSLOT",
        20 => "IRP_MJ_QUERY_SECURITY",
        21 => "IRP_MJ_SET_SECURITY",
        22 => "IRP_MJ_POWER",
        23 => "IRP_MJ_SYSTEM_CONTROL",
        24 => "IRP_MJ_DEVICE_CHANGE",
        25 => "IRP_MJ_QUERY_QUOTA",
        26 => "IRP_MJ_SET_QUOTA",
        27 => "IRP_MJ_PNP",
        _ => "IRP_MJ_UNKNOWN",
    }
}

fn device_type_name(value: u32) -> &'static str {
    match value {
        0x0001 => "FILE_DEVICE_BEEP",
        0x0002 => "FILE_DEVICE_CD_ROM",
        0x0003 => "FILE_DEVICE_CD_ROM_FILE_SYSTEM",
        0x0004 => "FILE_DEVICE_CONTROLLER",
        0x0005 => "FILE_DEVICE_DATALINK",
        0x0006 => "FILE_DEVICE_DFS",
        0x0007 => "FILE_DEVICE_DISK",
        0x0008 => "FILE_DEVICE_DISK_FILE_SYSTEM",
        0x0009 => "FILE_DEVICE_FILE_SYSTEM",
        0x000A => "FILE_DEVICE_INPORT_PORT",
        0x000B => "FILE_DEVICE_KEYBOARD",
        0x000C => "FILE_DEVICE_MAILSLOT",
        0x000D => "FILE_DEVICE_MIDI_IN",
        0x000E => "FILE_DEVICE_MIDI_OUT",
        0x000F => "FILE_DEVICE_MOUSE",
        0x0010 => "FILE_DEVICE_MULTI_UNC_PROVIDER",
        0x0011 => "FILE_DEVICE_NAMED_PIPE",
        0x0012 => "FILE_DEVICE_NETWORK",
        0x0013 => "FILE_DEVICE_NETWORK_BROWSER",
        0x0014 => "FILE_DEVICE_NETWORK_FILE_SYSTEM",
        0x0015 => "FILE_DEVICE_NULL",
        0x0016 => "FILE_DEVICE_PARALLEL_PORT",
        0x0017 => "FILE_DEVICE_PHYSICAL_NETCARD",
        0x0018 => "FILE_DEVICE_PRINTER",
        0x0019 => "FILE_DEVICE_SCANNER",
        0x001A => "FILE_DEVICE_SERIAL_MOUSE_PORT",
        0x001B => "FILE_DEVICE_SERIAL_PORT",
        0x001C => "FILE_DEVICE_SCREEN",
        0x001D => "FILE_DEVICE_SOUND",
        0x001E => "FILE_DEVICE_STREAMS",
        0x001F => "FILE_DEVICE_TAPE",
        0x0020 => "FILE_DEVICE_TAPE_FILE_SYSTEM",
        0x0021 => "FILE_DEVICE_TRANSPORT",
        0x0022 => "FILE_DEVICE_UNKNOWN",
        0x0023 => "FILE_DEVICE_VIDEO",
        0x002D => "FILE_DEVICE_NETWORK_REDIRECTOR",
        _ if value >= 0x8000 => "CUSTOM_DEVICE_TYPE",
        _ => "FILE_DEVICE_*",
    }
}

fn method_name(value: u32) -> &'static str {
    match value {
        0 => "METHOD_BUFFERED",
        1 => "METHOD_IN_DIRECT",
        2 => "METHOD_OUT_DIRECT",
        3 => "METHOD_NEITHER",
        _ => "METHOD_UNKNOWN",
    }
}

fn access_name(value: u32) -> &'static str {
    match value {
        0 => "FILE_ANY_ACCESS",
        1 => "FILE_READ_ACCESS",
        2 => "FILE_WRITE_ACCESS",
        3 => "FILE_READ_WRITE_ACCESS",
        _ => "FILE_UNKNOWN_ACCESS",
    }
}

fn parse_hex_u32(value: &str) -> Option<u32> {
    u32::from_str_radix(value.trim_start_matches("0x"), 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::formats::pe::{PeChainedRuntimeFunction, PeSection, IMAGE_SCN_MEM_EXECUTE};

    fn runtime(
        begin_rva: u32,
        end_rva: u32,
        unwind_info_rva: u32,
        chained_parent: Option<PeChainedRuntimeFunction>,
    ) -> PeRuntimeFunctionInfo {
        PeRuntimeFunctionInfo {
            begin_rva,
            end_rva,
            unwind_info_rva,
            unwind_version: 1,
            unwind_flags: 0,
            prolog_size: 0,
            unwind_code_count: 0,
            frame_register: 0,
            frame_offset: 0,
            exception_handler_rva: 0,
            handler_data_rva: 0,
            stack_alloc_size: 0,
            saved_registers: Vec::new(),
            unwind_operations: Vec::new(),
            chained_parent,
            epilog_scopes: Vec::new(),
        }
    }

    #[test]
    fn chained_unwind_fragment_keeps_parent_export_ownership() {
        let exports = vec![Export {
            name: "ExportedWrapper".into(),
            ordinal: 1,
            rva: 0x1000,
            forward_to: String::new(),
        }];
        let parent = runtime(0x1000, 0x1080, 0x2000, None);
        let child = runtime(
            0x1080,
            0x1100,
            0x2010,
            Some(PeChainedRuntimeFunction {
                begin_rva: 0x1000,
                end_rva: 0x1080,
                unwind_info_rva: 0x2000,
            }),
        );
        assert_eq!(
            owner_for_rva(0x10a0, &exports, &[parent, child]),
            (0x1000, "ExportedWrapper".into())
        );
    }

    fn sample(code: &[u8], subsystem: u16) -> Vec<MajorFunctionAssignment> {
        let pe = PeFile {
            arch: 64,
            machine: 0x8664,
            timestamp: 0,
            coff_characteristics: 0x22,
            major_linker_version: 0,
            minor_linker_version: 0,
            image_base: 0x140000000,
            entry_point: 0x1000,
            size_of_image: 0x2000,
            size_of_headers: 0x200,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            checksum: 0,
            subsystem,
            dll_characteristics: 0,
            data_dirs: vec![(0, 0); 16],
            anomalies: vec![],
            sections: vec![PeSection {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x100,
                raw_offset: 0x200,
                raw_size: 0x100,
                characteristics: IMAGE_SCN_MEM_EXECUTE,
                entropy: 0.0,
            }],
        };
        let mut raw = vec![0xcc; 0x300];
        raw[0x200..0x200 + code.len()].copy_from_slice(code);
        let cached = major_function_assignments(&pe, &raw, &decode_executable(&pe, &raw, &[], &[]));
        let direct = major_function_assignments(&pe, &raw, &[]);
        assert_eq!(
            serde_json::to_value(&cached).unwrap(),
            serde_json::to_value(direct).unwrap()
        );
        cached
    }

    #[test]
    fn entry_object_and_pointer_store_establish_static_assignment() {
        // lea rax,[rip+0x19]; mov [rcx+0xe0],rax; ret
        let code = [
            0x48, 0x8d, 0x05, 0x19, 0, 0, 0, 0x48, 0x89, 0x81, 0xe0, 0, 0, 0, 0xc3,
        ];
        let result = sample(&code, 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].major_index, 14);
        assert_eq!(result[0].target_rva, "0x00001020");
        assert!(sample(&code, 3).is_empty());
    }

    #[test]
    fn overwritten_object_alias_is_not_a_dispatch_assignment() {
        let code = [
            0x48, 0x8d, 0x05, 0x19, 0, 0, 0, 0x31, 0xc9, 0x48, 0x89, 0x81, 0xe0, 0, 0, 0, 0xc3,
        ];
        assert!(sample(&code, 1).is_empty());
    }

    #[test]
    fn partial_pointer_stores_are_not_dispatch_assignments() {
        let code = [
            0x48, 0x8d, 0x05, 0x19, 0, 0, 0, 0x89, 0x81, 0xe0, 0, 0, 0, 0xc3,
        ];
        assert!(sample(&code, 1).is_empty());
    }

    #[test]
    fn call_boundaries_end_unproven_object_provenance() {
        let code = [
            0x48, 0x8d, 0x05, 0x19, 0, 0, 0, 0xe8, 0, 0, 0, 0, 0x48, 0x89, 0x81, 0xe0, 0, 0, 0,
            0xc3,
        ];
        assert!(sample(&code, 1).is_empty());
    }

    #[test]
    fn direct_helper_receives_the_entry_object_argument() {
        let mut code = vec![0xcc; 0x40];
        code[..6].copy_from_slice(&[0xe8, 0x1b, 0, 0, 0, 0xc3]);
        code[0x20..0x2f].copy_from_slice(&[
            0x48, 0x8d, 0x05, 0x19, 0, 0, 0, 0x48, 0x89, 0x81, 0xe0, 0, 0, 0, 0xc3,
        ]);
        let result = sample(&code, 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].target_rva, "0x00001040");
        assert!(result[0].object_origin.contains("helper depth 1"));
    }

    #[test]
    fn a_known_false_branch_does_not_create_an_assignment() {
        let mut code = vec![0xcc; 0x30];
        code[..7].copy_from_slice(&[0x31, 0xc0, 0x85, 0xc0, 0x75, 0x0a, 0xc3]);
        code[0x10..0x1f].copy_from_slice(&[
            0x48, 0x8d, 0x05, 0x19, 0, 0, 0, 0x48, 0x89, 0x81, 0xe0, 0, 0, 0, 0xc3,
        ]);
        assert!(sample(&code, 1).is_empty());
    }

    #[test]
    fn bounded_indexed_initialization_recovers_all_28_entries() {
        let code = [
            0x48, 0x8d, 0x05, 0x39, 0, 0, 0, 0x31, 0xd2, 0x48, 0x89, 0x44, 0xd1, 0x70, 0x83, 0xc2,
            1, 0x83, 0xfa, 0x1c, 0x72, 0xf3, 0xc3,
        ];
        let result = sample(&code, 1);
        assert_eq!(result.len(), 28);
        assert_eq!(
            result
                .iter()
                .map(|item| item.major_index)
                .collect::<Vec<_>>(),
            (0..28).collect::<Vec<_>>()
        );
    }
}
