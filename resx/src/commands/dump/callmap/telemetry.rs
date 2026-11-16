//! Telemetry reachability for a traced call: which ETW providers, kernel notify
//! callbacks, audit records and change notifications the call can reach, and who
//! can consume them.
//!
//! The search is breadth-first over direct calls, imports into other images and
//! system calls into the kernel, so the shortest path to each source is reported
//! and the budget is spent evenly across the call graph. It records sources; it
//! does not establish that one fires, since providers, sessions, callbacks and
//! audit policy are enabled at run time.

use super::*;
use serde::Serialize;

/// What kind of telemetry a sink produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(in crate::commands::dump) enum TelemetryKind {
    KernelCallback,
    EtwThreatIntel,
    EtwKernel,
    Audit,
    FilterStack,
    RegistryNotify,
    DirectoryNotify,
    Wmi,
    Wfp,
    Amsi,
    EtwUser,
    JobNotify,
    Consumer,
}

impl TelemetryKind {
    pub(in crate::commands::dump) fn label(self) -> &'static str {
        match self {
            Self::KernelCallback => "kernel callback",
            Self::EtwThreatIntel => "ETW-TI",
            Self::EtwKernel => "ETW kernel",
            Self::Audit => "audit",
            Self::FilterStack => "driver stack",
            Self::RegistryNotify => "registry notify",
            Self::DirectoryNotify => "directory notify",
            Self::Wmi => "WMI",
            Self::Wfp => "WFP",
            Self::Amsi => "AMSI",
            Self::EtwUser => "ETW user-mode",
            Self::JobNotify => "job notify",
            Self::Consumer => "consumer",
        }
    }

    fn heading(self) -> &'static str {
        match self {
            Self::KernelCallback => "Kernel callbacks",
            Self::EtwThreatIntel => "ETW Threat-Intelligence",
            Self::EtwKernel => "ETW kernel providers",
            Self::Audit => "Security auditing",
            Self::FilterStack => "Driver stacks and filters",
            Self::RegistryNotify => "Registry change notifications",
            Self::DirectoryNotify => "Directory change notifications",
            Self::Wmi => "WMI events",
            Self::Wfp => "Windows Filtering Platform",
            Self::Amsi => "AMSI",
            Self::EtwUser => "ETW user-mode providers",
            Self::JobNotify => "Job object notifications",
            Self::Consumer => "Telemetry consumers",
        }
    }

    /// Where the event is produced: in the calling process, or outside its reach.
    fn origin(self) -> &'static str {
        match self {
            Self::EtwUser | Self::Amsi => "in-process",
            Self::Consumer => "consumer",
            _ => "kernel",
        }
    }
}

/// One recognized telemetry source or consumer API.
pub(in crate::commands::dump) struct Sink {
    /// Exact name, or a prefix ending in `*`.
    pattern: &'static str,
    pub(in crate::commands::dump) kind: TelemetryKind,
    /// What the sink emits or does.
    fires: &'static str,
    /// Who can receive it.
    consumers: &'static str,
}

const fn sink(
    pattern: &'static str,
    kind: TelemetryKind,
    fires: &'static str,
    consumers: &'static str,
) -> Sink {
    Sink {
        pattern,
        kind,
        fires,
        consumers,
    }
}

use TelemetryKind::*;

const ETW_USER: &str = "ETW sessions enabled for the provider: EDR user-mode sensors, logman/xperf traces, Event Log channels";
const ETW_KERNEL: &str = "kernel ETW sessions enabled for the provider (EDR sensors, Sysmon-style tools, trace collectors)";

/// Ordered: the first match wins, so specific names precede prefixes.
static SINKS: &[Sink] = &[
    // APIs that register for or read telemetry. Listed first: some share prefixes
    // with sources (Fwpm*, EtwEventWrite*).
    sink("RegNotifyChangeKeyValue", Consumer, "watches a registry key for changes", "the caller (registry change watcher)"),
    sink("NtNotifyChangeKey", Consumer, "watches a registry key for changes", "the caller (registry change watcher)"),
    sink("ZwNotifyChangeKey", Consumer, "watches a registry key for changes", "the caller (registry change watcher)"),
    sink("NtNotifyChangeMultipleKeys", Consumer, "watches registry keys for changes", "the caller (registry change watcher)"),
    sink("ReadDirectoryChangesW", Consumer, "watches a directory for changes", "the caller (directory change watcher)"),
    sink("ReadDirectoryChangesExW", Consumer, "watches a directory for changes", "the caller (directory change watcher)"),
    sink("NtNotifyChangeDirectoryFile*", Consumer, "watches a directory for changes", "the caller (directory change watcher)"),
    sink("FindFirstChangeNotification*", Consumer, "watches a directory for changes", "the caller (directory change watcher)"),
    sink("EvtSubscribe", Consumer, "subscribes to Event Log channel events", "the caller (event log subscriber)"),
    sink("OpenTrace*", Consumer, "opens an ETW session or log for consumption", "the caller (ETW consumer)"),
    sink("ProcessTrace", Consumer, "consumes ETW events", "the caller (ETW consumer)"),
    sink("StartTrace*", Consumer, "starts an ETW session", "the caller (ETW controller)"),
    sink("EnableTraceEx*", Consumer, "enables a provider in an ETW session", "the caller (ETW controller)"),
    sink("FwpmNetEventSubscribe*", Consumer, "subscribes to WFP network events", "the caller (WFP event subscriber)"),
    sink("PsSetCreateProcessNotifyRoutine*", Consumer, "registers a process-creation callback", "the registering driver"),
    sink("PsSetCreateThreadNotifyRoutine*", Consumer, "registers a thread-creation callback", "the registering driver"),
    sink("PsSetLoadImageNotifyRoutine*", Consumer, "registers an image-load callback", "the registering driver"),
    sink("ObRegisterCallbacks", Consumer, "registers process/thread handle callbacks", "the registering driver"),
    sink("CmRegisterCallback*", Consumer, "registers a registry callback", "the registering driver"),
    sink("FltRegisterFilter", Consumer, "registers a file-system minifilter", "the registering driver"),
    sink("FwpsCalloutRegister*", Consumer, "registers a WFP callout", "the registering driver"),
    // Kernel notify callbacks: third-party drivers run synchronously and can veto.
    sink("PspCallProcessNotifyRoutines", KernelCallback, "process creation and exit notify routines", "drivers registered with PsSetCreateProcessNotifyRoutine(Ex/Ex2): EDR and Sysmon-style drivers; the Ex forms can block creation"),
    sink("PspCallThreadNotifyRoutines", KernelCallback, "thread creation and exit notify routines", "drivers registered with PsSetCreateThreadNotifyRoutine(Ex)"),
    sink("PsCallImageNotifyRoutines", KernelCallback, "image-load notify routines", "drivers registered with PsSetLoadImageNotifyRoutine(Ex)"),
    sink("PspCallImageNotifyRoutines", KernelCallback, "image-load notify routines", "drivers registered with PsSetLoadImageNotifyRoutine(Ex)"),
    sink("ObpCallPreOperationCallbacks", KernelCallback, "object pre-operation callbacks on handle create or duplicate", "drivers registered with ObRegisterCallbacks; can strip requested access"),
    sink("ObpCallPostOperationCallbacks", KernelCallback, "object post-operation callbacks on handle create or duplicate", "drivers registered with ObRegisterCallbacks"),
    sink("ObpPreInterceptHandle*", KernelCallback, "object pre-operation callbacks on handle create or duplicate", "drivers registered with ObRegisterCallbacks; can strip requested access"),
    sink("ObpPostInterceptHandle*", KernelCallback, "object post-operation callbacks on handle create or duplicate", "drivers registered with ObRegisterCallbacks"),
    sink("CmpCallCallBacks*", KernelCallback, "registry operation callbacks", "drivers registered with CmRegisterCallback(Ex); can block or alter the operation"),
    sink("ExCallCallBack", KernelCallback, "a registered callback block (for example Win32k process and thread callouts)", "kernel components that registered the block"),
    sink("ExNotifyCallback", KernelCallback, "a callback object notification", "drivers registered with ExRegisterCallback on the object"),
    // Exploit-mitigation events share the EtwTi prefix but use their own provider.
    sink("EtwTimLog*", EtwKernel, "exploit-mitigation event (Microsoft-Windows-Security-Mitigations)", ETW_KERNEL),
    // ETW Threat-Intelligence: kernel-generated, consumable only by antimalware PPL.
    sink("EtwTi*", EtwThreatIntel, "Microsoft-Windows-Threat-Intelligence event", "consumers running as antimalware protected processes (EDR); cannot be patched from user mode"),
    // Kernel ETW.
    sink("EtwTraceProcess", EtwKernel, "kernel process start/stop event (Microsoft-Windows-Kernel-Process, NT Kernel Logger)", "kernel ETW sessions; WMI Win32_ProcessStartTrace and process event subscriptions"),
    sink("EtwTraceProcessTerminate", EtwKernel, "kernel process termination event", "kernel ETW sessions; WMI Win32_ProcessStopTrace subscriptions"),
    sink("EtwTraceThread", EtwKernel, "kernel thread start/stop event (Microsoft-Windows-Kernel-Process)", "kernel ETW sessions; WMI Win32_ThreadStartTrace subscriptions"),
    sink("EtwTraceImageLoad", EtwKernel, "kernel image load event (Microsoft-Windows-Kernel-Process)", "kernel ETW sessions; WMI Win32_ModuleLoadTrace subscriptions"),
    sink("EtwTraceImageUnload", EtwKernel, "kernel image unload event", ETW_KERNEL),
    sink("EtwTraceObjectOperation", EtwKernel, "kernel object operation event", ETW_KERNEL),
    sink("EtwTraceObject", EtwKernel, "kernel object event", ETW_KERNEL),
    sink("EtwpTraceRegistry", EtwKernel, "kernel registry event (Microsoft-Windows-Kernel-Registry)", ETW_KERNEL),
    sink("EtwpTraceHandle", EtwKernel, "kernel handle event", ETW_KERNEL),
    sink("EtwpTraceFileIo*", EtwKernel, "kernel file I/O event (Microsoft-Windows-Kernel-File)", ETW_KERNEL),
    sink("EtwTraceKernelEvent", EtwKernel, "NT Kernel Logger event", ETW_KERNEL),
    sink("EtwpLogKernelEvent", EtwKernel, "NT Kernel Logger event", ETW_KERNEL),
    sink("PspLogAuditTerminateRemoteProcessEvent", EtwKernel, "termination of another process (Microsoft-Windows-Kernel-Audit-API-Calls)", ETW_KERNEL),
    sink("EtwWrite", EtwKernel, "kernel ETW provider event (provider not recovered)", ETW_KERNEL),
    sink("EtwWriteEx", EtwKernel, "kernel ETW provider event (provider not recovered)", ETW_KERNEL),
    sink("EtwWriteTransfer", EtwKernel, "kernel ETW provider event (provider not recovered)", ETW_KERNEL),
    sink("EtwWriteString", EtwKernel, "kernel ETW provider string event", ETW_KERNEL),
    // Security auditing, written to the Security log through LSA.
    sink("SeAuditProcessCreation", Audit, "process creation audit (Security event 4688)", "the Security event log when Audit Process Creation is enabled: EvtSubscribe on the Security channel, SIEM forwarders"),
    sink("SeAuditProcessExit", Audit, "process exit audit (Security event 4689)", "the Security event log when Audit Process Termination is enabled: EvtSubscribe on the Security channel"),
    sink("SepAdtLogAuditRecord", Audit, "security audit record", "the Security event log when the audit subcategory is enabled: EvtSubscribe on the Security channel"),
    sink("SeAuditHandleCreation", Audit, "handle creation audit", "the Security event log when object access auditing applies"),
    sink("SeOpenObjectAuditAlarm*", Audit, "object open audit", "the Security event log when the object's SACL and audit policy apply"),
    sink("SepAdtCloseObjectAuditAlarm", Audit, "object close audit", "the Security event log when object access auditing applies"),
    // I/O sent to a driver stack: attached filters see it.
    sink("IofCallDriver", FilterStack, "an I/O request sent to a driver stack", "filter drivers attached to the device: file-system minifilters, volume and network filters"),
    sink("IoCallDriver", FilterStack, "an I/O request sent to a driver stack", "filter drivers attached to the device: file-system minifilters, volume and network filters"),
    // Change notifications.
    sink("CmpPostNotify", RegistryNotify, "a registry change notification", "RegNotifyChangeKeyValue and NtNotifyChangeKey watchers on the key"),
    sink("CmpReportNotify*", RegistryNotify, "a registry change notification", "RegNotifyChangeKeyValue and NtNotifyChangeKey watchers on the key"),
    sink("FsRtlNotifyFullReportChange", DirectoryNotify, "a directory change notification", "ReadDirectoryChangesW/ExW and FindFirstChangeNotification watchers"),
    sink("FsRtlNotifyFilterReportChange", DirectoryNotify, "a directory change notification", "ReadDirectoryChangesW/ExW and FindFirstChangeNotification watchers"),
    // WMI.
    sink("IoWMIWriteEvent", Wmi, "a WMI event", "WMI event consumers, including permanent subscriptions"),
    sink("WmiTraceMessage*", Wmi, "a WMI trace message", "WMI and ETW trace consumers"),
    // WFP.
    sink("Fwpm*", Wfp, "a WFP management operation (audited as WFP policy change)", "Microsoft-Windows-WFP events and the Security log when Filtering Platform Policy Change auditing is enabled"),
    sink("Kfd*", Wfp, "WFP classification", "WFP callout drivers registered at the layer"),
    sink("Fwps*", Wfp, "a WFP callout operation", "WFP callout drivers"),
    // AMSI.
    sink("Amsi*", Amsi, "content submitted for antimalware scanning", "registered AMSI providers (antimalware products); runs in the calling process"),
    // User-mode ETW: emitted in the calling process.
    sink("EtwEventWrite*", EtwUser, "user-mode ETW provider event", ETW_USER),
    sink("EventWrite*", EtwUser, "user-mode ETW provider event", ETW_USER),
    sink("tlgWrite*", EtwUser, "TraceLogging provider event", ETW_USER),
    sink("_tlgWrite*", EtwUser, "TraceLogging provider event", ETW_USER),
    sink("McGenEventWrite*", EtwUser, "manifest-based provider event", ETW_USER),
    sink("EtwWriteUMSecurityEvent", EtwUser, "user-mode security event", ETW_USER),
    // Jobs.
    sink("PspSendProcessNotificationToJobChain", JobNotify, "job object process notification", "the job's completion port owner (JOB_OBJECT_MSG_* messages)"),
];

/// Check functions, not emitters, that share an emitter's prefix.
const NOT_SINKS: &[&str] = &[
    "EtwEventEnabled",
    "EtwEventProviderEnabled",
    "EventEnabled",
    "EventProviderEnabled",
];

/// Strip import, thunk and displacement decoration from a call label.
fn bare_name(label: &str) -> &str {
    let name = label.rsplit('!').next().unwrap_or(label);
    let name = name
        .strip_prefix("__imp_")
        .or_else(|| name.strip_prefix("_imp_"))
        .unwrap_or(name);
    name.split("+0x").next().unwrap_or(name).trim()
}

/// The telemetry sink a call target names, if any.
pub(in crate::commands::dump) fn classify(label: &str) -> Option<&'static Sink> {
    let name = bare_name(label);
    if name.is_empty() || NOT_SINKS.iter().any(|n| n.eq_ignore_ascii_case(name)) {
        return None;
    }
    SINKS
        .iter()
        .find(|sink| match sink.pattern.strip_suffix('*') {
            Some(prefix) => name
                .get(..prefix.len())
                .is_some_and(|head| head.eq_ignore_ascii_case(prefix)),
            None => name.eq_ignore_ascii_case(sink.pattern),
        })
}

/// Runtime, locking and diagnostic helpers whose callees do not lead to telemetry
/// sources; skipping them keeps the search budget on paths that do.
fn is_unproductive(name: &str) -> bool {
    const EXACT: &[&str] = &[
        "memset",
        "memcpy",
        "memmove",
        "memcmp",
        "__chkstk",
        "_security_check_cookie",
        "_report_gsfailure",
        "guard_dispatch_icall",
        "RtlCaptureContext",
        "RtlCaptureStackBackTrace",
        "RtlWalkFrameChain",
        "KeBugCheck",
        "KeBugCheckEx",
        "KeBugCheck2",
        "DbgPrint",
        "DbgPrintEx",
        "DbgPrompt",
        "ExAllocatePool2",
        "ExAllocatePool3",
        "ExFreePoolWithTag",
        "ExFreePool",
    ];
    const PREFIXES: &[&str] = &[
        "wcs",
        "str",
        "_guard_",
        "Feature_",
        "wil_",
        "KeAbPre",
        "KeAbPost",
        "Exf",
        "KiAcquire",
        "KiRelease",
        "KiRaiseIrql",
        "KiLowerIrql",
        "HalpInterrupt",
        "RtlInitUnicodeString",
        "RtlCopyMemory",
        "RtlCompareMemory",
        "RtlFreeUnicodeString",
    ];
    EXACT.iter().any(|n| n.eq_ignore_ascii_case(name))
        || PREFIXES.iter().any(|p| {
            name.get(..p.len())
                .is_some_and(|h| h.eq_ignore_ascii_case(p))
        })
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::commands::dump) struct TelemetryStep {
    pub function: String,
    pub image: String,
    /// Call site in the caller, as an RVA of the caller's image.
    pub site_rva: String,
    /// `call`, `tail call`, `import` (into another image) or `syscall` (into the kernel).
    pub transition: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::commands::dump) struct TelemetrySource {
    pub kind: &'static str,
    pub function: String,
    pub image: String,
    pub fires: &'static str,
    pub consumers: &'static str,
    /// `kernel`: produced outside the calling process. `in-process`: produced in the
    /// calling process, where that process can suppress it.
    pub origin: &'static str,
    /// Call depth from the traced function.
    pub depth: usize,
    /// Distinct call sites of the sink found within the budget.
    pub occurrences: usize,
    pub path: Vec<TelemetryStep>,
    /// Heuristic path relevance, not proof that the source fired.
    pub relevance: &'static str,
    #[serde(skip)]
    order: TelemetryKind,
}

#[derive(Debug, Clone, Serialize)]
pub(in crate::commands::dump) struct TelemetryReport {
    pub function: String,
    pub image: String,
    /// Set when the traced function itself registers for or reads telemetry.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumer: Option<String>,
    pub depth_limit: usize,
    pub functions_searched: usize,
    pub function_limit: usize,
    pub budget_reached: bool,
    pub kernel_reached: bool,
    pub sources: Vec<TelemetrySource>,
    pub notes: Vec<String>,
}

/// Functions the search may expand; `--max-total unlimited` keeps a safety bound.
fn search_limit(cfg: &Config) -> usize {
    match cfg.max_total {
        0 => 262_144,
        n => n.max(TELEMETRY_MIN_FUNCTIONS),
    }
}

/// Telemetry sources often sit several calls below a syscall, so the search
/// expands far more functions than a rendered call map.
const TELEMETRY_MIN_FUNCTIONS: usize = 20_000;

/// An image visited by the search.
#[derive(Clone)]
enum SearchImage {
    Root,
    Loaded(std::rc::Rc<LoadedTraceImage>),
}

struct Pending {
    image: SearchImage,
    rva: u32,
    depth: usize,
    /// Index of this function's node in `nodes`.
    node: usize,
}

struct Node {
    function: String,
    image: String,
    site_rva: u32,
    transition: &'static str,
    parent: Option<usize>,
}

#[allow(clippy::too_many_arguments)]
pub(in crate::commands::dump) fn search(
    root_calls: &[ApiCall],
    root_insns: &[Instruction],
    function: &str,
    image_name: &str,
    session: &AnalysisSession<'_>,
    symbol_index: &SymbolIndex,
    arch: u32,
    image_base: u64,
    cfg: &Config,
    root_rva: u32,
) -> TelemetryReport {
    let root_view = TraceImageView {
        analysis: session.image(),
        symbol_index,
        exports: session.image().exports(),
        arch,
        image_base,
        dynamic: Some(session.resolution()),
    };
    let mut decode_cfg = cfg.clone();
    decode_cfg.whole_function = true;
    decode_cfg.max_insns = decode_cfg.max_insns.min(300);
    let depth_limit = cfg.telemetry_depth.max(1);
    let function_limit = search_limit(cfg);

    let mut nodes = vec![Node {
        function: function.to_owned(),
        image: image_name.to_owned(),
        site_rva: root_rva,
        transition: "call",
        parent: None,
    }];
    let mut visited: std::collections::HashSet<(String, u32)> =
        std::collections::HashSet::from([(image_name.to_ascii_lowercase(), root_rva)]);
    let mut queue: std::collections::VecDeque<Pending> = std::collections::VecDeque::new();
    let mut found: Vec<TelemetrySource> = Vec::new();
    // The traced API may itself be a source, such as AmsiScanBuffer.
    if let Some(sink) = classify(function).filter(|sink| sink.kind != Consumer) {
        found.push(TelemetrySource {
            kind: sink.kind.label(),
            function: function.to_owned(),
            image: image_name.to_owned(),
            fires: sink.fires,
            consumers: sink.consumers,
            origin: sink.kind.origin(),
            depth: 0,
            occurrences: 1,
            path: vec![TelemetryStep {
                function: function.to_owned(),
                image: image_name.to_owned(),
                site_rva: format!("0x{root_rva:08X}"),
                transition: "call",
            }],
            relevance: "direct",
            order: sink.kind,
        });
    }
    let mut expanded = 0usize;
    let mut spinner = SearchSpinner::new(cfg);
    let mut budget_reached = false;
    let mut kernel_reached = false;
    let mut kernel_unnamed: Option<String> = None;

    // The root's calls are already decoded; process them first.
    let mut pending_calls: Option<(Vec<ApiCall>, Vec<Instruction>)> =
        Some((root_calls.to_vec(), root_insns.to_vec()));
    let mut current = Pending {
        image: SearchImage::Root,
        rva: root_rva,
        depth: 0,
        node: 0,
    };

    loop {
        let decoded = match pending_calls.take() {
            Some(decoded) => Some(decoded),
            None => {
                let Some(next) = queue.pop_front() else {
                    break;
                };
                if expanded >= function_limit {
                    budget_reached = true;
                    break;
                }
                expanded += 1;
                current = next;
                spinner.update(
                    expanded,
                    current.depth,
                    found.len(),
                    &nodes[current.node].function,
                );
                decode_calls(&current, &root_view, &decode_cfg)
            }
        };
        let Some((calls, insns)) = decoded else {
            continue;
        };
        let current_image_name = match &current.image {
            SearchImage::Root => image_name.to_owned(),
            SearchImage::Loaded(image) => image.dll_name.clone(),
        };

        for call in &calls {
            let name = bare_name(&call.label).to_owned();
            let transition = if call.kind.eq_ignore_ascii_case("jmp") {
                "tail call"
            } else {
                "call"
            };
            if let Some(sink) = classify(&call.label) {
                let image = if call.is_import && !call.dll.is_empty() {
                    call.dll.clone()
                } else {
                    current_image_name.clone()
                };
                record(
                    &mut found,
                    sink,
                    &name,
                    &image,
                    &nodes,
                    current.node,
                    call.rva,
                    if call.is_import { "import" } else { transition },
                    current.depth + 1,
                );
                continue;
            }
            if current.depth + 1 >= depth_limit || is_unproductive(&name) {
                continue;
            }

            // A system call: continue in the kernel routine that services it.
            if call.is_import {
                if let Some(target) = resolve_syscall_trace_target(call, &insns, cfg) {
                    kernel_reached = true;
                    if !target.image.pdb_loaded {
                        kernel_unnamed.get_or_insert_with(|| target.image.dll_name.clone());
                    }
                    if let Some(sink) = classify(&target.symbol_name) {
                        record(
                            &mut found,
                            sink,
                            &target.symbol_name,
                            &target.image.dll_name,
                            &nodes,
                            current.node,
                            call.rva,
                            "syscall",
                            current.depth + 1,
                        );
                        continue;
                    }
                    let key = (target.image.dll_name.to_ascii_lowercase(), target.rva);
                    if visited.insert(key) {
                        nodes.push(Node {
                            function: target.symbol_name.clone(),
                            image: target.image.dll_name.clone(),
                            site_rva: call.rva,
                            transition: "syscall",
                            parent: Some(current.node),
                        });
                        queue.push_back(Pending {
                            image: SearchImage::Loaded(target.image.clone()),
                            rva: target.rva,
                            depth: current.depth + 1,
                            node: nodes.len() - 1,
                        });
                    }
                    continue;
                }
                // An import from another user-mode image: continue in its export.
                if let Some((image, rva, export)) = resolve_import(call, cfg) {
                    let key = (image.dll_name.to_ascii_lowercase(), rva);
                    if visited.insert(key) {
                        nodes.push(Node {
                            function: export,
                            image: image.dll_name.clone(),
                            site_rva: call.rva,
                            transition: "import",
                            parent: Some(current.node),
                        });
                        queue.push_back(Pending {
                            image: SearchImage::Loaded(image),
                            rva,
                            depth: current.depth + 1,
                            node: nodes.len() - 1,
                        });
                    }
                }
                continue;
            }
            if call.is_indirect || call.target_rva == 0 {
                continue;
            }
            let key = (current_image_name.to_ascii_lowercase(), call.target_rva);
            if visited.insert(key) {
                nodes.push(Node {
                    function: name,
                    image: current_image_name.clone(),
                    site_rva: call.rva,
                    transition,
                    parent: Some(current.node),
                });
                queue.push_back(Pending {
                    image: current.image.clone(),
                    rva: call.target_rva,
                    depth: current.depth + 1,
                    node: nodes.len() - 1,
                });
            }
        }
    }

    spinner.finish();

    for source in &mut found {
        source.relevance = path_relevance(source);
    }
    found.sort_by(|a, b| {
        a.order
            .cmp(&b.order)
            .then(a.depth.cmp(&b.depth))
            .then(a.function.cmp(&b.function))
    });

    let mut notes = vec![
        "Static reachability: a source fires only on the path shown, and only when its provider, session, callback or audit policy is enabled at run time.".to_owned(),
        "Indirect calls (function pointers, COM, registered callbacks themselves) are not followed.".to_owned(),
    ];
    if let Some(image) = kernel_unnamed {
        notes.push(format!(
            "{image} was traced without PDB symbols: internal dispatchers such as PspCallProcessNotifyRoutines and EtwTi* have no names to recognize. Load symbols (--sym-path / --sym-server) for full kernel coverage."
        ));
    }
    if !kernel_reached {
        notes.push("No system call was reached within the depth limit; kernel-side sources were not searched. Raise --telemetry-depth if the call should enter the kernel.".to_owned());
    }
    if budget_reached {
        notes.push(format!(
            "Search stopped at {function_limit} functions; deeper sources may be missing. Raise --max-total."
        ));
    }

    TelemetryReport {
        function: function.to_owned(),
        image: image_name.to_owned(),
        consumer: classify(function)
            .filter(|sink| sink.kind == Consumer)
            .map(|sink| sink.fires.to_owned()),
        depth_limit,
        functions_searched: expanded,
        function_limit,
        budget_reached,
        kernel_reached,
        sources: found,
        notes,
    }
}

fn decode_calls(
    pending: &Pending,
    root_view: &TraceImageView<'_>,
    cfg: &Config,
) -> Option<(Vec<ApiCall>, Vec<Instruction>)> {
    match &pending.image {
        SearchImage::Root => calls_in(root_view, pending.rva, cfg),
        SearchImage::Loaded(image) => {
            let facts = ImageFacts::new(&image.pe, &image.raw);
            let view = image.as_view(&facts);
            calls_in(&view, pending.rva, cfg)
        }
    }
}

fn calls_in(
    view: &TraceImageView<'_>,
    rva: u32,
    cfg: &Config,
) -> Option<(Vec<ApiCall>, Vec<Instruction>)> {
    let file_off = view.analysis.pe().rva_to_offset(rva)?;
    let insns = decode_traced_function(view, file_off, rva, cfg)?;
    let mut calls = collect_api_calls_in(
        &insns,
        view.analysis,
        view.symbol_index,
        view.image_base,
        cfg.hostile,
    );
    if let Some(report) = view.dynamic {
        apply_dynamic_resolution(&mut calls, &insns, report);
    }
    Some((calls, insns))
}

/// The image and export RVA an import call lands on, following one forwarder.
fn resolve_import(
    call: &ApiCall,
    cfg: &Config,
) -> Option<(std::rc::Rc<LoadedTraceImage>, u32, String)> {
    let mut dll = call.dll.clone();
    let mut name = bare_name(&call.label).to_owned();
    for _ in 0..2 {
        if dll.is_empty() || name.is_empty() || name.starts_with('#') {
            return None;
        }
        let file = if dll.contains('.') {
            dll.clone()
        } else {
            format!("{dll}.dll")
        };
        let image = load_trace_image(&file, cfg)?;
        let export = image
            .exports
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(&name))?;
        if export.forward_to.is_empty() {
            return (export.rva != 0).then(|| (image.clone(), export.rva, export.name.clone()));
        }
        let (target_dll, target_name) = export.forward_to.rsplit_once('.')?;
        dll = target_dll.to_owned();
        name = target_name.to_owned();
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn record(
    found: &mut Vec<TelemetrySource>,
    sink: &Sink,
    function: &str,
    image: &str,
    nodes: &[Node],
    parent: usize,
    site_rva: u32,
    transition: &'static str,
    depth: usize,
) {
    if let Some(existing) = found
        .iter_mut()
        .find(|s| s.function.eq_ignore_ascii_case(function))
    {
        existing.occurrences += 1;
        return;
    }
    let mut path = Vec::new();
    let mut at = Some(parent);
    while let Some(index) = at {
        let node = &nodes[index];
        path.push(TelemetryStep {
            function: node.function.clone(),
            image: node.image.clone(),
            site_rva: format!("0x{:08X}", node.site_rva),
            transition: node.transition,
        });
        at = node.parent;
    }
    path.reverse();
    path.push(TelemetryStep {
        function: function.to_owned(),
        image: image.to_owned(),
        site_rva: format!("0x{site_rva:08X}"),
        transition,
    });
    // TraceLogging and manifest writers are shared by user and kernel code; in a
    // kernel image they emit a kernel provider event the caller cannot suppress.
    let (kind, fires, consumers) = if sink.kind == EtwUser && is_kernel_image(image) {
        (
            EtwKernel,
            "kernel TraceLogging or manifest provider event",
            ETW_KERNEL,
        )
    } else {
        (sink.kind, sink.fires, sink.consumers)
    };
    found.push(TelemetrySource {
        kind: kind.label(),
        function: function.to_owned(),
        image: image.to_owned(),
        fires,
        consumers,
        origin: kind.origin(),
        depth,
        occurrences: 1,
        path,
        relevance: "direct",
        order: kind,
    });
}

/// Conservative, name-based triage of a *shortest static path*. Unknown paths
/// remain candidates; a direct label does not establish runtime execution.
fn path_relevance(source: &TelemetrySource) -> &'static str {
    let names: Vec<&str> = source
        .path
        .iter()
        .map(|step| step.function.as_str())
        .collect();
    let has = |part: &str| names.iter().any(|name| name.contains(part));
    if has("IoRaiseInformationalHardError")
        || has("MiCauseOverCommitPopup")
        || has("CarReportRuleViolation")
        || has("VfCheckUserHandle")
        || has("ObCloseHandleTableEntry")
        || has("ObQueryNameStringMode")
        || has("ObpDeregisterObject")
        || has("ObpPushStackInfo")
        || has("EtwTracePool")
        || has("KeShouldYieldProcessor")
        || has("CmpCloseKeyObject")
        || has("IopCloseFile")
        || has("MiCommitRequestFailed")
    {
        return "incidental";
    }
    if source.order == Audit
        || has("ObpAuditObjectAccess")
        || has("MiArbitraryCodeBlocked")
        || has("EtwTraceMemoryAcg")
        || has("EtwpTimLogMitigationForProcess")
    {
        return "conditional";
    }
    "direct"
}

/// Kernel images reached through system calls, and drivers.
fn is_kernel_image(image: &str) -> bool {
    let name = image.rsplit(['\\', '/']).next().unwrap_or(image);
    NT_KERNEL_IMAGES
        .iter()
        .chain(WIN32K_KERNEL_IMAGES)
        .any(|kernel| kernel.eq_ignore_ascii_case(name))
        || name.to_ascii_lowercase().ends_with(".sys")
}

/// `A → B ⇒ kernel!C → D`: `⇒` marks a system call, `↪` an import into another image.
fn format_path(path: &[TelemetryStep]) -> String {
    let mut out = String::new();
    for (index, step) in path.iter().enumerate() {
        if index > 0 {
            out.push_str(match step.transition {
                "syscall" => " ⇒ ",
                "import" => " ↪ ",
                _ => " → ",
            });
        }
        if index == 0 || step.transition != "call" && step.transition != "tail call" {
            out.push_str(&format!(
                "{}!{}",
                short_dll_name(&step.image),
                step.function
            ));
        } else {
            out.push_str(&step.function);
        }
    }
    out
}

/// Truncate to `width` display characters, marking the cut.
fn fit(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        return text.to_owned();
    }
    let mut out: String = text.chars().take(width.saturating_sub(1)).collect();
    out.push('…');
    out
}

pub(in crate::commands::dump) fn print_report(
    w: &mut dyn Write,
    report: &TelemetryReport,
    c: &Colors,
    verbose: bool,
) {
    let width = crate::core::table::output_width().max(40).saturating_sub(1);
    let incidental = report
        .sources
        .iter()
        .filter(|s| s.relevance == "incidental")
        .count();
    let visible: Vec<&TelemetrySource> = report
        .sources
        .iter()
        .filter(|s| verbose || s.relevance != "incidental")
        .collect();
    writeln!(w).ok();
    writeln!(
        w,
        "{}",
        c.bold(&c.b_yellow(&fit(&format!("Telemetry: {}", report.function), width)))
    )
    .ok();
    let direct = report
        .sources
        .iter()
        .filter(|s| s.relevance == "direct")
        .count();
    let conditional = report
        .sources
        .iter()
        .filter(|s| s.relevance == "conditional")
        .count();
    writeln!(
        w,
        "  {}",
        c.dim(&fit(
            &format!(
                "{} candidates ({} direct, {} conditional) · {} incidental{}",
                direct + conditional,
                direct,
                conditional,
                incidental,
                if verbose { "" } else { " hidden" }
            ),
            width.saturating_sub(2)
        ))
    )
    .ok();
    writeln!(
        w,
        "  {}",
        c.dim(&format!(
            "{} functions searched · depth ≤{}",
            report.functions_searched, report.depth_limit
        ))
    )
    .ok();
    if let Some(consumer) = &report.consumer {
        writeln!(w, "  {} {}", c.b_cyan("Telemetry consumer:"), consumer).ok();
    }
    if report.sources.is_empty() {
        writeln!(
            w,
            "  {}",
            c.dim("(no telemetry sources found within the search limits)")
        )
        .ok();
    }

    let mut index = 0;
    while index < visible.len() {
        let kind = visible[index].order;
        let group: Vec<&TelemetrySource> = visible[index..]
            .iter()
            .take_while(|s| s.order == kind)
            .copied()
            .collect();
        index += group.len();

        let heading = format!("{} ({})", kind.heading(), group.len());
        writeln!(w, "  {}", c.bold(&heading)).ok();

        for source in &group {
            print_verbose_source(w, source, c);
        }
    }

    // The first two notes are the standing caveats; the rest are specific to this run.
    for note in report.notes.iter().skip(2) {
        writeln!(w, "  {}", c.warning(&fit(note, width.saturating_sub(2)))).ok();
    }
    if verbose {
        for note in report.notes.iter().take(2) {
            writeln!(w, "  {}", c.dim(note)).ok();
        }
    } else {
        writeln!(
            w,
            "  {}",
            c.dim(&fit(
                "Static path triage; runtime events unverified. --verbose: incidental paths; --json: all sources.",
                width.saturating_sub(2)
            ))
        )
        .ok();
    }
}

fn print_verbose_source(w: &mut dyn Write, source: &TelemetrySource, c: &Colors) {
    let repeats = if source.occurrences > 1 {
        c.dim(&format!("  ×{}", source.occurrences))
    } else {
        String::new()
    };
    writeln!(
        w,
        "    {} {}!{}  {}{}",
        c.b_yellow("●"),
        c.cyan(short_dll_name(&source.image)),
        c.b_white(&source.function),
        c.dim(&format!(
            "[{} · depth {} · {}]",
            source.origin, source.depth, source.relevance
        )),
        repeats,
    )
    .ok();
    writeln!(w, "      {} {}", c.dim("fires    :"), source.fires).ok();
    writeln!(w, "      {} {}", c.dim("consumers:"), source.consumers).ok();
    writeln!(
        w,
        "      {} {}",
        c.dim("path     :"),
        format_path(&source.path)
    )
    .ok();
}

/// Live search status on stderr: a spinner with counts, redrawn at most ten times a
/// second. Only on an interactive stderr, never with `--quiet`.
struct SearchSpinner {
    active: bool,
    started: std::time::Instant,
    last_draw: std::time::Instant,
    frame: usize,
}

impl SearchSpinner {
    const FRAMES: [&'static str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

    fn new(cfg: &Config) -> Self {
        use std::io::IsTerminal;
        let now = std::time::Instant::now();
        Self {
            active: !cfg.quiet && std::io::stderr().is_terminal(),
            started: now,
            last_draw: now - std::time::Duration::from_secs(1),
            frame: 0,
        }
    }

    fn update(&mut self, functions: usize, depth: usize, sources: usize, current: &str) {
        if !self.active || self.last_draw.elapsed() < std::time::Duration::from_millis(100) {
            return;
        }
        self.last_draw = std::time::Instant::now();
        self.frame = (self.frame + 1) % Self::FRAMES.len();
        let status = format!(
            "{} searching telemetry  {:>6} functions · depth {} · {} source(s) · {:.0}s  {}",
            Self::FRAMES[self.frame],
            functions,
            depth,
            sources,
            self.started.elapsed().as_secs_f32(),
            current
        );
        let width = crate::core::table::output_width().clamp(40, 160) - 2;
        eprint!("\r\x1b[2K  {}", fit(&status, width));
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }

    fn finish(&self) {
        if self.active {
            eprint!("\r\x1b[2K");
            let _ = std::io::Write::flush(&mut std::io::stderr());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_sources_consumers_and_decorated_labels() {
        assert_eq!(
            classify("PspCallProcessNotifyRoutines").unwrap().kind,
            KernelCallback
        );
        assert_eq!(
            classify("EtwTiLogReadWriteVm").unwrap().kind,
            EtwThreatIntel
        );
        assert_eq!(
            classify("EtwTimLogProhibitDynamicCode").unwrap().kind,
            EtwKernel
        );
        assert_eq!(
            classify("ntdll!EtwEventWriteTransfer").unwrap().kind,
            EtwUser
        );
        assert_eq!(
            classify("tlgWriteTransfer_EtwEventWriteTransfer")
                .unwrap()
                .kind,
            EtwUser
        );
        assert_eq!(classify("_imp_AmsiScanBuffer").unwrap().kind, Amsi);
        assert_eq!(classify("CmpPostNotify").unwrap().kind, RegistryNotify);
        assert_eq!(classify("SeAuditProcessCreation").unwrap().kind, Audit);
        assert_eq!(classify("EtwTraceProcess").unwrap().kind, EtwKernel);
        assert_eq!(classify("EtwTraceProcess+0x1A").unwrap().kind, EtwKernel);
        // Consumers match before the sources that share their prefix.
        assert_eq!(classify("FwpmNetEventSubscribe0").unwrap().kind, Consumer);
        assert_eq!(classify("FwpmFilterAdd0").unwrap().kind, Wfp);
        assert_eq!(classify("ReadDirectoryChangesExW").unwrap().kind, Consumer);
        assert_eq!(classify("EvtSubscribe").unwrap().kind, Consumer);
        // Enablement checks and look-alikes are not sources.
        assert!(classify("EtwEventEnabled").is_none());
        assert!(classify("EtwTraceAutoBoostEntryExhaustion").is_none());
        assert!(classify("NtCreateUserProcess").is_none());
        assert!(classify("").is_none());
    }

    #[test]
    fn kernel_tracelogging_is_reported_as_a_kernel_source() {
        let sink = classify("tlgWriteTransfer_EtwWriteTransfer").unwrap();
        let nodes = [Node {
            function: "NtClose".into(),
            image: "ntoskrnl.exe".into(),
            site_rva: 0,
            transition: "syscall",
            parent: None,
        }];
        let mut found = Vec::new();
        record(
            &mut found,
            sink,
            "tlgWriteTransfer_EtwWriteTransfer",
            "ntoskrnl.exe",
            &nodes,
            0,
            0,
            "call",
            1,
        );
        record(
            &mut found,
            sink,
            "tlgWriteTransfer_EtwEventWriteTransfer",
            "KernelBase.dll",
            &nodes,
            0,
            0,
            "call",
            1,
        );
        assert_eq!((found[0].kind, found[0].origin), ("ETW kernel", "kernel"));
        assert_eq!(
            (found[1].kind, found[1].origin),
            ("ETW user-mode", "in-process")
        );
        // A repeated sink counts occurrences instead of adding a row.
        record(
            &mut found,
            sink,
            "tlgWriteTransfer_EtwWriteTransfer",
            "ntoskrnl.exe",
            &nodes,
            0,
            4,
            "call",
            3,
        );
        assert_eq!((found.len(), found[0].occurrences), (2, 2));
    }

    #[test]
    fn origin_separates_tamperable_in_process_sources() {
        assert_eq!(EtwUser.origin(), "in-process");
        assert_eq!(Amsi.origin(), "in-process");
        assert_eq!(EtwThreatIntel.origin(), "kernel");
        assert_eq!(KernelCallback.origin(), "kernel");
    }

    #[test]
    fn path_marks_syscall_and_import_transitions() {
        let step = |function: &str, image: &str, transition| TelemetryStep {
            function: function.into(),
            image: image.into(),
            site_rva: "0x0".into(),
            transition,
        };
        let path = [
            step("CreateProcessW", "KernelBase.dll", "call"),
            step("CreateProcessInternalW", "KernelBase.dll", "call"),
            step("NtCreateUserProcess", "ntoskrnl.exe", "syscall"),
            step("PspCallProcessNotifyRoutines", "ntoskrnl.exe", "call"),
        ];
        assert_eq!(
            format_path(&path),
            "KernelBase!CreateProcessW → CreateProcessInternalW ⇒ ntoskrnl!NtCreateUserProcess → PspCallProcessNotifyRoutines"
        );
    }
}
