#![cfg(windows)]
//! Call maps, coverage and telemetry over the local Windows system images.

use std::process::Command;

use serde_json::Value;

fn resx(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(args)
        .output()
        .expect("failed to start RESX")
}

fn json(args: &[&str]) -> Value {
    let output = resx(args);
    assert!(
        output.status.success(),
        "RESX failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("invalid RESX JSON")
}

/// Driver dispatch and IOCTL contracts describe a whole kernel image; a user-mode
/// call map must not append them.
#[test]
fn user_mode_call_map_omits_image_wide_ioctl_contracts() {
    let output = resx(&[
        "calls",
        "KernelBase.dll",
        "CreateProcessW",
        "--depth",
        "1",
        "--no-pdb",
        "--no-color",
    ]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("CreateProcessInternalW"), "{text}");
    assert!(!text.contains("IOCTL"), "unexpected IOCTL table:\n{text}");
}

/// A function with an unwind extent is decoded whole by default, so call sites
/// past the first 500 instructions are present.
#[test]
fn whole_function_decoding_reaches_the_process_creation_syscall() {
    let report = json(&[
        "dump",
        "KernelBase.dll",
        "CreateProcessInternalW",
        "--calls",
        "--no-pdb",
        "--json",
        "--quiet",
    ]);
    let dump = &report["dump"];
    let instructions = dump["instructions"].as_array().unwrap().len();
    assert!(
        instructions > 1000,
        "only {instructions} instructions decoded"
    );
    assert!(
        dump["api_calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|call| call["label"] == "NtCreateUserProcess"),
        "NtCreateUserProcess call not decoded"
    );

    // An explicit budget is still honored exactly.
    let capped = json(&[
        "dump",
        "KernelBase.dll",
        "CreateProcessInternalW",
        "--max-insns",
        "50",
        "--no-pdb",
        "--json",
        "--quiet",
    ]);
    assert_eq!(capped["dump"]["instructions"].as_array().unwrap().len(), 50);
}

/// The cross-reference sweep covers every executable byte instead of stopping at a
/// fixed instruction budget.
#[test]
fn xrefs_scan_the_whole_image() {
    let output = resx(&[
        "xrefs",
        "KernelBase.dll",
        "NtCreateUserProcess",
        "--no-pdb",
        "--no-color",
    ]);
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("CreateProcessInternalW"), "{text}");
    assert!(!text.contains("budget reached"), "{text}");
}

/// Without kernel symbols the search still crosses into the kernel and finds
/// user-mode ETW writers by their import names, and says what it could not name.
#[test]
fn telemetry_search_crosses_into_the_kernel_without_symbols() {
    let report = json(&[
        "calls",
        "KernelBase.dll",
        "CreateProcessW",
        "--depth",
        "1",
        "--telemetry",
        "--telemetry-depth",
        "4",
        "--no-pdb",
        "--json",
        "--quiet",
    ]);
    let telemetry = &report["dump"]["telemetry"];
    assert_eq!(telemetry["kernel_reached"], true, "{telemetry:#}");
    let sources = telemetry["sources"].as_array().unwrap();
    let etw = sources
        .iter()
        .find(|s| s["function"] == "EtwEventWriteTransfer")
        .unwrap_or_else(|| panic!("no user-mode ETW writer: {sources:#?}"));
    assert_eq!(etw["origin"], "in-process");
    assert_eq!(etw["path"][0]["function"], "CreateProcessW");
    assert!(
        telemetry["notes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|n| n.as_str().unwrap().contains("without PDB symbols")),
        "missing symbol note: {telemetry:#}"
    );
}

/// The process-creation telemetry an EDR relies on, found through
/// NtCreateUserProcess. Needs PDB symbols for ntoskrnl.exe (symbol server or cache).
#[test]
#[ignore = "requires PDB symbols for the local ntoskrnl.exe"]
fn telemetry_search_finds_process_creation_callbacks_audit_and_etw() {
    let report = json(&[
        "calls",
        "KernelBase.dll",
        "CreateProcessW",
        "--depth",
        "1",
        "--telemetry",
        "--json",
        "--quiet",
    ]);
    let sources = report["dump"]["telemetry"]["sources"].as_array().unwrap();
    let find = |name: &str| {
        sources
            .iter()
            .find(|s| s["function"] == name)
            .unwrap_or_else(|| panic!("{name} not found: {sources:#?}"))
    };
    let callback = find("PspCallProcessNotifyRoutines");
    assert_eq!(callback["kind"], "kernel callback");
    assert!(callback["path"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["transition"] == "syscall" && s["function"] == "NtCreateUserProcess"));
    assert_eq!(find("SeAuditProcessCreation")["kind"], "audit");
    assert_eq!(find("EtwTraceProcess")["kind"], "ETW kernel");
    assert_eq!(find("EtwTiLogAllocExecVm")["kind"], "ETW-TI");
}
