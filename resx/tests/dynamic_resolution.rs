#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use serde_json::Value;

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("resx crate should be inside workspace")
        .to_path_buf()
}

fn build_dir() -> PathBuf {
    let target =
        PathBuf::from(std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_owned()));
    if target.is_absolute() {
        target.join("resx-fixtures-test")
    } else {
        workspace_root().join(target).join("resx-fixtures-test")
    }
}

/// Builds the fixtures once per test process; parallel tests would otherwise race
/// on the same object files.
fn fixture(name: &str) -> PathBuf {
    static BUILT: OnceLock<()> = OnceLock::new();
    BUILT.get_or_init(|| {
        let script = workspace_root()
            .join("resx-fixtures")
            .join("scripts")
            .join("build.ps1");
        let output = Command::new("powershell")
            .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-File"])
            .arg(&script)
            .arg("-OutDir")
            .arg(build_dir())
            .current_dir(workspace_root())
            .output()
            .expect("failed to launch resx-fixtures build script");
        assert!(
            output.status.success(),
            "fixture build failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    });
    let exe = build_dir().join(format!("{name}.exe"));
    assert!(exe.exists(), "fixture {} was not built", exe.display());
    exe
}

fn resx_json(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(args)
        .args(["--json", "--no-pdb", "--quiet"])
        .output()
        .expect("failed to run resx");
    assert!(
        output.status.success(),
        "resx {args:?} failed\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("resx stdout was not json")
}

fn behavior(name: &str) -> Value {
    let exe = fixture(name);
    resx_json(&["behavior", exe.to_str().unwrap()])["behavior"].clone()
}

fn module_stem(module: &str) -> String {
    let lower = module.to_ascii_lowercase();
    lower.strip_suffix(".dll").unwrap_or(&lower).to_owned()
}

/// Every expected `(module, api, source)` was resolved, and the pointer is called.
fn assert_resolved(report: &Value, expected: &[(&str, &str, &str)]) {
    let resolved = report["resolved_apis"]
        .as_array()
        .unwrap_or_else(|| panic!("no resolved_apis in {report:#}"));
    for (module, api, source) in expected {
        let hit = resolved.iter().find(|entry| entry["api"] == *api);
        let hit = hit.unwrap_or_else(|| panic!("{api} was not resolved in {report:#}"));
        assert_eq!(
            module_stem(hit["module"].as_str().unwrap_or("?")),
            *module,
            "wrong module for {api}: {hit:#}"
        );
        assert!(
            hit["api_source"]
                .as_str()
                .is_some_and(|actual| actual.starts_with(source)),
            "wrong source for {api}, expected {source}: {hit:#}"
        );
        assert!(
            hit["call_sites"]
                .as_array()
                .is_some_and(|sites| !sites.is_empty()),
            "no call through the resolved {api}: {hit:#}"
        );
    }
}

fn rules(report: &Value) -> Vec<(String, String)> {
    report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|finding| finding["category"] == "api-resolution")
        .map(|finding| {
            (
                finding["rule"].as_str().unwrap().to_owned(),
                finding["severity"].as_str().unwrap().to_owned(),
            )
        })
        .collect()
}

const PLAIN: &[(&str, &str, &str)] = &[
    ("ws2_32", "#115", "ordinal"),
    ("ws2_32", "WSACleanup", "literal"),
    ("kernel32", "GetTickCount", "literal"),
    ("kernel32", "VirtualAlloc", "literal"),
    ("kernel32", "VirtualFree", "literal"),
    ("advapi32", "RegOpenKeyExW", "literal"),
    ("advapi32", "RegCloseKey", "literal"),
];

const OBFUSCATED: &[(&str, &str, &str)] = &[
    ("kernel32", "CreateThread", "xor 0x5A"),
    ("user32", "GetSystemMetrics", "sub 0x03"),
    ("kernel32", "GetCurrentThreadId", "stack string"),
    ("advapi32", "GetUserNameW", "xor 0x5A"),
    ("kernel32", "VirtualProtect", "rolling xor 0x31+i"),
];

const PEB: &[(&str, &str, &str)] = &[
    ("kernel32", "VirtualAlloc", "ror13-add hash 0x91AFCA54"),
    ("kernel32", "VirtualFree", "ror13-add hash 0x30633AC"),
    ("ntdll", "RtlGetVersion", "fnv-1a hash 0xCDC95E31"),
    ("kernel32", "QueryPerformanceCounter", "literal"),
    ("kernel32", "GetTickCount", "literal"),
    ("kernel32", "Sleep", "ror13-add hash 0xDB2D49B0"),
];

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn plain_loader_lookups_are_resolved_and_graded_low() {
    for name in ["dynres_plain", "dynres_plain_x86"] {
        let report = behavior(name);
        assert_resolved(&report, PLAIN);
        assert_eq!(report["api_resolution"], "loader API by name", "{name}");
        assert_eq!(
            rules(&report),
            [("loader-api-resolution".to_owned(), "low".to_owned())],
            "{name}: the PEB and header reads in BenignProbes are not walks"
        );
    }
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn hidden_names_are_decoded_and_graded_by_technique() {
    for name in ["dynres_obfuscated", "dynres_obfuscated_x86"] {
        let report = behavior(name);
        assert_resolved(&report, OBFUSCATED);
        let rules = rules(&report);
        assert!(
            rules.contains(&("encoded-api-names".to_owned(), "high".to_owned())),
            "{name}: {rules:?}"
        );
        assert!(
            rules.contains(&("stack-string-api-names".to_owned(), "medium".to_owned())),
            "{name}: {rules:?}"
        );
        assert!(
            !rules
                .iter()
                .any(|(rule, _)| rule == "unrecovered-api-names"),
            "{name}: the static CRT's own lookups are recovered: {rules:?}"
        );
        let advapi = report["resolved_apis"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["api"] == "GetUserNameW")
            .unwrap();
        assert_eq!(
            advapi["module_source"], "rolling xor 0x2B+i (UTF-16)",
            "{name}"
        );
    }
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn loader_list_walks_and_hashes_are_inverted() {
    for name in ["dynres_peb", "dynres_peb_x86"] {
        let report = behavior(name);
        assert_resolved(&report, PEB);
        let rules = rules(&report);
        for rule in [
            "peb-module-walk",
            "api-hashing",
            "export-table-walk",
            "import-table-walk",
        ] {
            assert!(
                rules
                    .iter()
                    .any(|(found, severity)| found == rule && severity == "high"),
                "{name}: missing high {rule} in {rules:?}"
            );
        }
        let virtual_alloc = report["resolved_apis"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["api"] == "VirtualAlloc")
            .unwrap();
        assert_eq!(
            virtual_alloc["module_source"], "loader-list walk, djb2 hash 0x7040EE75",
            "{name}"
        );
    }
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn call_tree_labels_calls_through_resolved_pointers() {
    let exe = fixture("dynres_peb");
    let json = resx_json(&[
        "dump",
        exe.to_str().unwrap(),
        "rentry",
        "--funcs-depth",
        "5",
        "--funcs-filter",
        "dynamic",
    ]);
    let tree = json["dump"]["api_call_tree"].as_str().unwrap();
    for line in [
        "call  kernel32!VirtualAlloc [dynamic]",
        "resolves: kernel32!VirtualAlloc (export-table walk",
        "call  ntdll!RtlGetVersion [dynamic]",
        "call  KERNEL32!QueryPerformanceCounter [dynamic]",
        "call  kernel32!Sleep [dynamic]",
    ] {
        assert!(tree.contains(line), "missing {line:?} in\n{tree}");
    }
    assert!(
        !tree.contains("[via r"),
        "unresolved indirect call kept in\n{tree}"
    );

    let plain = fixture("dynres_plain");
    let json = resx_json(&[
        "dump",
        plain.to_str().unwrap(),
        "rentry",
        "--funcs-depth",
        "5",
        "--funcs-filter",
        "dynamic",
    ]);
    let tree = json["dump"]["api_call_tree"].as_str().unwrap();
    for line in [
        // Through the global API table, filled in another function.
        "call  ws2_32!#115 [dynamic]",
        "call  kernel32!GetTickCount [dynamic]",
        // A CFG-guarded tail jump through the resolved pointer.
        "jmp  kernel32!VirtualFree [dynamic]",
        // Resolved through the Resolve(dll, name) wrapper.
        "call  advapi32!RegOpenKeyExW [dynamic]",
        "resolves: advapi32!RegOpenKeyExW (GetProcAddress)",
    ] {
        assert!(tree.contains(line), "missing {line:?} in\n{tree}");
    }
}
