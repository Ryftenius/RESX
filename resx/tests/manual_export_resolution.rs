#![cfg(windows)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

#[test]
fn xor_names_and_manual_export_walk_are_linked_to_indirect_calls() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/manual_resolver.exe");
    let output = Command::new(env!("CARGO_BIN_EXE_resx"))
        .arg("behavior")
        .arg(&fixture)
        .args(["--json", "--no-pdb", "--no-headers", "--quiet"])
        .output()
        .expect("failed to start RESX");
    assert!(
        output.status.success(),
        "RESX failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("invalid RESX JSON");
    let behavior = &report["behavior"];
    let resolved = behavior["resolved_apis"]
        .as_array()
        .expect("missing resolved APIs");
    let expected = [
        "VirtualAlloc",
        "VirtualProtect",
        "VirtualFree",
        "FindFirstFileW",
        "FindNextFileW",
        "FindClose",
        "GetLastError",
    ];
    assert_eq!(
        resolved.len(),
        expected.len(),
        "unexpected resolutions: {resolved:#?}"
    );
    for api in expected {
        let hit = resolved
            .iter()
            .find(|entry| entry["api"] == api)
            .unwrap_or_else(|| panic!("{api} not recovered: {resolved:#?}"));
        assert_eq!(hit["module"], "kernelbase.dll", "wrong module for {api}");
        assert_eq!(hit["api_source"], "xor 0x5A", "wrong decoding for {api}");
        assert!(
            hit["method"]
                .as_str()
                .unwrap()
                .contains("export-table walk"),
            "wrong resolver for {api}: {hit:#?}"
        );
        assert!(
            hit["call_sites"]
                .as_array()
                .is_some_and(|sites| !sites.is_empty()),
            "no indirect call linked to {api}: {hit:#?}"
        );
    }
}
