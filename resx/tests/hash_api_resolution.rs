#![cfg(windows)]

use std::path::Path;
use std::process::Command;

use serde_json::Value;

/// `hash_resolver.exe` finds modules and exports by ROR13 hash; no API name is in the image.
#[test]
fn ror13_hashes_are_inverted_and_linked_to_indirect_calls() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/hash_resolver.exe");
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
    assert!(
        behavior["api_resolution"]
            .as_str()
            .is_some_and(|verdict| verdict.contains("API hashing (ror13-add)")),
        "hashing not reported: {}",
        behavior["api_resolution"]
    );
    let resolved = behavior["resolved_apis"]
        .as_array()
        .expect("missing resolved APIs");
    let expected = [
        ("LoadLibraryA", "0xEC0E4E8E"),
        ("VirtualAlloc", "0x91AFCA54"),
        ("VirtualProtect", "0x7946C61B"),
        ("VirtualFree", "0x30633AC"),
        ("GetComputerNameW", "0x96A422A5"),
        ("GetUserNameW", "0x5C52AA4A"),
    ];
    for (api, hash) in expected {
        let hit = resolved
            .iter()
            .find(|entry| entry["api"] == api)
            .unwrap_or_else(|| panic!("{api} not recovered: {resolved:#?}"));
        assert_eq!(
            hit["api_source"],
            format!("ror13-add hash {hash}"),
            "wrong hash for {api}"
        );
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
