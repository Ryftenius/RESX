use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("test")
        .join(name)
}

fn run_json(args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(args)
        .output()
        .expect("failed to run resx");
    assert!(
        output.status.success(),
        "resx failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("invalid json")
}

#[test]
fn peinfo_dump_and_metadata_commands_use_versioned_json() {
    let j58 = fixture("J58.dll");
    let peinfo = run_json(&[
        "peinfo",
        j58.to_str().unwrap(),
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(peinfo["schema_version"], 1);
    assert_eq!(peinfo["peinfo"]["file_name"], "J58.dll");
    assert!(peinfo["peinfo"]["sections"]
        .as_array()
        .is_some_and(|v| !v.is_empty()));

    let exports = run_json(&[
        "eat",
        j58.to_str().unwrap(),
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(exports["schema_version"], 1);
    let first_export = exports["exports"]
        .as_array()
        .and_then(|items| items.first())
        .and_then(|entry| entry["name"].as_str())
        .expect("expected at least one export");

    let dump = run_json(&[
        "dump",
        j58.to_str().unwrap(),
        first_export,
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(dump["schema_version"], 1);
    assert_eq!(dump["dump"]["function"], first_export);
    assert!(dump["dump"]["instructions"]
        .as_array()
        .is_some_and(|v| !v.is_empty()));

    let imports = run_json(&[
        "iat",
        j58.to_str().unwrap(),
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(imports["schema_version"], 1);
    assert!(imports["imports"].as_array().is_some());
}

#[test]
fn symbol_and_type_commands_use_versioned_json() {
    let j58 = fixture("J58.dll");
    let j58_pdb = fixture("J58.pdb");

    let syms = run_json(&[
        "syms",
        j58.to_str().unwrap(),
        "--pdb",
        j58_pdb.to_str().unwrap(),
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(syms["schema_version"], 1);
    assert!(syms["symbols"].as_array().is_some_and(|v| !v.is_empty()));

    let types = run_json(&[
        "types",
        j58.to_str().unwrap(),
        "--pdb",
        j58_pdb.to_str().unwrap(),
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(types["schema_version"], 1);
    assert!(types["types"].as_array().is_some());
}

#[test]
fn explain_command_uses_versioned_json() {
    let explain = run_json(&[
        "explain",
        "NtQuerySystemInformation",
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(explain["schema_version"], 1);
    assert_eq!(explain["explain"]["query"], "NtQuerySystemInformation");
}
