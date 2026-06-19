use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn fixture(name: &str) -> Option<PathBuf> {
    let mut roots = Vec::new();

    if let Some(workspace_dir) = Path::new(env!("CARGO_MANIFEST_DIR")).parent() {
        roots.push(workspace_dir.to_path_buf());
        if let Some(parent) = workspace_dir.parent() {
            roots.push(parent.to_path_buf());
        }
    }
    if let Ok(cwd) = std::env::current_dir() {
        roots.push(cwd);
    }

    for root in roots {
        let path = root.join("test").join(name);
        if let Ok(canonical) = path.canonicalize() {
            return Some(canonical);
        }
    }
    None
}

fn require_fixture(name: &str) -> Option<PathBuf> {
    let fixture = fixture(name);
    if fixture.is_none() {
        eprintln!("skipping json envelope test: missing fixture {}", name);
    }
    fixture
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

fn run_json_in(cwd: &Path, args: &[&str]) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_resx"))
        .current_dir(cwd)
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
    let Some(j58) = require_fixture("J58.dll") else {
        return;
    };
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

    let xrefs = run_json(&[
        "xrefs",
        j58.to_str().unwrap(),
        first_export,
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(xrefs["schema_version"], 1);
    assert_eq!(xrefs["dump"]["function"], first_export);
    assert!(xrefs["dump"]["xrefs"].as_array().is_some());

    let imports = run_json(&[
        "iat",
        j58.to_str().unwrap(),
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(imports["schema_version"], 1);
    assert!(imports["imports"].as_array().is_some());

    let diff = run_json(&[
        "diff",
        j58.to_str().unwrap(),
        j58.to_str().unwrap(),
        "--json",
        "--no-color",
        "--quiet",
        "--no-pdb",
    ]);
    assert_eq!(diff["schema_version"], 1);
    assert_eq!(diff["diff"]["summary"]["similarity_score"], 100);
    assert!(diff["diff"]["matches"]
        .as_array()
        .is_some_and(|v| !v.is_empty()));
}

#[test]
fn dump_command_resolves_explicit_relative_image_from_current_directory() {
    let exe = PathBuf::from(env!("CARGO_BIN_EXE_resx"));
    let exe_dir = exe
        .parent()
        .expect("resx test binary should have a parent directory");
    let exe_name = exe
        .file_name()
        .expect("resx test binary should have a file name")
        .to_string_lossy()
        .to_string();
    let relative = format!(".\\{exe_name}");

    let dump = run_json_in(
        exe_dir,
        &[
            "dump",
            relative.as_str(),
            "--json",
            "--no-color",
            "--quiet",
            "--no-pdb",
        ],
    );
    assert_eq!(dump["schema_version"], 1);
    assert_eq!(dump["dump"]["dll"], exe_name);
    assert!(dump["dump"]["sections"]
        .as_array()
        .is_some_and(|v| !v.is_empty()));
}

#[test]
fn symbol_and_type_commands_use_versioned_json() {
    let Some(j58) = require_fixture("J58.dll") else {
        return;
    };
    let Some(j58_pdb) = require_fixture("J58.pdb") else {
        return;
    };

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
