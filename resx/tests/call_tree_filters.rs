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
/// on the same object and PDB files.
fn ensure_sentinel() -> PathBuf {
    static SENTINEL: OnceLock<PathBuf> = OnceLock::new();
    SENTINEL.get_or_init(build_sentinel).clone()
}

fn build_sentinel() -> PathBuf {
    let exe = build_dir().join("resx_sentinel.exe");
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
        output.status.success() && exe.exists(),
        "resx_sentinel build failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    exe
}

/// Call tree for the CRT entry point of the stripped sentinel, which reaches the
/// real main through __scrt_common_main.
fn call_tree(exe: &Path, extra: &[&str]) -> (String, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_resx"))
        .arg("dump")
        .arg(exe)
        .args([
            "rentry",
            "--funcs-depth",
            "5",
            "--json",
            "--no-pdb",
            "--quiet",
        ])
        .args(extra)
        .output()
        .expect("failed to run resx");
    assert!(
        output.status.success(),
        "resx failed for {extra:?}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: Value = serde_json::from_slice(&output.stdout).expect("resx stdout was not json");
    let tree = json["dump"]["api_call_tree"]
        .as_str()
        .expect("api_call_tree should be a string")
        .to_owned();
    (tree, json)
}

const SCAN_CYCLE_APIS: &[&str] = &[
    "KERNEL32!CreateWaitableTimerExW",
    "KERNEL32!VirtualAlloc",
    "KERNEL32!CreateThread",
    "KERNEL32!AcquireSRWLockExclusive",
    "KERNEL32!VirtualProtect",
    "KERNEL32!VirtualQuery",
    "KERNEL32!MapViewOfFile",
    "KERNEL32!UnmapViewOfFile",
    "bcrypt!BCryptOpenAlgorithmProvider",
    "bcrypt!BCryptHashData",
    "bcrypt!BCryptFinishHash",
    "KERNEL32!CancelWaitableTimer",
];

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn sentinel_call_tree_reaches_every_scan_stage() {
    let exe = ensure_sentinel();
    let (tree, _) = call_tree(&exe, &[]);
    for api in SCAN_CYCLE_APIS {
        assert!(tree.contains(api), "missing {api} in\n{tree}");
    }
    // Calls through linker import thunks resolve to the import, not a sub_ body.
    assert!(
        !tree.contains("bcrypt!BCryptCreateHash [import · tail call]"),
        "{tree}"
    );
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn winapi_filter_drops_runtime_and_keeps_paths() {
    let exe = ensure_sentinel();
    let (tree, json) = call_tree(&exe, &["--funcs-filter", "winapi"]);
    for api in SCAN_CYCLE_APIS {
        assert!(tree.contains(api), "missing {api} in\n{tree}");
    }
    for runtime in ["api-ms-win-crt-", "VCRUNTIME140!", "ucrtbase!"] {
        assert!(
            !tree.contains(runtime),
            "runtime call {runtime} kept in\n{tree}"
        );
    }
    // The real main is anonymous without a PDB and survives only as a path node.
    assert!(
        tree.contains("sub_") && tree.contains("[internal]"),
        "{tree}"
    );
    let roots = json["dump"]["api_calls"].as_array().unwrap();
    let runtime_root = |call: &Value| {
        let dll = call["dll"]
            .as_str()
            .unwrap_or_default()
            .to_ascii_lowercase();
        dll.starts_with("api-ms-win-crt-") || dll.starts_with("vcruntime")
    };
    assert!(!roots.iter().any(runtime_root), "{roots:#?}");
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn dll_and_internal_filters_select_their_calls() {
    let exe = ensure_sentinel();

    let (bcrypt, _) = call_tree(&exe, &["--funcs-filter", "bcrypt.dll"]);
    let imports: Vec<&str> = bcrypt
        .lines()
        .filter(|line| line.contains("[import"))
        .collect();
    assert!(!imports.is_empty(), "{bcrypt}");
    assert!(
        imports.iter().all(|line| line.contains("bcrypt!")),
        "{bcrypt}"
    );

    let (internal, _) = call_tree(&exe, &["--funcs-filter", "internal"]);
    assert!(!internal.is_empty());
    assert!(!internal.contains("[import"), "{internal}");

    let (not_kernel32, _) = call_tree(&exe, &["--funcs-filter", "iat,!kernel32"]);
    assert!(not_kernel32.contains("bcrypt!"), "{not_kernel32}");
    assert!(!not_kernel32.contains("KERNEL32!"), "{not_kernel32}");
}
