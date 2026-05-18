#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const EXPORTS: &[&str] = &[
    "ResxParsePacket",
    "ResxDeviceIoctlDispatch",
    "ResxThreadCallbackEntry",
    "ResxSwitchJumpTableDispatch",
    "ResxIndirectCallMessage",
];

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("resx crate should be inside workspace")
        .to_path_buf()
}

fn corpus_root() -> PathBuf {
    workspace_root().join("resx-palace")
}

fn build_dir() -> PathBuf {
    workspace_root()
        .join("target-resx-tests")
        .join("resx-palace-test")
}

fn build_out_dir_arg() -> String {
    r"..\target-resx-tests\resx-palace-test".to_owned()
}

fn sample_path(name: &str) -> PathBuf {
    build_dir().join(name)
}

fn ensure_samples() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let dll = sample_path("resx_palace.dll");
    let variant = sample_path("resx_palace_variant.dll");
    let exe = sample_path("resx_palace_probe.exe");
    if dll.exists() && variant.exists() && exe.exists() {
        return Some((dll, variant, exe));
    }

    let script = corpus_root().join("scripts").join("build.ps1");
    let out_dir_arg = build_out_dir_arg();
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            script.to_str().unwrap(),
            "-OutDir",
            out_dir_arg.as_str(),
        ])
        .current_dir(workspace_root())
        .output()
        .expect("failed to launch resx-palace build script");

    if !output.status.success() {
        eprintln!(
            "skipping resx-palace integration test: sample build failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        return None;
    }

    if dll.exists() && variant.exists() && exe.exists() {
        Some((dll, variant, exe))
    } else {
        eprintln!("skipping resx-palace integration test: build did not produce expected samples");
        None
    }
}

fn run_resx(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(args)
        .output()
        .expect("failed to run resx");
    assert!(
        output.status.success(),
        "resx failed for {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("resx stdout was not utf-8")
}

fn run_json(args: &[&str]) -> Value {
    serde_json::from_str(&run_resx(args)).expect("resx stdout was not json")
}

fn array_contains_name(items: &Value, name: &str) -> bool {
    items
        .as_array()
        .is_some_and(|values| values.iter().any(|item| item["name"] == name))
}

#[test]
fn resx_palace_samples_exercise_binary_analysis_commands() {
    let Some((dll, variant, exe)) = ensure_samples() else {
        return;
    };
    let dll = dll.to_str().unwrap();
    let variant = variant.to_str().unwrap();
    let exe = exe.to_str().unwrap();
    let scan_root = build_dir();
    let scan_root = scan_root.to_str().unwrap();

    let peinfo = run_json(&["peinfo", dll, "--json", "--no-color", "--quiet"]);
    assert_eq!(peinfo["schema_version"], 1);
    assert_eq!(peinfo["peinfo"]["file_name"], "resx_palace.dll");
    assert!(peinfo["peinfo"]["sections"]
        .as_array()
        .is_some_and(|sections| !sections.is_empty()));

    let eat = run_json(&["eat", dll, "--json", "--no-color", "--quiet"]);
    assert_eq!(eat["schema_version"], 1);
    for expected in EXPORTS {
        assert!(
            array_contains_name(&eat["exports"], expected),
            "missing export {expected} in {eat:#}"
        );
    }

    for expected in EXPORTS {
        let dump = run_json(&["dump", dll, expected, "--json", "--no-color", "--quiet"]);
        assert_eq!(dump["schema_version"], 1);
        assert_eq!(dump["dump"]["function"], *expected);
        assert!(dump["dump"]["instructions"]
            .as_array()
            .is_some_and(|instructions| !instructions.is_empty()));
    }

    let cfg = run_resx(&[
        "cfg",
        dll,
        "ResxSwitchJumpTableDispatch",
        "--no-color",
        "--quiet",
    ]);
    assert!(cfg.contains("CFG: resx_palace.dll!ResxSwitchJumpTableDispatch"));
    assert!(
        cfg.contains("block") || cfg.contains("Basic") || cfg.contains("->"),
        "cfg output did not look like a graph:\n{cfg}"
    );

    let reconstruct = run_json(&[
        "reconstruct-cfg",
        exe,
        "--json",
        "--no-color",
        "--quiet",
        "--no-pdb",
        "--depth",
        "2",
        "--max-total",
        "64",
    ]);
    assert_eq!(reconstruct["schema_version"], 1);
    assert_eq!(
        reconstruct["reconstruct_cfg"]["image"],
        "resx_palace_probe.exe"
    );
    assert!(reconstruct["reconstruct_cfg"]["roots"]
        .as_array()
        .is_some_and(|roots| !roots.is_empty()));

    let diff = run_json(&[
        "diff",
        dll,
        dll,
        "--json",
        "--no-color",
        "--quiet",
        "--no-pdb",
    ]);
    assert_eq!(diff["schema_version"], 1);
    assert_eq!(diff["diff"]["summary"]["similarity_score"], 100);
    assert!(diff["diff"]["summary"]["exact_matches"]
        .as_u64()
        .is_some_and(|count| count > 0));

    let variant_diff = run_json(&[
        "diff",
        dll,
        variant,
        "--json",
        "--no-color",
        "--quiet",
        "--no-pdb",
        "--max-functions",
        "256",
    ]);
    assert_eq!(variant_diff["schema_version"], 1);
    let variant_score = variant_diff["diff"]["summary"]["similarity_score"]
        .as_u64()
        .unwrap_or(0);
    assert!(
        (55..100).contains(&variant_score),
        "variant diff should be related but not identical: {variant_diff:#}"
    );
    assert!(variant_diff["diff"]["summary"]["changed_matches"]
        .as_u64()
        .is_some_and(|count| count > 0));
    assert!(variant_diff["diff"]["heatmap"]["section_entropy"]
        .as_array()
        .is_some_and(|sections| !sections.is_empty()));
    assert!(variant_diff["diff"]["heatmap"]["hotspots"]
        .as_array()
        .is_some_and(|hotspots| !hotspots.is_empty()));

    let multi_diff = run_json(&[
        "diff",
        dll,
        variant,
        exe,
        "--json",
        "--no-color",
        "--quiet",
        "--no-pdb",
        "--max-functions",
        "256",
    ]);
    assert_eq!(multi_diff["schema_version"], 1);
    assert!(multi_diff["diff_matrix"]["pairs"]
        .as_array()
        .is_some_and(|pairs| pairs.len() == 3));
    assert!(multi_diff["diff_matrix"]["pairs"]
        .as_array()
        .unwrap()
        .iter()
        .all(|pair| pair["heatmap"]["signal_averages"].is_object()));

    let heatmap_dot = run_resx(&[
        "diff",
        dll,
        variant,
        "--diff-graph",
        "--diff-graph-format",
        "dot",
        "--no-pdb",
        "--max-functions",
        "256",
        "--no-color",
        "--quiet",
    ]);
    assert!(heatmap_dot.contains("digraph diff_heatmap"));
    assert!(heatmap_dot.contains("heat"));

    let cfg_diff_text = run_resx(&[
        "diff",
        dll,
        variant,
        "--show-cfg-diff",
        "ResxSwitchJumpTableDispatch",
        "--no-pdb",
        "--max-functions",
        "256",
        "--no-color",
        "--quiet",
    ]);
    assert!(cfg_diff_text.contains("CFG Diff"));
    assert!(cfg_diff_text.contains("ResxSwitchJumpTableDispatch"));
    assert!(cfg_diff_text.contains("left-only") || cfg_diff_text.contains("right-only"));

    let cfg_diff_json = run_json(&[
        "diff",
        dll,
        variant,
        "--show-cfg-diff",
        "auto",
        "--cfg-diff-format",
        "json",
        "--no-pdb",
        "--max-functions",
        "256",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(cfg_diff_json["schema_version"], 1);
    assert!(cfg_diff_json["cfg_diff"]["blocks"]
        .as_array()
        .is_some_and(|blocks| !blocks.is_empty()));

    let cfg_diff_dot = run_resx(&[
        "diff",
        dll,
        variant,
        "--show-cfg-diff",
        "ResxSwitchJumpTableDispatch",
        "--cfg-diff-format",
        "dot",
        "--no-pdb",
        "--max-functions",
        "256",
        "--no-color",
        "--quiet",
    ]);
    assert!(cfg_diff_dot.contains("digraph cfg_diff"));
    assert!(cfg_diff_dot.contains("cluster_left"));

    let db_path = sample_path("resx_palace.resxdb");
    let db = db_path.to_str().unwrap();
    let index = run_json(&[
        "index",
        scan_root,
        "--db",
        db,
        "--extensions",
        "exe,dll",
        "--max-files",
        "8",
        "--max-functions",
        "256",
        "--no-pdb",
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(index["schema_version"], 1);
    assert!(index["index"]["images"]
        .as_array()
        .is_some_and(|images| images.len() >= 3));

    let hunt = run_json(&[
        "hunt",
        variant,
        "--db",
        db,
        "--diff-threshold",
        "55",
        "--max-candidates",
        "8",
        "--max-functions",
        "256",
        "--no-pdb",
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(hunt["schema_version"], 1);
    let candidates = hunt["hunt"]["candidates"]
        .as_array()
        .expect("hunt candidates should be an array");
    assert!(candidates
        .iter()
        .any(|item| item["name"] == "resx_palace.dll"));
    let base = candidates
        .iter()
        .find(|item| item["name"] == "resx_palace.dll")
        .expect("missing base DLL hunt candidate");
    assert!(
        base["unique_score"].as_u64().unwrap_or(0) >= 55,
        "base DLL should retain a useful unique-code score: {hunt:#}"
    );

    let scan = run_json(&[
        "scan",
        scan_root,
        "--extensions",
        "exe,dll",
        "--max-files",
        "8",
        "--max-candidates",
        "16",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(scan["schema_version"], 1);
    assert_eq!(scan["kind"], "scan");
    let results = scan["results"]
        .as_array()
        .expect("scan results should be an array");
    assert!(results.iter().any(|item| item["name"] == "resx_palace.dll"));
    assert!(results
        .iter()
        .any(|item| item["name"] == "resx_palace_variant.dll"));
    assert!(results
        .iter()
        .any(|item| item["name"] == "resx_palace_probe.exe"));

    let dll_report = results
        .iter()
        .find(|item| item["name"] == "resx_palace.dll")
        .expect("missing DLL scan report");
    for expected in [
        "ResxParsePacket",
        "ResxDeviceIoctlDispatch",
        "ResxThreadCallbackEntry",
        "ResxSwitchJumpTableDispatch",
        "ResxIndirectCallMessage",
    ] {
        assert!(
            array_contains_name(&dll_report["candidates"], expected),
            "missing scan candidate {expected} in {dll_report:#}"
        );
    }
}
