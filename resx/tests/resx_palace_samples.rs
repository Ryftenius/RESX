#![cfg(windows)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

const EXPORTS: &[&str] = &[
    "ResxParsePacket",
    "ResxDeviceIoctlDispatch",
    "ResxThreadCallbackEntry",
    "ResxSwitchJumpTableDispatch",
    "ResxIndirectCallMessage",
    "ResxBehaviorSignals",
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
    let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_owned());
    let target = PathBuf::from(target);
    if target.is_absolute() {
        target.join("resx-palace-test")
    } else {
        workspace_root().join(target).join("resx-palace-test")
    }
}

fn build_out_dir_arg() -> String {
    let target = std::env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".to_owned());
    let target = PathBuf::from(target);
    let out = if target.is_absolute() {
        target.join("resx-palace-test")
    } else {
        PathBuf::from("..").join(target).join("resx-palace-test")
    };
    out.to_string_lossy().to_string()
}

fn sample_path(name: &str) -> PathBuf {
    build_dir().join(name)
}

fn ensure_samples() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let dll = sample_path("resx_palace.dll");
    let variant = sample_path("resx_palace_variant.dll");
    let exe = sample_path("resx_palace_probe.exe");

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

fn parse_hex_u64(value: &Value) -> u64 {
    let text = value.as_str().expect("expected hex string");
    u64::from_str_radix(text.trim_start_matches("0x"), 16).expect("valid hex string")
}

fn hex_byte(value: u8) -> String {
    format!("{value:02X}")
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

    let import_xrefs = run_json(&[
        "xrefs",
        dll,
        "CreateFileW",
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(import_xrefs["schema_version"], 1);
    assert_eq!(import_xrefs["dump"]["function"], "CreateFileW");
    assert_eq!(import_xrefs["dump"]["is_import_slot"], true);
    assert_eq!(import_xrefs["dump"]["import_target_dll"], "KERNEL32.dll");
    assert_eq!(import_xrefs["dump"]["import_target_name"], "CreateFileW");
    assert!(
        import_xrefs["dump"]["instructions"].is_null()
            || import_xrefs["dump"]["instructions"]
                .as_array()
                .is_some_and(|instructions| instructions.is_empty())
    );
    assert!(import_xrefs["dump"]["xrefs"]
        .as_array()
        .is_some_and(|xrefs| !xrefs.is_empty()));

    let image_base = parse_hex_u64(&peinfo["peinfo"]["image_base"]);
    let inner_parse_packet_va = format!("0x{:X}", image_base + 0x1205);
    for args in [
        vec![
            "dump",
            dll,
            "--at",
            inner_parse_packet_va.as_str(),
            "--json",
            "--no-color",
            "--quiet",
            "--no-pdb",
        ],
        vec![
            "dump",
            dll,
            "--at",
            "file:0x600",
            "--json",
            "--no-color",
            "--quiet",
            "--no-pdb",
        ],
        vec![
            "dump",
            dll,
            "0x1205",
            "--json",
            "--no-color",
            "--quiet",
            "--no-pdb",
        ],
    ] {
        let dump_at = run_json(&args);
        assert_eq!(dump_at["dump"]["function"], "ResxParsePacket");
        assert_eq!(dump_at["dump"]["rva"], "0x00001200");
        assert_eq!(dump_at["dump"]["instructions"][0]["rva"], "0x00001200");
    }

    let patch_out = build_dir().join("resx_palace.patch-test.dll");
    let _ = fs::remove_file(&patch_out);
    let patch_out = patch_out.to_str().unwrap();
    let original_raw = fs::read(dll).expect("read resx-palace dll");
    let patch_file_offset = 0x600usize;
    let original_byte = original_raw[patch_file_offset];
    let replacement_byte = if original_byte == 0x90 { 0xCC } else { 0x90 };
    let original_hex = hex_byte(original_byte);
    let replacement_hex = hex_byte(replacement_byte);

    let patch_dry_run = run_json(&[
        "patch",
        dll,
        "--at",
        "file:0x600",
        "--patch-bytes",
        replacement_hex.as_str(),
        "--expect",
        original_hex.as_str(),
        "--dry-run",
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(patch_dry_run["schema_version"], 1);
    assert_eq!(patch_dry_run["patch"]["write"]["performed"], false);
    assert_eq!(patch_dry_run["patch"]["address"]["rva"], "0x00001200");
    assert_eq!(
        patch_dry_run["patch"]["bytes"]["replacement"],
        replacement_hex
    );

    let second_replacement_byte = if original_raw[patch_file_offset + 1] == 0x90 {
        0xCC
    } else {
        0x90
    };
    let original_pair_hex = format!(
        "{} {}",
        hex_byte(original_raw[patch_file_offset]),
        hex_byte(original_raw[patch_file_offset + 1])
    );
    let second_replacement_hex = hex_byte(second_replacement_byte);
    let replacement_pair_hex = format!("{} {}", replacement_hex, second_replacement_hex);
    let patch_unquoted_bytes = run_json(&[
        "patch",
        dll,
        "--at",
        "file:0x600",
        "--patch-bytes",
        replacement_hex.as_str(),
        second_replacement_hex.as_str(),
        "--expect",
        original_pair_hex.as_str(),
        "--dry-run",
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(patch_unquoted_bytes["patch"]["bytes"]["length"], 2);
    assert_eq!(
        patch_unquoted_bytes["patch"]["bytes"]["replacement"],
        replacement_pair_hex
    );

    let patch = run_json(&[
        "patch",
        dll,
        "file:0x600",
        replacement_hex.as_str(),
        "--expect",
        original_hex.as_str(),
        "--patch-out",
        patch_out,
        "--update-checksum",
        "--json",
        "--no-color",
        "--quiet",
    ]);
    assert_eq!(patch["schema_version"], 1);
    assert_eq!(patch["patch"]["image"], "resx_palace.dll");
    assert_eq!(patch["patch"]["address"]["file_offset"], "0x00000600");
    assert_eq!(patch["patch"]["bytes"]["original"], original_hex);
    assert_eq!(patch["patch"]["bytes"]["replacement"], replacement_hex);
    assert_eq!(patch["patch"]["write"]["performed"], true);
    assert_eq!(patch["patch"]["checksum"]["updated"], true);
    assert!(patch["patch"]["checksum"]["new"].as_str().is_some());

    let source_after_patch = fs::read(dll).expect("read original after patch copy");
    let patched_raw = fs::read(patch_out).expect("read patched copy");
    assert_eq!(source_after_patch, original_raw);
    assert_eq!(patched_raw.len(), original_raw.len());
    assert_eq!(patched_raw[patch_file_offset], replacement_byte);
    assert_ne!(
        patched_raw[patch_file_offset],
        original_raw[patch_file_offset]
    );
    let _ = fs::remove_file(patch_out);

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

    let behavior = run_json(&["behavior", dll, "--json", "--no-color", "--quiet"]);
    assert_eq!(behavior["schema_version"], 1);
    assert_eq!(behavior["behavior"]["image"], "resx_palace.dll");
    let behavior_findings = behavior["behavior"]["findings"]
        .as_array()
        .expect("behavior findings should be an array");
    for expected_rule in [
        "tls-callback",
        "cpuid-check",
        "int3-breakpoint",
        "syscall-stub-pattern",
        "executable-memory-api",
        "dynamic-loader-api",
    ] {
        assert!(
            behavior_findings
                .iter()
                .any(|item| item["rule"] == expected_rule),
            "missing behavior rule {expected_rule} in {behavior:#}"
        );
    }

    let unpack = run_json(&["unpack", dll, "--json", "--no-color", "--quiet"]);
    assert_eq!(unpack["schema_version"], 1);
    assert_eq!(unpack["unpack"]["image"], "resx_palace.dll");
    let protector_hints = unpack["unpack"]["protector_hints"]
        .as_array()
        .expect("unpack protector_hints should be an array");
    for expected_rule in ["upx-marker", "vmprotect-themida-marker"] {
        assert!(
            protector_hints
                .iter()
                .any(|item| item["rule"] == expected_rule),
            "missing unpack protector rule {expected_rule} in {unpack:#}"
        );
    }
    assert!(unpack["unpack"]["oep_candidates"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(unpack["unpack"]["import_rebuild_hints"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(unpack["unpack"]["vm_candidates"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(unpack["unpack"]["layer2"]["oep_windows"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(unpack["unpack"]["layer2"]["import_plan"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(unpack["unpack"]["layer2"]["vm_sketches"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));

    let entropy = run_json(&[
        "entropy",
        dll,
        "--json",
        "--no-color",
        "--quiet",
        "--entropy-window",
        "512",
        "--entropy-stride",
        "512",
    ]);
    assert_eq!(entropy["schema_version"], 1);
    assert_eq!(entropy["entropy"]["image"], "resx_palace.dll");
    assert!(entropy["entropy"]["windows"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
    assert!(entropy["entropy"]["summary"]["window_count"]
        .as_u64()
        .is_some_and(|count| count > 0));

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
