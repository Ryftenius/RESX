#![cfg(windows)]

use std::path::Path;
use std::process::Command;

#[test]
fn public_overlap_fixture_exposes_both_streams_and_hidden_call() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/overlap_probe.exe");
    let result = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(["dump", fixture.to_str().unwrap(), "OverlapProbe"])
        .args(["--bytes", "--calls", "--no-pdb", "--no-color"])
        .output()
        .expect("run RESX on public overlap fixture");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let output = String::from_utf8(result.stdout).unwrap();
    for expected in [
        "* marks instructions involved in overlapping decode streams:",
        "0x0000100f starts inside instruction at 0x0000100d",
        "*0000100d",
        "*0000100f",
        "... Continuation of 0x0000100d",
        "... Continuation of 0x0000100f",
        "0000100d  49 bb e8 0f 00 00 00 eb 08 9f",
        "0000100f  e8 0f 00 00 00",
        "CALL  HiddenTarget",
    ] {
        assert!(output.contains(expected), "missing {expected}:\n{output}");
    }
    let carrier = output.find("*0000100d").unwrap();
    let carrier_continuation = output.find("│00001017  b8 22 00 00 c0").unwrap();
    let alternate = output.find("*0000100f").unwrap();
    assert!(carrier < carrier_continuation && carrier_continuation < alternate);
}

#[test]
fn overlap_is_clear_without_instruction_bytes() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/overlap_probe.exe");
    let result = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(["dump", fixture.to_str().unwrap(), "OverlapProbe"])
        .args(["--calls", "--no-pdb", "--no-color"])
        .output()
        .expect("run RESX on public overlap fixture");
    assert!(result.status.success());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("0x0000100f starts inside instruction at 0x0000100d"));
    assert!(output.contains("*0000100f  call"));
    assert!(!output.contains("0000100f  e8 0f 00 00 00"));
}

#[test]
fn overlapping_paths_have_distinct_terminal_colors() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/overlap_probe.exe");
    let result = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(["dump", fixture.to_str().unwrap(), "OverlapProbe"])
        .args(["--bytes", "--no-pdb", "--color"])
        .output()
        .expect("run RESX with terminal colors forced");
    assert!(result.status.success());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("\x1b[94m*\x1b[0m\x1b[94m0000100d\x1b[0m"));
    assert!(output.contains("\x1b[95m*\x1b[0m\x1b[95m0000100f\x1b[0m"));
}

#[test]
fn ordinary_function_keeps_compact_listing() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/overlap_probe.exe");
    let result = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(["dump", fixture.to_str().unwrap(), "HiddenTarget"])
        .args(["--no-pdb", "--no-color"])
        .output()
        .expect("run RESX on ordinary exported function");
    assert!(result.status.success());
    let output = String::from_utf8(result.stdout).unwrap();
    assert!(output.contains("00001023  xor"));
    assert!(!output.contains("* marks instructions involved in overlapping decode streams"));
}
