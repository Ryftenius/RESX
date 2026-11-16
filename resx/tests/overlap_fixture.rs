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
        "0000100d  49 bb e8 0f 00 00 00 eb 08 9f",
        "0000100f  e8 0f 00 00 00",
        "CALL  HiddenTarget",
    ] {
        assert!(output.contains(expected), "missing {expected}:\n{output}");
    }
}
