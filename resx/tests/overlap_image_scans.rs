#![cfg(windows)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn temporary_fixture(
    name: &str,
    carrier: Option<&[u8; 10]>,
    je_displacement: u8,
) -> (PathBuf, PathBuf) {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "resx-overlap-scan-{}-{unique}-{name}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let mut bytes =
        std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/overlap_probe.exe"))
            .unwrap();
    let marker = [0x49, 0xbb, 0xe8, 0x0f, 0, 0, 0, 0xeb, 0x08, 0x9f];
    let offset = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .unwrap();
    assert_eq!(&bytes[offset - 4..offset], &[0x74, 0x04, 0xeb, 0x00]);
    bytes[offset - 3] = je_displacement;
    if let Some(carrier) = carrier {
        bytes[offset..offset + carrier.len()].copy_from_slice(carrier);
    }
    let path = dir.join(format!("{name}.exe"));
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

fn add_self_import(bytes: &mut [u8]) {
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let opt = pe + 24;
    let section_table =
        opt + u16::from_le_bytes(bytes[pe + 20..pe + 22].try_into().unwrap()) as usize;
    // Use spare .rdata bytes for one import descriptor, ILT, IAT, and name.
    // The import slot is at RVA 0x2158.
    bytes[section_table + 40 + 8..section_table + 40 + 12].copy_from_slice(&0x200u32.to_le_bytes());
    bytes[opt + 120..opt + 128].copy_from_slice(&[0x20, 0x21, 0, 0, 40, 0, 0, 0]);
    bytes[0x720..0x734].fill(0);
    bytes[0x720..0x724].copy_from_slice(&0x2148u32.to_le_bytes());
    bytes[0x72c..0x730].copy_from_slice(&0x2168u32.to_le_bytes());
    bytes[0x730..0x734].copy_from_slice(&0x2158u32.to_le_bytes());
    bytes[0x748..0x750].copy_from_slice(&0x2180u64.to_le_bytes());
    bytes[0x758..0x760].copy_from_slice(&0x2180u64.to_le_bytes());
    bytes[0x768..0x770].copy_from_slice(b"iat.exe\0");
    bytes[0x782..0x78f].copy_from_slice(b"HiddenTarget\0");
}

fn run(path: &Path, dir: &Path, command: &str, overlap: bool) -> String {
    let mut args = vec![command, path.to_str().unwrap(), "HiddenTarget"];
    if command == "callers" {
        args.extend([
            "--no-system",
            "--scan-exe",
            "--format",
            "flat",
            "--show-site",
            "--depth",
            "1",
        ]);
    }
    args.extend(["--no-pdb", "--no-color"]);
    if overlap {
        args.push("--overlap-seams");
    }
    let result = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args(args)
        .env("LOCALAPPDATA", dir.join("cache"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{command}: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8(result.stdout).unwrap()
}

#[test]
fn image_wide_scans_follow_three_distinct_seam_shapes_only_when_enabled() {
    // The call sits at carrier+2 in a mov imm64, at +1 in a push imm32,
    // and at +3 in an imul imm32. All rel32 operands point to HiddenTarget.
    for (name, carrier, branch, site) in [
        ("mov", None, 0x04, "0x0000100F"),
        (
            "push",
            Some([0x68, 0xe8, 0x10, 0, 0, 0, 0xeb, 0x09, 0x90, 0x90]),
            0x03,
            "0x0000100E",
        ),
        (
            "imul",
            Some([0x48, 0x69, 0xc0, 0xe8, 0x0e, 0, 0, 0, 0xeb, 0x07]),
            0x05,
            "0x00001010",
        ),
    ] {
        let (dir, path) = temporary_fixture(name, carrier.as_ref(), branch);
        let xrefs_default = run(&path, &dir, "xrefs", false);
        assert!(
            xrefs_default.contains("Cross References:\n  (none)"),
            "{name}: {xrefs_default}"
        );
        let xrefs_overlap = run(&path, &dir, "xrefs", true);
        assert!(
            xrefs_overlap.contains(&format!("[site {site}] -> HiddenTarget")),
            "{name}: {xrefs_overlap}"
        );
        assert!(
            xrefs_overlap.contains("[overlap seam]"),
            "{name}: {xrefs_overlap}"
        );

        // Run the default mode again after the opt-in index is cached. A
        // cached overlap-aware index must not leak into the default scan.
        let callers_overlap = run(&path, &dir, "callers", true);
        assert!(
            callers_overlap.contains(&format!("{name}.exe!OverlapProbe")),
            "{name}: {callers_overlap}"
        );
        assert!(
            callers_overlap.contains("1 total caller references"),
            "{name}: {callers_overlap}"
        );
        assert!(
            callers_overlap.contains(&format!("call@{site}")),
            "{name}: {callers_overlap}"
        );
        let callers_default = run(&path, &dir, "callers", false);
        assert!(
            callers_default.contains("0 total caller references"),
            "{name}: {callers_default}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }
}

#[test]
fn seam_indirect_call_requires_a_real_import_slot() {
    let (dir, path) = temporary_fixture(
        "iat",
        Some(&[0x49, 0xbb, 0xff, 0x15, 0x43, 0x11, 0, 0, 0xeb, 0x07]),
        0x04,
    );
    let mut bytes = std::fs::read(&path).unwrap();
    add_self_import(&mut bytes);
    std::fs::write(&path, &bytes).unwrap();

    let no_flag = run(&path, &dir, "callers", false);
    assert!(no_flag.contains("0 total caller references"), "{no_flag}");
    let with_flag = run(&path, &dir, "callers", true);
    assert!(
        with_flag.contains("1 total caller references"),
        "{with_flag}"
    );
    assert!(with_flag.contains("call@0x0000100F"), "{with_flag}");
    let result = Command::new(env!("CARGO_BIN_EXE_resx"))
        .args([
            "xrefs",
            path.to_str().unwrap(),
            "--at",
            "0x2158",
            "--overlap-seams",
            "--no-pdb",
            "--no-color",
        ])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let xrefs = String::from_utf8(result.stdout).unwrap();
    assert!(xrefs.contains("[site 0x0000100F]"), "{xrefs}");
    assert!(xrefs.contains("[overlap seam]"), "{xrefs}");
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn mapped_non_import_pointer_is_not_claimed_as_a_hidden_import_call() {
    let (dir, path) = temporary_fixture(
        "fake-iat",
        Some(&[0x49, 0xbb, 0xff, 0x15, 0x0e, 0, 0, 0, 0xeb, 0x07]),
        0x04,
    );
    for command in ["xrefs", "callers"] {
        let output = run(&path, &dir, command, true);
        assert!(!output.contains("[overlap seam]"), "{command}: {output}");
        if command == "callers" {
            assert!(output.contains("0 total caller references"), "{output}");
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn ordinary_rex_prefixed_iat_call_is_indexed_at_its_instruction_start() {
    // This matches a call form present in whoami.exe and notepad.exe. The
    // FF opcode is one byte after the actual instruction boundary.
    let (dir, path) = temporary_fixture(
        "iat",
        Some(&[0x48, 0xff, 0x15, 0x44, 0x11, 0, 0, 0x90, 0x90, 0x90]),
        0x02,
    );
    let mut bytes = std::fs::read(&path).unwrap();
    add_self_import(&mut bytes);
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    let opt = pe + 24;
    // Supply one valid x64 runtime function so callers' boundary validation
    // marks the REX prefix at RVA 0x100D as an instruction start.
    bytes[opt + 136..opt + 144].copy_from_slice(&[0xa0, 0x21, 0, 0, 12, 0, 0, 0]);
    bytes[0x7a0..0x7ac].copy_from_slice(&[0x03, 0x10, 0, 0, 0x20, 0x10, 0, 0, 0xb0, 0x21, 0, 0]);
    bytes[0x7b0..0x7b4].copy_from_slice(&[1, 0, 0, 0]);
    std::fs::write(&path, &bytes).unwrap();

    for overlap in [false, true] {
        let callers = run(&path, &dir, "callers", overlap);
        assert!(callers.contains("1 total caller references"), "{callers}");
        assert!(callers.contains("call@0x0000100D"), "{callers}");
    }
    std::fs::remove_dir_all(dir).unwrap();
}

#[test]
fn opcode_bytes_without_branch_into_seam_are_not_indexed() {
    // Keep the hidden E8 bytes but redirect the conditional branch to the
    // primary-stream start, so there is no branch-reachable seam.
    let (dir, path) = temporary_fixture("unreachable", None, 0x02);
    for command in ["xrefs", "callers"] {
        let output = run(&path, &dir, command, true);
        assert!(!output.contains("[overlap seam]"), "{command}: {output}");
        if command == "callers" {
            assert!(output.contains("0 total caller references"), "{output}");
        }
    }
    std::fs::remove_dir_all(dir).unwrap();
}
