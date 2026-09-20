#![cfg(windows)]

use serde_json::Value;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

fn fixture() -> PathBuf {
    static DIRECTORY: OnceLock<PathBuf> = OnceLock::new();
    let directory = DIRECTORY.get_or_init(|| {
        if let Some(directory) = std::env::var_os("RESX_FIXTURE_DIR") {
            return PathBuf::from(directory);
        }
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf();
        let directory = root
            .join("target")
            .join(format!("fixture-contracts-{}", std::process::id()));
        let result = Command::new("powershell")
            .args(["-NoProfile", "-File"])
            .arg(root.join("resx-fixtures/scripts/build.ps1"))
            .arg("-OutDir")
            .arg(&directory)
            .output()
            .expect("launch fixture compiler");
        assert!(
            result.status.success(),
            "fixture build failed\n{}\n{}",
            String::from_utf8_lossy(&result.stdout),
            String::from_utf8_lossy(&result.stderr)
        );
        directory
    });
    let path = directory.join("resx_fixtures.dll");
    assert!(
        path.is_file(),
        "build resx-fixtures first, or set RESX_FIXTURE_DIR: {}",
        path.display()
    );
    path
}

fn analyze(command: &str, extra: &[&str]) -> Value {
    analyze_path(command, fixture(), extra)
}

fn analyze_path(command: &str, path: PathBuf, extra: &[&str]) -> Value {
    let result = Command::new(env!("CARGO_BIN_EXE_resx"))
        .arg(command)
        .arg(path)
        .args(extra)
        .args(["--json", "--quiet", "--no-color", "--no-pdb"])
        .output()
        .expect("launch RESX");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).expect("JSON output")
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn exported_read_only_data_is_not_presented_as_a_function() {
    let path = fixture().with_file_name("data_exports.dll");
    assert!(
        path.is_file(),
        "rebuild resx-fixtures to produce data_exports.dll"
    );
    let eat = analyze_path("eat", path.clone(), &[]);
    let export = eat["exports"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["name"] == "ResxFixtureData")
        .unwrap();
    let rva =
        u64::from_str_radix(export["rva"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let sections = analyze_path("sections", path.clone(), &[]);
    let section = sections["dump"]["sections"]
        .as_array()
        .unwrap()
        .iter()
        .find(|section| {
            let start = u64::from_str_radix(
                section["rva"].as_str().unwrap().trim_start_matches("0x"),
                16,
            )
            .unwrap();
            let size = u64::from_str_radix(
                section["virtual_size"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("0x"),
                16,
            )
            .unwrap();
            start <= rva && rva < start + size
        })
        .unwrap();
    assert!(!section["protections"].as_str().unwrap().contains('X'));
    let report = analyze_path("dump", path, &["ResxFixtureData", "--max-insns", "16"]);
    assert!(
        report["dump"]["instructions"].is_null()
            || report["dump"]["instructions"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "exported read-only object was decoded as executable code"
    );
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn exports_match_the_linker_definition() {
    let definition = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../resx-fixtures/src/resx_fixtures.def"),
    )
    .unwrap();
    let exports = analyze("eat", &[]);
    let exports = exports["exports"].as_array().unwrap();
    let expected: Vec<_> = definition
        .lines()
        .map(str::trim)
        .filter(|line| line.starts_with("Resx"))
        .collect();
    assert!(!expected.is_empty());
    assert_eq!(exports.len(), expected.len());
    for line in expected {
        let name = line.split_whitespace().next().unwrap();
        assert!(
            exports.iter().any(|item| item["name"] == name),
            "missing {name}"
        );
    }
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn an_import_slot_is_data_not_the_imported_function_body() {
    let report = analyze("xrefs", &["CreateFileW"]);
    let dump = &report["dump"];
    assert_eq!(dump["is_import_slot"], true);
    assert_eq!(dump["import_target_name"], "CreateFileW");
    assert!(
        dump["instructions"].is_null()
            || dump["instructions"].as_array().is_some_and(Vec::is_empty)
    );
    assert!(dump["xrefs"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn direct_import_slot_dump_does_not_decode_the_pointer_as_code() {
    let report = analyze("dump", &["CreateFileW"]);
    assert_eq!(report["dump"]["is_import_slot"], true);
    assert!(
        report["dump"]["instructions"].is_null()
            || report["dump"]["instructions"]
                .as_array()
                .is_some_and(Vec::is_empty)
    );
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn named_export_disassembly_has_instructions_without_pdbs() {
    let report = analyze("dump", &["ResxParsePacket", "--max-insns", "32"]);
    assert_eq!(report["dump"]["function"], "ResxParsePacket");
    assert!(report["dump"]["instructions"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));
}

#[test]
#[ignore = "requires local RESX fixture sources; they are not distributed in the repository"]
fn ioctl_calls_recover_arguments_without_treating_every_constant_as_a_call() {
    let path = fixture().parent().unwrap().join("api_arguments.dll");
    let report = analyze_path("ioctl", path, &[]);
    let calls = report["ioctl"]["call_sites"].as_array().unwrap();
    let call = calls
        .iter()
        .find(|call| call["ioctl_code"] == 0x8337_a004u32)
        .expect("known IOCTL call");
    let arguments = call["arguments"].as_array().unwrap();
    let output_length = arguments
        .iter()
        .find(|argument| argument["name"] == "output_length")
        .unwrap();
    assert_eq!(output_length["value"]["value"], 32);
    assert!(calls
        .iter()
        .all(|call| call["ioctl_code"] != 0x8337_600cu32));
    assert!(calls
        .iter()
        .all(|call| call["kernel_object_identity"].is_null()));
    let ndis = calls
        .iter()
        .find(|call| call["ioctl_code"] == 0x170002u32)
        .expect("NDIS query call");
    assert_eq!(ndis["ndis_oid"], 0x10101u32);
    let named = calls
        .iter()
        .find(|call| call["ioctl_code"] == 0x8337_6008u32)
        .expect("named device call");
    assert_eq!(named["device_handle"]["kind"], "api_result");
    assert_eq!(named["device_handle"]["path"], "\\\\.\\RESX_FIXTURE_ONLY");
}

#[test]
#[ignore = "requires RESX_FIXTURE_DIR built with build.ps1 -WithNdis; static inspection only"]
fn ndis_requests_follow_wdk_layout_and_reject_wrong_object_headers() {
    let path = fixture().parent().unwrap().join("ndis_requests.dll");
    let report = analyze_path("ioctl", path, &[]);
    let calls = report["ioctl"]["call_sites"].as_array().unwrap();
    let ndis: Vec<_> = calls
        .iter()
        .filter(|call| {
            call["dll"]
                .as_str()
                .is_some_and(|dll| dll.eq_ignore_ascii_case("ndis.sys"))
        })
        .collect();
    assert_eq!(ndis.len(), 3);
    assert!(ndis
        .iter()
        .all(|call| call["ioctl_code"].is_null() && call["kernel_object_identity"].is_null()));
    let query = ndis
        .iter()
        .find(|call| call["ndis_request"]["operation"] == "query_information")
        .unwrap();
    assert_eq!(query["ndis_oid"], 0x10101u32);
    let method = ndis
        .iter()
        .find(|call| call["ndis_request"]["operation"] == "method")
        .unwrap();
    assert_eq!(method["ndis_oid"], 0x1010102u32);
    for (name, value) in [
        ("input_buffer_length", 12),
        ("output_buffer_length", 64),
        ("method_id", 7),
    ] {
        let field = method["ndis_request"]["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["name"] == name)
            .unwrap();
        assert_eq!(field["value"]["value"], value);
    }
    assert_eq!(
        ndis.iter()
            .filter(|call| call["ndis_request"].is_null() && call["ndis_oid"].is_null())
            .count(),
        1
    );
}
