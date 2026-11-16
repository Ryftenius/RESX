//! Local end-to-end check: compiled fixtures and Windows SDK are not CI inputs.
#![cfg(windows)]

use resx_ffi::{
    analysis::headers,
    commands,
    core::{
        color::Colors,
        config::{Config, Options},
    },
};
use serde_json::Value;

#[test]
#[ignore = "requires RESX_HEADER_FIXTURE_DIR containing resx_sentinel.exe and a local SDK"]
fn sentinel_callbacks_and_rng_flags_are_contextual_and_opt_in() {
    let directory = std::env::var("RESX_HEADER_FIXTURE_DIR").expect("fixture directory");
    let path = std::path::Path::new(&directory).join("resx_sentinel.exe");
    let path = path.to_str().unwrap();
    let sdk = headers::installed_sdk().expect("installed Windows SDK");
    let options = Options {
        api_args: true,
        no_pdb: true,
        json: true,
        ..Options::default()
    };
    let mut cfg = Config::from_options(&options, false);
    cfg.headers = Some(sdk.to_string_lossy().into_owned());
    let colors = Colors::new(false);
    let mut output = Vec::new();
    commands::behavior::run(path, &cfg, &mut output, &colors).unwrap();
    let behavior: Value = serde_json::from_slice(&output).unwrap();
    let signatures = behavior["behavior"]["api_signatures"].as_object().unwrap();
    let thread = signatures
        .values()
        .find(|s| s["call"].as_str().unwrap().starts_with("CreateThread("))
        .unwrap();
    assert!(thread["call"]
        .as_str()
        .unwrap()
        .contains("lpStartAddress=&fn_0x000016E0"));
    assert_eq!(thread["arguments"][2]["kind"], "callback");
    assert_eq!(thread["arguments"][2]["value"]["rva"], 0x16e0);
    assert_eq!(
        thread["arguments"][2]["value"]["typedef"],
        "LPTHREAD_START_ROUTINE"
    );
    assert!(thread["arguments"][2]["value"]["evidence"]
        .as_str()
        .unwrap()
        .contains("API-contract inference"));
    let rng = signatures
        .values()
        .find(|s| s["call"].as_str().unwrap().starts_with("BCryptGenRandom("))
        .unwrap();
    // This report sees the import thunk's incoming parameter, not the caller's
    // concrete flags. Do not invent a constant; the dump below checks that site.
    assert!(rng["call"].as_str().unwrap().contains("dwFlags=arg4"));
    let raw = std::fs::read(path).unwrap();
    let pe = resx_ffi::formats::pe::parse_pe(&raw).unwrap();
    assert!(pe.rva_to_section(0x16e0).unwrap().is_executable());
    assert_eq!(
        &pe.rva_bytes(&raw, 0x16e0).unwrap()[..6],
        &[0x40, 0x53, 0x48, 0x83, 0xec, 0x20]
    );
    for (rva, expected) in [
        ("0x1630", "lpStartAddress=&fn_0x000016E0"),
        ("0x13A0", "dwFlags=BCRYPT_USE_SYSTEM_PREFERRED_RNG"),
    ] {
        cfg.at_rva = rva.into();
        cfg.funcs_depth = 1;
        output.clear();
        commands::dump::run(path, "", &cfg, &mut output, &colors).unwrap();
        let dump: Value = serde_json::from_slice(&output).unwrap();
        assert!(dump["dump"]["api_calls"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["signature"]["call"]
                .as_str()
                .is_some_and(|s| s.contains(expected))));
        assert!(dump["dump"]["api_call_tree"]
            .as_str()
            .unwrap()
            .contains(expected.split('=').nth(1).unwrap()));
    }
    cfg.api_args = false;
    output.clear();
    commands::behavior::run(path, &cfg, &mut output, &colors).unwrap();
    let plain: Value = serde_json::from_slice(&output).unwrap();
    assert!(plain["behavior"]
        .get("api_signatures")
        .is_none_or(|v| v.as_object().is_some_and(|v| v.is_empty())));
}

#[test]
#[ignore = "requires RESX_HEADER_FIXTURE_DIR containing optimized dynres fixtures and a local SDK"]
fn sdk_enrichment_reaches_api_behavior_dump_and_call_tree() {
    let directory = std::env::var("RESX_HEADER_FIXTURE_DIR").expect("fixture directory");
    let sdk = headers::installed_sdk().expect("installed Windows SDK");
    let options = Options {
        api_args: true,
        no_pdb: true,
        json: true,
        ..Options::default()
    };
    let mut cfg = Config::from_options(&options, false);
    cfg.headers = Some(sdk.to_string_lossy().into_owned());
    let colors = Colors::new(false);
    let mut output = Vec::new();
    commands::api::run("VirtualAlloc", &cfg, &mut output).unwrap();
    let api: Value = serde_json::from_slice(&output).unwrap();
    assert_eq!(
        api["api"]["prototype"]["params"].as_array().unwrap().len(),
        4
    );

    for file in [
        "dynres_plain.exe",
        "dynres_plain_x86.exe",
        "dynres_obfuscated.exe",
        "dynres_peb.exe",
    ] {
        let path = std::path::Path::new(&directory).join(file);
        let path = path.to_str().unwrap();
        output.clear();
        commands::behavior::run(path, &cfg, &mut output, &colors).unwrap();
        let behavior: Value = serde_json::from_slice(&output).unwrap();
        let signatures = behavior["behavior"]["api_signatures"].as_object().unwrap();
        assert!(
            signatures.values().any(|s| s["call"]
                .as_str()
                .is_some_and(|s| s.starts_with("VirtualAlloc("))),
            "{file}: {signatures:?}"
        );
        if file == "dynres_plain.exe" {
            assert!(
                signatures
                    .values()
                    .any(|s| s["call"].as_str().is_some_and(|s| s
                        .starts_with("VirtualAlloc(lpAddress=NULL, dwSize=0x1000,")
                        && s.contains("MEM_COMMIT")
                        && s.contains("MEM_RESERVE")
                        && s.contains("flProtect=PAGE_READWRITE"))),
                "{file}: {signatures:?}"
            );
        }
        let alloc = behavior["behavior"]["resolved_apis"]
            .as_array()
            .unwrap()
            .iter()
            .find(|api| api["api"] == "VirtualAlloc" || api["api"] == "VirtualProtect")
            .unwrap();
        let site = u32::from_str_radix(
            alloc["call_sites"][0]
                .as_str()
                .unwrap()
                .trim_start_matches("0x"),
            16,
        )
        .unwrap();
        let raw = std::fs::read(path).unwrap();
        let pe = resx_ffi::formats::pe::parse_pe(&raw).unwrap();
        let resolution = resx_ffi::analysis::resolution::cached(&pe, &raw);
        let body = resolution.function_containing(&pe, &raw, site).unwrap();
        cfg.at_rva = format!("0x{:X}", body[0].ip() - pe.image_base);
        cfg.funcs_depth = 2;
        output.clear();
        commands::dump::run(path, "", &cfg, &mut output, &colors).unwrap();
        let dump: Value = serde_json::from_slice(&output).unwrap();
        let calls = dump["dump"]["api_calls"].as_array().unwrap();
        assert!(
            calls.iter().any(|call| call["signature"]["call"]
                .as_str()
                .is_some_and(|s| s.contains("("))),
            "{file}: missing structured signatures"
        );
        assert!(
            dump["dump"]["api_call_tree"]
                .as_str()
                .unwrap()
                .contains("lpAddress"),
            "{file}: missing call-tree signature"
        );
        assert!(
            dump["dump"]["instructions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|insn| insn["comment"]
                    .as_str()
                    .is_some_and(|s| s.contains("lpAddress="))),
            "{file}: missing disassembly signature"
        );
        cfg.headers = None;
        output.clear();
        commands::dump::run(path, "", &cfg, &mut output, &colors).unwrap();
        let plain: Value = serde_json::from_slice(&output).unwrap();
        assert!(plain["dump"]["api_calls"]
            .as_array()
            .unwrap()
            .iter()
            .all(|call| call.get("signature").is_none()));
        cfg.headers = Some(sdk.to_string_lossy().into_owned());
    }
}
