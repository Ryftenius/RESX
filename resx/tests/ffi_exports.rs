#![cfg(windows)]

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::ptr;
use std::time::Instant;

use resx_ffi::ffi::{
    ResxCfg, ResxCfgAt, ResxCfgDiff, ResxCfgOrdinal, ResxDiff, ResxDump, ResxDumpAt,
    ResxDumpOrdinal, ResxFollowCallers, ResxFreeString, ResxHelp, ResxHunt, ResxIndex, ResxIntelli,
    ResxLocate, ResxLocateSymbols, ResxPeCheck, ResxPeInfo, ResxPriority, ResxReconstructCfg,
    ResxRunArgs, ResxRunCommandJson, ResxScan, ResxSections, ResxShowEat, ResxShowIat,
    ResxShowSyms, ResxTypes, ResxUpdate, ResxVersion, ResxYara,
};
use serde_json::{json, Value};

const RSX_STATUS_OK: i32 = 0;
const EXPORT_NAME: &str = "ResxSwitchJumpTableDispatch";

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("resx crate should be inside workspace")
        .to_path_buf()
}

fn corpus_root() -> PathBuf {
    workspace_root().join("resx-fixtures")
}

fn build_dir() -> PathBuf {
    workspace_root()
        .join("target-resx-tests")
        .join("resx-fixtures-test")
}

fn build_out_dir_arg() -> String {
    r"..\target-resx-tests\resx-fixtures-test".to_owned()
}

fn sample_path(name: &str) -> PathBuf {
    build_dir().join(name)
}

fn ensure_samples() -> Option<(PathBuf, PathBuf, PathBuf)> {
    let dll = sample_path("resx_fixtures.dll");
    let variant = sample_path("resx_fixtures_variant.dll");
    let exe = sample_path("resx_fixtures_probe.exe");
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
        .expect("failed to launch resx-fixtures build script");

    if !output.status.success() {
        panic!(
            "RESX FFI test: sample build failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    if dll.exists() && variant.exists() && exe.exists() {
        Some((dll, variant, exe))
    } else {
        panic!("RESX FFI test: build did not produce expected samples");
    }
}

fn cstr(value: impl AsRef<str>) -> CString {
    CString::new(value.as_ref()).expect("test string contained NUL")
}

fn options(value: Value) -> CString {
    cstr(value.to_string())
}

fn with_out(call: impl FnOnce(*mut *mut c_char) -> i32) -> (i32, String) {
    let mut out: *mut c_char = ptr::null_mut();
    let status = call(&mut out);
    let text = if out.is_null() {
        String::new()
    } else {
        let text = unsafe { CStr::from_ptr(out) }
            .to_string_lossy()
            .into_owned();
        ResxFreeString(out);
        text
    };
    (status, text)
}

fn call_json(call: impl FnOnce(*mut *mut c_char) -> i32) -> Value {
    let (status, text) = with_out(call);
    assert_eq!(status, RSX_STATUS_OK, "FFI call failed:\n{text}");
    let value: Value = serde_json::from_str(&text).expect("FFI output was not JSON");
    assert_eq!(value["ffi"]["status"], "ok");
    value
}

fn call_any_json(call: impl FnOnce(*mut *mut c_char) -> i32) -> (i32, Value) {
    let (status, text) = with_out(call);
    let value: Value = serde_json::from_str(&text).expect("FFI output was not JSON");
    (status, value)
}

fn payload(call: impl FnOnce(*mut *mut c_char) -> i32) -> Value {
    call_json(call)["payload"].clone()
}

fn trace_step<T>(name: &str, f: impl FnOnce() -> T) -> T {
    let trace = std::env::var_os("RESX_FFI_TRACE").is_some();
    let started = Instant::now();
    if trace {
        eprintln!("[ffi] start {name}");
    }
    let result = f();
    if trace {
        eprintln!(
            "[ffi] done  {name} ({:.2}s)",
            started.elapsed().as_secs_f64()
        );
    }
    result
}

fn export_rva_and_ordinal(eat_payload: &Value) -> (String, u32) {
    let export = eat_payload["exports"]
        .as_array()
        .expect("exports should be an array")
        .iter()
        .find(|item| item["name"] == EXPORT_NAME)
        .expect("missing expected export");
    (
        export["rva"].as_str().unwrap().to_owned(),
        export["ordinal"].as_u64().unwrap() as u32,
    )
}

#[test]
fn ffi_export_symbols_are_linkable() {
    let _ = ResxFreeString as extern "C" fn(*mut c_char);
    let _ = ResxVersion as extern "C" fn(*mut *mut c_char) -> i32;
    let _ = ResxHelp as extern "C" fn(*mut *mut c_char) -> i32;
    let _ = ResxRunArgs as extern "C" fn(usize, *const *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxRunCommandJson as extern "C" fn(*const c_char, *mut *mut c_char) -> i32;
    let _ = ResxDump
        as extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxDumpAt
        as extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxDumpOrdinal
        as extern "C" fn(*const c_char, u32, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxCfg
        as extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxCfgAt
        as extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ =
        ResxCfgOrdinal as extern "C" fn(*const c_char, u32, *const c_char, *mut *mut c_char) -> i32;
    let _ =
        ResxReconstructCfg as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxIntelli
        as extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxPeInfo as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxSections as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxPeCheck as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxShowEat as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxShowIat as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxShowSyms as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxTypes
        as extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxFollowCallers
        as extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxLocate as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ =
        ResxLocateSymbols as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxDiff
        as extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxCfgDiff
        as extern "C" fn(
            *const c_char,
            *const c_char,
            *const c_char,
            *const c_char,
            *mut *mut c_char,
        ) -> i32;
    let _ = ResxIndex as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxHunt as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxScan as extern "C" fn(*const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxYara
        as extern "C" fn(*const c_char, *const c_char, *const c_char, *mut *mut c_char) -> i32;
    let _ = ResxPriority as extern "C" fn(*const c_char, *mut *mut c_char) -> i32;
    let _ = ResxUpdate as extern "C" fn(*const c_char, *mut *mut c_char) -> i32;
}

#[test]
fn ffi_wrappers_cover_resx_analysis_surface() {
    let Some((dll, variant, exe)) = ensure_samples() else {
        return;
    };
    let dll = cstr(dll.to_string_lossy());
    let variant = cstr(variant.to_string_lossy());
    let exe = cstr(exe.to_string_lossy());
    let scan_root = cstr(build_dir().to_string_lossy());
    let function = cstr(EXPORT_NAME);
    let no_pdb = options(json!({"no_pdb": true, "max_insns": 128, "max_functions": 256}));

    let (status, version) = trace_step("ResxVersion", || with_out(|out| ResxVersion(out)));
    assert_eq!(status, RSX_STATUS_OK);
    assert!(version.contains("RESX v"));

    let (status, help) = trace_step("ResxHelp", || with_out(|out| ResxHelp(out)));
    assert_eq!(status, RSX_STATUS_OK);
    assert!(help.contains("ResxRunCommandJson"));

    let argv = [
        cstr("eat"),
        cstr(dll.to_string_lossy()),
        cstr("--json"),
        cstr("--no-color"),
        cstr("--quiet"),
    ];
    let argv_ptrs = argv.iter().map(|s| s.as_ptr()).collect::<Vec<_>>();
    let (status, raw_eat) = trace_step("ResxRunArgs/eat", || {
        with_out(|out| ResxRunArgs(argv_ptrs.len(), argv_ptrs.as_ptr(), out))
    });
    assert_eq!(status, RSX_STATUS_OK, "{raw_eat}");
    let raw_eat: Value =
        serde_json::from_str(&raw_eat).expect("ResxRunArgs should return raw JSON");
    assert_eq!(raw_eat["schema_version"], 1);

    let peinfo = trace_step("ResxPeInfo", || {
        payload(|out| ResxPeInfo(dll.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert_eq!(peinfo["peinfo"]["file_name"], "resx_fixtures.dll");

    let eat = trace_step("ResxShowEat", || {
        payload(|out| ResxShowEat(dll.as_ptr(), no_pdb.as_ptr(), out))
    });
    let (rva, ordinal) = export_rva_and_ordinal(&eat);
    let rva = cstr(rva);

    let iat = trace_step("ResxShowIat", || {
        payload(|out| ResxShowIat(dll.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert!(iat["imports"].is_array());

    let sections = trace_step("ResxSections", || {
        payload(|out| ResxSections(dll.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert!(sections["dump"]["sections"].is_array());

    let pecheck = trace_step("ResxPeCheck", || {
        payload(|out| ResxPeCheck(dll.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert!(pecheck["pechk"]["header_corrupt"].is_boolean());
    assert!(pecheck["pechk"]["findings"].is_array());

    let dump = trace_step("ResxDump", || {
        payload(|out| ResxDump(dll.as_ptr(), function.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert_eq!(dump["dump"]["function"], EXPORT_NAME);

    let dump_at = trace_step("ResxDumpAt", || {
        payload(|out| ResxDumpAt(dll.as_ptr(), rva.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert!(dump_at["dump"]["instructions"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));

    let dump_ordinal = trace_step("ResxDumpOrdinal", || {
        payload(|out| ResxDumpOrdinal(dll.as_ptr(), ordinal, no_pdb.as_ptr(), out))
    });
    assert!(dump_ordinal["dump"]["instructions"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));

    let cfg = trace_step("ResxCfg", || {
        call_json(|out| ResxCfg(dll.as_ptr(), function.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert!(cfg["text"].as_str().unwrap_or_default().contains("CFG:"));

    let cfg_at = trace_step("ResxCfgAt", || {
        call_json(|out| ResxCfgAt(dll.as_ptr(), rva.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert!(cfg_at["text"].as_str().unwrap_or_default().contains("CFG:"));

    let cfg_ordinal = trace_step("ResxCfgOrdinal", || {
        call_json(|out| ResxCfgOrdinal(dll.as_ptr(), ordinal, no_pdb.as_ptr(), out))
    });
    assert!(cfg_ordinal["text"]
        .as_str()
        .unwrap_or_default()
        .contains("CFG:"));

    let intelli = trace_step("ResxIntelli", || {
        payload(|out| ResxIntelli(dll.as_ptr(), function.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert_eq!(intelli["dump"]["function"], EXPORT_NAME);

    let reconstruct = trace_step("ResxReconstructCfg", || {
        payload(|out| ResxReconstructCfg(exe.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert_eq!(
        reconstruct["reconstruct_cfg"]["image"],
        "resx_fixtures_probe.exe"
    );

    let diff = trace_step("ResxDiff", || {
        payload(|out| ResxDiff(dll.as_ptr(), variant.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert!(diff["diff"]["summary"]["similarity_score"]
        .as_u64()
        .is_some_and(|score| score > 50));

    let cfg_diff = trace_step("ResxCfgDiff", || {
        payload(|out| {
            ResxCfgDiff(
                dll.as_ptr(),
                variant.as_ptr(),
                function.as_ptr(),
                no_pdb.as_ptr(),
                out,
            )
        })
    });
    assert!(cfg_diff["cfg_diff"]["blocks"]
        .as_array()
        .is_some_and(|blocks| !blocks.is_empty()));

    let db_path = cstr(sample_path("ffi.resxdb").to_string_lossy());
    let corpus_options = options(json!({
        "db": db_path.to_string_lossy(),
        "extensions": "exe,dll",
        "max_files": 8,
        "max_functions": 256,
        "no_pdb": true
    }));
    let index = trace_step("ResxIndex", || {
        payload(|out| ResxIndex(scan_root.as_ptr(), corpus_options.as_ptr(), out))
    });
    assert!(index["index"]["images"]
        .as_array()
        .is_some_and(|images| images.len() >= 3));

    let hunt = trace_step("ResxHunt", || {
        payload(|out| ResxHunt(variant.as_ptr(), corpus_options.as_ptr(), out))
    });
    assert!(hunt["hunt"]["candidates"]
        .as_array()
        .is_some_and(|items| !items.is_empty()));

    let scan = trace_step("ResxScan", || {
        payload(|out| ResxScan(scan_root.as_ptr(), corpus_options.as_ptr(), out))
    });
    assert_eq!(scan["kind"], "scan");

    let locate_options = options(json!({
        "include_image": dll.to_string_lossy(),
        "no_system": true,
        "no_cwd": true,
        "no_path": true,
        "no_pdb": true,
        "max_total": 32
    }));
    let locate = trace_step("ResxLocate", || {
        payload(|out| ResxLocate(function.as_ptr(), locate_options.as_ptr(), out))
    });
    assert!(locate["matches"].as_array().is_some());

    let locate_symbols = trace_step("ResxLocateSymbols", || {
        payload(|out| ResxLocateSymbols(function.as_ptr(), locate_options.as_ptr(), out))
    });
    assert!(locate_symbols["matches"].as_array().is_some());

    let request = cstr(
        json!({
            "command": "diff",
            "args": [dll.to_string_lossy(), dll.to_string_lossy()],
            "options": {"no_pdb": true, "max_functions": 128}
        })
        .to_string(),
    );
    let generic = trace_step("ResxRunCommandJson/diff", || {
        payload(|out| ResxRunCommandJson(request.as_ptr(), out))
    });
    assert_eq!(generic["diff"]["summary"]["similarity_score"], 100);

    let (types_status, types) = trace_step("ResxTypes", || {
        call_any_json(|out| ResxTypes(dll.as_ptr(), ptr::null(), no_pdb.as_ptr(), out))
    });
    if types_status == RSX_STATUS_OK {
        assert!(types["payload"]["types"].is_array());
    }

    let callers_options = options(json!({
        "include_image": exe.to_string_lossy(),
        "no_system": true,
        "no_cwd": true,
        "no_path": true,
        "depth": 1,
        "max_total": 16,
        "no_pdb": true
    }));
    let (callers_status, callers) = trace_step("ResxFollowCallers", || {
        call_any_json(|out| {
            ResxFollowCallers(
                dll.as_ptr(),
                function.as_ptr(),
                callers_options.as_ptr(),
                out,
            )
        })
    });
    if callers_status == RSX_STATUS_OK {
        assert!(callers["payload"]["callers"].is_object());
    }

    let missing_rule = cstr(sample_path("missing-rule.yar").to_string_lossy());
    let (status, yara_error) = trace_step("ResxYara/missing-rule", || {
        with_out(|out| ResxYara(dll.as_ptr(), missing_rule.as_ptr(), no_pdb.as_ptr(), out))
    });
    assert_ne!(status, RSX_STATUS_OK);
    assert!(yara_error.contains("\"status\": \"error\""));
}
