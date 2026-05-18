#![allow(non_snake_case)]

use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::Once;
use std::time::Instant;

use clap::Parser;
use rayon::ThreadPoolBuilder;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::cli::help::{is_help_request, is_version_request, preprocess_args, version_string};
use crate::cli::router::dispatch;
use crate::core::color::Colors;
use crate::core::config::{Cli, Config};
use crate::core::json::SCHEMA_VERSION;

const RSX_STATUS_OK: c_int = 0;
const RSX_STATUS_NULL_ARGUMENT: c_int = 1;
const RSX_STATUS_INVALID_UTF8: c_int = 2;
const RSX_STATUS_INVALID_JSON: c_int = 3;
const RSX_STATUS_INVALID_OPTIONS: c_int = 4;
const RSX_STATUS_EXECUTION_ERROR: c_int = 5;
const RSX_STATUS_PANIC: c_int = 255;

static RAYON_INIT: Once = Once::new();

#[derive(Debug)]
struct FfiError {
    status: c_int,
    message: String,
}

impl FfiError {
    fn new(status: c_int, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }
}

#[derive(Debug)]
struct CapturedRun {
    command: String,
    args: Vec<String>,
    stdout: String,
}

#[derive(Debug, Deserialize)]
struct CommandJsonRequest {
    command: Option<String>,
    args: Option<Vec<String>>,
    argv: Option<Vec<String>>,
    options: Option<Value>,
}

#[no_mangle]
// This C ABI entry point must accept the opaque pointer returned by RESX.
#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub extern "C" fn RsxFreeString(value: *mut c_char) {
    if value.is_null() {
        return;
    }
    unsafe {
        let _ = CString::from_raw(value);
    }
}

#[no_mangle]
pub extern "C" fn RsxVersion(out_utf8: *mut *mut c_char) -> c_int {
    write_plain(out_utf8, version_string())
}

#[no_mangle]
pub extern "C" fn RsxHelp(out_utf8: *mut *mut c_char) -> c_int {
    write_plain(out_utf8, ffi_help_text())
}

#[no_mangle]
pub extern "C" fn RsxRunArgs(
    argc: usize,
    argv: *const *const c_char,
    out_utf8: *mut *mut c_char,
) -> c_int {
    ffi_boundary(out_utf8, || {
        let raw_args = read_argv(argc, argv)?;
        let normalized = normalize_raw_argv(raw_args);
        run_cli_capture(&normalized).map(|run| run.stdout)
    })
}

#[no_mangle]
pub extern "C" fn RsxRunCommandJson(
    request_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary(out_json, || {
        let request = read_required_json::<CommandJsonRequest>("request_json", request_json)?;
        let (raw_args, command, args) = if let Some(argv) = request.argv {
            let normalized = normalize_raw_argv(argv);
            let command = normalized.get(1).cloned().unwrap_or_default();
            let mut args = normalized.iter().skip(2).cloned().collect::<Vec<_>>();
            if request.options.is_some() {
                append_options(
                    &mut args,
                    request.options.as_ref(),
                    command_supports_json(&command),
                )?;
            }
            let mut raw_args = vec!["resx".to_owned(), command.clone()];
            raw_args.extend(args.iter().cloned());
            let command = raw_args.get(1).cloned().unwrap_or_default();
            (raw_args, command, args)
        } else {
            let command = request
                .command
                .as_deref()
                .map(str::trim)
                .filter(|cmd| !cmd.is_empty())
                .ok_or_else(|| {
                    FfiError::new(
                        RSX_STATUS_INVALID_OPTIONS,
                        "request_json.command is required when argv is absent",
                    )
                })?
                .to_owned();
            let mut args = request.args.unwrap_or_default();
            append_options(
                &mut args,
                request.options.as_ref(),
                command_supports_json(&command),
            )?;
            let mut raw_args = vec!["resx".to_owned(), command.clone()];
            raw_args.extend(args.iter().cloned());
            (raw_args, command, args)
        };
        run_enveloped(&raw_args, &command, &args)
    })
}

#[no_mangle]
pub extern "C" fn RsxDump(
    image_path: *const c_char,
    function_name: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_two_strings(
        out_json,
        "image_path",
        image_path,
        "function_name",
        function_name,
        |image, function| run_typed("dump", vec![image, function], options_json, true),
    )
}

#[no_mangle]
pub extern "C" fn RsxDumpAt(
    image_path: *const c_char,
    rva: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_two_strings(
        out_json,
        "image_path",
        image_path,
        "rva",
        rva,
        |image, rva| {
            run_typed(
                "dump",
                vec![image, "--at".to_owned(), rva],
                options_json,
                true,
            )
        },
    )
}

#[no_mangle]
pub extern "C" fn RsxDumpOrdinal(
    image_path: *const c_char,
    ordinal: c_uint,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "image_path", image_path, |image| {
        run_typed(
            "dump",
            vec![image, "--ordinal".to_owned(), ordinal.to_string()],
            options_json,
            true,
        )
    })
}

#[no_mangle]
pub extern "C" fn RsxCfg(
    image_path: *const c_char,
    function_name: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_two_strings(
        out_json,
        "image_path",
        image_path,
        "function_name",
        function_name,
        |image, function| run_typed("cfg", vec![image, function], options_json, false),
    )
}

#[no_mangle]
pub extern "C" fn RsxCfgAt(
    image_path: *const c_char,
    rva: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_two_strings(
        out_json,
        "image_path",
        image_path,
        "rva",
        rva,
        |image, rva| {
            run_typed(
                "cfg",
                vec![image, "--at".to_owned(), rva],
                options_json,
                false,
            )
        },
    )
}

#[no_mangle]
pub extern "C" fn RsxCfgOrdinal(
    image_path: *const c_char,
    ordinal: c_uint,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "image_path", image_path, |image| {
        run_typed(
            "cfg",
            vec![image, "--ordinal".to_owned(), ordinal.to_string()],
            options_json,
            false,
        )
    })
}

#[no_mangle]
pub extern "C" fn RsxReconstructCfg(
    image_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "image_path", image_path, |image| {
        run_typed("reconstruct-cfg", vec![image], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxIntelli(
    image_path: *const c_char,
    function_name: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary(out_json, || {
        let image = read_required_cstr("image_path", image_path)?;
        let mut args = vec![image];
        if let Some(function) = read_optional_cstr(function_name)? {
            args.push(function);
        }
        run_typed("intelli", args, options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxPeInfo(
    image_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "image_path", image_path, |image| {
        run_typed("peinfo", vec![image], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxSections(
    image_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "image_path", image_path, |image| {
        run_typed("sections", vec![image], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxPeCheck(
    image_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "image_path", image_path, |image| {
        run_typed("pechk", vec![image], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxShowEat(
    image_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "image_path", image_path, |image| {
        run_typed("eat", vec![image], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxShowIat(
    image_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "image_path", image_path, |image| {
        run_typed("iat", vec![image], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxShowSyms(
    image_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "image_path", image_path, |image| {
        run_typed("syms", vec![image], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxTypes(
    image_path: *const c_char,
    query: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary(out_json, || {
        let image = read_required_cstr("image_path", image_path)?;
        let mut args = vec![image];
        if let Some(query) = read_optional_cstr(query)? {
            args.push(query);
        }
        run_typed("types", args, options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxFollowCallers(
    image_path: *const c_char,
    function_name: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_two_strings(
        out_json,
        "image_path",
        image_path,
        "function_name",
        function_name,
        |image, function| run_typed("callers", vec![image, function], options_json, true),
    )
}

#[no_mangle]
pub extern "C" fn RsxLocate(
    function_name: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "function_name", function_name, |function| {
        run_typed("locate", vec![function], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxLocateSymbols(
    function_name: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "function_name", function_name, |function| {
        run_typed("locate-sym", vec![function], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxExplain(
    term: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "term", term, |term| {
        run_typed("explain", vec![term], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxDiff(
    left_image_path: *const c_char,
    right_image_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_two_strings(
        out_json,
        "left_image_path",
        left_image_path,
        "right_image_path",
        right_image_path,
        |left, right| run_typed("diff", vec![left, right], options_json, true),
    )
}

#[no_mangle]
pub extern "C" fn RsxCfgDiff(
    left_image_path: *const c_char,
    right_image_path: *const c_char,
    target: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    ffi_boundary(out_json, || {
        let left = read_required_cstr("left_image_path", left_image_path)?;
        let right = read_required_cstr("right_image_path", right_image_path)?;
        let target = read_required_cstr("target", target)?;
        let args = vec![
            left,
            right,
            "--show-cfg-diff".to_owned(),
            target,
            "--cfg-diff-format".to_owned(),
            "json".to_owned(),
        ];
        run_typed("diff", args, options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxIndex(
    root_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "root_path", root_path, |root| {
        run_typed("index", vec![root], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxHunt(
    sample_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "sample_path", sample_path, |sample| {
        run_typed("hunt", vec![sample], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxScan(
    root_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_one_string(out_json, "root_path", root_path, |root| {
        run_typed("scan", vec![root], options_json, true)
    })
}

#[no_mangle]
pub extern "C" fn RsxYara(
    image_path: *const c_char,
    rule_path: *const c_char,
    options_json: *const c_char,
    out_json: *mut *mut c_char,
) -> c_int {
    with_two_strings(
        out_json,
        "image_path",
        image_path,
        "rule_path",
        rule_path,
        |image, rule| run_typed("yara", vec![image, rule], options_json, true),
    )
}

#[no_mangle]
pub extern "C" fn RsxPriority(options_json: *const c_char, out_json: *mut *mut c_char) -> c_int {
    ffi_boundary(out_json, || {
        run_typed("priority", Vec::new(), options_json, false)
    })
}

#[no_mangle]
pub extern "C" fn RsxUpdate(options_json: *const c_char, out_json: *mut *mut c_char) -> c_int {
    ffi_boundary(out_json, || {
        run_typed("update", Vec::new(), options_json, false)
    })
}

fn write_plain(out_utf8: *mut *mut c_char, value: String) -> c_int {
    ffi_boundary(out_utf8, || Ok(value))
}

fn with_one_string<F>(
    out_json: *mut *mut c_char,
    name: &'static str,
    value: *const c_char,
    f: F,
) -> c_int
where
    F: FnOnce(String) -> Result<String, FfiError>,
{
    ffi_boundary(out_json, || {
        let value = read_required_cstr(name, value)?;
        f(value)
    })
}

fn with_two_strings<F>(
    out_json: *mut *mut c_char,
    left_name: &'static str,
    left: *const c_char,
    right_name: &'static str,
    right: *const c_char,
    f: F,
) -> c_int
where
    F: FnOnce(String, String) -> Result<String, FfiError>,
{
    ffi_boundary(out_json, || {
        let left = read_required_cstr(left_name, left)?;
        let right = read_required_cstr(right_name, right)?;
        f(left, right)
    })
}

fn ffi_boundary<F>(out: *mut *mut c_char, f: F) -> c_int
where
    F: FnOnce() -> Result<String, FfiError>,
{
    if out.is_null() {
        return RSX_STATUS_NULL_ARGUMENT;
    }
    unsafe {
        *out = ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(f));
    match result {
        Ok(Ok(value)) => write_allocated(out, &value).unwrap_or(RSX_STATUS_INVALID_UTF8),
        Ok(Err(err)) => {
            let body = error_envelope(err.status, &err.message);
            let _ = write_allocated(out, &body);
            err.status
        }
        Err(_) => {
            let body = error_envelope(
                RSX_STATUS_PANIC,
                "RESX panicked while processing the request",
            );
            let _ = write_allocated(out, &body);
            RSX_STATUS_PANIC
        }
    }
}

fn write_allocated(out: *mut *mut c_char, value: &str) -> Result<c_int, ()> {
    let sanitized = value.replace('\0', "\\u0000");
    let c_string = CString::new(sanitized).map_err(|_| ())?;
    unsafe {
        *out = c_string.into_raw();
    }
    Ok(RSX_STATUS_OK)
}

fn read_required_cstr(name: &str, value: *const c_char) -> Result<String, FfiError> {
    if value.is_null() {
        return Err(FfiError::new(
            RSX_STATUS_NULL_ARGUMENT,
            format!("{name} must not be null"),
        ));
    }
    let raw = unsafe { CStr::from_ptr(value) };
    raw.to_str()
        .map(str::to_owned)
        .map_err(|_| FfiError::new(RSX_STATUS_INVALID_UTF8, format!("{name} is not UTF-8")))
}

fn read_optional_cstr(value: *const c_char) -> Result<Option<String>, FfiError> {
    if value.is_null() {
        return Ok(None);
    }
    let raw = unsafe { CStr::from_ptr(value) };
    let text = raw
        .to_str()
        .map_err(|_| FfiError::new(RSX_STATUS_INVALID_UTF8, "optional string is not UTF-8"))?;
    if text.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(text.to_owned()))
    }
}

fn read_required_json<T>(name: &str, value: *const c_char) -> Result<T, FfiError>
where
    T: for<'de> Deserialize<'de>,
{
    let text = read_required_cstr(name, value)?;
    serde_json::from_str(&text)
        .map_err(|e| FfiError::new(RSX_STATUS_INVALID_JSON, format!("{name}: {e}")))
}

fn read_options_json(value: *const c_char) -> Result<Option<Value>, FfiError> {
    if value.is_null() {
        return Ok(None);
    }
    let text = read_required_cstr("options_json", value)?;
    if text.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|e| FfiError::new(RSX_STATUS_INVALID_JSON, format!("options_json: {e}")))
}

fn read_argv(argc: usize, argv: *const *const c_char) -> Result<Vec<String>, FfiError> {
    if argc == 0 {
        return Ok(Vec::new());
    }
    if argv.is_null() {
        return Err(FfiError::new(
            RSX_STATUS_NULL_ARGUMENT,
            "argv must not be null when argc is nonzero",
        ));
    }
    let values = unsafe { std::slice::from_raw_parts(argv, argc) };
    values
        .iter()
        .enumerate()
        .map(|(idx, item)| read_required_cstr(&format!("argv[{idx}]"), *item))
        .collect()
}

fn run_typed(
    command: &str,
    mut args: Vec<String>,
    options_json: *const c_char,
    default_json: bool,
) -> Result<String, FfiError> {
    let options = read_options_json(options_json)?;
    append_options(&mut args, options.as_ref(), default_json)?;
    let mut raw_args = vec!["resx".to_owned(), command.to_owned()];
    raw_args.extend(args.iter().cloned());
    run_enveloped(&raw_args, command, &args)
}

fn run_enveloped(raw_args: &[String], command: &str, args: &[String]) -> Result<String, FfiError> {
    run_cli_capture(raw_args).map(|run| {
        let command = if command.is_empty() {
            run.command.as_str()
        } else {
            command
        };
        let args = if args.is_empty() { &run.args } else { args };
        success_envelope(command, args, &run.stdout)
    })
}

fn run_cli_capture(raw_args: &[String]) -> Result<CapturedRun, FfiError> {
    let started = Instant::now();
    let raw_args = normalize_raw_argv(raw_args.to_vec());

    if is_version_request(&raw_args) {
        return Ok(CapturedRun {
            command: "version".to_owned(),
            args: Vec::new(),
            stdout: format!("{}\n", version_string()),
        });
    }
    if is_help_request(&raw_args) {
        return Ok(CapturedRun {
            command: "help".to_owned(),
            args: Vec::new(),
            stdout: ffi_help_text(),
        });
    }

    let parsed_args = preprocess_args(&raw_args);
    let cli = Cli::try_parse_from(parsed_args)
        .map_err(|e| FfiError::new(RSX_STATUS_INVALID_OPTIONS, e.to_string().trim().to_owned()))?;
    let cfg = Config::from_cli(&cli, false);
    if cfg.workers > 0 {
        RAYON_INIT.call_once(|| {
            let _ = ThreadPoolBuilder::new()
                .num_threads(cfg.workers)
                .build_global();
        });
    }

    let c = Colors::new(false);
    let mut out = Vec::new();
    dispatch(&raw_args, &cli, &cfg, &mut out, &c)
        .map_err(|e| FfiError::new(RSX_STATUS_EXECUTION_ERROR, e))?;
    if cfg.verbose && !cfg.json {
        let elapsed = started.elapsed();
        writeln_no_fail(
            &mut out,
            &format!("\n<completed in {:.2}s>", elapsed.as_secs_f64()),
        );
    }
    let stdout = String::from_utf8(out).map_err(|_| {
        FfiError::new(
            RSX_STATUS_INVALID_UTF8,
            "command output was not valid UTF-8",
        )
    })?;
    Ok(CapturedRun {
        command: raw_args.get(1).cloned().unwrap_or_default(),
        args: raw_args.iter().skip(2).cloned().collect(),
        stdout,
    })
}

fn append_options(
    args: &mut Vec<String>,
    options: Option<&Value>,
    default_json: bool,
) -> Result<(), FfiError> {
    let json_requested = option_bool(options, "json").unwrap_or(default_json);
    if json_requested {
        args.push("--json".to_owned());
    }
    let color_requested = option_bool(options, "color").unwrap_or(false);
    if color_requested {
        args.push("--color".to_owned());
    } else {
        args.push("--no-color".to_owned());
    }
    if option_bool(options, "quiet").unwrap_or(true) {
        args.push("--quiet".to_owned());
    }

    let Some(Value::Object(map)) = options else {
        if options.is_some() {
            return Err(FfiError::new(
                RSX_STATUS_INVALID_OPTIONS,
                "options_json must be a JSON object",
            ));
        }
        return Ok(());
    };

    for (key, value) in map {
        if is_option_meta_key(key) {
            continue;
        }
        append_option_value(args, key, value)?;
    }
    if let Some(extra) = map.get("cli_args").or_else(|| map.get("extra_args")) {
        append_extra_args(args, extra)?;
    }
    Ok(())
}

fn append_option_value(args: &mut Vec<String>, key: &str, value: &Value) -> Result<(), FfiError> {
    let flag = ffi_flag_name(key);
    match value {
        Value::Null => Ok(()),
        Value::Bool(true) => {
            args.push(format!("--{flag}"));
            Ok(())
        }
        Value::Bool(false) => Ok(()),
        Value::Number(number) => {
            args.push(format!("--{flag}"));
            args.push(number.to_string());
            Ok(())
        }
        Value::String(text) => {
            if !text.is_empty() {
                args.push(format!("--{flag}"));
                args.push(text.clone());
            }
            Ok(())
        }
        Value::Array(values) => {
            for item in values {
                match item {
                    Value::String(text) => {
                        args.push(format!("--{flag}"));
                        args.push(text.clone());
                    }
                    Value::Number(number) => {
                        args.push(format!("--{flag}"));
                        args.push(number.to_string());
                    }
                    Value::Bool(true) => args.push(format!("--{flag}")),
                    Value::Bool(false) | Value::Null => {}
                    _ => {
                        return Err(FfiError::new(
                            RSX_STATUS_INVALID_OPTIONS,
                            format!("options_json.{key} array contains an unsupported value"),
                        ));
                    }
                }
            }
            Ok(())
        }
        Value::Object(_) => Err(FfiError::new(
            RSX_STATUS_INVALID_OPTIONS,
            format!("options_json.{key} must be a scalar or array"),
        )),
    }
}

fn append_extra_args(args: &mut Vec<String>, value: &Value) -> Result<(), FfiError> {
    let Value::Array(items) = value else {
        return Err(FfiError::new(
            RSX_STATUS_INVALID_OPTIONS,
            "options_json.cli_args must be an array of strings",
        ));
    };
    for item in items {
        let Some(text) = item.as_str() else {
            return Err(FfiError::new(
                RSX_STATUS_INVALID_OPTIONS,
                "options_json.cli_args must be an array of strings",
            ));
        };
        args.push(text.to_owned());
    }
    Ok(())
}

fn option_bool(options: Option<&Value>, key: &str) -> Option<bool> {
    let Value::Object(map) = options? else {
        return None;
    };
    map.get(key)
        .or_else(|| map.get(&key.replace('_', "-")))
        .and_then(Value::as_bool)
}

fn is_option_meta_key(key: &str) -> bool {
    matches!(
        key,
        "args" | "argv" | "cli_args" | "extra_args" | "command" | "json" | "color" | "quiet"
    )
}

fn ffi_flag_name(key: &str) -> String {
    match key {
        "at_rva" => "at",
        "pdb_file" => "pdb",
        "out_file" => "out",
        "show_xrefs" => "xrefs",
        "show_strings" => "strings",
        "cfg_view" => "cfg",
        "diff_max_functions" => "max-functions",
        "left_pdb_file" => "left-pdb",
        "right_pdb_file" => "right-pdb",
        "cfg_diff_target" => "show-cfg-diff",
        "cfg_diff_format" => "cfg-diff-format",
        "cfg_diff_out" => "cfg-diff-out",
        "corpus_db" => "db",
        "scan_extensions" => "extensions",
        "scan_dirs" => "include-dir",
        "scan_dlls" => "include-image",
        "scope_file" => "scope-file",
        "max_dll_mb" => "max-dll-size",
        "follow_format" => "format",
        "reconstruct_thread_filter" => "thread-filter",
        "reconstruct_api_filter" => "api-filter",
        "no_follow_fwd" => "no-follow-forward",
        _ => return key.replace('_', "-"),
    }
    .to_owned()
}

fn normalize_raw_argv(mut args: Vec<String>) -> Vec<String> {
    if args.is_empty() {
        return vec!["resx".to_owned()];
    }
    let first = args[0].to_ascii_lowercase();
    if first == "resx"
        || first == "resx.exe"
        || first.ends_with("\\resx.exe")
        || first.ends_with("/resx")
    {
        return args;
    }
    if is_known_command(&first) || first.starts_with('-') {
        args.insert(0, "resx".to_owned());
    }
    args
}

fn is_known_command(command: &str) -> bool {
    matches!(
        command,
        "dump"
            | "cfg"
            | "reconstruct-cfg"
            | "intelli"
            | "peinfo"
            | "sections"
            | "eat"
            | "iat"
            | "syms"
            | "pechk"
            | "priority"
            | "callers"
            | "locate"
            | "locate-sym"
            | "explain"
            | "scan"
            | "diff"
            | "index"
            | "hunt"
            | "types"
            | "yara"
            | "update"
            | "version"
    )
}

fn command_supports_json(command: &str) -> bool {
    matches!(
        command.to_ascii_lowercase().as_str(),
        "dump"
            | "reconstruct-cfg"
            | "intelli"
            | "peinfo"
            | "sections"
            | "eat"
            | "iat"
            | "syms"
            | "pechk"
            | "callers"
            | "locate"
            | "locate-sym"
            | "explain"
            | "scan"
            | "diff"
            | "index"
            | "hunt"
            | "types"
            | "yara"
    )
}

fn success_envelope(command: &str, args: &[String], stdout: &str) -> String {
    let trimmed = stdout.trim();
    let parsed = if trimmed.is_empty() {
        None
    } else {
        serde_json::from_str::<Value>(trimmed).ok()
    };
    let mut root = Map::new();
    root.insert("schema_version".to_owned(), json!(SCHEMA_VERSION));
    root.insert(
        "ffi".to_owned(),
        json!({
            "api_version": 1,
            "status": "ok",
            "status_code": RSX_STATUS_OK,
            "command": command,
            "args": args,
            "format": if parsed.is_some() { "json" } else { "text" },
            "resx_version": env!("CARGO_PKG_VERSION"),
        }),
    );
    if let Some(payload) = parsed {
        root.insert("payload".to_owned(), payload);
    } else {
        root.insert("text".to_owned(), json!(stdout));
    }
    serde_json::to_string_pretty(&Value::Object(root)).unwrap_or_else(|_| "{}".to_owned())
}

fn error_envelope(status: c_int, message: &str) -> String {
    serde_json::to_string_pretty(&json!({
        "schema_version": SCHEMA_VERSION,
        "ffi": {
            "api_version": 1,
            "status": "error",
            "status_code": status,
            "error": message,
            "resx_version": env!("CARGO_PKG_VERSION"),
        }
    }))
    .unwrap_or_else(|_| "{\"schema_version\":1}".to_owned())
}

fn ffi_help_text() -> String {
    format!(
        r#"{version}

Native DLL/FFI entry points:
  RsxRunArgs(argc, argv, out_utf8)
  RsxRunCommandJson(request_json, out_json)

Typed analysis exports:
  RsxDump / RsxDumpAt / RsxDumpOrdinal
  RsxCfg / RsxCfgAt / RsxCfgOrdinal
  RsxReconstructCfg / RsxIntelli
  RsxPeInfo / RsxSections / RsxPeCheck
  RsxShowEat / RsxShowIat / RsxShowSyms / RsxTypes
  RsxFollowCallers / RsxLocate / RsxLocateSymbols / RsxExplain
  RsxDiff / RsxCfgDiff / RsxIndex / RsxHunt / RsxScan / RsxYara
  RsxPriority / RsxUpdate

Memory:
  All returned char* values are UTF-8 and must be released with RsxFreeString.

Options:
  Pass options_json as a JSON object using CLI flag names in snake_case or kebab-case.
  Example: {{"no_pdb":true,"diff_mode":"balanced","max_functions":2000}}

For the full interactive CLI help, run `resx help`.
"#,
        version = version_string()
    )
}

fn writeln_no_fail(out: &mut Vec<u8>, line: &str) {
    out.extend_from_slice(line.as_bytes());
    out.push(b'\n');
}
