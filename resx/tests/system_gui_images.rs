#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;

use serde_json::Value;

fn system32() -> PathBuf {
    PathBuf::from(std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".to_owned()))
        .join("System32")
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

#[test]
fn extensionless_lookup_supports_user_and_win32k_images() {
    let images = [
        ("user32", "user32.dll"),
        ("win32u", "win32u.dll"),
        ("win32k", "win32k.sys"),
        ("win32kbase", "win32kbase.sys"),
        ("win32kfull", "win32kfull.sys"),
    ];

    for (arg, file_name) in images {
        if !system32().join(file_name).is_file() {
            eprintln!("skipping {file_name}: not present in System32");
            continue;
        }
        let peinfo = run_json(&["peinfo", arg, "--json", "--quiet", "--no-color", "--no-pdb"]);
        assert_eq!(peinfo["schema_version"], 1);
        assert_eq!(peinfo["peinfo"]["file_name"], file_name);
        assert!(peinfo["peinfo"]["sections"]
            .as_array()
            .is_some_and(|sections| !sections.is_empty()));
    }
}

#[test]
fn win32u_syscall_stub_routes_to_win32k_family_when_available() {
    if !system32().join("win32u.dll").is_file() {
        eprintln!("skipping win32u syscall route test: win32u.dll not present");
        return;
    }

    let eat = run_json(&[
        "eat",
        "win32u",
        "--json",
        "--quiet",
        "--no-color",
        "--no-pdb",
    ]);
    let has_nt_user_get_message = eat["exports"].as_array().is_some_and(|exports| {
        exports
            .iter()
            .any(|export| export["name"] == "NtUserGetMessage")
    });
    if !has_nt_user_get_message {
        eprintln!("skipping win32u syscall route test: NtUserGetMessage export not present");
        return;
    }

    let dump = run_json(&[
        "dump",
        "win32u",
        "NtUserGetMessage",
        "--json",
        "--quiet",
        "--no-color",
        "--no-pdb",
        "--funcs",
        "--max-insns",
        "24",
    ]);
    assert_eq!(dump["schema_version"], 1);
    assert_eq!(dump["dump"]["function"], "NtUserGetMessage");
    assert_eq!(
        dump["dump"]["current_syscall"]["kernel_symbol"],
        "NtUserGetMessage"
    );
    assert!(dump["dump"]["current_syscall"]["kernel_module"]
        .as_str()
        .is_some_and(|module| module.to_ascii_lowercase().starts_with("win32k")));
    assert!(dump["dump"]["api_call_tree"]
        .as_str()
        .is_some_and(|tree| tree.contains("win32u!NtUserGetMessage")));
}
