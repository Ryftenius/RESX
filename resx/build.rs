#[cfg(windows)]
fn main() {
    use std::env;

    emit_build_identity();
    generate_ntstatus_table();

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=resx.manifest");

    let version = env::var("CARGO_PKG_VERSION").expect("missing CARGO_PKG_VERSION");
    let description = env::var("CARGO_PKG_DESCRIPTION").expect("missing CARGO_PKG_DESCRIPTION");
    let repository = env::var("CARGO_PKG_REPOSITORY").unwrap_or_default();
    let file_version = normalize_file_version(&version);
    let comments = if repository.is_empty() {
        "Windows binary recon CLI".to_string()
    } else {
        format!("Repository: {repository}")
    };

    let mut res = winres::WindowsResource::new();
    res.set_manifest_file("resx.manifest");
    res.set("CompanyName", "RYFTENIUS");
    res.set("FileDescription", &description);
    res.set("FileVersion", &version);
    res.set("InternalName", "resx");
    res.set("LegalCopyright", "Copyright (c) RYFTENIUS");
    res.set("OriginalFilename", "resx.exe");
    res.set("ProductName", "RESX (Reverse Engineering Suite Extended)");
    res.set("ProductVersion", &version);
    res.set("Comments", &comments);
    res.set_version_info(winres::VersionInfo::FILEVERSION, file_version);
    res.set_version_info(winres::VersionInfo::PRODUCTVERSION, file_version);
    res.compile().expect("failed to compile Windows resources");
}

#[cfg(windows)]
fn emit_build_identity() {
    use std::{path::PathBuf, process::Command};

    let git_output = |args: &[&str]| {
        Command::new("git")
            .args(args)
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .map(|value| value.trim().to_owned())
            .filter(|value| !value.is_empty())
    };
    if let Some(git_dir) = git_output(&["rev-parse", "--absolute-git-dir"]) {
        let git_dir = PathBuf::from(git_dir);
        println!("cargo:rerun-if-changed={}", git_dir.join("HEAD").display());
        if let Some(reference) = git_output(&["symbolic-ref", "-q", "HEAD"]) {
            println!(
                "cargo:rerun-if-changed={}",
                git_dir.join(reference).display()
            );
        }
    }
    let commit = Command::new("git")
        .args(["rev-parse", "--verify", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| value.len() == 40 && value.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .unwrap_or_else(|| "unknown".to_owned());
    println!("cargo:rustc-env=RESX_GIT_COMMIT={commit}");
}

#[cfg(windows)]
fn generate_ntstatus_table() {
    use std::{collections::BTreeMap, env, fs, path::PathBuf};

    let mut candidates = Vec::new();
    if let Ok(root) = env::var("WindowsSdkDir") {
        candidates.push(PathBuf::from(root).join("Include"));
    }
    if let Ok(root) = env::var("ProgramFiles(x86)") {
        candidates.push(PathBuf::from(root).join("Windows Kits/10/Include"));
    }
    let header = candidates.into_iter().find_map(|include| {
        let mut versions = fs::read_dir(include)
            .ok()?
            .filter_map(Result::ok)
            .collect::<Vec<_>>();
        versions.sort_by_key(|entry| entry.file_name());
        versions
            .into_iter()
            .rev()
            .map(|entry| entry.path().join("shared/ntstatus.h"))
            .find(|path| path.is_file())
    });
    let mut codes = BTreeMap::<u32, String>::new();
    if let Some(header) = header {
        println!("cargo:rerun-if-changed={}", header.display());
        if let Ok(source) = fs::read_to_string(header) {
            for line in source.lines() {
                let mut fields = line.split_whitespace();
                if fields.next() != Some("#define") {
                    continue;
                }
                let Some(name) = fields.next().filter(|name| name.starts_with("STATUS_")) else {
                    continue;
                };
                let Some(start) = line.find("((NTSTATUS)0x").map(|index| index + 13) else {
                    continue;
                };
                let hex = line[start..]
                    .chars()
                    .take_while(|c| c.is_ascii_hexdigit())
                    .collect::<String>();
                if let Ok(value) = u32::from_str_radix(&hex, 16) {
                    if value == 0 && name == "STATUS_SUCCESS" {
                        codes.insert(value, name.to_owned());
                    } else {
                        codes.entry(value).or_insert_with(|| name.to_owned());
                    }
                }
            }
        }
    }
    for (value, name) in [
        (0x00000000, "STATUS_SUCCESS"),
        (0x00000103, "STATUS_PENDING"),
        (0x80000005, "STATUS_BUFFER_OVERFLOW"),
        (0xC0000005, "STATUS_ACCESS_VIOLATION"),
        (0xC000000D, "STATUS_INVALID_PARAMETER"),
        (0xC0000022, "STATUS_ACCESS_DENIED"),
        (0xC0000023, "STATUS_BUFFER_TOO_SMALL"),
        (0xC00000BB, "STATUS_NOT_SUPPORTED"),
    ] {
        codes.insert(value, name.to_owned());
    }
    let mut generated = String::from("pub static NTSTATUS_CODES: &[(u32, &str)] = &[\n");
    for (value, name) in codes {
        generated.push_str(&format!("    (0x{value:08X}, \"{name}\"),\n"));
    }
    generated.push_str("];\n");
    let out =
        PathBuf::from(env::var_os("OUT_DIR").expect("missing OUT_DIR")).join("ntstatus_codes.rs");
    fs::write(out, generated).expect("failed to write NTSTATUS table");
}

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn normalize_file_version(version: &str) -> u64 {
    let mut parts = version
        .split('.')
        .take(4)
        .map(|part| part.parse::<u16>().unwrap_or(0))
        .collect::<Vec<_>>();

    while parts.len() < 4 {
        parts.push(0);
    }

    ((parts[0] as u64) << 48)
        | ((parts[1] as u64) << 32)
        | ((parts[2] as u64) << 16)
        | (parts[3] as u64)
}
