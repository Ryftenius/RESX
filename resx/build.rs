#[cfg(windows)]
fn main() {
    use std::env;

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
    res.set("ProductName", "RESX");
    res.set("ProductVersion", &version);
    res.set("Comments", &comments);
    res.set_version_info(winres::VersionInfo::FILEVERSION, file_version);
    res.set_version_info(winres::VersionInfo::PRODUCTVERSION, file_version);
    res.compile().expect("failed to compile Windows resources");
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
