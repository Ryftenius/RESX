use crate::formats::pe::{
    ImportDll, PeClrInfo, PeDebugInfo, PeFile, PeLoadConfigInfo, IMAGE_GUARD_XFG_ENABLED,
};

use super::model::{BuildAssessment, Candidate};

pub fn machine_name(machine: u16) -> &'static str {
    match machine {
        0x014C => "I386",
        0x8664 => "AMD64",
        0xAA64 => "ARM64",
        0x01C4 => "ARMNT",
        _ => "Unknown",
    }
}

pub fn subsystem_name(subsystem: u16) -> &'static str {
    match subsystem {
        0 => "Unknown",
        1 => "Native",
        2 => "Windows GUI",
        3 => "Windows CUI",
        5 => "OS/2 CUI",
        7 => "POSIX CUI",
        8 => "Native Win9x",
        9 => "Windows CE GUI",
        10 => "EFI Application",
        11 => "EFI Boot Service Driver",
        12 => "EFI Runtime Driver",
        13 => "EFI ROM",
        14 => "Xbox",
        16 => "Windows Boot Application",
        17 => "Xbox Code Catalog",
        _ => "Other",
    }
}

pub fn detect_image_kind(pe: &PeFile, file_name: &str) -> String {
    let lower = file_name.to_ascii_lowercase();
    let is_dll = pe.coff_characteristics & 0x2000 != 0;
    if lower.ends_with(".sys") || (pe.subsystem == 1 && is_dll) {
        return "SYS / Driver".to_owned();
    }
    if lower.ends_with(".dll") || is_dll {
        return "DLL".to_owned();
    }
    if lower.ends_with(".exe") {
        return "EXE".to_owned();
    }
    if lower.ends_with(".efi") {
        return "EFI".to_owned();
    }
    if lower.ends_with(".bin") {
        return "BIN".to_owned();
    }
    match pe.subsystem {
        10..=13 => "EFI".to_owned(),
        16 => "Boot Application".to_owned(),
        1 => "Native Image".to_owned(),
        2 | 3 => "EXE".to_owned(),
        _ if is_dll => "DLL".to_owned(),
        _ => "PE Image".to_owned(),
    }
}

pub fn assess_build(
    pe: &PeFile,
    raw: &[u8],
    imports: &[ImportDll],
    debug: &PeDebugInfo,
    clr: Option<&PeClrInfo>,
    load_config: Option<&PeLoadConfigInfo>,
) -> BuildAssessment {
    let sections = pe
        .sections
        .iter()
        .map(|section| section.name.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let strings = collect_image_strings(raw);
    let import_dlls = imports
        .iter()
        .map(|dll| dll.dll.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let import_names = imports
        .iter()
        .flat_map(|dll| {
            dll.entries
                .iter()
                .map(|entry| entry.name.to_ascii_lowercase())
        })
        .collect::<Vec<_>>();

    let mut langs: Vec<(&str, Candidate)> = Vec::new();
    let mut tools: Vec<(&str, Candidate)> = Vec::new();
    let mut components: Vec<(&str, Candidate)> = Vec::new();
    let mut packers: Vec<(&str, Candidate)> = Vec::new();

    if let Some(clr_info) = clr {
        push_candidate(
            &mut langs,
            ".NET",
            100,
            format!(
                "CLR header present (runtime {}.{})",
                clr_info.major_runtime_version, clr_info.minor_runtime_version
            ),
        );
        push_candidate(
            &mut tools,
            ".NET IL compiler",
            100,
            "COM descriptor directory present",
        );
    }

    if has_section(&sections, ".gopclntab")
        || has_section(&sections, ".go.buildinfo")
        || strings_contains_any(&strings, &["go build id", "runtime.g", "runtime.main"])
    {
        push_candidate(&mut langs, "Go", 100, "Go runtime markers detected");
        push_candidate(
            &mut tools,
            "Go toolchain",
            100,
            "Go-specific sections/strings detected",
        );
    }

    if contains_any(&import_names, &["@lstrclr", "@ustrclr", "@dynarrayclear"]) {
        push_candidate(
            &mut langs,
            "Object Pascal / Delphi",
            95,
            "Delphi runtime markers detected",
        );
        push_candidate(
            &mut tools,
            "Delphi / Pascal compiler",
            95,
            "Borland/Delphi-style symbols detected",
        );
    }

    if contains_any(&import_dlls, &["hsrts", "libgmp"]) {
        push_candidate(&mut langs, "Haskell", 95, "GHC/RTS markers detected");
        push_candidate(
            &mut tools,
            "GHC",
            95,
            "Haskell RTS imports/strings detected",
        );
    }

    let rust_markers = strings_contains_any(
        &strings,
        &[
            "/rustc/",
            "rust_begin_unwind",
            "std::rt::lang_start_internal",
            "core::panicking::panic",
            "alloc::",
            "cargo:",
        ],
    ) || contains_any(
        &import_names,
        &["__rust_alloc", "__rust_dealloc", "__rust_panic_cleanup"],
    );
    if rust_markers {
        push_candidate(
            &mut langs,
            "Rust",
            100,
            "Rust runtime strings/symbols detected",
        );
        push_candidate(
            &mut tools,
            "rustc / Cargo",
            95,
            "Rust standard library or compiler markers detected",
        );
    }

    if contains_prefix(&import_dlls, "python")
        || strings_contains_any(
            &strings,
            &[
                "pyi_rth_",
                "pyimod",
                "meipass",
                "pyinstaller",
                "python3.dll",
            ],
        )
    {
        push_candidate(
            &mut langs,
            "Python",
            95,
            "Python runtime/bundle markers detected",
        );
        push_candidate(
            &mut tools,
            "PyInstaller / embedded CPython",
            90,
            "Python DLL or PyInstaller markers detected",
        );
    }
    if strings_contains_any(
        &strings,
        &[
            "nuitka",
            "__nuitka_binary_dir",
            "onefile_child_grace_time_int",
        ],
    ) {
        push_candidate(&mut tools, "Nuitka", 95, "Nuitka loader markers detected");
        push_candidate(
            &mut components,
            "Nuitka Python bundle",
            95,
            "Nuitka onefile/runtime strings detected",
        );
    }
    if strings_contains_any(&strings, &["py2exe", "zipextimporter", "boot_common.py"]) {
        push_candidate(&mut tools, "py2exe", 90, "py2exe bundle markers detected");
    }
    if strings_contains_any(&strings, &["cx_freeze", "initscripts\\console"]) {
        push_candidate(
            &mut tools,
            "cx_Freeze",
            90,
            "cx_Freeze bundle markers detected",
        );
    }

    if contains_any(&import_dlls, &["node.dll", "libnode.dll", "chrome_elf.dll"])
        || strings_contains_any(
            &strings,
            &[
                "electron.asar",
                "app.asar",
                "crashpad_handler",
                "resources.pak",
            ],
        )
    {
        push_candidate(
            &mut langs,
            "JavaScript / TypeScript",
            90,
            "Node/Electron runtime markers detected",
        );
        push_candidate(
            &mut tools,
            "Node.js / Electron bundle",
            90,
            "Electron/Node runtime assets detected",
        );
        push_candidate(
            &mut components,
            "Electron bundle",
            90,
            "Electron resource markers detected",
        );
    }

    if strings_contains_any(
        &strings,
        &[
            "tauri.conf.json",
            "__tauri__",
            "tauri://localhost",
            "wry::",
            "tao::",
        ],
    ) || contains_any(&import_dlls, &["webview2loader.dll"])
    {
        push_candidate(&mut langs, "Rust", 80, "Tauri runtime markers detected");
        push_candidate(
            &mut tools,
            "Tauri bundle",
            95,
            "Tauri/WebView2 runtime markers detected",
        );
        push_candidate(
            &mut components,
            "Tauri",
            95,
            "Tauri bootstrap or protocol strings detected",
        );
        push_candidate(
            &mut components,
            "WebView2",
            85,
            "WebView2 loader/runtime markers detected",
        );
    }

    if contains_any(
        &import_names,
        &[
            "__cxxframehandler3",
            "__cxxframehandler4",
            "_cxxthrowexception",
        ],
    ) {
        push_candidate(&mut langs, "C++", 80, "C++ EH/RTTI markers detected");
    }

    if contains_any(
        &import_dlls,
        &["msvcp140.dll", "msvcp_win.dll", "libstdc++-6.dll"],
    ) {
        push_candidate(
            &mut langs,
            "C++",
            70,
            "C++ standard library import detected",
        );
    }

    if contains_any(
        &import_dlls,
        &[
            "libstdc++-6.dll",
            "libgcc_s_seh-1.dll",
            "libwinpthread-1.dll",
        ],
    ) || has_section(&sections, ".eh_frame")
        || has_section(&sections, ".gcc_except_table")
    {
        push_candidate(
            &mut tools,
            "MinGW / GCC",
            90,
            "GCC runtime markers detected",
        );
        if !contains_label(&langs, "C++") {
            push_candidate(
                &mut langs,
                "C / C++",
                55,
                "GCC/MinGW runtime imports detected",
            );
        }
    }

    if contains_any(
        &import_dlls,
        &[
            "vcruntime140.dll",
            "vcruntime140_1.dll",
            "ucrtbase.dll",
            "msvcrt.dll",
        ],
    ) {
        push_candidate(&mut tools, "MSVC", 70, "MSVC/UCRT runtime import detected");
        if !contains_any_label(&langs, &["Rust", "Go", "C++", "Object Pascal / Delphi"]) {
            push_candidate(
                &mut langs,
                "C / C++",
                45,
                "Generic MSVC runtime import detected",
            );
        }
    }

    apply_component_heuristics(&mut components, &import_dlls, &strings);
    apply_rust_crate_heuristics(&mut components, &strings);
    apply_packer_heuristics(&mut packers, pe, &sections, &import_dlls, &strings, imports);

    if langs.is_empty() && clr.is_none() {
        push_candidate(
            &mut langs,
            "C / C++ (undetermined)",
            20,
            "No strong managed/runtime-specific markers were found",
        );
    }

    if let Some(codeview) = &debug.codeview {
        if !codeview.pdb_path.is_empty() {
            push_candidate(
                &mut tools,
                "PDB-linked native build",
                30,
                format!("CodeView PDB path: {}", codeview.pdb_path),
            );
        }
    }

    if let Some(load) = load_config {
        if load.guard_flags & IMAGE_GUARD_XFG_ENABLED != 0 {
            push_candidate(
                &mut tools,
                "MSVC (modern CFG/XFG)",
                35,
                "XFG enabled in GuardFlags",
            );
        }
    }

    let likely_languages = finalize_candidates(&mut langs, 3, 40);
    let likely_toolchains = finalize_candidates(&mut tools, 4, 35);
    let likely_components = finalize_candidates(&mut components, 8, 45);
    let detected_packers = finalize_candidates(&mut packers, 4, 45);
    let mut evidence = collect_evidence(&langs, 40);
    evidence.extend(collect_evidence(&tools, 35));
    evidence.extend(collect_evidence(&components, 45));
    evidence.extend(collect_evidence(&packers, 45));
    evidence.truncate(16);

    let platform = if clr.is_some() {
        ".NET PE".to_owned()
    } else {
        "Native PE".to_owned()
    };
    let runtime = if clr.is_some() {
        ".NET CLR".to_owned()
    } else if contains_label(&langs, "Python") {
        "Python runtime bundle".to_owned()
    } else if contains_label(&components, "Electron bundle") {
        "Node/Electron runtime bundle".to_owned()
    } else if contains_label(&components, "Tauri") {
        "Tauri/WebView2 runtime bundle".to_owned()
    } else if contains_label(&langs, "Go") {
        "Go native runtime".to_owned()
    } else if contains_label(&langs, "Rust") {
        "Rust native runtime".to_owned()
    } else {
        "Native PE".to_owned()
    };

    BuildAssessment {
        platform,
        runtime,
        likely_languages,
        likely_toolchains,
        likely_components,
        packers: detected_packers,
        evidence,
    }
}

fn apply_rust_crate_heuristics(list: &mut Vec<(&'static str, Candidate)>, strings: &[String]) {
    let crate_markers: [(&str, &[&str]); 13] = [
        (
            "Tokio",
            &["tokio::", "tokio-runtime-worker", "tokio::runtime"],
        ),
        ("Serde", &["serde::", "serde_json::", "serde_yaml::"]),
        ("Reqwest", &["reqwest::", "hyper::client"]),
        ("Hyper", &["hyper::", "h2::proto"]),
        ("Rustls", &["rustls::", "webpki::", "ring::aead"]),
        ("SQLx", &["sqlx::", "sqlx-core"]),
        ("Rusqlite", &["rusqlite::", "libsqlite3-sys"]),
        ("Clap", &["clap::", "clap_builder::"]),
        ("Anyhow", &["anyhow::", "thiserror::"]),
        (
            "Tracing",
            &["tracing::", "tracing_subscriber::", "env_logger::"],
        ),
        ("Regex", &["regex::", "regex-automata::"]),
        ("Rayon", &["rayon::", "rayon-core::"]),
        ("Egui", &["egui::", "eframe::", "epaint::"]),
    ];

    for (label, markers) in crate_markers {
        if strings_contains_any(strings, markers) {
            push_candidate(
                list,
                label,
                80,
                format!("Rust crate markers detected ({})", markers[0]),
            );
        }
    }
}

fn apply_component_heuristics(
    list: &mut Vec<(&'static str, Candidate)>,
    import_dlls: &[String],
    strings: &[String],
) {
    let dll_components: [(&str, &[&str], &str); 13] = [
        (
            "OpenSSL",
            &["libssl", "libcrypto", "ssleay32", "libeay32"],
            "OpenSSL import DLL detected",
        ),
        (
            "libcurl",
            &["libcurl", "curl.dll"],
            "libcurl import DLL detected",
        ),
        ("SQLite", &["sqlite3.dll"], "SQLite import DLL detected"),
        (
            "zlib",
            &["zlib1.dll", "zlibwapi.dll"],
            "zlib import DLL detected",
        ),
        (
            "Qt",
            &["qt5core.dll", "qt6core.dll", "qt5gui.dll", "qt6gui.dll"],
            "Qt runtime import DLL detected",
        ),
        ("SDL2", &["sdl2.dll"], "SDL2 import DLL detected"),
        ("GLFW", &["glfw3.dll"], "GLFW import DLL detected"),
        ("Vulkan", &["vulkan-1.dll"], "Vulkan loader detected"),
        ("OpenGL", &["opengl32.dll"], "OpenGL import detected"),
        (
            "Direct3D",
            &["d3d11.dll", "d3d12.dll", "dxgi.dll"],
            "Direct3D import detected",
        ),
        ("libuv", &["libuv.dll"], "libuv import DLL detected"),
        (
            "wxWidgets",
            &["wxmsw", "wxbase"],
            "wxWidgets import DLL detected",
        ),
        (
            "OpenCV",
            &["opencv_world", "opencv_core"],
            "OpenCV import DLL detected",
        ),
    ];

    for (label, needles, evidence) in dll_components {
        if contains_any(import_dlls, needles) {
            push_candidate(list, label, 75, evidence);
        }
    }

    if strings_contains_any(strings, &["webview2", "msedgewebview2", "icorewebview2"]) {
        push_candidate(list, "WebView2", 80, "WebView2 strings detected");
    }
    if strings_contains_any(
        strings,
        &["openssl/", "libcurl/", "sqlite format 3", "zlib"],
    ) {
        if strings_contains_any(strings, &["openssl/"]) {
            push_candidate(list, "OpenSSL", 55, "OpenSSL version string detected");
        }
        if strings_contains_any(strings, &["libcurl/"]) {
            push_candidate(list, "libcurl", 55, "libcurl version string detected");
        }
        if strings_contains_any(strings, &["sqlite format 3"]) {
            push_candidate(list, "SQLite", 55, "SQLite file format string detected");
        }
        if strings_contains_any(strings, &["zlib"]) {
            push_candidate(list, "zlib", 40, "zlib strings detected");
        }
    }
}

fn apply_packer_heuristics(
    list: &mut Vec<(&'static str, Candidate)>,
    pe: &PeFile,
    sections: &[String],
    import_dlls: &[String],
    strings: &[String],
    imports: &[ImportDll],
) {
    if has_section(sections, "upx0")
        || has_section(sections, "upx1")
        || strings_contains_any(strings, &["upx!"])
    {
        push_candidate(list, "UPX", 100, "UPX section names or strings detected");
    }
    if has_section(sections, ".aspack") || strings_contains_any(strings, &["aspack"]) {
        push_candidate(list, "ASPack", 95, "ASPack markers detected");
    }
    if has_section(sections, "mpress1")
        || has_section(sections, "mpress2")
        || strings_contains_any(strings, &["mpress"])
    {
        push_candidate(list, "MPRESS", 95, "MPRESS markers detected");
    }
    if has_section(sections, ".vmp0")
        || has_section(sections, ".vmp1")
        || has_section(sections, ".themida")
        || strings_contains_any(strings, &["vmprotect", "themida"])
    {
        push_candidate(
            list,
            "VMProtect / Themida",
            95,
            "VMProtect/Themida markers detected",
        );
    }
    if has_section(sections, ".enigma1")
        || has_section(sections, ".enigma2")
        || strings_contains_any(strings, &["the enigma protector"])
    {
        push_candidate(
            list,
            "Enigma Protector",
            95,
            "Enigma Protector markers detected",
        );
    }
    if strings_contains_any(strings, &["pyinstaller"]) {
        push_candidate(
            list,
            "PyInstaller",
            85,
            "PyInstaller one-file markers detected",
        );
    }

    let high_entropy_exec = pe
        .sections
        .iter()
        .filter(|section| section.is_executable() && section.entropy >= 7.15)
        .count();
    let import_count: usize = imports.iter().map(|dll| dll.entries.len()).sum();
    let tiny_runtime = import_count <= 12
        && !contains_any(
            import_dlls,
            &["msvcrt.dll", "ucrtbase.dll", "kernel32.dll", "ntdll.dll"],
        );
    if high_entropy_exec > 0 && (tiny_runtime || pe.sections.iter().any(|s| s.entropy >= 7.4)) {
        push_candidate(
            list,
            "Packed / Compressed Native Image",
            60,
            format!(
                "{} executable section(s) show high entropy with a sparse import surface",
                high_entropy_exec
            ),
        );
    }
    if pe
        .sections
        .iter()
        .any(|section| section.protection_string().contains('W') && section.is_executable())
        && high_entropy_exec > 0
    {
        push_candidate(
            list,
            "Runtime-unpacked / self-modifying image",
            55,
            "Writable+executable sections were found alongside high-entropy code",
        );
    }
}

fn collect_image_strings(raw: &[u8]) -> Vec<String> {
    use std::collections::BTreeSet;

    let mut out = BTreeSet::new();

    let mut ascii = Vec::new();
    for &b in raw.iter().take(8 * 1024 * 1024) {
        if (0x20..=0x7E).contains(&b) {
            ascii.push(b);
            continue;
        }
        if ascii.len() >= 4 {
            let s = String::from_utf8_lossy(&ascii).to_ascii_lowercase();
            out.insert(s);
        }
        ascii.clear();
    }
    if ascii.len() >= 4 {
        out.insert(String::from_utf8_lossy(&ascii).to_ascii_lowercase());
    }

    let mut wide = Vec::new();
    let mut i = 0usize;
    while i + 1 < raw.len().min(8 * 1024 * 1024) {
        let lo = raw[i];
        let hi = raw[i + 1];
        if hi == 0 && (0x20..=0x7E).contains(&lo) {
            wide.push(lo);
            i += 2;
            continue;
        }
        if wide.len() >= 4 {
            let s = String::from_utf8_lossy(&wide).to_ascii_lowercase();
            out.insert(s);
        }
        wide.clear();
        i += 2;
    }
    if wide.len() >= 4 {
        out.insert(String::from_utf8_lossy(&wide).to_ascii_lowercase());
    }

    out.into_iter().take(8192).collect()
}

fn push_candidate(
    list: &mut Vec<(&'static str, Candidate)>,
    label: &'static str,
    score: i32,
    evidence: impl Into<String>,
) {
    if let Some((_, existing)) = list.iter_mut().find(|(name, _)| *name == label) {
        existing.score += score;
        existing.evidence.push(evidence.into());
        return;
    }
    list.push((
        label,
        Candidate {
            score,
            evidence: vec![evidence.into()],
        },
    ));
}

fn finalize_candidates(
    list: &mut Vec<(&'static str, Candidate)>,
    limit: usize,
    min_score: i32,
) -> Vec<String> {
    list.sort_by(|a, b| b.1.score.cmp(&a.1.score).then_with(|| a.0.cmp(b.0)));
    list.iter()
        .filter(|(_, item)| item.score >= min_score)
        .take(limit)
        .map(|(label, _)| (*label).to_owned())
        .collect()
}

fn collect_evidence(list: &[(&'static str, Candidate)], min_score: i32) -> Vec<String> {
    let mut out = Vec::new();
    for (label, candidate) in list {
        if candidate.score < min_score {
            continue;
        }
        if let Some(first) = candidate.evidence.first() {
            out.push(format!("{}: {}", label, first));
        }
    }
    out
}

fn contains_any(haystack: &[String], needles: &[&str]) -> bool {
    needles.iter().any(|needle| {
        let needle = needle.to_ascii_lowercase();
        haystack.iter().any(|entry| entry.contains(&needle))
    })
}

fn strings_contains_any(haystack: &[String], needles: &[&str]) -> bool {
    contains_any(haystack, needles)
}

fn contains_prefix(haystack: &[String], prefix: &str) -> bool {
    let prefix = prefix.to_ascii_lowercase();
    haystack.iter().any(|entry| entry.starts_with(&prefix))
}

fn has_section(sections: &[String], name: &str) -> bool {
    let want = name.to_ascii_lowercase();
    sections.iter().any(|section| section == &want)
}

fn contains_label(list: &[(&str, Candidate)], label: &str) -> bool {
    list.iter()
        .any(|(name, item)| *name == label && item.score >= 40)
}

fn contains_any_label(list: &[(&str, Candidate)], labels: &[&str]) -> bool {
    labels.iter().any(|label| contains_label(list, label))
}
