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
    raw: &[u8],
    imports: &[ImportDll],
    debug: &PeDebugInfo,
    clr: Option<&PeClrInfo>,
    load_config: Option<&PeLoadConfigInfo>,
) -> BuildAssessment {
    let sections = collect_section_names(raw);
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

    if has_section(&sections, ".gopclntab") || has_section(&sections, ".go.buildinfo") {
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

    if contains_prefix(&import_dlls, "python") {
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

    if contains_any(&import_dlls, &["node.dll", "libnode.dll", "chrome_elf.dll"]) {
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

    let likely_languages = finalize_candidates(&mut langs);
    let likely_toolchains = finalize_candidates(&mut tools);
    let mut evidence = collect_evidence(&langs);
    evidence.extend(collect_evidence(&tools));
    evidence.truncate(8);

    let platform = if clr.is_some() {
        ".NET PE".to_owned()
    } else {
        "Native PE".to_owned()
    };
    let runtime = if clr.is_some() {
        ".NET CLR".to_owned()
    } else if contains_label(&langs, "Python") {
        "Python runtime bundle".to_owned()
    } else if contains_label(&langs, "JavaScript / TypeScript") {
        "Node/Electron runtime bundle".to_owned()
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
        evidence,
    }
}

fn collect_section_names(raw: &[u8]) -> Vec<String> {
    let pe = match crate::formats::pe::parse_pe(raw) {
        Ok(pe) => pe,
        Err(_) => return Vec::new(),
    };
    pe.sections
        .iter()
        .map(|section| section.name.to_ascii_lowercase())
        .collect()
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

fn finalize_candidates(list: &mut Vec<(&'static str, Candidate)>) -> Vec<String> {
    list.sort_by(|a, b| b.1.score.cmp(&a.1.score).then_with(|| a.0.cmp(b.0)));
    list.iter()
        .filter(|(_, item)| item.score >= 40)
        .take(3)
        .map(|(label, _)| (*label).to_owned())
        .collect()
}

fn collect_evidence(list: &[(&'static str, Candidate)]) -> Vec<String> {
    let mut out = Vec::new();
    for (label, candidate) in list {
        if candidate.score < 40 {
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
