use std::ffi::OsStr;
use std::io::Write;
use std::thread;

use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::json::versioned_object;
use crate::core::output::StageProgress;
use crate::core::search::find_dll_path;
use crate::formats::metadata::{query_file_metadata, FileMetadata};
use crate::formats::pe::{
    find_startup_routines, parse_pe, read_clr_info, read_debug_info, read_exports, read_imports,
    read_load_config, ImportDll, PeDebugInfo, PeLoadConfigInfo,
    IMAGE_DLLCHARACTERISTICS_APPCONTAINER, IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE,
    IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY, IMAGE_DLLCHARACTERISTICS_GUARD_CF,
    IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA, IMAGE_DLLCHARACTERISTICS_NO_SEH,
    IMAGE_DLLCHARACTERISTICS_NX_COMPAT, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
    IMAGE_FILE_DEBUG_STRIPPED, IMAGE_FILE_LINE_NUMS_STRIPPED, IMAGE_FILE_LOCAL_SYMS_STRIPPED,
    IMAGE_FILE_RELOCS_STRIPPED, IMAGE_GUARD_CASTGUARD_PRESENT, IMAGE_GUARD_CFW_INSTRUMENTED,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, IMAGE_GUARD_CF_INSTRUMENTED,
    IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT, IMAGE_GUARD_MEMCPY_PRESENT,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT, IMAGE_GUARD_RETPOLINE_PRESENT, IMAGE_GUARD_RF_ENABLE,
    IMAGE_GUARD_RF_INSTRUMENTED, IMAGE_GUARD_RF_STRICT, IMAGE_GUARD_XFG_ENABLED,
};

use self::detect::{assess_build, detect_image_kind, machine_name, subsystem_name};
use self::model::{
    debug_types, safe_seh, to_anomaly_json, to_section_json, to_startup_json, AnalysisJson,
    DebugJson, MitigationsJson, NameJson, PeInfoJson, SignerJson,
};
use self::render::{blank_as_unknown, render_text, TextReport};

mod detect;
mod model;
mod render;

pub fn run(dll_arg: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    let mut progress = StageProgress::new(9, !cfg.quiet && !cfg.json, c.on);
    if !cfg.quiet && !cfg.json {
        writeln!(
            w,
            "{}",
            c.info(&format!("Collecting PE info for '{}'...", dll_arg))
        )
        .ok();
    }

    let dll_path = find_dll_path(dll_arg, cfg)?;
    progress.tick("locating target image");
    let dll_path_str = dll_path.to_string_lossy().to_string();
    let file_name = dll_path
        .file_name()
        .unwrap_or_else(|| OsStr::new(""))
        .to_string_lossy()
        .to_string();
    let metadata_path = dll_path_str.clone();
    let metadata_task =
        thread::spawn(move || query_file_metadata(&metadata_path).unwrap_or_default());

    let raw = std::fs::read(&dll_path).map_err(|e| format!("read file: {}", e))?;
    progress.tick("reading image");
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    progress.tick("parsing PE headers");
    let exports = read_exports(&pe, &raw);
    progress.tick("reading export table");
    let imports = read_imports(&pe, &raw);
    progress.tick("reading import table");
    let import_count: usize = imports.iter().map(|dll| dll.entries.len()).sum();
    let debug = read_debug_info(&pe, &raw);
    progress.tick("reading debug directory");
    let clr = read_clr_info(&pe, &raw);
    progress.tick("reading CLR metadata");
    let load_config = read_load_config(&pe, &raw);
    progress.tick("reading load config");
    let metadata = metadata_task.join().unwrap_or_default();
    progress.tick("querying file metadata");
    progress.finish();

    let known_names = collect_known_names(&file_name, &metadata);
    let image_kind = detect_image_kind(&pe, &file_name);
    let assessment = assess_build(&pe, &raw, &imports, &debug, clr.as_ref(), load_config.as_ref());
    let veh_imports = detect_veh_imports(&imports);
    let startup_routines = find_startup_routines(&pe, &raw);

    if cfg.json {
        let out = PeInfoJson {
            path: dll_path_str,
            file_name,
            file_size: raw.len() as u64,
            image_kind,
            arch: format!("x{}", pe.arch),
            machine: machine_name(pe.machine).to_owned(),
            linker_version: format!("{}.{}", pe.major_linker_version, pe.minor_linker_version),
            timestamp: format!("0x{:08X}", pe.timestamp),
            image_base: format!("0x{:016X}", pe.image_base),
            entry_point: format!("0x{:08X}", pe.entry_point),
            size_of_image: format!("0x{:08X}", pe.size_of_image),
            size_of_headers: format!("0x{:08X}", pe.size_of_headers),
            section_alignment: format!("0x{:08X}", pe.section_alignment),
            file_alignment: format!("0x{:08X}", pe.file_alignment),
            checksum: format!("0x{:08X}", pe.checksum),
            subsystem: format!("0x{:04X}", pe.subsystem),
            subsystem_name: subsystem_name(pe.subsystem).to_owned(),
            dll_characteristics: format!("0x{:04X}", pe.dll_characteristics),
            coff_characteristics: format!("0x{:04X}", pe.coff_characteristics),
            header_corrupt: pe.header_corruption_detected(),
            export_count: exports.len(),
            import_dll_count: imports.len(),
            import_count,
            analysis: AnalysisJson {
                platform: assessment.platform.clone(),
                runtime: assessment.runtime.clone(),
                likely_languages: assessment.likely_languages.clone(),
                likely_toolchains: assessment.likely_toolchains.clone(),
                likely_components: assessment.likely_components.clone(),
                packers: assessment.packers.clone(),
                evidence: assessment.evidence.clone(),
                clr_metadata_version: clr
                    .as_ref()
                    .map(|value| value.metadata_version.clone())
                    .unwrap_or_default(),
            },
            debug: to_debug_json(&pe, &debug),
            mitigations: to_mitigations_json(&pe, load_config.as_ref(), &veh_imports),
            names: NameJson {
                product_name: metadata.product_name.clone(),
                file_description: metadata.file_description.clone(),
                company_name: metadata.company_name.clone(),
                original_filename: metadata.original_filename.clone(),
                internal_name: metadata.internal_name.clone(),
                known_names,
                file_version: metadata.file_version.clone(),
                product_version: metadata.product_version.clone(),
                comments: metadata.comments.clone(),
                legal_copyright: metadata.legal_copyright.clone(),
            },
            signer: SignerJson {
                status: blank_as_unknown(&metadata.signature_status),
                subject: metadata.signer_subject.clone(),
                issuer: metadata.signer_issuer.clone(),
                thumbprint: metadata.signer_thumbprint.clone(),
            },
            startup_routines: startup_routines.iter().map(to_startup_json).collect(),
            sections: pe.sections.iter().map(to_section_json).collect(),
            anomalies: pe.anomalies.iter().map(to_anomaly_json).collect(),
        };
        writeln!(
            w,
            "{}",
            serde_json::to_string_pretty(&versioned_object("peinfo", &out)).unwrap_or_default()
        )
        .ok();
        return Ok(());
    }

    render_text(
        w,
        c,
        &TextReport {
            dll_path_str: &dll_path_str,
            file_name: &file_name,
            raw_len: raw.len(),
            pe: &pe,
            exports_len: exports.len(),
            imports_len: imports.len(),
            import_count,
            image_kind: &image_kind,
            assessment: &assessment,
            debug: &debug,
            clr: clr.as_ref(),
            load_config: load_config.as_ref(),
            veh_imports: &veh_imports,
            metadata: &metadata,
            known_names: &known_names,
        },
    );
    Ok(())
}

fn collect_known_names(file_name: &str, meta: &FileMetadata) -> Vec<String> {
    let mut out = Vec::new();
    for candidate in [file_name, &meta.original_filename, &meta.internal_name] {
        let trimmed = candidate.trim();
        if !trimmed.is_empty()
            && !out
                .iter()
                .any(|value: &String| value.eq_ignore_ascii_case(trimmed))
        {
            out.push(trimmed.to_owned());
        }
    }
    out
}

fn to_debug_json(pe: &crate::formats::pe::PeFile, debug: &PeDebugInfo) -> DebugJson {
    DebugJson {
        has_debug_directory: !debug.entries.is_empty(),
        debug_types: debug_types(debug),
        has_codeview: debug.codeview.is_some(),
        debug_stripped: pe.coff_characteristics & IMAGE_FILE_DEBUG_STRIPPED != 0,
        line_numbers_stripped: pe.coff_characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED != 0,
        local_symbols_stripped: pe.coff_characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED != 0,
        pdb_path: debug
            .codeview
            .as_ref()
            .map(|value| value.pdb_path.clone())
            .unwrap_or_default(),
        pdb_name: debug
            .codeview
            .as_ref()
            .map(|value| value.pdb_name.clone())
            .unwrap_or_default(),
        pdb_guid_age: debug
            .codeview
            .as_ref()
            .map(|value| value.guid_age.clone())
            .unwrap_or_default(),
    }
}

fn to_mitigations_json(
    pe: &crate::formats::pe::PeFile,
    load_config: Option<&PeLoadConfigInfo>,
    veh_imports: &[String],
) -> MitigationsJson {
    let guard_flags = load_config
        .map(|value| value.guard_flags)
        .unwrap_or_default();
    MitigationsJson {
        reloc_stripped: pe.coff_characteristics & IMAGE_FILE_RELOCS_STRIPPED != 0,
        aslr: pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0,
        high_entropy_va: pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0,
        nx_compat: pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0,
        no_seh: pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH != 0,
        seh_available: pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH == 0,
        force_integrity: pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0,
        appcontainer: pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0,
        wdm_driver: pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0,
        cfg: pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0,
        cfg_instrumented: guard_flags & IMAGE_GUARD_CF_INSTRUMENTED != 0,
        cfg_w_instrumented: guard_flags & IMAGE_GUARD_CFW_INSTRUMENTED != 0,
        cfg_function_table: guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT != 0,
        xfg: guard_flags & IMAGE_GUARD_XFG_ENABLED != 0,
        retpoline: guard_flags & IMAGE_GUARD_RETPOLINE_PRESENT != 0,
        rf_instrumented: guard_flags & IMAGE_GUARD_RF_INSTRUMENTED != 0,
        rf_enabled: guard_flags & IMAGE_GUARD_RF_ENABLE != 0,
        rf_strict: guard_flags & IMAGE_GUARD_RF_STRICT != 0,
        cet_eh_continuation: guard_flags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT != 0,
        cast_guard: guard_flags & IMAGE_GUARD_CASTGUARD_PRESENT != 0,
        memcpy_guard: guard_flags & IMAGE_GUARD_MEMCPY_PRESENT != 0,
        delay_load_iat_protected: guard_flags & IMAGE_GUARD_PROTECT_DELAYLOAD_IAT != 0,
        security_cookie: load_config.is_some_and(|value| value.security_cookie != 0),
        safe_seh: safe_seh(pe.arch, pe.dll_characteristics, load_config),
        se_handler_count: load_config
            .map(|value| value.se_handler_count)
            .unwrap_or_default(),
        veh_imports: veh_imports.to_vec(),
    }
}

fn detect_veh_imports(imports: &[ImportDll]) -> Vec<String> {
    let veh_names = [
        "AddVectoredExceptionHandler",
        "AddVectoredContinueHandler",
        "RemoveVectoredExceptionHandler",
        "RemoveVectoredContinueHandler",
        "RtlAddVectoredExceptionHandler",
        "RtlAddVectoredContinueHandler",
        "RtlRemoveVectoredExceptionHandler",
        "RtlRemoveVectoredContinueHandler",
    ];

    let mut out = Vec::new();
    for dll in imports {
        for entry in &dll.entries {
            if veh_names
                .iter()
                .any(|name| entry.name.eq_ignore_ascii_case(name))
            {
                out.push(format!("{}!{}", dll.dll, entry.name));
            }
        }
    }
    out.sort();
    out.dedup();
    out
}
