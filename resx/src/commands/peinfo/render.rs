use std::io::Write;

use crate::core::color::Colors;
use crate::core::output::{print_pe_anomalies, print_sections};
use crate::formats::metadata::FileMetadata;
use crate::formats::pe::{
    PeClrInfo, PeDebugInfo, PeFile, PeLoadConfigInfo, IMAGE_DLLCHARACTERISTICS_APPCONTAINER,
    IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY,
    IMAGE_DLLCHARACTERISTICS_GUARD_CF, IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA,
    IMAGE_DLLCHARACTERISTICS_NO_BIND, IMAGE_DLLCHARACTERISTICS_NO_ISOLATION,
    IMAGE_DLLCHARACTERISTICS_NO_SEH, IMAGE_DLLCHARACTERISTICS_NX_COMPAT,
    IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE, IMAGE_DLLCHARACTERISTICS_WDM_DRIVER,
    IMAGE_FILE_DEBUG_STRIPPED, IMAGE_FILE_LINE_NUMS_STRIPPED, IMAGE_FILE_LOCAL_SYMS_STRIPPED,
    IMAGE_FILE_RELOCS_STRIPPED, IMAGE_GUARD_CASTGUARD_PRESENT, IMAGE_GUARD_CFW_INSTRUMENTED,
    IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT, IMAGE_GUARD_CF_INSTRUMENTED,
    IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT, IMAGE_GUARD_MEMCPY_PRESENT,
    IMAGE_GUARD_PROTECT_DELAYLOAD_IAT, IMAGE_GUARD_RETPOLINE_PRESENT, IMAGE_GUARD_RF_ENABLE,
    IMAGE_GUARD_RF_INSTRUMENTED, IMAGE_GUARD_RF_STRICT, IMAGE_GUARD_XFG_ENABLED,
};

use super::detect::{machine_name, subsystem_name};
use super::model::{debug_types, safe_seh, BuildAssessment};
use super::triage::TriageFinding;

pub struct TextReport<'a> {
    pub dll_path_str: &'a str,
    pub file_name: &'a str,
    pub raw_len: usize,
    pub pe: &'a PeFile,
    pub exports_len: usize,
    pub imports_len: usize,
    pub import_count: usize,
    pub image_kind: &'a str,
    pub assessment: &'a BuildAssessment,
    pub debug: &'a PeDebugInfo,
    pub clr: Option<&'a PeClrInfo>,
    pub load_config: Option<&'a PeLoadConfigInfo>,
    pub veh_imports: &'a [String],
    pub metadata: &'a FileMetadata,
    pub known_names: &'a [String],
    pub triage: &'a [TriageFinding],
}

pub fn render_text(w: &mut dyn Write, c: &Colors, report: &TextReport<'_>) {
    let mut rows: Vec<Vec<String>> = Vec::new();
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_yellow("General PE Info:"))).ok();
    print_kv(&mut rows, c, "Path", report.dll_path_str);
    print_dual_kv(
        &mut rows,
        c,
        ("File", report.file_name),
        ("Kind", report.image_kind),
    );
    print_dual_kv(
        &mut rows,
        c,
        ("Size", &format!("{} bytes", report.raw_len)),
        ("Arch", &format!("x{}", report.pe.arch)),
    );
    print_dual_kv(
        &mut rows,
        c,
        ("Machine", machine_name(report.pe.machine)),
        ("Subsystem", subsystem_name(report.pe.subsystem)),
    );
    print_dual_kv(
        &mut rows,
        c,
        (
            "Linker",
            &format!(
                "{}.{}",
                report.pe.major_linker_version, report.pe.minor_linker_version
            ),
        ),
        ("Timestamp", &format!("0x{:08X}", report.pe.timestamp)),
    );
    print_dual_kv(
        &mut rows,
        c,
        ("Entry", &format!("0x{:08X}", report.pe.entry_point)),
        ("ImageBase", &format!("0x{:016X}", report.pe.image_base)),
    );
    print_dual_kv(
        &mut rows,
        c,
        ("ImageSize", &format!("0x{:08X}", report.pe.size_of_image)),
        ("Headers", &format!("0x{:08X}", report.pe.size_of_headers)),
    );
    print_dual_kv(
        &mut rows,
        c,
        (
            "SectAlign",
            &format!("0x{:08X}", report.pe.section_alignment),
        ),
        ("FileAlign", &format!("0x{:08X}", report.pe.file_alignment)),
    );
    print_dual_kv(
        &mut rows,
        c,
        ("Checksum", &format!("0x{:08X}", report.pe.checksum)),
        ("SubsystemId", &format!("0x{:04X}", report.pe.subsystem)),
    );
    print_dual_kv(
        &mut rows,
        c,
        (
            "DLLChars",
            &format!("0x{:04X}", report.pe.dll_characteristics),
        ),
        (
            "COFFChars",
            &format!("0x{:04X}", report.pe.coff_characteristics),
        ),
    );
    print_dual_kv(
        &mut rows,
        c,
        ("Exports", &report.exports_len.to_string()),
        ("ImportDLLs", &report.imports_len.to_string()),
    );
    print_kv(&mut rows, c, "Imports", &report.import_count.to_string());

    let path_row = rows.remove(0);
    crate::core::table::print(w, &["Field", "Value"], &[path_row], c);
    crate::core::table::print(w, &["Field", "Value"], &rows, c);
    rows.clear();
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_cyan("Build / Runtime Detection:"))).ok();
    print_dual_kv(
        &mut rows,
        c,
        ("Platform", &report.assessment.platform),
        ("Runtime", &report.assessment.runtime),
    );
    if !report.assessment.likely_languages.is_empty() {
        print_kv(
            &mut rows,
            c,
            "LikelyLanguages",
            &report.assessment.likely_languages.join(", "),
        );
    }
    if !report.assessment.likely_toolchains.is_empty() {
        print_kv(
            &mut rows,
            c,
            "LikelyToolchains",
            &report.assessment.likely_toolchains.join(", "),
        );
    }
    if !report.assessment.likely_components.is_empty() {
        print_kv(
            &mut rows,
            c,
            "LikelyComponents",
            &report.assessment.likely_components.join(", "),
        );
    }
    if !report.assessment.packers.is_empty() {
        print_kv(
            &mut rows,
            c,
            "Packers",
            &report.assessment.packers.join(", "),
        );
    }
    for note in &report.assessment.evidence {
        print_kv(&mut rows, c, "Evidence", note);
    }

    crate::core::table::print(w, &["Field", "Value"], &rows, c);
    rows.clear();
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.green("Debug / Symbols:"))).ok();
    print_dual_kv(
        &mut rows,
        c,
        ("DebugDir", yes_no(!report.debug.entries.is_empty())),
        ("CodeView", yes_no(report.debug.codeview.is_some())),
    );
    let kinds = debug_types(report.debug);
    if !kinds.is_empty() {
        print_kv(&mut rows, c, "DebugTypes", &kinds.join(", "));
    }
    print_dual_kv(
        &mut rows,
        c,
        (
            "DebugStripped",
            yes_no(report.pe.coff_characteristics & IMAGE_FILE_DEBUG_STRIPPED != 0),
        ),
        (
            "LineNumsStripped",
            yes_no(report.pe.coff_characteristics & IMAGE_FILE_LINE_NUMS_STRIPPED != 0),
        ),
    );
    print_kv(
        &mut rows,
        c,
        "LocalSymsStripped",
        yes_no(report.pe.coff_characteristics & IMAGE_FILE_LOCAL_SYMS_STRIPPED != 0),
    );
    if let Some(codeview) = &report.debug.codeview {
        print_optional_kv(&mut rows, c, "PDBPath", &codeview.pdb_path);
        print_optional_kv(&mut rows, c, "PDBName", &codeview.pdb_name);
        print_optional_kv(&mut rows, c, "PDBGuidAge", &codeview.guid_age);
    }
    if let Some(clr) = report.clr {
        let clr_summary = format!(
            "CLR {}.{} {}",
            clr.major_runtime_version,
            clr.minor_runtime_version,
            if clr.metadata_version.is_empty() {
                String::new()
            } else {
                format!("({})", clr.metadata_version)
            }
        );
        print_kv(&mut rows, c, ".NET", clr_summary.trim());
        print_kv(&mut rows, c, "CLRFlags", &format!("0x{:08X}", clr.flags));
        print_kv(
            &mut rows,
            c,
            "CLRMetadata",
            &format!(
                "RVA 0x{:08X}  size 0x{:X}",
                clr.metadata_rva, clr.metadata_size
            ),
        );
        print_kv(
            &mut rows,
            c,
            "CLREntryPoint",
            &format!("0x{:08X}", clr.entry_point_token_or_rva),
        );
    }

    crate::core::table::print(w, &["Field", "Value"], &rows, c);
    rows.clear();
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_yellow("Mitigations / Hardening:"))).ok();
    print_dual_kv(
        &mut rows,
        c,
        (
            "RelocsStripped",
            yes_no(report.pe.coff_characteristics & IMAGE_FILE_RELOCS_STRIPPED != 0),
        ),
        (
            "ASLR",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE != 0),
        ),
    );
    print_dual_kv(
        &mut rows,
        c,
        (
            "HighEntropyVA",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA != 0),
        ),
        (
            "NXCOMPAT",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NX_COMPAT != 0),
        ),
    );
    print_dual_kv(
        &mut rows,
        c,
        (
            "NOSEH",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH != 0),
        ),
        (
            "CFG",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF != 0),
        ),
    );
    print_dual_kv(
        &mut rows,
        c,
        (
            "SEH",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_SEH == 0),
        ),
        ("VEH", yes_no(!report.veh_imports.is_empty())),
    );
    if let Some(load) = report.load_config {
        print_dual_kv(
            &mut rows,
            c,
            (
                "CFGInstr",
                yes_no(load.guard_flags & IMAGE_GUARD_CF_INSTRUMENTED != 0),
            ),
            (
                "CFGWInstr",
                yes_no(load.guard_flags & IMAGE_GUARD_CFW_INSTRUMENTED != 0),
            ),
        );
        print_dual_kv(
            &mut rows,
            c,
            (
                "CFGFuncTable",
                yes_no(load.guard_flags & IMAGE_GUARD_CF_FUNCTION_TABLE_PRESENT != 0),
            ),
            ("CFGFuncCount", &load.guard_cf_function_count.to_string()),
        );
        print_dual_kv(
            &mut rows,
            c,
            ("LoadCfgSize", &format!("0x{:X}", load.size)),
            ("GuardFlags", &format!("0x{:08X}", load.guard_flags)),
        );
        print_dual_kv(
            &mut rows,
            c,
            (
                "XFG",
                yes_no(load.guard_flags & IMAGE_GUARD_XFG_ENABLED != 0),
            ),
            (
                "XFGCheckPtr",
                yes_no(load.guard_xfg_check_function_pointer != 0),
            ),
        );
        print_dual_kv(
            &mut rows,
            c,
            (
                "Retpoline",
                yes_no(load.guard_flags & IMAGE_GUARD_RETPOLINE_PRESENT != 0),
            ),
            (
                "RFInstr",
                yes_no(load.guard_flags & IMAGE_GUARD_RF_INSTRUMENTED != 0),
            ),
        );
        print_dual_kv(
            &mut rows,
            c,
            (
                "RFEnabled",
                yes_no(load.guard_flags & IMAGE_GUARD_RF_ENABLE != 0),
            ),
            (
                "RFStrict",
                yes_no(load.guard_flags & IMAGE_GUARD_RF_STRICT != 0),
            ),
        );
        print_dual_kv(
            &mut rows,
            c,
            (
                "CETEHCont",
                yes_no(load.guard_flags & IMAGE_GUARD_EH_CONTINUATION_TABLE_PRESENT != 0),
            ),
            ("EHContCount", &load.guard_eh_continuation_count.to_string()),
        );
        print_dual_kv(
            &mut rows,
            c,
            (
                "DelayIATProtect",
                yes_no(load.guard_flags & IMAGE_GUARD_PROTECT_DELAYLOAD_IAT != 0),
            ),
            (
                "CastGuard",
                yes_no(load.guard_flags & IMAGE_GUARD_CASTGUARD_PRESENT != 0),
            ),
        );
        print_dual_kv(
            &mut rows,
            c,
            (
                "MemcpyGuard",
                yes_no(load.guard_flags & IMAGE_GUARD_MEMCPY_PRESENT != 0),
            ),
            ("SecurityCookie", yes_no(load.security_cookie != 0)),
        );
        print_kv(
            &mut rows,
            c,
            "SafeSEH",
            yes_no(safe_seh(
                report.pe.arch,
                report.pe.dll_characteristics,
                report.load_config,
            )),
        );
        print_kv(
            &mut rows,
            c,
            "SEHHandlers",
            &load.se_handler_count.to_string(),
        );
    } else {
        print_kv(&mut rows, c, "LoadConfig", "Not present");
    }
    if !report.veh_imports.is_empty() {
        print_kv(&mut rows, c, "VEHImports", &report.veh_imports.join(", "));
    }
    print_dual_kv(
        &mut rows,
        c,
        (
            "ForceIntegrity",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY != 0),
        ),
        (
            "AppContainer",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER != 0),
        ),
    );
    print_dual_kv(
        &mut rows,
        c,
        (
            "WDMDriver",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_WDM_DRIVER != 0),
        ),
        (
            "TerminalSrvAware",
            yes_no(
                report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE != 0,
            ),
        ),
    );
    print_dual_kv(
        &mut rows,
        c,
        (
            "NoIsolation",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_ISOLATION != 0),
        ),
        (
            "NoBind",
            yes_no(report.pe.dll_characteristics & IMAGE_DLLCHARACTERISTICS_NO_BIND != 0),
        ),
    );

    crate::core::table::print(w, &["Field", "Value"], &rows, c);
    rows.clear();
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_blue("Names / Version:"))).ok();
    print_optional_kv(&mut rows, c, "ProductName", &report.metadata.product_name);
    print_optional_kv(
        &mut rows,
        c,
        "FileDescription",
        &report.metadata.file_description,
    );
    print_optional_kv(&mut rows, c, "CompanyName", &report.metadata.company_name);
    print_optional_kv(
        &mut rows,
        c,
        "OriginalFilename",
        &report.metadata.original_filename,
    );
    print_optional_kv(&mut rows, c, "InternalName", &report.metadata.internal_name);
    if !report.known_names.is_empty() {
        print_kv(&mut rows, c, "KnownNames", &report.known_names.join(", "));
    }
    print_optional_kv(&mut rows, c, "FileVersion", &report.metadata.file_version);
    print_optional_kv(
        &mut rows,
        c,
        "ProductVersion",
        &report.metadata.product_version,
    );
    print_optional_kv(&mut rows, c, "Comments", &report.metadata.comments);
    print_optional_kv(&mut rows, c, "Copyright", &report.metadata.legal_copyright);

    crate::core::table::print(w, &["Field", "Value"], &rows, c);
    rows.clear();
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_mag("Signer / Authenticode:"))).ok();
    print_kv(
        &mut rows,
        c,
        "Status",
        &blank_as_unknown(&report.metadata.signature_status),
    );
    print_optional_kv(&mut rows, c, "Subject", &report.metadata.signer_subject);
    print_optional_kv(&mut rows, c, "Issuer", &report.metadata.signer_issuer);
    print_optional_kv(
        &mut rows,
        c,
        "Thumbprint",
        &report.metadata.signer_thumbprint,
    );

    crate::core::table::print(w, &["Field", "Value"], &rows, c);
    print_sections(w, report.pe, c);
    print_triage(w, report.triage, c);
    print_pe_anomalies(w, &report.pe.anomalies, c);
}

fn print_triage(w: &mut dyn Write, findings: &[TriageFinding], c: &Colors) {
    if findings.is_empty() {
        return;
    }
    writeln!(w, "\n{}", c.bold(&c.b_yellow("Analyst Triage:"))).ok();
    for finding in findings {
        let marker = if finding.severity == "warn" {
            c.b_yellow("!")
        } else {
            c.b_cyan("i")
        };
        writeln!(
            w,
            "  {} {} {}",
            marker,
            c.bold(&finding.title),
            c.dim(&format!("[{} confidence]", finding.confidence))
        )
        .ok();
        for evidence in &finding.evidence {
            writeln!(w, "    {} {}", c.cyan("observed:"), evidence).ok();
        }
        if !finding.interpretation.is_empty() {
            writeln!(
                w,
                "    {} {}",
                c.b_mag("interpretation:"),
                finding.interpretation
            )
            .ok();
        }
    }
}

fn print_kv(rows: &mut Vec<Vec<String>>, _c: &Colors, key: &str, value: &str) {
    rows.push(vec![key.to_owned(), value.to_owned()]);
}

fn print_dual_kv(rows: &mut Vec<Vec<String>>, c: &Colors, left: (&str, &str), right: (&str, &str)) {
    print_kv(rows, c, left.0, left.1);
    print_kv(rows, c, right.0, right.1);
}

fn print_optional_kv(rows: &mut Vec<Vec<String>>, c: &Colors, key: &str, value: &str) {
    if !value.trim().is_empty() {
        print_kv(rows, c, key, value);
    }
}

pub fn blank_as_unknown(value: &str) -> String {
    if value.trim().is_empty() {
        "Unknown".to_owned()
    } else {
        value.to_owned()
    }
}

pub fn yes_no(value: bool) -> &'static str {
    if value {
        "Yes"
    } else {
        "No"
    }
}
