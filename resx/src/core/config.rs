use crate::core::priority::{
    built_in_priority_names, built_in_priority_prefixes, load_priority_file,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    name = "resx",
    version = env!("CARGO_PKG_VERSION"),
    author = "TITAN Softwork Solutions",
    about = "Windows binary recon CLI for exports, symbols, metadata, CFG, callers, and triage",
    long_about = None,
    disable_help_flag = true,
)]
pub struct Cli {
    pub dll: Option<String>,

    pub function: Option<String>,

    #[arg(value_name = "EXTRA_IMAGE")]
    pub extra_images: Vec<String>,

    #[arg(long = "at")]
    pub at_rva: Option<String>,

    #[arg(long = "ordinal", short = 'n')]
    pub ordinal: Option<u32>,

    #[arg(long = "path", action = clap::ArgAction::Append, value_name = "DIR")]
    pub paths: Vec<String>,

    #[arg(long = "priority")]
    pub priority: bool,

    #[arg(long = "no-system")]
    pub no_system: bool,

    #[arg(long = "no-cwd")]
    pub no_cwd: bool,

    #[arg(long = "no-path")]
    pub no_path: bool,

    #[arg(long = "arch", default_value = "auto")]
    pub arch: String,

    #[arg(long = "rebase")]
    pub rebase: Option<String>,

    #[arg(long = "pdb")]
    pub pdb_file: Option<String>,

    #[arg(long = "sym-path")]
    pub sym_path: Option<String>,

    #[arg(long = "sym-server")]
    pub sym_server: Option<String>,

    #[arg(long = "reload")]
    pub reload: bool,

    #[arg(long = "no-pdb")]
    pub no_pdb: bool,

    #[arg(long = "c-out")]
    pub c_out: Option<String>,

    #[arg(long = "edrchk")]
    pub edrchk: bool,

    #[arg(long = "unsafe-map-image")]
    pub unsafe_map_image: bool,

    #[arg(long = "hookchk")]
    pub hookchk: bool,

    #[arg(long = "intelli")]
    pub intelli: bool,

    #[arg(long = "patch", hide = true)]
    pub patch: bool,

    #[arg(long = "patch-bytes", value_name = "HEX")]
    pub patch_bytes: Option<String>,

    #[arg(long = "expect", alias = "expected", value_name = "HEX")]
    pub patch_expect: Option<String>,

    #[arg(long = "patch-out", value_name = "FILE")]
    pub patch_out: Option<String>,

    #[arg(long = "dry-run")]
    pub patch_dry_run: bool,

    #[arg(long = "in-place")]
    pub patch_in_place: bool,

    #[arg(long = "overwrite")]
    pub patch_overwrite: bool,

    #[arg(long = "update-checksum")]
    pub patch_update_checksum: bool,

    #[arg(long = "reconstruct-cfg")]
    pub reconstruct_cfg: bool,

    #[arg(long = "thread-filter", default_value = "")]
    pub reconstruct_thread_filter: String,

    #[arg(long = "api-filter", default_value = "")]
    pub reconstruct_api_filter: String,

    #[arg(long = "max-insns", default_value_t = 500)]
    pub max_insns: usize,

    #[arg(long = "max-bytes", default_value_t = 8192)]
    pub max_bytes: usize,

    #[arg(long = "bytes", default_value_t = true, action = clap::ArgAction::SetTrue)]
    pub show_bytes: bool,

    #[arg(long = "no-bytes", action = clap::ArgAction::SetTrue)]
    pub no_bytes: bool,

    #[arg(long = "intel", default_value_t = true, action = clap::ArgAction::SetTrue)]
    pub intel: bool,

    #[arg(long = "att", action = clap::ArgAction::SetTrue)]
    pub att: bool,

    #[arg(long = "follow-jmp", default_value_t = true, action = clap::ArgAction::SetTrue)]
    pub follow_jmp: bool,

    #[arg(long = "no-follow-jmp", action = clap::ArgAction::SetTrue)]
    pub no_follow_jmp: bool,

    #[arg(long = "no-follow-forward")]
    pub no_follow_forward: bool,

    #[arg(long = "show-offsets")]
    pub show_offsets: bool,

    #[arg(long = "show-rva")]
    pub show_rva: bool,

    #[arg(long = "addr-width", default_value_t = 8)]
    pub addr_width: usize,

    #[arg(long = "width", default_value_t = 10)]
    pub byte_col_width: usize,

    #[arg(long = "color")]
    pub force_color: bool,

    #[arg(long = "no-color")]
    pub no_color: bool,

    #[arg(long = "json")]
    pub json: bool,

    #[arg(long = "out", short = 'o')]
    pub out_file: Option<String>,

    #[arg(long = "verbose", short = 'v')]
    pub verbose: bool,

    #[arg(long = "quiet", short = 'q')]
    pub quiet: bool,

    #[arg(long = "recomp")]
    pub recomp: bool,

    #[arg(long = "xrefs")]
    pub xrefs: bool,

    #[arg(long = "strings")]
    pub strings: bool,

    #[arg(long = "funcs")]
    pub funcs: bool,

    /// Recursively trace internal sub_XXXXXXXX calls N levels deep (implies --funcs).
    #[arg(long = "funcs-depth", value_name = "N")]
    pub funcs_depth: Option<u32>,

    #[arg(long = "cfg", value_name = "FMT")]
    pub cfg_view: Option<String>,

    #[arg(long = "show-eat")]
    pub show_eat: bool,

    #[arg(long = "show-iat")]
    pub show_iat: bool,

    #[arg(long = "sections")]
    pub sections: bool,

    #[arg(long = "pechk")]
    pub pechk: bool,

    #[arg(long = "show-syms")]
    pub show_syms: bool,

    #[arg(long = "follow-callers")]
    pub follow_callers: bool,

    #[arg(long = "peinfo")]
    pub peinfo: bool,

    #[arg(long = "yara", action = clap::ArgAction::Append, value_name = "RULE_FILE")]
    pub yara: Vec<String>,

    #[arg(long = "resx-scan", hide = true)]
    pub resx_scan: bool,

    #[arg(long = "resx-diff", hide = true)]
    pub resx_diff: bool,

    #[arg(long = "resx-index", hide = true)]
    pub resx_index: bool,

    #[arg(long = "resx-hunt", hide = true)]
    pub resx_hunt: bool,

    #[arg(long = "db", default_value = "resx-corpus.json")]
    pub corpus_db: String,

    #[arg(long = "diff-mode", default_value = "balanced")]
    pub diff_mode: String,

    #[arg(long = "diff-threshold", default_value_t = 65)]
    pub diff_threshold: u8,

    #[arg(long = "include-weak")]
    pub include_weak: bool,

    #[arg(long = "max-functions", default_value_t = 2000)]
    pub diff_max_functions: usize,

    #[arg(long = "left-pdb")]
    pub left_pdb_file: Option<String>,

    #[arg(long = "right-pdb")]
    pub right_pdb_file: Option<String>,

    #[arg(long = "show-cfg-diff", value_name = "FUNCTION_OR_RVA")]
    pub cfg_diff_target: Option<String>,

    #[arg(long = "cfg-diff-format", default_value = "text")]
    pub cfg_diff_format: String,

    #[arg(long = "cfg-diff-out")]
    pub cfg_diff_out: Option<String>,

    #[arg(long = "max-cfg-blocks", default_value_t = 128)]
    pub max_cfg_blocks: usize,

    #[arg(long = "diff-graph")]
    pub diff_graph: bool,

    #[arg(long = "diff-graph-format", default_value = "text")]
    pub diff_graph_format: String,

    #[arg(long = "diff-graph-out")]
    pub diff_graph_out: Option<String>,

    #[arg(long = "scan-root", hide = true)]
    pub scan_root: Option<String>,

    #[arg(long = "jsonl")]
    pub jsonl: bool,

    #[arg(long = "extensions", default_value = "exe,dll,sys")]
    pub scan_extensions: String,

    #[arg(long = "max-files", default_value_t = 200)]
    pub max_files: usize,

    #[arg(long = "max-file-mb", default_value_t = 200)]
    pub max_file_mb: u64,

    #[arg(long = "max-candidates", default_value_t = 32)]
    pub max_candidates: usize,

    #[arg(long = "include-dir", alias = "scan-dir", action = clap::ArgAction::Append, value_name = "DIR")]
    pub scan_dirs: Vec<String>,

    #[arg(long = "include-image", alias = "scan-dll", action = clap::ArgAction::Append, value_name = "DLL")]
    pub scan_dlls: Vec<String>,

    #[arg(long = "scan-exe")]
    pub scan_exe: bool,

    #[arg(long = "include", default_value = "")]
    pub include: String,

    #[arg(long = "scope-file", alias = "include-file", default_value = "")]
    pub scope_file: String,

    #[arg(long = "exclude", default_value = "")]
    pub exclude: String,

    #[arg(long = "max-dll-size", default_value_t = 200)]
    pub max_dll_mb: u64,

    #[arg(long = "workers", default_value_t = 8)]
    pub workers: usize,

    #[arg(long = "depth", default_value_t = 3)]
    pub depth: usize,

    #[arg(long = "max-callers", default_value_t = 30)]
    pub max_callers: usize,

    #[arg(long = "max-total", default_value_t = 500)]
    pub max_total: usize,

    #[arg(long = "format", default_value = "tree")]
    pub follow_format: String,

    #[arg(long = "show-site")]
    pub show_site: bool,

    #[arg(long = "filter-dll", default_value = "")]
    pub filter_dll: String,

    #[arg(long = "example")]
    pub example: bool,

    #[arg(long = "locate")]
    pub locate: bool,

    #[arg(long = "locate-sym")]
    pub locate_deep: bool,

    #[arg(long = "update")]
    pub update: bool,

    #[arg(long = "explain")]
    pub explain: bool,

    #[arg(long = "prefix")]
    pub explain_prefix: bool,

    #[arg(long = "api")]
    pub explain_api: bool,

    /// Enable aggressive tracing: recursive register backward-slice, decoder-driven
    /// reverse-index, indirect-JMP emission, and suspicion annotations in disasm.
    #[arg(long = "hostile")]
    pub hostile: bool,
}

#[derive(Debug, Clone)]
pub struct Config {
    pub dll: String,
    pub function: String,
    pub extra_diff_images: Vec<String>,

    pub at_rva: String,
    pub ordinal: u32,

    pub extra_paths: Vec<String>,
    pub priority_dirs: Vec<String>,
    pub priority_names: Vec<String>,
    pub priority_prefixes: Vec<String>,
    pub priority_regexes: Vec<String>,
    pub no_system: bool,
    pub no_cwd: bool,
    pub no_path: bool,

    pub arch: String,
    pub rebase: String,

    pub pdb_file: String,
    pub sym_path: String,
    pub sym_server: String,
    pub reload: bool,
    pub no_pdb: bool,
    pub c_out: String,
    pub edrchk: bool,
    pub unsafe_map_image: bool,
    pub hookchk: bool,
    pub intelli: bool,
    pub patch: bool,
    pub patch_bytes: String,
    pub patch_expect: String,
    pub patch_out: String,
    pub patch_dry_run: bool,
    pub patch_in_place: bool,
    pub patch_overwrite: bool,
    pub patch_update_checksum: bool,
    pub reconstruct_cfg: bool,
    pub reconstruct_thread_filter: String,
    pub reconstruct_api_filter: String,

    pub max_insns: usize,
    pub max_bytes: usize,
    pub show_bytes: bool,
    pub intel_syntax: bool,
    pub follow_jmp: bool,
    pub no_follow_fwd: bool,
    pub show_offsets: bool,
    pub show_rva: bool,
    pub addr_width: usize,
    pub byte_col_width: usize,

    pub json: bool,
    pub out_file: String,
    pub verbose: bool,
    pub quiet: bool,

    pub recomp: bool,
    pub show_xrefs: bool,
    pub show_strings: bool,
    pub funcs_depth: u32,
    pub cfg_view: String,
    pub show_eat: bool,
    pub show_iat: bool,
    pub sections: bool,
    pub pechk: bool,
    pub show_syms: bool,
    pub follow_callers: bool,
    pub peinfo: bool,
    pub yara: Vec<String>,
    pub resx_diff: bool,
    pub resx_index: bool,
    pub resx_hunt: bool,
    pub corpus_db: String,
    pub diff_mode: String,
    pub diff_threshold: u8,
    pub include_weak: bool,
    pub diff_max_functions: usize,
    pub left_pdb_file: String,
    pub right_pdb_file: String,
    pub cfg_diff_target: String,
    pub cfg_diff_format: String,
    pub cfg_diff_out: String,
    pub max_cfg_blocks: usize,
    pub diff_graph: bool,
    pub diff_graph_format: String,
    pub diff_graph_out: String,
    pub scan_dirs: Vec<String>,
    pub scan_extensions: String,
    pub max_files: usize,
    pub max_file_mb: u64,
    pub max_candidates: usize,
    pub scan_dlls: Vec<String>,
    pub scan_exe: bool,
    pub include: String,
    pub scope_file: String,
    pub exclude: String,
    pub max_dll_mb: u64,
    pub workers: usize,
    pub depth: usize,
    pub max_callers: usize,
    pub max_total: usize,
    pub follow_format: String,
    pub show_site: bool,
    pub filter_dll: String,
    pub locate: bool,
    pub locate_deep: bool,
    pub explain: bool,
    pub explain_prefix: bool,
    pub explain_api: bool,
    pub hostile: bool,
}

impl Config {
    pub fn from_cli(cli: &Cli, _color: bool) -> Self {
        let priority_file = load_priority_file();
        let mut priority_names = built_in_priority_names();
        priority_names.extend(priority_file.exact_names);
        let mut priority_prefixes = built_in_priority_prefixes();
        priority_prefixes.extend(priority_file.prefixes);
        Config {
            dll: cli.dll.clone().unwrap_or_default(),
            function: cli.function.clone().unwrap_or_default(),
            extra_diff_images: cli.extra_images.clone(),
            at_rva: cli.at_rva.clone().unwrap_or_default(),
            ordinal: cli.ordinal.unwrap_or(0),
            extra_paths: cli.paths.clone(),
            priority_dirs: priority_file.priority_dirs,
            priority_names,
            priority_prefixes,
            priority_regexes: priority_file.regexes,
            no_system: cli.no_system,
            no_cwd: cli.no_cwd,
            no_path: cli.no_path,
            arch: cli.arch.clone(),
            rebase: cli.rebase.clone().unwrap_or_default(),
            pdb_file: cli.pdb_file.clone().unwrap_or_default(),
            sym_path: cli.sym_path.clone().unwrap_or_default(),
            sym_server: cli.sym_server.clone().unwrap_or_default(),
            reload: cli.reload,
            no_pdb: cli.no_pdb,
            c_out: cli.c_out.clone().unwrap_or_default(),
            edrchk: cli.edrchk,
            unsafe_map_image: cli.unsafe_map_image,
            hookchk: cli.hookchk,
            intelli: cli.intelli,
            patch: cli.patch,
            patch_bytes: cli.patch_bytes.clone().unwrap_or_default(),
            patch_expect: cli.patch_expect.clone().unwrap_or_default(),
            patch_out: cli.patch_out.clone().unwrap_or_default(),
            patch_dry_run: cli.patch_dry_run,
            patch_in_place: cli.patch_in_place,
            patch_overwrite: cli.patch_overwrite,
            patch_update_checksum: cli.patch_update_checksum,
            reconstruct_cfg: cli.reconstruct_cfg,
            reconstruct_thread_filter: cli.reconstruct_thread_filter.clone(),
            reconstruct_api_filter: cli.reconstruct_api_filter.clone(),
            max_insns: cli.max_insns,
            max_bytes: cli.max_bytes,
            show_bytes: cli.show_bytes && !cli.no_bytes,
            intel_syntax: !cli.att || cli.intel,
            follow_jmp: cli.follow_jmp && !cli.no_follow_jmp,
            no_follow_fwd: cli.no_follow_forward,
            show_offsets: cli.show_offsets,
            show_rva: cli.show_rva,
            addr_width: cli.addr_width,
            byte_col_width: cli.byte_col_width,
            json: cli.json
                || cli.jsonl
                || cli.resx_scan
                || (cli.resx_diff && cli.cfg_diff_format.eq_ignore_ascii_case("json")),
            out_file: cli.out_file.clone().unwrap_or_default(),
            verbose: cli.verbose,
            quiet: cli.quiet,
            recomp: cli.recomp,
            show_xrefs: cli.xrefs,
            show_strings: cli.strings,
            funcs_depth: cli.funcs_depth.unwrap_or(if cli.funcs { 1 } else { 0 }),
            cfg_view: cli.cfg_view.clone().unwrap_or_default(),
            show_eat: cli.show_eat,
            show_iat: cli.show_iat,
            sections: cli.sections,
            pechk: cli.pechk,
            show_syms: cli.show_syms,
            follow_callers: cli.follow_callers,
            peinfo: cli.peinfo,
            yara: cli.yara.clone(),
            resx_diff: cli.resx_diff,
            resx_index: cli.resx_index,
            resx_hunt: cli.resx_hunt,
            corpus_db: cli.corpus_db.clone(),
            diff_mode: cli.diff_mode.clone(),
            diff_threshold: cli.diff_threshold,
            include_weak: cli.include_weak,
            diff_max_functions: cli.diff_max_functions,
            left_pdb_file: cli.left_pdb_file.clone().unwrap_or_default(),
            right_pdb_file: cli.right_pdb_file.clone().unwrap_or_default(),
            cfg_diff_target: cli.cfg_diff_target.clone().unwrap_or_default(),
            cfg_diff_format: cli.cfg_diff_format.clone(),
            cfg_diff_out: cli.cfg_diff_out.clone().unwrap_or_default(),
            max_cfg_blocks: cli.max_cfg_blocks,
            diff_graph: cli.diff_graph,
            diff_graph_format: cli.diff_graph_format.clone(),
            diff_graph_out: cli.diff_graph_out.clone().unwrap_or_default(),
            scan_dirs: cli.scan_dirs.clone(),
            scan_extensions: cli.scan_extensions.clone(),
            max_files: cli.max_files,
            max_file_mb: cli.max_file_mb,
            max_candidates: cli.max_candidates,
            scan_dlls: cli.scan_dlls.clone(),
            scan_exe: cli.scan_exe,
            include: cli.include.clone(),
            scope_file: cli.scope_file.clone(),
            exclude: cli.exclude.clone(),
            max_dll_mb: cli.max_dll_mb,
            workers: cli.workers,
            depth: cli.depth,
            max_callers: cli.max_callers,
            max_total: cli.max_total,
            follow_format: cli.follow_format.clone(),
            show_site: cli.show_site,
            filter_dll: cli.filter_dll.clone(),
            locate: cli.locate || cli.locate_deep,
            locate_deep: cli.locate_deep,
            explain: cli.explain,
            explain_prefix: cli.explain_prefix,
            explain_api: cli.explain_api,
            hostile: cli.hostile,
        }
    }

    pub fn effective_arch(&self, pe_arch: u32) -> u32 {
        match self.arch.as_str() {
            "x86" | "32" => 32,
            "x64" | "64" => 64,
            _ => pe_arch,
        }
    }

    pub fn rebase_addr(&self) -> Result<Option<u64>, String> {
        if self.rebase.is_empty() {
            return Ok(None);
        }
        let s = self.rebase.trim();
        if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            return u64::from_str_radix(hex, 16)
                .map(Some)
                .map_err(|_| format!("invalid --rebase value: {}", self.rebase));
        }
        s.parse::<u64>()
            .map(Some)
            .map_err(|_| format!("invalid --rebase value: {}", self.rebase))
    }
}
