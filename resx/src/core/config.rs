use crate::core::priority::{
    built_in_priority_names, built_in_priority_prefixes, load_priority_file,
};
use clap::Parser;

fn parse_budget(value: &str) -> Result<usize, String> {
    if value.eq_ignore_ascii_case("unlimited") {
        return Ok(0);
    }
    value
        .parse::<usize>()
        .map_err(|_| "budget must be a non-negative integer or `unlimited`".to_owned())
}

fn parse_strings_min_len(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| (1..=4096).contains(value))
        .ok_or_else(|| "strings minimum length must be between 1 and 4096".to_owned())
}

fn parse_strings_limit(value: &str) -> Result<usize, String> {
    value
        .parse::<usize>()
        .ok()
        .filter(|value| (1..=8192).contains(value))
        .ok_or_else(|| "strings limit must be between 1 and 8192".to_owned())
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "resx",
    version = env!("CARGO_PKG_VERSION"),
    author = "Ryftenius",
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

    #[arg(long = "no-pdb", alias = "fast")]
    pub no_pdb: bool,

    /// Opt into platform version/signature queries (may use Windows trust services).
    #[arg(long = "file-metadata")]
    pub file_metadata: bool,

    #[arg(long = "payload-dir")]
    pub payload_dir: Option<String>,
    #[arg(long = "codec", value_parser = ["auto", "zlib", "gzip", "deflate", "base64", "hex", "aes-cbc"])]
    pub codec: Option<String>,
    #[arg(long = "payload-offset")]
    pub payload_offset: Option<u64>,
    #[arg(long = "payload-length")]
    pub payload_length: Option<u64>,
    #[arg(long = "key-file")]
    pub key_file: Option<String>,
    #[arg(long = "iv-hex")]
    pub iv_hex: Option<String>,
    #[arg(long = "pkcs7")]
    pub pkcs7: bool,

    #[arg(long = "c-out", alias = "decompile-out")]
    pub c_out: Option<String>,

    #[arg(long = "edrchk")]
    pub edrchk: bool,

    #[arg(long = "unsafe-map-image")]
    pub unsafe_map_image: bool,

    #[arg(long = "hookchk")]
    pub hookchk: bool,

    #[arg(long = "intelli")]
    pub intelli: bool,

    #[arg(long = "behavior")]
    pub behavior: bool,

    #[arg(long = "entropy")]
    pub entropy: bool,

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

    #[arg(long = "entropy-window", default_value_t = 1024)]
    pub entropy_window: usize,

    #[arg(long = "entropy-stride", default_value_t = 512)]
    pub entropy_stride: usize,

    #[arg(long = "entropy-all")]
    pub entropy_all: bool,

    #[arg(long = "reconstruct-cfg")]
    pub reconstruct_cfg: bool,

    #[arg(long = "thread-filter", default_value = "")]
    pub reconstruct_thread_filter: String,

    #[arg(long = "api-filter", default_value = "")]
    pub reconstruct_api_filter: String,

    #[arg(long = "max-insns", aliases = ["limit", "insns", "analysis-budget", "xref-budget"], default_value = "500", value_parser = parse_budget)]
    pub max_insns: usize,

    #[arg(long = "max-bytes", alias = "byte-limit", default_value_t = 8192)]
    pub max_bytes: usize,

    #[arg(
        long = "bytes",
        aliases = ["hex", "opcode", "opcodes"],
        num_args = 0..=1,
        default_missing_value = "0",
        value_name = "N"
    )]
    pub bytes: Option<Option<usize>>,

    #[arg(long = "no-bytes", action = clap::ArgAction::SetTrue)]
    pub no_bytes: bool,

    #[arg(long = "nodis", aliases = ["no-dis", "no-disassembly"])]
    pub no_disassembly: bool,

    /// Add bounded lightweight SSA, stack-slot, and control-transfer annotations.
    #[arg(long = "ssa")]
    pub ssa: bool,

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

    #[arg(long = "offset", alias = "show-offsets")]
    pub show_offsets: bool,

    #[arg(long = "rva", alias = "show-rva")]
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

    /// Emit structured developer diagnostics to stderr for every command.
    #[arg(long = "diagnostic")]
    pub diagnostic: bool,

    /// Include bounded TRACE events in addition to the default DEBUG level.
    #[arg(long = "diagnostic-trace")]
    pub diagnostic_trace: bool,

    /// Maximum instructions in each bounded verbose evidence window.
    #[arg(long = "disasm-context", default_value_t = 12, value_parser = clap::value_parser!(u32).range(4..=32))]
    pub disasm_context: u32,

    #[arg(long = "debug-report", value_name = "REPORT.ZIP")]
    pub debug_report: Option<String>,

    #[arg(long = "debug-report-include-target", requires = "debug_report")]
    pub debug_report_include_target: bool,

    #[arg(long = "time")]
    pub time: bool,

    #[arg(long = "quiet", short = 'q')]
    pub quiet: bool,

    #[arg(long = "recomp")]
    pub recomp: bool,

    #[arg(long = "xrefs", alias = "refs")]
    pub xrefs: bool,

    #[arg(long = "strings", alias = "strrefs")]
    pub strings: bool,

    /// Minimum candidate length for the standalone strings command.
    #[arg(long = "strings-min-len", default_value_t = 5, value_parser = parse_strings_min_len)]
    pub strings_min_len: usize,

    /// Maximum strings returned by the standalone strings command.
    #[arg(long = "strings-limit", default_value_t = 200, value_parser = parse_strings_limit)]
    pub strings_limit: usize,

    #[arg(long = "strings-encoding", default_value = "both", value_parser = ["ascii", "utf16le", "both"])]
    pub strings_encoding: String,

    #[arg(long = "strings-interesting")]
    pub strings_interesting: bool,

    #[arg(long = "strings-match", value_name = "TEXT")]
    pub strings_match: Option<String>,

    #[arg(long = "strings-tag", value_name = "TAG")]
    pub strings_tag: Option<String>,

    /// Retain permissive UTF-16 candidates, including low-quality binary coincidences.
    #[arg(long = "strings-raw-wide")]
    pub strings_raw_wide: bool,

    #[arg(long = "funcs")]
    pub funcs: bool,

    /// Recursively trace internal sub_XXXXXXXX calls N levels deep (implies --funcs).
    #[arg(long = "funcs-depth", alias = "call-depth", value_name = "N")]
    pub funcs_depth: Option<u32>,

    /// Highlight calls whose name contains this case-insensitive text.
    #[arg(long = "highlight", value_name = "NAME")]
    pub highlight: Option<String>,

    /// Maximum calls rendered for each function in recursive call views.
    #[arg(long = "max-subcalls", default_value_t = 64)]
    pub max_subcalls: usize,

    /// Include recovered MajorFunction and IOCTL contracts in CFG-oriented output.
    #[arg(long = "driver-flow")]
    pub driver_flow: bool,

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

    /// Search executable sections using raw, decoded, or semantic instruction matching.
    #[arg(long = "resx-find", hide = true)]
    pub resx_find: bool,

    #[arg(long = "find", value_name = "QUERY")]
    pub find_pattern: Option<String>,

    #[arg(long = "find-mode", value_parser = ["auto", "raw", "decoded", "semantic"], default_value = "auto")]
    pub find_mode: String,

    /// Try bounded single-byte transforms before decoding a candidate stream.
    #[arg(long = "find-encoded")]
    pub find_encoded: bool,

    #[arg(long = "find-budget", default_value = "8388608", value_parser = parse_budget)]
    pub find_budget: usize,

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

    #[arg(long = "max-total", alias = "cfg-budget", default_value = "500", value_parser = parse_budget)]
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

    /// Enable aggressive tracing: recursive register backward-slice, decoder-driven
    /// reverse-index, indirect-JMP emission, and suspicion annotations in disasm.
    #[arg(long = "hostile")]
    pub hostile: bool,

    #[arg(long = "resx-config", hide = true)]
    pub resx_config: bool,

    #[arg(long = "command-style", value_parser = ["standard", "slash"])]
    pub command_style: Option<String>,

    #[arg(long = "entry-macro")]
    pub entry_macro: Option<String>,

    #[arg(long = "rentry-macro")]
    pub rentry_macro: Option<String>,
}

/// Build and run Clap's generated parser on a bounded worker stack. The generated command graph
/// can exceed the Windows main thread's 1 MiB reserve in unoptimized builds.
pub fn parse_cli(args: Vec<String>) -> Result<Cli, clap::Error> {
    let worker = std::thread::Builder::new()
        .name("resx-parser".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(move || Cli::try_parse_from(args))
        .map_err(|error| clap::Error::raw(clap::error::ErrorKind::Io, error.to_string()))?;
    worker.join().map_err(|_| {
        clap::Error::raw(
            clap::error::ErrorKind::Format,
            "RESX command parser terminated unexpectedly",
        )
    })?
}

#[derive(Debug, Clone)]
pub struct Config {
    pub color: bool,
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
    pub file_metadata: bool,
    pub c_out: String,
    pub edrchk: bool,
    pub unsafe_map_image: bool,
    pub hookchk: bool,
    pub intelli: bool,
    pub behavior: bool,
    pub entropy: bool,
    pub patch: bool,
    pub patch_bytes: String,
    pub patch_expect: String,
    pub patch_out: String,
    pub patch_dry_run: bool,
    pub patch_in_place: bool,
    pub patch_overwrite: bool,
    pub patch_update_checksum: bool,
    pub entropy_window: usize,
    pub entropy_stride: usize,
    pub entropy_all: bool,
    pub reconstruct_cfg: bool,
    pub reconstruct_thread_filter: String,
    pub reconstruct_api_filter: String,

    pub max_insns: usize,
    pub max_bytes: usize,
    pub show_bytes: bool,
    pub no_disassembly: bool,
    pub ssa: bool,
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
    pub diagnostic: bool,
    pub diagnostic_trace: bool,
    pub disasm_context: usize,
    pub time: bool,
    pub quiet: bool,

    pub recomp: bool,
    pub show_xrefs: bool,
    pub show_strings: bool,
    pub strings_min_len: usize,
    pub strings_limit: usize,
    pub strings_encoding: String,
    pub strings_interesting: bool,
    pub strings_match: String,
    pub strings_tag: String,
    pub strings_raw_wide: bool,
    pub funcs_depth: u32,
    pub highlight: String,
    pub max_subcalls: usize,
    pub driver_flow: bool,
    pub cfg_view: String,
    pub show_eat: bool,
    pub show_iat: bool,
    pub sections: bool,
    pub pechk: bool,
    pub show_syms: bool,
    pub follow_callers: bool,
    pub peinfo: bool,
    pub yara: Vec<String>,
    pub resx_find: bool,
    pub find_pattern: String,
    pub find_mode: String,
    pub find_encoded: bool,
    pub find_budget: usize,
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
    pub hostile: bool,
    pub command_style: String,
    pub entry_macro: String,
    pub rentry_macro: String,
    pub resx_config: bool,
}

impl Config {
    pub fn from_cli(cli: &Cli, color: bool) -> Self {
        let preferences = crate::core::preferences::Preferences::load();
        let priority_file = load_priority_file();
        let mut priority_names = built_in_priority_names();
        priority_names.extend(priority_file.exact_names);
        let mut priority_prefixes = built_in_priority_prefixes();
        priority_prefixes.extend(priority_file.prefixes);
        Config {
            color,
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
            file_metadata: cli.file_metadata,
            c_out: cli.c_out.clone().unwrap_or_default(),
            edrchk: cli.edrchk,
            unsafe_map_image: cli.unsafe_map_image,
            hookchk: cli.hookchk,
            intelli: cli.intelli,
            behavior: cli.behavior,
            entropy: cli.entropy,
            patch: cli.patch,
            patch_bytes: cli.patch_bytes.clone().unwrap_or_default(),
            patch_expect: cli.patch_expect.clone().unwrap_or_default(),
            patch_out: cli.patch_out.clone().unwrap_or_default(),
            patch_dry_run: cli.patch_dry_run,
            patch_in_place: cli.patch_in_place,
            patch_overwrite: cli.patch_overwrite,
            patch_update_checksum: cli.patch_update_checksum,
            entropy_window: cli.entropy_window,
            entropy_stride: cli.entropy_stride,
            entropy_all: cli.entropy_all,
            reconstruct_cfg: cli.reconstruct_cfg,
            reconstruct_thread_filter: cli.reconstruct_thread_filter.clone(),
            reconstruct_api_filter: cli.reconstruct_api_filter.clone(),
            max_insns: cli.max_insns,
            max_bytes: cli
                .bytes
                .flatten()
                .filter(|bytes| *bytes > 0)
                .unwrap_or(cli.max_bytes),
            show_bytes: cli.bytes.is_some() && !cli.no_bytes,
            no_disassembly: cli.no_disassembly,
            ssa: cli.ssa,
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
            verbose: (cli.verbose || cli.diagnostic || cli.diagnostic_trace) && !cli.quiet,
            diagnostic: (cli.diagnostic || cli.diagnostic_trace) && !cli.quiet,
            diagnostic_trace: cli.diagnostic_trace && !cli.quiet,
            disasm_context: cli.disasm_context.clamp(4, 32) as usize,
            time: cli.time && !cli.quiet,
            quiet: cli.quiet,
            recomp: cli.recomp,
            show_xrefs: cli.xrefs,
            show_strings: cli.strings,
            strings_min_len: cli.strings_min_len,
            strings_limit: cli.strings_limit,
            strings_encoding: cli.strings_encoding.clone(),
            strings_interesting: cli.strings_interesting,
            strings_match: cli.strings_match.clone().unwrap_or_default(),
            strings_tag: cli.strings_tag.clone().unwrap_or_default(),
            strings_raw_wide: cli.strings_raw_wide,
            funcs_depth: cli.funcs_depth.unwrap_or(if cli.funcs { 1 } else { 0 }),
            highlight: cli.highlight.clone().unwrap_or_default(),
            max_subcalls: cli.max_subcalls.clamp(1, 4096),
            driver_flow: cli.driver_flow,
            cfg_view: cli.cfg_view.clone().unwrap_or_default(),
            show_eat: cli.show_eat,
            show_iat: cli.show_iat,
            sections: cli.sections,
            pechk: cli.pechk,
            show_syms: cli.show_syms,
            follow_callers: cli.follow_callers,
            peinfo: cli.peinfo,
            yara: cli.yara.clone(),
            resx_find: cli.resx_find,
            find_pattern: cli.find_pattern.clone().unwrap_or_default(),
            find_mode: cli.find_mode.clone(),
            find_encoded: cli.find_encoded,
            find_budget: cli.find_budget,
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
            hostile: cli.hostile,
            command_style: preferences.command_style,
            entry_macro: preferences.entry_macro,
            rentry_macro: preferences.rentry_macro,
            resx_config: cli.resx_config,
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

#[cfg(test)]
mod tests {
    use super::parse_cli;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn lightweight_ssa_is_explicitly_opt_in() {
        assert!(!parse_cli(args(&["resx"])).unwrap().ssa);
        assert!(parse_cli(args(&["resx", "--ssa"])).unwrap().ssa);
    }

    #[test]
    fn removed_flow_line_options_are_rejected() {
        assert!(parse_cli(args(&["resx", "--flow-lines"])).is_err());
        assert!(parse_cli(args(&["resx", "--branch-arrows"])).is_err());
    }
}
