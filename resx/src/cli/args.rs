//! Command-line grammar. Every command owns its arguments; shared concerns are
//! flattened option groups, each rendered under its own `--help` heading.
//!
//! Option names from earlier releases stay accepted as hidden aliases so scripts,
//! the FFI layer, and the VS Code extension keep working unchanged.

use clap::{Args, Parser, Subcommand};

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

const FILTER_TERMS: &str = "winapi, iat, internal, crt, syscall, or a DLL name";

fn parse_filter_term(value: &str) -> Result<String, String> {
    let term = value.trim();
    if term.trim_start_matches(['!', '-']).trim().is_empty() {
        Err(format!("expected {FILTER_TERMS}"))
    } else {
        Ok(term.to_owned())
    }
}

fn parse_filter_spec(value: &str) -> Result<String, String> {
    let has_term = value
        .split(',')
        .map(|term| term.trim().trim_start_matches(['!', '-']).trim())
        .any(|term| !term.is_empty());
    if has_term {
        Ok(value.trim().to_owned())
    } else {
        Err(format!(
            "expected {FILTER_TERMS} (comma-separated, ! to exclude)"
        ))
    }
}

#[derive(Parser, Debug, Clone)]
#[command(
    name = "resx",
    bin_name = "resx",
    author = "Ryftenius",
    about = "Windows binary recon CLI for exports, symbols, metadata, CFG, callers, and triage",
    disable_help_flag = true,
    disable_help_subcommand = true,
    disable_version_flag = true,
    subcommand_required = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,

    #[command(flatten)]
    pub global: GlobalArgs,
}

/// Output and diagnostics accepted by every command, before or after it.
#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Output")]
pub struct GlobalArgs {
    /// Structured JSON output
    #[arg(long, global = true)]
    pub json: bool,

    /// Write output to FILE; evidence commands require a new file
    #[arg(long = "out", short = 'o', value_name = "FILE", global = true)]
    pub out_file: Option<String>,

    /// Coverage and diagnostics on stderr
    #[arg(long, short = 'v', global = true)]
    pub verbose: bool,

    /// Suppress optional diagnostics; overrides --verbose
    #[arg(long, short = 'q', global = true)]
    pub quiet: bool,

    /// DEBUG developer trace on stderr; implies --verbose
    #[arg(long, global = true)]
    pub diagnostic: bool,

    /// Include bounded TRACE events; implies --diagnostic
    #[arg(long = "diagnostic-trace", global = true)]
    pub diagnostic_trace: bool,

    /// Instructions per verbose evidence window
    #[arg(
        long = "disasm-context",
        value_name = "4..32",
        default_value_t = 12,
        value_parser = clap::value_parser!(u32).range(4..=32),
        global = true
    )]
    pub disasm_context: u32,

    /// Write a sanitized reproducibility bundle
    #[arg(long = "debug-report", value_name = "REPORT.ZIP", global = true)]
    pub debug_report: Option<String>,

    /// Include target bytes in the debug report (64 MiB cap)
    #[arg(
        long = "debug-report-include-target",
        requires = "debug_report",
        global = true
    )]
    pub debug_report_include_target: bool,

    /// Print command completion time on stderr
    #[arg(long, global = true)]
    pub time: bool,

    /// Force terminal colors
    #[arg(long = "color", global = true)]
    pub force_color: bool,

    /// Disable terminal colors
    #[arg(long = "no-color", global = true)]
    pub no_color: bool,

    /// Print the command's examples
    #[arg(long, global = true, hide = true)]
    pub example: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum Command {
    // Inspect
    /// PE identity, directories, toolchain and hardening metadata
    Peinfo(PeinfoArgs),
    /// Section layout, permissions, entropy and mapping
    Sections(ImageArgs),
    /// Structural and loader-relevant anomaly checks
    Pechk(ImageArgs),
    /// Export table
    Eat(ImageArgs),
    /// Import table
    Iat(ImageArgs),
    /// Symbols
    Syms(ImageArgs),
    /// PDB-backed type browsing
    Types(TypesArgs),

    // Code and flow
    /// Targeted disassembly with optional call map, CFG and C-like reconstruction
    Dump(DumpArgs),
    /// Recursive API call tree for one function, filterable by import source
    Calls(CallsArgs),
    /// Incoming references to a function or import
    #[command(alias = "refs")]
    Xrefs(DumpArgs),
    /// Function control-flow graph
    Cfg(DumpArgs),
    /// Startup and reachable image flow
    ReconstructCfg(ReconstructArgs),
    /// Reverse caller tree across the configured images
    #[command(alias = "follow")]
    Callers(CallersArgs),
    /// Bounded static intelligence report
    Intelli(DumpArgs),
    /// Static behavior indicators
    Behavior(BehaviorArgs),

    // Evidence
    /// API arguments and producer relationships
    Contracts(EvidenceArgs),
    /// Named pipe, ALPC, RPC, COM and mapping evidence
    Ipc(EvidenceArgs),
    /// Endpoint and socket/HTTP configuration candidates
    Network(EvidenceArgs),
    /// CNG/CAPI algorithms, providers, modes and arguments
    Crypto(EvidenceArgs),
    /// Bounded ASCII and UTF-16LE extraction
    Strings(StringsArgs),
    /// Driver dispatch, capabilities and virtualization primitives
    Driver(DeviceArgs),
    /// IOCTL/NDIS argument and request evidence
    Ioctl(DeviceArgs),
    /// Section/window entropy visualization
    Entropy(EntropyArgs),

    // Search and comparison
    /// YARA-compatible scan
    Yara(YaraArgs),
    /// Bytes, text, constants and instruction patterns
    Find(FindArgs),
    /// Bounded PE corpus inventory
    Scan(ScanArgs),
    /// Structural image/function comparison
    Diff(DiffArgs),
    /// Create a reusable corpus index
    Index(IndexArgs),
    /// Rank similar indexed images
    Hunt(HuntArgs),
    /// Resolve image/export names
    Locate(LocateArgs),
    /// Deeper symbol search, including PDB-only names
    LocateSym(LocateArgs),

    // Explicit transformations
    /// Bounded operator-directed codec/AES-CBC decoding
    Payload(PayloadArgs),
    /// Checked patch plan or new patched image
    Patch(PatchArgs),

    // Configuration
    /// Open the priority search configuration
    Priority,
    /// Saved command preferences
    Config(ConfigArgs),
    /// Update a source checkout
    Update,

    /// `resx <image> <target>` dumps and `resx <name>` locates, as in earlier releases.
    #[command(hide = true)]
    Implicit(ImplicitArgs),
}

impl Command {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Peinfo(_) => "peinfo",
            Self::Sections(_) => "sections",
            Self::Pechk(_) => "pechk",
            Self::Eat(_) => "eat",
            Self::Iat(_) => "iat",
            Self::Syms(_) => "syms",
            Self::Types(_) => "types",
            Self::Dump(_) => "dump",
            Self::Calls(_) => "calls",
            Self::Xrefs(_) => "xrefs",
            Self::Cfg(_) => "cfg",
            Self::ReconstructCfg(_) => "reconstruct-cfg",
            Self::Callers(_) => "callers",
            Self::Intelli(_) => "intelli",
            Self::Behavior(_) => "behavior",
            Self::Contracts(_) => "contracts",
            Self::Ipc(_) => "ipc",
            Self::Network(_) => "network",
            Self::Crypto(_) => "crypto",
            Self::Strings(_) => "strings",
            Self::Driver(_) => "driver",
            Self::Ioctl(_) => "ioctl",
            Self::Entropy(_) => "entropy",
            Self::Yara(_) => "yara",
            Self::Find(_) => "find",
            Self::Scan(_) => "scan",
            Self::Diff(_) => "diff",
            Self::Index(_) => "index",
            Self::Hunt(_) => "hunt",
            Self::Locate(_) => "locate",
            Self::LocateSym(_) => "locate-sym",
            Self::Payload(_) => "payload",
            Self::Patch(_) => "patch",
            Self::Priority => "priority",
            Self::Config(_) => "config",
            Self::Update => "update",
            Self::Implicit(_) => "dump",
        }
    }
}

// ---------------------------------------------------------------------------
// Shared option groups
// ---------------------------------------------------------------------------

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Image lookup")]
pub struct LookupArgs {
    /// Add an image lookup directory
    #[arg(long = "path", value_name = "DIR", action = clap::ArgAction::Append)]
    pub paths: Vec<String>,

    /// Skip the Windows system directories
    #[arg(long = "no-system")]
    pub no_system: bool,

    /// Skip the current directory
    #[arg(long = "no-cwd")]
    pub no_cwd: bool,

    /// Skip PATH directories
    #[arg(long = "no-path")]
    pub no_path: bool,

    /// Architecture to decode as
    #[arg(long, value_name = "ARCH", default_value = "auto")]
    pub arch: String,

    /// Rebase reported addresses onto BASE
    #[arg(long, value_name = "BASE")]
    pub rebase: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Symbols")]
pub struct SymbolArgs {
    /// Use an explicit local PDB
    #[arg(long = "pdb", value_name = "FILE")]
    pub pdb_file: Option<String>,

    /// Symbol search path
    #[arg(long = "sym-path", value_name = "PATH")]
    pub sym_path: Option<String>,

    /// Symbol server URL
    #[arg(long = "sym-server", value_name = "URL")]
    pub sym_server: Option<String>,

    /// Refresh cached symbols
    #[arg(long)]
    pub reload: bool,

    /// Disable symbol loading
    #[arg(long = "no-pdb", alias = "fast")]
    pub no_pdb: bool,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Target")]
pub struct TargetArgs {
    /// Export or symbol name, IMAGE!NAME, entry, rentry, or rva:/va:/file: address
    #[arg(value_name = "TARGET", help_heading = None::<&str>)]
    pub target: Option<String>,

    /// Start at ADDR: RVA, va:0x..., or file:0x...
    #[arg(long = "at", value_name = "ADDR")]
    pub at: Option<String>,

    /// Start at an export ordinal
    #[arg(long, short = 'n', value_name = "N")]
    pub ordinal: Option<u32>,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Analysis")]
pub struct AnalysisArgs {
    /// Instruction budget per function
    #[arg(
        long = "max-insns",
        value_name = "N|unlimited",
        aliases = ["limit", "insns", "analysis-budget", "xref-budget"],
        default_value = "500",
        value_parser = parse_budget
    )]
    pub max_insns: usize,

    /// Total traversal budget for recursive views
    #[arg(
        long = "max-total",
        value_name = "N|unlimited",
        alias = "cfg-budget",
        default_value = "500",
        value_parser = parse_budget
    )]
    pub max_total: usize,

    /// Aggressive tracing with register slices and suspicion annotations
    #[arg(long)]
    pub hostile: bool,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Listing")]
pub struct ListingArgs {
    /// Byte budget per function
    #[arg(
        long = "max-bytes",
        value_name = "N",
        alias = "byte-limit",
        default_value_t = 8192
    )]
    pub max_bytes: usize,

    /// Show opcode bytes, optionally capping the decoded byte count
    #[arg(
        long = "bytes",
        aliases = ["hex", "opcode", "opcodes"],
        num_args = 0..=1,
        default_missing_value = "0",
        value_name = "N"
    )]
    pub bytes: Option<Option<usize>>,

    /// Hide opcode bytes
    #[arg(long = "no-bytes")]
    pub no_bytes: bool,

    /// Omit the disassembly listing
    #[arg(long = "nodis", aliases = ["no-dis", "no-disassembly"])]
    pub no_disassembly: bool,

    /// Add bounded SSA, stack-slot and control-transfer annotations
    #[arg(long)]
    pub ssa: bool,

    /// Intel syntax (default)
    #[arg(long, default_value_t = true, action = clap::ArgAction::SetTrue, hide = true)]
    pub intel: bool,

    /// AT&T syntax
    #[arg(long, action = clap::ArgAction::SetTrue)]
    pub att: bool,

    /// Follow JMP thunks (default)
    #[arg(
        long = "follow-jmp",
        default_value_t = true,
        action = clap::ArgAction::SetTrue,
        hide = true
    )]
    pub follow_jmp: bool,

    /// Do not follow JMP thunks to their destination
    #[arg(long = "no-follow-jmp", action = clap::ArgAction::SetTrue)]
    pub no_follow_jmp: bool,

    /// Do not follow export forwarders
    #[arg(long = "no-follow-forward")]
    pub no_follow_forward: bool,

    /// Show file offsets
    #[arg(long = "offset", alias = "show-offsets")]
    pub show_offsets: bool,

    /// Show RVAs
    #[arg(long = "rva", alias = "show-rva")]
    pub show_rva: bool,

    /// Address column width
    #[arg(long = "addr-width", value_name = "N", default_value_t = 8)]
    pub addr_width: usize,

    /// Opcode-byte column width
    #[arg(long = "width", value_name = "N", default_value_t = 10)]
    pub byte_col_width: usize,
}

/// The API call map inside `dump`, `cfg`, `xrefs` and `intelli`.
#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Call tree")]
pub struct CallTreeArgs {
    /// Add the API call map, tracing internal callees DEPTH levels deep [default: 1]
    #[arg(
        long = "calls",
        value_name = "DEPTH",
        num_args = 0..=1,
        default_missing_value = "1"
    )]
    pub calls: Option<u32>,

    /// Keep matching calls and the path to them (terms as in `resx help calls`); implies --calls 3
    #[arg(
        long = "calls-only",
        value_name = "TERMS",
        value_delimiter = ',',
        value_parser = parse_filter_term
    )]
    pub calls_only: Vec<String>,

    /// Drop matching calls and everything below them
    #[arg(
        long = "calls-exclude",
        value_name = "TERMS",
        value_delimiter = ',',
        value_parser = parse_filter_term
    )]
    pub calls_exclude: Vec<String>,

    /// Maximum calls rendered per function
    #[arg(long = "max-subcalls", value_name = "N", default_value_t = 64)]
    pub max_subcalls: usize,

    /// Highlight calls whose name contains NAME
    #[arg(long, value_name = "NAME")]
    pub highlight: Option<String>,

    #[arg(long = "funcs", hide = true)]
    pub funcs: bool,

    #[arg(
        long = "funcs-depth",
        alias = "call-depth",
        value_name = "N",
        hide = true
    )]
    pub funcs_depth: Option<u32>,

    #[arg(
        long = "funcs-filter",
        alias = "call-filter",
        value_name = "FILTER",
        value_parser = parse_filter_spec,
        hide = true
    )]
    pub funcs_filter: Option<String>,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Report sections")]
pub struct ReportArgs {
    /// Incoming references
    #[arg(long, alias = "refs")]
    pub xrefs: bool,

    /// String references
    #[arg(long, alias = "strrefs")]
    pub strings: bool,

    /// Control-flow graph view (text)
    #[arg(long = "cfg", value_name = "FMT")]
    pub cfg_view: Option<String>,

    /// C-like reconstruction
    #[arg(long)]
    pub recomp: bool,

    /// Write the C-like reconstruction to FILE
    #[arg(long = "c-out", alias = "decompile-out", value_name = "FILE")]
    pub c_out: Option<String>,

    /// Recovered MajorFunction and IOCTL contracts
    #[arg(long = "driver-flow")]
    pub driver_flow: bool,

    /// Heuristic triage findings
    #[arg(long)]
    pub intelli: bool,

    /// Compare disk bytes with the loaded module prologue
    #[arg(long)]
    pub edrchk: bool,

    /// Static entry/thunk hook triage
    #[arg(long)]
    pub hookchk: bool,

    #[arg(long = "unsafe-map-image", hide = true)]
    pub unsafe_map_image: bool,

    /// Section table
    #[arg(long)]
    pub sections: bool,

    /// PE anomaly checks
    #[arg(long)]
    pub pechk: bool,

    /// Export table
    #[arg(long = "show-eat")]
    pub show_eat: bool,

    /// Import table
    #[arg(long = "show-iat")]
    pub show_iat: bool,

    /// Symbol table
    #[arg(long = "show-syms")]
    pub show_syms: bool,

    /// Scan the image with YARA rules (repeatable)
    #[arg(long, value_name = "RULES", action = clap::ArgAction::Append)]
    pub yara: Vec<String>,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Flow")]
pub struct FlowArgs {
    /// Traversal depth
    #[arg(long, value_name = "N", default_value_t = 3)]
    pub depth: usize,

    /// Maximum callers kept per node
    #[arg(long = "max-callers", value_name = "N", default_value_t = 30)]
    pub max_callers: usize,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Search scope")]
pub struct ScopeArgs {
    /// Also search images under DIR (repeatable)
    #[arg(
        long = "include-dir",
        alias = "scan-dir",
        value_name = "DIR",
        action = clap::ArgAction::Append
    )]
    pub scan_dirs: Vec<String>,

    /// Also search IMAGE (repeatable)
    #[arg(
        long = "include-image",
        alias = "scan-dll",
        value_name = "IMAGE",
        action = clap::ArgAction::Append
    )]
    pub scan_dlls: Vec<String>,

    /// Include EXE images, not only DLLs
    #[arg(long = "scan-exe")]
    pub scan_exe: bool,

    /// Only search image names matching PATTERN
    #[arg(long, value_name = "PATTERN", default_value = "")]
    pub include: String,

    /// Only search images matching the file pattern or list in FILE
    #[arg(
        long = "scope-file",
        alias = "include-file",
        value_name = "FILE",
        default_value = ""
    )]
    pub scope_file: String,

    /// Skip image names matching PATTERN
    #[arg(long, value_name = "PATTERN", default_value = "")]
    pub exclude: String,

    /// Narrow results to images whose name contains TEXT
    #[arg(long = "filter-dll", value_name = "TEXT", default_value = "")]
    pub filter_dll: String,

    /// Skip images larger than MB
    #[arg(long = "max-dll-size", value_name = "MB", default_value_t = 200)]
    pub max_dll_mb: u64,

    /// Worker threads
    #[arg(long, value_name = "N", default_value_t = 8)]
    pub workers: usize,
}

#[derive(Args, Debug, Clone)]
#[command(next_help_heading = "Matching")]
pub struct MatchArgs {
    /// Matching profile
    #[arg(
        long = "mode",
        alias = "diff-mode",
        value_name = "MODE",
        default_value = "balanced"
    )]
    pub diff_mode: String,

    /// Similarity threshold, 0-100
    #[arg(
        long = "threshold",
        alias = "diff-threshold",
        value_name = "N",
        default_value_t = 65
    )]
    pub diff_threshold: u8,

    /// Keep weak matches
    #[arg(long = "include-weak")]
    pub include_weak: bool,

    /// Maximum functions profiled per image
    #[arg(long = "max-functions", value_name = "N", default_value_t = 2000)]
    pub diff_max_functions: usize,

    /// Maximum candidates considered per function
    #[arg(long = "max-candidates", value_name = "N", default_value_t = 32)]
    pub max_candidates: usize,

    /// Maximum basic blocks compared per CFG
    #[arg(long = "max-cfg-blocks", value_name = "N", default_value_t = 128)]
    pub max_cfg_blocks: usize,
}

// ---------------------------------------------------------------------------
// Command arguments
// ---------------------------------------------------------------------------

#[derive(Args, Debug, Clone)]
pub struct DeviceArgs {
    #[command(flatten)]
    pub image: ImageArgs,
    /// Query one local device endpoint's SDDL and non-elevated open access (no IOCTL sent)
    #[arg(long = "device-security", value_name = "PATH")]
    pub device_security: Option<String>,
    #[arg(
        long = "device-security-worker",
        hide = true,
        requires = "device_security"
    )]
    pub device_security_worker: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ImageArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct PeinfoArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,
    /// Query platform version/signature metadata (may use Windows trust services)
    #[arg(long = "file-metadata")]
    pub file_metadata: bool,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct TypesArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,
    /// Type or symbol name to search for
    pub query: Option<String>,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct DumpArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,
    #[command(flatten)]
    pub target: TargetArgs,
    #[command(flatten)]
    pub report: ReportArgs,
    #[command(flatten)]
    pub calls: CallTreeArgs,
    #[command(flatten)]
    pub listing: ListingArgs,
    #[command(flatten)]
    pub analysis: AnalysisArgs,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct CallsArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,
    #[command(flatten)]
    pub target: TargetArgs,

    /// Internal call levels to trace
    #[arg(
        long,
        value_name = "N",
        default_value_t = 3,
        help_heading = "Call tree"
    )]
    pub depth: u32,

    /// Keep matching calls and the path to them: winapi, iat, internal, crt, syscall, NAME.dll
    #[arg(
        long,
        value_name = "TERMS",
        value_delimiter = ',',
        value_parser = parse_filter_term,
        help_heading = "Call tree"
    )]
    pub only: Vec<String>,

    /// Drop matching calls and everything below them
    #[arg(
        long,
        value_name = "TERMS",
        value_delimiter = ',',
        value_parser = parse_filter_term,
        help_heading = "Call tree"
    )]
    pub exclude: Vec<String>,

    /// Maximum calls rendered per function
    #[arg(
        long = "max-subcalls",
        value_name = "N",
        default_value_t = 64,
        help_heading = "Call tree"
    )]
    pub max_subcalls: usize,

    /// Highlight calls whose name contains NAME
    #[arg(long, value_name = "NAME", help_heading = "Call tree")]
    pub highlight: Option<String>,

    /// Show call-site RVAs
    #[arg(long = "rva", alias = "show-rva", help_heading = "Call tree")]
    pub show_rva: bool,

    /// Show call-site file offsets
    #[arg(long = "offset", alias = "show-offsets", help_heading = "Call tree")]
    pub show_offsets: bool,

    #[command(flatten)]
    pub analysis: AnalysisArgs,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct ReconstructArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,

    /// Focus on threads: spawned, api, or a name
    #[arg(long = "thread-filter", value_name = "FILTER", default_value = "")]
    pub thread_filter: String,

    /// Focus on paths that reach API
    #[arg(long = "api-filter", value_name = "API", default_value = "")]
    pub api_filter: String,

    /// Add recovered MajorFunction and IOCTL contracts
    #[arg(long = "driver-flow")]
    pub driver_flow: bool,

    /// Maximum calls rendered per function
    #[arg(long = "max-subcalls", value_name = "N", default_value_t = 64)]
    pub max_subcalls: usize,

    #[arg(long = "funcs", hide = true)]
    pub funcs: bool,

    #[arg(long = "funcs-depth", alias = "call-depth", hide = true)]
    pub funcs_depth: Option<u32>,

    #[command(flatten)]
    pub flow: FlowArgs,
    #[command(flatten)]
    pub analysis: AnalysisArgs,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct CallersArgs {
    /// Image that exports or contains FUNCTION
    pub image: String,
    /// Function whose callers are traced
    pub function: String,

    /// Output layout: tree, flat, or list
    #[arg(long = "format", value_name = "FORMAT", default_value = "tree")]
    pub format: String,

    /// Print call-site RVAs
    #[arg(long = "show-site")]
    pub show_site: bool,

    /// Show RVAs
    #[arg(long = "rva", alias = "show-rva")]
    pub show_rva: bool,

    #[command(flatten)]
    pub flow: FlowArgs,
    #[command(flatten)]
    pub scope: ScopeArgs,
    #[command(flatten)]
    pub analysis: AnalysisArgs,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct BehaviorArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,
    #[command(flatten)]
    pub analysis: AnalysisArgs,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct EvidenceArgs {
    /// Image file
    pub image: String,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct StringsArgs {
    /// Image file
    pub image: String,

    /// Minimum candidate length, 1-4096
    #[arg(
        long = "min-len",
        alias = "strings-min-len",
        value_name = "N",
        default_value_t = 5,
        value_parser = parse_strings_min_len
    )]
    pub min_len: usize,

    /// Maximum strings returned, 1-8192
    #[arg(
        long = "limit",
        alias = "strings-limit",
        value_name = "N",
        default_value_t = 200,
        value_parser = parse_strings_limit
    )]
    pub limit: usize,

    /// Encodings to extract
    #[arg(
        long = "encoding",
        alias = "strings-encoding",
        default_value = "both",
        value_parser = ["ascii", "utf16le", "both"]
    )]
    pub encoding: String,

    /// Only strings tagged as interesting
    #[arg(long = "interesting", alias = "strings-interesting")]
    pub interesting: bool,

    /// Only strings containing TEXT
    #[arg(long = "match", alias = "strings-match", value_name = "TEXT")]
    pub matching: Option<String>,

    /// Only strings carrying TAG
    #[arg(long = "tag", alias = "strings-tag", value_name = "TAG")]
    pub tag: Option<String>,

    /// Keep permissive UTF-16 candidates, including binary coincidences
    #[arg(long = "raw-wide", alias = "strings-raw-wide")]
    pub raw_wide: bool,

    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct EntropyArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,

    /// Window size in bytes
    #[arg(
        long = "window",
        alias = "entropy-window",
        value_name = "BYTES",
        default_value_t = 1024
    )]
    pub window: usize,

    /// Step between windows in bytes
    #[arg(
        long = "stride",
        alias = "entropy-stride",
        value_name = "BYTES",
        default_value_t = 512
    )]
    pub stride: usize,

    /// Include non-executable sections
    #[arg(long = "all", alias = "entropy-all")]
    pub all: bool,

    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct YaraArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,
    /// Rule files, directories of .yar/.yara files, or JSON rule lists
    #[arg(value_name = "RULES")]
    pub rules: Vec<String>,

    #[arg(long = "yara", value_name = "RULES", action = clap::ArgAction::Append, hide = true)]
    pub legacy_rules: Vec<String>,

    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct FindArgs {
    /// Image path, or a name resolved through the lookup order
    pub image: String,
    /// Bytes, text, constant, instruction sequence, or semantic name
    pub query: Option<String>,

    /// Matching mode
    #[arg(
        long = "mode",
        alias = "find-mode",
        default_value = "auto",
        value_parser = ["auto", "raw", "decoded", "semantic"]
    )]
    pub mode: String,

    /// Try bounded single-byte transforms before decoding a candidate stream
    #[arg(long = "encoded", alias = "find-encoded")]
    pub encoded: bool,

    /// Byte budget for the search
    #[arg(
        long = "budget",
        alias = "find-budget",
        value_name = "N|unlimited",
        default_value = "8388608",
        value_parser = parse_budget
    )]
    pub budget: usize,

    #[arg(long = "find", value_name = "QUERY", hide = true)]
    pub legacy_query: Option<String>,

    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct ScanArgs {
    /// Directory or image to inventory
    pub root: String,

    /// One JSON object per line
    #[arg(long)]
    pub jsonl: bool,

    /// File extensions to include
    #[arg(
        long = "extensions",
        value_name = "LIST",
        default_value = "exe,dll,sys"
    )]
    pub extensions: String,

    /// Maximum images inventoried
    #[arg(long = "max-files", value_name = "N", default_value_t = 200)]
    pub max_files: usize,

    /// Skip files larger than MB
    #[arg(long = "max-file-mb", value_name = "MB", default_value_t = 200)]
    pub max_file_mb: u64,

    /// Maximum fuzz-target candidates per image
    #[arg(long = "max-candidates", value_name = "N", default_value_t = 32)]
    pub max_candidates: usize,

    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct DiffArgs {
    /// Two or more images to compare
    #[arg(value_name = "IMAGE", num_args = 2.., required = true)]
    pub images: Vec<String>,

    /// PDB for the first image
    #[arg(long = "left-pdb", value_name = "FILE")]
    pub left_pdb: Option<String>,

    /// PDB for the second image
    #[arg(long = "right-pdb", value_name = "FILE")]
    pub right_pdb: Option<String>,

    /// Pair the basic blocks of FUNCTION, an RVA, or auto
    #[arg(
        long = "show-cfg",
        alias = "show-cfg-diff",
        value_name = "FUNCTION_OR_RVA"
    )]
    pub show_cfg: Option<String>,

    /// CFG diff format: text, dot, or json
    #[arg(
        long = "cfg-format",
        alias = "cfg-diff-format",
        value_name = "FMT",
        default_value = "text"
    )]
    pub cfg_format: String,

    /// Write the CFG diff to FILE
    #[arg(long = "cfg-out", alias = "cfg-diff-out", value_name = "FILE")]
    pub cfg_out: Option<String>,

    /// Add function hotspots, section entropy deltas and a graph
    #[arg(long = "graph", alias = "diff-graph")]
    pub graph: bool,

    /// Graph format: text, dot, or json
    #[arg(
        long = "graph-format",
        alias = "diff-graph-format",
        value_name = "FMT",
        default_value = "text"
    )]
    pub graph_format: String,

    /// Write the graph to FILE
    #[arg(long = "graph-out", alias = "diff-graph-out", value_name = "FILE")]
    pub graph_out: Option<String>,

    #[command(flatten)]
    pub matching: MatchArgs,
    #[command(flatten)]
    pub analysis: AnalysisArgs,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct IndexArgs {
    /// Directory or image to index
    pub root: String,

    /// Corpus database file
    #[arg(long, value_name = "FILE", default_value = "resx-corpus.json")]
    pub db: String,

    /// File extensions to include
    #[arg(
        long = "extensions",
        value_name = "LIST",
        default_value = "exe,dll,sys"
    )]
    pub extensions: String,

    /// Maximum images indexed
    #[arg(long = "max-files", value_name = "N", default_value_t = 200)]
    pub max_files: usize,

    /// Skip files larger than MB
    #[arg(long = "max-file-mb", value_name = "MB", default_value_t = 200)]
    pub max_file_mb: u64,

    #[command(flatten)]
    pub matching: MatchArgs,
    #[command(flatten)]
    pub analysis: AnalysisArgs,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct HuntArgs {
    /// Sample to rank against the corpus
    pub sample: String,

    /// Corpus database file
    #[arg(long, value_name = "FILE", default_value = "resx-corpus.json")]
    pub db: String,

    #[command(flatten)]
    pub matching: MatchArgs,
    #[command(flatten)]
    pub analysis: AnalysisArgs,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct LocateArgs {
    /// Export, symbol, or image name
    pub name: String,
    #[command(flatten)]
    pub scope: ScopeArgs,
    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct PayloadArgs {
    /// Input file
    pub input: String,

    /// New directory that receives every decoded layer
    #[arg(long = "out-dir", alias = "payload-dir", value_name = "DIR")]
    pub out_dir: Option<String>,

    /// Codec to apply
    #[arg(
        long,
        value_parser = ["auto", "zlib", "gzip", "deflate", "base64", "hex", "aes-cbc"]
    )]
    pub codec: Option<String>,

    /// Start of the source byte range
    #[arg(long = "offset", alias = "payload-offset", value_name = "N")]
    pub offset: Option<u64>,

    /// Length of the source byte range
    #[arg(long = "length", alias = "payload-length", value_name = "N")]
    pub length: Option<u64>,

    /// Raw AES key file (aes-cbc)
    #[arg(long = "key-file", value_name = "FILE")]
    pub key_file: Option<String>,

    /// IV as 32 hex digits (aes-cbc)
    #[arg(long = "iv-hex", value_name = "HEX")]
    pub iv_hex: Option<String>,

    /// Remove PKCS#7 padding (aes-cbc)
    #[arg(long)]
    pub pkcs7: bool,
}

#[derive(Args, Debug, Clone)]
pub struct PatchArgs {
    /// Image to patch
    pub image: String,
    /// Address (RVA, va:0x..., or file:0x...) then replacement hex bytes; with --at, every
    /// operand is a byte. Bytes may be split across operands.
    #[arg(value_name = "ADDR HEX")]
    pub operands: Vec<String>,

    /// Address: RVA, va:0x..., or file:0x...
    #[arg(long = "at", value_name = "ADDR")]
    pub at: Option<String>,

    /// Replacement bytes as hex
    #[arg(long = "bytes", alias = "patch-bytes", value_name = "HEX")]
    pub patch_bytes: Option<String>,

    /// Require the current bytes to match before writing
    #[arg(long = "expect", alias = "expected", value_name = "HEX")]
    pub expect: Option<String>,

    /// Patched copy path [default: <name>.patched.<ext>]
    #[arg(long = "patch-out", value_name = "FILE")]
    pub patch_out: Option<String>,

    /// Validate and report without writing
    #[arg(long = "dry-run")]
    pub dry_run: bool,

    /// Modify the source image itself
    #[arg(long = "in-place")]
    pub in_place: bool,

    /// Allow replacing an existing output copy
    #[arg(long)]
    pub overwrite: bool,

    /// Recalculate the PE optional-header checksum
    #[arg(long = "update-checksum")]
    pub update_checksum: bool,

    #[command(flatten)]
    pub lookup: LookupArgs,
    #[command(flatten)]
    pub symbols: SymbolArgs,
}

#[derive(Args, Debug, Clone)]
pub struct ConfigArgs {
    /// Preferred display style for printed commands
    #[arg(long = "command-style", value_parser = ["standard", "slash"])]
    pub command_style: Option<String>,

    /// Name of the declared-entry function macro
    #[arg(long = "entry-macro", value_name = "NAME")]
    pub entry_macro: Option<String>,

    /// Name of the real-entry function macro
    #[arg(long = "rentry-macro", value_name = "NAME")]
    pub rentry_macro: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct ImplicitArgs {
    #[command(flatten)]
    pub dump: DumpArgs,
    #[command(flatten)]
    pub scope: ScopeArgs,
}

/// Build and run clap's parser on a bounded worker stack. The generated command
/// graph can exceed the Windows main thread's 1 MiB reserve in unoptimized builds.
pub fn parse_cli(args: Vec<String>) -> Result<Cli, clap::Error> {
    on_parser_stack(move || Cli::try_parse_from(args)).unwrap_or_else(|| {
        Err(clap::Error::raw(
            clap::error::ErrorKind::Format,
            "RESX command parser terminated unexpectedly",
        ))
    })
}

/// Runs `work` on a thread with enough stack for clap's command graph.
pub fn on_parser_stack<T: Send + 'static>(work: impl FnOnce() -> T + Send + 'static) -> Option<T> {
    std::thread::Builder::new()
        .name("resx-parser".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(work)
        .ok()
        .and_then(|worker| worker.join().ok())
}

#[cfg(test)]
mod tests {
    use super::{parse_cli, Cli, Command};
    use clap::CommandFactory;

    fn parse(values: &[&str]) -> Result<(Command, crate::core::config::Options), clap::Error> {
        let args = std::iter::once("resx")
            .chain(values.iter().copied())
            .map(str::to_owned)
            .collect();
        parse_cli(args).map(Cli::lower)
    }

    #[test]
    fn grammar_is_internally_consistent() {
        super::on_parser_stack(|| Cli::command().debug_assert()).unwrap();
    }

    #[test]
    fn output_options_are_accepted_before_the_command() {
        let (command, options) = parse(&["--json", "dump", "a.dll", "f"]).unwrap();
        assert_eq!(command.name(), "dump");
        assert_eq!(options.dll.as_deref(), Some("a.dll"));
        assert_eq!(options.function.as_deref(), Some("f"));
        assert!(options.json);
    }

    #[test]
    fn options_are_scoped_to_their_command() {
        assert!(parse(&["peinfo", "a.dll", "--calls-only", "winapi"]).is_err());
        assert!(parse(&["strings", "a.dll", "--max-insns", "5"]).is_err());
        assert!(parse(&["dump", "a.dll", "f", "--entropy-window", "5"]).is_err());
    }

    #[test]
    fn lightweight_ssa_is_explicitly_opt_in() {
        assert!(!parse(&["dump", "a.dll", "f"]).unwrap().1.ssa);
        assert!(parse(&["dump", "a.dll", "f", "--ssa"]).unwrap().1.ssa);
    }

    #[test]
    fn removed_flow_line_options_are_rejected() {
        assert!(parse(&["dump", "a.dll", "f", "--flow-lines"]).is_err());
        assert!(parse(&["dump", "a.dll", "f", "--branch-arrows"]).is_err());
    }

    /// Spellings from before per-command options. Scripts, the FFI layer and the VS Code
    /// extension pass these, so each must keep parsing under its command.
    #[test]
    fn legacy_spellings_still_parse() {
        let dump = ["dump", "a.dll", "f"];
        let legacy: &[(&[&str], &[&str])] = &[
            (&dump, &["--funcs"]),
            (&dump, &["--funcs-depth", "3"]),
            (&dump, &["--call-depth", "3"]),
            (&dump, &["--funcs-filter", "winapi,!crt"]),
            (&dump, &["--call-filter", "iat"]),
            (&dump, &["--limit", "9"]),
            (&dump, &["--insns", "9"]),
            (&dump, &["--analysis-budget", "9"]),
            (&dump, &["--xref-budget", "9"]),
            (&dump, &["--cfg-budget", "9"]),
            (&dump, &["--byte-limit", "9"]),
            (&dump, &["--hex"]),
            (&dump, &["--opcode"]),
            (&dump, &["--opcodes"]),
            (&dump, &["--no-dis"]),
            (&dump, &["--no-disassembly"]),
            (&dump, &["--show-offsets"]),
            (&dump, &["--show-rva"]),
            (&dump, &["--fast"]),
            (&dump, &["--refs"]),
            (&dump, &["--strrefs"]),
            (&dump, &["--decompile-out", "o.c"]),
            (&dump, &["--unsafe-map-image"]),
            (&dump, &["--intel"]),
            (&["intelli", "a.dll"], &["--funcs-depth", "2"]),
            (&["reconstruct-cfg", "a.dll"], &["--funcs-depth", "2"]),
            (&["strings", "a.dll"], &["--strings-min-len", "8"]),
            (&["strings", "a.dll"], &["--strings-limit", "9"]),
            (&["strings", "a.dll"], &["--strings-encoding", "ascii"]),
            (&["strings", "a.dll"], &["--strings-interesting"]),
            (&["strings", "a.dll"], &["--strings-match", "x"]),
            (&["strings", "a.dll"], &["--strings-tag", "y"]),
            (&["strings", "a.dll"], &["--strings-raw-wide"]),
            (&["entropy", "a.dll"], &["--entropy-window", "9"]),
            (&["entropy", "a.dll"], &["--entropy-stride", "9"]),
            (&["entropy", "a.dll"], &["--entropy-all"]),
            (&["find", "a.dll", "q"], &["--find-mode", "raw"]),
            (&["find", "a.dll", "q"], &["--find-encoded"]),
            (&["find", "a.dll", "q"], &["--find-budget", "9"]),
            (&["find", "a.dll"], &["--find", "q"]),
            (&["diff", "a", "b"], &["--diff-mode", "deep"]),
            (&["diff", "a", "b"], &["--diff-threshold", "9"]),
            (&["diff", "a", "b"], &["--diff-graph"]),
            (&["diff", "a", "b"], &["--diff-graph-format", "dot"]),
            (&["diff", "a", "b"], &["--diff-graph-out", "g"]),
            (&["diff", "a", "b"], &["--show-cfg-diff", "auto"]),
            (&["diff", "a", "b"], &["--cfg-diff-format", "dot"]),
            (&["diff", "a", "b"], &["--cfg-diff-out", "c"]),
            (&["hunt", "a"], &["--diff-threshold", "9"]),
            (&["callers", "a", "f"], &["--scan-dir", "d"]),
            (&["callers", "a", "f"], &["--scan-dll", "x"]),
            (&["callers", "a", "f"], &["--include-file", "l"]),
            (&["payload", "a"], &["--payload-dir", "d"]),
            (&["payload", "a"], &["--payload-offset", "1"]),
            (&["payload", "a"], &["--payload-length", "2"]),
            (&["patch", "a", "--at", "0x10"], &["--patch-bytes", "90"]),
            (&["patch", "a", "0x10", "90"], &["--expected", "55"]),
            (&["yara", "a"], &["--yara", "r.yar"]),
        ];
        for (command, spelling) in legacy {
            let argv: Vec<&str> = command.iter().chain(spelling.iter()).copied().collect();
            if let Err(error) = parse(&argv) {
                panic!("{spelling:?} no longer parses under {command:?}: {error}");
            }
        }
    }
    #[test]
    fn calls_lowers_its_filter_into_one_spec() {
        let (_, options) = parse(&[
            "calls",
            "a.exe",
            "main",
            "--depth",
            "4",
            "--only",
            "winapi,bcrypt",
            "--exclude",
            "crt",
        ])
        .unwrap();
        assert_eq!(options.funcs_depth, Some(4));
        assert_eq!(options.funcs_filter.as_deref(), Some("winapi,bcrypt,!crt"));
        assert!(options.no_disassembly);

        let (_, dump) = parse(&["dump", "a.exe", "main", "--calls-only", "iat"]).unwrap();
        assert_eq!(
            dump.funcs_depth, None,
            "Config applies the filter's implied depth"
        );
        assert_eq!(dump.funcs_filter.as_deref(), Some("iat"));
        assert_eq!(
            parse(&["dump", "a.exe", "main", "--calls"])
                .unwrap()
                .1
                .funcs_depth,
            Some(1)
        );
        assert!(parse(&["calls", "a.exe", "main", "--only", ""]).is_err());
    }
}
