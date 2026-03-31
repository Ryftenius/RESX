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

    #[arg(long = "include-dir", alias = "scan-dir", action = clap::ArgAction::Append, value_name = "DIR")]
    pub scan_dirs: Vec<String>,

    #[arg(long = "include-image", alias = "scan-dll", action = clap::ArgAction::Append, value_name = "DLL")]
    pub scan_dlls: Vec<String>,

    #[arg(long = "scan-exe")]
    pub scan_exe: bool,

    #[arg(long = "include", default_value = "")]
    pub include: String,

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
}

#[derive(Debug, Clone)]
pub struct Config {
    pub dll: String,
    pub function: String,

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
    pub scan_dirs: Vec<String>,
    pub scan_dlls: Vec<String>,
    pub scan_exe: bool,
    pub include: String,
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
            json: cli.json,
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
            scan_dirs: cli.scan_dirs.clone(),
            scan_dlls: cli.scan_dlls.clone(),
            scan_exe: cli.scan_exe,
            include: cli.include.clone(),
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
