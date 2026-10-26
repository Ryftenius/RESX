//! Lowers a parsed command into the flat [`Options`] that [`Config`] is built from.
//!
//! The internal mode fields (`peinfo`, `resx_diff`, `show_eat`, ...) are set exactly as
//! the pre-subcommand parser set them, so every `Config` a command receives is the
//! same as before; only the grammar in front of it changed.
//!
//! [`Config`]: crate::core::config::Config

use super::args::*;
use crate::core::config::Options;

impl Cli {
    /// Splits the parse into the command to dispatch and the options it runs with.
    pub fn lower(self) -> (Command, Options) {
        let mut options = Options::default();
        self.global.apply(&mut options);
        self.command.clone().apply(&mut options);
        (self.command, options)
    }
}

impl GlobalArgs {
    fn apply(self, o: &mut Options) {
        o.json = self.json;
        o.out_file = self.out_file;
        o.verbose = self.verbose;
        o.quiet = self.quiet;
        o.diagnostic = self.diagnostic;
        o.diagnostic_trace = self.diagnostic_trace;
        o.disasm_context = self.disasm_context;
        o.debug_report = self.debug_report;
        o.debug_report_include_target = self.debug_report_include_target;
        o.time = self.time;
        o.force_color = self.force_color;
        o.no_color = self.no_color;
        o.example = self.example;
    }
}

impl Command {
    fn apply(self, o: &mut Options) {
        match self {
            Self::Api(args) => o.function = Some(args.name),
            Self::Peinfo(args) => {
                image(o, args.image);
                o.file_metadata = args.file_metadata;
                args.lookup.apply(o);
                args.symbols.apply(o);
                o.peinfo = true;
            }
            Self::Sections(args) => {
                args.apply(o);
                o.sections = true;
            }
            Self::Pechk(args) => {
                args.apply(o);
                o.pechk = true;
            }
            Self::Eat(args) => {
                args.apply(o);
                o.show_eat = true;
            }
            Self::Iat(args) => {
                args.apply(o);
                o.show_iat = true;
            }
            Self::Syms(args) => {
                args.apply(o);
                o.show_syms = true;
            }
            Self::Types(args) => {
                image(o, args.image);
                o.function = args.query;
                args.lookup.apply(o);
                args.symbols.apply(o);
            }
            Self::Dump(args) => args.apply(o),
            Self::Calls(args) => args.apply(o),
            Self::Xrefs(args) => {
                args.apply(o);
                o.xrefs = true;
            }
            Self::Cfg(args) => {
                args.apply(o);
                o.cfg_view = Some("text".to_owned());
            }
            Self::ReconstructCfg(args) => {
                args.apply(o);
                o.reconstruct_cfg = true;
            }
            Self::Callers(args) => {
                args.apply(o);
                o.follow_callers = true;
            }
            Self::Intelli(args) => {
                args.apply(o);
                o.intelli = true;
            }
            Self::Behavior(args) => {
                image(o, args.image);
                args.analysis.apply(o);
                args.lookup.apply(o);
                args.symbols.apply(o);
                o.behavior = true;
            }
            Self::Contracts(args) | Self::Ipc(args) | Self::Network(args) | Self::Crypto(args) => {
                image(o, args.image);
                args.lookup.apply(o);
                args.symbols.apply(o);
            }
            Self::Strings(args) => args.apply(o),
            Self::Driver(args) | Self::Ioctl(args) => args.apply(o),
            Self::Entropy(args) => {
                image(o, args.image);
                o.entropy_window = args.window;
                o.entropy_stride = args.stride;
                o.entropy_all = args.all;
                args.lookup.apply(o);
                args.symbols.apply(o);
                o.entropy = true;
            }
            Self::Yara(args) => {
                image(o, args.image);
                o.yara = args.rules;
                o.yara.extend(args.legacy_rules);
                args.lookup.apply(o);
                args.symbols.apply(o);
            }
            Self::Find(args) => {
                image(o, args.image);
                o.find_pattern = args.query.or(args.legacy_query);
                o.find_mode = args.mode;
                o.find_encoded = args.encoded;
                o.find_budget = args.budget;
                args.lookup.apply(o);
                args.symbols.apply(o);
                o.resx_find = true;
            }
            Self::Scan(args) => {
                o.scan_root = Some(args.root);
                o.jsonl = args.jsonl;
                o.scan_extensions = args.extensions;
                o.max_files = args.max_files;
                o.max_file_mb = args.max_file_mb;
                o.max_candidates = args.max_candidates;
                args.symbols.apply(o);
                o.resx_scan = true;
            }
            Self::Diff(args) => args.apply(o),
            Self::Index(args) => {
                image(o, args.root);
                o.corpus_db = args.db;
                o.scan_extensions = args.extensions;
                o.max_files = args.max_files;
                o.max_file_mb = args.max_file_mb;
                args.matching.apply(o);
                args.analysis.apply(o);
                args.lookup.apply(o);
                args.symbols.apply(o);
                o.resx_index = true;
            }
            Self::Hunt(args) => {
                image(o, args.sample);
                o.corpus_db = args.db;
                args.matching.apply(o);
                args.analysis.apply(o);
                args.lookup.apply(o);
                args.symbols.apply(o);
                o.resx_hunt = true;
            }
            Self::Locate(args) => {
                args.apply(o);
                o.locate = true;
            }
            Self::LocateSym(args) => {
                args.apply(o);
                o.locate_deep = true;
            }
            Self::Payload(args) => {
                image(o, args.input);
                o.payload_dir = args.out_dir;
                o.codec = args.codec;
                o.payload_offset = args.offset;
                o.payload_length = args.length;
                o.key_file = args.key_file;
                o.iv_hex = args.iv_hex;
                o.pkcs7 = args.pkcs7;
            }
            Self::Patch(args) => args.apply(o),
            Self::Priority => o.priority = true,
            Self::Config(args) => {
                o.command_style = args.command_style;
                o.entry_macro = args.entry_macro;
                o.rentry_macro = args.rentry_macro;
                o.headers = args.headers;
                o.resx_config = true;
            }
            Self::Update => o.update = true,
            Self::Implicit(args) => {
                args.dump.apply(o);
                args.scope.apply(o);
            }
        }
    }
}

fn image(o: &mut Options, image: String) {
    o.dll = Some(image);
}

impl LookupArgs {
    fn apply(self, o: &mut Options) {
        o.paths = self.paths;
        o.no_system = self.no_system;
        o.no_cwd = self.no_cwd;
        o.no_path = self.no_path;
        o.arch = self.arch;
        o.rebase = self.rebase;
    }
}

impl SymbolArgs {
    fn apply(self, o: &mut Options) {
        o.pdb_file = self.pdb_file;
        o.sym_path = self.sym_path;
        o.sym_server = self.sym_server;
        o.reload = self.reload;
        o.no_pdb = self.no_pdb;
        o.no_headers = self.no_headers;
        o.api_args = self.api_args;
    }
}

impl TargetArgs {
    fn apply(self, o: &mut Options) {
        o.function = self.target;
        o.at_rva = self.at;
        o.ordinal = self.ordinal;
    }
}

impl AnalysisArgs {
    fn apply(self, o: &mut Options) {
        o.max_insns = self.max_insns;
        o.max_total = self.max_total;
        o.hostile = self.hostile;
    }
}

impl ListingArgs {
    fn apply(self, o: &mut Options) {
        o.max_bytes = self.max_bytes;
        o.bytes = self.bytes;
        o.no_bytes = self.no_bytes;
        o.no_disassembly = self.no_disassembly;
        o.ssa = self.ssa;
        o.intel = self.intel;
        o.att = self.att;
        o.follow_jmp = self.follow_jmp;
        o.no_follow_jmp = self.no_follow_jmp;
        o.no_follow_forward = self.no_follow_forward;
        o.show_offsets = self.show_offsets;
        o.show_rva = self.show_rva;
        o.addr_width = self.addr_width;
        o.byte_col_width = self.byte_col_width;
    }
}

/// Joins `--only` terms with `!`-prefixed `--exclude` terms and any legacy raw spec
/// into the single filter spec the call-map engine parses.
fn filter_spec(only: Vec<String>, exclude: Vec<String>, legacy: Option<String>) -> Option<String> {
    let terms: Vec<String> = only
        .into_iter()
        .chain(exclude.into_iter().map(|term| format!("!{term}")))
        .chain(legacy)
        .collect();
    (!terms.is_empty()).then(|| terms.join(","))
}

impl CallTreeArgs {
    fn apply(self, o: &mut Options) {
        o.funcs = self.funcs;
        o.funcs_depth = self.calls.or(self.funcs_depth);
        o.funcs_filter = filter_spec(self.calls_only, self.calls_exclude, self.funcs_filter);
        o.max_subcalls = self.max_subcalls;
        o.highlight = self.highlight;
    }
}

impl ReportArgs {
    fn apply(self, o: &mut Options) {
        o.xrefs = self.xrefs;
        o.strings = self.strings;
        o.cfg_view = self.cfg_view;
        o.recomp = self.recomp;
        o.c_out = self.c_out;
        o.driver_flow = self.driver_flow;
        o.intelli = self.intelli;
        o.edrchk = self.edrchk;
        o.hookchk = self.hookchk;
        o.unsafe_map_image = self.unsafe_map_image;
        o.sections = self.sections;
        o.pechk = self.pechk;
        o.show_eat = self.show_eat;
        o.show_iat = self.show_iat;
        o.show_syms = self.show_syms;
        o.yara = self.yara;
    }
}

impl FlowArgs {
    fn apply(self, o: &mut Options) {
        o.depth = self.depth;
        o.max_callers = self.max_callers;
    }
}

impl ScopeArgs {
    fn apply(self, o: &mut Options) {
        o.scan_dirs = self.scan_dirs;
        o.scan_dlls = self.scan_dlls;
        o.scan_exe = self.scan_exe;
        o.include = self.include;
        o.scope_file = self.scope_file;
        o.exclude = self.exclude;
        o.filter_dll = self.filter_dll;
        o.max_dll_mb = self.max_dll_mb;
        o.workers = self.workers;
    }
}

impl MatchArgs {
    fn apply(self, o: &mut Options) {
        o.diff_mode = self.diff_mode;
        o.diff_threshold = self.diff_threshold;
        o.include_weak = self.include_weak;
        o.diff_max_functions = self.diff_max_functions;
        o.max_candidates = self.max_candidates;
        o.max_cfg_blocks = self.max_cfg_blocks;
    }
}

impl DeviceArgs {
    fn apply(self, o: &mut Options) {
        self.image.apply(o);
        o.device_security = self.device_security;
        o.device_security_worker = self.device_security_worker;
    }
}

impl ImageArgs {
    fn apply(self, o: &mut Options) {
        image(o, self.image);
        self.lookup.apply(o);
        self.symbols.apply(o);
    }
}

impl DumpArgs {
    fn apply(self, o: &mut Options) {
        image(o, self.image);
        self.target.apply(o);
        self.report.apply(o);
        self.calls.apply(o);
        self.listing.apply(o);
        self.analysis.apply(o);
        self.lookup.apply(o);
        self.symbols.apply(o);
    }
}

impl CallsArgs {
    fn apply(self, o: &mut Options) {
        image(o, self.image);
        self.target.apply(o);
        o.funcs_depth = Some(self.depth);
        o.funcs_filter = filter_spec(self.only, self.exclude, None);
        o.max_subcalls = self.max_subcalls;
        o.highlight = self.highlight;
        o.show_rva = self.show_rva;
        o.show_offsets = self.show_offsets;
        o.no_disassembly = true;
        self.analysis.apply(o);
        self.lookup.apply(o);
        self.symbols.apply(o);
    }
}

impl ReconstructArgs {
    fn apply(self, o: &mut Options) {
        image(o, self.image);
        o.reconstruct_thread_filter = self.thread_filter;
        o.reconstruct_api_filter = self.api_filter;
        o.driver_flow = self.driver_flow;
        o.max_subcalls = self.max_subcalls;
        o.funcs = self.funcs;
        o.funcs_depth = self.funcs_depth;
        self.flow.apply(o);
        self.analysis.apply(o);
        self.lookup.apply(o);
        self.symbols.apply(o);
    }
}

impl CallersArgs {
    fn apply(self, o: &mut Options) {
        image(o, self.image);
        o.function = Some(self.function);
        o.follow_format = self.format;
        o.show_site = self.show_site;
        o.show_rva = self.show_rva;
        self.flow.apply(o);
        self.scope.apply(o);
        self.analysis.apply(o);
        self.lookup.apply(o);
        self.symbols.apply(o);
    }
}

impl StringsArgs {
    fn apply(self, o: &mut Options) {
        image(o, self.image);
        o.strings_min_len = self.min_len;
        o.strings_limit = self.limit;
        o.strings_encoding = self.encoding;
        o.strings_interesting = self.interesting;
        o.strings_match = self.matching;
        o.strings_tag = self.tag;
        o.strings_raw_wide = self.raw_wide;
        self.lookup.apply(o);
        self.symbols.apply(o);
    }
}

impl DiffArgs {
    fn apply(self, o: &mut Options) {
        let mut images = self.images.into_iter();
        o.dll = images.next();
        o.function = images.next();
        o.extra_images = images.collect();
        o.left_pdb_file = self.left_pdb;
        o.right_pdb_file = self.right_pdb;
        o.cfg_diff_target = self.show_cfg;
        o.cfg_diff_format = self.cfg_format;
        o.cfg_diff_out = self.cfg_out;
        o.diff_graph = self.graph;
        o.diff_graph_format = self.graph_format;
        o.diff_graph_out = self.graph_out;
        self.matching.apply(o);
        self.analysis.apply(o);
        self.lookup.apply(o);
        self.symbols.apply(o);
        o.resx_diff = true;
    }
}

impl LocateArgs {
    fn apply(self, o: &mut Options) {
        image(o, self.name);
        self.scope.apply(o);
        self.lookup.apply(o);
        self.symbols.apply(o);
    }
}

impl PatchArgs {
    fn apply(self, o: &mut Options) {
        image(o, self.image);
        let mut operands = self.operands.into_iter();
        o.at_rva = self.at.or_else(|| operands.next());
        let bytes: Vec<String> = self.patch_bytes.into_iter().chain(operands).collect();
        o.patch_bytes = (!bytes.is_empty()).then(|| bytes.join(" "));
        o.patch_expect = self.expect;
        o.patch_out = self.patch_out;
        o.patch_dry_run = self.dry_run;
        o.patch_in_place = self.in_place;
        o.patch_overwrite = self.overwrite;
        o.patch_update_checksum = self.update_checksum;
        self.lookup.apply(o);
        self.symbols.apply(o);
        o.patch = true;
    }
}
