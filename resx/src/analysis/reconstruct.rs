use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;

use iced_x86::{Mnemonic, OpKind, Register};
use serde::Serialize;

use crate::analysis::disasm::{collect_api_calls, disassemble_at, is_ret, ApiCall, Instruction};
use crate::analysis::discovery::{discover_functions, FunctionDiscoveryReport};
use crate::analysis::symbols::SymbolIndex;
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::formats::pdb::PdbSymbol;
use crate::formats::pe::{
    read_runtime_function, read_u32, read_u64, Export, PeFile, PeStartupRoutine,
};

#[derive(Debug, Serialize)]
pub struct ReconstructReport {
    pub image: String,
    pub path: String,
    pub arch: String,
    pub image_base: String,
    pub entry_point: String,
    pub pdb: PdbInfo,
    pub function_discovery: FunctionDiscoveryReport,
    pub roots: Vec<FlowFunction>,
    pub stats: ReconstructStats,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PdbInfo {
    pub enabled: bool,
    pub loaded: bool,
    pub symbol_count: usize,
    pub function_count: usize,
    pub sized_function_count: usize,
    pub status: String,
    pub error: String,
}

impl PdbInfo {
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            loaded: false,
            symbol_count: 0,
            function_count: 0,
            sized_function_count: 0,
            status: "disabled".to_owned(),
            error: String::new(),
        }
    }

    pub fn loaded(symbols: &[PdbSymbol]) -> Self {
        let function_count = symbols.iter().filter(|sym| sym.kind == "function").count();
        let sized_function_count = symbols
            .iter()
            .filter(|sym| sym.kind == "function" && sym.size > 0)
            .count();
        Self {
            enabled: true,
            loaded: true,
            symbol_count: symbols.len(),
            function_count,
            sized_function_count,
            status: "loaded".to_owned(),
            error: String::new(),
        }
    }

    pub fn unavailable(error: String) -> Self {
        Self {
            enabled: true,
            loaded: false,
            symbol_count: 0,
            function_count: 0,
            sized_function_count: 0,
            status: "unavailable".to_owned(),
            error,
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct ReconstructStats {
    pub roots: usize,
    pub functions_expanded: usize,
    pub call_edges: usize,
    pub import_edges: usize,
    pub indirect_edges: usize,
    pub thread_edges: usize,
    pub workpool_edges: usize,
    pub thread_api_edges: usize,
    pub exception_edges: usize,
    pub cycle_edges: usize,
    pub truncated_edges: usize,
    pub decode_errors: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowFunction {
    pub name: String,
    pub kind: String,
    pub rva: String,
    pub va: String,
    pub section: String,
    pub symbol_source: String,
    pub symbol_category: String,
    pub symbol_size: String,
    pub prototype: String,
    pub decode_bound: String,
    pub thread_lane: usize,
    pub note: String,
    pub status: String,
    pub edges: Vec<FlowEdge>,
    pub returns: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FlowEdge {
    pub site_rva: String,
    pub kind: String,
    pub target: String,
    pub target_rva: String,
    pub target_va: String,
    pub target_source: String,
    pub target_category: String,
    pub thread_lane: usize,
    pub tags: Vec<String>,
    pub detail: String,
    pub relation: String,
    pub child: Option<Box<FlowFunction>>,
}

#[derive(Debug, Clone, Copy)]
struct CallbackSpec {
    relation: &'static str,
    tag: &'static str,
    arg_index: usize,
}

#[derive(Debug, Clone)]
struct PdbFunction {
    size: u64,
    type_name: String,
}

struct TraceContext<'a> {
    raw: &'a [u8],
    pe: &'a PeFile,
    exports: &'a [Export],
    symbol_index: &'a SymbolIndex,
    pdb_functions: HashMap<u32, PdbFunction>,
    arch: u32,
    image_base: u64,
    cfg: &'a Config,
    expanded: HashSet<u32>,
    stats: ReconstructStats,
    max_depth: usize,
    max_total: usize,
    next_lane: usize,
}

#[allow(clippy::too_many_arguments)]
pub fn reconstruct_image(
    image: &str,
    path: &str,
    raw: &[u8],
    pe: &PeFile,
    exports: &[Export],
    symbol_index: &SymbolIndex,
    pdb_symbols: &[PdbSymbol],
    pdb: PdbInfo,
    startup_routines: &[PeStartupRoutine],
    arch: u32,
    cfg: &Config,
) -> ReconstructReport {
    let pdb_functions = build_pdb_function_index(pdb_symbols);
    let mut ctx = TraceContext {
        raw,
        pe,
        exports,
        symbol_index,
        pdb_functions,
        arch,
        image_base: pe.image_base,
        cfg,
        expanded: HashSet::new(),
        stats: ReconstructStats::default(),
        max_depth: cfg.depth.max(1),
        max_total: cfg.max_total.max(1),
        next_lane: 1,
    };

    let roots = if startup_routines.is_empty() {
        vec![PeStartupRoutine {
            kind: "PE Entry Point".to_owned(),
            source: "AddressOfEntryPoint".to_owned(),
            rva: pe.entry_point,
            va: pe.image_base + pe.entry_point as u64,
            section_name: pe
                .rva_to_section(pe.entry_point)
                .map(|section| section.name.clone())
                .unwrap_or_default(),
            note: "loader transfers control here after image initialization".to_owned(),
        }]
    } else {
        startup_routines.to_vec()
    };

    let mut traced_roots = Vec::new();
    for root in roots {
        if !is_executable_rva(pe, root.rva) {
            continue;
        }
        let mut path_stack = HashSet::new();
        traced_roots.push(ctx.trace_function(
            root.rva,
            root_name(&root, symbol_index, pe.image_base),
            root.kind,
            root.source,
            root.note,
            0,
            0,
            &mut path_stack,
        ));
    }

    ctx.stats.roots = traced_roots.len();
    let notes = vec![
        "static best-effort reconstruction; runtime dispatch, data-dependent branches, and dynamically generated code may be incomplete".to_owned(),
        "thread/workpool callback edges are shown only when the callback argument resolves to executable code in the same image".to_owned(),
        "exception edges use x64 unwind handler RVAs when present; language-specific scope tables are not fully expanded".to_owned(),
    ];

    ReconstructReport {
        image: image.to_owned(),
        path: path.to_owned(),
        arch: format!("x{}", arch),
        image_base: hex64(pe.image_base),
        entry_point: hex32(pe.entry_point),
        pdb,
        function_discovery: discover_functions(
            raw,
            pe,
            exports,
            symbol_index,
            pdb_symbols,
            startup_routines,
            cfg,
        ),
        roots: traced_roots,
        stats: ctx.stats,
        notes,
    }
}

impl<'a> TraceContext<'a> {
    #[allow(clippy::too_many_arguments)]
    fn trace_function(
        &mut self,
        rva: u32,
        name: String,
        kind: String,
        source: String,
        note: String,
        depth: usize,
        lane: usize,
        path_stack: &mut HashSet<u32>,
    ) -> FlowFunction {
        let sym = self.symbol_meta(rva);
        let decode_bound = self.decode_bound_label(rva, sym.as_ref());
        let symbol_source = sym
            .as_ref()
            .map(|s| s.source.clone())
            .unwrap_or_else(|| "synthetic".to_owned());
        let symbol_category = classify_function_symbol(&name, &symbol_source, sym.as_ref());
        let section = self
            .pe
            .rva_to_section(rva)
            .map(|section| section.name.clone())
            .unwrap_or_default();
        let mut node = FlowFunction {
            name,
            kind,
            rva: hex32(rva),
            va: hex64(self.image_base + rva as u64),
            section,
            symbol_source,
            symbol_category,
            symbol_size: sym
                .as_ref()
                .and_then(|s| (s.size > 0).then(|| format!("0x{:X}", s.size)))
                .unwrap_or_default(),
            prototype: sym
                .as_ref()
                .map(|s| s.prototype.clone())
                .unwrap_or_default(),
            decode_bound,
            thread_lane: lane,
            note: join_detail(&[source, note]),
            status: "expanded".to_owned(),
            edges: Vec::new(),
            returns: Vec::new(),
        };

        if !path_stack.insert(rva) {
            node.status = "cycle".to_owned();
            self.stats.cycle_edges += 1;
            return node;
        }

        if depth >= self.max_depth {
            node.status = format!("truncated: max depth {}", self.max_depth);
            self.stats.truncated_edges += 1;
            path_stack.remove(&rva);
            return node;
        }

        if self.expanded.len() >= self.max_total {
            node.status = format!("truncated: max total {}", self.max_total);
            self.stats.truncated_edges += 1;
            path_stack.remove(&rva);
            return node;
        }

        if !self.expanded.insert(rva) {
            node.status = "already expanded elsewhere".to_owned();
            path_stack.remove(&rva);
            return node;
        }
        self.stats.functions_expanded += 1;

        let Some(file_off) = self.pe.rva_to_offset(rva) else {
            node.status = "decode error: RVA is not mapped to a file offset".to_owned();
            self.stats.decode_errors += 1;
            path_stack.remove(&rva);
            return node;
        };

        let mut decode_cfg = self.cfg.clone();
        if let Some(size) = sym.as_ref().and_then(|s| (s.size > 0).then_some(s.size)) {
            let size = size.min(usize::MAX as u64) as usize;
            if size > 0 {
                decode_cfg.max_bytes = if decode_cfg.max_bytes == 0 {
                    size
                } else {
                    decode_cfg.max_bytes.min(size)
                };
            }
        }

        let insns = match disassemble_at(
            self.raw,
            self.pe,
            file_off,
            rva,
            self.arch,
            self.image_base,
            self.exports,
            Some(self.symbol_index),
            &decode_cfg,
        ) {
            Ok(insns) => insns,
            Err(err) => {
                node.status = format!("decode error: {}", err);
                self.stats.decode_errors += 1;
                path_stack.remove(&rva);
                return node;
            }
        };

        node.returns = insns
            .iter()
            .filter(|insn| is_ret(insn.iced.mnemonic()))
            .map(|insn| hex32(insn.rva))
            .collect();

        let mut calls = collect_api_calls(
            &insns,
            self.pe,
            self.raw,
            self.symbol_index,
            self.image_base,
            true,
        );
        calls.sort_by_key(|call| call.rva);

        for call in calls {
            node.edges
                .push(self.edge_from_call(&insns, &call, depth, lane, path_stack));
        }

        if let Some(runtime) = read_runtime_function(self.pe, self.raw, rva) {
            if runtime.exception_handler_rva != 0
                && runtime.exception_handler_rva != rva
                && is_executable_rva(self.pe, runtime.exception_handler_rva)
            {
                self.stats.exception_edges += 1;
                let handler_rva = runtime.exception_handler_rva;
                let handler_name =
                    best_symbol_name(self.symbol_index, self.image_base, handler_rva);
                let handler_meta = self.symbol_meta(handler_rva);
                let handler_source = handler_meta
                    .as_ref()
                    .map(|s| s.source.clone())
                    .unwrap_or_else(|| "synthetic".to_owned());
                let handler_category =
                    classify_function_symbol(&handler_name, &handler_source, handler_meta.as_ref());
                let child = if path_stack.contains(&handler_rva) {
                    None
                } else {
                    Some(Box::new(self.trace_function(
                        handler_rva,
                        handler_name.clone(),
                        "Exception Handler".to_owned(),
                        ".pdata unwind".to_owned(),
                        format!(
                            "handler for runtime function 0x{:08X}..0x{:08X}",
                            runtime.begin_rva, runtime.end_rva
                        ),
                        depth + 1,
                        lane,
                        path_stack,
                    )))
                };
                node.edges.push(FlowEdge {
                    site_rva: hex32(runtime.begin_rva),
                    kind: "exception".to_owned(),
                    target: handler_name,
                    target_rva: hex32(handler_rva),
                    target_va: hex64(self.image_base + handler_rva as u64),
                    target_source: handler_source,
                    target_category: handler_category,
                    thread_lane: lane,
                    tags: vec!["try-except".to_owned(), "unwind".to_owned()],
                    detail: format!(
                        "UNWIND_INFO 0x{:08X}, flags 0x{:X}",
                        runtime.unwind_info_rva, runtime.unwind_flags
                    ),
                    relation: "exception-handler".to_owned(),
                    child,
                });
            }
        }

        path_stack.remove(&rva);
        node
    }

    fn edge_from_call(
        &mut self,
        insns: &[Instruction],
        call: &ApiCall,
        depth: usize,
        lane: usize,
        path_stack: &mut HashSet<u32>,
    ) -> FlowEdge {
        self.stats.call_edges += 1;

        let mut tags = Vec::new();
        if call.is_import {
            self.stats.import_edges += 1;
            tags.push("import".to_owned());
        }
        if call.is_indirect {
            self.stats.indirect_edges += 1;
            tags.push("indirect".to_owned());
        }
        if call.kind.eq_ignore_ascii_case("jmp") {
            tags.push("tail-jump".to_owned());
        }
        if is_terminator_api(&call.label) {
            tags.push("program-end".to_owned());
        }
        if let Some(intent) = thread_api_intent(&call.label) {
            self.stats.thread_api_edges += 1;
            tags.push("thread-api".to_owned());
            tags.push(intent.to_owned());
        }

        let target_rva = executable_target_rva(self.pe, call.target_rva);
        let target_meta = target_rva.and_then(|rva| self.symbol_meta(rva));
        let target_name = call_target_name(call);
        let target_source = target_meta
            .as_ref()
            .map(|meta| meta.source.clone())
            .unwrap_or_else(|| {
                if call.is_import {
                    "import".to_owned()
                } else {
                    "unknown".to_owned()
                }
            });
        let target_category =
            classify_edge_target(&target_name, &target_source, target_meta.as_ref());
        let mut relation = "callee".to_owned();
        let mut child = None;
        let mut detail_parts = Vec::new();
        if let Some(method) = &call.indirect_method {
            detail_parts.push(method.clone());
        }
        if !call.switch_cases.is_empty() {
            detail_parts.push(format!("switch cases: {:?}", call.switch_cases));
        }
        if let Some(intent) = describe_thread_intent(call, insns, self.pe, self.raw) {
            detail_parts.push(intent);
        }

        let mut edge_lane = lane;
        if let Some(spec) = callback_spec(&call.label) {
            tags.push(spec.tag.to_owned());
            relation = spec.relation.to_owned();
            if spec.tag == "thread-spawn" {
                self.stats.thread_edges += 1;
            } else {
                self.stats.workpool_edges += 1;
            }

            match recover_callback_target(insns, call.rva, spec.arg_index, self.pe, self.raw) {
                Some((callback_rva, method)) => {
                    detail_parts.push(format!(
                        "{} callback arg{} via {}",
                        spec.relation, spec.arg_index, method
                    ));
                    let callback_name =
                        best_symbol_name(self.symbol_index, self.image_base, callback_rva);
                    edge_lane = self.allocate_lane();
                    child = Some(Box::new(self.trace_function(
                        callback_rva,
                        callback_name,
                        relation_title(spec.relation),
                        format!("{} @ {}", call_target_name(call), hex32(call.rva)),
                        format!("callback recovered from {}", call_target_name(call)),
                        depth + 1,
                        edge_lane,
                        path_stack,
                    )));
                }
                None => {
                    detail_parts.push(format!(
                        "{} callback arg{} unresolved",
                        spec.relation, spec.arg_index
                    ));
                }
            }
        } else if let Some(target_rva) = target_rva {
            let target_name = best_symbol_name(self.symbol_index, self.image_base, target_rva);
            if path_stack.contains(&target_rva) {
                tags.push("cycle".to_owned());
                self.stats.cycle_edges += 1;
            } else {
                child = Some(Box::new(self.trace_function(
                    target_rva,
                    target_name,
                    if call.kind.eq_ignore_ascii_case("jmp") {
                        "Tail Call".to_owned()
                    } else {
                        "Function".to_owned()
                    },
                    format!("{} @ {}", call.kind, hex32(call.rva)),
                    String::new(),
                    depth + 1,
                    lane,
                    path_stack,
                )));
            }
        }

        FlowEdge {
            site_rva: hex32(call.rva),
            kind: call.kind.clone(),
            target: target_name,
            target_rva: target_rva
                .map(hex32)
                .unwrap_or_else(|| hex32(call.target_rva)),
            target_va: target_rva
                .map(|rva| hex64(self.image_base + rva as u64))
                .unwrap_or_default(),
            target_source,
            target_category,
            thread_lane: edge_lane,
            tags,
            detail: detail_parts.join("; "),
            relation,
            child,
        }
    }

    fn allocate_lane(&mut self) -> usize {
        let lane = self.next_lane;
        self.next_lane += 1;
        lane
    }

    fn symbol_meta(&self, rva: u32) -> Option<SymbolMeta> {
        if let Some(func) = self.pdb_functions.get(&rva) {
            return Some(SymbolMeta {
                source: "pdb".to_owned(),
                size: func.size,
                prototype: func.type_name.clone(),
            });
        }

        let va = self.image_base + rva as u64;
        let hit = self.symbol_index.lookup(va)?;
        if hit.displacement != 0 {
            return None;
        }
        let source = if hit.symbol.size > 0 || !hit.symbol.type_name.is_empty() {
            "pdb"
        } else if self
            .exports
            .iter()
            .any(|export| export.rva == rva && !export.name.is_empty())
        {
            "export"
        } else {
            "symbol"
        };
        Some(SymbolMeta {
            source: source.to_owned(),
            size: hit.symbol.size,
            prototype: hit.symbol.type_name,
        })
    }

    fn decode_bound_label(&self, rva: u32, sym: Option<&SymbolMeta>) -> String {
        if let Some(runtime) = read_runtime_function(self.pe, self.raw, rva) {
            return format!(
                ".pdata 0x{:08X}..0x{:08X}",
                runtime.begin_rva, runtime.end_rva
            );
        }
        if let Some(sym) = sym.filter(|sym| sym.source == "pdb" && sym.size > 0) {
            return format!("pdb-size 0x{:X}", sym.size);
        }
        "section/max-bytes".to_owned()
    }
}

#[derive(Debug, Clone)]
struct SymbolMeta {
    source: String,
    size: u64,
    prototype: String,
}

#[derive(Debug, Clone)]
struct RenderFilters {
    thread: String,
    api: String,
}

impl RenderFilters {
    fn from_config(cfg: &Config) -> Self {
        Self {
            thread: cfg.reconstruct_thread_filter.trim().to_ascii_lowercase(),
            api: cfg.reconstruct_api_filter.trim().to_ascii_lowercase(),
        }
    }

    fn active(&self) -> bool {
        !self.thread.is_empty() || !self.api.is_empty()
    }

    fn function_visible(&self, func: &FlowFunction) -> bool {
        if !self.active() {
            return true;
        }
        let thread_ok = self.thread.is_empty()
            || self.function_matches_thread(func)
            || func
                .edges
                .iter()
                .any(|edge| self.edge_matches_thread_tree(edge));
        let api_ok = self.api.is_empty()
            || function_text(func).contains(&self.api)
            || func
                .edges
                .iter()
                .any(|edge| self.edge_matches_api_tree(edge));
        thread_ok && api_ok
    }

    fn edge_visible(&self, edge: &FlowEdge) -> bool {
        if !self.active() {
            return true;
        }
        let thread_ok = self.thread.is_empty() || self.edge_matches_thread_tree(edge);
        let api_ok = self.api.is_empty() || self.edge_matches_api_tree(edge);
        thread_ok && api_ok
    }

    fn function_matches_thread(&self, func: &FlowFunction) -> bool {
        if self.thread.is_empty() {
            return true;
        }
        match self.thread.as_str() {
            "all" => true,
            "spawned" => func.thread_lane != 0,
            "api" => false,
            needle => func.thread_lane != 0 && function_text(func).contains(needle),
        }
    }

    fn edge_matches_thread_tree(&self, edge: &FlowEdge) -> bool {
        if self.thread.is_empty() || self.thread == "all" {
            return true;
        }
        let direct = match self.thread.as_str() {
            "spawned" => {
                edge.thread_lane != 0 || has_tag(edge, "thread-spawn") || has_tag(edge, "workpool")
            }
            "api" => has_tag(edge, "thread-api"),
            needle => {
                (edge.thread_lane != 0 || edge.tags.iter().any(|tag| tag.contains("thread")))
                    && edge_text(edge).contains(needle)
            }
        };
        direct
            || edge
                .child
                .as_ref()
                .is_some_and(|child| self.function_visible(child))
    }

    fn edge_matches_api_tree(&self, edge: &FlowEdge) -> bool {
        if self.api.is_empty() {
            return true;
        }
        edge_text(edge).contains(&self.api)
            || edge
                .child
                .as_ref()
                .is_some_and(|child| self.function_visible(child))
    }
}

fn function_text(func: &FlowFunction) -> String {
    format!(
        "{} {} {} {} {} {} {}",
        func.name,
        func.kind,
        func.rva,
        func.symbol_source,
        func.symbol_category,
        func.prototype,
        func.note
    )
    .to_ascii_lowercase()
}

fn edge_text(edge: &FlowEdge) -> String {
    format!(
        "{} {} {} {} {} {} {} {}",
        edge.kind,
        edge.target,
        edge.target_rva,
        edge.target_source,
        edge.target_category,
        edge.tags.join(" "),
        edge.detail,
        edge.relation
    )
    .to_ascii_lowercase()
}

fn has_tag(edge: &FlowEdge, wanted: &str) -> bool {
    edge.tags.iter().any(|tag| tag == wanted)
}

pub fn render_ascii(report: &ReconstructReport, c: &Colors, cfg: &Config) -> String {
    let filters = RenderFilters::from_config(cfg);
    let mut out = String::new();
    let _ = writeln!(
        out,
        "{}",
        c.bold(&c.b_blue(&format!("Reconstructed CFG: {}", report.image)))
    );
    let _ = writeln!(
        out,
        "  {} {}  {} {}  {} {}",
        c.dim("arch:"),
        c.b_white(&report.arch),
        c.dim("image_base:"),
        c.cyan(&report.image_base),
        c.dim("entry:"),
        c.green(&report.entry_point)
    );
    let _ = writeln!(out, "  {} {}", c.dim("path:"), report.path);
    let _ = writeln!(
        out,
        "  {} {}  {} {}  {} {}",
        c.dim("pdb:"),
        color_pdb_status(&report.pdb, c),
        c.dim("symbols:"),
        c.b_white(&report.pdb.symbol_count.to_string()),
        c.dim("functions:"),
        c.b_white(&format!(
            "{} / {} sized",
            report.pdb.function_count, report.pdb.sized_function_count
        ))
    );
    let _ = writeln!(out, "  {} {}", c.dim("legend:"), render_symbol_legend(c));
    let _ = writeln!(out);

    if report.roots.is_empty() {
        let _ = writeln!(out, "{}", c.dim("(no executable startup roots found)"));
    } else {
        let visible_roots = report
            .roots
            .iter()
            .enumerate()
            .filter(|(_, root)| filters.function_visible(root))
            .collect::<Vec<_>>();
        if visible_roots.is_empty() {
            let _ = writeln!(out, "{}", c.dim("(no paths matched filters)"));
        }
        for (pos, (idx, root)) in visible_roots.iter().enumerate() {
            render_root(&mut out, root, idx + 1, report.roots.len(), c, &filters);
            if pos + 1 < visible_roots.len() {
                let _ = writeln!(out);
            }
        }
    }

    let _ = writeln!(out);
    let _ = writeln!(out, "{}", c.bold(&c.b_cyan("Summary")));
    let _ = writeln!(
        out,
        "  roots={} functions={} calls={} imports={} indirect={} threads={} workpools={} exceptions={} cycles={} truncated={} decode_errors={}",
        report.stats.roots,
        report.stats.functions_expanded,
        report.stats.call_edges,
        report.stats.import_edges,
        report.stats.indirect_edges,
        report.stats.thread_edges,
        report.stats.workpool_edges,
        report.stats.exception_edges,
        report.stats.cycle_edges,
        report.stats.truncated_edges,
        report.stats.decode_errors,
    );
    if !report.notes.is_empty() {
        let _ = writeln!(out, "{}", c.dim("Notes:"));
        for note in &report.notes {
            let _ = writeln!(out, "  - {}", c.dim(note));
        }
    }
    if filters.active() {
        let _ = writeln!(out, "{}", c.dim("Filters:"));
        if !filters.thread.is_empty() {
            let _ = writeln!(out, "  - thread-filter: {}", c.b_mag(&filters.thread));
        }
        if !filters.api.is_empty() {
            let _ = writeln!(out, "  - api-filter: {}", c.b_yellow(&filters.api));
        }
    }

    out
}

fn render_root(
    out: &mut String,
    root: &FlowFunction,
    index: usize,
    total: usize,
    c: &Colors,
    filters: &RenderFilters,
) {
    let _ = writeln!(
        out,
        "{} {}",
        c.bold(&c.b_yellow(&format!("Root {}/{}:", index, total))),
        format_function_header(root, c)
    );
    render_function_body(out, root, "", c, filters);
}

fn render_function_body(
    out: &mut String,
    func: &FlowFunction,
    prefix: &str,
    c: &Colors,
    filters: &RenderFilters,
) {
    if func.status != "expanded" {
        let _ = writeln!(
            out,
            "{}`-- {}",
            prefix,
            c.dim(&format!("{} [{}]", func.status, func.rva))
        );
        return;
    }

    let visible_edges = func
        .edges
        .iter()
        .filter(|edge| filters.edge_visible(edge))
        .collect::<Vec<_>>();
    let return_count = if func.returns.is_empty() || filters.active() {
        0
    } else {
        1
    };
    let total = visible_edges.len() + return_count;
    if total == 0 {
        let text = if filters.active() {
            "no matching calls recovered"
        } else {
            "no calls recovered"
        };
        let _ = writeln!(out, "{}`-- {}", prefix, c.dim(text));
        return;
    }

    for (idx, edge) in visible_edges.iter().enumerate() {
        let is_last = idx + 1 == total;
        render_edge(out, edge, prefix, is_last, c, filters);
    }

    if return_count > 0 {
        render_return(out, &func.returns, prefix, true, c);
    }
}

fn render_edge(
    out: &mut String,
    edge: &FlowEdge,
    prefix: &str,
    is_last: bool,
    c: &Colors,
    filters: &RenderFilters,
) {
    let branch = if is_last { "`--" } else { "|--" };
    let next_prefix = format!("{}{}", prefix, if is_last { "    " } else { "|   " });
    let mut display_tags = edge.tags.clone();
    if !edge.target_category.is_empty()
        && !display_tags.iter().any(|tag| tag == &edge.target_category)
    {
        display_tags.push(edge.target_category.clone());
    }
    let tags = if display_tags.is_empty() {
        String::new()
    } else {
        format!(" [{}]", display_tags.join(", "))
    };
    let detail = if edge.detail.is_empty() {
        String::new()
    } else {
        format!(" ; {}", edge.detail)
    };
    let target = color_target_name(edge, c);
    let branch = color_branch(branch, edge.thread_lane, &edge.tags, c);

    let _ = writeln!(
        out,
        "{}{} {} {} -> {}{}{}",
        prefix,
        branch,
        c.cyan(&edge.site_rva),
        c.bold(&edge.kind),
        target,
        c.dim(&tags),
        c.dim(&detail)
    );

    if let Some(child) = edge.child.as_ref() {
        if edge.relation == "callee" {
            render_function_body(out, child, &next_prefix, c, filters);
        } else {
            let _ = writeln!(
                out,
                "{}`-- {} -> {}",
                next_prefix,
                c.bold(&edge.relation),
                format_function_header(child, c)
            );
            render_function_body(out, child, &format!("{}    ", next_prefix), c, filters);
        }
    }
}

fn render_return(out: &mut String, returns: &[String], prefix: &str, is_last: bool, c: &Colors) {
    let branch = if is_last { "`--" } else { "|--" };
    let rendered = if returns.len() <= 4 {
        returns.join(", ")
    } else {
        format!(
            "{}, {}, ... ({} sites)",
            returns[0],
            returns[1],
            returns.len()
        )
    };
    let _ = writeln!(
        out,
        "{}{} {} {}",
        prefix,
        branch,
        c.bold("return/program-end"),
        c.dim(&rendered)
    );
}

fn format_function_header(func: &FlowFunction, c: &Colors) -> String {
    let section = if func.section.is_empty() {
        String::new()
    } else {
        format!(" {}", c.dim(&format!("[{}]", func.section)))
    };
    let note = if func.note.is_empty() {
        String::new()
    } else {
        format!(" {}", c.dim(&format!("({})", func.note)))
    };
    let mut meta = Vec::new();
    if !func.symbol_source.is_empty() {
        meta.push(func.symbol_source.clone());
    }
    if !func.symbol_category.is_empty() && func.symbol_category != func.symbol_source {
        meta.push(func.symbol_category.clone());
    }
    if !func.symbol_size.is_empty() {
        meta.push(format!("size {}", func.symbol_size));
    }
    if !func.decode_bound.is_empty() {
        meta.push(format!("bound {}", func.decode_bound));
    }
    if func.thread_lane != 0 {
        meta.push(format!("thread lane {}", func.thread_lane));
    }
    let meta = if meta.is_empty() {
        String::new()
    } else {
        format!(" {}", c.dim(&format!("<{}>", meta.join(", "))))
    };
    let prototype = if func.prototype.is_empty() {
        String::new()
    } else {
        format!(" {}", c.dim(&func.prototype))
    };
    format!(
        "{} {} {}{}{}{}{}",
        color_function_name(
            &func.name,
            &func.symbol_source,
            &func.symbol_category,
            func.thread_lane,
            c,
        ),
        c.dim(&func.rva),
        c.dim(&func.kind),
        section,
        meta,
        prototype,
        note
    )
}

fn color_pdb_status(pdb: &PdbInfo, c: &Colors) -> String {
    if !pdb.enabled {
        c.dim("disabled")
    } else if pdb.loaded {
        c.green("loaded")
    } else {
        c.yellow(&format!("unavailable ({})", pdb.error))
    }
}

fn render_symbol_legend(c: &Colors) -> String {
    [
        c.b_mag("internal-pdb"),
        c.b_cyan("internal-export"),
        c.b_yellow("internal/c++"),
        c.yellow("internal/crt"),
        c.b_red("nt-api"),
        c.cyan("microsoft-api"),
        c.b_yellow("cpp-runtime"),
        c.yellow("crt-runtime"),
        c.green("external-import"),
    ]
    .join("  ")
}

fn color_function_name(
    name: &str,
    source: &str,
    category: &str,
    lane: usize,
    c: &Colors,
) -> String {
    if lane != 0 {
        return lane_color(lane, name, c);
    }
    match category {
        "internal-pdb" => c.b_mag(name),
        "internal-cpp" => c.b_yellow(name),
        "internal-crt" => c.yellow(name),
        "internal-export" => c.b_cyan(name),
        _ if source == "pdb" => c.b_mag(name),
        _ if source == "export" => c.b_cyan(name),
        _ if name.starts_with("sub_") => c.cyan(name),
        _ => c.b_white(name),
    }
}

fn color_target_name(edge: &FlowEdge, c: &Colors) -> String {
    let name = if edge.target_rva != "0x00000000" {
        format!("{} {}", edge.target, edge.target_rva)
    } else {
        edge.target.clone()
    };

    if edge
        .tags
        .iter()
        .any(|tag| tag == "thread-spawn" || tag == "thread-api")
    {
        return c.b_mag(&name);
    }
    if edge.tags.iter().any(|tag| tag == "workpool") {
        return c.magenta(&name);
    }
    match edge.target_category.as_str() {
        "internal-pdb" => return c.b_mag(&name),
        "internal-cpp" | "cpp-runtime" => return c.b_yellow(&name),
        "internal-crt" | "crt-runtime" => return c.yellow(&name),
        "internal-export" => return c.b_cyan(&name),
        "nt-api" => return c.b_red(&name),
        "microsoft-api" => return c.cyan(&name),
        "external-import" => return c.green(&name),
        _ => {}
    }
    if edge.target_source == "pdb" {
        return c.b_mag(&name);
    }
    if edge.target_source == "import" || edge.tags.iter().any(|tag| tag == "import") {
        return c.cyan(&name);
    }
    c.b_white(&name)
}

fn color_branch(branch: &str, lane: usize, tags: &[String], c: &Colors) -> String {
    if tags
        .iter()
        .any(|tag| tag == "thread-spawn" || tag == "thread-api")
    {
        c.b_mag(branch)
    } else if tags.iter().any(|tag| tag == "workpool") {
        c.magenta(branch)
    } else if lane != 0 {
        lane_color(lane, branch, c)
    } else {
        c.dim(branch)
    }
}

fn lane_color(lane: usize, text: &str, c: &Colors) -> String {
    match lane % 5 {
        1 => c.b_mag(text),
        2 => c.b_yellow(text),
        3 => c.b_blue(text),
        4 => c.b_cyan(text),
        _ => c.green(text),
    }
}

fn is_nt_like_name(name: &str) -> bool {
    let tail = name.rsplit(['!', ':']).next().unwrap_or(name);
    tail.starts_with("Nt") || tail.starts_with("Zw") || tail.starts_with("Rtl")
}

fn classify_function_symbol(name: &str, source: &str, meta: Option<&SymbolMeta>) -> String {
    if source == "pdb" {
        let prototype = meta.map(|m| m.prototype.as_str()).unwrap_or_default();
        if is_cpp_symbol(name) || is_cpp_symbol(prototype) {
            "internal-cpp"
        } else if is_crt_symbol_name(name) {
            "internal-crt"
        } else {
            "internal-pdb"
        }
    } else if source == "export" {
        "internal-export"
    } else if source == "symbol" {
        "internal-symbol"
    } else {
        "synthetic"
    }
    .to_owned()
}

fn classify_edge_target(name: &str, source: &str, meta: Option<&SymbolMeta>) -> String {
    if source == "pdb" || source == "export" || source == "symbol" {
        return classify_function_symbol(name, source, meta);
    }
    if source != "import" {
        return source.to_owned();
    }

    let (dll, func) = split_import_name(name);
    if is_nt_like_name(func) {
        "nt-api"
    } else if is_cpp_runtime_symbol(&dll, func) {
        "cpp-runtime"
    } else if is_crt_runtime_symbol(&dll, func) {
        "crt-runtime"
    } else if is_microsoft_dll(&dll) {
        "microsoft-api"
    } else {
        "external-import"
    }
    .to_owned()
}

fn split_import_name(name: &str) -> (String, &str) {
    if let Some((dll, func)) = name.rsplit_once('!') {
        (dll.to_ascii_lowercase(), func)
    } else {
        (String::new(), name)
    }
}

fn is_microsoft_dll(dll: &str) -> bool {
    let dll = dll.trim_start_matches("api-ms-");
    dll.starts_with("win-")
        || dll.starts_with("ext-ms-")
        || matches!(
            dll,
            "ntdll.dll"
                | "kernel32.dll"
                | "kernelbase.dll"
                | "user32.dll"
                | "gdi32.dll"
                | "advapi32.dll"
                | "sechost.dll"
                | "rpcrt4.dll"
                | "shell32.dll"
                | "ole32.dll"
                | "oleaut32.dll"
                | "combase.dll"
                | "ws2_32.dll"
                | "bcrypt.dll"
                | "crypt32.dll"
                | "wintrust.dll"
                | "winhttp.dll"
                | "wininet.dll"
                | "urlmon.dll"
                | "shlwapi.dll"
                | "version.dll"
                | "dbghelp.dll"
                | "psapi.dll"
                | "iphlpapi.dll"
                | "dnsapi.dll"
                | "netapi32.dll"
                | "wtsapi32.dll"
                | "mswsock.dll"
                | "imm32.dll"
                | "setupapi.dll"
                | "cfgmgr32.dll"
                | "powrprof.dll"
                | "mpr.dll"
                | "userenv.dll"
                | "dwmapi.dll"
                | "uxtheme.dll"
                | "propsys.dll"
                | "profapi.dll"
                | "normaliz.dll"
        )
}

fn is_crt_runtime_symbol(dll: &str, name: &str) -> bool {
    dll.contains("ucrt")
        || dll.contains("msvcrt")
        || dll.contains("vcruntime")
        || dll.contains("api-ms-win-crt")
        || is_crt_symbol_name(name)
}

fn is_cpp_runtime_symbol(dll: &str, name: &str) -> bool {
    dll.contains("msvcp")
        || name.contains("Cxx")
        || name.contains("CXX")
        || name.contains("C++")
        || name.contains("std::")
        || name.starts_with("??")
        || name.starts_with("?")
        || name.contains("operator ")
        || name.contains("__std_")
}

fn is_cpp_symbol(text: &str) -> bool {
    text.contains("::")
        || text.starts_with("??")
        || text.starts_with("?")
        || text.contains("operator ")
        || text.contains("class ")
        || text.contains("struct ")
        || text.contains("std::")
        || text.contains("ATL::")
        || text.contains("wil::")
        || text.contains("Microsoft::")
}

fn is_crt_symbol_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("__scrt")
        || lower.starts_with("__crt")
        || lower.starts_with("_crt")
        || lower.starts_with("_initterm")
        || lower.starts_with("_seh")
        || lower.starts_with("_except")
        || lower.starts_with("_cxx")
        || lower.contains("security_cookie")
        || matches!(
            lower.as_str(),
            "memcpy"
                | "memmove"
                | "memset"
                | "memcmp"
                | "malloc"
                | "free"
                | "calloc"
                | "realloc"
                | "strlen"
                | "strnlen"
                | "strcmp"
                | "strncmp"
                | "stricmp"
                | "_stricmp"
                | "_strnicmp"
                | "strcpy"
                | "strncpy"
                | "strchr"
                | "strrchr"
                | "strstr"
                | "wcslen"
                | "wcscmp"
                | "_wcsicmp"
                | "_wcsnicmp"
                | "wcscpy"
                | "wcschr"
                | "wcsrchr"
                | "wcsstr"
                | "atexit"
                | "exit"
                | "abort"
                | "terminate"
        )
}

fn build_pdb_function_index(symbols: &[PdbSymbol]) -> HashMap<u32, PdbFunction> {
    let mut out = HashMap::new();
    for sym in symbols {
        if sym.kind != "function" || sym.rva == 0 {
            continue;
        }
        let replace = out
            .get(&sym.rva)
            .map(|old: &PdbFunction| old.size == 0 && sym.size > 0)
            .unwrap_or(true);
        if replace {
            out.insert(
                sym.rva,
                PdbFunction {
                    size: sym.size,
                    type_name: sym.type_name.clone(),
                },
            );
        }
    }
    out
}

fn callback_spec(name: &str) -> Option<CallbackSpec> {
    let name = normalize_api_name(name);
    let spec = match name.as_str() {
        "createthread" | "beginthreadex" | "_beginthreadex" => CallbackSpec {
            relation: "thread-start",
            tag: "thread-spawn",
            arg_index: 3,
        },
        "beginthread" | "_beginthread" => CallbackSpec {
            relation: "thread-start",
            tag: "thread-spawn",
            arg_index: 1,
        },
        "createremotethread" => CallbackSpec {
            relation: "thread-start",
            tag: "thread-spawn",
            arg_index: 4,
        },
        "queueuserworkitem"
        | "rtlqueueworkitem"
        | "createthreadpoolwork"
        | "trysubmitthreadpoolcallback"
        | "createthreadpooltimer"
        | "createthreadpoolwait" => CallbackSpec {
            relation: "work-callback",
            tag: "workpool",
            arg_index: 1,
        },
        "tpallocwork" | "tpalloctimer" | "tpallocwait" => CallbackSpec {
            relation: "work-callback",
            tag: "workpool",
            arg_index: 2,
        },
        "registerwaitforsingleobject" => CallbackSpec {
            relation: "work-callback",
            tag: "workpool",
            arg_index: 3,
        },
        _ => return None,
    };
    Some(spec)
}

fn thread_api_intent(name: &str) -> Option<&'static str> {
    match normalize_api_name(name).as_str() {
        "switchtothread" | "ntyieldexecution" | "zwyieldexecution" => Some("thread-yield"),
        "openthread" | "ntopenthread" | "zwopenthread" => Some("thread-open"),
        "getthreadcontext"
        | "wow64getthreadcontext"
        | "ntgetcontextthread"
        | "zwgetcontextthread" => Some("thread-context-read"),
        "setthreadcontext"
        | "wow64setthreadcontext"
        | "ntsetcontextthread"
        | "zwsetcontextthread" => Some("thread-context-write"),
        "suspendthread" | "ntsuspendthread" | "zwsuspendthread" => Some("thread-suspend"),
        "resumethread" | "ntresumethread" | "zwresumethread" => Some("thread-resume"),
        "queuethreadapc" | "ntqueueapcthread" | "zwqueueapcthread" => Some("thread-apc"),
        "getthreadid" | "getcurrentthreadid" | "teb" => Some("thread-id"),
        "getcurrentthread" | "duplicatehandle" => Some("thread-handle"),
        _ => None,
    }
}

fn describe_thread_intent(
    call: &ApiCall,
    insns: &[Instruction],
    pe: &PeFile,
    raw: &[u8],
) -> Option<String> {
    let intent = thread_api_intent(&call.label)?;
    let name = normalize_api_name(&call.label);
    let mut detail = format!("thread intent: {}", intent);

    if matches!(
        name.as_str(),
        "switchtothread" | "ntyieldexecution" | "zwyieldexecution"
    ) {
        detail.push_str(" (current thread yields; no target thread handle)");
        return Some(detail);
    }

    let interesting_arg = match name.as_str() {
        "openthread" | "ntopenthread" | "zwopenthread" => Some(3),
        "getthreadcontext"
        | "wow64getthreadcontext"
        | "ntgetcontextthread"
        | "zwgetcontextthread"
        | "setthreadcontext"
        | "wow64setthreadcontext"
        | "ntsetcontextthread"
        | "zwsetcontextthread"
        | "suspendthread"
        | "ntsuspendthread"
        | "zwsuspendthread"
        | "resumethread"
        | "ntresumethread"
        | "zwresumethread"
        | "queuethreadapc"
        | "ntqueueapcthread"
        | "zwqueueapcthread" => Some(1),
        _ => None,
    };

    if let Some(arg) = interesting_arg {
        if let Some(value) = recover_immediate_arg(insns, call.rva, arg, pe, raw) {
            detail.push_str(&format!("; arg{}=0x{:X}", arg, value));
        } else {
            detail.push_str(&format!("; arg{} unresolved", arg));
        }
    }
    Some(detail)
}

fn recover_immediate_arg(
    insns: &[Instruction],
    call_rva: u32,
    arg_index: usize,
    pe: &PeFile,
    raw: &[u8],
) -> Option<u64> {
    let call_idx = insns.iter().position(|insn| insn.rva == call_rva)?;
    if pe.arch == 64 {
        let reg = x64_arg_register(arg_index)?;
        return resolve_immediate_register_before(insns, call_idx, reg, pe, raw, 0);
    }
    recover_x86_stack_immediate_arg(insns, call_idx, arg_index, pe, raw)
}

fn recover_x86_stack_immediate_arg(
    insns: &[Instruction],
    call_idx: usize,
    arg_index: usize,
    pe: &PeFile,
    raw: &[u8],
) -> Option<u64> {
    let mut seen_args = 0usize;
    for (idx, insn) in insns[..call_idx].iter().enumerate().rev().take(48) {
        if insn.iced.mnemonic() != Mnemonic::Push || insn.iced.op_count() == 0 {
            continue;
        }
        seen_args += 1;
        if seen_args != arg_index {
            continue;
        }
        if let Some(value) = immediate_operand_value(&insn.iced, 0) {
            return Some(value);
        }
        if insn.iced.op0_kind() == OpKind::Register {
            return resolve_immediate_register_before(
                insns,
                idx,
                insn.iced.op0_register().full_register(),
                pe,
                raw,
                0,
            );
        }
        break;
    }
    None
}

fn recover_callback_target(
    insns: &[Instruction],
    call_rva: u32,
    arg_index: usize,
    pe: &PeFile,
    raw: &[u8],
) -> Option<(u32, String)> {
    let call_idx = insns.iter().position(|insn| insn.rva == call_rva)?;
    if pe.arch == 64 {
        let reg = x64_arg_register(arg_index)?;
        return resolve_register_before(insns, call_idx, reg, pe, raw, 0)
            .map(|(rva, method)| (rva, format!("{} {}", register_name(reg), method)));
    }

    resolve_x86_stack_arg(insns, call_idx, arg_index, pe, raw)
}

fn resolve_x86_stack_arg(
    insns: &[Instruction],
    call_idx: usize,
    arg_index: usize,
    pe: &PeFile,
    raw: &[u8],
) -> Option<(u32, String)> {
    let mut seen_args = 0usize;
    for (idx, insn) in insns[..call_idx].iter().enumerate().rev().take(48) {
        if insn.iced.mnemonic() != Mnemonic::Push || insn.iced.op_count() == 0 {
            continue;
        }
        seen_args += 1;
        if seen_args != arg_index {
            continue;
        }
        if let Some(rva) = code_target_from_operand(&insn.iced, 0, pe, raw, false) {
            return Some((rva, "stack push immediate".to_owned()));
        }
        if insn.iced.op0_kind() == OpKind::Register {
            let reg = insn.iced.op0_register().full_register();
            return resolve_register_before(insns, idx, reg, pe, raw, 0).map(|(rva, method)| {
                (rva, format!("stack push {} {}", register_name(reg), method))
            });
        }
        break;
    }
    None
}

fn resolve_register_before(
    insns: &[Instruction],
    before_idx: usize,
    reg: Register,
    pe: &PeFile,
    raw: &[u8],
    depth: usize,
) -> Option<(u32, String)> {
    if depth > 6 {
        return None;
    }
    let wanted = reg.full_register();
    let scan_start = before_idx.saturating_sub(64);

    for (idx, insn) in insns[scan_start..before_idx].iter().enumerate().rev() {
        let absolute_idx = scan_start + idx;
        let iced = &insn.iced;
        if iced.op_count() == 0 || iced.op0_kind() != OpKind::Register {
            continue;
        }
        let dst = iced.op0_register().full_register();
        if dst != wanted {
            continue;
        }

        match iced.mnemonic() {
            Mnemonic::Lea | Mnemonic::Mov => {
                if iced.op1_kind() == OpKind::Register {
                    let src = iced.op1_register().full_register();
                    return resolve_register_before(insns, absolute_idx, src, pe, raw, depth + 1)
                        .map(|(rva, method)| {
                            (rva, format!("<- {} {}", register_name(src), method))
                        });
                }

                let deref_memory = iced.mnemonic() == Mnemonic::Mov;
                if let Some(rva) = code_target_from_operand(iced, 1, pe, raw, deref_memory) {
                    let method = if iced.mnemonic() == Mnemonic::Lea {
                        "loaded address".to_owned()
                    } else if deref_memory && iced.op1_kind() == OpKind::Memory {
                        "loaded function pointer".to_owned()
                    } else {
                        "loaded immediate".to_owned()
                    };
                    return Some((rva, method));
                }
                return None;
            }
            Mnemonic::Xor
                if iced.op1_kind() == OpKind::Register
                    && iced.op1_register().full_register() == wanted =>
            {
                return None;
            }
            _ => return None,
        }
    }

    None
}

fn resolve_immediate_register_before(
    insns: &[Instruction],
    before_idx: usize,
    reg: Register,
    pe: &PeFile,
    raw: &[u8],
    depth: usize,
) -> Option<u64> {
    if depth > 6 {
        return None;
    }
    let wanted = reg.full_register();
    let scan_start = before_idx.saturating_sub(64);

    for (idx, insn) in insns[scan_start..before_idx].iter().enumerate().rev() {
        let absolute_idx = scan_start + idx;
        let iced = &insn.iced;
        if iced.op_count() == 0 || iced.op0_kind() != OpKind::Register {
            continue;
        }
        if iced.op0_register().full_register() != wanted {
            continue;
        }

        match iced.mnemonic() {
            Mnemonic::Mov | Mnemonic::Lea => {
                if let Some(value) = immediate_operand_value(iced, 1) {
                    return Some(value);
                }
                if iced.op1_kind() == OpKind::Register {
                    return resolve_immediate_register_before(
                        insns,
                        absolute_idx,
                        iced.op1_register().full_register(),
                        pe,
                        raw,
                        depth + 1,
                    );
                }
                if iced.op1_kind() == OpKind::Memory {
                    let addr = memory_address(iced)?;
                    if let Some(value) = read_pointer_value(pe, raw, addr) {
                        return Some(value);
                    }
                }
                return None;
            }
            Mnemonic::Xor
                if iced.op1_kind() == OpKind::Register
                    && iced.op1_register().full_register() == wanted =>
            {
                return Some(0);
            }
            _ => return None,
        }
    }

    None
}

fn code_target_from_operand(
    instr: &iced_x86::Instruction,
    op_index: u32,
    pe: &PeFile,
    raw: &[u8],
    deref_memory: bool,
) -> Option<u32> {
    let kind = instr.op_kind(op_index);
    match kind {
        OpKind::Immediate8 => code_rva_from_value(pe, instr.immediate8() as u64),
        OpKind::Immediate16 => code_rva_from_value(pe, instr.immediate16() as u64),
        OpKind::Immediate32 | OpKind::Immediate32to64 => {
            code_rva_from_value(pe, instr.immediate32() as u64)
        }
        OpKind::Immediate64 => code_rva_from_value(pe, instr.immediate64()),
        OpKind::Memory => {
            let addr = memory_address(instr)?;
            if deref_memory {
                read_pointer_target(pe, raw, addr)
            } else {
                code_rva_from_value(pe, addr)
            }
        }
        _ => None,
    }
}

fn immediate_operand_value(instr: &iced_x86::Instruction, op_index: u32) -> Option<u64> {
    match instr.op_kind(op_index) {
        OpKind::Immediate8 => Some(instr.immediate8() as u64),
        OpKind::Immediate16 => Some(instr.immediate16() as u64),
        OpKind::Immediate32 | OpKind::Immediate32to64 => Some(instr.immediate32() as u64),
        OpKind::Immediate64 => Some(instr.immediate64()),
        _ => None,
    }
}

fn memory_address(instr: &iced_x86::Instruction) -> Option<u64> {
    if matches!(instr.memory_base(), Register::RIP | Register::EIP) {
        Some(instr.ip_rel_memory_address())
    } else if instr.memory_base() == Register::None && instr.memory_index() == Register::None {
        let value = instr.memory_displacement64();
        (value != 0).then_some(value)
    } else {
        None
    }
}

fn read_pointer_target(pe: &PeFile, raw: &[u8], address: u64) -> Option<u32> {
    let slot_rva = pe
        .va_to_rva(address)
        .or_else(|| code_rva_from_value(pe, address))?;
    let off = pe.rva_to_offset(slot_rva)?;
    let value = read_pointer_value_at_offset(pe, raw, off);
    code_rva_from_value(pe, value)
}

fn read_pointer_value(pe: &PeFile, raw: &[u8], address: u64) -> Option<u64> {
    let slot_rva = pe.va_to_rva(address).or_else(|| {
        u32::try_from(address)
            .ok()
            .filter(|rva| pe.rva_to_section(*rva).is_some())
    })?;
    let off = pe.rva_to_offset(slot_rva)?;
    Some(read_pointer_value_at_offset(pe, raw, off))
}

fn read_pointer_value_at_offset(pe: &PeFile, raw: &[u8], off: usize) -> u64 {
    if pe.arch == 64 {
        read_u64(raw, off)
    } else {
        read_u32(raw, off) as u64
    }
}

fn code_rva_from_value(pe: &PeFile, value: u64) -> Option<u32> {
    pe.va_to_rva(value)
        .or_else(|| {
            u32::try_from(value)
                .ok()
                .filter(|rva| pe.rva_to_section(*rva).is_some())
        })
        .filter(|rva| is_executable_rva(pe, *rva))
}

fn executable_target_rva(pe: &PeFile, rva: u32) -> Option<u32> {
    (rva != 0 && is_executable_rva(pe, rva)).then_some(rva)
}

fn is_executable_rva(pe: &PeFile, rva: u32) -> bool {
    pe.rva_to_section(rva)
        .is_some_and(|section| section.is_executable())
}

fn x64_arg_register(arg_index: usize) -> Option<Register> {
    match arg_index {
        1 => Some(Register::RCX),
        2 => Some(Register::RDX),
        3 => Some(Register::R8),
        4 => Some(Register::R9),
        _ => None,
    }
}

fn relation_title(relation: &str) -> String {
    match relation {
        "thread-start" => "Thread Start".to_owned(),
        "work-callback" => "Workpool Callback".to_owned(),
        _ => "Callback".to_owned(),
    }
}

fn root_name(root: &PeStartupRoutine, symbol_index: &SymbolIndex, image_base: u64) -> String {
    let name = best_symbol_name(symbol_index, image_base, root.rva);
    if name.starts_with("sub_") {
        format!("{} {}", root.kind, name)
    } else {
        name
    }
}

fn best_symbol_name(symbol_index: &SymbolIndex, image_base: u64, rva: u32) -> String {
    let va = image_base + rva as u64;
    if let Some(hit) = symbol_index.lookup(va) {
        if hit.displacement == 0 {
            return hit.symbol.name;
        }
        if hit.displacement <= 0x20 {
            return format!("{}+0x{:X}", hit.symbol.name, hit.displacement);
        }
    }
    format!("sub_{:08X}", rva)
}

fn call_target_name(call: &ApiCall) -> String {
    if call.dll.is_empty() {
        call.label.clone()
    } else {
        format!("{}!{}", call.dll, call.label)
    }
}

fn join_detail(parts: &[String]) -> String {
    parts
        .iter()
        .filter(|part| !part.trim().is_empty())
        .cloned()
        .collect::<Vec<_>>()
        .join("; ")
}

fn normalize_api_name(name: &str) -> String {
    name.rsplit(['!', ':'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('_')
        .trim_end_matches(['A', 'W'])
        .to_ascii_lowercase()
}

fn is_terminator_api(name: &str) -> bool {
    matches!(
        normalize_api_name(name).as_str(),
        "exitprocess"
            | "rtlexituserprocess"
            | "terminateprocess"
            | "ntterminateprocess"
            | "zwterminateprocess"
            | "exitthread"
            | "rtlexituserthread"
            | "ntterminatethread"
            | "zwterminatethread"
            | "terminatethread"
            | "exit"
            | "quick_exit"
            | "abort"
    )
}

fn register_name(reg: Register) -> &'static str {
    match reg.full_register() {
        Register::RAX => "rax",
        Register::RBX => "rbx",
        Register::RCX => "rcx",
        Register::RDX => "rdx",
        Register::RSI => "rsi",
        Register::RDI => "rdi",
        Register::R8 => "r8",
        Register::R9 => "r9",
        Register::R10 => "r10",
        Register::R11 => "r11",
        Register::R12 => "r12",
        Register::R13 => "r13",
        Register::R14 => "r14",
        Register::R15 => "r15",
        Register::EAX => "eax",
        Register::EBX => "ebx",
        Register::ECX => "ecx",
        Register::EDX => "edx",
        _ => "reg",
    }
}

fn hex32(value: u32) -> String {
    format!("0x{:08X}", value)
}

fn hex64(value: u64) -> String {
    format!("0x{:016X}", value)
}

#[cfg(test)]
mod tests {
    use super::{
        callback_spec, classify_edge_target, classify_function_symbol, normalize_api_name,
        thread_api_intent,
    };

    #[test]
    fn callback_specs_cover_thread_and_pool_apis() {
        let create_thread = callback_spec("KERNEL32.dll!CreateThread").unwrap();
        assert_eq!(create_thread.relation, "thread-start");
        assert_eq!(create_thread.arg_index, 3);

        let work = callback_spec("CreateThreadpoolWork").unwrap();
        assert_eq!(work.relation, "work-callback");
        assert_eq!(work.arg_index, 1);
    }

    #[test]
    fn normalize_api_name_strips_scope_and_ansi_suffix() {
        assert_eq!(normalize_api_name("KERNEL32!CreateThread"), "createthread");
        assert_eq!(normalize_api_name("USER32!MessageBoxW"), "messagebox");
    }

    #[test]
    fn thread_api_intents_cover_context_and_yield_calls() {
        assert_eq!(thread_api_intent("SwitchToThread"), Some("thread-yield"));
        assert_eq!(
            thread_api_intent("ntdll!NtGetContextThread"),
            Some("thread-context-read")
        );
        assert_eq!(
            thread_api_intent("kernel32!OpenThread"),
            Some("thread-open")
        );
    }

    #[test]
    fn symbol_categories_split_internal_and_runtime_targets() {
        assert_eq!(
            classify_function_symbol("RealFunction", "pdb", None),
            "internal-pdb"
        );
        assert_eq!(
            classify_function_symbol("?Run@@YAXXZ", "pdb", None),
            "internal-cpp"
        );
        assert_eq!(
            classify_function_symbol("_initterm", "pdb", None),
            "internal-crt"
        );
        assert_eq!(
            classify_function_symbol("DllMain", "export", None),
            "internal-export"
        );
        assert_eq!(
            classify_edge_target("ntdll.dll!NtOpenProcess", "import", None),
            "nt-api"
        );
        assert_eq!(
            classify_edge_target("kernel32.dll!CreateFileW", "import", None),
            "microsoft-api"
        );
        assert_eq!(
            classify_edge_target("ucrtbase.dll!malloc", "import", None),
            "crt-runtime"
        );
        assert_eq!(
            classify_edge_target("ntdll.dll!wcsrchr", "import", None),
            "crt-runtime"
        );
        assert_eq!(
            classify_edge_target("msvcp140.dll!?_Xlength_error@std@@YAXXZ", "import", None),
            "cpp-runtime"
        );
        assert_eq!(
            classify_edge_target("plugin.dll!Run", "import", None),
            "external-import"
        );
    }
}
