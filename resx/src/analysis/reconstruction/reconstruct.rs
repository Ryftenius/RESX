mod recovery;
mod render;

use recovery::*;
pub use render::render_ascii;
use render::{classify_edge_target, classify_function_symbol, SymbolMeta};

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

#[cfg(test)]
mod tests {
    use super::render::color_function_kind;
    use super::{
        callback_spec, classify_edge_target, classify_function_symbol, normalize_api_name,
        thread_api_intent,
    };
    use crate::core::color::Colors;

    #[test]
    fn tls_callback_kind_is_bright_red_only_when_color_is_enabled() {
        let colored = color_function_kind("TLS Callback", &Colors::new(true));
        assert!(colored.contains("\x1b[91mTLS Callback"));
        assert_eq!(
            color_function_kind("TLS Callback", &Colors::new(false)),
            "TLS Callback"
        );
        assert!(!color_function_kind("PE Entry Point", &Colors::new(true)).contains("\x1b[91m"));
    }

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
