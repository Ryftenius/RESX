use iced_x86::{Mnemonic, OpKind, Register};
use std::fmt::Write as _;
use std::io::Write;

use crate::analysis::disasm::{
    apply_dynamic_resolution, collect_api_calls_in, disassemble_at, ApiCall, Instruction,
};
use crate::analysis::{image::ImageFacts, session::AnalysisSession, symbols::SymbolIndex};
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::search::find_dll_path;
use crate::formats::pdb::{load_pdb_symbol, load_pdb_symbols};
use crate::formats::pe::{parse_pe, read_exports, Export};

use super::style::{color_kind, color_target, is_nt_api, short_dll_name};
use super::switchfmt::{format_case_values, format_class_value};
use super::{RecoveredSwitchDispatch, RecoveredSwitchTarget};

const NT_KERNEL_IMAGES: &[&str] = &[
    "ntoskrnl.exe",
    "ntkrnlmp.exe",
    "ntkrnlpa.exe",
    "ntkrpamp.exe",
];
const WIN32K_KERNEL_IMAGES: &[&str] = &["win32kbase.sys", "win32kfull.sys", "win32k.sys"];
const NO_KERNEL_IMAGES: &[&str] = &[];

pub(super) struct ApiCallTree {
    roots: Vec<CallNode>,
    unbuilt: usize,
    total: usize,
    filter: Option<CallFilter>,
    /// Functions left unexpanded because `--max-total` was reached.
    budget_skipped: usize,
}

impl ApiCallTree {
    /// True when a root-level call survived the call-tree filter.
    pub(super) fn keeps_root(&self, call: &ApiCall) -> bool {
        self.filter.is_none()
            || self.roots.iter().any(|node| {
                node.call.rva == call.rva
                    && node.call.target_rva == call.target_rva
                    && node.call.label == call.label
            })
    }
}

struct CallNode {
    signature: Option<crate::analysis::headers::CallSignature>,
    call: ApiCall,
    location: String,
    kernel: Option<KernelCallTarget>,
    children: Vec<CallNode>,
    /// Calls past `--max-subcalls` that were never traced (unfiltered trees only).
    unbuilt: usize,
    /// A filtered repeat of a callee whose expansion is shown earlier in the tree.
    expanded_above: bool,
}

struct KernelCallTarget {
    image: String,
    symbol: String,
    classes: Vec<u32>,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn build_api_call_tree(
    calls: &[ApiCall],
    insns: &[Instruction],
    func_name: &str,
    source_image_name: &str,
    session: &AnalysisSession<'_>,
    headers: Option<&crate::analysis::headers::HeaderIndex>,
    symbol_index: &crate::analysis::symbols::SymbolIndex,
    arch: u32,
    image_base: u64,
    cfg: &Config,
    root_rva: u32,
) -> ApiCallTree {
    let display_calls: Vec<ApiCall> =
        if let Some(call) = synthetic_syscall_call(insns, func_name, source_image_name) {
            let mut merged = calls.to_vec();
            if !merged.iter().any(|existing| {
                existing.rva == call.rva && existing.label.eq_ignore_ascii_case(&call.label)
            }) {
                merged.push(call);
            }
            merged.sort_by_key(|call| call.rva);
            merged
        } else {
            calls.to_vec()
        };

    let filter = CallFilter::parse(&cfg.funcs_filter);
    let root_image = TraceImageView {
        analysis: session.image(),
        symbol_index,
        exports: session.image().exports(),
        arch,
        image_base,
        dynamic: Some(session.resolution()),
    };
    let mut sub_cfg = cfg.clone();
    sub_cfg.max_insns = sub_cfg.max_insns.min(300);
    let mut builder = TreeBuilder {
        headers,
        exports: session.exports(),
        cfg,
        sub_cfg,
        filter: filter.as_ref(),
        visited: std::collections::HashSet::from([(root_image.key(), root_rva)]),
        expanded: std::collections::HashMap::new(),
        expansions: 0,
        expansion_limit: expansion_limit(cfg.max_total),
        budget_skipped: 0,
    };
    let (roots, unbuilt) = builder.build_level(&display_calls, insns, &root_image, 0);
    let budget_skipped = builder.budget_skipped;
    ApiCallTree {
        roots,
        unbuilt,
        total: display_calls.len(),
        filter,
        budget_skipped,
    }
}

/// The calls a function renders when it has more than `cap`, in address order: system
/// calls first, then other imports, internal calls, and runtime helpers last. A large
/// function's first call sites are often helpers; its transitions should not be cut.
fn select_within_cap(calls: &[ApiCall], cap: usize) -> Vec<ApiCall> {
    if calls.len() <= cap {
        return calls.to_vec();
    }
    let rank = |call: &ApiCall| -> u8 {
        let name = call.label.rsplit('!').next().unwrap_or(&call.label);
        if call.is_import && is_nt_api(name) {
            0
        } else if is_runtime_helper(name) {
            3
        } else if call.is_import || call.dynamic.is_some() {
            1
        } else {
            2
        }
    };
    let mut order: Vec<usize> = (0..calls.len()).collect();
    order.sort_by_key(|&i| (rank(&calls[i]), calls[i].rva));
    order.truncate(cap);
    order.sort_unstable();
    order.into_iter().map(|i| calls[i].clone()).collect()
}

fn is_runtime_helper(name: &str) -> bool {
    const HELPERS: &[&str] = &[
        "memset",
        "memcpy",
        "memmove",
        "memcmp",
        "__chkstk",
        "_security_check_cookie",
        "_report_gsfailure",
        "guard_dispatch_icall",
        "_guard_dispatch_icall_nop",
    ];
    HELPERS.iter().any(|h| name.eq_ignore_ascii_case(h))
        || name.starts_with("Feature_")
        || name.starts_with("wil_")
}

/// Functions a call map may expand. `--max-total unlimited` (0) keeps a safety bound.
fn expansion_limit(max_total: usize) -> usize {
    if max_total == 0 {
        65_536
    } else {
        max_total
    }
}

/// Decode a traced function: the whole reachable body when its extent is known,
/// otherwise the bounded linear listing from `cfg`.
fn decode_traced_function(
    image: &TraceImageView<'_>,
    file_off: usize,
    rva: u32,
    cfg: &Config,
) -> Option<Vec<Instruction>> {
    let options: crate::analysis::options::TraversalOptions = cfg.into();
    if let Some(insns) = crate::analysis::inspection::decode_reachable_function(
        image.analysis.raw(),
        image.analysis.pe(),
        rva,
        image.arch,
        image.image_base,
        image.exports,
        Some(image.symbol_index),
        &options,
    ) {
        return Some(insns);
    }
    disassemble_at(
        image.analysis.raw(),
        image.analysis.pe(),
        file_off,
        rva,
        image.arch,
        image.image_base,
        image.exports,
        Some(image.symbol_index),
        cfg,
    )
    .ok()
}

pub(super) fn print_api_calls(
    w: &mut dyn Write,
    tree: &ApiCallTree,
    func_name: &str,
    c: &Colors,
    cfg: &Config,
) {
    writeln!(w).ok();
    let header = match &tree.filter {
        Some(filter) => format!(
            "API Call Map for {}  [{} of {} call site(s) · filter: {}]:",
            func_name,
            tree.roots.len(),
            tree.total,
            filter.spec()
        ),
        None => format!(
            "API Call Map for {}  [{} call site(s)]:",
            func_name, tree.total
        ),
    };
    writeln!(w, "{}", c.bold(&c.b_cyan(&header))).ok();

    if tree.total == 0 {
        writeln!(w, "{}", c.dim("  (no CALL/JMP targets found)")).ok();
        return;
    }
    if tree.roots.is_empty() {
        let spec = tree
            .filter
            .as_ref()
            .map(CallFilter::spec)
            .unwrap_or_default();
        writeln!(
            w,
            "{}",
            c.dim(&format!("  (no calls match the call-tree filter {spec})"))
        )
        .ok();
        return;
    }

    let mut dll_map = std::collections::HashMap::new();
    print_call_nodes(w, &tree.roots, tree.unbuilt, c, cfg, &mut dll_map, "  ");
    if tree.budget_skipped > 0 {
        writeln!(w, "  {}", c.warning(&budget_note(tree.budget_skipped))).ok();
    }
}

fn budget_note(skipped: usize) -> String {
    format!(
        "{skipped} call(s) not expanded: the --max-total budget of traced functions was reached; raise --max-total"
    )
}

pub(super) fn render_api_call_tree(tree: &ApiCallTree, cfg: &Config) -> String {
    let mut out = String::new();
    write_call_nodes_text(&mut out, &tree.roots, tree.unbuilt, cfg, "  ");
    if tree.budget_skipped > 0 {
        let _ = writeln!(out, "  {}", budget_note(tree.budget_skipped));
    }
    out
}

#[derive(Clone)]
pub(super) struct SyscallCallDetails {
    pub kernel_module: String,
    pub kernel_symbol: String,
    pub kernel_rva: u32,
    pub service_number: Option<u32>,
}

fn synthetic_syscall_call(
    insns: &[Instruction],
    func_name: &str,
    source_image_name: &str,
) -> Option<ApiCall> {
    if !is_nt_api(func_name) {
        return None;
    }

    let syscall_site = insns.iter().find(|insn| {
        matches!(insn.iced.mnemonic(), Mnemonic::Syscall | Mnemonic::Sysenter)
            || (insn.iced.mnemonic() == Mnemonic::Int && insn.iced.immediate8() == 0x2E)
    })?;

    Some(ApiCall {
        rva: syscall_site.rva,
        kind: "syscall".to_owned(),
        target_rva: 0,
        label: func_name.to_owned(),
        dll: syscall_stub_provider(func_name, source_image_name).to_owned(),
        is_import: true,
        is_indirect: false,
        indirect_method: None,
        switch_cases: Vec::new(),
        dynamic: None,
        resolves: None,
    })
}

pub(super) fn synthetic_syscall_api_call(
    insns: &[Instruction],
    func_name: &str,
    source_image_name: &str,
) -> Option<ApiCall> {
    synthetic_syscall_call(insns, func_name, source_image_name)
}

fn detect_syscall_number_from_insns(insns: &[Instruction]) -> Option<u32> {
    for insn in insns.iter().take(12) {
        match insn.iced.mnemonic() {
            Mnemonic::Mov
                if insn.iced.op_count() >= 2 && insn.iced.op0_kind() == OpKind::Register =>
            {
                let dst = insn.iced.op0_register();
                if matches!(
                    dst,
                    Register::EAX | Register::RAX | Register::AX | Register::AL
                ) {
                    return match insn.iced.op1_kind() {
                        OpKind::Immediate8 => Some(insn.iced.immediate8to32() as u32),
                        OpKind::Immediate16 => Some(insn.iced.immediate16() as u32),
                        OpKind::Immediate32 => Some(insn.iced.immediate32()),
                        OpKind::Immediate32to64 => Some(insn.iced.immediate32to64() as u32),
                        OpKind::Immediate64 => Some(insn.iced.immediate64() as u32),
                        _ => None,
                    };
                }
            }
            Mnemonic::Ret => break,
            _ => {}
        }
    }
    None
}

pub(super) fn resolve_syscall_call_details(
    call: &ApiCall,
    insns: &[Instruction],
    cfg: &Config,
) -> Option<SyscallCallDetails> {
    let target = resolve_syscall_trace_target(call, insns, cfg)?;
    let service_number = if call.kind.eq_ignore_ascii_case("syscall") {
        detect_syscall_number_from_insns(insns)
    } else {
        None
    };
    Some(SyscallCallDetails {
        kernel_module: target.image.dll_name.clone(),
        kernel_symbol: target.symbol_name,
        kernel_rva: target.rva,
        service_number,
    })
}

struct TraceImageView<'a> {
    analysis: &'a ImageFacts<'a>,
    symbol_index: &'a crate::analysis::symbols::SymbolIndex,
    exports: &'a [Export],
    arch: u32,
    image_base: u64,
    /// Dynamic API resolution for the image being dumped; kernel images reached
    /// through a syscall are not analyzed for it.
    dynamic: Option<&'a crate::analysis::resolution::ResolutionReport>,
}

impl TraceImageView<'_> {
    /// Identity of the traced image, so equal RVAs in different images stay distinct.
    fn key(&self) -> usize {
        self.analysis.raw().as_ptr() as usize
    }
}

fn call_location(call: &ApiCall, image: &TraceImageView<'_>, cfg: &Config) -> String {
    if !cfg.show_rva && !cfg.show_offsets {
        return format!("0x{:X}", call.rva);
    }

    let mut parts = Vec::with_capacity(2);
    if cfg.show_rva {
        parts.push(format!("RVA 0x{:08X}", call.rva));
    }
    if cfg.show_offsets {
        if let Some(offset) = image.analysis.pe().rva_to_offset(call.rva) {
            parts.push(format!("off 0x{offset:X}"));
        } else {
            parts.push("off ?".to_owned());
        }
    }
    parts.join(" ")
}

fn plain_call_target(call: &ApiCall) -> String {
    if call.dll.is_empty() {
        call.label.clone()
    } else {
        format!("{}!{}", short_dll_name(&call.dll), call.label)
    }
}

fn is_highlighted(call: &ApiCall, cfg: &Config) -> bool {
    let needle = cfg.highlight.trim();
    !needle.is_empty()
        && call
            .label
            .to_ascii_lowercase()
            .contains(&needle.to_ascii_lowercase())
}

struct LoadedTraceImage {
    dll_name: String,
    dll_path: String,
    raw: Vec<u8>,
    pe: crate::formats::pe::PeFile,
    exports: Vec<Export>,
    symbol_index: crate::analysis::symbols::SymbolIndex,
    /// Lowercase export and PDB names to (RVA, display name).
    by_name: std::collections::HashMap<String, (u32, String)>,
    /// Whether PDB symbols were loaded, so internal routines have names.
    pdb_loaded: bool,
    arch: u32,
    image_base: u64,
}

impl LoadedTraceImage {
    fn as_view<'a>(&'a self, analysis: &'a ImageFacts<'a>) -> TraceImageView<'a> {
        TraceImageView {
            analysis,
            symbol_index: &self.symbol_index,
            exports: &self.exports,
            arch: self.arch,
            image_base: self.image_base,
            dynamic: None,
        }
    }
}

struct TreeBuilder<'a> {
    headers: Option<&'a crate::analysis::headers::HeaderIndex>,
    exports: &'a dyn crate::analysis::resolution::ExportProvider,
    cfg: &'a Config,
    sub_cfg: Config,
    filter: Option<&'a CallFilter>,
    /// Expanded functions by (image, RVA).
    visited: std::collections::HashSet<(usize, u32)>,
    /// Callees already expanded, and whether that expansion kept any calls.
    expanded: std::collections::HashMap<(usize, u32), bool>,
    expansions: usize,
    expansion_limit: usize,
    budget_skipped: usize,
}

impl TreeBuilder<'_> {
    fn build_level(
        &mut self,
        calls: &[ApiCall],
        insns: &[Instruction],
        image: &TraceImageView<'_>,
        depth: u32,
    ) -> (Vec<CallNode>, usize) {
        // Unfiltered trees stop tracing at the render cap. Filtered trees evaluate every
        // call so the cap applies to what survives the filter, not to what precedes it.
        let selected = if self.filter.is_some() {
            calls.to_vec()
        } else {
            select_within_cap(calls, self.cfg.max_subcalls)
        };
        let budget = selected.len();
        let mut nodes = Vec::new();
        let signatures = self
            .headers
            .map(|index| {
                crate::analysis::headers::enrich_calls_in(
                    index,
                    image.analysis,
                    self.exports,
                    insns,
                    &selected,
                )
            })
            .unwrap_or_default();
        for call in &selected {
            if let Some(mut node) = self.build_node(call, insns, image, depth) {
                node.signature = signatures.get(&call.rva).cloned();
                nodes.push(node);
            }
        }
        (nodes, calls.len() - budget)
    }

    fn build_node(
        &mut self,
        call: &ApiCall,
        insns: &[Instruction],
        image: &TraceImageView<'_>,
        depth: u32,
    ) -> Option<CallNode> {
        if self.filter.is_some_and(|filter| filter.excludes(call)) {
            return None;
        }
        let syscall_target = resolve_syscall_trace_target(call, insns, self.cfg);
        let descend = depth + 1 < self.cfg.funcs_depth;
        let callee_key = (image.key(), call.target_rva);
        let can_recurse = !call.is_import
            && !call.is_indirect
            && call.target_rva != 0
            && descend
            && !self.visited.contains(&callee_key);

        let mut children = Vec::new();
        let mut unbuilt = 0;
        let mut expanded_here = false;
        if can_recurse {
            if let Some(file_off) = image.analysis.pe().rva_to_offset(call.target_rva) {
                if self.take_expansion() {
                    self.visited.insert(callee_key);
                    expanded_here = true;
                    if let Some((sub_insns, sub_calls)) =
                        self.trace_callee(image, file_off, call.target_rva)
                    {
                        (children, unbuilt) =
                            self.build_level(&sub_calls, &sub_insns, image, depth + 1);
                    }
                    self.expanded.insert(callee_key, !children.is_empty());
                }
            }
        } else if let Some(target) = syscall_target.as_ref().filter(|_| descend) {
            if let Some(file_off) = target.image.pe.rva_to_offset(target.rva) {
                let facts = ImageFacts::new(&target.image.pe, &target.image.raw);
                let kernel_view = target.image.as_view(&facts);
                let kernel_key = (kernel_view.key(), target.rva);
                if !self.visited.contains(&kernel_key) && self.take_expansion() {
                    self.visited.insert(kernel_key);
                    if let Some((sub_insns, sub_calls)) =
                        self.trace_callee(&kernel_view, file_off, target.rva)
                    {
                        (children, unbuilt) =
                            self.build_level(&sub_calls, &sub_insns, &kernel_view, depth + 1);
                    }
                }
            }
        }

        let expanded_above = self.filter.is_some()
            && !expanded_here
            && !call.is_import
            && !call.is_indirect
            && call.target_rva != 0
            && self.expanded.get(&callee_key).copied().unwrap_or(false);
        let keep = self.filter.is_none_or(|filter| filter.matches(call))
            || !children.is_empty()
            || expanded_above;
        if !keep {
            return None;
        }

        Some(CallNode {
            signature: None,
            call: call.clone(),
            location: call_location(call, image, self.cfg),
            kernel: syscall_target.map(|target| KernelCallTarget {
                image: target.image.dll_name.clone(),
                symbol: target.symbol_name,
                classes: target.classes,
            }),
            children,
            unbuilt,
            expanded_above,
        })
    }

    /// Reserve one function expansion within `--max-total`.
    fn take_expansion(&mut self) -> bool {
        if self.expansions >= self.expansion_limit {
            self.budget_skipped += 1;
            return false;
        }
        self.expansions += 1;
        true
    }

    fn trace_callee(
        &self,
        image: &TraceImageView<'_>,
        file_off: usize,
        rva: u32,
    ) -> Option<(Vec<Instruction>, Vec<ApiCall>)> {
        let insns = decode_traced_function(image, file_off, rva, &self.sub_cfg)?;
        let mut calls = collect_api_calls_in(
            &insns,
            image.analysis,
            image.symbol_index,
            image.image_base,
            self.cfg.hostile,
        );
        if let Some(report) = image.dynamic {
            apply_dynamic_resolution(&mut calls, &insns, report);
        }
        Some((insns, calls))
    }
}

fn colored_call_tag(call: &ApiCall, c: &Colors) -> String {
    if let Some(method) = &call.dynamic {
        return c.dim(&format!(" [dynamic · {method}]"));
    }
    let nt = is_nt_api(&call.label);
    match (call.is_import, call.is_indirect, call.kind.as_str(), nt) {
        (true, _, "jmp", true) => c.dim(" [syscall] [tail call]"),
        (true, _, _, true) => c.dim(" [syscall]"),
        (true, _, "jmp", false) => {
            if let Some(method) = &call.indirect_method {
                c.dim(&format!(" [import · tail call · {}]", method))
            } else {
                c.dim(" [import · tail call]")
            }
        }
        (true, _, _, false) => {
            if let Some(method) = &call.indirect_method {
                c.dim(&format!(" [import · {}]", method))
            } else {
                c.dim(" [import]")
            }
        }
        (_, true, _, _) => {
            if let Some(method) = &call.indirect_method {
                c.dim(&format!(" [indirect · {}]", method))
            } else {
                c.dim(" [indirect]")
            }
        }
        (_, _, "jmp", _) => {
            if let Some(method) = &call.indirect_method {
                c.dim(&format!(" [↳ {}]", method))
            } else {
                c.dim(" [tail call]")
            }
        }
        _ => {
            if let Some(method) = &call.indirect_method {
                c.dim(&format!(" [↳ {}]", method))
            } else {
                c.dim(" [internal]")
            }
        }
    }
}

fn text_call_tag(call: &ApiCall) -> &'static str {
    if call.dynamic.is_some() {
        return "[dynamic]";
    }
    match (
        call.is_import,
        call.is_indirect,
        call.kind.as_str(),
        is_nt_api(&call.label),
    ) {
        (true, _, "jmp", true) => "[syscall] [tail call]",
        (true, _, _, true) => "[syscall]",
        (true, _, "jmp", false) => "[import · tail call]",
        (true, _, _, false) => "[import]",
        (_, true, _, _) => "[indirect]",
        (_, _, "jmp", _) => "[tail call]",
        _ => "[internal]",
    }
}

const EXPANDED_ABOVE_TAG: &str = " [expanded above]";

/// Separate parameters from call edges. Commas inside strings or expressions
/// remain part of the value. Long values wrap inside their parameter branch.
fn argument_tree(call: &str, width: usize, more: bool) -> Vec<String> {
    let Some((_, body)) = call.split_once('(') else {
        return Vec::new();
    };
    let body = body.strip_suffix(')').unwrap_or(body);
    if body.is_empty() {
        return Vec::new();
    }
    let mut parts = Vec::new();
    let (mut start, mut depth, mut quoted, mut escaped) = (0, 0usize, false, false);
    for (at, ch) in body.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                quoted = false;
            }
            continue;
        }
        match ch {
            '"' => quoted = true,
            '(' | '[' | '{' => depth += 1,
            ')' | ']' | '}' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(body[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    parts.push(body[start..].trim());
    let content_width = width.saturating_sub(8).max(1);
    let column = parts
        .iter()
        .filter_map(|part| part.split_once('='))
        .map(|(name, _)| name.chars().count())
        .max()
        .unwrap_or(0)
        .min(32)
        .min(content_width / 2);
    let mut lines = vec![format!("{} args", if more { "├──" } else { "└──" })];
    let stem = if more { "│   " } else { "    " };
    for (index, part) in parts.iter().enumerate() {
        let last = index + 1 == parts.len();
        let text = match part.split_once('=') {
            Some((name, value)) => format!("{name:column$} = {value}"),
            None => (*part).to_owned(),
        };
        let chars: Vec<_> = text.chars().collect();
        let first_end = chars.len().min(content_width);
        lines.push(format!(
            "{stem}{} {}",
            if last { "└──" } else { "├──" },
            chars[..first_end].iter().collect::<String>()
        ));
        let indent = (column + 3).min(content_width.saturating_sub(1));
        for chunk in chars[first_end..].chunks((content_width - indent).max(1)) {
            lines.push(format!(
                "{stem}{}{}{}",
                if last { "    " } else { "│   " },
                " ".repeat(indent),
                chunk.iter().collect::<String>()
            ));
        }
    }
    lines
}

fn compact_call_tag(call: &ApiCall, c: &Colors, cfg: &Config) -> String {
    if cfg.verbose || call.dynamic.is_some() {
        return colored_call_tag(call, c);
    }
    if call.kind == "jmp" {
        return c.dim(" [tail call]");
    }
    if call.is_indirect && !call.is_import {
        return c.dim(" [indirect]");
    }
    String::new()
}

fn print_call_nodes(
    w: &mut dyn Write,
    nodes: &[CallNode],
    unbuilt: usize,
    c: &Colors,
    cfg: &Config,
    dll_map: &mut std::collections::HashMap<String, usize>,
    line_prefix: &str,
) {
    let visible_len = nodes.len().min(cfg.max_subcalls);
    let omitted = nodes.len() - visible_len + unbuilt;
    for (i, node) in nodes.iter().take(visible_len).enumerate() {
        let call = &node.call;
        let is_last = i + 1 == visible_len && omitted == 0;
        let branch = if is_last { "└──" } else { "├──" };
        let colored_target = if is_highlighted(call, cfg) {
            c.selected_marker(&plain_call_target(call))
        } else {
            color_target(call, c, dll_map)
        };
        let repeat = if node.expanded_above {
            c.dim(EXPANDED_ABOVE_TAG)
        } else {
            String::new()
        };
        let telemetry_tag = if cfg.telemetry {
            telemetry::classify(&call.label)
                .map(|sink| format!(" [telemetry · {}]", sink.kind.label()))
                .unwrap_or_default()
        } else {
            String::new()
        };

        if node.kernel.is_some() && c.on {
            // A user-to-kernel transition stands out as one red band.
            let plain = format!(
                "{}  {}  {}{}{}{}",
                node.location,
                call.kind.to_ascii_uppercase(),
                plain_call_target(call),
                strip_ansi(&compact_call_tag(call, c, cfg)),
                if node.expanded_above {
                    EXPANDED_ABOVE_TAG
                } else {
                    ""
                },
                telemetry_tag,
            );
            writeln!(w, "{}{} {}", line_prefix, branch, c.transition(&plain)).ok();
        } else {
            writeln!(
                w,
                "{}{} {}  {}  {}{}{}{}",
                line_prefix,
                branch,
                c.dim(&node.location),
                color_kind(&call.kind, c),
                colored_target,
                compact_call_tag(call, c, cfg),
                repeat,
                c.b_yellow(&telemetry_tag),
            )
            .ok();
        }

        let detail_prefix = format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
        let argument_rows = node
            .signature
            .as_ref()
            .map(|signature| {
                argument_tree(
                    &signature.call,
                    crate::core::table::output_width()
                        .min(120)
                        .saturating_sub(detail_prefix.chars().count()),
                    !call.switch_cases.is_empty()
                        || call.resolves.is_some()
                        || node.kernel.is_some()
                        || !node.children.is_empty(),
                )
            })
            .unwrap_or_default();
        for line in &argument_rows {
            writeln!(w, "{detail_prefix}{line}").ok();
        }
        if !call.switch_cases.is_empty() {
            writeln!(
                w,
                "{}{}  {}",
                detail_prefix,
                c.dim("when :"),
                c.cyan(&format_case_values(&call.switch_cases)),
            )
            .ok();
        }
        if let Some(resolves) = &call.resolves {
            writeln!(
                w,
                "{}{} {}",
                detail_prefix,
                c.dim("resolves:"),
                c.cyan(resolves)
            )
            .ok();
        }

        if let Some(kernel) = &node.kernel {
            if c.on {
                writeln!(
                    w,
                    "{}{}",
                    detail_prefix,
                    c.transition(&format!(
                        "kernel: {}!{}",
                        short_dll_name(&kernel.image),
                        kernel.symbol
                    )),
                )
                .ok();
            } else {
                writeln!(
                    w,
                    "{}kernel: {}!{}",
                    detail_prefix,
                    short_dll_name(&kernel.image),
                    kernel.symbol
                )
                .ok();
            }
            if !kernel.classes.is_empty() {
                let classes = kernel
                    .classes
                    .iter()
                    .map(|v| format_class_value(*v))
                    .collect::<Vec<_>>()
                    .join("|");
                writeln!(
                    w,
                    "{}{} {}",
                    detail_prefix,
                    c.dim("class :"),
                    c.b_white(&classes)
                )
                .ok();
            }
        }

        if !node.children.is_empty() {
            print_call_nodes(
                w,
                &node.children,
                node.unbuilt,
                c,
                cfg,
                dll_map,
                &detail_prefix,
            );
        }
        if !argument_rows.is_empty() && node.children.is_empty() {
            writeln!(w, "{}", detail_prefix.trim_end()).ok();
        }
    }
    if omitted > 0 {
        writeln!(
            w,
            "{}└── {}",
            line_prefix,
            c.dim(&format!(
                "{} subcalls omitted; raise --max-subcalls",
                omitted
            ))
        )
        .ok();
    }
}

fn write_call_nodes_text(
    out: &mut String,
    nodes: &[CallNode],
    unbuilt: usize,
    cfg: &Config,
    line_prefix: &str,
) {
    let visible_len = nodes.len().min(cfg.max_subcalls);
    let omitted = nodes.len() - visible_len + unbuilt;
    for (i, node) in nodes.iter().take(visible_len).enumerate() {
        let call = &node.call;
        let is_last = i + 1 == visible_len && omitted == 0;
        let branch = if is_last { "└──" } else { "├──" };
        let telemetry_tag = if cfg.telemetry {
            telemetry::classify(&call.label)
                .map(|sink| format!(" [telemetry · {}]", sink.kind.label()))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "{}{} {}  {}  {} {}{}{}",
            line_prefix,
            branch,
            node.location,
            call.kind,
            plain_call_target(call),
            text_call_tag(call),
            if node.expanded_above {
                EXPANDED_ABOVE_TAG
            } else {
                ""
            },
            telemetry_tag
        );

        let detail_prefix = format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
        let argument_rows = node
            .signature
            .as_ref()
            .map(|signature| {
                argument_tree(
                    &signature.call,
                    120usize.saturating_sub(detail_prefix.chars().count()),
                    !call.switch_cases.is_empty()
                        || call.resolves.is_some()
                        || node.kernel.is_some()
                        || !node.children.is_empty(),
                )
            })
            .unwrap_or_default();
        for line in &argument_rows {
            let _ = writeln!(out, "{detail_prefix}{line}");
        }
        if !call.switch_cases.is_empty() {
            let _ = writeln!(
                out,
                "{}when : {}",
                detail_prefix,
                format_case_values(&call.switch_cases)
            );
        }
        if let Some(resolves) = &call.resolves {
            let _ = writeln!(out, "{}resolves: {}", detail_prefix, resolves);
        }

        if let Some(kernel) = &node.kernel {
            let _ = writeln!(
                out,
                "{}kernel: {}!{}",
                detail_prefix,
                short_dll_name(&kernel.image),
                kernel.symbol
            );
        }

        if !node.children.is_empty() {
            write_call_nodes_text(out, &node.children, node.unbuilt, cfg, &detail_prefix);
        }
        if !argument_rows.is_empty() && node.children.is_empty() {
            let _ = writeln!(out, "{}", detail_prefix.trim_end());
        }
    }
    if omitted > 0 {
        let _ = writeln!(
            out,
            "{}└── {} subcalls omitted; raise --max-subcalls",
            line_prefix, omitted
        );
    }
}

struct SyscallTraceTarget {
    image: std::rc::Rc<LoadedTraceImage>,
    rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
}

/// Remove ANSI style sequences from already-colored text.
fn strip_ansi(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\x1b' {
            for next in chars.by_ref() {
                if next.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            out.push(ch);
        }
    }
    out
}

mod filter;
mod syscall;
pub(super) mod telemetry;
use filter::CallFilter;
pub(super) use syscall::*;

#[cfg(test)]
mod tests {
    #[test]
    fn argument_subtree_preserves_quoted_commas_and_wraps_values() {
        let lines = super::argument_tree(
            r#"f(path=L"C:\a,b.txt", flags=CTL_CODE(A, B), size=0)"#,
            80,
            false,
        );
        assert_eq!(
            lines,
            [
                "└── args",
                r#"    ├── path  = L"C:\a,b.txt""#,
                "    ├── flags = CTL_CODE(A, B)",
                "    └── size  = 0"
            ]
        );
        let wrapped = super::argument_tree("f(value=日本語日本語日本語)", 18, true);
        assert!(wrapped.iter().all(|line| line.chars().count() <= 18));
        assert_eq!(
            wrapped
                .iter()
                .map(|line| line.matches('日').count())
                .sum::<usize>(),
            3
        );
        assert_eq!(wrapped[0], "├── args");
        assert!(super::argument_tree("GetLastError()", 80, false).is_empty());
    }

    use super::{
        is_probable_win32k_syscall_name, normalize_image_base, syscall_kernel_images,
        syscall_stub_provider, NT_KERNEL_IMAGES, WIN32K_KERNEL_IMAGES,
    };
    use crate::analysis::disasm::ApiCall;

    fn import_call(dll: &str, label: &str) -> ApiCall {
        ApiCall {
            rva: 0x1000,
            kind: "call".to_owned(),
            target_rva: 0,
            label: label.to_owned(),
            dll: dll.to_owned(),
            is_import: true,
            is_indirect: false,
            indirect_method: None,
            switch_cases: Vec::new(),
            dynamic: None,
            resolves: None,
        }
    }

    #[test]
    fn syscall_images_route_native_and_win32k_families() {
        let native = import_call("ntdll.dll", "NtOpenProcess");
        assert_eq!(syscall_kernel_images(&native), NT_KERNEL_IMAGES);

        let gui = import_call("win32u.dll", "NtUserGetMessage");
        assert_eq!(syscall_kernel_images(&gui), WIN32K_KERNEL_IMAGES);

        let gdi = import_call("user32.dll", "NtGdiDdDDICreateDevice");
        assert_eq!(syscall_kernel_images(&gdi), WIN32K_KERNEL_IMAGES);
    }

    #[test]
    fn synthetic_provider_uses_win32u_for_gui_syscalls() {
        assert_eq!(
            syscall_stub_provider("NtUserGetMessage", "win32u.dll"),
            "win32u.dll"
        );
        assert_eq!(
            syscall_stub_provider("NtDCompositionCreateChannel", "win32u.dll"),
            "win32u.dll"
        );
        assert_eq!(
            syscall_stub_provider("NtQuerySystemInformation", "ntdll.dll"),
            "ntdll.dll"
        );
    }

    #[test]
    fn win32k_syscall_name_detection_covers_gui_exports() {
        assert!(is_probable_win32k_syscall_name("NtUserGetMessage"));
        assert!(is_probable_win32k_syscall_name("NtGdiCreateBitmap"));
        assert!(is_probable_win32k_syscall_name(
            "NtDCompositionCommitChannel"
        ));
        assert!(!is_probable_win32k_syscall_name("NtOpenProcess"));
    }

    #[test]
    fn image_base_normalization_strips_common_extensions() {
        assert_eq!(
            normalize_image_base(r"C:\Windows\System32\win32kfull.sys"),
            "win32kfull"
        );
        assert_eq!(normalize_image_base("ntoskrnl.exe"), "ntoskrnl");
        assert_eq!(normalize_image_base("win32u.dll"), "win32u");
    }
}
