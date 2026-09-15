use super::*;

#[derive(Debug, Clone)]
pub(super) struct SymbolMeta {
    pub(super) source: String,
    pub(super) size: u64,
    pub(super) prototype: String,
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
    let root_label = format!("Root {}/{}:", index, total);
    let root_label = if root.kind == "TLS Callback" {
        c.bold(&c.b_red(&root_label))
    } else {
        c.bold(&c.b_yellow(&root_label))
    };
    let _ = writeln!(out, "{} {}", root_label, format_function_header(root, c));
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
        color_function_kind(&func.kind, c),
        section,
        meta,
        prototype,
        note
    )
}

pub(super) fn color_function_kind(kind: &str, c: &Colors) -> String {
    if kind == "TLS Callback" {
        c.bold(&c.b_red(kind))
    } else {
        c.dim(kind)
    }
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

pub(super) fn classify_function_symbol(
    name: &str,
    source: &str,
    meta: Option<&SymbolMeta>,
) -> String {
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

pub(super) fn classify_edge_target(name: &str, source: &str, meta: Option<&SymbolMeta>) -> String {
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
