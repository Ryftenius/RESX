use std::io::Write;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::analysis::follow::scan::{
    import_lookup_key, CallSite, Caller, FollowScanConfig, ScanImage, WrapperTarget,
};
use crate::core::color::Colors;
use crate::core::output::{AsyncProgress, StageProgress};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuncRef {
    pub dll: String,
    pub dll_path: String,
    pub dll_base: String,
    pub name: String,
    key: String,
    pub rva: u32,
    pub va: u64,
    pub is_internal: bool,
}

impl FuncRef {
    pub fn new(
        dll: String,
        dll_path: String,
        name: String,
        rva: u32,
        va: u64,
        is_internal: bool,
    ) -> Self {
        let dll_base = dll
            .rsplit(&['/', '\\'][..])
            .next()
            .unwrap_or(&dll)
            .trim_end_matches(".dll")
            .trim_end_matches(".DLL")
            .to_ascii_lowercase();
        let key = format!("{}!{}", dll.to_ascii_lowercase(), name);
        Self {
            dll,
            dll_path,
            dll_base,
            name,
            key,
            rva,
            va,
            is_internal,
        }
    }

    pub fn key(&self) -> &str {
        &self.key
    }

    pub fn display(&self) -> &str {
        &self.name
    }
}

#[derive(Debug, Clone)]
pub struct CallNode {
    pub func: FuncRef,
    pub depth: usize,
    pub sites: Vec<CallSite>,
    pub callers: Vec<CallNode>,
    pub truncated: bool,
    /// Set when this node reached its target via a wrapper/thunk export.
    /// Format: "dll_name!ExportName"
    pub via_wrapper: Option<String>,
}

pub struct TraceCtx<'a> {
    pub cfg: &'a FollowScanConfig,
    pub graph: &'a GlobalCallGraph,
    pub visited: Mutex<std::collections::HashSet<String>>,
    pub total: AtomicUsize,
}

impl<'a> TraceCtx<'a> {
    fn mark_visited(&self, key: &str) -> bool {
        let mut v = self.visited.lock().unwrap();
        v.insert(key.to_owned())
    }

    fn check_total(&self) -> bool {
        self.cfg.max_total > 0 && self.total.load(Ordering::Relaxed) >= self.cfg.max_total
    }

    fn inc_total(&self) {
        self.total.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct GlobalCallGraph {
    direct: std::collections::HashMap<DirectTarget, Vec<Caller>>,
    imports: std::collections::HashMap<String, Vec<Caller>>,
    image_count: usize,
    total_file_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DirectTarget {
    dll_base: String,
    rva: u32,
}

impl DirectTarget {
    fn from_func(func: &FuncRef) -> Self {
        Self {
            dll_base: func.dll_base.clone(),
            rva: func.rva,
        }
    }
}

impl GlobalCallGraph {
    pub fn build(
        scan_images: &[ScanImage],
        cfg: &FollowScanConfig,
        target_arch: u32,
        c: &Colors,
    ) -> Self {
        let lane_count = cfg.workers.clamp(1, 8);
        let progress = AsyncProgress::new(scan_images.len(), lane_count, c.on && !cfg.quiet, c.on);
        let loaded: Vec<_> = scan_images
            .par_iter()
            .filter_map(|image| {
                let lane = rayon::current_thread_index().unwrap_or(0);
                let label = image.path.file_name().unwrap_or_default().to_string_lossy();
                let loaded = image.index(cfg).cloned();
                progress.tick(lane, &label);
                loaded
            })
            .collect();
        progress.finish();

        let mut stage = StageProgress::new(3, c.on && !cfg.quiet, c.on);
        stage.tick("merging direct caller buckets");

        let mut direct: std::collections::HashMap<DirectTarget, Vec<Caller>> =
            std::collections::HashMap::new();
        let mut imports: std::collections::HashMap<String, Vec<Caller>> =
            std::collections::HashMap::new();

        for index in &loaded {
            let arch_match = match cfg.arch.as_str() {
                "x86" | "32" => index.arch == 32,
                "x64" | "64" => index.arch == 64,
                _ => target_arch == 0 || index.arch == target_arch,
            };
            if !arch_match {
                continue;
            }

            for (target_rva, callers) in &index.direct {
                direct
                    .entry(DirectTarget {
                        dll_base: index.dll_base_lower.clone(),
                        rva: *target_rva,
                    })
                    .or_default()
                    .extend(callers.iter().cloned());
            }

            for (key, callers) in &index.imports {
                imports
                    .entry(key.clone())
                    .or_default()
                    .extend(callers.iter().cloned());
            }
        }

        stage.tick("deduping direct caller buckets");
        for callers in direct.values_mut() {
            dedup_callers(callers);
        }
        stage.tick("deduping import caller buckets");
        for callers in imports.values_mut() {
            dedup_callers(callers);
        }

        // Wrapper expansion: for each export in any scanned image that is a JMP-thunk
        // wrapper around another target, inject the wrapper's own callers as indirect
        // callers of the final target, annotated with `via_wrapper`.
        for index in &loaded {
            for wrapper in &index.wrappers {
                let wrapper_dt = DirectTarget {
                    dll_base: index.dll_base_lower.clone(),
                    rva: wrapper.rva,
                };
                let wrapper_callers = match direct.get(&wrapper_dt) {
                    Some(c) if !c.is_empty() => c.clone(),
                    _ => continue,
                };
                let via = format!("{}!{}", index.dll_name, wrapper.name);
                let expanded: Vec<Caller> = wrapper_callers
                    .into_iter()
                    .map(|mut c| {
                        c.via_wrapper = Some(via.clone());
                        c
                    })
                    .collect();
                match &wrapper.resolves_to {
                    WrapperTarget::Import { dll_base, func } => {
                        imports
                            .entry(import_lookup_key(dll_base, func))
                            .or_default()
                            .extend(expanded);
                    }
                    WrapperTarget::Direct { target_rva } => {
                        direct
                            .entry(DirectTarget {
                                dll_base: index.dll_base_lower.clone(),
                                rva: *target_rva,
                            })
                            .or_default()
                            .extend(expanded);
                    }
                }
            }
        }

        stage.finish();

        Self {
            direct,
            imports,
            image_count: loaded.len(),
            total_file_bytes: loaded.iter().map(|idx| idx.file_len).sum(),
        }
    }

    pub fn image_count(&self) -> usize {
        self.image_count
    }

    pub fn total_file_bytes(&self) -> u64 {
        self.total_file_bytes
    }

    fn callers_for(&self, target: &FuncRef) -> Vec<Caller> {
        let mut merged: Vec<Caller> = Vec::new();
        if let Some(direct) = self.direct.get(&DirectTarget::from_func(target)) {
            merged.extend(direct.iter().cloned());
        }
        if let Some(imports) = self
            .imports
            .get(&import_lookup_key(&target.dll_base, &target.name))
        {
            merged.extend(imports.iter().cloned());
        }
        dedup_callers(&mut merged);
        merged
    }
}

fn dedup_callers(callers: &mut Vec<Caller>) {
    let mut merged: std::collections::BTreeMap<String, Caller> = std::collections::BTreeMap::new();
    for caller in callers.drain(..) {
        // Include via_wrapper in the key so a function that calls both directly
        // and via a wrapper is preserved as two distinct entries.
        let key = format!(
            "{}|{}",
            caller.func.key(),
            caller.via_wrapper.as_deref().unwrap_or("")
        );
        let entry = merged.entry(key).or_insert_with(|| Caller {
            func: caller.func.clone(),
            sites: Vec::new(),
            via_wrapper: caller.via_wrapper.clone(),
        });
        entry.sites.extend(caller.sites);
    }
    *callers = merged
        .into_values()
        .map(|mut caller| {
            caller
                .sites
                .sort_by(|a, b| a.rva.cmp(&b.rva).then_with(|| a.pattern.cmp(&b.pattern)));
            caller
                .sites
                .dedup_by(|a, b| a.rva == b.rva && a.pattern == b.pattern);
            caller
        })
        .collect();
}

// Flat storage node used during BFS construction.
struct FlatEntry {
    func: FuncRef,
    sites: Vec<CallSite>,
    depth: usize,
    truncated: bool,
    children: Vec<usize>,
    via_wrapper: Option<String>,
}

pub fn build_call_tree(
    root: FuncRef,
    ctx: &TraceCtx<'_>,
    w: &mut dyn Write,
    c: &Colors,
) -> CallNode {
    let mut flat: Vec<FlatEntry> = vec![FlatEntry {
        func: root.clone(),
        sites: Vec::new(),
        depth: 0,
        truncated: false,
        children: Vec::new(),
        via_wrapper: None,
    }];
    let mut frontier: Vec<(FuncRef, usize)> = vec![(root, 0)];

    for depth in 0..ctx.cfg.depth {
        if frontier.is_empty() || ctx.check_total() {
            break;
        }

        if !ctx.cfg.quiet {
            let msg = if frontier.len() == 1 {
                format!(
                    "depth {}  ·  querying global caller graph built from {} files",
                    depth,
                    ctx.graph.image_count()
                )
            } else {
                format!(
                    "depth {}  ·  querying {} targets against global caller graph ({} files indexed)",
                    depth,
                    frontier.len(),
                    ctx.graph.image_count()
                )
            };
            writeln!(w, "{}", c.info(&msg)).ok();
            w.flush().ok();
        }

        let mut next_frontier: Vec<(FuncRef, usize)> = Vec::new();
        let mut found_this_level = 0usize;

        for (target, parent_idx) in &frontier {
            let mut callers = ctx.graph.callers_for(target);
            if !ctx.cfg.filter_dll.is_empty() {
                let filter = ctx.cfg.filter_dll.to_lowercase();
                callers.retain(|caller| caller.func.dll.to_lowercase().contains(&filter));
            }
            callers.sort_by(|a, b| a.func.key().cmp(b.func.key()));

            if ctx.cfg.max_callers > 0 && callers.len() > ctx.cfg.max_callers {
                callers.truncate(ctx.cfg.max_callers);
                flat[*parent_idx].truncated = true;
            }

            for caller in callers {
                if ctx.check_total() {
                    flat[*parent_idx].truncated = true;
                    break;
                }
                ctx.inc_total();
                let is_new = ctx.mark_visited(caller.func.key());
                let new_idx = flat.len();
                flat.push(FlatEntry {
                    func: caller.func.clone(),
                    sites: caller.sites,
                    depth: depth + 1,
                    truncated: !is_new,
                    children: Vec::new(),
                    via_wrapper: caller.via_wrapper,
                });
                flat[*parent_idx].children.push(new_idx);
                if is_new {
                    found_this_level += 1;
                    next_frontier.push((caller.func, new_idx));
                }
            }
        }

        if !ctx.cfg.quiet {
            writeln!(
                w,
                "{}",
                c.dim(&format!(
                    "  -> {} unique caller(s) found at depth {}",
                    found_this_level,
                    depth + 1
                ))
            )
            .ok();
        }

        frontier = next_frontier;
    }

    fn to_call_node(idx: usize, flat: &[FlatEntry]) -> CallNode {
        let e = &flat[idx];
        CallNode {
            func: e.func.clone(),
            depth: e.depth,
            sites: e.sites.clone(),
            truncated: e.truncated,
            via_wrapper: e.via_wrapper.clone(),
            callers: e
                .children
                .iter()
                .map(|&ci| to_call_node(ci, flat))
                .collect(),
        }
    }

    to_call_node(0, &flat)
}
