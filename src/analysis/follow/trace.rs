use std::io::Write;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use rayon::prelude::*;

use crate::analysis::follow::scan::{
    scan_image_for_callers, CallSite, Caller, FollowScanConfig, ScanImage,
};
use crate::core::color::Colors;
use crate::core::output::AsyncProgress;

#[derive(Debug, Clone)]
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
}

pub struct TraceCtx<'a> {
    pub cfg: &'a FollowScanConfig,
    pub scan_images: &'a [ScanImage],
    pub target_arch: u32,
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

// Flat storage node used during BFS construction.
struct FlatEntry {
    func: FuncRef,
    sites: Vec<CallSite>,
    depth: usize,
    truncated: bool,
    children: Vec<usize>, // indices into flat vec
}

fn scan_frontier(
    frontier: &[(FuncRef, usize)],
    ctx: &TraceCtx<'_>,
    progress: &AsyncProgress,
) -> Vec<Vec<Caller>> {
    let job_count = frontier.len().saturating_mul(ctx.scan_images.len());
    if job_count == 0 {
        return vec![Vec::new(); frontier.len()];
    }

    let jobs: Vec<(usize, usize)> = (0..frontier.len())
        .flat_map(|frontier_idx| {
            (0..ctx.scan_images.len()).map(move |image_idx| (frontier_idx, image_idx))
        })
        .collect();

    let mut grouped: Vec<Vec<Caller>> = vec![Vec::new(); frontier.len()];
    let mut hits: Vec<(usize, Caller)> = jobs
        .par_iter()
        .flat_map_iter(|(frontier_idx, image_idx)| {
            let (target, _) = &frontier[*frontier_idx];
            let image = &ctx.scan_images[*image_idx];
            let image_name = image.path.file_name().unwrap_or_default().to_string_lossy();
            let label = format!("{}!{}  <-  {}", target.dll, target.name, image_name);
            let lane = rayon::current_thread_index().unwrap_or(0);
            let callers = scan_image_for_callers(image, target, ctx.target_arch, ctx.cfg);
            progress.tick(lane, &label);
            callers
                .into_iter()
                .map(move |caller| (*frontier_idx, caller))
        })
        .collect();

    if !ctx.cfg.filter_dll.is_empty() {
        let f = ctx.cfg.filter_dll.to_lowercase();
        hits.retain(|(_, caller)| caller.func.dll.to_lowercase().contains(&f));
    }

    for (frontier_idx, caller) in hits.drain(..) {
        grouped[frontier_idx].push(caller);
    }
    for callers in &mut grouped {
        callers.sort_by(|a, b| a.func.key().cmp(b.func.key()));
    }
    grouped
}

/// Build a caller graph for `root` using breadth-first expansion so that all
/// `(target, image)` scan jobs at the same depth level can be balanced by one
/// shared work queue.
pub fn build_call_tree(
    root: FuncRef,
    ctx: &TraceCtx<'_>,
    w: &mut dyn Write,
    c: &Colors,
) -> CallNode {
    // Flat storage; index 0 is always the root.
    let mut flat: Vec<FlatEntry> = vec![FlatEntry {
        func: root.clone(),
        sites: Vec::new(),
        depth: 0,
        truncated: false,
        children: Vec::new(),
    }];

    // BFS frontier: (FuncRef to expand, its index in flat)
    let mut frontier: Vec<(FuncRef, usize)> = vec![(root, 0)];

    for depth in 0..ctx.cfg.depth {
        if frontier.is_empty() || ctx.check_total() {
            break;
        }

        let n = frontier.len();
        let scan_total = ctx.scan_images.len();

        if !ctx.cfg.quiet {
            let msg = if n == 1 {
                format!(
                    "depth {}  ·  scanning {} files for 1 target",
                    depth, scan_total
                )
            } else {
                format!(
                    "depth {}  ·  scanning {} files for {} targets in parallel",
                    depth, scan_total, n
                )
            };
            writeln!(w, "{}", c.info(&msg)).ok();
            w.flush().ok();
        }

        let total_jobs = n.saturating_mul(scan_total);
        let lane_count = ctx.cfg.workers.clamp(1, 8);
        let progress = AsyncProgress::new(total_jobs, lane_count, c.on && !ctx.cfg.quiet, c.on);
        let callers_by_target = scan_frontier(&frontier, ctx, &progress);
        progress.finish();

        // Serial: wire results into the flat vec and build the next frontier.
        let mut next_frontier: Vec<(FuncRef, usize)> = Vec::new();
        let mut found_this_level = 0usize;

        for ((_, parent_idx), mut callers) in frontier.iter().zip(callers_by_target.into_iter()) {
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

    // Reconstruct the CallNode tree from the flat vec using stored children indices.
    fn to_call_node(idx: usize, flat: &[FlatEntry]) -> CallNode {
        let e = &flat[idx];
        CallNode {
            func: e.func.clone(),
            depth: e.depth,
            sites: e.sites.clone(),
            truncated: e.truncated,
            callers: e
                .children
                .iter()
                .map(|&ci| to_call_node(ci, flat))
                .collect(),
        }
    }

    to_call_node(0, &flat)
}
