use std::io::Write;

use serde::Serialize;

use crate::analysis::follow::scan::FollowScanConfig;
use crate::analysis::follow::trace::CallNode;
use crate::core::color::Colors;

fn is_false(b: &bool) -> bool {
    !*b
}

pub fn print_call_tree(
    w: &mut dyn Write,
    node: &CallNode,
    prefix: &str,
    is_last: bool,
    cfg: &FollowScanConfig,
    c: &Colors,
) {
    let (branch, child_pfx) = if node.depth == 0 {
        ("".to_owned(), "".to_owned())
    } else if is_last {
        ("`-- ".to_owned(), format!("{}    ", prefix))
    } else {
        ("|-- ".to_owned(), format!("{}|   ", prefix))
    };

    let dll_label = c.dim(&format!("[{}]", node.func.dll));
    let func_label = if node.func.is_internal {
        c.dim(node.func.display())
    } else {
        c.b_yellow(node.func.display())
    };

    let mut extra = String::new();
    if cfg.show_rva && node.func.rva != 0 {
        extra.push_str(&c.dim(&format!("  RVA:0x{:08X}", node.func.rva)));
    }
    if cfg.show_site && !node.sites.is_empty() {
        let site_strs: Vec<String> = node
            .sites
            .iter()
            .map(|s| format!("0x{:08X}({})", s.rva, s.pattern))
            .collect();
        extra.push_str(&c.dim(&format!("  call@[{}]", site_strs.join(", "))));
    }

    if node.depth == 0 {
        writeln!(w, "{}{}  {}", func_label, extra, dll_label).ok();
    } else {
        writeln!(w, "{}{}{}{}", prefix, branch, func_label, extra).ok();
    }

    if node.truncated && node.callers.is_empty() {
        writeln!(
            w,
            "{}`-- {}",
            child_pfx,
            c.dim("[... truncated (--depth / --max-callers / --max-total)]")
        )
        .ok();
    }

    for (i, child) in node.callers.iter().enumerate() {
        let last = i + 1 == node.callers.len() && !node.truncated;
        print_call_tree(w, child, &child_pfx, last, cfg, c);
    }

    if node.truncated && !node.callers.is_empty() {
        writeln!(w, "{}`-- {}", child_pfx, c.dim("[... truncated]")).ok();
    }
}

pub fn print_call_flat(w: &mut dyn Write, node: &CallNode, cfg: &FollowScanConfig, c: &Colors) {
    fn walk(w: &mut dyn Write, n: &CallNode, depth: usize, cfg: &FollowScanConfig, c: &Colors) {
        let indent = "  ".repeat(depth);
        let arrow = if depth == 0 { " " } else { "<-" };
        let rva = if cfg.show_rva && n.func.rva != 0 {
            c.dim(&format!("  [RVA:0x{:08X}]", n.func.rva))
        } else {
            String::new()
        };
        let site = if cfg.show_site && !n.sites.is_empty() {
            c.dim(&format!("  call@0x{:08X}", n.sites[0].rva))
        } else {
            String::new()
        };
        writeln!(
            w,
            "{} {} {}!{}{}{}",
            indent,
            c.dim(arrow),
            c.cyan(&n.func.dll),
            c.b_yellow(n.func.display()),
            rva,
            site
        )
        .ok();
        for child in &n.callers {
            walk(w, child, depth + 1, cfg, c);
        }
    }
    walk(w, node, 0, cfg, c);
}

pub fn print_call_list(w: &mut dyn Write, node: &CallNode, cfg: &FollowScanConfig, c: &Colors) {
    let mut seen = std::collections::HashSet::new();
    fn walk(
        w: &mut dyn Write,
        n: &CallNode,
        seen: &mut std::collections::HashSet<String>,
        cfg: &FollowScanConfig,
        c: &Colors,
    ) {
        if n.depth > 0 && seen.insert(n.func.key().to_owned()) {
            let rva = if cfg.show_rva {
                c.dim(&format!("\t[RVA:0x{:08X}]", n.func.rva))
            } else {
                String::new()
            };
            writeln!(
                w,
                "  {}!{}{}",
                c.cyan(&n.func.dll),
                c.b_yellow(n.func.display()),
                rva
            )
            .ok();
        }
        for child in &n.callers {
            walk(w, child, seen, cfg, c);
        }
    }
    walk(w, node, &mut seen, cfg, c);
}

#[derive(Serialize)]
pub struct NodeJson {
    pub dll: String,
    pub dll_path: String,
    pub function: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub rva: String,
    #[serde(skip_serializing_if = "is_false")]
    pub internal: bool,
    pub depth: usize,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub call_sites: Vec<SiteJson>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub callers: Vec<NodeJson>,
    #[serde(skip_serializing_if = "is_false")]
    pub truncated: bool,
}

#[derive(Serialize)]
pub struct SiteJson {
    pub rva: String,
    pub pattern: String,
}

pub fn node_to_json(node: &CallNode) -> NodeJson {
    NodeJson {
        dll: node.func.dll.clone(),
        dll_path: node.func.dll_path.clone(),
        function: node.func.display().to_owned(),
        rva: if node.func.rva != 0 {
            format!("0x{:08X}", node.func.rva)
        } else {
            String::new()
        },
        internal: node.func.is_internal,
        depth: node.depth,
        truncated: node.truncated,
        call_sites: node
            .sites
            .iter()
            .map(|s| SiteJson {
                rva: format!("0x{:08X}", s.rva),
                pattern: s.pattern.clone(),
            })
            .collect(),
        callers: node.callers.iter().map(node_to_json).collect(),
    }
}

pub fn count_nodes(node: &CallNode) -> (usize, usize) {
    let mut seen = std::collections::HashSet::new();
    let mut total = 0usize;
    fn walk(n: &CallNode, seen: &mut std::collections::HashSet<String>, total: &mut usize) {
        if n.depth > 0 {
            *total += 1;
            seen.insert(n.func.key().to_owned());
        }
        for child in &n.callers {
            walk(child, seen, total);
        }
    }
    walk(node, &mut seen, &mut total);
    (total, seen.len())
}
