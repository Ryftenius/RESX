use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::formats::pdb::PdbSymbol;
use crate::formats::pe::Export;

pub fn display_symbol_name(name: &str) -> String {
    let (scope, tail) = match name.rsplit_once('!') {
        Some((scope, tail)) => (Some(scope), tail),
        None => (None, name),
    };
    let cleaned_tail = match tail.split_once("$thunk$") {
        Some((base, _)) if !base.is_empty() => base,
        _ => tail,
    };
    match scope {
        Some(scope) => format!("{}!{}", scope, cleaned_tail),
        None => cleaned_tail.to_owned(),
    }
}

#[derive(Debug, Clone)]
pub struct ResolvedSymbol {
    pub name: String,
    pub kind: String,
    pub type_name: String,
    pub va: u64,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct SymbolMatch {
    pub symbol: ResolvedSymbol,
    pub displacement: u64,
}

#[derive(Debug, Default)]
struct SymbolIndexInner {
    exact: HashMap<u64, ResolvedSymbol>,
    ordered: BTreeMap<u64, ResolvedSymbol>,
}

#[derive(Debug, Clone, Default)]
pub struct SymbolIndex {
    inner: Arc<SymbolIndexInner>,
}

impl SymbolIndex {
    pub fn from_exports_and_pdb(
        exports: &[Export],
        pdb_symbols: &[PdbSymbol],
        image_base: u64,
    ) -> Self {
        let mut inner = SymbolIndexInner::default();

        for e in exports {
            if e.name.is_empty() {
                continue;
            }
            let sym = ResolvedSymbol {
                name: display_symbol_name(&e.name),
                kind: "function".to_owned(),
                type_name: String::new(),
                va: image_base + e.rva as u64,
                size: 0,
            };
            insert_symbol(&mut inner, sym);
        }

        for s in pdb_symbols {
            let sym = ResolvedSymbol {
                name: display_symbol_name(&s.name),
                kind: s.kind.clone(),
                type_name: s.type_name.clone(),
                va: s.va,
                size: s.size,
            };
            insert_symbol(&mut inner, sym);
        }

        Self {
            inner: Arc::new(inner),
        }
    }

    pub fn exact_name(&self, address: u64) -> Option<&str> {
        self.inner.exact.get(&address).map(|s| s.name.as_str())
    }

    pub fn exact(&self, address: u64) -> Option<ResolvedSymbol> {
        self.inner.exact.get(&address).cloned()
    }

    pub fn describe(&self, address: u64) -> Option<String> {
        let hit = self.lookup(address)?;
        let mut out = hit.symbol.name.clone();
        if hit.displacement != 0 {
            out.push_str(&format!("+0x{:X}", hit.displacement));
        }
        if !hit.symbol.type_name.is_empty() {
            out.push_str(&format!(" ({})", hit.symbol.type_name));
        } else if hit.symbol.kind == "data" {
            out.push_str(" (data)");
        }
        Some(out)
    }

    pub fn lookup(&self, address: u64) -> Option<SymbolMatch> {
        if let Some(sym) = self.inner.exact.get(&address) {
            return Some(SymbolMatch {
                symbol: sym.clone(),
                displacement: 0,
            });
        }

        let prev = self.inner.ordered.range(..=address).next_back()?;
        let next = self.inner.ordered.range(address..).next();

        let prev_sym = prev.1;
        let prev_disp = address.saturating_sub(prev_sym.va);

        // Strong match if the symbol has a real size and we're inside it.
        if prev_sym.size > 0 && prev_disp < prev_sym.size {
            return Some(SymbolMatch {
                symbol: prev_sym.clone(),
                displacement: prev_disp,
            });
        }

        // Unknown-size symbols are dangerous. Be much stricter.
        // Allow only a tiny near-window, and only if there isn't a competing next symbol
        // that is equally or more plausible.
        let near_window = match prev_sym.kind.as_str() {
            "function" => 0x20,
            "data" => 0x10,
            _ => 0x08,
        };

        if prev_disp > near_window {
            return None;
        }

        if let Some((next_va, _next_sym)) = next {
            let next_gap = next_va.saturating_sub(address);
            if next_gap <= prev_disp {
                return None;
            }
        }

        Some(SymbolMatch {
            symbol: prev_sym.clone(),
            displacement: prev_disp,
        })
    }
}

fn score(sym: &ResolvedSymbol) -> u32 {
    let mut score = 0;
    if sym.kind == "function" {
        score += 6;
    }
    if sym.kind == "data" {
        score += 4;
    }
    if sym.size > 0 {
        score += 4;
    }
    if !sym.type_name.is_empty() {
        score += 2;
    }
    if !sym.name.starts_with('#') {
        score += 1;
    }
    score
}

fn insert_symbol(index: &mut SymbolIndexInner, sym: ResolvedSymbol) {
    let keep_existing = index
        .exact
        .get(&sym.va)
        .map(|old| score(old) >= score(&sym))
        .unwrap_or(false);
    if !keep_existing {
        index.exact.insert(sym.va, sym.clone());
        index.ordered.insert(sym.va, sym);
    }
}
