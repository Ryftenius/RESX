//! Caller-owned export names used to validate decoded strings and invert hashes.
//! No filesystem lookup or host configuration belongs in this module.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, OnceLock};

/// A stable export snapshot. Earlier modules take precedence for duplicate names.
#[derive(Default)]
pub struct ExportDictionary {
    pub(super) apis: HashMap<String, Arc<str>>,
    pub(super) modules: HashSet<String>,
    pub(super) module_names: Vec<String>,
}

/// An explicit, optionally lazy source of export names.
/// The returned dictionary must remain the same snapshot for this provider's lifetime.
pub trait ExportProvider: Send + Sync {
    fn dictionary(&self) -> &ExportDictionary;
}

impl ExportProvider for ExportDictionary {
    fn dictionary(&self) -> &ExportDictionary {
        self
    }
}

impl ExportDictionary {
    pub fn add_exports<'a>(&mut self, module: &str, names: impl IntoIterator<Item = &'a str>) {
        self.add_module(module);
        let module: Arc<str> = Arc::from(module);
        for name in names {
            if !name.is_empty() && !name.starts_with('#') {
                self.apis
                    .entry(name.to_owned())
                    .or_insert_with(|| Arc::clone(&module));
            }
        }
    }

    pub fn add_module(&mut self, name: &str) {
        let lower = name.to_ascii_lowercase();
        if self.modules.insert(lower.clone()) {
            self.module_names.push(lower.clone());
        }
        if let Some(stem) = lower.strip_suffix(".dll") {
            if self.modules.insert(stem.to_owned()) {
                self.module_names.push(stem.to_owned());
            }
        }
    }

    pub fn is_api(&self, name: &str) -> bool {
        self.apis.contains_key(name)
    }

    pub fn is_module(&self, name: &str) -> bool {
        self.modules.contains(&name.to_ascii_lowercase())
    }

    pub fn module_of(&self, api: &str) -> Option<&str> {
        self.apis.get(api).map(AsRef::as_ref)
    }
}

pub(crate) fn empty() -> &'static ExportDictionary {
    static EMPTY: OnceLock<ExportDictionary> = OnceLock::new();
    EMPTY.get_or_init(ExportDictionary::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_order_controls_duplicate_exports_and_ordinals_are_not_names() {
        let mut dictionary = ExportDictionary::default();
        dictionary.add_exports("ALPHA.DLL", ["Shared", "", "#123"]);
        dictionary.add_exports("beta.dll", ["Shared", "Other"]);
        assert_eq!(dictionary.module_of("Shared"), Some("ALPHA.DLL"));
        assert_eq!(dictionary.module_of("Other"), Some("beta.dll"));
        assert!(dictionary.is_module("alpha"));
        assert!(dictionary.is_module("AlPhA.DlL"));
        assert!(!dictionary.is_api("shared"));
        assert!(!dictionary.is_api("#123"));
        assert!(!dictionary.is_api(""));
    }
}
