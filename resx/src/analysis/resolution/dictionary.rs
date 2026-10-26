//! Export and module names from the local system, used to validate decoded strings
//! and to invert API hashes. Built once per process, on first use, and only when an
//! image actually hides a name.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::OnceLock;

use crate::formats::pe::{parse_pe, read_exports};

/// Modules whose exports are worth resolving dynamically, in the order a name found
/// in several of them is attributed.
const EXPORT_SOURCES: &[&str] = &[
    "kernel32.dll",
    "ntdll.dll",
    "kernelbase.dll",
    "user32.dll",
    "advapi32.dll",
    "ws2_32.dll",
    "wininet.dll",
    "winhttp.dll",
    "shell32.dll",
    "shlwapi.dll",
    "ole32.dll",
    "oleaut32.dll",
    "combase.dll",
    "gdi32.dll",
    "crypt32.dll",
    "bcrypt.dll",
    "ncrypt.dll",
    "psapi.dll",
    "dbghelp.dll",
    "urlmon.dll",
    "iphlpapi.dll",
    "dnsapi.dll",
    "netapi32.dll",
    "secur32.dll",
    "sspicli.dll",
    "wtsapi32.dll",
    "userenv.dll",
    "version.dll",
    "rpcrt4.dll",
    "mpr.dll",
    "winmm.dll",
    "setupapi.dll",
    "wintrust.dll",
    "imagehlp.dll",
    "amsi.dll",
    "wevtapi.dll",
    "msvcrt.dll",
    "ucrtbase.dll",
];

pub(super) struct Dictionary {
    /// Export name → module it is attributed to.
    pub apis: HashMap<String, &'static str>,
    /// Lowercase module file names, with and without the `.dll` extension.
    pub modules: HashSet<String>,
    /// Module names as they are hashed: the exporting modules first, then the rest.
    pub module_names: Vec<String>,
}

impl Dictionary {
    pub fn is_api(&self, name: &str) -> bool {
        self.apis.contains_key(name)
    }

    pub fn is_module(&self, name: &str) -> bool {
        self.modules.contains(&name.to_ascii_lowercase())
    }

    pub fn module_of(&self, api: &str) -> Option<&'static str> {
        self.apis.get(api).copied()
    }
}

pub(super) fn get() -> &'static Dictionary {
    static DICTIONARY: OnceLock<Dictionary> = OnceLock::new();
    DICTIONARY.get_or_init(load)
}

fn system_dir() -> Option<PathBuf> {
    let root = std::env::var_os("SystemRoot").or_else(|| std::env::var_os("windir"))?;
    Some(PathBuf::from(root).join("System32"))
}

fn load() -> Dictionary {
    let mut apis = HashMap::new();
    let mut modules = HashSet::new();
    let mut module_names: Vec<String> = Vec::new();
    let system = system_dir();

    for &module in EXPORT_SOURCES {
        add_module(&mut modules, &mut module_names, module);
        let Some(raw) = system
            .as_ref()
            .and_then(|dir| std::fs::read(dir.join(module)).ok())
        else {
            continue;
        };
        let Ok(pe) = parse_pe(&raw) else {
            continue;
        };
        for export in read_exports(&pe, &raw) {
            if !export.name.is_empty() && !export.name.starts_with('#') {
                apis.entry(export.name).or_insert(module);
            }
        }
    }
    if let Some(entries) = system.and_then(|dir| std::fs::read_dir(dir).ok()) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
            if name.ends_with(".dll") || name.ends_with(".drv") || name.ends_with(".sys") {
                add_module(&mut modules, &mut module_names, &name);
            }
        }
    }
    Dictionary {
        apis,
        modules,
        module_names,
    }
}

fn add_module(modules: &mut HashSet<String>, names: &mut Vec<String>, name: &str) {
    let lower = name.to_ascii_lowercase();
    if modules.insert(lower.clone()) {
        names.push(lower.clone());
    }
    if let Some(stem) = lower.strip_suffix(".dll") {
        if modules.insert(stem.to_owned()) {
            names.push(stem.to_owned());
        }
    }
}
