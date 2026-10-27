//! Local export discovery, loaded lazily for an explicit provider instance.

use super::cache::{SnapshotCache, SourceKey};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

use crate::analysis::resolution::{ExportDictionary, ExportProvider};
use crate::formats::pe::{parse_pe, read_exports};

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

pub struct SystemExports {
    directory: Option<PathBuf>,
    dictionary: OnceLock<Arc<ExportDictionary>>,
}

impl SystemExports {
    /// Capture the selected system directory. No files are read until requested.
    pub fn discover() -> Self {
        let root = std::env::var_os("SystemRoot").or_else(|| std::env::var_os("windir"));
        Self {
            directory: root.map(PathBuf::from).map(|root| root.join("System32")),
            dictionary: OnceLock::new(),
        }
    }

    /// Use an explicit export directory, without consulting the host environment.
    pub fn from_directory(directory: impl Into<PathBuf>) -> Self {
        Self {
            directory: Some(directory.into()),
            dictionary: OnceLock::new(),
        }
    }
}

impl ExportProvider for SystemExports {
    fn dictionary(&self) -> &ExportDictionary {
        self.dictionary.get_or_init(|| {
            static CACHE: SnapshotCache<ExportDictionary> = SnapshotCache::new();
            let directory = self
                .directory
                .as_ref()
                .map(|dir| std::path::absolute(dir).unwrap_or_else(|_| dir.clone()));
            let names = module_names(directory.as_deref());
            let fingerprint = fingerprint(directory.as_deref(), &names);
            let key = SourceKey {
                root: directory.clone(),
                fingerprint,
            };
            CACHE
                .get_or_load(key, || Ok(load(directory.as_deref(), &names)))
                .expect("export loading reports unavailable sources as missing names")
        })
    }
}

fn load(system: Option<&Path>, names: &[String]) -> ExportDictionary {
    let mut dictionary = ExportDictionary::default();
    for &module in EXPORT_SOURCES {
        dictionary.add_module(module);
        let Some(raw) =
            system.and_then(|dir| crate::core::input::read_image(dir.join(module)).ok())
        else {
            continue;
        };
        let Ok(pe) = parse_pe(&raw) else { continue };
        dictionary.add_exports(
            module,
            read_exports(&pe, &raw)
                .iter()
                .map(|export| export.name.as_str()),
        );
    }
    for name in names {
        dictionary.add_module(name);
    }
    dictionary
}

fn module_names(system: Option<&Path>) -> Vec<String> {
    let mut names: Vec<_> = system
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .into_iter()
        .flatten()
        .flatten()
        .map(|entry| entry.file_name().to_string_lossy().to_ascii_lowercase())
        .filter(|name| name.ends_with(".dll") || name.ends_with(".drv") || name.ends_with(".sys"))
        .collect();
    names.sort();
    names
}

fn fingerprint(system: Option<&Path>, names: &[String]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    names.hash(&mut hasher);
    for module in EXPORT_SOURCES {
        module.hash(&mut hasher);
        let metadata = system.and_then(|dir| std::fs::metadata(dir.join(module)).ok());
        metadata.as_ref().map(|meta| meta.len()).hash(&mut hasher);
        metadata
            .and_then(|meta| meta.modified().ok())
            .hash(&mut hasher);
    }
    hasher.finish()
}
