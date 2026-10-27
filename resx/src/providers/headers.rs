//! Windows SDK discovery and disk caching, separate from header interpretation.

use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

use super::cache::{SnapshotCache, SourceKey};
use super::watch::DirectoryWatch;
use crate::analysis::headers::HeaderIndex;

// Keep the existing on-disk cache format compatible.
const FORMAT: u32 = 2;
const SCANNED: &[&str] = &["um", "shared", "ucrt", "km"];

/// One explicit SDK snapshot. Reuse it for a request; create another to refresh.
pub struct SdkHeaders {
    directory: PathBuf,
    cache: Option<PathBuf>,
    index: OnceLock<Result<Arc<HeaderIndex>, String>>,
}

impl SdkHeaders {
    /// `None` disables disk caching. Construction performs no filesystem work.
    pub fn new(directory: impl Into<PathBuf>, cache: Option<PathBuf>) -> Self {
        Self {
            directory: directory.into(),
            cache,
            index: OnceLock::new(),
        }
    }

    pub fn get(&self) -> Result<Arc<HeaderIndex>, String> {
        self.index
            .get_or_init(|| load_from(&self.directory, self.cache.as_deref()).map(Arc::new))
            .clone()
    }
}

/// Compatibility convenience function using the existing per-user disk cache.
pub fn load(dir: &Path) -> Result<HeaderIndex, String> {
    load_from(dir, cache_dir().as_deref())
}

/// CLI adapter. Load once at the command boundary and pass the index to analyses.
pub fn configured(dir: Option<&str>) -> Option<Arc<HeaderIndex>> {
    let dir = dir.filter(|dir| !dir.is_empty())?;
    static CACHE: ConfiguredHeaders = ConfiguredHeaders::new();
    match configured_in(Path::new(dir), cache_dir().as_deref(), &CACHE) {
        Ok(index) => Some(index),
        Err(error) => {
            eprintln!("[resx] Windows headers unavailable: {error}");
            None
        }
    }
}

/// The directory holding `um/windows.h` for `dir`: an SDK version directory, its
/// `Include` parent, the kit root, or (for convenience) any directory from which the
/// newest installed Windows 10/11 SDK is found.
pub fn resolve_root(dir: &Path) -> Option<PathBuf> {
    let has_headers = |path: &Path| path.join("um").join("windows.h").is_file();
    if has_headers(dir) {
        return Some(dir.to_path_buf());
    }
    let newest = |include: &Path| -> Option<PathBuf> {
        let mut versions: Vec<PathBuf> = std::fs::read_dir(include)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| has_headers(path))
            .collect();
        versions.sort();
        versions.pop()
    };
    newest(dir).or_else(|| newest(&dir.join("Include")))
}

/// An installed Windows SDK, for pointing out where Windows.h lives when the
/// configured directory (an MSVC toolset, say) does not have it.
pub fn installed_sdk() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::var_os("WindowsSdkDir") {
        candidates.push(PathBuf::from(dir));
    }
    for var in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(dir) = std::env::var_os(var) {
            candidates.push(PathBuf::from(dir).join("Windows Kits").join("10"));
        }
    }
    candidates.iter().find_map(|dir| resolve_root(dir))
}

/// Loads the index for `dir` from the per-user cache, building it first if the
/// headers changed since it was written.
fn configured_in(
    dir: &Path,
    cache_root: Option<&Path>,
    cache: &ConfiguredHeaders,
) -> Result<Arc<HeaderIndex>, String> {
    let root = source_root(dir)?;
    let watched = cache.sources.get_or_load(
        SourceKey {
            root: Some(root.clone()),
            fingerprint: 0,
        },
        || Ok(WatchedSource::new(&root)),
    )?;
    let manifest = watched.manifest();
    let manifest = manifest.get_or_init(|| manifest_from(&root));
    let key = SourceKey {
        root: Some(root.clone()),
        fingerprint: manifest.fingerprint,
    };
    cache.indices.get_or_load(key, || {
        load_snapshot(&root, &manifest.files, manifest.fingerprint, cache_root)
    })
}

struct ConfiguredHeaders {
    sources: SnapshotCache<WatchedSource>,
    indices: SnapshotCache<HeaderIndex>,
}

impl ConfiguredHeaders {
    const fn new() -> Self {
        Self {
            sources: SnapshotCache::new(),
            indices: SnapshotCache::new(),
        }
    }
}

struct HeaderManifest {
    files: HeaderFiles,
    fingerprint: u64,
}

struct WatchedSource {
    state: Mutex<SourceState>,
}

struct SourceState {
    watch: Option<DirectoryWatch>,
    manifest: Arc<OnceLock<HeaderManifest>>,
}

impl WatchedSource {
    fn new(root: &Path) -> Self {
        Self {
            state: Mutex::new(SourceState {
                // Register before the first scan so concurrent edits are noticed.
                watch: DirectoryWatch::new(root),
                manifest: Arc::new(OnceLock::new()),
            }),
        }
    }

    fn manifest(&self) -> Arc<OnceLock<HeaderManifest>> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let changed = state.watch.as_mut().and_then(DirectoryWatch::changed);
        if changed.is_none() {
            state.watch = None;
        }
        if changed != Some(false) {
            state.manifest = Arc::new(OnceLock::new());
        }
        // Each revision gets its own slot. An older in-flight scan cannot replace
        // a newer revision, and enumeration runs after releasing this mutex.
        Arc::clone(&state.manifest)
    }
}

type HeaderFiles = Vec<(String, PathBuf)>;

fn source_root(dir: &Path) -> Result<PathBuf, String> {
    let root = resolve_root(dir).ok_or_else(|| {
        format!(
            "{} has no um\\windows.h; point --headers at a Windows SDK Include directory",
            dir.display()
        )
    })?;
    std::path::absolute(root).map_err(|e| e.to_string())
}

fn manifest_from(root: &Path) -> HeaderManifest {
    let files = header_files(root);
    let fingerprint = fingerprint(root, &files);
    HeaderManifest { files, fingerprint }
}

fn load_from(dir: &Path, cache_root: Option<&Path>) -> Result<HeaderIndex, String> {
    let root = source_root(dir)?;
    let manifest = manifest_from(&root);
    load_snapshot(&root, &manifest.files, manifest.fingerprint, cache_root)
}

fn load_snapshot(
    root: &Path,
    files: &[(String, PathBuf)],
    fingerprint: u64,
    cache_root: Option<&Path>,
) -> Result<HeaderIndex, String> {
    let cache = cache_root.map(|dir| dir.join(format!("headers-{fingerprint:016x}.json")));
    if let Some(index) = cache
        .as_ref()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<HeaderIndex>(&bytes).ok())
    {
        return Ok(index.finish());
    }
    let index = build(root, files)?;
    if let Some(path) = cache {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec(&index) {
            let _ = std::fs::write(path, bytes);
        }
    }
    Ok(index)
}

fn cache_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|dir| dir.join("RESX").join("cache"))
}

fn header_files(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for sub in SCANNED {
        let mut stack = vec![root.join(sub)];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut entries: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    stack.push(path);
                } else if path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("h"))
                {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.push((relative, path));
                }
            }
        }
    }
    out
}

fn fingerprint(root: &Path, files: &[(String, PathBuf)]) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    FORMAT.hash(&mut hasher);
    root.to_string_lossy()
        .to_ascii_lowercase()
        .hash(&mut hasher);
    for (relative, path) in files {
        relative.hash(&mut hasher);
        if let Ok(meta) = std::fs::metadata(path) {
            meta.len().hash(&mut hasher);
            if let Ok(modified) = meta.modified() {
                modified.hash(&mut hasher);
            }
        }
    }
    hasher.finish()
}

fn build(root: &Path, files: &[(String, PathBuf)]) -> Result<HeaderIndex, String> {
    if files.is_empty() {
        return Err(format!("no headers under {}", root.display()));
    }
    // Stream each file through the pure builder; do not retain all header text.
    let sources = files.iter().filter_map(|(relative, path)| {
        std::fs::read(path).ok().map(|bytes| {
            (
                relative.as_str(),
                String::from_utf8_lossy(&bytes).into_owned(),
            )
        })
    });
    Ok(HeaderIndex::from_sources(
        root.to_string_lossy().into_owned(),
        sources,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct TempRoot(PathBuf);
    impl TempRoot {
        fn new() -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "resx-sdk-provider-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn header(&self, sdk: &str, text: &str) -> PathBuf {
            let root = self.0.join(sdk);
            std::fs::create_dir_all(root.join("um")).unwrap();
            std::fs::write(root.join("um/windows.h"), text).unwrap();
            root
        }
    }
    impl Drop for TempRoot {
        fn drop(&mut self) {
            // Only the unique directory successfully created by this test is owned.
            std::fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn unavailable_notifications_rescan_instead_of_reusing_a_manifest() {
        let source = WatchedSource {
            state: Mutex::new(SourceState {
                watch: None,
                manifest: Arc::new(OnceLock::new()),
            }),
        };
        assert!(!Arc::ptr_eq(&source.manifest(), &source.manifest()));
    }

    #[cfg(windows)]
    #[test]
    fn notifications_reuse_unchanged_manifests_and_invalidate_edits_and_new_files() {
        let temp = TempRoot::new();
        let root = temp.header("sdk", "int First(void);");
        let source = WatchedSource::new(&root);
        assert!(source.state.lock().unwrap().watch.is_some());
        // Windows may finish metadata writes from setup after the handle opens.
        // Wait for those events to settle before asserting unchanged reuse.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let original = loop {
            let current = source.manifest();
            current.get_or_init(|| manifest_from(&root));
            std::thread::sleep(std::time::Duration::from_millis(10));
            if Arc::ptr_eq(&current, &source.manifest()) {
                break current;
            }
            assert!(std::time::Instant::now() < deadline, "source never settled");
        };
        let first_fingerprint = original.get().unwrap().fingerprint;

        let await_revision = |old: &Arc<OnceLock<HeaderManifest>>| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            loop {
                let new = source.manifest();
                if !Arc::ptr_eq(old, &new) {
                    return new;
                }
                assert!(std::time::Instant::now() < deadline, "notification missing");
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        };
        temp.header("sdk", "int Updated(int count);");
        let edited = await_revision(&original);
        let manifest = edited.get_or_init(|| manifest_from(&root));
        assert_ne!(first_fingerprint, manifest.fingerprint);
        assert_eq!(manifest.files.len(), 1);
        std::fs::write(root.join("um/new.h"), "int Added(void);").unwrap();
        let added = await_revision(&edited);
        assert_eq!(added.get_or_init(|| manifest_from(&root)).files.len(), 2);
        // Old readers retain their snapshot through both invalidations.
        assert_eq!(original.get().unwrap().fingerprint, first_fingerprint);
    }

    #[test]
    fn sdk_snapshots_are_lazy_isolated_and_refresh_between_requests() {
        let temp = TempRoot::new();
        let a = temp.header("alpha", "int Alpha(void);");
        let b = temp.header("beta", "int Beta(void);");
        let cache = temp.0.join("cache");
        let first = SdkHeaders::new(&a, Some(cache.clone()));
        let second = SdkHeaders::new(&b, Some(cache.clone()));
        assert!(first.index.get().is_none());
        assert!(!cache.exists());
        let memory_cache = ConfiguredHeaders::new();
        let cached = configured_in(&a, Some(&cache), &memory_cache).unwrap();
        assert!(Arc::ptr_eq(
            &cached,
            &configured_in(&a, Some(&cache), &memory_cache).unwrap()
        ));
        let index = first.get().unwrap();
        assert!(index.prototype("Alpha").is_some());
        assert!(index.prototype("Beta").is_none());
        assert!(second.get().unwrap().prototype("Beta").is_some());
        temp.header("alpha", "int UpdatedAlpha(int count);");
        assert!(Arc::ptr_eq(&index, &first.get().unwrap()));
        let cached_refresh = configured_in(&a, Some(&cache), &memory_cache).unwrap();
        assert!(cached_refresh.prototype("UpdatedAlpha").is_some());
        assert!(!Arc::ptr_eq(&cached, &cached_refresh));
        let refreshed = SdkHeaders::new(&a, Some(cache)).get().unwrap();
        assert!(refreshed.prototype("UpdatedAlpha").is_some());
        assert!(refreshed.prototype("Alpha").is_none());
    }

    #[test]
    fn corrupt_disk_cache_is_rebuilt_and_missing_sdk_does_not_poison_new_requests() {
        let temp = TempRoot::new();
        let root = temp.0.join("sdk");
        assert!(SdkHeaders::new(&root, None).get().is_err());
        temp.header("sdk", "int Available(void);");
        let cache = temp.0.join("cache");
        assert!(SdkHeaders::new(&root, Some(cache.clone())).get().is_ok());
        let cached = std::fs::read_dir(&cache)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        std::fs::write(&cached, b"{broken").unwrap();
        let rebuilt = SdkHeaders::new(&root, Some(cache)).get().unwrap();
        assert!(rebuilt.prototype("Available").is_some());
        assert!(serde_json::from_slice::<HeaderIndex>(&std::fs::read(cached).unwrap()).is_ok());
    }
}
