//! Bounded reuse of immutable source snapshots at the environment boundary.

use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone, PartialEq, Eq)]
pub(super) struct SourceKey {
    pub root: Option<PathBuf>,
    pub fingerprint: u64,
}

pub(super) struct SnapshotCache<T> {
    entries: Mutex<Vec<(SourceKey, Arc<T>)>>,
}

impl<T> SnapshotCache<T> {
    pub const fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn get_or_load(
        &self,
        key: SourceKey,
        load: impl FnOnce() -> Result<T, String>,
    ) -> Result<Arc<T>, String> {
        {
            let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
            if let Some((_, value)) = entries.iter().find(|(cached, _)| *cached == key) {
                return Ok(Arc::clone(value));
            }
        }
        // Filesystem work and parsing happen outside the cache lock. Failures are
        // not retained; a later request can recover without restarting the process.
        let value = Arc::new(load()?);
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
        if let Some((_, cached)) = entries.iter().find(|(cached, _)| *cached == key) {
            return Ok(Arc::clone(cached));
        }
        let evicted = (entries.len() == 4).then(|| entries.remove(0));
        entries.push((key, Arc::clone(&value)));
        drop(entries);
        // Closing source handles or freeing large snapshots must not hold the lock.
        drop(evicted);
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_include_source_and_revision_failures_retry_and_retention_is_bounded() {
        let cache = SnapshotCache::new();
        let key = |root: &str, fingerprint| SourceKey {
            root: Some(root.into()),
            fingerprint,
        };
        assert!(cache
            .get_or_load(key("a", 1), || Err("unavailable".into()))
            .is_err());
        let a = cache.get_or_load(key("a", 1), || Ok(10)).unwrap();
        assert!(Arc::ptr_eq(
            &a,
            &cache
                .get_or_load(key("a", 1), || panic!("unnecessary reload"))
                .unwrap()
        ));
        assert_eq!(*cache.get_or_load(key("b", 1), || Ok(20)).unwrap(), 20);
        assert_eq!(*cache.get_or_load(key("a", 2), || Ok(30)).unwrap(), 30);
        for revision in 3..10 {
            cache.get_or_load(key("a", revision), || Ok(40)).unwrap();
        }
        assert_eq!(cache.entries.lock().unwrap().len(), 4);
        assert_eq!(*a, 10); // Eviction does not invalidate an active session.
    }
}
