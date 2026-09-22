//! Bounded semantic classifications shared by reconstruction consumers.
//!
//! These facts describe static call/instruction evidence. They do not claim that a
//! call succeeded, that two handles identify the same runtime object, or that an
//! inferred acquire/release pair executed on one concrete path.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::Serialize;

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct CallEvidence {
    pub rva: u32,
    pub block_start: u32,
    pub name: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemanticEvent {
    pub rva: u32,
    pub name: String,
    pub kind: String,
    pub action: String,
    pub confidence: &'static str,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ResourceLifetime {
    pub kind: String,
    pub acquire_rva: u32,
    pub release_rva: u32,
    pub confidence: &'static str,
    pub limitation: &'static str,
}

#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SemanticSummary {
    pub resources: Vec<SemanticEvent>,
    pub lifetimes: Vec<ResourceLifetime>,
    pub synchronization: Vec<SemanticEvent>,
    pub scaffolding_blocks: Vec<u32>,
    pub scaffolding: Vec<SemanticEvent>,
}

fn normalized(name: &str) -> String {
    name.rsplit('!')
        .next()
        .unwrap_or(name)
        .trim_start_matches('_')
        .to_ascii_lowercase()
        .replace([' ', '$'], "")
}

pub fn scaffolding_kind(name: &str) -> Option<&'static str> {
    let name = normalized(name);
    let patterns: &[(&str, &[&str])] = &[
        (
            "formatting",
            &["write_fmt", "format_args", "fmt::", "std::io::stdio"],
        ),
        (
            "panic",
            &[
                "unwrap_failed",
                "panic_",
                "panicking::",
                "rust_begin_unwind",
            ],
        ),
        (
            "unwind",
            &[
                "panic_cannot_unwind",
                "unwind_resume",
                "_cxxthrowexception",
                "__cxa_",
            ],
        ),
        (
            "drop-glue",
            &[
                "drop_in_place",
                "drop_glue",
                "ehvector_destructor_iterator",
                "scalar_deleting_destructor",
            ],
        ),
        (
            "allocation",
            &[
                "rust_alloc",
                "rust_dealloc",
                "alloc::alloc",
                "operatornew",
                "operatordelete",
            ],
        ),
        (
            "runtime-check",
            &[
                "__security_check_cookie",
                "__chkstk",
                "invalid_parameter",
                "terminate",
            ],
        ),
    ];
    patterns.iter().find_map(|(kind, names)| {
        names
            .iter()
            .any(|part| name.contains(part))
            .then_some(*kind)
    })
}

fn resource_call(name: &str) -> Option<(&'static str, &'static str)> {
    let name = normalized(name);
    let exact = name.split('<').next().unwrap_or(&name);
    if ["createfilea", "createfilew", "openfile", "fopen", "_wfopen"]
        .iter()
        .any(|part| exact.ends_with(part))
        || name.contains("openoptions::open")
        || name.contains("file::open")
    {
        Some(("file", "acquire"))
    } else if exact.ends_with("closehandle")
        || exact.ends_with("fclose")
        || name.contains("file::drop")
    {
        Some(("file-or-handle", "release"))
    } else if [
        "createthread",
        "openprocess",
        "openthread",
        "createeventa",
        "createeventw",
    ]
    .iter()
    .any(|part| exact.ends_with(part))
    {
        Some(("handle", "acquire"))
    } else if name.contains("box::new")
        || name.contains("rust_alloc")
        || exact.ends_with("malloc")
        || exact.ends_with("operatornew")
    {
        Some(("heap", "acquire"))
    } else if name.contains("drop_in_place")
        || name.contains("rust_dealloc")
        || exact.ends_with("free")
        || exact.ends_with("operatordelete")
    {
        Some(("heap-or-owner", "release"))
    } else if name.contains("box::into_raw") {
        Some(("heap-owner", "transfer-out"))
    } else if name.contains("box::from_raw") {
        Some(("heap-owner", "transfer-in"))
    } else {
        None
    }
}

fn synchronization_call(name: &str) -> Option<(&'static str, &'static str)> {
    let name = normalized(name);
    if name.contains("entercriticalsection")
        || name.contains("acquiresrwlock")
        || name.ends_with("mutex::lock")
        || name.ends_with("rwlock::read")
        || name.ends_with("rwlock::write")
    {
        Some(("lock", "acquire"))
    } else if name.contains("leavecriticalsection")
        || name.contains("releasesrwlock")
        || name.ends_with("mutexguard::drop")
        || name.ends_with("rwlockreadguard::drop")
        || name.ends_with("rwlockwriteguard::drop")
    {
        Some(("lock", "release"))
    } else if name.contains("waitforsingleobject")
        || name.contains("waitformultipleobjects")
        || name.ends_with("condvar::wait")
        || name.ends_with("thread::join")
    {
        Some(("wait", "wait"))
    } else if name.contains("setevent")
        || name.contains("releasesemaphore")
        || name.ends_with("condvar::notify_one")
        || name.ends_with("condvar::notify_all")
    {
        Some(("signal", "signal"))
    } else {
        None
    }
}

pub fn instruction_synchronization(mnemonic: &str, has_lock_prefix: bool) -> Option<&'static str> {
    if has_lock_prefix {
        Some("atomic read-modify-write")
    } else if matches!(mnemonic, "mfence" | "lfence" | "sfence") {
        Some("memory fence")
    } else {
        None
    }
}

pub fn analyze_calls(calls: &[CallEvidence]) -> SemanticSummary {
    let mut summary = SemanticSummary::default();
    let mut pending = BTreeMap::<String, VecDeque<u32>>::new();
    let mut scaffolding_blocks = BTreeSet::new();
    for call in calls.iter().take(100_000) {
        if let Some((kind, action)) = resource_call(&call.name) {
            summary.resources.push(SemanticEvent {
                rva: call.rva,
                name: call.name.clone(),
                kind: kind.to_owned(),
                action: action.to_owned(),
                confidence: "call-target",
            });
            if action == "acquire" {
                pending
                    .entry(kind.to_owned())
                    .or_default()
                    .push_back(call.rva);
            } else if action == "release" {
                let compatible = if kind == "file-or-handle" {
                    ["file", "handle"]
                        .into_iter()
                        .find_map(|key| pending.get_mut(key).and_then(VecDeque::pop_front))
                } else if kind == "heap-or-owner" {
                    ["heap", "heap-owner"]
                        .into_iter()
                        .find_map(|key| pending.get_mut(key).and_then(VecDeque::pop_front))
                } else {
                    pending.get_mut(kind).and_then(VecDeque::pop_front)
                };
                if let Some(acquire_rva) = compatible {
                    summary.lifetimes.push(ResourceLifetime {
                        kind: kind.to_owned(),
                        acquire_rva,
                        release_rva: call.rva,
                        confidence: "ordered-call-pair",
                        limitation: "static order only; object identity and path feasibility are not proven",
                    });
                }
            }
        }
        if let Some((kind, action)) = synchronization_call(&call.name) {
            summary.synchronization.push(SemanticEvent {
                rva: call.rva,
                name: call.name.clone(),
                kind: kind.to_owned(),
                action: action.to_owned(),
                confidence: "call-target",
            });
        }
        if let Some(kind) = scaffolding_kind(&call.name) {
            // Allocators frequently appear in otherwise useful user blocks. Keep
            // the call as a collapse candidate, but do not classify its entire
            // basic block as runtime scaffolding.
            if kind != "allocation" {
                scaffolding_blocks.insert(call.block_start);
            }
            summary.scaffolding.push(SemanticEvent {
                rva: call.rva,
                name: call.name.clone(),
                kind: kind.to_owned(),
                action: "collapse-candidate".to_owned(),
                confidence: "call-target",
            });
        }
    }
    summary.scaffolding_blocks = scaffolding_blocks.into_iter().collect();
    summary
}

/// Returns a stable family key while preserving enough qualification to avoid
/// folding unrelated functions that merely share a leaf name.
pub fn monomorphization_family(name: &str) -> String {
    let without_hash = name
        .rsplit_once("::h")
        .filter(|(_, hash)| hash.len() >= 8 && hash.chars().all(|ch| ch.is_ascii_hexdigit()))
        .map(|(prefix, _)| prefix)
        .unwrap_or(name);
    let mut result = String::with_capacity(without_hash.len());
    let mut depth = 0usize;
    for ch in without_hash.chars() {
        match ch {
            '<' => {
                if depth == 0 {
                    result.push_str("<…>");
                }
                depth += 1;
            }
            '>' if depth > 0 => depth -= 1,
            _ if depth == 0 => result.push(ch),
            _ => {}
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_bounded_resource_sync_and_scaffolding_facts() {
        let calls = vec![
            CallEvidence {
                rva: 0x10,
                block_start: 0x10,
                name: "KERNEL32!CreateFileW".into(),
            },
            CallEvidence {
                rva: 0x20,
                block_start: 0x20,
                name: "std::sync::poison::mutex::Mutex::lock".into(),
            },
            CallEvidence {
                rva: 0x30,
                block_start: 0x30,
                name: "core::result::unwrap_failed".into(),
            },
            CallEvidence {
                rva: 0x40,
                block_start: 0x40,
                name: "KERNEL32!CloseHandle".into(),
            },
        ];
        let result = analyze_calls(&calls);
        assert_eq!(result.resources.len(), 2);
        assert_eq!(result.lifetimes[0].acquire_rva, 0x10);
        assert_eq!(result.synchronization.len(), 1);
        assert_eq!(result.scaffolding_blocks, vec![0x30]);
    }

    #[test]
    fn folds_only_generic_and_hash_suffixes() {
        assert_eq!(
            monomorphization_family("crate::work<Vec<u8>>::run::h0123456789abcdef"),
            "crate::work<…>::run"
        );
        assert_eq!(monomorphization_family("a::run"), "a::run");
        assert_eq!(
            monomorphization_family("ns::work<std::vector<int>>::run"),
            "ns::work<…>::run"
        );
    }
}
