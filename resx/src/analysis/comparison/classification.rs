use super::*;

pub(super) struct FunctionClassification<'a> {
    pub(super) name: &'a str,
    pub(super) source: &'a str,
    pub(super) confidence: u8,
    pub(super) size_bytes: usize,
    pub(super) insn_count: usize,
    pub(super) block_count: usize,
    pub(super) edge_count: usize,
    pub(super) api_set: &'a BTreeSet<String>,
    pub(super) string_ref_count: usize,
}

pub(super) fn classify_function(input: FunctionClassification<'_>) -> (bool, String, Vec<String>) {
    let lname = normalized_name(input.name);
    let raw_name = input.name.to_ascii_lowercase();
    let mut tags = BTreeSet::new();

    if !input.api_set.is_empty() {
        tags.insert("calls-api".to_owned());
    }
    if input.string_ref_count > 0 {
        tags.insert("string-ref".to_owned());
    }
    if input.insn_count >= 96 || input.block_count >= 18 {
        tags.insert("large".to_owned());
    }
    if input.edge_count > input.block_count.max(1) {
        tags.insert("branchy".to_owned());
    }
    if input
        .api_set
        .iter()
        .any(|api| api.starts_with("ntoskrnl.exe!"))
    {
        tags.insert("kernel-api".to_owned());
    }
    if input.api_set.iter().any(|api| {
        api.contains("excreatecallback")
            || api.contains("obregistercallbacks")
            || api.contains("psset")
            || api.contains("cmregistercallback")
    }) {
        tags.insert("callback-registration".to_owned());
    }
    if input.api_set.iter().any(|api| {
        api.contains("virtualalloc")
            || api.contains("writeprocessmemory")
            || api.contains("ntwritevirtualmemory")
    }) {
        tags.insert("process-memory-api".to_owned());
    }

    let runtime_helper = [
        "__security_",
        "__gs",
        "__guard_",
        "_guard_",
        "__chkstk",
        "_chkstk",
        "memcpy",
        "memmove",
        "memset",
        "strlen",
        "strnlen",
        "guard_dispatch_icall",
        "guard_check_icall",
    ]
    .iter()
    .any(|prefix| raw_name.starts_with(prefix) || lname.starts_with(prefix));

    let mut reason = String::new();
    let source_lower = input.source.to_ascii_lowercase();
    let anonymous_unwind = source_lower.contains(".pdata") && lname.is_empty();
    let named_api_count = input
        .api_set
        .iter()
        .filter(|api| !api.starts_with('['))
        .count();

    if input.size_bytes <= 8 || input.insn_count <= 2 {
        reason = "tiny stub".to_owned();
    } else if runtime_helper {
        reason = "compiler/runtime helper".to_owned();
    } else if anonymous_unwind && input.api_set.iter().any(|api| is_common_runtime_api(api)) {
        reason = "compiler/runtime support".to_owned();
    } else if anonymous_unwind
        && input.string_ref_count == 0
        && named_api_count == 0
        && input.size_bytes <= 1024
    {
        reason = "anonymous unwind/support function".to_owned();
    } else if input.confidence <= 35 && input.source.to_ascii_lowercase().contains("prologue") {
        reason = "low-confidence prologue hint".to_owned();
    }

    let noise = !reason.is_empty();
    (noise, reason, tags.into_iter().collect())
}

pub(super) fn is_common_runtime_api(api: &str) -> bool {
    [
        "deletecriticalsection",
        "encodepointer",
        "exitprocess",
        "flsalloc",
        "flsfree",
        "flsgetvalue",
        "flssetvalue",
        "freeenvironmentstrings",
        "getacp",
        "getcommandline",
        "getcpinfo",
        "getcurrentprocess",
        "getcurrentprocessid",
        "getcurrentthreadid",
        "getenvironmentstrings",
        "getlasterror",
        "getmodulefilename",
        "getmodulehandle",
        "getprocaddress",
        "getstartupinfo",
        "getstdhandle",
        "getsystemtimeasfiletime",
        "heapalloc",
        "heapfree",
        "initializecriticalsection",
        "isdebuggerpresent",
        "queryperformancecounter",
        "setlasterror",
        "sleep",
        "terminateprocess",
        "tlsalloc",
        "tlsfree",
        "tlsgetvalue",
        "tlssetvalue",
        "unhandledexceptionfilter",
        "widechartomultibyte",
    ]
    .iter()
    .any(|needle| api.contains(needle))
}

pub(super) fn prune_nested_function_hints(
    functions: &mut Vec<FunctionFingerprint>,
    notes: &mut Vec<String>,
    side: &str,
) {
    functions.sort_by(|a, b| {
        a.rva
            .cmp(&b.rva)
            .then_with(|| b.confidence.cmp(&a.confidence))
            .then_with(|| b.size_bytes.cmp(&a.size_bytes))
    });
    let mut keep: Vec<FunctionFingerprint> = Vec::new();
    let mut suppressed = 0usize;
    for fp in functions.drain(..) {
        let fp_end = fp.rva.saturating_add(fp.size_bytes as u32);
        let nested = keep.iter().any(|parent| {
            let parent_end = parent.rva.saturating_add(parent.size_bytes as u32);
            fp.rva > parent.rva
                && fp_end <= parent_end
                && parent.size_bytes >= fp.size_bytes.saturating_add(16)
                && fp.confidence < parent.confidence
                && fp.confidence <= 55
                && normalized_name(&fp.name).is_empty()
        });
        if nested {
            suppressed += 1;
        } else {
            keep.push(fp);
        }
    }
    keep.sort_by_key(|item| item.rva);
    *functions = keep;
    if suppressed > 0 {
        notes.push(format!(
            "{}: suppressed {} nested low-confidence function hints",
            side, suppressed
        ));
    }
}

pub(super) fn indexed_function_ref(fp: &IndexedFunction) -> FunctionRef {
    FunctionRef {
        name: fp.name.clone(),
        rva: fp.rva.clone(),
        section: fp.section.clone(),
        source: fp.source.clone(),
        confidence: fp.confidence,
        size_bytes: fp.size_bytes,
        insn_count: fp.insn_count,
        block_count: fp.block_count,
        edge_count: fp.edge_count,
        semantic_hash: fp.semantic_hash.clone(),
        cfg_hash: fp.cfg_hash.clone(),
        api_hash: fp.api_hash.clone(),
        fuzzy_hash: fp.fuzzy_hash.clone(),
        noise: fp.noise,
        noise_reason: fp.noise_reason.clone(),
        trait_tags: fp.trait_tags.clone(),
    }
}

pub(super) fn metadata_similarity_score(sample: &IndexedImage, candidate: &IndexedImage) -> u8 {
    let import_score = score_float(set_similarity(
        &vec_to_set(&sample.imports),
        &vec_to_set(&candidate.imports),
    ));
    let export_score = score_float(set_similarity(
        &vec_to_set(&sample.exports),
        &vec_to_set(&candidate.exports),
    ));
    let string_score = score_float(set_similarity(
        &vec_to_set(&sample.strings),
        &vec_to_set(&candidate.strings),
    ));
    ((import_score as f64 * 0.45) + (export_score as f64 * 0.35) + (string_score as f64 * 0.20))
        .round()
        .min(100.0) as u8
}

pub(super) fn signature_hints_from_diff(
    matches: &[FunctionMatch],
    metadata: &MetadataDelta,
) -> SignatureHints {
    let stable_semantic_hashes = matches
        .iter()
        .filter(|m| !m.left.noise && !m.right.noise)
        .filter(|m| matches!(m.tier.as_str(), "exact" | "strong"))
        .map(|m| m.left.semantic_hash.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(32)
        .collect::<Vec<_>>();
    let stable_function_names = matches
        .iter()
        .filter(|m| !m.left.noise && !m.right.noise)
        .filter_map(|m| {
            let name = normalized_name(&m.left.name);
            (!name.is_empty()).then_some(m.left.name.clone())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(32)
        .collect::<Vec<_>>();

    let shared_imports = matches
        .iter()
        .flat_map(|m| m.evidence.shared_apis.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(24)
        .collect::<Vec<_>>();
    let mut notes =
        vec!["semantic hashes are RESX normalized-code tokens, not raw byte signatures".to_owned()];
    if metadata.common_strings > 0 {
        notes.push(format!(
            "{} normalized strings are shared; use --json for metadata deltas",
            metadata.common_strings
        ));
    }

    SignatureHints {
        stable_semantic_hashes,
        stable_function_names,
        shared_imports,
        shared_strings: Vec::new(),
        notes,
    }
}

pub(super) fn signature_hints_from_hunt(
    matches: &[HuntFunctionMatch],
    sample: &IndexedImage,
    candidate: &IndexedImage,
) -> SignatureHints {
    let stable_semantic_hashes = matches
        .iter()
        .filter(|m| !m.sample.noise && !m.candidate.noise)
        .filter(|m| matches!(m.tier.as_str(), "exact" | "strong"))
        .map(|m| m.sample.semantic_hash.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(32)
        .collect::<Vec<_>>();
    let stable_function_names = matches
        .iter()
        .filter(|m| !m.sample.noise && !m.candidate.noise)
        .filter_map(|m| {
            let name = normalized_name(&m.sample.name);
            (!name.is_empty()).then_some(m.sample.name.clone())
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .take(32)
        .collect::<Vec<_>>();
    let sample_imports = vec_to_set(&sample.imports);
    let candidate_imports = vec_to_set(&candidate.imports);
    let sample_strings = vec_to_set(&sample.strings);
    let candidate_strings = vec_to_set(&candidate.strings);

    SignatureHints {
        stable_semantic_hashes,
        stable_function_names,
        shared_imports: sample_imports
            .intersection(&candidate_imports)
            .take(24)
            .cloned()
            .collect(),
        shared_strings: sample_strings
            .intersection(&candidate_strings)
            .filter(|s| s.len() >= 5)
            .take(24)
            .cloned()
            .collect(),
        notes: vec![
            "semantic hashes are RESX normalized-code tokens, not raw byte signatures".to_owned(),
        ],
    }
}

pub(super) fn family_tags(
    summary: &DiffSummary,
    metadata_score: u8,
    sample: &IndexedImage,
    candidate: &IndexedImage,
) -> Vec<String> {
    let mut tags = BTreeSet::new();
    if summary.unique_similarity_score >= 90 && summary.left_function_coverage >= 60 {
        tags.insert("shared-codebase".to_owned());
    }
    if summary.exact_matches >= 8 && summary.changed_matches > 0 {
        tags.insert("variant-build".to_owned());
    }
    if summary.left_function_coverage >= 70 && summary.right_function_coverage < 50 {
        tags.insert("sample-is-subset".to_owned());
    }
    if summary.right_function_coverage >= 70 && summary.left_function_coverage < 50 {
        tags.insert("candidate-is-subset".to_owned());
    }
    if summary.unique_similarity_score >= 75 && metadata_score < 45 {
        tags.insert("metadata-or-string-renamed".to_owned());
    }
    for tag in sample
        .traits
        .tags
        .iter()
        .filter(|tag| candidate.traits.tags.contains(tag))
    {
        tags.insert(format!("shared-{tag}"));
    }
    tags.into_iter().collect()
}
