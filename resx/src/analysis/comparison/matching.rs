use super::*;

pub(super) fn candidate_matches(
    left: &[FunctionFingerprint],
    right: &[FunctionFingerprint],
    min_score: u8,
) -> Vec<CandidateMatch> {
    let mut by_semantic: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut by_cfg_hash: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut by_api_hash: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut by_fuzzy_hash: HashMap<u64, Vec<usize>> = HashMap::new();
    let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
    let mut by_block_count: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (idx, fp) in right.iter().enumerate() {
        by_semantic.entry(fp.semantic_hash).or_default().push(idx);
        by_cfg_hash.entry(fp.cfg_hash).or_default().push(idx);
        if !fp.api_set.is_empty() {
            by_api_hash.entry(fp.api_hash).or_default().push(idx);
        }
        if fp.fuzzy_hash != 0 {
            by_fuzzy_hash.entry(fp.fuzzy_hash).or_default().push(idx);
        }
        let name = normalized_name(&fp.name);
        if !name.is_empty() {
            by_name.entry(name).or_default().push(idx);
        }
        by_block_count.entry(fp.block_count).or_default().push(idx);
    }

    let mut candidates = Vec::new();
    for (left_idx, l) in left.iter().enumerate() {
        let mut right_indices = HashSet::new();
        if let Some(indices) = by_semantic.get(&l.semantic_hash) {
            right_indices.extend(indices.iter().copied());
        }
        if let Some(indices) = by_cfg_hash.get(&l.cfg_hash) {
            right_indices.extend(indices.iter().copied());
        }
        if !l.api_set.is_empty() {
            if let Some(indices) = by_api_hash.get(&l.api_hash) {
                right_indices.extend(indices.iter().copied());
            }
        }
        if l.fuzzy_hash != 0 {
            if let Some(indices) = by_fuzzy_hash.get(&l.fuzzy_hash) {
                right_indices.extend(indices.iter().copied());
            }
        }
        let name = normalized_name(&l.name);
        if !name.is_empty() {
            if let Some(indices) = by_name.get(&name) {
                right_indices.extend(indices.iter().copied());
            }
        }
        if l.block_count > 0 {
            let low = (l.block_count / 4).saturating_sub(4);
            let high = l.block_count.saturating_mul(4).saturating_add(4);
            for (_, indices) in by_block_count.range(low..=high) {
                right_indices.extend(indices.iter().copied());
            }
        }
        if right_indices.is_empty() && left.len().saturating_mul(right.len()) <= 250_000 {
            right_indices.extend(0..right.len());
        }

        for right_idx in right_indices {
            let r = &right[right_idx];
            if !plausible_pair(l, r) {
                continue;
            }
            let (score, evidence) = score_pair(l, r);
            if score >= min_score {
                candidates.push(CandidateMatch {
                    left_idx,
                    right_idx,
                    score,
                    evidence,
                });
            }
        }
    }
    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| left[a.left_idx].rva.cmp(&left[b.left_idx].rva))
            .then_with(|| right[a.right_idx].rva.cmp(&right[b.right_idx].rva))
    });
    candidates
}

pub(super) fn score_indexed_images(
    sample: &IndexedImage,
    candidate: &IndexedImage,
    min_score: u8,
) -> Option<HuntCandidate> {
    let mut candidates = Vec::new();
    for (left_idx, l) in sample.functions.iter().enumerate() {
        for (right_idx, r) in candidate.functions.iter().enumerate() {
            if !plausible_indexed_pair(l, r) {
                continue;
            }
            let (score, evidence) = score_indexed_pair(l, r);
            if score >= min_score {
                candidates.push(CandidateMatch {
                    left_idx,
                    right_idx,
                    score,
                    evidence,
                });
            }
        }
    }
    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| {
                sample.functions[a.left_idx]
                    .rva
                    .cmp(&sample.functions[b.left_idx].rva)
            })
            .then_with(|| {
                candidate.functions[a.right_idx]
                    .rva
                    .cmp(&candidate.functions[b.right_idx].rva)
            })
    });

    let mut matched_left = HashSet::new();
    let mut matched_right = HashSet::new();
    let mut matches = Vec::new();
    for hit in candidates {
        if matched_left.contains(&hit.left_idx) || matched_right.contains(&hit.right_idx) {
            continue;
        }
        matched_left.insert(hit.left_idx);
        matched_right.insert(hit.right_idx);
        let l = &sample.functions[hit.left_idx];
        let r = &candidate.functions[hit.right_idx];
        matches.push(HuntFunctionMatch {
            tier: tier(hit.score).to_owned(),
            score: hit.score,
            sample: indexed_function_ref(l),
            candidate: indexed_function_ref(r),
            evidence: hit.evidence,
        });
    }

    if matches.is_empty() {
        return None;
    }

    let summary = build_indexed_summary(&sample.functions, &candidate.functions, &matches);
    let metadata_score = metadata_similarity_score(sample, candidate);
    let score = ((summary.similarity_score as f64 * 0.70)
        + (summary.unique_similarity_score as f64 * 0.20)
        + (metadata_score as f64 * 0.10))
        .round()
        .clamp(0.0, 100.0) as u8;
    if score < min_score && summary.unique_similarity_score < min_score {
        return None;
    }

    let signature_hints = signature_hints_from_hunt(&matches, sample, candidate);
    let family_tags = family_tags(&summary, metadata_score, sample, candidate);
    let mut top_matches = matches;
    top_matches.sort_by(|a, b| {
        match_noise_rank(a.sample.noise || a.candidate.noise)
            .cmp(&match_noise_rank(b.sample.noise || b.candidate.noise))
            .then_with(|| match_name_rank(&a.sample.name).cmp(&match_name_rank(&b.sample.name)))
            .then_with(|| b.score.cmp(&a.score))
            .then_with(|| a.sample.rva.cmp(&b.sample.rva))
    });
    top_matches.truncate(12);

    Some(HuntCandidate {
        rank: 0,
        path: candidate.summary.path.clone(),
        name: candidate.summary.name.clone(),
        arch: candidate.summary.arch.clone(),
        score,
        unique_score: summary.unique_similarity_score,
        metadata_score,
        left_coverage: summary.left_function_coverage,
        right_coverage: summary.right_function_coverage,
        matched_functions: summary.matched_functions,
        exact_matches: summary.exact_matches,
        strong_matches: summary.strong_matches,
        changed_matches: summary.changed_matches,
        weak_matches: summary.weak_matches,
        noisy_matches: summary.noisy_matches,
        family_tags,
        signature_hints,
        top_matches,
    })
}

pub(super) fn match_noise_rank(noise: bool) -> u8 {
    if noise {
        1
    } else {
        0
    }
}

pub(super) fn match_name_rank(name: &str) -> u8 {
    if normalized_name(name).is_empty() {
        1
    } else {
        0
    }
}

pub(super) fn plausible_indexed_pair(l: &IndexedFunction, r: &IndexedFunction) -> bool {
    if l.semantic_hash == r.semantic_hash {
        return true;
    }
    if l.noise || r.noise {
        let name = normalized_name(&l.name);
        return !name.is_empty()
            && name == normalized_name(&r.name)
            && ratio(l.size_bytes as f64, r.size_bytes as f64) >= 0.80;
    }
    let name = normalized_name(&l.name);
    if !name.is_empty() && name == normalized_name(&r.name) {
        return true;
    }
    if hamming_hex64(&l.fuzzy_hash, &r.fuzzy_hash) <= 16 {
        return true;
    }
    if l.block_count == 0 || r.block_count == 0 || l.insn_count == 0 || r.insn_count == 0 {
        return false;
    }
    let size_ratio = ratio(l.size_bytes as f64, r.size_bytes as f64);
    let block_delta = l.block_count.abs_diff(r.block_count);
    let insn_ratio = ratio(l.insn_count as f64, r.insn_count as f64);
    size_ratio >= 0.25
        && insn_ratio >= 0.25
        && block_delta <= l.block_count.max(r.block_count).max(4)
}

pub(super) fn score_indexed_pair(l: &IndexedFunction, r: &IndexedFunction) -> (u8, MatchEvidence) {
    let semantic_equal = l.semantic_hash == r.semantic_hash;
    let cfg_score = score_float(multiset_jaccard(&l.shape_tokens, &r.shape_tokens));
    let block_score = score_float(multiset_jaccard(&l.block_hashes, &r.block_hashes));
    let opcode_score = score_float(multiset_jaccard(&l.opcode_ngrams, &r.opcode_ngrams));
    let l_api = vec_to_set(&l.api_set);
    let r_api = vec_to_set(&r.api_set);
    let l_const = vec_to_set(&l.const_set);
    let r_const = vec_to_set(&r.const_set);
    let api_score = score_float(set_similarity(&l_api, &r_api));
    let constant_score = score_float(set_similarity(&l_const, &r_const));
    let size_score = score_float(ratio(l.size_bytes as f64, r.size_bytes as f64));
    let name_score = score_float(name_similarity(&l.name, &r.name));

    let mut score = (block_score as f64 * 0.30
        + opcode_score as f64 * 0.20
        + cfg_score as f64 * 0.15
        + api_score as f64 * 0.10
        + size_score as f64 * 0.10
        + name_score as f64 * 0.10
        + constant_score as f64 * 0.05)
        .round() as u8;
    if semantic_equal {
        score = score.max(if l.size_bytes == r.size_bytes {
            100
        } else {
            98
        });
    } else if l.cfg_hash == r.cfg_hash && l.api_hash == r.api_hash {
        score = score.max(86);
    } else if l.cfg_hash == r.cfg_hash {
        score = score.max(80);
    } else {
        let fuzzy = 64u8.saturating_sub(hamming_hex64(&l.fuzzy_hash, &r.fuzzy_hash));
        score = score.max((fuzzy as f64 * 1.25).round().min(79.0) as u8);
    }
    if (l.noise || r.noise) && !(semantic_equal && l.noise == r.noise) {
        score = score.min(72);
    }

    let shared_apis = l_api
        .intersection(&r_api)
        .take(16)
        .cloned()
        .collect::<Vec<_>>();
    let mut notes = Vec::new();
    if semantic_equal {
        notes.push("normalized semantic hash matched".to_owned());
    }
    if l.api_set != r.api_set {
        notes.push("API/import call set changed".to_owned());
    }
    if l.block_count != r.block_count {
        notes.push(format!(
            "basic block count changed: {} -> {}",
            l.block_count, r.block_count
        ));
    }
    if l.noise || r.noise {
        let reason = [l.noise_reason.as_str(), r.noise_reason.as_str()]
            .into_iter()
            .filter(|reason| !reason.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join("; ");
        if !reason.is_empty() {
            notes.push(format!("noise-filtered match: {reason}"));
        }
    }

    (
        score.min(100),
        MatchEvidence {
            semantic_hash_equal: semantic_equal,
            cfg_score,
            block_score,
            opcode_score,
            api_score,
            constant_score,
            size_score,
            name_score,
            shared_apis,
            notes,
        },
    )
}

pub(super) fn plausible_pair(l: &FunctionFingerprint, r: &FunctionFingerprint) -> bool {
    if l.semantic_hash == r.semantic_hash {
        return true;
    }
    if l.noise || r.noise {
        let name = normalized_name(&l.name);
        return !name.is_empty()
            && name == normalized_name(&r.name)
            && ratio(l.size_bytes as f64, r.size_bytes as f64) >= 0.80;
    }
    if normalized_name(&l.name) == normalized_name(&r.name) && !normalized_name(&l.name).is_empty()
    {
        return true;
    }
    if hamming64(l.fuzzy_hash, r.fuzzy_hash) <= 16 {
        return true;
    }
    if l.block_count == 0 || r.block_count == 0 || l.insn_count == 0 || r.insn_count == 0 {
        return false;
    }
    let size_ratio = ratio(l.size_bytes as f64, r.size_bytes as f64);
    let block_delta = l.block_count.abs_diff(r.block_count);
    let insn_ratio = ratio(l.insn_count as f64, r.insn_count as f64);
    size_ratio >= 0.25
        && insn_ratio >= 0.25
        && block_delta <= l.block_count.max(r.block_count).max(4)
}

pub(super) fn score_pair(l: &FunctionFingerprint, r: &FunctionFingerprint) -> (u8, MatchEvidence) {
    let semantic_equal = l.semantic_hash == r.semantic_hash;
    let cfg_score = score_float(multiset_jaccard(&l.shape_tokens, &r.shape_tokens));
    let block_score = score_float(multiset_jaccard_u64(&l.block_hashes, &r.block_hashes));
    let opcode_score = score_float(multiset_jaccard(&l.opcode_ngrams, &r.opcode_ngrams));
    let api_score = score_float(set_similarity(&l.api_set, &r.api_set));
    let constant_score = score_float(set_similarity(&l.const_set, &r.const_set));
    let size_score = score_float(ratio(l.size_bytes as f64, r.size_bytes as f64));
    let name_score = score_float(name_similarity(&l.name, &r.name));

    let mut score = (block_score as f64 * 0.30
        + opcode_score as f64 * 0.20
        + cfg_score as f64 * 0.15
        + api_score as f64 * 0.10
        + size_score as f64 * 0.10
        + name_score as f64 * 0.10
        + constant_score as f64 * 0.05)
        .round() as u8;

    if semantic_equal {
        score = score.max(if l.size_bytes == r.size_bytes {
            100
        } else {
            98
        });
    } else if l.cfg_hash == r.cfg_hash && l.api_hash == r.api_hash {
        score = score.max(86);
    } else if l.cfg_hash == r.cfg_hash {
        score = score.max(80);
    }
    if (l.noise || r.noise) && !(semantic_equal && l.noise == r.noise) {
        score = score.min(72);
    }

    let shared_apis = l
        .api_set
        .intersection(&r.api_set)
        .take(16)
        .cloned()
        .collect::<Vec<_>>();
    let mut notes = Vec::new();
    if semantic_equal {
        notes.push("normalized semantic hash matched".to_owned());
    }
    if l.string_ref_count != r.string_ref_count {
        notes.push(format!(
            "string reference count changed: {} -> {}",
            l.string_ref_count, r.string_ref_count
        ));
    }
    if l.api_set != r.api_set {
        notes.push("API/import call set changed".to_owned());
    }
    if l.block_count != r.block_count {
        notes.push(format!(
            "basic block count changed: {} -> {}",
            l.block_count, r.block_count
        ));
    }
    if l.noise || r.noise {
        let reason = [l.noise_reason.as_str(), r.noise_reason.as_str()]
            .into_iter()
            .filter(|reason| !reason.is_empty())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>()
            .join("; ");
        if !reason.is_empty() {
            notes.push(format!("noise-filtered match: {reason}"));
        }
    }

    (
        score.min(100),
        MatchEvidence {
            semantic_hash_equal: semantic_equal,
            cfg_score,
            block_score,
            opcode_score,
            api_score,
            constant_score,
            size_score,
            name_score,
            shared_apis,
            notes,
        },
    )
}
