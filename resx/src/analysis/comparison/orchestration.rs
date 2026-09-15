use super::*;

pub fn diff_images(request: DiffRequest<'_>) -> Result<DiffReport, String> {
    let cfg = request.cfg;
    let mode = normalize_mode(&cfg.diff_mode);
    let threshold = cfg.diff_threshold.min(100);
    let max_functions = cfg.diff_max_functions.max(1);
    let min_score = if cfg.include_weak {
        threshold.min(50)
    } else {
        threshold
    };

    let left = profile_image(
        request.left_path,
        "left",
        left_pdb(cfg),
        &mode,
        max_functions,
        cfg,
    )?;
    let right = profile_image(
        request.right_path,
        "right",
        right_pdb(cfg),
        &mode,
        max_functions,
        cfg,
    )?;

    Ok(diff_profile_pair(
        &left,
        &right,
        &mode,
        threshold,
        cfg.include_weak,
        max_functions,
        min_score,
    ))
}

pub fn diff_many_images(request: MultiDiffRequest<'_>) -> Result<MultiDiffReport, String> {
    let cfg = request.cfg;
    if request.paths.len() < 2 {
        return Err("multi diff needs at least two images".to_owned());
    }

    let mode = normalize_mode(&cfg.diff_mode);
    let threshold = cfg.diff_threshold.min(100);
    let max_functions = cfg.diff_max_functions.max(1);
    let min_score = if cfg.include_weak {
        threshold.min(50)
    } else {
        threshold
    };

    let mut profiles = Vec::with_capacity(request.paths.len());
    let mut notes = Vec::new();
    for (idx, path) in request.paths.iter().enumerate() {
        let side = format!("image{}", idx + 1);
        let pdb = match idx {
            0 => left_pdb(cfg),
            1 => right_pdb(cfg),
            _ => "",
        };
        let profile = profile_image(path, &side, pdb, &mode, max_functions, cfg)?;
        notes.extend(profile.summary.notes.iter().cloned());
        profiles.push(profile);
    }

    let mut pairs = Vec::new();
    for left_idx in 0..profiles.len() {
        for right_idx in (left_idx + 1)..profiles.len() {
            let report = diff_profile_pair(
                &profiles[left_idx],
                &profiles[right_idx],
                &mode,
                threshold,
                cfg.include_weak,
                max_functions,
                min_score,
            );
            pairs.push(MultiDiffPair {
                left_index: left_idx,
                right_index: right_idx,
                left: report.left,
                right: report.right,
                summary: report.summary,
                metadata: report.metadata,
                heatmap: report.heatmap,
                changed_clusters: report.changed_clusters,
                signature_hints: report.signature_hints,
                notes: report.notes,
            });
        }
    }

    Ok(MultiDiffReport {
        options: options_report(&mode, threshold, cfg.include_weak, max_functions),
        images: profiles
            .iter()
            .map(|profile| profile.summary.clone())
            .collect(),
        pairs,
        notes: dedupe_strings(notes),
    })
}

pub(super) fn diff_profile_pair(
    left: &ImageProfile,
    right: &ImageProfile,
    mode: &str,
    threshold: u8,
    include_weak: bool,
    max_functions: usize,
    min_score: u8,
) -> DiffReport {
    let mut notes = Vec::new();
    notes.extend(left.summary.notes.iter().cloned());
    notes.extend(right.summary.notes.iter().cloned());

    let mut matches = Vec::new();
    let mut matched_left = HashSet::new();
    let mut matched_right = HashSet::new();

    if left.summary.arch != right.summary.arch {
        notes.push(format!(
            "architecture mismatch: left {} vs right {}; function-level structural matching skipped",
            left.summary.arch, right.summary.arch
        ));
    } else {
        let candidates = candidate_matches(&left.functions, &right.functions, min_score);
        for candidate in candidates {
            if matched_left.contains(&candidate.left_idx)
                || matched_right.contains(&candidate.right_idx)
            {
                continue;
            }
            matched_left.insert(candidate.left_idx);
            matched_right.insert(candidate.right_idx);
            let l = &left.functions[candidate.left_idx];
            let r = &right.functions[candidate.right_idx];
            matches.push(FunctionMatch {
                tier: tier(candidate.score).to_owned(),
                score: candidate.score,
                left: function_ref(l),
                right: function_ref(r),
                evidence: candidate.evidence,
            });
        }
    }

    matches.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.left.rva.cmp(&b.left.rva))
            .then_with(|| a.right.rva.cmp(&b.right.rva))
    });

    let left_only = left
        .functions
        .iter()
        .enumerate()
        .filter(|(idx, _)| !matched_left.contains(idx))
        .map(|(_, fp)| function_ref(fp))
        .collect::<Vec<_>>();
    let right_only = right
        .functions
        .iter()
        .enumerate()
        .filter(|(idx, _)| !matched_right.contains(idx))
        .map(|(_, fp)| function_ref(fp))
        .collect::<Vec<_>>();

    let summary = build_summary(
        &left.functions,
        &right.functions,
        &matches,
        &left_only,
        &right_only,
    );
    let metadata = metadata_delta(left, right);
    let changed_clusters = build_clusters(&matches, &left_only, &right_only);
    let signature_hints = signature_hints_from_diff(&matches, &metadata);
    let heatmap = build_heatmap(left, right, &matches, &left_only, &right_only);

    DiffReport {
        options: options_report(mode, threshold, include_weak, max_functions),
        left: left.summary.clone(),
        right: right.summary.clone(),
        summary,
        metadata,
        matches,
        left_only,
        right_only,
        changed_clusters,
        signature_hints,
        heatmap,
        notes: dedupe_strings(notes),
    }
}

pub fn diff_function_cfg(request: CfgDiffRequest<'_>) -> Result<CfgDiffReport, String> {
    let cfg = request.cfg;
    let mode = normalize_mode(&cfg.diff_mode);
    let threshold = cfg.diff_threshold.min(100);
    let max_functions = cfg.diff_max_functions.max(1);
    let left = profile_image(
        request.left_path,
        "left",
        left_pdb(cfg),
        &mode,
        max_functions,
        cfg,
    )?;
    let right = profile_image(
        request.right_path,
        "right",
        right_pdb(cfg),
        &mode,
        max_functions,
        cfg,
    )?;

    if left.summary.arch != right.summary.arch {
        return Err(format!(
            "architecture mismatch: left {} vs right {}",
            left.summary.arch, right.summary.arch
        ));
    }

    let selected = select_cfg_diff_pair(request.target, &left.functions, &right.functions)?;
    let (left_idx, right_idx, pair_score, pair_evidence) = selected;
    let left_fp = &left.functions[left_idx];
    let right_fp = &right.functions[right_idx];
    let left_cfg = profile_cfg_function(
        request.left_path,
        left_fp,
        left_pdb(cfg),
        &mode,
        cfg.max_cfg_blocks.max(1),
        cfg,
    )?;
    let right_cfg = profile_cfg_function(
        request.right_path,
        right_fp,
        right_pdb(cfg),
        &mode,
        cfg.max_cfg_blocks.max(1),
        cfg,
    )?;
    let (blocks, summary) = diff_cfg_blocks(&left_cfg.blocks, &right_cfg.blocks);

    let mut notes = Vec::new();
    notes.extend(left.summary.notes.iter().cloned());
    notes.extend(right.summary.notes.iter().cloned());
    if !pair_evidence.notes.is_empty() {
        notes.extend(
            pair_evidence
                .notes
                .iter()
                .map(|note| format!("function match: {note}")),
        );
    }
    notes.push(format!(
        "function match score {} ({})",
        pair_score,
        tier(pair_score)
    ));
    if left_cfg.blocks.len() >= cfg.max_cfg_blocks || right_cfg.blocks.len() >= cfg.max_cfg_blocks {
        notes.push(format!(
            "CFG block output capped at --max-cfg-blocks {} per side",
            cfg.max_cfg_blocks.max(1)
        ));
    }

    Ok(CfgDiffReport {
        options: options_report(&mode, threshold, cfg.include_weak, max_functions),
        target: request.target.to_owned(),
        left_image: left.summary,
        right_image: right.summary,
        left_function: left_cfg.function,
        right_function: right_cfg.function,
        summary,
        blocks,
        notes: dedupe_strings(notes),
    })
}

pub fn profile_image_for_index(path: &Path, cfg: &Config) -> Result<IndexedImage, String> {
    profile_image_as_indexed(path, cfg, "index")
}

pub(super) fn profile_image_as_indexed(
    path: &Path,
    cfg: &Config,
    side: &str,
) -> Result<IndexedImage, String> {
    let mode = normalize_mode(&cfg.diff_mode);
    let profile = profile_image(path, side, "", &mode, cfg.diff_max_functions.max(1), cfg)?;
    Ok(indexed_image_from_profile(&profile))
}

pub fn new_corpus_index(root: &Path, cfg: &Config) -> CorpusIndex {
    let mode = normalize_mode(&cfg.diff_mode);
    CorpusIndex {
        schema_version: 1,
        kind: "resx-corpus-index".to_owned(),
        root: root.to_string_lossy().to_string(),
        created_by: format!("resx {}", env!("CARGO_PKG_VERSION")),
        options: options_report(
            &mode,
            cfg.diff_threshold.min(100),
            cfg.include_weak,
            cfg.diff_max_functions.max(1),
        ),
        images: Vec::new(),
        skipped: Vec::new(),
        notes: Vec::new(),
    }
}

pub fn hunt_corpus(
    sample_path: &Path,
    index: &CorpusIndex,
    cfg: &Config,
) -> Result<HuntReport, String> {
    let mode = normalize_mode(&cfg.diff_mode);
    let threshold = cfg.diff_threshold.min(100);
    let max_functions = cfg.diff_max_functions.max(1);
    let min_score = if cfg.include_weak {
        threshold.min(50)
    } else {
        threshold
    };
    let sample = profile_image_as_indexed(sample_path, cfg, "sample")?;
    let mut notes = sample.summary.notes.clone();
    if index.schema_version != 1 {
        notes.push(format!(
            "index schema version {} is not the current version 1",
            index.schema_version
        ));
    }

    let mut candidates = index
        .images
        .iter()
        .filter(|candidate| candidate.summary.arch == sample.summary.arch)
        .filter_map(|candidate| score_indexed_images(&sample, candidate, min_score))
        .collect::<Vec<_>>();

    candidates.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| b.unique_score.cmp(&a.unique_score))
            .then_with(|| b.matched_functions.cmp(&a.matched_functions))
            .then_with(|| a.path.cmp(&b.path))
    });
    candidates.truncate(cfg.max_candidates.max(1));
    for (idx, candidate) in candidates.iter_mut().enumerate() {
        candidate.rank = idx + 1;
    }

    Ok(HuntReport {
        options: options_report(&mode, threshold, cfg.include_weak, max_functions),
        index_root: index.root.clone(),
        sample: sample.summary,
        indexed_images: index.images.len(),
        candidates,
        notes: dedupe_strings(notes),
    })
}
