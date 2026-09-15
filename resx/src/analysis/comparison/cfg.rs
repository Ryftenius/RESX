use super::*;

pub(super) fn select_cfg_diff_pair(
    target: &str,
    left: &[FunctionFingerprint],
    right: &[FunctionFingerprint],
) -> Result<(usize, usize, u8, MatchEvidence), String> {
    let mut candidates = candidate_matches(left, right, 0);
    if candidates.is_empty() {
        return Err("no plausible function matches were found for CFG diff".to_owned());
    }

    let mut matched_left = HashSet::new();
    let mut matched_right = HashSet::new();
    let mut pairs = Vec::new();
    for candidate in candidates.drain(..) {
        if matched_left.contains(&candidate.left_idx)
            || matched_right.contains(&candidate.right_idx)
        {
            continue;
        }
        matched_left.insert(candidate.left_idx);
        matched_right.insert(candidate.right_idx);
        pairs.push(candidate);
    }

    let target = target.trim();
    if target.eq_ignore_ascii_case("auto") {
        return pairs
            .iter()
            .filter(|pair| {
                !left[pair.left_idx].noise
                    && !right[pair.right_idx].noise
                    && matches!(tier(pair.score), "changed" | "weak")
            })
            .max_by(|a, b| {
                a.score.cmp(&b.score).then_with(|| {
                    left[a.left_idx]
                        .size_bytes
                        .cmp(&left[b.left_idx].size_bytes)
                })
            })
            .or_else(|| pairs.iter().find(|pair| !left[pair.left_idx].noise))
            .or_else(|| pairs.first())
            .map(|pair| {
                (
                    pair.left_idx,
                    pair.right_idx,
                    pair.score,
                    pair.evidence.clone(),
                )
            })
            .ok_or_else(|| "no matched functions available for CFG diff".to_owned());
    }

    for pair in &pairs {
        if function_matches_target(&left[pair.left_idx], target)
            || function_matches_target(&right[pair.right_idx], target)
        {
            return Ok((
                pair.left_idx,
                pair.right_idx,
                pair.score,
                pair.evidence.clone(),
            ));
        }
    }

    let left_hit = left
        .iter()
        .position(|fp| function_matches_target(fp, target));
    let right_hit = right
        .iter()
        .position(|fp| function_matches_target(fp, target));
    match (left_hit, right_hit) {
        (Some(l), Some(r)) => {
            let (score, evidence) = score_pair(&left[l], &right[r]);
            Ok((l, r, score, evidence))
        }
        (Some(_), None) => Err(format!(
            "target `{target}` was found only on the left side; no matched right function"
        )),
        (None, Some(_)) => Err(format!(
            "target `{target}` was found only on the right side; no matched left function"
        )),
        (None, None) => Err(format!(
            "target `{target}` was not found; use a function name, RVA, or `auto`"
        )),
    }
}

pub(super) fn function_matches_target(fp: &FunctionFingerprint, target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    if fp.name.eq_ignore_ascii_case(target) {
        return true;
    }
    parse_hex32(target).is_some_and(|rva| rva == fp.rva)
}

pub(super) fn profile_cfg_function(
    path: &Path,
    fp: &FunctionFingerprint,
    pdb_file: &str,
    mode: &str,
    max_blocks: usize,
    cfg: &Config,
) -> Result<CfgFunctionProfile, String> {
    let raw = crate::core::input::read_image(path)
        .map_err(|e| format!("read '{}': {}", path.display(), e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let arch = cfg.effective_arch(pe.arch);
    let exports = read_exports(&pe, &raw);
    let imports = read_imports(&pe, &raw);
    let data = read_data_summary(&pe, &raw);
    let path_str = path.to_string_lossy().to_string();
    let pdb_symbols = if cfg.no_pdb {
        Vec::new()
    } else {
        load_pdb_symbols(
            &path_str,
            &cfg.sym_path,
            &cfg.sym_server,
            pdb_file,
            cfg.verbose,
            cfg.reload,
        )
        .unwrap_or_default()
    };
    let symbol_index = SymbolIndex::from_exports_and_pdb(&exports, &pdb_symbols, pe.image_base);
    let import_slots = import_slot_map(&imports);
    let string_rvas = data.strings.iter().map(|s| s.rva).collect::<BTreeSet<_>>();
    let file_off = pe
        .rva_to_offset(fp.rva)
        .ok_or_else(|| format!("RVA {} is not mapped in {}", hex32(fp.rva), path.display()))?;
    let decode_cfg = decode_config(cfg, mode);
    let insns = disassemble_at(
        &raw,
        &pe,
        file_off,
        fp.rva,
        arch,
        pe.image_base,
        &exports,
        Some(&symbol_index),
        &decode_cfg,
    )
    .map_err(|e| format!("disassembly failed for {}: {}", fp.name, e))?;
    let blocks = build_basic_blocks(&insns, pe.image_base);
    let block_ids = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| (block.start_rva, idx))
        .collect::<BTreeMap<_, _>>();
    let blocks = blocks
        .iter()
        .take(max_blocks)
        .enumerate()
        .map(|(idx, block)| {
            cfg_block_profile(
                idx,
                block,
                &raw,
                &pe,
                &symbol_index,
                &import_slots,
                &string_rvas,
                &block_ids,
                cfg,
            )
        })
        .collect::<Vec<_>>();

    Ok(CfgFunctionProfile {
        function: function_ref(fp),
        blocks,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) fn cfg_block_profile(
    id: usize,
    block: &BasicBlock,
    raw: &[u8],
    pe: &PeFile,
    symbols: &SymbolIndex,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
    block_ids: &BTreeMap<u32, usize>,
    cfg: &Config,
) -> CfgBlockProfile {
    let mut normalized_ops = Vec::new();
    let mut opcodes = Vec::new();
    let mut const_set = BTreeSet::new();
    let mut lines = Vec::new();
    for insn in &block.insns {
        let normalized = normalize_instruction(insn, pe, import_slots, string_rvas, block_ids);
        opcodes.push(normalized.opcode);
        const_set.extend(normalized.constants);
        normalized_ops.push(normalized.text);
        lines.push(format_instruction_line(insn));
    }
    let api_set = collect_api_calls(&block.insns, pe, raw, symbols, pe.image_base, cfg.hostile)
        .iter()
        .filter_map(normalized_api_call)
        .collect::<BTreeSet<_>>();
    let edge_tokens = block
        .edges
        .iter()
        .map(|edge| format!("{}:{}", edge.kind, normalize_edge_label(&edge.label)))
        .collect::<Vec<_>>();
    let display_edges = block
        .edges
        .iter()
        .map(|edge| format!("{}:{}", edge.kind, edge.label))
        .collect::<Vec<_>>();
    let hash = stable_hash_tokens(&normalized_ops);
    CfgBlockProfile {
        id,
        start_rva: block.start_rva,
        end_rva: block.end_rva,
        insn_count: block.insns.len(),
        hash,
        normalized_ops,
        opcode_ngrams: ngrams(&opcodes, 2),
        api_set,
        const_set,
        edge_tokens,
        display_edges,
        lines,
    }
}

pub(super) fn diff_cfg_blocks(
    left: &[CfgBlockProfile],
    right: &[CfgBlockProfile],
) -> (Vec<CfgBlockDiff>, CfgDiffSummary) {
    let mut candidates = Vec::new();
    for (left_idx, l) in left.iter().enumerate() {
        for (right_idx, r) in right.iter().enumerate() {
            let (score, evidence) = score_cfg_block(l, r);
            if score >= 35 || l.hash == r.hash {
                candidates.push(CfgBlockCandidate {
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
            .then_with(|| left[a.left_idx].start_rva.cmp(&left[b.left_idx].start_rva))
            .then_with(|| {
                right[a.right_idx]
                    .start_rva
                    .cmp(&right[b.right_idx].start_rva)
            })
    });

    let mut matched_left = HashSet::new();
    let mut matched_right = HashSet::new();
    let mut block_diffs = Vec::new();
    let mut matched_left_insns = 0usize;
    let mut matched_right_insns = 0usize;
    let mut exact = 0usize;
    let mut changed = 0usize;
    let mut weighted_total = 0usize;
    let mut weighted_score = 0usize;

    for candidate in candidates {
        if matched_left.contains(&candidate.left_idx)
            || matched_right.contains(&candidate.right_idx)
        {
            continue;
        }
        let l = &left[candidate.left_idx];
        let r = &right[candidate.right_idx];
        matched_left.insert(candidate.left_idx);
        matched_right.insert(candidate.right_idx);
        matched_left_insns += l.insn_count.max(1);
        matched_right_insns += r.insn_count.max(1);
        let weight = l.insn_count.max(1) + r.insn_count.max(1);
        weighted_total += weight;
        weighted_score += weight * candidate.score as usize;
        if candidate.score >= 98 {
            exact += 1;
        } else {
            changed += 1;
        }
        block_diffs.push(CfgBlockDiff {
            tier: cfg_block_tier(candidate.score).to_owned(),
            score: candidate.score,
            left: Some(cfg_block_ref(l)),
            right: Some(cfg_block_ref(r)),
            evidence: candidate.evidence,
        });
    }

    for (idx, block) in left.iter().enumerate() {
        if !matched_left.contains(&idx) {
            block_diffs.push(CfgBlockDiff {
                tier: "left-only".to_owned(),
                score: 0,
                left: Some(cfg_block_ref(block)),
                right: None,
                evidence: empty_cfg_block_evidence(),
            });
        }
    }
    for (idx, block) in right.iter().enumerate() {
        if !matched_right.contains(&idx) {
            block_diffs.push(CfgBlockDiff {
                tier: "right-only".to_owned(),
                score: 0,
                left: None,
                right: Some(cfg_block_ref(block)),
                evidence: empty_cfg_block_evidence(),
            });
        }
    }
    block_diffs.sort_by(|a, b| {
        cfg_block_sort_rva(a)
            .cmp(&cfg_block_sort_rva(b))
            .then_with(|| a.tier.cmp(&b.tier))
    });

    let left_total = left.iter().map(|b| b.insn_count.max(1)).sum();
    let right_total = right.iter().map(|b| b.insn_count.max(1)).sum();
    let summary = CfgDiffSummary {
        score: if weighted_total == 0 {
            0
        } else {
            ((weighted_score as f64 / weighted_total as f64).round() as u8).min(100)
        },
        matched_blocks: matched_left.len(),
        exact_blocks: exact,
        changed_blocks: changed,
        left_only_blocks: left.len().saturating_sub(matched_left.len()),
        right_only_blocks: right.len().saturating_sub(matched_right.len()),
        left_block_coverage: coverage(matched_left_insns, left_total),
        right_block_coverage: coverage(matched_right_insns, right_total),
    };
    (block_diffs, summary)
}

pub(super) fn score_cfg_block(l: &CfgBlockProfile, r: &CfgBlockProfile) -> (u8, CfgBlockEvidence) {
    let hash_equal = l.hash == r.hash;
    let op_score = score_float(multiset_jaccard(&l.normalized_ops, &r.normalized_ops));
    let ngram_score = score_float(multiset_jaccard(&l.opcode_ngrams, &r.opcode_ngrams));
    let api_score = score_float(set_similarity(&l.api_set, &r.api_set));
    let constant_score = score_float(set_similarity(&l.const_set, &r.const_set));
    let edge_score = score_float(multiset_jaccard(&l.edge_tokens, &r.edge_tokens));
    let size_score = score_float(ratio(l.insn_count as f64, r.insn_count as f64));
    let mut score = (op_score as f64 * 0.35
        + ngram_score as f64 * 0.20
        + edge_score as f64 * 0.20
        + api_score as f64 * 0.10
        + constant_score as f64 * 0.10
        + size_score as f64 * 0.05)
        .round() as u8;
    if hash_equal {
        score = 100;
    }

    let mut notes = Vec::new();
    if hash_equal {
        notes.push("normalized block hash matched".to_owned());
    }
    if l.api_set != r.api_set {
        notes.push("API/import refs changed".to_owned());
    }
    if l.edge_tokens != r.edge_tokens {
        notes.push("edge shape changed".to_owned());
    }
    if l.insn_count != r.insn_count {
        notes.push(format!(
            "instruction count changed: {} -> {}",
            l.insn_count, r.insn_count
        ));
    }

    (
        score.min(100),
        CfgBlockEvidence {
            normalized_hash_equal: hash_equal,
            op_score,
            api_score,
            constant_score,
            edge_score,
            notes,
        },
    )
}

pub(super) fn cfg_block_ref(block: &CfgBlockProfile) -> CfgBlockRef {
    CfgBlockRef {
        id: block.id,
        rva: hex32(block.start_rva),
        end_rva: hex32(block.end_rva),
        insn_count: block.insn_count,
        hash: hex64(block.hash),
        edges: block.display_edges.clone(),
        lines: block.lines.clone(),
    }
}

pub(super) fn cfg_block_sort_rva(block: &CfgBlockDiff) -> u32 {
    block
        .left
        .as_ref()
        .or(block.right.as_ref())
        .and_then(|b| parse_hex32(&b.rva))
        .unwrap_or(0)
}

pub(super) fn empty_cfg_block_evidence() -> CfgBlockEvidence {
    CfgBlockEvidence {
        normalized_hash_equal: false,
        op_score: 0,
        api_score: 0,
        constant_score: 0,
        edge_score: 0,
        notes: Vec::new(),
    }
}

pub(super) fn cfg_block_tier(score: u8) -> &'static str {
    match score {
        98..=100 => "exact",
        80..=97 => "similar",
        55..=79 => "changed",
        _ => "weak",
    }
}

pub(super) fn format_instruction_line(insn: &Instruction) -> String {
    if insn.comment.is_empty() {
        format!("0x{:08X}  {}", insn.rva, insn.text)
    } else {
        format!("0x{:08X}  {}  ; {}", insn.rva, insn.text, insn.comment)
    }
}

pub(super) fn normalize_edge_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    let mut chars = label.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '0' && matches!(chars.peek(), Some('x' | 'X')) {
            out.push_str("0xADDR");
            chars.next();
            while chars.peek().is_some_and(|c| c.is_ascii_hexdigit()) {
                chars.next();
            }
        } else if ch.is_ascii_digit() {
            out.push('N');
            while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                chars.next();
            }
        } else {
            out.push(ch.to_ascii_lowercase());
        }
    }
    out
}
