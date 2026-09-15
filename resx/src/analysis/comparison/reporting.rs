use super::*;

pub(super) fn build_summary(
    left_functions: &[FunctionFingerprint],
    right_functions: &[FunctionFingerprint],
    matches: &[FunctionMatch],
    left_only: &[FunctionRef],
    right_only: &[FunctionRef],
) -> DiffSummary {
    let left_total: usize = left_functions.iter().map(|f| f.size_bytes.max(1)).sum();
    let right_total: usize = right_functions.iter().map(|f| f.size_bytes.max(1)).sum();
    let unique_left_total: usize = left_functions
        .iter()
        .filter(|f| !f.noise)
        .map(|f| f.size_bytes.max(1))
        .sum();
    let unique_right_total: usize = right_functions
        .iter()
        .filter(|f| !f.noise)
        .map(|f| f.size_bytes.max(1))
        .sum();
    let mut weighted_total = 0usize;
    let mut weighted_score = 0usize;
    let mut unique_weighted_total = 0usize;
    let mut unique_weighted_score = 0usize;
    let mut matched_left_bytes = 0usize;
    let mut matched_right_bytes = 0usize;
    let mut unique_matched_left_bytes = 0usize;
    let mut unique_matched_right_bytes = 0usize;
    let mut exact = 0usize;
    let mut strong = 0usize;
    let mut changed = 0usize;
    let mut weak = 0usize;
    let mut unique_matched = 0usize;
    let mut noisy_matches = 0usize;

    for m in matches {
        let weight = m.left.size_bytes.max(1) + m.right.size_bytes.max(1);
        weighted_total += weight;
        weighted_score += weight * m.score as usize;
        matched_left_bytes += m.left.size_bytes.max(1);
        matched_right_bytes += m.right.size_bytes.max(1);
        if m.left.noise || m.right.noise {
            noisy_matches += 1;
        } else {
            unique_matched += 1;
            unique_weighted_total += weight;
            unique_weighted_score += weight * m.score as usize;
            unique_matched_left_bytes += m.left.size_bytes.max(1);
            unique_matched_right_bytes += m.right.size_bytes.max(1);
        }
        match m.tier.as_str() {
            "exact" => exact += 1,
            "strong" => strong += 1,
            "changed" => changed += 1,
            "weak" => weak += 1,
            _ => {}
        }
    }

    let raw_similarity = if weighted_total == 0 {
        0
    } else {
        ((weighted_score as f64 / weighted_total as f64).round() as u8).min(100)
    };
    let unmatched_unique_total: usize = left_only
        .iter()
        .chain(right_only.iter())
        .filter(|f| !f.noise)
        .map(|f| f.size_bytes.max(1))
        .sum();
    let unique_denominator = unique_weighted_total + unmatched_unique_total;
    let unique_similarity_score = if unique_denominator == 0 {
        0
    } else {
        ((unique_weighted_score as f64 / unique_denominator as f64).round() as u8).min(100)
    };
    let noisy_ratio = if matches.is_empty() {
        0.0
    } else {
        noisy_matches as f64 / matches.len() as f64
    };

    DiffSummary {
        similarity_score: if noisy_ratio >= 0.50 && unique_similarity_score > 0 {
            ((unique_similarity_score as f64 * 0.75) + (raw_similarity as f64 * 0.25))
                .round()
                .min(100.0) as u8
        } else {
            raw_similarity
        },
        unique_similarity_score,
        left_function_coverage: coverage(
            unique_matched_left_bytes.max(matched_left_bytes),
            unique_left_total.max(left_total),
        ),
        right_function_coverage: coverage(
            unique_matched_right_bytes.max(matched_right_bytes),
            unique_right_total.max(right_total),
        ),
        matched_functions: matches.len(),
        unique_matched_functions: unique_matched,
        noisy_matches,
        exact_matches: exact,
        strong_matches: strong,
        changed_matches: changed,
        weak_matches: weak,
        left_only_functions: left_only.len(),
        right_only_functions: right_only.len(),
    }
}

pub(super) fn build_indexed_summary(
    left_functions: &[IndexedFunction],
    right_functions: &[IndexedFunction],
    matches: &[HuntFunctionMatch],
) -> DiffSummary {
    let left_total: usize = left_functions.iter().map(|f| f.size_bytes.max(1)).sum();
    let right_total: usize = right_functions.iter().map(|f| f.size_bytes.max(1)).sum();
    let mut weighted_total = 0usize;
    let mut weighted_score = 0usize;
    let mut unique_weighted_total = 0usize;
    let mut unique_weighted_score = 0usize;
    let mut matched_left_bytes = 0usize;
    let mut matched_right_bytes = 0usize;
    let mut exact = 0usize;
    let mut strong = 0usize;
    let mut changed = 0usize;
    let mut weak = 0usize;
    let mut unique_matched = 0usize;
    let mut noisy_matches = 0usize;

    for m in matches {
        let weight = m.sample.size_bytes.max(1) + m.candidate.size_bytes.max(1);
        weighted_total += weight;
        weighted_score += weight * m.score as usize;
        matched_left_bytes += m.sample.size_bytes.max(1);
        matched_right_bytes += m.candidate.size_bytes.max(1);
        if m.sample.noise || m.candidate.noise {
            noisy_matches += 1;
        } else {
            unique_matched += 1;
            unique_weighted_total += weight;
            unique_weighted_score += weight * m.score as usize;
        }
        match m.tier.as_str() {
            "exact" => exact += 1,
            "strong" => strong += 1,
            "changed" => changed += 1,
            "weak" => weak += 1,
            _ => {}
        }
    }

    let raw_similarity = if weighted_total == 0 {
        0
    } else {
        ((weighted_score as f64 / weighted_total as f64).round() as u8).min(100)
    };
    let matched_left = matches
        .iter()
        .map(|m| m.sample.rva.as_str())
        .collect::<BTreeSet<_>>();
    let matched_right = matches
        .iter()
        .map(|m| m.candidate.rva.as_str())
        .collect::<BTreeSet<_>>();
    let unmatched_unique_total: usize = left_functions
        .iter()
        .filter(|f| !f.noise && !matched_left.contains(f.rva.as_str()))
        .map(|f| f.size_bytes.max(1))
        .sum::<usize>()
        + right_functions
            .iter()
            .filter(|f| !f.noise && !matched_right.contains(f.rva.as_str()))
            .map(|f| f.size_bytes.max(1))
            .sum::<usize>();
    let unique_denominator = unique_weighted_total + unmatched_unique_total;
    let unique_similarity_score = if unique_denominator == 0 {
        0
    } else {
        ((unique_weighted_score as f64 / unique_denominator as f64).round() as u8).min(100)
    };
    let noisy_ratio = if matches.is_empty() {
        0.0
    } else {
        noisy_matches as f64 / matches.len() as f64
    };

    DiffSummary {
        similarity_score: if noisy_ratio >= 0.50 && unique_similarity_score > 0 {
            ((unique_similarity_score as f64 * 0.75) + (raw_similarity as f64 * 0.25))
                .round()
                .min(100.0) as u8
        } else {
            raw_similarity
        },
        unique_similarity_score,
        left_function_coverage: coverage(matched_left_bytes, left_total),
        right_function_coverage: coverage(matched_right_bytes, right_total),
        matched_functions: matches.len(),
        unique_matched_functions: unique_matched,
        noisy_matches,
        exact_matches: exact,
        strong_matches: strong,
        changed_matches: changed,
        weak_matches: weak,
        left_only_functions: left_functions.len().saturating_sub(matches.len()),
        right_only_functions: right_functions.len().saturating_sub(matches.len()),
    }
}

pub(super) fn metadata_delta(left: &ImageProfile, right: &ImageProfile) -> MetadataDelta {
    MetadataDelta {
        common_exports: left.exports.intersection(&right.exports).count(),
        left_only_exports: capped_delta(&left.exports, &right.exports),
        right_only_exports: capped_delta(&right.exports, &left.exports),
        common_imports: left.imports.intersection(&right.imports).count(),
        left_only_imports: capped_delta(&left.imports, &right.imports),
        right_only_imports: capped_delta(&right.imports, &left.imports),
        common_strings: left.strings.intersection(&right.strings).count(),
        left_only_strings: capped_delta(&left.strings, &right.strings),
        right_only_strings: capped_delta(&right.strings, &left.strings),
    }
}

pub(super) fn build_heatmap(
    left: &ImageProfile,
    right: &ImageProfile,
    matches: &[FunctionMatch],
    left_only: &[FunctionRef],
    right_only: &[FunctionRef],
) -> DiffHeatmap {
    let section_entropy = section_entropy_delta(&left.summary.sections, &right.summary.sections);
    let signal_averages = average_signals(matches);
    let mut hotspots = Vec::new();

    for m in matches
        .iter()
        .filter(|m| matches!(m.tier.as_str(), "changed" | "weak") || m.score < 90)
    {
        let lowest_signal = [
            m.evidence.cfg_score,
            m.evidence.block_score,
            m.evidence.opcode_score,
            m.evidence.api_score,
            m.evidence.constant_score,
            m.evidence.size_score,
            m.evidence.name_score,
        ]
        .into_iter()
        .min()
        .unwrap_or(m.score);
        let entropy_delta = entropy_delta_for_sections(
            &left.summary.sections,
            &right.summary.sections,
            &m.left.section,
            &m.right.section,
        );
        hotspots.push(DiffHotspot {
            kind: "function-pair".to_owned(),
            heat: (100u8.saturating_sub(m.score)).max(100u8.saturating_sub(lowest_signal)),
            score: m.score,
            left_name: m.left.name.clone(),
            right_name: m.right.name.clone(),
            left_rva: m.left.rva.clone(),
            right_rva: m.right.rva.clone(),
            section: if m.left.section == m.right.section {
                m.left.section.clone()
            } else {
                format!("{} -> {}", m.left.section, m.right.section)
            },
            entropy_delta,
            signals: Some(m.evidence.clone()),
            notes: m.evidence.notes.clone(),
        });
    }

    for f in left_only.iter().take(128) {
        hotspots.push(DiffHotspot {
            kind: "left-only".to_owned(),
            heat: 100,
            score: 0,
            left_name: f.name.clone(),
            right_name: String::new(),
            left_rva: f.rva.clone(),
            right_rva: String::new(),
            section: f.section.clone(),
            entropy_delta: None,
            signals: None,
            notes: vec!["function exists only in left image".to_owned()],
        });
    }
    for f in right_only.iter().take(128) {
        hotspots.push(DiffHotspot {
            kind: "right-only".to_owned(),
            heat: 100,
            score: 0,
            left_name: String::new(),
            right_name: f.name.clone(),
            left_rva: String::new(),
            right_rva: f.rva.clone(),
            section: f.section.clone(),
            entropy_delta: None,
            signals: None,
            notes: vec!["function exists only in right image".to_owned()],
        });
    }

    hotspots.sort_by(|a, b| {
        b.heat
            .cmp(&a.heat)
            .then_with(|| a.score.cmp(&b.score))
            .then_with(|| a.left_rva.cmp(&b.left_rva))
            .then_with(|| a.right_rva.cmp(&b.right_rva))
    });
    hotspots.truncate(64);

    DiffHeatmap {
        section_entropy,
        signal_averages,
        hotspots,
        notes: vec![
            "heat is driven by inverse match score, weakest structural signal, unmatched functions, and PE section entropy deltas".to_owned(),
            "entropy values are Shannon entropy over raw section bytes rounded to three decimals".to_owned(),
        ],
    }
}

pub(super) fn average_signals(matches: &[FunctionMatch]) -> DiffSignalAverages {
    if matches.is_empty() {
        return DiffSignalAverages {
            cfg_score: 0,
            block_score: 0,
            opcode_score: 0,
            api_score: 0,
            constant_score: 0,
            size_score: 0,
            name_score: 0,
        };
    }
    let count = matches.len() as u32;
    let sum = |f: fn(&MatchEvidence) -> u8| -> u8 {
        ((matches.iter().map(|m| f(&m.evidence) as u32).sum::<u32>() as f64 / count as f64).round()
            as u8)
            .min(100)
    };
    DiffSignalAverages {
        cfg_score: sum(|e| e.cfg_score),
        block_score: sum(|e| e.block_score),
        opcode_score: sum(|e| e.opcode_score),
        api_score: sum(|e| e.api_score),
        constant_score: sum(|e| e.constant_score),
        size_score: sum(|e| e.size_score),
        name_score: sum(|e| e.name_score),
    }
}

pub(super) fn section_entropy_delta(
    left: &[SectionEntropy],
    right: &[SectionEntropy],
) -> Vec<SectionEntropyDelta> {
    let left_map = section_map(left);
    let right_map = section_map(right);
    let mut keys = left_map.keys().cloned().collect::<BTreeSet<_>>();
    keys.extend(right_map.keys().cloned());

    let mut deltas = keys
        .into_iter()
        .map(|key| {
            let l = left_map.get(&key).copied();
            let r = right_map.get(&key).copied();
            let entropy_delta = match (l, r) {
                (Some(l), Some(r)) => Some(round3((r.entropy - l.entropy).abs())),
                _ => None,
            };
            let size_heat = match (l, r) {
                (Some(l), Some(r)) => {
                    (100.0 - (ratio(l.raw_size as f64, r.raw_size as f64) * 100.0)).round() as u8
                }
                _ => 100,
            };
            let entropy_heat = entropy_delta
                .map(|delta| ((delta / 2.0) * 100.0).round().clamp(0.0, 100.0) as u8)
                .unwrap_or(100);
            let protection = match (l, r) {
                (Some(l), Some(r)) if l.protection == r.protection => l.protection.clone(),
                (Some(l), Some(r)) => format!("{} -> {}", l.protection, r.protection),
                (Some(l), None) => l.protection.clone(),
                (None, Some(r)) => r.protection.clone(),
                (None, None) => String::new(),
            };
            let note = match (l, r, entropy_delta) {
                (Some(_), Some(_), Some(delta)) if delta >= 1.0 => {
                    format!("large entropy delta {:.3}", delta)
                }
                (Some(_), Some(_), Some(delta)) if delta >= 0.25 => {
                    format!("entropy delta {:.3}", delta)
                }
                (Some(l), Some(r), _) if l.raw_size != r.raw_size => {
                    format!("raw size changed {} -> {}", l.raw_size, r.raw_size)
                }
                (Some(_), Some(_), _) => "stable entropy/size".to_owned(),
                (Some(_), None, _) => "section exists only in left image".to_owned(),
                (None, Some(_), _) => "section exists only in right image".to_owned(),
                (None, None, _) => String::new(),
            };
            SectionEntropyDelta {
                section: l.or(r).map(|section| section.name.clone()).unwrap_or(key),
                left_entropy: l.map(|section| section.entropy),
                right_entropy: r.map(|section| section.entropy),
                entropy_delta,
                left_size: l.map(|section| section.raw_size),
                right_size: r.map(|section| section.raw_size),
                protection,
                executable: l.map(|section| section.executable).unwrap_or(false)
                    || r.map(|section| section.executable).unwrap_or(false),
                heat: entropy_heat.max(size_heat),
                note,
            }
        })
        .collect::<Vec<_>>();
    deltas.sort_by(|a, b| b.heat.cmp(&a.heat).then_with(|| a.section.cmp(&b.section)));
    deltas
}

pub(super) fn section_map(sections: &[SectionEntropy]) -> BTreeMap<String, &SectionEntropy> {
    sections
        .iter()
        .map(|section| (normalized_section_key(&section.name), section))
        .collect()
}

pub(super) fn entropy_delta_for_sections(
    left_sections: &[SectionEntropy],
    right_sections: &[SectionEntropy],
    left_section: &str,
    right_section: &str,
) -> Option<f64> {
    let left_key = normalized_section_key(left_section);
    let right_key = normalized_section_key(right_section);
    let left = section_map(left_sections);
    let right = section_map(right_sections);
    let l = left.get(&left_key)?;
    let r = right.get(&right_key)?;
    Some(round3((r.entropy - l.entropy).abs()))
}

pub(super) fn normalized_section_key(name: &str) -> String {
    name.trim()
        .trim_matches('\0')
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

pub(super) fn build_clusters(
    matches: &[FunctionMatch],
    left_only: &[FunctionRef],
    right_only: &[FunctionRef],
) -> Vec<DiffCluster> {
    let mut clusters = Vec::new();
    let changed = matches
        .iter()
        .filter(|m| matches!(m.tier.as_str(), "changed" | "weak"))
        .map(|m| ClusterItem {
            section: format!("{} -> {}", m.left.section, m.right.section),
            rva: parse_hex32(&m.left.rva).unwrap_or(0),
            end_rva: parse_hex32(&m.left.rva)
                .unwrap_or(0)
                .saturating_add(m.left.size_bytes as u32),
            score: m.score,
            label: format!("{} -> {}", m.left.name, m.right.name),
        })
        .collect::<Vec<_>>();
    clusters.extend(cluster_items("changed", "pair", changed));

    let left = left_only
        .iter()
        .map(|f| ClusterItem {
            section: f.section.clone(),
            rva: parse_hex32(&f.rva).unwrap_or(0),
            end_rva: parse_hex32(&f.rva)
                .unwrap_or(0)
                .saturating_add(f.size_bytes as u32),
            score: 0,
            label: f.name.clone(),
        })
        .collect::<Vec<_>>();
    clusters.extend(cluster_items("left-only", "left", left));

    let right = right_only
        .iter()
        .map(|f| ClusterItem {
            section: f.section.clone(),
            rva: parse_hex32(&f.rva).unwrap_or(0),
            end_rva: parse_hex32(&f.rva)
                .unwrap_or(0)
                .saturating_add(f.size_bytes as u32),
            score: 0,
            label: f.name.clone(),
        })
        .collect::<Vec<_>>();
    clusters.extend(cluster_items("right-only", "right", right));

    clusters.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then_with(|| a.side.cmp(&b.side))
            .then_with(|| a.start_rva.cmp(&b.start_rva))
    });
    clusters.truncate(64);
    clusters
}

#[derive(Debug, Clone)]
pub(super) struct ClusterItem {
    section: String,
    rva: u32,
    end_rva: u32,
    score: u8,
    label: String,
}

pub(super) fn cluster_items(
    kind: &str,
    side: &str,
    mut items: Vec<ClusterItem>,
) -> Vec<DiffCluster> {
    if items.is_empty() {
        return Vec::new();
    }
    items.sort_by(|a, b| a.section.cmp(&b.section).then_with(|| a.rva.cmp(&b.rva)));
    let mut out = Vec::new();
    let mut current: Vec<ClusterItem> = Vec::new();
    let mut section = String::new();

    for item in items {
        let adjacent = current
            .last()
            .is_some_and(|prev| item.rva <= prev.end_rva.saturating_add(0x200));
        if current.is_empty() || (item.section == section && adjacent) {
            section = item.section.clone();
            current.push(item);
            continue;
        }
        out.push(finish_cluster(kind, side, &current));
        section = item.section.clone();
        current.clear();
        current.push(item);
    }
    if !current.is_empty() {
        out.push(finish_cluster(kind, side, &current));
    }
    out
}

pub(super) fn finish_cluster(kind: &str, side: &str, items: &[ClusterItem]) -> DiffCluster {
    let start = items.iter().map(|i| i.rva).min().unwrap_or(0);
    let end = items.iter().map(|i| i.end_rva).max().unwrap_or(start);
    let average_score = if items.iter().any(|i| i.score != 0) {
        let total: usize = items.iter().map(|i| i.score as usize).sum();
        (total / items.len()).min(100) as u8
    } else {
        0
    };
    DiffCluster {
        kind: kind.to_owned(),
        side: side.to_owned(),
        section: items.first().map(|i| i.section.clone()).unwrap_or_default(),
        start_rva: hex32(start),
        end_rva: hex32(end),
        functions: items.len(),
        average_score,
        examples: items.iter().take(6).map(|i| i.label.clone()).collect(),
    }
}

pub(super) fn section_entropy(pe: &PeFile) -> Vec<SectionEntropy> {
    pe.sections
        .iter()
        .map(|section| SectionEntropy {
            name: section.name.clone(),
            rva: hex32(section.virtual_address),
            virtual_size: section.virtual_size,
            raw_size: section.raw_size,
            protection: section.protection_string(),
            entropy: round3(section.entropy),
            executable: section.is_executable(),
        })
        .collect()
}

pub(super) fn image_traits(
    pe: &PeFile,
    exports: &BTreeSet<String>,
    imports: &BTreeSet<String>,
    strings: &BTreeSet<String>,
) -> ImageTraits {
    let section_tokens = pe
        .sections
        .iter()
        .map(|section| {
            format!(
                "{}:{}:{}",
                section.name.to_ascii_lowercase(),
                section.protection_string(),
                bucket(section.virtual_size as u64)
            )
        })
        .collect::<Vec<_>>();
    let executable_sections = pe
        .sections
        .iter()
        .filter(|section| section.is_executable())
        .map(|section| section.name.clone())
        .collect::<Vec<_>>();

    let mut tags = BTreeSet::new();
    if imports.iter().any(|item| item.starts_with("ntoskrnl.exe!")) {
        tags.insert("kernel-imports".to_owned());
    }
    if !exports.is_empty() {
        tags.insert("exports".to_owned());
    }
    if strings.len() < 4 {
        tags.insert("low-string-surface".to_owned());
    }
    if pe.anomalies.iter().any(|a| a.severity == "high") {
        tags.insert("pe-anomaly".to_owned());
    }
    if imports.iter().any(|item| {
        item.contains("virtualalloc")
            || item.contains("writeprocessmemory")
            || item.contains("createremotethread")
            || item.contains("ntwritevirtualmemory")
    }) {
        tags.insert("process-memory-api".to_owned());
    }
    if imports.iter().any(|item| {
        item.contains("excreatecallback")
            || item.contains("psset")
            || item.contains("obregistercallbacks")
            || item.contains("cmregistercallback")
    }) {
        tags.insert("callback-registration".to_owned());
    }

    ImageTraits {
        import_hash: hex64(stable_hash_tokens(imports.iter().map(String::as_str))),
        export_hash: hex64(stable_hash_tokens(exports.iter().map(String::as_str))),
        string_hash: hex64(stable_hash_tokens(strings.iter().map(String::as_str))),
        section_hash: hex64(stable_hash_tokens(
            section_tokens.iter().map(String::as_str),
        )),
        import_count: imports.len(),
        export_count: exports.len(),
        string_count: strings.len(),
        executable_sections,
        tags: tags.into_iter().collect(),
    }
}
