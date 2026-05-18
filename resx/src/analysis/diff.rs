use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use iced_x86::{OpKind, Register};
use serde::{Deserialize, Serialize};

use crate::analysis::cfgview::{build_basic_blocks, BasicBlock};
use crate::analysis::disasm::{collect_api_calls, disassemble_at, find_string_refs, Instruction};
use crate::analysis::discovery::{discover_functions, DiscoveredFunction};
use crate::analysis::symbols::SymbolIndex;
use crate::core::config::Config;
use crate::core::output::ProgressBar;
use crate::formats::pdb::load_pdb_symbols;
use crate::formats::pe::{
    find_startup_routines, parse_pe, read_data_summary, read_exports, read_imports, Export,
    ImportDll, PeDataSummary, PeFile,
};

#[derive(Debug, Clone)]
pub struct DiffRequest<'a> {
    pub left_path: &'a Path,
    pub right_path: &'a Path,
    pub cfg: &'a Config,
}

#[derive(Debug, Clone)]
pub struct CfgDiffRequest<'a> {
    pub left_path: &'a Path,
    pub right_path: &'a Path,
    pub target: &'a str,
    pub cfg: &'a Config,
}

#[derive(Debug, Clone)]
pub struct MultiDiffRequest<'a> {
    pub paths: &'a [std::path::PathBuf],
    pub cfg: &'a Config,
}

#[derive(Debug, Serialize)]
pub struct DiffReport {
    pub options: DiffOptionsReport,
    pub left: DiffImageSummary,
    pub right: DiffImageSummary,
    pub summary: DiffSummary,
    pub metadata: MetadataDelta,
    pub matches: Vec<FunctionMatch>,
    pub left_only: Vec<FunctionRef>,
    pub right_only: Vec<FunctionRef>,
    pub changed_clusters: Vec<DiffCluster>,
    pub signature_hints: SignatureHints,
    pub heatmap: DiffHeatmap,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MultiDiffReport {
    pub options: DiffOptionsReport,
    pub images: Vec<DiffImageSummary>,
    pub pairs: Vec<MultiDiffPair>,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct MultiDiffPair {
    pub left_index: usize,
    pub right_index: usize,
    pub left: DiffImageSummary,
    pub right: DiffImageSummary,
    pub summary: DiffSummary,
    pub metadata: MetadataDelta,
    pub heatmap: DiffHeatmap,
    pub changed_clusters: Vec<DiffCluster>,
    pub signature_hints: SignatureHints,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffOptionsReport {
    pub mode: String,
    pub threshold: u8,
    pub include_weak: bool,
    pub max_functions: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiffImageSummary {
    pub path: String,
    pub name: String,
    pub arch: String,
    pub image_base: String,
    pub entry_point: String,
    pub size_bytes: u64,
    pub exports: usize,
    pub imports: usize,
    pub strings: usize,
    pub discovered_functions: usize,
    pub profiled_functions: usize,
    #[serde(default)]
    pub sections: Vec<SectionEntropy>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionEntropy {
    pub name: String,
    pub rva: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub protection: String,
    pub entropy: f64,
    pub executable: bool,
}

#[derive(Debug, Serialize)]
pub struct DiffSummary {
    pub similarity_score: u8,
    pub unique_similarity_score: u8,
    pub left_function_coverage: u8,
    pub right_function_coverage: u8,
    pub matched_functions: usize,
    pub unique_matched_functions: usize,
    pub noisy_matches: usize,
    pub exact_matches: usize,
    pub strong_matches: usize,
    pub changed_matches: usize,
    pub weak_matches: usize,
    pub left_only_functions: usize,
    pub right_only_functions: usize,
}

#[derive(Debug, Serialize)]
pub struct MetadataDelta {
    pub common_exports: usize,
    pub left_only_exports: Vec<String>,
    pub right_only_exports: Vec<String>,
    pub common_imports: usize,
    pub left_only_imports: Vec<String>,
    pub right_only_imports: Vec<String>,
    pub common_strings: usize,
    pub left_only_strings: Vec<String>,
    pub right_only_strings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FunctionRef {
    pub name: String,
    pub rva: String,
    pub section: String,
    pub source: String,
    pub confidence: u8,
    pub size_bytes: usize,
    pub insn_count: usize,
    pub block_count: usize,
    pub edge_count: usize,
    pub semantic_hash: String,
    pub cfg_hash: String,
    pub api_hash: String,
    pub fuzzy_hash: String,
    pub noise: bool,
    pub noise_reason: String,
    pub trait_tags: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct FunctionMatch {
    pub tier: String,
    pub score: u8,
    pub left: FunctionRef,
    pub right: FunctionRef,
    pub evidence: MatchEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct MatchEvidence {
    pub semantic_hash_equal: bool,
    pub cfg_score: u8,
    pub block_score: u8,
    pub opcode_score: u8,
    pub api_score: u8,
    pub constant_score: u8,
    pub size_score: u8,
    pub name_score: u8,
    pub shared_apis: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct DiffCluster {
    pub kind: String,
    pub side: String,
    pub section: String,
    pub start_rva: String,
    pub end_rva: String,
    pub functions: usize,
    pub average_score: u8,
    pub examples: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SignatureHints {
    pub stable_semantic_hashes: Vec<String>,
    pub stable_function_names: Vec<String>,
    pub shared_imports: Vec<String>,
    pub shared_strings: Vec<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffHeatmap {
    pub section_entropy: Vec<SectionEntropyDelta>,
    pub signal_averages: DiffSignalAverages,
    pub hotspots: Vec<DiffHotspot>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SectionEntropyDelta {
    pub section: String,
    pub left_entropy: Option<f64>,
    pub right_entropy: Option<f64>,
    pub entropy_delta: Option<f64>,
    pub left_size: Option<u32>,
    pub right_size: Option<u32>,
    pub protection: String,
    pub executable: bool,
    pub heat: u8,
    pub note: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffSignalAverages {
    pub cfg_score: u8,
    pub block_score: u8,
    pub opcode_score: u8,
    pub api_score: u8,
    pub constant_score: u8,
    pub size_score: u8,
    pub name_score: u8,
}

#[derive(Debug, Clone, Serialize)]
pub struct DiffHotspot {
    pub kind: String,
    pub heat: u8,
    pub score: u8,
    pub left_name: String,
    pub right_name: String,
    pub left_rva: String,
    pub right_rva: String,
    pub section: String,
    pub entropy_delta: Option<f64>,
    pub signals: Option<MatchEvidence>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusIndex {
    pub schema_version: u32,
    pub kind: String,
    pub root: String,
    pub created_by: String,
    pub options: DiffOptionsReport,
    pub images: Vec<IndexedImage>,
    pub skipped: Vec<IndexSkip>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexSkip {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedImage {
    pub summary: DiffImageSummary,
    pub traits: ImageTraits,
    pub exports: Vec<String>,
    pub imports: Vec<String>,
    pub strings: Vec<String>,
    pub functions: Vec<IndexedFunction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageTraits {
    pub import_hash: String,
    pub export_hash: String,
    pub string_hash: String,
    pub section_hash: String,
    pub import_count: usize,
    pub export_count: usize,
    pub string_count: usize,
    pub executable_sections: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexedFunction {
    pub name: String,
    pub rva: String,
    pub section: String,
    pub source: String,
    pub confidence: u8,
    pub size_bytes: usize,
    pub insn_count: usize,
    pub block_count: usize,
    pub edge_count: usize,
    pub semantic_hash: String,
    pub cfg_hash: String,
    pub api_hash: String,
    pub fuzzy_hash: String,
    pub shape_tokens: Vec<String>,
    pub block_hashes: Vec<String>,
    pub opcode_ngrams: Vec<String>,
    pub api_set: Vec<String>,
    pub const_set: Vec<String>,
    pub internal_targets: Vec<String>,
    pub noise: bool,
    pub noise_reason: String,
    pub trait_tags: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HuntReport {
    pub options: DiffOptionsReport,
    pub index_root: String,
    pub sample: DiffImageSummary,
    pub indexed_images: usize,
    pub candidates: Vec<HuntCandidate>,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HuntCandidate {
    pub rank: usize,
    pub path: String,
    pub name: String,
    pub arch: String,
    pub score: u8,
    pub unique_score: u8,
    pub metadata_score: u8,
    pub left_coverage: u8,
    pub right_coverage: u8,
    pub matched_functions: usize,
    pub exact_matches: usize,
    pub strong_matches: usize,
    pub changed_matches: usize,
    pub weak_matches: usize,
    pub noisy_matches: usize,
    pub family_tags: Vec<String>,
    pub signature_hints: SignatureHints,
    pub top_matches: Vec<HuntFunctionMatch>,
}

#[derive(Debug, Serialize)]
pub struct HuntFunctionMatch {
    pub tier: String,
    pub score: u8,
    pub sample: FunctionRef,
    pub candidate: FunctionRef,
    pub evidence: MatchEvidence,
}

#[derive(Debug, Serialize)]
pub struct CfgDiffReport {
    pub options: DiffOptionsReport,
    pub target: String,
    pub left_image: DiffImageSummary,
    pub right_image: DiffImageSummary,
    pub left_function: FunctionRef,
    pub right_function: FunctionRef,
    pub summary: CfgDiffSummary,
    pub blocks: Vec<CfgBlockDiff>,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct CfgDiffSummary {
    pub score: u8,
    pub matched_blocks: usize,
    pub exact_blocks: usize,
    pub changed_blocks: usize,
    pub left_only_blocks: usize,
    pub right_only_blocks: usize,
    pub left_block_coverage: u8,
    pub right_block_coverage: u8,
}

#[derive(Debug, Serialize)]
pub struct CfgBlockDiff {
    pub tier: String,
    pub score: u8,
    pub left: Option<CfgBlockRef>,
    pub right: Option<CfgBlockRef>,
    pub evidence: CfgBlockEvidence,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgBlockRef {
    pub id: usize,
    pub rva: String,
    pub end_rva: String,
    pub insn_count: usize,
    pub hash: String,
    pub edges: Vec<String>,
    pub lines: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct CfgBlockEvidence {
    pub normalized_hash_equal: bool,
    pub op_score: u8,
    pub api_score: u8,
    pub constant_score: u8,
    pub edge_score: u8,
    pub notes: Vec<String>,
}

#[derive(Debug)]
struct ImageProfile {
    summary: DiffImageSummary,
    traits: ImageTraits,
    functions: Vec<FunctionFingerprint>,
    exports: BTreeSet<String>,
    imports: BTreeSet<String>,
    strings: BTreeSet<String>,
}

#[derive(Debug, Clone)]
struct FunctionFingerprint {
    name: String,
    rva: u32,
    section: String,
    source: String,
    confidence: u8,
    size_bytes: usize,
    insn_count: usize,
    block_count: usize,
    edge_count: usize,
    semantic_hash: u64,
    cfg_hash: u64,
    api_hash: u64,
    shape_tokens: Vec<String>,
    block_hashes: Vec<u64>,
    opcode_ngrams: Vec<String>,
    api_set: BTreeSet<String>,
    const_set: BTreeSet<String>,
    string_ref_count: usize,
    internal_targets: Vec<u32>,
    fuzzy_hash: u64,
    noise: bool,
    noise_reason: String,
    trait_tags: Vec<String>,
}

#[derive(Debug, Clone)]
struct CandidateMatch {
    left_idx: usize,
    right_idx: usize,
    score: u8,
    evidence: MatchEvidence,
}

#[derive(Debug, Clone)]
struct CfgFunctionProfile {
    function: FunctionRef,
    blocks: Vec<CfgBlockProfile>,
}

#[derive(Debug, Clone)]
struct CfgBlockProfile {
    id: usize,
    start_rva: u32,
    end_rva: u32,
    insn_count: usize,
    hash: u64,
    normalized_ops: Vec<String>,
    opcode_ngrams: Vec<String>,
    api_set: BTreeSet<String>,
    const_set: BTreeSet<String>,
    edge_tokens: Vec<String>,
    display_edges: Vec<String>,
    lines: Vec<String>,
}

#[derive(Debug, Clone)]
struct CfgBlockCandidate {
    left_idx: usize,
    right_idx: usize,
    score: u8,
    evidence: CfgBlockEvidence,
}

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

fn diff_profile_pair(
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

fn profile_image_as_indexed(path: &Path, cfg: &Config, side: &str) -> Result<IndexedImage, String> {
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

fn profile_image(
    path: &Path,
    side: &str,
    pdb_file: &str,
    mode: &str,
    max_functions: usize,
    cfg: &Config,
) -> Result<ImageProfile, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read '{}': {}", path.display(), e))?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    let arch = cfg.effective_arch(pe.arch);
    let exports = read_exports(&pe, &raw);
    let imports = read_imports(&pe, &raw);
    let data = read_data_summary(&pe, &raw);
    let startup = find_startup_routines(&pe, &raw);
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

    let mut discovery_cfg = cfg.clone();
    discovery_cfg.max_total = discovery_cfg.max_total.max(max_functions);
    let discovery = discover_functions(
        &raw,
        &pe,
        &exports,
        &symbol_index,
        &pdb_symbols,
        &startup,
        &discovery_cfg,
    );

    let mut discovered = discovery.functions.clone();
    discovered.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| parse_hex32(&a.rva).cmp(&parse_hex32(&b.rva)))
    });
    discovered.truncate(max_functions);
    discovered.sort_by_key(|item| item.rva.clone());

    let import_slots = import_slot_map(&imports);
    let import_names = import_name_set(&imports);
    let export_names = export_name_set(&exports);
    let strings = string_set(&data);
    let string_rvas = data.strings.iter().map(|s| s.rva).collect::<BTreeSet<_>>();

    let mut notes = discovery
        .notes
        .iter()
        .map(|note| format!("{}: {}", side, note))
        .collect::<Vec<_>>();
    if !cfg.no_pdb && pdb_symbols.is_empty() {
        notes.push(format!(
            "{}: PDB symbols were unavailable; diff falls back to static discovery",
            side
        ));
    }
    if discovery.stats.total > max_functions {
        notes.push(format!(
            "{}: profiled {} of {} discovered functions due to --max-functions",
            side, max_functions, discovery.stats.total
        ));
    }

    let mut decode_cfg = decode_config(cfg, mode);
    let mut functions = Vec::new();
    let progress = ProgressBar::new(
        discovered.len(),
        !cfg.quiet && !cfg.json && !discovered.is_empty(),
        false,
    );
    for function in &discovered {
        progress.tick(&format!("{}: {}", side, function.name));
        match profile_function(
            function,
            &raw,
            &pe,
            arch,
            &exports,
            &symbol_index,
            &import_slots,
            &string_rvas,
            &mut decode_cfg,
        ) {
            Ok(Some(fp)) => functions.push(fp),
            Ok(None) => {}
            Err(err) => notes.push(format!("{}: {}: {}", side, function.name, err)),
        }
    }
    progress.finish();
    prune_nested_function_hints(&mut functions, &mut notes, side);

    let import_count = imports.iter().map(|dll| dll.entries.len()).sum();
    let traits = image_traits(&pe, &export_names, &import_names, &strings);
    let summary = DiffImageSummary {
        path: path_str,
        name: path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string(),
        arch: format!("x{}", arch),
        image_base: hex64(pe.image_base),
        entry_point: hex32(pe.entry_point),
        size_bytes: raw.len() as u64,
        exports: exports.len(),
        imports: import_count,
        strings: data.strings.len(),
        discovered_functions: discovery.stats.total,
        profiled_functions: functions.len(),
        sections: section_entropy(&pe),
        notes: dedupe_strings(notes),
    };

    Ok(ImageProfile {
        summary,
        traits,
        functions,
        exports: export_names,
        imports: import_names,
        strings,
    })
}

fn indexed_image_from_profile(profile: &ImageProfile) -> IndexedImage {
    IndexedImage {
        summary: profile.summary.clone(),
        traits: profile.traits.clone(),
        exports: profile.exports.iter().cloned().collect(),
        imports: profile.imports.iter().cloned().collect(),
        strings: profile.strings.iter().take(4096).cloned().collect(),
        functions: profile.functions.iter().map(indexed_function).collect(),
    }
}

fn indexed_function(fp: &FunctionFingerprint) -> IndexedFunction {
    IndexedFunction {
        name: fp.name.clone(),
        rva: hex32(fp.rva),
        section: fp.section.clone(),
        source: fp.source.clone(),
        confidence: fp.confidence,
        size_bytes: fp.size_bytes,
        insn_count: fp.insn_count,
        block_count: fp.block_count,
        edge_count: fp.edge_count,
        semantic_hash: hex64(fp.semantic_hash),
        cfg_hash: hex64(fp.cfg_hash),
        api_hash: hex64(fp.api_hash),
        fuzzy_hash: hex64(fp.fuzzy_hash),
        shape_tokens: fp.shape_tokens.clone(),
        block_hashes: fp.block_hashes.iter().map(|hash| hex64(*hash)).collect(),
        opcode_ngrams: fp.opcode_ngrams.clone(),
        api_set: fp.api_set.iter().cloned().collect(),
        const_set: fp.const_set.iter().cloned().collect(),
        internal_targets: fp
            .internal_targets
            .iter()
            .map(|target| hex32(*target))
            .collect(),
        noise: fp.noise,
        noise_reason: fp.noise_reason.clone(),
        trait_tags: fp.trait_tags.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn profile_function(
    function: &DiscoveredFunction,
    raw: &[u8],
    pe: &PeFile,
    arch: u32,
    exports: &[Export],
    symbols: &SymbolIndex,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
    cfg: &mut Config,
) -> Result<Option<FunctionFingerprint>, String> {
    let Some(rva) = parse_hex32(&function.rva) else {
        return Ok(None);
    };
    let Some(file_off) = pe.rva_to_offset(rva) else {
        return Ok(None);
    };
    if !pe
        .rva_to_section(rva)
        .is_some_and(|section| section.is_executable())
    {
        return Ok(None);
    }

    let insns = disassemble_at(
        raw,
        pe,
        file_off,
        rva,
        arch,
        pe.image_base,
        exports,
        Some(symbols),
        cfg,
    )
    .map_err(|e| format!("disassembly failed: {}", e))?;
    if insns.is_empty() {
        return Ok(None);
    }

    let blocks = build_basic_blocks(&insns, pe.image_base);
    let block_ids = blocks
        .iter()
        .enumerate()
        .map(|(idx, block)| (block.start_rva, idx))
        .collect::<BTreeMap<_, _>>();

    let mut normalized_ops = Vec::with_capacity(insns.len());
    let mut opcodes = Vec::with_capacity(insns.len());
    let mut const_set = BTreeSet::new();
    for insn in &insns {
        let normalized = normalize_instruction(insn, pe, import_slots, string_rvas, &block_ids);
        opcodes.push(normalized.opcode);
        const_set.extend(normalized.constants);
        normalized_ops.push(normalized.text);
    }

    let mut block_hashes = Vec::new();
    let mut shape_tokens = Vec::new();
    for block in &blocks {
        let mut block_ops = Vec::new();
        for insn in &block.insns {
            let normalized = normalize_instruction(insn, pe, import_slots, string_rvas, &block_ids);
            block_ops.push(normalized.text);
        }
        block_hashes.push(stable_hash_tokens(&block_ops));
        shape_tokens.push(format!("block:{}", bucket(block.insns.len() as u64)));
        for edge in &block.edges {
            shape_tokens.push(format!("edge:{}", edge.kind));
        }
    }

    let api_calls = collect_api_calls(&insns, pe, raw, symbols, pe.image_base, cfg.hostile);
    let api_set = api_calls
        .iter()
        .filter_map(normalized_api_call)
        .collect::<BTreeSet<_>>();
    let internal_targets = api_calls
        .iter()
        .filter(|call| !call.is_import && call.target_rva != 0)
        .filter(|call| {
            pe.rva_to_section(call.target_rva)
                .is_some_and(|section| section.is_executable())
        })
        .map(|call| call.target_rva)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let api_hash = stable_hash_tokens(api_set.iter().map(String::as_str));
    let string_ref_count = find_string_refs(raw, pe, &insns).len();

    let size_bytes = function_size(&insns);
    let semantic_hash = stable_hash_tokens(&normalized_ops);
    let cfg_hash = stable_hash_tokens(&shape_tokens);
    let edge_count = blocks.iter().map(|block| block.edges.len()).sum();
    let fuzzy_hash = simhash_tokens(
        shape_tokens
            .iter()
            .chain(opcodes.iter())
            .chain(api_set.iter())
            .map(String::as_str),
    );
    let (noise, noise_reason, trait_tags) = classify_function(FunctionClassification {
        name: &function.name,
        source: &function.source,
        confidence: function.confidence,
        size_bytes,
        insn_count: insns.len(),
        block_count: blocks.len(),
        edge_count,
        api_set: &api_set,
        string_ref_count,
    });

    Ok(Some(FunctionFingerprint {
        name: function.name.clone(),
        rva,
        section: function.section.clone(),
        source: function.source.clone(),
        confidence: function.confidence,
        size_bytes,
        insn_count: insns.len(),
        block_count: blocks.len(),
        edge_count,
        semantic_hash,
        cfg_hash,
        api_hash,
        shape_tokens,
        block_hashes,
        opcode_ngrams: ngrams(&opcodes, 3),
        api_set,
        const_set,
        string_ref_count,
        internal_targets,
        fuzzy_hash,
        noise,
        noise_reason,
        trait_tags,
    }))
}

fn select_cfg_diff_pair(
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

fn function_matches_target(fp: &FunctionFingerprint, target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    if fp.name.eq_ignore_ascii_case(target) {
        return true;
    }
    parse_hex32(target).is_some_and(|rva| rva == fp.rva)
}

fn profile_cfg_function(
    path: &Path,
    fp: &FunctionFingerprint,
    pdb_file: &str,
    mode: &str,
    max_blocks: usize,
    cfg: &Config,
) -> Result<CfgFunctionProfile, String> {
    let raw = std::fs::read(path).map_err(|e| format!("read '{}': {}", path.display(), e))?;
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
fn cfg_block_profile(
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

fn diff_cfg_blocks(
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

fn score_cfg_block(l: &CfgBlockProfile, r: &CfgBlockProfile) -> (u8, CfgBlockEvidence) {
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

fn cfg_block_ref(block: &CfgBlockProfile) -> CfgBlockRef {
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

fn cfg_block_sort_rva(block: &CfgBlockDiff) -> u32 {
    block
        .left
        .as_ref()
        .or(block.right.as_ref())
        .and_then(|b| parse_hex32(&b.rva))
        .unwrap_or(0)
}

fn empty_cfg_block_evidence() -> CfgBlockEvidence {
    CfgBlockEvidence {
        normalized_hash_equal: false,
        op_score: 0,
        api_score: 0,
        constant_score: 0,
        edge_score: 0,
        notes: Vec::new(),
    }
}

fn cfg_block_tier(score: u8) -> &'static str {
    match score {
        98..=100 => "exact",
        80..=97 => "similar",
        55..=79 => "changed",
        _ => "weak",
    }
}

fn format_instruction_line(insn: &Instruction) -> String {
    if insn.comment.is_empty() {
        format!("0x{:08X}  {}", insn.rva, insn.text)
    } else {
        format!("0x{:08X}  {}  ; {}", insn.rva, insn.text, insn.comment)
    }
}

fn normalize_edge_label(label: &str) -> String {
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

fn candidate_matches(
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

fn score_indexed_images(
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

fn match_noise_rank(noise: bool) -> u8 {
    if noise {
        1
    } else {
        0
    }
}

fn match_name_rank(name: &str) -> u8 {
    if normalized_name(name).is_empty() {
        1
    } else {
        0
    }
}

fn plausible_indexed_pair(l: &IndexedFunction, r: &IndexedFunction) -> bool {
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

fn score_indexed_pair(l: &IndexedFunction, r: &IndexedFunction) -> (u8, MatchEvidence) {
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

fn plausible_pair(l: &FunctionFingerprint, r: &FunctionFingerprint) -> bool {
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

fn score_pair(l: &FunctionFingerprint, r: &FunctionFingerprint) -> (u8, MatchEvidence) {
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

fn build_summary(
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

fn build_indexed_summary(
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

fn metadata_delta(left: &ImageProfile, right: &ImageProfile) -> MetadataDelta {
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

fn build_heatmap(
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

fn average_signals(matches: &[FunctionMatch]) -> DiffSignalAverages {
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

fn section_entropy_delta(
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

fn section_map(sections: &[SectionEntropy]) -> BTreeMap<String, &SectionEntropy> {
    sections
        .iter()
        .map(|section| (normalized_section_key(&section.name), section))
        .collect()
}

fn entropy_delta_for_sections(
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

fn normalized_section_key(name: &str) -> String {
    name.trim()
        .trim_matches('\0')
        .trim_start_matches('.')
        .to_ascii_lowercase()
}

fn build_clusters(
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
struct ClusterItem {
    section: String,
    rva: u32,
    end_rva: u32,
    score: u8,
    label: String,
}

fn cluster_items(kind: &str, side: &str, mut items: Vec<ClusterItem>) -> Vec<DiffCluster> {
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

fn finish_cluster(kind: &str, side: &str, items: &[ClusterItem]) -> DiffCluster {
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

fn section_entropy(pe: &PeFile) -> Vec<SectionEntropy> {
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

fn image_traits(
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

struct FunctionClassification<'a> {
    name: &'a str,
    source: &'a str,
    confidence: u8,
    size_bytes: usize,
    insn_count: usize,
    block_count: usize,
    edge_count: usize,
    api_set: &'a BTreeSet<String>,
    string_ref_count: usize,
}

fn classify_function(input: FunctionClassification<'_>) -> (bool, String, Vec<String>) {
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

fn is_common_runtime_api(api: &str) -> bool {
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

fn prune_nested_function_hints(
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

fn indexed_function_ref(fp: &IndexedFunction) -> FunctionRef {
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

fn metadata_similarity_score(sample: &IndexedImage, candidate: &IndexedImage) -> u8 {
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

fn signature_hints_from_diff(
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

fn signature_hints_from_hunt(
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

fn family_tags(
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

fn options_report(
    mode: &str,
    threshold: u8,
    include_weak: bool,
    max_functions: usize,
) -> DiffOptionsReport {
    DiffOptionsReport {
        mode: mode.to_owned(),
        threshold,
        include_weak,
        max_functions,
    }
}

fn vec_to_set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

fn normalize_instruction(
    insn: &Instruction,
    pe: &PeFile,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
    block_ids: &BTreeMap<u32, usize>,
) -> NormalizedInstruction {
    let opcode = format!("{:?}", insn.iced.mnemonic()).to_ascii_lowercase();
    let mut parts = vec![opcode.clone()];
    let mut constants = Vec::new();

    for idx in 0..insn.iced.op_count() {
        let op = match insn.iced.op_kind(idx) {
            OpKind::Register => format!("reg:{}", register_class(insn.iced.op_register(idx))),
            OpKind::Memory => normalize_memory(&insn.iced, pe, import_slots, string_rvas),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                let target = insn.iced.near_branch_target();
                let label = pe
                    .va_to_rva(target)
                    .and_then(|rva| block_ids.get(&rva).copied().map(|id| format!("block:{id}")))
                    .unwrap_or_else(|| classify_address(target, pe, import_slots, string_rvas));
                format!("branch:{label}")
            }
            _ => {
                if let Some(value) = immediate_value(&insn.iced, idx) {
                    let class = classify_immediate(value, pe, import_slots, string_rvas);
                    constants.push(class.clone());
                    format!("imm:{class}")
                } else {
                    "op:?".to_owned()
                }
            }
        };
        parts.push(op);
    }

    NormalizedInstruction {
        opcode,
        text: parts.join("|"),
        constants,
    }
}

struct NormalizedInstruction {
    opcode: String,
    text: String,
    constants: Vec<String>,
}

fn normalize_memory(
    instr: &iced_x86::Instruction,
    pe: &PeFile,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
) -> String {
    let base = instr.memory_base();
    if matches!(
        base,
        Register::RSP | Register::RBP | Register::ESP | Register::EBP
    ) {
        return format!(
            "mem:stack:{}",
            displacement_class(instr.memory_displacement64())
        );
    }
    if matches!(base, Register::RIP | Register::EIP) {
        return format!(
            "mem:rip:{}",
            classify_address(instr.ip_rel_memory_address(), pe, import_slots, string_rvas)
        );
    }
    if base == Register::None && instr.memory_index() == Register::None {
        return format!(
            "mem:absolute:{}",
            classify_address(instr.memory_displacement64(), pe, import_slots, string_rvas)
        );
    }
    format!(
        "mem:{}:{}",
        register_class(base),
        displacement_class(instr.memory_displacement64())
    )
}

fn classify_immediate(
    value: u64,
    pe: &PeFile,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
) -> String {
    let address_class = classify_address(value, pe, import_slots, string_rvas);
    if address_class != "absolute" {
        return address_class;
    }
    match value {
        0 => "zero".to_owned(),
        1 => "one".to_owned(),
        2..=16 => "small".to_owned(),
        17..=0xFF => "byte".to_owned(),
        0x100..=0xFFFF => {
            if value.is_power_of_two() {
                "pow2".to_owned()
            } else {
                "word".to_owned()
            }
        }
        0x8000_0000..=0xFFFF_FFFF => {
            let v = value as u32;
            if (v & 0xC000_0000) == 0xC000_0000 || (v & 0x8000_0000) == 0x8000_0000 {
                "status".to_owned()
            } else {
                "dword".to_owned()
            }
        }
        _ => "qword".to_owned(),
    }
}

fn classify_address(
    value: u64,
    pe: &PeFile,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
) -> String {
    let rva = pe.va_to_rva(value).or_else(|| {
        u32::try_from(value)
            .ok()
            .filter(|rva| pe.rva_to_section(*rva).is_some())
    });
    let Some(rva) = rva else {
        return "absolute".to_owned();
    };
    if import_slots.contains_key(&rva) {
        return "import-slot".to_owned();
    }
    if string_rvas.contains(&rva) {
        return "string".to_owned();
    }
    if let Some(section) = pe.rva_to_section(rva) {
        if section.is_executable() {
            return "code".to_owned();
        }
        let name = section.name.to_ascii_lowercase();
        if name.contains("rdata") || name.contains("rsrc") {
            return "readonly-data".to_owned();
        }
        return "data".to_owned();
    }
    "absolute".to_owned()
}

fn displacement_class(value: u64) -> &'static str {
    if value == 0 {
        "zero"
    } else if value <= 0x7F {
        "small"
    } else if value <= 0xFFFF {
        "medium"
    } else {
        "large"
    }
}

fn register_class(reg: Register) -> &'static str {
    let name = format!("{:?}", reg).to_ascii_lowercase();
    if name == "none" {
        "none"
    } else if name.starts_with("xmm") {
        "xmm"
    } else if name.starts_with("ymm") {
        "ymm"
    } else if name.starts_with("zmm") {
        "zmm"
    } else if matches!(name.as_str(), "cs" | "ds" | "es" | "fs" | "gs" | "ss") {
        "seg"
    } else if name.starts_with('r')
        && !name.ends_with('d')
        && !name.ends_with('w')
        && !name.ends_with('l')
    {
        "gpr64"
    } else if name.starts_with('e') || name.ends_with('d') {
        "gpr32"
    } else if name.ends_with('w')
        || matches!(
            name.as_str(),
            "ax" | "bx" | "cx" | "dx" | "si" | "di" | "sp" | "bp"
        )
    {
        "gpr16"
    } else if name.ends_with('l')
        || name.ends_with('h')
        || matches!(name.as_str(), "al" | "bl" | "cl" | "dl")
    {
        "gpr8"
    } else {
        "reg"
    }
}

fn immediate_value(instr: &iced_x86::Instruction, idx: u32) -> Option<u64> {
    match instr.op_kind(idx) {
        OpKind::Immediate8 => Some(instr.immediate8() as u64),
        OpKind::Immediate16 => Some(instr.immediate16() as u64),
        OpKind::Immediate32 | OpKind::Immediate32to64 => Some(instr.immediate32() as u64),
        OpKind::Immediate64 => Some(instr.immediate64()),
        _ => None,
    }
}

fn normalized_api_call(call: &crate::analysis::disasm::ApiCall) -> Option<String> {
    if call.is_import || !call.dll.is_empty() {
        let dll = call.dll.trim().to_ascii_lowercase();
        let name = normalize_api_name(&call.label);
        return Some(if dll.is_empty() {
            name
        } else {
            format!("{dll}!{name}")
        });
    }
    let name = normalize_api_name(&call.label);
    if name.starts_with("sub_") || name.is_empty() {
        None
    } else {
        Some(name)
    }
}

fn normalize_api_name(name: &str) -> String {
    let tail = name
        .rsplit(['!', ':'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('_');
    let tail = tail
        .strip_suffix('A')
        .or_else(|| tail.strip_suffix('W'))
        .unwrap_or(tail);
    tail.to_ascii_lowercase()
}

fn normalized_name(name: &str) -> String {
    let tail = name
        .rsplit(['!', ':'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('_');
    if tail.starts_with("sub_") || tail.starts_with("fn_") {
        String::new()
    } else {
        tail.to_ascii_lowercase()
    }
}

fn name_similarity(left: &str, right: &str) -> f64 {
    let l = normalized_name(left);
    let r = normalized_name(right);
    if l.is_empty() || r.is_empty() {
        return 0.0;
    }
    if l == r {
        1.0
    } else if l.contains(&r) || r.contains(&l) {
        0.65
    } else {
        0.0
    }
}

fn function_ref(fp: &FunctionFingerprint) -> FunctionRef {
    FunctionRef {
        name: fp.name.clone(),
        rva: hex32(fp.rva),
        section: fp.section.clone(),
        source: fp.source.clone(),
        confidence: fp.confidence,
        size_bytes: fp.size_bytes,
        insn_count: fp.insn_count,
        block_count: fp.block_count,
        edge_count: fp.edge_count,
        semantic_hash: hex64(fp.semantic_hash),
        cfg_hash: hex64(fp.cfg_hash),
        api_hash: hex64(fp.api_hash),
        fuzzy_hash: hex64(fp.fuzzy_hash),
        noise: fp.noise,
        noise_reason: fp.noise_reason.clone(),
        trait_tags: fp.trait_tags.clone(),
    }
}

fn function_size(insns: &[Instruction]) -> usize {
    match (insns.first(), insns.last()) {
        (Some(first), Some(last)) => last
            .rva
            .saturating_sub(first.rva)
            .saturating_add(last.bytes.len() as u32) as usize,
        _ => 0,
    }
}

fn decode_config(cfg: &Config, mode: &str) -> Config {
    let mut out = cfg.clone();
    match mode {
        "quick" => {
            out.max_bytes = out.max_bytes.clamp(512, 2048);
            out.max_insns = out.max_insns.clamp(64, 256);
        }
        "deep" => {
            out.max_bytes = out.max_bytes.max(16 * 1024);
            out.max_insns = out.max_insns.max(2048);
        }
        _ => {
            out.max_bytes = out.max_bytes.max(4096);
            out.max_insns = out.max_insns.max(512);
        }
    }
    out
}

fn normalize_mode(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "quick" => "quick".to_owned(),
        "deep" => "deep".to_owned(),
        _ => "balanced".to_owned(),
    }
}

fn left_pdb(cfg: &Config) -> &str {
    if cfg.left_pdb_file.is_empty() {
        &cfg.pdb_file
    } else {
        &cfg.left_pdb_file
    }
}

fn right_pdb(cfg: &Config) -> &str {
    if cfg.right_pdb_file.is_empty() {
        &cfg.pdb_file
    } else {
        &cfg.right_pdb_file
    }
}

fn import_slot_map(imports: &[ImportDll]) -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    for dll in imports {
        for entry in &dll.entries {
            out.insert(
                entry.slot_rva,
                format!(
                    "{}!{}",
                    dll.dll.to_ascii_lowercase(),
                    normalize_api_name(&entry.name)
                ),
            );
        }
    }
    out
}

fn import_name_set(imports: &[ImportDll]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for dll in imports {
        for entry in &dll.entries {
            out.insert(format!(
                "{}!{}",
                dll.dll.to_ascii_lowercase(),
                normalize_api_name(&entry.name)
            ));
        }
    }
    out
}

fn export_name_set(exports: &[Export]) -> BTreeSet<String> {
    exports
        .iter()
        .filter(|e| !e.name.is_empty())
        .map(|e| normalized_name(&e.name))
        .filter(|name| !name.is_empty())
        .collect()
}

fn string_set(data: &PeDataSummary) -> BTreeSet<String> {
    data.strings
        .iter()
        .map(|s| s.value.trim().to_owned())
        .filter(|s| s.len() >= 4)
        .take(4096)
        .collect()
}

fn tier(score: u8) -> &'static str {
    match score {
        98..=100 => "exact",
        80..=97 => "strong",
        65..=79 => "changed",
        50..=64 => "weak",
        _ => "low",
    }
}

fn coverage(matched: usize, total: usize) -> u8 {
    if total == 0 {
        0
    } else {
        (((matched as f64 / total as f64) * 100.0).round() as u8).min(100)
    }
}

fn ratio(a: f64, b: f64) -> f64 {
    if a <= 0.0 && b <= 0.0 {
        1.0
    } else if a <= 0.0 || b <= 0.0 {
        0.0
    } else {
        a.min(b) / a.max(b)
    }
}

fn score_float(value: f64) -> u8 {
    (value.clamp(0.0, 1.0) * 100.0).round() as u8
}

fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn set_similarity(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f64 {
    if left.is_empty() && right.is_empty() {
        1.0
    } else {
        let common = left.intersection(right).count();
        let total = left.union(right).count();
        if total == 0 {
            0.0
        } else {
            common as f64 / total as f64
        }
    }
}

fn multiset_jaccard(left: &[String], right: &[String]) -> f64 {
    let l = count_map(left.iter().map(String::as_str));
    let r = count_map(right.iter().map(String::as_str));
    counted_jaccard(&l, &r)
}

fn multiset_jaccard_u64(left: &[u64], right: &[u64]) -> f64 {
    let l = count_map(left.iter().copied());
    let r = count_map(right.iter().copied());
    counted_jaccard(&l, &r)
}

fn count_map<T, I>(items: I) -> HashMap<T, usize>
where
    T: Eq + std::hash::Hash,
    I: IntoIterator<Item = T>,
{
    let mut map = HashMap::new();
    for item in items {
        *map.entry(item).or_insert(0) += 1;
    }
    map
}

fn counted_jaccard<T>(left: &HashMap<T, usize>, right: &HashMap<T, usize>) -> f64
where
    T: Eq + std::hash::Hash,
{
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let mut intersection = 0usize;
    let mut union = 0usize;
    let keys = left.keys().chain(right.keys()).collect::<HashSet<_>>();
    for key in keys {
        let l = left.get(key).copied().unwrap_or(0);
        let r = right.get(key).copied().unwrap_or(0);
        intersection += l.min(r);
        union += l.max(r);
    }
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

fn ngrams(tokens: &[String], n: usize) -> Vec<String> {
    if tokens.is_empty() {
        return Vec::new();
    }
    if tokens.len() < n {
        return vec![tokens.join("|")];
    }
    tokens
        .windows(n)
        .map(|window| window.join("|"))
        .collect::<Vec<_>>()
}

fn bucket(value: u64) -> &'static str {
    match value {
        0 => "0",
        1 => "1",
        2..=3 => "2-3",
        4..=7 => "4-7",
        8..=15 => "8-15",
        16..=31 => "16-31",
        32..=63 => "32-63",
        _ => "64+",
    }
}

fn stable_hash_tokens<'a, I, S>(tokens: I) -> u64
where
    I: IntoIterator<Item = S>,
    S: AsRef<str> + 'a,
{
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for token in tokens {
        for byte in token.as_ref().as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

fn stable_hash_one(token: &str) -> u64 {
    stable_hash_tokens([token])
}

fn simhash_tokens<'a, I, S>(tokens: I) -> u64
where
    I: IntoIterator<Item = S>,
    S: AsRef<str> + 'a,
{
    let mut weights = [0i32; 64];
    let mut seen = false;
    for token in tokens {
        seen = true;
        let hash = stable_hash_one(token.as_ref());
        for (idx, weight) in weights.iter_mut().enumerate() {
            if (hash >> idx) & 1 == 1 {
                *weight += 1;
            } else {
                *weight -= 1;
            }
        }
    }
    if !seen {
        return 0;
    }
    weights.iter().enumerate().fold(0u64, |acc, (idx, weight)| {
        if *weight >= 0 {
            acc | (1u64 << idx)
        } else {
            acc
        }
    })
}

fn hamming_hex64(left: &str, right: &str) -> u8 {
    let Some(l) = parse_hex64(left) else {
        return 64;
    };
    let Some(r) = parse_hex64(right) else {
        return 64;
    };
    (l ^ r).count_ones() as u8
}

fn hamming64(left: u64, right: u64) -> u8 {
    (left ^ right).count_ones() as u8
}

fn capped_delta(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).take(64).cloned().collect()
}

fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

fn parse_hex32(raw: &str) -> Option<u32> {
    let s = raw.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(hex, 16).ok()
}

fn parse_hex64(raw: &str) -> Option<u64> {
    let s = raw.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(hex, 16).ok()
}

fn hex32(value: u32) -> String {
    format!("0x{:08X}", value)
}

fn hex64(value: u64) -> String {
    format!("0x{:016X}", value)
}

#[cfg(test)]
mod tests {
    use super::{stable_hash_tokens, tier};

    #[test]
    fn stable_hash_tokens_is_reproducible() {
        let a = stable_hash_tokens(["mov|reg:gpr64|imm:small", "ret"]);
        let b = stable_hash_tokens(["mov|reg:gpr64|imm:small", "ret"]);
        let c = stable_hash_tokens(["mov|reg:gpr64|imm:byte", "ret"]);
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn score_tiers_match_public_thresholds() {
        assert_eq!(tier(100), "exact");
        assert_eq!(tier(80), "strong");
        assert_eq!(tier(65), "changed");
        assert_eq!(tier(50), "weak");
    }
}
