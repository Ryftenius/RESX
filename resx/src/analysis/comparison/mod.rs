mod cfg;
mod classification;
mod matching;
mod normalize;
mod orchestration;
mod profile;
mod reporting;
mod sequence;

use cfg::*;
use classification::*;
use matching::*;
use normalize::*;
pub use orchestration::*;
use profile::*;
use reporting::*;
pub use sequence::*;

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
