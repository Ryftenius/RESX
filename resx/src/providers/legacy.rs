//! Host-aware adapters for the pre-context Rust entry points.

use std::collections::HashMap;
use std::sync::Arc;

use crate::analysis::{
    behavior, disasm, headers, image::ImageFacts, resolution, session::AnalysisSession,
};
use crate::formats::pe::{ImportDll, PeFile};

use super::exports::SystemExports;

pub fn resolution_analyze(pe: &PeFile, raw: &[u8]) -> resolution::ResolutionReport {
    resolution::analyze_with_exports(pe, raw, &SystemExports::discover())
}

/// Retained for source compatibility. Session-owned results provide safe reuse.
pub fn resolution_cached(pe: &PeFile, raw: &[u8]) -> Arc<resolution::ResolutionReport> {
    Arc::new(resolution_analyze(pe, raw))
}

pub fn resolution_arguments(
    pe: &PeFile,
    raw: &[u8],
    insns: &[iced_x86::Instruction],
) -> HashMap<u32, Vec<headers::ArgValue>> {
    resolution::call_arguments_in(&ImageFacts::new(pe, raw), &SystemExports::discover(), insns)
}

pub fn header_enrich(
    index: &headers::HeaderIndex,
    pe: &PeFile,
    raw: &[u8],
    insns: &[disasm::Instruction],
    calls: &[disasm::ApiCall],
) -> HashMap<u32, headers::CallSignature> {
    headers::enrich_calls_in(
        index,
        &ImageFacts::new(pe, raw),
        &SystemExports::discover(),
        insns,
        calls,
    )
}

pub fn behavior_with_headers(
    image: &str,
    pe: &PeFile,
    raw: &[u8],
    imports: &[ImportDll],
    headers: Option<&headers::HeaderIndex>,
) -> behavior::BehaviorReport {
    let exports = SystemExports::discover();
    let session = AnalysisSession::with_exports(pe, raw, &exports);
    behavior::analyze_with_context(image, &session, imports, headers)
}
