//! Analysis settings independent of CLI output and file lookup.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOptions {
    /// Instruction budget for linear decoding, and for function decoding when
    /// `whole_function` is off. `0` means unlimited, within a safety bound.
    pub max_insns: usize,
    pub max_bytes: usize,
    pub intel_syntax: bool,
    pub detailed_comments: bool,
    pub hostile: bool,
    /// Decode every reachable instruction of a function whose extent is known from
    /// its unwind record, instead of stopping at `max_insns`. Bounded by
    /// [`MAX_FUNCTION_INSNS`].
    pub whole_function: bool,
}

/// Safety bound on one function's decoded instructions; unwind extents come from the
/// image and may be hostile.
pub const MAX_FUNCTION_INSNS: usize = 262_144;

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            max_insns: 500,
            max_bytes: 8192,
            intel_syntax: true,
            detailed_comments: false,
            hostile: false,
            whole_function: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraversalOptions {
    pub decode: DecodeOptions,
    pub max_total: usize,
}

impl Default for TraversalOptions {
    fn default() -> Self {
        Self {
            decode: DecodeOptions::default(),
            max_total: 500,
        }
    }
}
