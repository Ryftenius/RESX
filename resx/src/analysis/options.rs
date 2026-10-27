//! Focused analysis inputs. Output format, terminal state and file lookup live
//! at the command boundary.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeOptions {
    pub max_insns: usize,
    pub max_bytes: usize,
    pub intel_syntax: bool,
    pub detailed_comments: bool,
    pub hostile: bool,
}

impl Default for DecodeOptions {
    fn default() -> Self {
        Self {
            max_insns: 500,
            max_bytes: 8192,
            intel_syntax: true,
            detailed_comments: false,
            hostile: false,
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
