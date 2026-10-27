//! Translate legacy CLI defaults into explicit analysis selections once.
use crate::analysis::inspection::{FunctionReports, ImageReports};
use crate::analysis::options::TraversalOptions;
use crate::core::config::Config;

pub(super) struct DumpRequest {
    pub image: ImageReports,
    pub function: FunctionReports,
    pub options: TraversalOptions,
    pub call_tree: bool,
    pub call_syscalls: bool,
}

impl DumpRequest {
    pub fn from_config(cfg: &Config, only_metadata: bool) -> Self {
        let table_view = only_metadata
            && (cfg.sections || cfg.pechk || cfg.show_eat || cfg.show_iat || cfg.show_syms);
        Self {
            image: ImageReports {
                discovery: cfg.json && !table_view,
                data: cfg.json && only_metadata && !table_view,
                indirect_flow: cfg.json && only_metadata && !table_view,
                intelli: cfg.intelli && only_metadata,
            },
            function: FunctionReports {
                calls: cfg.funcs_depth > 0,
                dynamic_resolution: false,
                arguments: false, // enabled only after the caller obtains the SDK index
                strings: cfg.show_strings,
                data: cfg.json || cfg.show_strings,
                signature: true,
                decode_conflicts: true,
                typed_ir: cfg.json,
                recursive_cfg: cfg.json || cfg.cfg_view.eq_ignore_ascii_case("text"),
                indirect_flow: cfg.json,
                intelli: cfg.intelli,
                recomp: cfg.recomp || !cfg.c_out.is_empty(),
                flow_contracts: !cfg.json && cfg.funcs_depth > 0,
            },
            options: cfg.into(),
            call_tree: cfg.funcs_depth > 0,
            call_syscalls: cfg.json,
        }
    }
}
