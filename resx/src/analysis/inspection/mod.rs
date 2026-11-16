//! Selected image/function reports. Requests contain analysis choices, not CLI
//! configuration or output format. Callers resolve paths, symbols and providers.
//!
//! ```no_run
//! use resx_ffi::analysis::{inspection::*, options::TraversalOptions,
//!     session::AnalysisSession, symbols::SymbolIndex};
//! use resx_ffi::formats::pe::parse_pe;
//! # fn example() -> Result<(), String> {
//! let raw = std::fs::read("sample.exe").map_err(|e| e.to_string())?;
//! let pe = parse_pe(&raw).map_err(|e| e.0)?;
//! let session = AnalysisSession::new(&pe, &raw);
//! let symbols = SymbolIndex::from_exports_and_pdb(session.image().exports(), &[], pe.image_base);
//! let request = FunctionRequest {
//!     rva: pe.entry_point, name: "entry", image_name: "sample.exe", arch: pe.arch,
//!     options: TraversalOptions::default(), ssa: false, annotate_conflicts: false,
//!     reports: FunctionReports { calls: true, signature: true, ..Default::default() },
//! };
//! let instructions = decode_function(&session, &request, &symbols)?;
//! let report = inspect_function(&session, &request, &symbols, None, instructions, &[]);
//! for call in report.calls { println!("{:08X} {}", call.rva, call.label); }
//! # Ok(())
//! # }
//! ```

mod decode;
pub use decode::{decode_function, decode_reachable_function};

use std::collections::HashMap;

use crate::analysis::{
    disasm::{self, ApiCall, Instruction},
    discovery::{discover_functions_in, FunctionDiscoveryReport},
    driver::{self, DriverReport},
    headers::{self, CallSignature, HeaderIndex},
    indirect::{analyze_indirect_flow_view, IndirectFlowReport},
    intelli::{analyze_image, IntelliFinding},
    ir::{summarize_typed_ir, TypedIrSummary},
    options::TraversalOptions,
    reconstruction::{
        decode_conflicts::{self, DecodeConflicts},
        signature::{self, FunctionSignature},
    },
    recursive_cfg::{recover_cfg, CfgRequest, RecursiveCfg},
    session::AnalysisSession,
    symbols::SymbolIndex,
};
use crate::formats::{
    pdb::PdbSymbol,
    pe::{Export, PeDataView},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImageReports {
    pub discovery: bool,
    pub data: bool,
    pub indirect_flow: bool,
    pub intelli: bool,
}

pub struct ImageReport<'a> {
    pub discovery: Option<FunctionDiscoveryReport>,
    pub data: Option<PeDataView<'a>>,
    pub indirect_flow: Option<IndirectFlowReport>,
    pub intelli: Vec<IntelliFinding>,
}

pub fn inspect_image<'a>(
    session: &'a AnalysisSession<'_>,
    reports: ImageReports,
    symbols: &SymbolIndex,
    pdb_symbols: &[PdbSymbol],
    max_total: usize,
) -> ImageReport<'a> {
    let facts = session.image();
    ImageReport {
        discovery: reports.discovery.then(|| {
            discover_functions_in(
                facts,
                facts.exports(),
                symbols,
                pdb_symbols,
                facts.startup_routines(),
                max_total,
            )
        }),
        data: reports.data.then(|| facts.data_summary()),
        indirect_flow: reports.indirect_flow.then(|| {
            analyze_indirect_flow_view(
                facts.pe(),
                facts.imports(),
                facts.data_summary(),
                &[],
                facts.load_config(),
            )
        }),
        intelli: if reports.intelli {
            analyze_image(facts.raw(), facts.imports(), None)
        } else {
            Vec::new()
        },
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct FunctionReports {
    pub calls: bool,
    /// Collect calls and recover arguments using the supplied SDK index, if any.
    pub arguments: bool,
    /// Collect calls and apply the session's dynamic API resolution report.
    pub dynamic_resolution: bool,
    pub strings: bool,
    pub data: bool,
    pub signature: bool,
    pub decode_conflicts: bool,
    pub typed_ir: bool,
    pub recursive_cfg: bool,
    pub indirect_flow: bool,
    pub intelli: bool,
    pub recomp: bool,
    pub flow_contracts: bool,
}

pub struct FunctionRequest<'a> {
    pub rva: u32,
    pub name: &'a str,
    pub image_name: &'a str,
    pub arch: u32,
    pub options: TraversalOptions,
    pub reports: FunctionReports,
    pub ssa: bool,
    pub annotate_conflicts: bool,
}

pub struct FunctionReport<'a> {
    pub instructions: Vec<Instruction>,
    pub calls: Vec<ApiCall>,
    pub arguments: HashMap<u32, CallSignature>,
    pub strings: Vec<String>,
    pub data: Option<PeDataView<'a>>,
    pub signature: Option<FunctionSignature>,
    pub decode_conflicts: Option<DecodeConflicts>,
    pub typed_ir: Option<TypedIrSummary>,
    pub recursive_cfg: Option<RecursiveCfg>,
    pub indirect_flow: Option<IndirectFlowReport>,
    pub intelli: Vec<IntelliFinding>,
    pub recomp: String,
    pub flow_contracts: Option<DriverReport>,
}

/// Analyze decoded instructions plus any caller-supplied switch targets. Symbol
/// and SDK lookup, cross-image tracing and live checks remain caller operations.
pub fn inspect_function<'a>(
    session: &'a AnalysisSession<'_>,
    request: &FunctionRequest<'_>,
    symbols: &SymbolIndex,
    headers: Option<&HeaderIndex>,
    mut insns: Vec<Instruction>,
    synthetic_calls: &[ApiCall],
) -> FunctionReport<'a> {
    let facts = session.image();
    let pe = facts.pe();
    let reports = request.reports;
    let calls = if reports.calls || reports.arguments || reports.dynamic_resolution {
        let mut calls = disasm::collect_api_calls_in(
            &insns,
            facts,
            symbols,
            pe.image_base,
            request.options.decode.hostile,
        );
        let switch_sites: std::collections::HashSet<_> =
            synthetic_calls.iter().map(|c| c.rva).collect();
        calls.retain(|c| !(c.is_indirect && c.target_rva == 0 && switch_sites.contains(&c.rva)));
        calls.extend_from_slice(synthetic_calls);
        if reports.dynamic_resolution {
            disasm::apply_dynamic_resolution(&mut calls, &insns, session.resolution());
        }
        calls.sort_by_key(|c| c.rva);
        calls
    } else {
        Vec::new()
    };
    let arguments = if reports.arguments {
        headers
            .map(|index| headers::enrich_calls_in(index, facts, session.exports(), &insns, &calls))
            .unwrap_or_default()
    } else {
        HashMap::new()
    };
    for insn in &mut insns {
        if let Some(signature) = arguments.get(&insn.rva) {
            if !insn.comment.is_empty() {
                insn.comment.push_str(" | ");
            }
            insn.comment.push_str(&signature.call);
        }
    }
    let prototype = symbols
        .exact(pe.image_base + u64::from(request.rva))
        .map(|s| s.type_name)
        .unwrap_or_default();
    let signature = reports
        .signature
        .then(|| signature::infer(&insns, request.rva, request.arch, request.name, &prototype));
    let conflicts = reports
        .decode_conflicts
        .then(|| decode_conflicts::inspect(&insns, request.arch));
    if request.annotate_conflicts {
        if let Some(conflicts) = &conflicts {
            decode_conflicts::annotate(&mut insns, conflicts);
        }
    }
    let typed_ir = reports
        .typed_ir
        .then(|| summarize_typed_ir(&insns, pe.image_base, Some(symbols), &prototype));
    let recursive_cfg = reports.recursive_cfg.then(|| {
        recover_cfg(CfgRequest {
            raw: facts.raw(),
            pe,
            start_rva: request.rva,
            arch: request.arch,
            image_base: pe.image_base,
            exports: facts.exports(),
            symbols: Some(symbols),
            options: &request.options,
            prototype: &prototype,
        })
    });
    let indirect_flow = reports.indirect_flow.then(|| {
        analyze_indirect_flow_view(
            pe,
            facts.imports(),
            facts.data_summary(),
            &calls,
            facts.load_config(),
        )
    });
    let intelli = if reports.intelli {
        analyze_image(facts.raw(), facts.imports(), Some(&insns))
    } else {
        Vec::new()
    };
    let recomp = if reports.recomp {
        let export = Export {
            name: request.name.to_owned(),
            rva: request.rva,
            ordinal: 0,
            forward_to: String::new(),
        };
        crate::analysis::recomp::reconstruct_c(
            &insns,
            &export,
            request.arch,
            pe.image_base,
            Some(symbols),
            crate::formats::pe::read_runtime_function(pe, facts.raw(), request.rva).as_ref(),
        )
    } else {
        String::new()
    };
    FunctionReport {
        strings: if reports.strings {
            disasm::find_string_refs(facts.raw(), pe, &insns)
        } else {
            Vec::new()
        },
        data: reports.data.then(|| facts.data_summary()),
        instructions: insns,
        calls,
        arguments,
        signature,
        decode_conflicts: conflicts,
        typed_ir,
        recursive_cfg,
        indirect_flow,
        intelli,
        recomp,
        flow_contracts: reports
            .flow_contracts
            .then(|| driver::analyze_driver_in(request.image_name, facts)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::image::tests::{image, imported_image};

    fn request(reports: FunctionReports) -> FunctionRequest<'static> {
        FunctionRequest {
            rva: 0x1000,
            name: "Entry",
            image_name: "sample",
            arch: 64,
            options: TraversalOptions::default(),
            reports,
            ssa: false,
            annotate_conflicts: false,
        }
    }

    #[test]
    fn narrow_requests_do_not_initialize_unrelated_analyses() {
        let (pe, mut raw) = imported_image();
        // call [Sleep]; ret
        raw[0x200..0x207].copy_from_slice(&[0xff, 0x15, 0x5a, 1, 0, 0, 0xc3]);
        let session = AnalysisSession::new(&pe, &raw);
        let symbols = SymbolIndex::from_exports_and_pdb(&[], &[], pe.image_base);
        let mut req = request(FunctionReports {
            signature: true,
            ..Default::default()
        });
        let insns = decode_function(&session, &req, &symbols).unwrap();
        let report = inspect_function(&session, &req, &symbols, None, insns.clone(), &[]);
        assert!(report.signature.is_some());
        assert!(report.calls.is_empty());
        assert!(report.recursive_cfg.is_none());
        assert!(!session.image().data_summary_initialized());
        assert!(!session.resolution_initialized());

        req.reports.calls = true;
        let report = inspect_function(&session, &req, &symbols, None, insns.clone(), &[]);
        assert_eq!(report.calls.len(), 1);
        assert!(report.calls[0].label.contains("Sleep"));
        assert!(!session.resolution_initialized());
        req.reports.dynamic_resolution = true;
        let report = inspect_function(&session, &req, &symbols, None, insns, &[]);
        assert_eq!(report.calls.len(), 1);
        assert!(session.resolution_initialized());
        assert!(!session.image().data_summary_initialized());
    }

    #[test]
    fn selected_image_and_function_reports_share_data_facts() {
        let pe = image();
        let mut raw = vec![0; 0x400];
        raw[0x200] = 0xc3;
        let session = AnalysisSession::new(&pe, &raw);
        let symbols = SymbolIndex::from_exports_and_pdb(&[], &[], pe.image_base);
        let empty = inspect_image(&session, ImageReports::default(), &symbols, &[], 64);
        assert!(empty.discovery.is_none());
        assert!(!session.image().data_summary_initialized());
        let image = inspect_image(
            &session,
            ImageReports {
                discovery: true,
                data: true,
                indirect_flow: true,
                intelli: false,
            },
            &symbols,
            &[],
            64,
        );
        assert!(image.discovery.is_some());
        assert!(image.indirect_flow.is_some());
        let req = request(FunctionReports {
            data: true,
            indirect_flow: true,
            ..Default::default()
        });
        let function = inspect_function(
            &session,
            &req,
            &symbols,
            None,
            decode_function(&session, &req, &symbols).unwrap(),
            &[],
        );
        assert!(std::ptr::eq(
            image.data.unwrap().pointers,
            function.data.unwrap().pointers
        ));
        assert!(std::ptr::eq(
            function.data.unwrap().runtime_functions,
            session.image().runtime_functions()
        ));
        assert!(function.indirect_flow.is_some());
        assert!(!session.resolution_initialized());
    }

    #[test]
    fn reachable_decode_keeps_both_branches_and_respects_instruction_budget() {
        let pe = image();
        let mut raw = vec![0xcc; 0x400];
        raw[0x200..0x20d].copy_from_slice(&[
            0x85, 0xc0, 0x74, 3, 0x31, 0xc0, 0xc3, 0xb8, 1, 0, 0, 0, 0xc3,
        ]);
        let session = AnalysisSession::new(&pe, &raw);
        let symbols = SymbolIndex::from_exports_and_pdb(&[], &[], pe.image_base);
        let mut req = request(FunctionReports::default());
        let insns = decode_function(&session, &req, &symbols).unwrap();
        assert_eq!(
            insns.iter().map(|i| i.rva).collect::<Vec<_>>(),
            [0x1000, 0x1002, 0x1004, 0x1006, 0x1007, 0x100c]
        );
        for limit in [1, 2, 3] {
            req.options.decode.max_insns = limit;
            assert_eq!(
                decode_function(&session, &req, &symbols).unwrap().len(),
                limit
            );
        }
        req.arch = 16;
        assert!(decode_function(&session, &req, &symbols).is_err());
        req.arch = 64;
        req.rva = 0x3000;
        assert!(decode_function(&session, &req, &symbols).is_err());
    }
}
