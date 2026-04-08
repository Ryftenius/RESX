use iced_x86::{Mnemonic, OpKind, Register};
use std::fmt::Write as _;
use std::io::Write;

use crate::analysis::disasm::{collect_api_calls, disassemble_at, ApiCall, Instruction};
use crate::analysis::symbols::SymbolIndex;
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::core::search::find_dll_path;
use crate::formats::pdb::{load_pdb_symbol, load_pdb_symbols};
use crate::formats::pe::{parse_pe, read_exports, Export};

use super::style::{color_kind, color_target, is_nt_api, short_dll_name};
use super::switchfmt::{format_case_values, format_class_value};
use super::{RecoveredSwitchDispatch, RecoveredSwitchTarget};

#[allow(clippy::too_many_arguments)]
pub(super) fn print_api_calls(
    w: &mut dyn Write,
    calls: &[ApiCall],
    insns: &[Instruction],
    func_name: &str,
    c: &Colors,
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    symbol_index: &crate::analysis::symbols::SymbolIndex,
    exports: &[Export],
    arch: u32,
    image_base: u64,
    cfg: &Config,
    root_rva: u32,
) {
    let synthetic_syscall = synthetic_syscall_call(insns, func_name);
    let display_calls: Vec<ApiCall> = if let Some(call) = synthetic_syscall {
        let mut merged = calls.to_vec();
        if !merged.iter().any(|existing| {
            existing.rva == call.rva && existing.label.eq_ignore_ascii_case(&call.label)
        }) {
            merged.push(call);
        }
        merged.sort_by_key(|call| call.rva);
        merged
    } else {
        calls.to_vec()
    };

    writeln!(w).ok();
    writeln!(
        w,
        "{}",
        c.bold(&c.b_cyan(&format!(
            "API Call Map for {}  [{} call site(s)]:",
            func_name,
            display_calls.len()
        )))
    )
    .ok();

    if display_calls.is_empty() {
        writeln!(w, "{}", c.dim("  (no CALL/JMP targets found)")).ok();
        return;
    }

    let mut visited = std::collections::HashSet::new();
    visited.insert(root_rva);
    let mut dll_map: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    let root_image = TraceImageView {
        raw,
        pe,
        symbol_index,
        exports,
        arch,
        image_base,
    };

    print_calls_recursive(
        w,
        &display_calls,
        insns,
        c,
        &root_image,
        cfg,
        0,
        &mut visited,
        &mut dll_map,
        "  ",
    );
}

#[allow(clippy::too_many_arguments)]
pub(super) fn render_api_call_tree(
    calls: &[ApiCall],
    insns: &[Instruction],
    func_name: &str,
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    symbol_index: &crate::analysis::symbols::SymbolIndex,
    exports: &[Export],
    arch: u32,
    image_base: u64,
    cfg: &Config,
    root_rva: u32,
) -> String {
    let synthetic_syscall = synthetic_syscall_call(insns, func_name);
    let display_calls: Vec<ApiCall> = if let Some(call) = synthetic_syscall {
        let mut merged = calls.to_vec();
        if !merged.iter().any(|existing| {
            existing.rva == call.rva && existing.label.eq_ignore_ascii_case(&call.label)
        }) {
            merged.push(call);
        }
        merged.sort_by_key(|call| call.rva);
        merged
    } else {
        calls.to_vec()
    };

    if display_calls.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let mut visited = std::collections::HashSet::new();
    visited.insert(root_rva);
    let root_image = TraceImageView {
        raw,
        pe,
        symbol_index,
        exports,
        arch,
        image_base,
    };
    write_calls_recursive_text(
        &mut out,
        &display_calls,
        insns,
        &root_image,
        cfg,
        0,
        &mut visited,
        "  ",
    );
    out
}

#[derive(Clone)]
pub(super) struct SyscallCallDetails {
    pub kernel_module: String,
    pub kernel_symbol: String,
    pub kernel_rva: u32,
    pub service_number: Option<u32>,
}

fn synthetic_syscall_call(insns: &[Instruction], func_name: &str) -> Option<ApiCall> {
    if !is_nt_api(func_name) {
        return None;
    }

    let syscall_site = insns.iter().find(|insn| {
        matches!(insn.iced.mnemonic(), Mnemonic::Syscall | Mnemonic::Sysenter)
            || (insn.iced.mnemonic() == Mnemonic::Int && insn.iced.immediate8() == 0x2E)
    })?;

    Some(ApiCall {
        rva: syscall_site.rva,
        kind: "syscall".to_owned(),
        target_rva: 0,
        label: func_name.to_owned(),
        dll: "ntdll.dll".to_owned(),
        is_import: true,
        is_indirect: false,
        indirect_method: None,
        switch_cases: Vec::new(),
    })
}

pub(super) fn synthetic_syscall_api_call(
    insns: &[Instruction],
    func_name: &str,
) -> Option<ApiCall> {
    synthetic_syscall_call(insns, func_name)
}

fn detect_syscall_number_from_insns(insns: &[Instruction]) -> Option<u32> {
    for insn in insns.iter().take(12) {
        match insn.iced.mnemonic() {
            Mnemonic::Mov
                if insn.iced.op_count() >= 2 && insn.iced.op0_kind() == OpKind::Register =>
            {
                let dst = insn.iced.op0_register();
                if matches!(
                    dst,
                    Register::EAX | Register::RAX | Register::AX | Register::AL
                ) {
                    return match insn.iced.op1_kind() {
                        OpKind::Immediate8 => Some(insn.iced.immediate8to32() as u32),
                        OpKind::Immediate16 => Some(insn.iced.immediate16() as u32),
                        OpKind::Immediate32 => Some(insn.iced.immediate32()),
                        OpKind::Immediate32to64 => Some(insn.iced.immediate32to64() as u32),
                        OpKind::Immediate64 => Some(insn.iced.immediate64() as u32),
                        _ => None,
                    };
                }
            }
            Mnemonic::Ret => break,
            _ => {}
        }
    }
    None
}

pub(super) fn resolve_syscall_call_details(
    call: &ApiCall,
    insns: &[Instruction],
    cfg: &Config,
) -> Option<SyscallCallDetails> {
    let target = resolve_syscall_trace_target(call, insns, cfg)?;
    let service_number = if call.kind.eq_ignore_ascii_case("syscall") {
        detect_syscall_number_from_insns(insns)
    } else {
        None
    };
    Some(SyscallCallDetails {
        kernel_module: target.image.dll_name,
        kernel_symbol: target.symbol_name,
        kernel_rva: target.rva,
        service_number,
    })
}

struct TraceImageView<'a> {
    raw: &'a [u8],
    pe: &'a crate::formats::pe::PeFile,
    symbol_index: &'a crate::analysis::symbols::SymbolIndex,
    exports: &'a [Export],
    arch: u32,
    image_base: u64,
}

struct LoadedTraceImage {
    dll_name: String,
    dll_path: String,
    raw: Vec<u8>,
    pe: crate::formats::pe::PeFile,
    exports: Vec<Export>,
    symbol_index: crate::analysis::symbols::SymbolIndex,
    arch: u32,
    image_base: u64,
}

impl LoadedTraceImage {
    fn as_view(&self) -> TraceImageView<'_> {
        TraceImageView {
            raw: &self.raw,
            pe: &self.pe,
            symbol_index: &self.symbol_index,
            exports: &self.exports,
            arch: self.arch,
            image_base: self.image_base,
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn print_calls_recursive(
    w: &mut dyn Write,
    calls: &[ApiCall],
    insns: &[Instruction],
    c: &Colors,
    image: &TraceImageView<'_>,
    cfg: &Config,
    depth: u32,
    visited: &mut std::collections::HashSet<u32>,
    dll_map: &mut std::collections::HashMap<String, usize>,
    line_prefix: &str,
) {
    let last = calls.len().saturating_sub(1);
    for (i, call) in calls.iter().enumerate() {
        let is_last = i == last;
        let branch = if is_last { "└──" } else { "├──" };
        let syscall_target = resolve_syscall_trace_target(call, insns, cfg);

        let can_recurse = !call.is_import
            && !call.is_indirect
            && call.target_rva != 0
            && depth + 1 < cfg.funcs_depth
            && !visited.contains(&call.target_rva);
        let can_recurse_syscall = depth + 1 < cfg.funcs_depth && syscall_target.is_some();

        let nt = is_nt_api(&call.label);
        let tag = match (call.is_import, call.is_indirect, call.kind.as_str(), nt) {
            (true, _, "jmp", true) => c.dim(" [syscall] [tail call]"),
            (true, _, _, true) => c.dim(" [syscall]"),
            (true, _, "jmp", false) => {
                if let Some(method) = &call.indirect_method {
                    c.dim(&format!(" [import · tail call · {}]", method))
                } else {
                    c.dim(" [import · tail call]")
                }
            }
            (true, _, _, false) => {
                if let Some(method) = &call.indirect_method {
                    c.dim(&format!(" [import · {}]", method))
                } else {
                    c.dim(" [import]")
                }
            }
            (_, true, _, _) => {
                if let Some(method) = &call.indirect_method {
                    c.dim(&format!(" [indirect · {}]", method))
                } else {
                    c.dim(" [indirect]")
                }
            }
            (_, _, "jmp", _) => {
                if let Some(method) = &call.indirect_method {
                    c.dim(&format!(" [↳ {}]", method))
                } else {
                    c.dim(" [tail call]")
                }
            }
            _ => {
                if let Some(method) = &call.indirect_method {
                    c.dim(&format!(" [↳ {}]", method))
                } else {
                    c.dim(" [internal]")
                }
            }
        };

        let colored_target = color_target(call, c, dll_map);

        writeln!(
            w,
            "{}{} {}  {}  {}{}",
            line_prefix,
            branch,
            c.dim(&format!("0x{:X}", call.rva)),
            color_kind(&call.kind, c),
            colored_target,
            tag,
        )
        .ok();

        if !call.switch_cases.is_empty() {
            let detail_prefix = format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
            let when_str = format_case_values(&call.switch_cases);
            writeln!(
                w,
                "{}{}  {}",
                detail_prefix,
                c.dim("when :"),
                c.cyan(&when_str),
            )
            .ok();
        }

        if let Some(target) = syscall_target.as_ref() {
            let detail_prefix = format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
            writeln!(
                w,
                "{}{} {}!{}",
                detail_prefix,
                c.dim("kernel:"),
                c.cyan(short_dll_name(&target.image.dll_name)),
                c.b_red(&target.symbol_name),
            )
            .ok();
            if !target.classes.is_empty() {
                let classes = target
                    .classes
                    .iter()
                    .map(|v| format_class_value(*v))
                    .collect::<Vec<_>>()
                    .join("|");
                writeln!(
                    w,
                    "{}{} {}",
                    detail_prefix,
                    c.dim("class :"),
                    c.b_white(&classes)
                )
                .ok();
            }
        }

        if can_recurse {
            if let Some(file_off) = image.pe.rva_to_offset(call.target_rva) {
                visited.insert(call.target_rva);
                let mut sub_cfg = cfg.clone();
                sub_cfg.max_insns = sub_cfg.max_insns.min(300);
                if let Ok(sub_insns) = disassemble_at(
                    image.raw,
                    image.pe,
                    file_off,
                    call.target_rva,
                    image.arch,
                    image.image_base,
                    image.exports,
                    Some(image.symbol_index),
                    &sub_cfg,
                ) {
                    let sub_calls = collect_api_calls(
                        &sub_insns,
                        image.pe,
                        image.raw,
                        image.symbol_index,
                        image.image_base,
                    );
                    if !sub_calls.is_empty() {
                        let child_prefix =
                            format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
                        print_calls_recursive(
                            w,
                            &sub_calls,
                            &sub_insns,
                            c,
                            image,
                            cfg,
                            depth + 1,
                            visited,
                            dll_map,
                            &child_prefix,
                        );
                    }
                }
            }
        } else if can_recurse_syscall {
            let target = syscall_target.unwrap();
            if let Some(file_off) = target.image.pe.rva_to_offset(target.rva) {
                let mut sub_cfg = cfg.clone();
                sub_cfg.max_insns = sub_cfg.max_insns.min(300);
                if let Ok(sub_insns) = disassemble_at(
                    &target.image.raw,
                    &target.image.pe,
                    file_off,
                    target.rva,
                    target.image.arch,
                    target.image.image_base,
                    &target.image.exports,
                    Some(&target.image.symbol_index),
                    &sub_cfg,
                ) {
                    let sub_calls = collect_api_calls(
                        &sub_insns,
                        &target.image.pe,
                        &target.image.raw,
                        &target.image.symbol_index,
                        target.image.image_base,
                    );
                    if !sub_calls.is_empty() {
                        let child_prefix =
                            format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
                        let kernel_view = target.image.as_view();
                        print_calls_recursive(
                            w,
                            &sub_calls,
                            &sub_insns,
                            c,
                            &kernel_view,
                            cfg,
                            depth + 1,
                            visited,
                            dll_map,
                            &child_prefix,
                        );
                    }
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn write_calls_recursive_text(
    out: &mut String,
    calls: &[ApiCall],
    insns: &[Instruction],
    image: &TraceImageView<'_>,
    cfg: &Config,
    depth: u32,
    visited: &mut std::collections::HashSet<u32>,
    line_prefix: &str,
) {
    let last = calls.len().saturating_sub(1);
    for (i, call) in calls.iter().enumerate() {
        let is_last = i == last;
        let branch = if is_last { "└──" } else { "├──" };
        let syscall_target = resolve_syscall_trace_target(call, insns, cfg);
        let can_recurse = !call.is_import
            && !call.is_indirect
            && call.target_rva != 0
            && depth + 1 < cfg.funcs_depth
            && !visited.contains(&call.target_rva);
        let can_recurse_syscall = depth + 1 < cfg.funcs_depth && syscall_target.is_some();

        let tag = match (
            call.is_import,
            call.is_indirect,
            call.kind.as_str(),
            is_nt_api(&call.label),
        ) {
            (true, _, "jmp", true) => "[syscall] [tail call]",
            (true, _, _, true) => "[syscall]",
            (true, _, "jmp", false) => "[import · tail call]",
            (true, _, _, false) => "[import]",
            (_, true, _, _) => "[indirect]",
            (_, _, "jmp", _) => "[tail call]",
            _ => "[internal]",
        };
        let target = if call.dll.is_empty() {
            call.label.clone()
        } else {
            format!("{}!{}", short_dll_name(&call.dll), call.label)
        };
        let _ = writeln!(
            out,
            "{}{} 0x{:X}  {}  {} {}",
            line_prefix, branch, call.rva, call.kind, target, tag
        );

        if !call.switch_cases.is_empty() {
            let detail_prefix = format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
            let _ = writeln!(
                out,
                "{}when : {}",
                detail_prefix,
                format_case_values(&call.switch_cases)
            );
        }

        if let Some(target) = syscall_target.as_ref() {
            let detail_prefix = format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
            let _ = writeln!(
                out,
                "{}kernel: {}!{}",
                detail_prefix,
                short_dll_name(&target.image.dll_name),
                target.symbol_name
            );
        }

        if can_recurse {
            if let Some(file_off) = image.pe.rva_to_offset(call.target_rva) {
                visited.insert(call.target_rva);
                let mut sub_cfg = cfg.clone();
                sub_cfg.max_insns = sub_cfg.max_insns.min(300);
                if let Ok(sub_insns) = disassemble_at(
                    image.raw,
                    image.pe,
                    file_off,
                    call.target_rva,
                    image.arch,
                    image.image_base,
                    image.exports,
                    Some(image.symbol_index),
                    &sub_cfg,
                ) {
                    let sub_calls = collect_api_calls(
                        &sub_insns,
                        image.pe,
                        image.raw,
                        image.symbol_index,
                        image.image_base,
                    );
                    if !sub_calls.is_empty() {
                        let child_prefix =
                            format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
                        write_calls_recursive_text(
                            out,
                            &sub_calls,
                            &sub_insns,
                            image,
                            cfg,
                            depth + 1,
                            visited,
                            &child_prefix,
                        );
                    }
                }
            }
        } else if can_recurse_syscall {
            let target = syscall_target.unwrap();
            if let Some(file_off) = target.image.pe.rva_to_offset(target.rva) {
                let mut sub_cfg = cfg.clone();
                sub_cfg.max_insns = sub_cfg.max_insns.min(300);
                if let Ok(sub_insns) = disassemble_at(
                    &target.image.raw,
                    &target.image.pe,
                    file_off,
                    target.rva,
                    target.image.arch,
                    target.image.image_base,
                    &target.image.exports,
                    Some(&target.image.symbol_index),
                    &sub_cfg,
                ) {
                    let sub_calls = collect_api_calls(
                        &sub_insns,
                        &target.image.pe,
                        &target.image.raw,
                        &target.image.symbol_index,
                        target.image.image_base,
                    );
                    if !sub_calls.is_empty() {
                        let child_prefix =
                            format!("{}{}   ", line_prefix, if is_last { " " } else { "│" });
                        let kernel_view = target.image.as_view();
                        write_calls_recursive_text(
                            out,
                            &sub_calls,
                            &sub_insns,
                            &kernel_view,
                            cfg,
                            depth + 1,
                            visited,
                            &child_prefix,
                        );
                    }
                }
            }
        }
    }
}

struct SyscallTraceTarget {
    image: LoadedTraceImage,
    rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
}

fn resolve_syscall_trace_target(
    call: &ApiCall,
    insns: &[Instruction],
    cfg: &Config,
) -> Option<SyscallTraceTarget> {
    if !call.is_import || !is_nt_api(&call.label) {
        return None;
    }
    let dll = call.dll.to_ascii_lowercase();
    if !dll.eq("ntdll.dll") && !dll.eq("ntdll") {
        return None;
    }

    for kernel_name in [
        "ntoskrnl.exe",
        "ntkrnlmp.exe",
        "ntkrnlpa.exe",
        "ntkrpamp.exe",
    ] {
        let Some(image) = load_trace_image(kernel_name, cfg) else {
            continue;
        };
        if let Some((rva, symbol_name)) = resolve_kernel_symbol(&image, &call.label, cfg) {
            if let Some(dispatch) = resolve_syscall_dispatch_target(call, insns, &image, rva, cfg) {
                return Some(SyscallTraceTarget {
                    image,
                    rva: dispatch.rva,
                    symbol_name: dispatch.symbol_name,
                    classes: dispatch.classes,
                });
            }
            return Some(SyscallTraceTarget {
                image,
                rva,
                symbol_name,
                classes: Vec::new(),
            });
        }
    }

    None
}

fn load_trace_image(name: &str, cfg: &Config) -> Option<LoadedTraceImage> {
    let dll_path = find_dll_path(name, cfg).ok()?;
    let dll_name = dll_path.file_name()?.to_string_lossy().to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();
    let raw = std::fs::read(&dll_path).ok()?;
    let pe = parse_pe(&raw).ok()?;
    let exports = read_exports(&pe, &raw);
    let pdb_symbols = if cfg.no_pdb {
        Vec::new()
    } else {
        load_pdb_symbols(
            &dll_path_str,
            &cfg.sym_path,
            &cfg.sym_server,
            &cfg.pdb_file,
            cfg.verbose,
            cfg.reload,
        )
        .unwrap_or_default()
    };
    let symbol_index = SymbolIndex::from_exports_and_pdb(&exports, &pdb_symbols, pe.image_base);

    Some(LoadedTraceImage {
        dll_name,
        dll_path: dll_path_str,
        arch: pe.arch,
        image_base: pe.image_base,
        raw,
        pe,
        exports,
        symbol_index,
    })
}

fn resolve_kernel_symbol(
    image: &LoadedTraceImage,
    name: &str,
    cfg: &Config,
) -> Option<(u32, String)> {
    for candidate in kernel_name_candidates(name) {
        if let Some(export) = image
            .exports
            .iter()
            .find(|e| e.name.eq_ignore_ascii_case(&candidate))
        {
            return Some((export.rva, export.name.clone()));
        }
        if !cfg.no_pdb {
            if let Some(rva) = load_pdb_symbol(
                &image.dll_path,
                &candidate,
                &cfg.sym_path,
                &cfg.sym_server,
                &cfg.pdb_file,
                image.image_base,
                cfg.verbose,
                cfg.reload,
            ) {
                return Some((rva, candidate));
            }
        }
    }
    None
}

fn kernel_name_candidates(name: &str) -> Vec<String> {
    let mut out = vec![name.to_owned()];
    if let Some(rest) = name.strip_prefix("Nt") {
        out.push(format!("Zw{}", rest));
    } else if let Some(rest) = name.strip_prefix("Zw") {
        out.push(format!("Nt{}", rest));
    }
    out
}

struct SyscallDispatchTarget {
    rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
}

fn resolve_syscall_dispatch_target(
    call: &ApiCall,
    caller_insns: &[Instruction],
    kernel_image: &LoadedTraceImage,
    syscall_rva: u32,
    cfg: &Config,
) -> Option<SyscallDispatchTarget> {
    if !call.label.eq_ignore_ascii_case("NtQuerySystemInformation")
        && !call.label.eq_ignore_ascii_case("ZwQuerySystemInformation")
    {
        return None;
    }

    let class_values =
        infer_immediate_arg_values(caller_insns, call.rva, Register::ECX, Register::RCX);
    if class_values.is_empty() {
        return None;
    }

    let file_off = kernel_image.pe.rva_to_offset(syscall_rva)?;
    let mut sub_cfg = cfg.clone();
    sub_cfg.max_insns = 96;
    let syscall_insns = disassemble_at(
        &kernel_image.raw,
        &kernel_image.pe,
        file_off,
        syscall_rva,
        kernel_image.arch,
        kernel_image.image_base,
        &kernel_image.exports,
        Some(&kernel_image.symbol_index),
        &sub_cfg,
    )
    .ok()?;

    let dispatcher = parse_qsi_dispatcher(&syscall_insns)?;
    let mut resolved: Vec<(u32, String, Vec<u32>)> = Vec::new();
    for &class_value in &class_values {
        if let Some(target_rva) = resolve_dispatch_rva(kernel_image, &dispatcher, class_value) {
            let name = kernel_symbol_name(kernel_image, target_rva);
            if let Some((_, _, classes)) =
                resolved.iter_mut().find(|(rva, _, _)| *rva == target_rva)
            {
                classes.push(class_value);
            } else {
                resolved.push((target_rva, name, vec![class_value]));
            }
        }
    }

    if resolved.is_empty() {
        return None;
    }

    let (rva, symbol_name, classes) = resolved[0].clone();
    Some(SyscallDispatchTarget {
        rva,
        symbol_name,
        classes,
    })
}

#[derive(Debug, Clone, Copy)]
pub(super) struct QsiDispatcher {
    pub class_bias: u32,
    pub max_index: u32,
    pub index_table_rva: u32,
    pub target_table_rva: u32,
}

pub(super) fn parse_qsi_dispatcher(insns: &[Instruction]) -> Option<QsiDispatcher> {
    let mut class_bias = None;
    let mut max_index = None;
    let mut index_table_rva: Option<(u32, Register)> = None;
    let mut target_table_rva: Option<(u32, Register)> = None;
    let mut saw_jump = false;

    for insn in insns {
        let iced = &insn.iced;
        if let Some(bias) = extract_lea_sub_bias(iced) {
            class_bias = Some(bias);
        }
        if iced.mnemonic() == Mnemonic::Cmp
            && iced.op0_kind() == OpKind::Register
            && matches!(iced.op0_register(), Register::EAX | Register::RAX)
        {
            max_index = immediate_value(iced);
        }
        if let Some(pair) = extract_index_table_rva(iced) {
            index_table_rva = Some(pair);
        }
        if let Some(pair) = extract_target_table_rva(iced) {
            target_table_rva = Some(pair);
        }
        if iced.mnemonic() == Mnemonic::Jmp && iced.op0_kind() == OpKind::Register {
            saw_jump = true;
        }
    }

    if !saw_jump {
        return None;
    }

    let (idx_rva, idx_base) = index_table_rva?;
    let (tgt_rva, tgt_base) = target_table_rva?;
    if idx_base.full_register() != tgt_base.full_register() {
        return None;
    }

    Some(QsiDispatcher {
        class_bias: class_bias?,
        max_index: max_index?,
        index_table_rva: idx_rva,
        target_table_rva: tgt_rva,
    })
}

fn extract_lea_sub_bias(instr: &iced_x86::Instruction) -> Option<u32> {
    if instr.mnemonic() == Mnemonic::Lea
        && instr.op0_kind() == OpKind::Register
        && matches!(instr.op0_register(), Register::EAX | Register::RAX)
        && instr.op1_kind() == OpKind::Memory
        && matches!(instr.memory_base(), Register::RCX | Register::ECX)
        && instr.memory_index() == Register::None
    {
        let disp = instr.memory_displacement64() as i64;
        if disp < 0 {
            return Some((-disp) as u32);
        }
    }
    if instr.mnemonic() == Mnemonic::Sub
        && instr.op0_kind() == OpKind::Register
        && matches!(instr.op0_register(), Register::EAX | Register::RAX)
    {
        return immediate_value(instr);
    }
    None
}

fn extract_index_table_rva(instr: &iced_x86::Instruction) -> Option<(u32, Register)> {
    if instr.mnemonic() != Mnemonic::Movzx
        || instr.op0_kind() != OpKind::Register
        || instr.op1_kind() != OpKind::Memory
    {
        return None;
    }
    let base = instr.memory_base();
    let index = instr.memory_index();
    if base == Register::None || index == Register::None {
        return None;
    }
    if instr.memory_index_scale() != 1 {
        return None;
    }
    let disp = instr.memory_displacement64() as u32;
    if disp == 0 {
        return None;
    }
    Some((disp, base))
}

fn extract_target_table_rva(instr: &iced_x86::Instruction) -> Option<(u32, Register)> {
    if instr.mnemonic() != Mnemonic::Mov
        || instr.op0_kind() != OpKind::Register
        || instr.op1_kind() != OpKind::Memory
    {
        return None;
    }
    let base = instr.memory_base();
    let index = instr.memory_index();
    if base == Register::None || index == Register::None {
        return None;
    }
    if instr.memory_index_scale() != 4 {
        return None;
    }
    let disp = instr.memory_displacement64() as u32;
    if disp == 0 {
        return None;
    }
    Some((disp, base))
}

fn resolve_dispatch_rva(
    image: &LoadedTraceImage,
    dispatcher: &QsiDispatcher,
    class_value: u32,
) -> Option<u32> {
    let adjusted = class_value.checked_sub(dispatcher.class_bias)?;
    if adjusted > dispatcher.max_index {
        return None;
    }

    let index_off = image
        .pe
        .rva_to_offset(dispatcher.index_table_rva.checked_add(adjusted)?)?;
    let slot_index = *image.raw.get(index_off)? as u32;
    let target_slot_rva = dispatcher
        .target_table_rva
        .checked_add(slot_index.checked_mul(4)?)?;
    let target_off = image.pe.rva_to_offset(target_slot_rva)?;
    let bytes = image.raw.get(target_off..target_off + 4)?;
    let target_rva = u32::from_le_bytes(bytes.try_into().ok()?);
    if target_rva == 0 {
        return None;
    }
    Some(target_rva)
}

fn kernel_symbol_name(image: &LoadedTraceImage, target_rva: u32) -> String {
    let target_va = image.image_base + target_rva as u64;
    if let Some(hit) = image.symbol_index.lookup(target_va) {
        if hit.displacement == 0 {
            return hit.symbol.name;
        }
        return format!("{}+0x{:X}", hit.symbol.name, hit.displacement);
    }
    format!("sub_{:08X}", target_rva)
}

fn infer_immediate_arg_values(
    insns: &[Instruction],
    call_rva: u32,
    arg32: Register,
    arg64: Register,
) -> Vec<u32> {
    let Some(pos) = insns.iter().position(|insn| insn.rva == call_rva) else {
        return Vec::new();
    };
    let mut values = Vec::new();

    for insn in insns[..pos].iter().rev().take(16) {
        match insn.iced.mnemonic() {
            Mnemonic::Mov => {
                if insn.iced.op0_kind() == OpKind::Register {
                    let dst = insn.iced.op0_register();
                    if dst == arg32 || dst == arg64 {
                        if let Some(value) = immediate_value(&insn.iced) {
                            values.push(value);
                        } else {
                            break;
                        }
                    }
                }
            }
            Mnemonic::Xor => {
                if insn.iced.op0_kind() == OpKind::Register
                    && insn.iced.op1_kind() == OpKind::Register
                    && insn.iced.op0_register() == insn.iced.op1_register()
                {
                    let dst = insn.iced.op0_register();
                    if dst == arg32 || dst == arg64 {
                        values.push(0);
                    }
                }
            }
            Mnemonic::Jne
            | Mnemonic::Je
            | Mnemonic::Ja
            | Mnemonic::Jae
            | Mnemonic::Jb
            | Mnemonic::Jbe => {}
            _ => {}
        }
    }

    values.sort_unstable();
    values.dedup();
    values
}

fn immediate_value(instr: &iced_x86::Instruction) -> Option<u32> {
    match instr.op1_kind() {
        OpKind::Immediate8 => Some(instr.immediate8to32() as u32),
        OpKind::Immediate16 => Some(instr.immediate16() as u32),
        OpKind::Immediate32 => Some(instr.immediate32()),
        OpKind::Immediate32to64 => Some(instr.immediate32to64() as u32),
        OpKind::Immediate64 => Some(instr.immediate64() as u32),
        _ => None,
    }
}

pub(super) fn best_symbol_name_for_rva(
    symbol_index: &SymbolIndex,
    image_base: u64,
    rva: u32,
) -> Option<String> {
    let va = image_base + rva as u64;
    let hit = symbol_index.lookup(va)?;
    if hit.displacement == 0 {
        return Some(hit.symbol.name);
    }
    Some(format!("{}+0x{:X}", hit.symbol.name, hit.displacement))
}

pub(super) fn switch_dispatch_to_api_calls(
    insns: &[Instruction],
    dispatch: &RecoveredSwitchDispatch,
) -> Vec<ApiCall> {
    let jmp_rva = match insns.iter().find(|i| i.is_jmp && i.call_target == 0) {
        Some(i) => i.rva,
        None => return Vec::new(),
    };

    dispatch
        .targets
        .iter()
        .map(|target| ApiCall {
            rva: jmp_rva,
            kind: "jmp".to_owned(),
            target_rva: target.target_rva,
            label: target.symbol_name.clone(),
            dll: String::new(),
            is_import: false,
            is_indirect: false,
            indirect_method: Some("switch dispatch".to_owned()),
            switch_cases: target.classes.clone(),
        })
        .collect()
}

pub(super) fn recover_local_switch_dispatch(
    insns: &[Instruction],
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    symbol_index: &SymbolIndex,
    image_base: u64,
) -> Option<RecoveredSwitchDispatch> {
    let dispatcher = parse_qsi_dispatcher(insns)?;
    let mut grouped: std::collections::BTreeMap<u32, Vec<u32>> = std::collections::BTreeMap::new();

    for class_value in
        dispatcher.class_bias..=dispatcher.class_bias.saturating_add(dispatcher.max_index)
    {
        let Some(target_rva) = resolve_dispatch_rva_local(raw, pe, &dispatcher, class_value) else {
            continue;
        };
        grouped.entry(target_rva).or_default().push(class_value);
    }

    let targets = grouped
        .into_iter()
        .map(|(target_rva, classes)| RecoveredSwitchTarget {
            target_rva,
            symbol_name: best_symbol_name_for_rva(symbol_index, image_base, target_rva)
                .unwrap_or_else(|| format!("sub_{:08X}", target_rva)),
            classes,
        })
        .collect();

    Some(RecoveredSwitchDispatch {
        dispatcher,
        targets,
    })
}

fn resolve_dispatch_rva_local(
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    dispatcher: &QsiDispatcher,
    class_value: u32,
) -> Option<u32> {
    let adjusted = class_value.checked_sub(dispatcher.class_bias)?;
    if adjusted > dispatcher.max_index {
        return None;
    }

    let index_off = pe.rva_to_offset(dispatcher.index_table_rva.checked_add(adjusted)?)?;
    let slot_index = *raw.get(index_off)? as u32;
    let target_slot_rva = dispatcher
        .target_table_rva
        .checked_add(slot_index.checked_mul(4)?)?;
    let target_off = pe.rva_to_offset(target_slot_rva)?;
    let bytes = raw.get(target_off..target_off + 4)?;
    let target_rva = u32::from_le_bytes(bytes.try_into().ok()?);
    if target_rva == 0 {
        return None;
    }
    Some(target_rva)
}
