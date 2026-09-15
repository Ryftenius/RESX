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

const NT_KERNEL_IMAGES: &[&str] = &[
    "ntoskrnl.exe",
    "ntkrnlmp.exe",
    "ntkrnlpa.exe",
    "ntkrpamp.exe",
];
const WIN32K_KERNEL_IMAGES: &[&str] = &["win32kbase.sys", "win32kfull.sys", "win32k.sys"];
const NO_KERNEL_IMAGES: &[&str] = &[];

#[allow(clippy::too_many_arguments)]
pub(super) fn print_api_calls(
    w: &mut dyn Write,
    calls: &[ApiCall],
    insns: &[Instruction],
    func_name: &str,
    source_image_name: &str,
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
    let synthetic_syscall = synthetic_syscall_call(insns, func_name, source_image_name);
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
    source_image_name: &str,
    raw: &[u8],
    pe: &crate::formats::pe::PeFile,
    symbol_index: &crate::analysis::symbols::SymbolIndex,
    exports: &[Export],
    arch: u32,
    image_base: u64,
    cfg: &Config,
    root_rva: u32,
) -> String {
    let synthetic_syscall = synthetic_syscall_call(insns, func_name, source_image_name);
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

fn synthetic_syscall_call(
    insns: &[Instruction],
    func_name: &str,
    source_image_name: &str,
) -> Option<ApiCall> {
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
        dll: syscall_stub_provider(func_name, source_image_name).to_owned(),
        is_import: true,
        is_indirect: false,
        indirect_method: None,
        switch_cases: Vec::new(),
    })
}

pub(super) fn synthetic_syscall_api_call(
    insns: &[Instruction],
    func_name: &str,
    source_image_name: &str,
) -> Option<ApiCall> {
    synthetic_syscall_call(insns, func_name, source_image_name)
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
    let visible_len = calls.len().min(cfg.max_subcalls);
    for (i, call) in calls.iter().take(visible_len).enumerate() {
        let is_last = i + 1 == visible_len && visible_len == calls.len();
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
                        cfg.hostile,
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
                        cfg.hostile,
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
    if calls.len() > visible_len {
        writeln!(
            w,
            "{}└── {}",
            line_prefix,
            c.dim(&format!(
                "{} subcalls omitted; raise --max-subcalls",
                calls.len() - visible_len
            ))
        )
        .ok();
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
    let visible_len = calls.len().min(cfg.max_subcalls);
    for (i, call) in calls.iter().take(visible_len).enumerate() {
        let is_last = i + 1 == visible_len && visible_len == calls.len();
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
                        cfg.hostile,
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
                        cfg.hostile,
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
    if calls.len() > visible_len {
        let _ = writeln!(
            out,
            "{}└── {} subcalls omitted; raise --max-subcalls",
            line_prefix,
            calls.len() - visible_len
        );
    }
}

struct SyscallTraceTarget {
    image: LoadedTraceImage,
    rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
}

mod syscall;
pub(super) use syscall::*;

#[cfg(test)]
mod tests {
    use super::{
        is_probable_win32k_syscall_name, normalize_image_base, syscall_kernel_images,
        syscall_stub_provider, NT_KERNEL_IMAGES, WIN32K_KERNEL_IMAGES,
    };
    use crate::analysis::disasm::ApiCall;

    fn import_call(dll: &str, label: &str) -> ApiCall {
        ApiCall {
            rva: 0x1000,
            kind: "call".to_owned(),
            target_rva: 0,
            label: label.to_owned(),
            dll: dll.to_owned(),
            is_import: true,
            is_indirect: false,
            indirect_method: None,
            switch_cases: Vec::new(),
        }
    }

    #[test]
    fn syscall_images_route_native_and_win32k_families() {
        let native = import_call("ntdll.dll", "NtOpenProcess");
        assert_eq!(syscall_kernel_images(&native), NT_KERNEL_IMAGES);

        let gui = import_call("win32u.dll", "NtUserGetMessage");
        assert_eq!(syscall_kernel_images(&gui), WIN32K_KERNEL_IMAGES);

        let gdi = import_call("user32.dll", "NtGdiDdDDICreateDevice");
        assert_eq!(syscall_kernel_images(&gdi), WIN32K_KERNEL_IMAGES);
    }

    #[test]
    fn synthetic_provider_uses_win32u_for_gui_syscalls() {
        assert_eq!(
            syscall_stub_provider("NtUserGetMessage", "win32u.dll"),
            "win32u.dll"
        );
        assert_eq!(
            syscall_stub_provider("NtDCompositionCreateChannel", "win32u.dll"),
            "win32u.dll"
        );
        assert_eq!(
            syscall_stub_provider("NtQuerySystemInformation", "ntdll.dll"),
            "ntdll.dll"
        );
    }

    #[test]
    fn win32k_syscall_name_detection_covers_gui_exports() {
        assert!(is_probable_win32k_syscall_name("NtUserGetMessage"));
        assert!(is_probable_win32k_syscall_name("NtGdiCreateBitmap"));
        assert!(is_probable_win32k_syscall_name(
            "NtDCompositionCommitChannel"
        ));
        assert!(!is_probable_win32k_syscall_name("NtOpenProcess"));
    }

    #[test]
    fn image_base_normalization_strips_common_extensions() {
        assert_eq!(
            normalize_image_base(r"C:\Windows\System32\win32kfull.sys"),
            "win32kfull"
        );
        assert_eq!(normalize_image_base("ntoskrnl.exe"), "ntoskrnl");
        assert_eq!(normalize_image_base("win32u.dll"), "win32u");
    }
}
