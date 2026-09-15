use super::*;

pub(super) fn resolve_syscall_trace_target(
    call: &ApiCall,
    insns: &[Instruction],
    cfg: &Config,
) -> Option<SyscallTraceTarget> {
    if !call.is_import || !is_nt_api(&call.label) {
        return None;
    }
    let kernel_images = syscall_kernel_images(call);
    if kernel_images.is_empty() {
        return None;
    }

    for kernel_name in kernel_images {
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

pub(super) fn syscall_stub_provider(func_name: &str, source_image_name: &str) -> &'static str {
    if is_win32k_syscall_provider(source_image_name) || is_probable_win32k_syscall_name(func_name) {
        "win32u.dll"
    } else {
        "ntdll.dll"
    }
}

pub(super) fn syscall_kernel_images(call: &ApiCall) -> &'static [&'static str] {
    if is_win32k_syscall_provider(&call.dll) || is_probable_win32k_syscall_name(&call.label) {
        WIN32K_KERNEL_IMAGES
    } else if is_native_syscall_provider(&call.dll) {
        NT_KERNEL_IMAGES
    } else {
        NO_KERNEL_IMAGES
    }
}

pub(super) fn is_native_syscall_provider(name: &str) -> bool {
    normalize_image_base(name) == "ntdll"
}

pub(super) fn is_win32k_syscall_provider(name: &str) -> bool {
    matches!(
        normalize_image_base(name).as_str(),
        "win32u" | "user32" | "gdi32" | "gdi32full"
    )
}

pub(super) fn normalize_image_base(name: &str) -> String {
    let file = name
        .rsplit(&['/', '\\'][..])
        .next()
        .unwrap_or(name)
        .to_ascii_lowercase();
    file.strip_suffix(".dll")
        .or_else(|| file.strip_suffix(".exe"))
        .or_else(|| file.strip_suffix(".sys"))
        .unwrap_or(&file)
        .to_owned()
}

pub(super) fn is_probable_win32k_syscall_name(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "NtBindComposition",
        "NtCloseComposition",
        "NtComposition",
        "NtCompositor",
        "NtConfigureInputSpace",
        "NtConfirmComposition",
        "NtCreateComposition",
        "NtCreateImplicitComposition",
        "NtDComposition",
        "NtDesktop",
        "NtDuplicateComposition",
        "NtDxgk",
        "NtEnableOneCore",
        "NtFlipObject",
        "NtGdi",
        "NtHWCursor",
        "NtInputSpace",
        "NtIsOneCore",
        "NtKST",
        "NtMIT",
        "NtMapVisual",
        "NtMin",
        "NtModerncore",
        "NtNotifyPresent",
        "NtOpenComposition",
        "NtQueryComposition",
        "NtRIM",
        "NtSetComposition",
        "NtSetCursor",
        "NtSetPointer",
        "NtSetShell",
        "NtTokenManager",
        "NtUnBindComposition",
        "NtUpdateInputSink",
        "NtUser",
        "NtValidateComposition",
        "NtVisual",
    ];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

pub(super) fn load_trace_image(name: &str, cfg: &Config) -> Option<LoadedTraceImage> {
    let dll_path = find_dll_path(name, cfg).ok()?;
    let dll_name = dll_path.file_name()?.to_string_lossy().to_string();
    let dll_path_str = dll_path.to_string_lossy().to_string();
    let raw = crate::core::input::read_image(&dll_path).ok()?;
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

pub(super) fn resolve_kernel_symbol(
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

pub(super) fn kernel_name_candidates(name: &str) -> Vec<String> {
    let mut out = vec![name.to_owned()];
    if let Some(rest) = name.strip_prefix("Nt") {
        out.push(format!("Zw{}", rest));
    } else if let Some(rest) = name.strip_prefix("Zw") {
        out.push(format!("Nt{}", rest));
    }
    out
}

pub(super) struct SyscallDispatchTarget {
    rva: u32,
    symbol_name: String,
    classes: Vec<u32>,
}

pub(super) fn resolve_syscall_dispatch_target(
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
pub(in crate::commands::dump) struct QsiDispatcher {
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

pub(super) fn extract_lea_sub_bias(instr: &iced_x86::Instruction) -> Option<u32> {
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

pub(super) fn extract_index_table_rva(instr: &iced_x86::Instruction) -> Option<(u32, Register)> {
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

pub(super) fn extract_target_table_rva(instr: &iced_x86::Instruction) -> Option<(u32, Register)> {
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

pub(super) fn resolve_dispatch_rva(
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

pub(super) fn kernel_symbol_name(image: &LoadedTraceImage, target_rva: u32) -> String {
    let target_va = image.image_base + target_rva as u64;
    if let Some(hit) = image.symbol_index.lookup(target_va) {
        if hit.displacement == 0 {
            return hit.symbol.name;
        }
        return format!("{}+0x{:X}", hit.symbol.name, hit.displacement);
    }
    format!("sub_{:08X}", target_rva)
}

pub(super) fn infer_immediate_arg_values(
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
            Mnemonic::Mov if insn.iced.op0_kind() == OpKind::Register => {
                let dst = insn.iced.op0_register();
                if dst == arg32 || dst == arg64 {
                    if let Some(value) = immediate_value(&insn.iced) {
                        values.push(value);
                    } else {
                        break;
                    }
                }
            }
            Mnemonic::Xor
                if insn.iced.op0_kind() == OpKind::Register
                    && insn.iced.op1_kind() == OpKind::Register
                    && insn.iced.op0_register() == insn.iced.op1_register() =>
            {
                let dst = insn.iced.op0_register();
                if dst == arg32 || dst == arg64 {
                    values.push(0);
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

pub(super) fn immediate_value(instr: &iced_x86::Instruction) -> Option<u32> {
    match instr.op1_kind() {
        OpKind::Immediate8 => Some(instr.immediate8to32() as u32),
        OpKind::Immediate16 => Some(instr.immediate16() as u32),
        OpKind::Immediate32 => Some(instr.immediate32()),
        OpKind::Immediate32to64 => Some(instr.immediate32to64() as u32),
        OpKind::Immediate64 => Some(instr.immediate64() as u32),
        _ => None,
    }
}

pub(in crate::commands::dump) fn best_symbol_name_for_rva(
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

pub(in crate::commands::dump) fn switch_dispatch_to_api_calls(
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

pub(in crate::commands::dump) fn recover_local_switch_dispatch(
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

pub(super) fn resolve_dispatch_rva_local(
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
