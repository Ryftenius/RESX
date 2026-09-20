use super::*;

pub(super) fn symbol_cache() -> &'static Mutex<HashMap<String, Vec<PdbSymbol>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<PdbSymbol>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn type_cache() -> &'static Mutex<HashMap<String, Vec<PdbTypeInfo>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Vec<PdbTypeInfo>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn lookup_cache() -> &'static Mutex<HashMap<String, Option<u32>>> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<u32>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

pub(super) fn pdb_cache_key(
    dll_path: &str,
    sym_path: &str,
    sym_server: &str,
    pdb_path: &str,
) -> String {
    format!(
        "{}|{}|{}|{}",
        dll_path.to_ascii_lowercase(),
        sym_path.to_ascii_lowercase(),
        sym_server.to_ascii_lowercase(),
        pdb_path.to_ascii_lowercase()
    )
}

pub(super) fn pdb_lookup_cache_key(
    dll_path: &str,
    func_name: &str,
    sym_path: &str,
    sym_server: &str,
    pdb_path: &str,
    image_base: u64,
) -> String {
    format!(
        "{}|{}|{}",
        pdb_cache_key(dll_path, sym_path, sym_server, pdb_path),
        image_base,
        func_name.to_ascii_lowercase()
    )
}

pub(super) fn find_symbol_rva(symbols: &[PdbSymbol], func_name: &str) -> Option<u32> {
    let want = func_name.to_ascii_lowercase();
    symbols
        .iter()
        .find(|sym| sym.name.eq_ignore_ascii_case(&want))
        .map(|sym| sym.rva)
}

pub(super) unsafe extern "system" fn enum_symbol_cb(
    sym_info: *mut SymbolInfo,
    _size: u32,
    user_ctx: usize,
) -> i32 {
    if sym_info.is_null() || user_ctx == 0 {
        return 1;
    }
    let info = &*sym_info;
    let ctx = &mut *(user_ctx as *mut EnumContext);
    let vec = &mut *ctx.out;
    let name_len = info.name_len as usize;
    let name = String::from_utf8_lossy(&info.name[..name_len.min(info.name.len())]).into_owned();
    if !name.is_empty() {
        // SYMBOL_INFO.TypeIndex already identifies the symbol's type. Asking
        // TI_GET_TYPEID again can unwrap a function into its return type.
        let type_id = (info.type_index != 0).then_some(info.type_index);
        let type_name = type_id
            .map(|id| {
                describe_type(
                    ctx.h_proc,
                    ctx.module_base,
                    id,
                    ctx.sym_get_type_info,
                    &mut Vec::new(),
                )
            })
            .unwrap_or_default();
        let size = if info.tag == SYM_TAG_FUNCTION || info.tag == SYM_TAG_PUBLIC {
            info.size as u64
        } else {
            type_id
                .and_then(|id| {
                    get_type_size(ctx.h_proc, ctx.module_base, id, ctx.sym_get_type_info)
                })
                .unwrap_or(info.size as u64)
        };
        let rva = info.address.saturating_sub(info.mod_base) as u32;
        vec.push(PdbSymbol {
            name,
            rva,
            va: info.address,
            kind: tag_name(info.tag).to_owned(),
            type_id: type_id.unwrap_or(0),
            type_name,
            size,
        });
    }
    1
}

pub(super) unsafe extern "system" fn enum_type_cb(
    sym_info: *mut SymbolInfo,
    _size: u32,
    user_ctx: usize,
) -> i32 {
    if sym_info.is_null() || user_ctx == 0 {
        return 1;
    }
    let info = &*sym_info;
    let ctx = &mut *(user_ctx as *mut TypeEnumContext);
    let vec = &mut *ctx.out;
    let name_len = info.name_len as usize;
    let name = String::from_utf8_lossy(&info.name[..name_len.min(info.name.len())]).into_owned();
    let primary_id = if info.index != 0 {
        info.index
    } else {
        info.type_index
    };
    if primary_id != 0 {
        vec.push(TypeSeed {
            type_id: primary_id,
            name: name.clone(),
            tag: info.tag,
        });
    }
    if info.type_index != 0 && info.type_index != primary_id {
        vec.push(TypeSeed {
            type_id: info.type_index,
            name,
            tag: info.tag,
        });
    }
    1
}

pub(super) unsafe fn get_type_size(
    h_proc: *mut c_void,
    module_base: u64,
    type_id: u32,
    sym_get_type_info: FnSymGetTypeInfo,
) -> Option<u64> {
    let mut len = 0u64;
    if sym_get_type_info(
        h_proc,
        module_base,
        type_id,
        TI_GET_LENGTH,
        &mut len as *mut _ as *mut c_void,
    ) == 0
    {
        None
    } else {
        Some(len)
    }
}

unsafe fn get_type_u32(
    h_proc: *mut c_void,
    module_base: u64,
    type_id: u32,
    request: u32,
    sym_get_type_info: FnSymGetTypeInfo,
) -> Option<u32> {
    let mut out = 0u32;
    if sym_get_type_info(
        h_proc,
        module_base,
        type_id,
        request,
        &mut out as *mut _ as *mut c_void,
    ) == 0
    {
        None
    } else {
        Some(out)
    }
}

unsafe fn get_type_u64(
    h_proc: *mut c_void,
    module_base: u64,
    type_id: u32,
    request: u32,
    sym_get_type_info: FnSymGetTypeInfo,
) -> Option<u64> {
    let mut out = 0u64;
    if sym_get_type_info(
        h_proc,
        module_base,
        type_id,
        request,
        &mut out as *mut _ as *mut c_void,
    ) == 0
    {
        None
    } else {
        Some(out)
    }
}

unsafe fn get_type_name(
    h_proc: *mut c_void,
    module_base: u64,
    type_id: u32,
    sym_get_type_info: FnSymGetTypeInfo,
) -> Option<String> {
    let mut ptr: *mut u16 = std::ptr::null_mut();
    if sym_get_type_info(
        h_proc,
        module_base,
        type_id,
        TI_GET_SYMNAME,
        &mut ptr as *mut _ as *mut c_void,
    ) == 0
        || ptr.is_null()
    {
        return None;
    }
    let mut len = 0usize;
    while *ptr.add(len) != 0 {
        len += 1;
    }
    let s = String::from_utf16_lossy(slice::from_raw_parts(ptr, len));
    LocalFree(ptr as *mut c_void);
    Some(s)
}

unsafe fn get_children_ids(
    h_proc: *mut c_void,
    module_base: u64,
    type_id: u32,
    sym_get_type_info: FnSymGetTypeInfo,
) -> Vec<u32> {
    let Some(count) = get_type_u32(
        h_proc,
        module_base,
        type_id,
        TI_GET_CHILDRENCOUNT,
        sym_get_type_info,
    ) else {
        return Vec::new();
    };
    if count == 0 || count > 4096 {
        return Vec::new();
    }
    // u32 backing storage meets the Windows structure's alignment requirement.
    let mut buf = vec![0u32; 2 + count as usize];
    let hdr = buf.as_mut_ptr() as *mut TiFindChildrenHeader;
    (*hdr).count = count;
    (*hdr).start = 0;
    if sym_get_type_info(
        h_proc,
        module_base,
        type_id,
        TI_FINDCHILDREN,
        hdr as *mut c_void,
    ) == 0
    {
        return Vec::new();
    }
    buf[2..].to_vec()
}

pub(super) unsafe fn build_type_info(
    h_proc: *mut c_void,
    module_base: u64,
    type_id: u32,
    sym_get_type_info: FnSymGetTypeInfo,
) -> (Option<PdbTypeInfo>, Vec<u32>) {
    let Some(tag) = get_type_u32(
        h_proc,
        module_base,
        type_id,
        TI_GET_SYMTAG,
        sym_get_type_info,
    ) else {
        return (None, Vec::new());
    };
    let mut nested = Vec::new();
    match tag {
        SYM_TAG_POINTER_TYPE | SYM_TAG_ARRAY_TYPE | SYM_TAG_TYPEDEF | SYM_TAG_FUNCTION_TYPE => {
            if let Some(inner_id) =
                get_type_u32(h_proc, module_base, type_id, TI_GET_TYPE, sym_get_type_info)
            {
                nested.push(inner_id);
            }
        }
        _ => {}
    }
    if !matches!(tag, SYM_TAG_UDT | SYM_TAG_ENUM | SYM_TAG_TYPEDEF) {
        return (None, nested);
    }

    let name = describe_type(
        h_proc,
        module_base,
        type_id,
        sym_get_type_info,
        &mut Vec::new(),
    );
    let size = get_type_size(h_proc, module_base, type_id, sym_get_type_info).unwrap_or(0);
    let mut members = Vec::new();

    if tag == SYM_TAG_UDT {
        for child_id in get_children_ids(h_proc, module_base, type_id, sym_get_type_info) {
            let child_tag = get_type_u32(
                h_proc,
                module_base,
                child_id,
                TI_GET_SYMTAG,
                sym_get_type_info,
            )
            .unwrap_or(0);
            if !matches!(child_tag, SYM_TAG_DATA | SYM_TAG_BASE_CLASS) {
                continue;
            }

            let member_name = if child_tag == SYM_TAG_BASE_CLASS {
                "<base>".to_owned()
            } else {
                get_type_name(h_proc, module_base, child_id, sym_get_type_info)
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| format!("member_{:X}", child_id))
            };
            let member_type_id = get_type_u32(
                h_proc,
                module_base,
                child_id,
                TI_GET_TYPE,
                sym_get_type_info,
            )
            .unwrap_or(0);
            let member_offset = get_type_u64(
                h_proc,
                module_base,
                child_id,
                TI_GET_OFFSET,
                sym_get_type_info,
            )
            .unwrap_or(0);
            let member_type_name = if member_type_id != 0 {
                describe_type(
                    h_proc,
                    module_base,
                    member_type_id,
                    sym_get_type_info,
                    &mut Vec::new(),
                )
            } else {
                String::new()
            };
            let member_size = if member_type_id != 0 {
                get_type_size(h_proc, module_base, member_type_id, sym_get_type_info).unwrap_or(0)
            } else {
                0
            };
            if member_type_id != 0 {
                nested.push(member_type_id);
            }
            members.push(PdbTypeMember {
                name: member_name,
                offset: member_offset,
                type_id: member_type_id,
                type_name: member_type_name,
                kind: type_tag_name(child_tag).to_owned(),
                size: member_size,
            });
        }
        members.sort_by(|a, b| a.offset.cmp(&b.offset).then_with(|| a.name.cmp(&b.name)));
    } else if tag == SYM_TAG_TYPEDEF {
        if let Some(target_id) =
            get_type_u32(h_proc, module_base, type_id, TI_GET_TYPE, sym_get_type_info)
        {
            nested.push(target_id);
        }
    }

    (
        Some(PdbTypeInfo {
            type_id,
            name,
            kind: type_tag_name(tag).to_owned(),
            size,
            members,
        }),
        nested,
    )
}

unsafe fn describe_type(
    h_proc: *mut c_void,
    module_base: u64,
    type_id: u32,
    sym_get_type_info: FnSymGetTypeInfo,
    seen: &mut Vec<u32>,
) -> String {
    describe_type_bounded(
        h_proc,
        module_base,
        type_id,
        sym_get_type_info,
        seen,
        &mut 512,
    )
}

unsafe fn describe_type_bounded(
    h_proc: *mut c_void,
    module_base: u64,
    type_id: u32,
    sym_get_type_info: FnSymGetTypeInfo,
    seen: &mut Vec<u32>,
    budget: &mut usize,
) -> String {
    if *budget == 0 {
        return "unknown /* type node limit */".into();
    }
    *budget -= 1;
    if type_id == 0 {
        return "void".to_owned();
    }
    if seen.len() >= 24 {
        return "unknown /* type depth limit */".into();
    }
    if seen.contains(&type_id) {
        return get_type_name(h_proc, module_base, type_id, sym_get_type_info)
            .unwrap_or_else(|| format!("type_{:X}", type_id));
    }
    seen.push(type_id);
    let tag = get_type_u32(
        h_proc,
        module_base,
        type_id,
        TI_GET_SYMTAG,
        sym_get_type_info,
    )
    .unwrap_or(0);
    let name = match tag {
        SYM_TAG_UDT | SYM_TAG_ENUM | SYM_TAG_TYPEDEF => {
            get_type_name(h_proc, module_base, type_id, sym_get_type_info)
                .unwrap_or_else(|| format!("type_{:X}", type_id))
        }
        SYM_TAG_POINTER_TYPE => {
            let inner = get_type_u32(h_proc, module_base, type_id, TI_GET_TYPE, sym_get_type_info)
                .map(|id| {
                    describe_type_bounded(h_proc, module_base, id, sym_get_type_info, seen, budget)
                })
                .unwrap_or_else(|| "void".to_owned());
            let suffix = if get_type_u32(
                h_proc,
                module_base,
                type_id,
                TI_GET_IS_REFERENCE,
                sym_get_type_info,
            )
            .unwrap_or(0)
                != 0
            {
                "&"
            } else {
                "*"
            };
            format!("{}{}", inner, suffix)
        }
        SYM_TAG_ARRAY_TYPE => {
            let inner_id =
                get_type_u32(h_proc, module_base, type_id, TI_GET_TYPE, sym_get_type_info)
                    .unwrap_or(0);
            let inner = describe_type_bounded(
                h_proc,
                module_base,
                inner_id,
                sym_get_type_info,
                seen,
                budget,
            );
            let total = get_type_size(h_proc, module_base, type_id, sym_get_type_info).unwrap_or(0);
            let elem = get_type_size(h_proc, module_base, inner_id, sym_get_type_info).unwrap_or(0);
            if elem > 0 && total >= elem {
                format!("{}[{}]", inner, total / elem)
            } else {
                format!("{}[]", inner)
            }
        }
        SYM_TAG_BASE_TYPE => {
            let base = get_type_u32(
                h_proc,
                module_base,
                type_id,
                TI_GET_BASETYPE,
                sym_get_type_info,
            )
            .unwrap_or(0);
            let len = get_type_size(h_proc, module_base, type_id, sym_get_type_info).unwrap_or(0);
            base_type_name(base, len).to_owned()
        }
        SYM_TAG_FUNCTION_TYPE => {
            let ret = get_type_u32(h_proc, module_base, type_id, TI_GET_TYPE, sym_get_type_info)
                .map(|id| {
                    describe_type_bounded(h_proc, module_base, id, sym_get_type_info, seen, budget)
                })
                .unwrap_or_else(|| "unknown".into());
            let cc = get_type_u32(
                h_proc,
                module_base,
                type_id,
                TI_GET_CALLING_CONVENTION,
                sym_get_type_info,
            );
            let convention = match cc {
                Some(0) => "__cdecl",
                Some(4) => "__fastcall",
                Some(7) => "__stdcall",
                Some(11) => "__thiscall",
                Some(24) => "__vectorcall",
                _ => "/* ABI unknown */",
            };
            let count = get_type_u32(
                h_proc,
                module_base,
                type_id,
                TI_GET_CHILDRENCOUNT,
                sym_get_type_info,
            );
            let args = match count {
                Some(0) => "void".to_owned(),
                Some(n) if n <= 128 => {
                    let children =
                        get_children_ids(h_proc, module_base, type_id, sym_get_type_info);
                    if children.len() != n as usize {
                        "/* arguments unavailable */".into()
                    } else {
                        children
                            .into_iter()
                            .map(|id| {
                                get_type_u32(
                                    h_proc,
                                    module_base,
                                    id,
                                    TI_GET_TYPE,
                                    sym_get_type_info,
                                )
                                .map(|ty| {
                                    if ty == 0 {
                                        "...".into()
                                    } else {
                                        describe_type_bounded(
                                            h_proc,
                                            module_base,
                                            ty,
                                            sym_get_type_info,
                                            seen,
                                            budget,
                                        )
                                    }
                                })
                                .unwrap_or_else(|| "unknown".into())
                            })
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                }
                _ => "/* arguments unavailable or over limit */".into(),
            };
            format!("{ret} {convention}({args})")
        }
        _ => get_type_name(h_proc, module_base, type_id, sym_get_type_info)
            .unwrap_or_else(|| format!("{}#{:X}", type_tag_name(tag), type_id)),
    };
    seen.pop();
    name
}

pub(super) fn base_type_name(base: u32, len: u64) -> &'static str {
    match (base, len) {
        (1, _) => "void",
        (2, 1) => "char",
        (3, 2) => "wchar_t",
        (6, 1) => "int8_t",
        (6, 2) => "int16_t",
        (6, 4) => "int32_t",
        (6, 8) => "int64_t",
        (7, 1) => "uint8_t",
        (7, 2) => "uint16_t",
        (7, 4) => "uint32_t",
        (7, 8) => "uint64_t",
        (8, 4) => "float",
        (8, 8) => "double",
        (10, 1) => "bool",
        (13, _) => "long",
        (14, _) => "unsigned long",
        (31, _) => "HRESULT",
        _ => "scalar",
    }
}

pub(super) fn type_tag_name(tag: u32) -> &'static str {
    match tag {
        SYM_TAG_UDT => "struct",
        SYM_TAG_ENUM => "enum",
        SYM_TAG_TYPEDEF => "typedef",
        SYM_TAG_POINTER_TYPE => "pointer",
        SYM_TAG_ARRAY_TYPE => "array",
        SYM_TAG_BASE_TYPE => "base",
        SYM_TAG_FUNCTION_TYPE => "function",
        SYM_TAG_BASE_CLASS => "base-class",
        SYM_TAG_DATA => "member",
        _ => "type",
    }
}
