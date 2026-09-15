use super::*;

#[allow(clippy::too_many_arguments)]
pub fn load_pdb_symbol(
    dll_path: &str,
    func_name: &str,
    sym_path: &str,
    sym_server: &str,
    pdb_path: &str,
    image_base: u64,
    verbose: bool,
    reload: bool,
) -> Option<u32> {
    let lookup_key = pdb_lookup_cache_key(
        dll_path, func_name, sym_path, sym_server, pdb_path, image_base,
    );
    if !reload {
        if let Some(cached) = lookup_cache()
            .lock()
            .ok()
            .and_then(|cache| cache.get(&lookup_key).cloned())
        {
            return cached;
        }
        if let Some(cached_symbols) = symbol_cache().lock().ok().and_then(|cache| {
            cache
                .get(&pdb_cache_key(dll_path, sym_path, sym_server, pdb_path))
                .cloned()
        }) {
            let cached = find_symbol_rva(&cached_symbols, func_name);
            if let Ok(mut cache) = lookup_cache().lock() {
                cache.insert(lookup_key, cached);
            }
            return cached;
        }
    }

    // SAFETY: loaded DbgHelp exports are checked for null and transmuted to their documented signatures;
    // C strings and callback state remain live for each synchronous call.
    let result = unsafe {
        let lib = LoadLibraryA(c"dbghelp.dll".as_ptr() as *const u8);
        if lib.is_null() {
            return None;
        }

        macro_rules! proc {
            ($name:literal, $ty:ty) => {{
                let p = get_proc(lib, concat!($name, "\0").as_bytes());
                if p.is_null() {
                    return None;
                }
                std::mem::transmute::<*const c_void, $ty>(p)
            }};
        }

        let sym_initialize: FnSymInitialize = proc!("SymInitialize", FnSymInitialize);
        let sym_cleanup: FnSymCleanup = proc!("SymCleanup", FnSymCleanup);
        let sym_set_options: FnSymSetOptions = proc!("SymSetOptions", FnSymSetOptions);
        let sym_load_module_ex: FnSymLoadModuleEx = proc!("SymLoadModuleEx", FnSymLoadModuleEx);
        let sym_from_name: FnSymFromName = proc!("SymFromName", FnSymFromName);
        let sym_get_module_info: FnSymGetModuleInfo =
            proc!("SymGetModuleInfo64", FnSymGetModuleInfo);
        let sym_set_search: FnSymSetSearchPath = proc!("SymSetSearchPath", FnSymSetSearchPath);

        sym_set_options(0x00000002 | 0x00000004 | 0x00000010);

        let resolved_pdb_path = resolve_pdb_path(dll_path, sym_server, pdb_path, verbose, reload);
        let sp = build_search_path(dll_path, sym_path, sym_server, &resolved_pdb_path);
        if verbose {
            eprintln!("  Symbol search path: {}", sp);
            if !resolved_pdb_path.is_empty() {
                eprintln!("  Exact PDB path: {}", resolved_pdb_path);
            }
        }
        let sp_c = CString::new(sp.clone()).ok()?;

        let h_proc = GetCurrentProcess();
        let r = sym_initialize(h_proc, sp_c.as_ptr() as *const u8, 0);
        if r == 0 {
            return None;
        }
        struct Cleanup(*mut c_void, FnSymCleanup);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // SAFETY: the function pointer was resolved from DbgHelp and the process was initialized.
                unsafe {
                    (self.1)(self.0);
                }
            }
        }
        let _cleanup = Cleanup(h_proc, sym_cleanup);

        sym_set_search(h_proc, sp_c.as_ptr() as *const u8);

        let img_c = CString::new(dll_path).ok()?;
        let base = sym_load_module_ex(
            h_proc,
            std::ptr::null_mut(),
            img_c.as_ptr() as *const u8,
            std::ptr::null(),
            image_base,
            0,
            std::ptr::null_mut(),
            0,
        );
        if base == 0 {
            if verbose {
                eprintln!("  SymLoadModuleEx failed for {}", dll_path);
            }
            return None;
        }
        if verbose {
            log_loaded_module(h_proc, base, sym_get_module_info);
        }

        let mut si = SymbolInfo {
            size_of_struct: 88,
            max_name_len: 512,
            ..Default::default()
        };

        let fn_c = CString::new(func_name).ok()?;
        let r = sym_from_name(h_proc, fn_c.as_ptr() as *const u8, &mut si);
        if r == 0 {
            return None;
        }

        if si.address < image_base {
            return None;
        }
        Some((si.address - image_base) as u32)
    };
    if let Ok(mut cache) = lookup_cache().lock() {
        cache.insert(lookup_key, result);
    }
    result
}

pub fn load_pdb_symbols(
    dll_path: &str,
    sym_path: &str,
    sym_server: &str,
    pdb_path: &str,
    verbose: bool,
    reload: bool,
) -> Result<Vec<PdbSymbol>, String> {
    let cache_key = pdb_cache_key(dll_path, sym_path, sym_server, pdb_path);
    if !reload {
        if let Some(cached) = symbol_cache()
            .lock()
            .ok()
            .and_then(|cache| cache.get(&cache_key).cloned())
        {
            return Ok(cached);
        }
    }

    // SAFETY: loaded DbgHelp exports are checked for null and transmuted to their documented signatures;
    // C strings, callback context, and output records remain live for each synchronous call.
    let result = unsafe {
        let lib = LoadLibraryA(c"dbghelp.dll".as_ptr() as *const u8);
        if lib.is_null() {
            return Err("dbghelp.dll unavailable".to_owned());
        }

        macro_rules! proc {
            ($name:literal, $ty:ty) => {{
                let p = get_proc(lib, concat!($name, "\0").as_bytes());
                if p.is_null() {
                    return Err(format!("missing dbghelp export {}", $name));
                }
                std::mem::transmute::<*const c_void, $ty>(p)
            }};
        }

        let sym_initialize: FnSymInitialize = proc!("SymInitialize", FnSymInitialize);
        let sym_cleanup: FnSymCleanup = proc!("SymCleanup", FnSymCleanup);
        let sym_set_options: FnSymSetOptions = proc!("SymSetOptions", FnSymSetOptions);
        let sym_load_module_ex: FnSymLoadModuleEx = proc!("SymLoadModuleEx", FnSymLoadModuleEx);
        let sym_enum_symbols: FnSymEnumSymbols = proc!("SymEnumSymbols", FnSymEnumSymbols);
        let sym_get_type_info: FnSymGetTypeInfo = proc!("SymGetTypeInfo", FnSymGetTypeInfo);
        let sym_get_module_info: FnSymGetModuleInfo =
            proc!("SymGetModuleInfo64", FnSymGetModuleInfo);
        let sym_set_search: FnSymSetSearchPath = proc!("SymSetSearchPath", FnSymSetSearchPath);

        sym_set_options(0x00000002 | 0x00000004 | 0x00000010);

        let resolved_pdb_path = resolve_pdb_path(dll_path, sym_server, pdb_path, verbose, reload);
        let sp = build_search_path(dll_path, sym_path, sym_server, &resolved_pdb_path);
        if verbose {
            eprintln!("  Symbol search path: {}", sp);
            if !resolved_pdb_path.is_empty() {
                eprintln!("  Exact PDB path: {}", resolved_pdb_path);
            }
        }
        let sp_c = CString::new(sp.clone()).map_err(|_| "invalid symbol path".to_owned())?;
        let h_proc = GetCurrentProcess();
        if sym_initialize(h_proc, sp_c.as_ptr() as *const u8, 0) == 0 {
            return Err("SymInitialize failed".to_owned());
        }
        struct Cleanup(*mut c_void, FnSymCleanup);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // SAFETY: the function pointer was resolved from DbgHelp and the process was initialized.
                unsafe {
                    (self.1)(self.0);
                }
            }
        }
        let _cleanup = Cleanup(h_proc, sym_cleanup);
        sym_set_search(h_proc, sp_c.as_ptr() as *const u8);

        let img_c = CString::new(dll_path).map_err(|_| "invalid module path".to_owned())?;
        let module_base = sym_load_module_ex(
            h_proc,
            std::ptr::null_mut(),
            img_c.as_ptr() as *const u8,
            std::ptr::null(),
            0,
            0,
            std::ptr::null_mut(),
            0,
        );
        if module_base == 0 {
            return Err(format!("SymLoadModuleEx failed for {}", dll_path));
        }
        if verbose {
            log_loaded_module(h_proc, module_base, sym_get_module_info);
        }

        let mask = CString::new("*").unwrap();
        let mut out: Vec<PdbSymbol> = Vec::new();
        let mut ctx = EnumContext {
            h_proc,
            module_base,
            sym_get_type_info,
            out: &mut out as *mut Vec<PdbSymbol>,
        };
        let ctx_ptr = &mut ctx as *mut EnumContext as usize;
        if sym_enum_symbols(
            h_proc,
            module_base,
            mask.as_ptr() as *const u8,
            enum_symbol_cb,
            ctx_ptr,
        ) == 0
        {
            return Err("SymEnumSymbols failed".to_owned());
        }
        out.sort_by(|a, b| a.rva.cmp(&b.rva).then_with(|| a.name.cmp(&b.name)));
        out.dedup_by(|a, b| a.rva == b.rva && a.name == b.name);
        Ok(out)
    };
    if let Ok(symbols) = &result {
        if let Ok(mut cache) = symbol_cache().lock() {
            cache.insert(cache_key, symbols.clone());
        }
    }
    result
}

pub fn load_pdb_types(
    dll_path: &str,
    sym_path: &str,
    sym_server: &str,
    pdb_path: &str,
    verbose: bool,
    reload: bool,
) -> Result<Vec<PdbTypeInfo>, String> {
    let cache_key = format!(
        "{}|types",
        pdb_cache_key(dll_path, sym_path, sym_server, pdb_path)
    );
    if !reload {
        if let Some(cached) = type_cache()
            .lock()
            .ok()
            .and_then(|cache| cache.get(&cache_key).cloned())
        {
            return Ok(cached);
        }
    }

    let preferred_pdb_path = if !pdb_path.is_empty() {
        pdb_path.to_owned()
    } else {
        resolve_pdb_path(dll_path, sym_server, pdb_path, verbose, reload)
    };
    if !preferred_pdb_path.is_empty() {
        match load_pdb_types_via_llvm_dump(&preferred_pdb_path) {
            Ok(types) if !types.is_empty() => {
                if verbose {
                    eprintln!(
                        "  llvm-pdbutil preferred path: {} type(s) from {}",
                        types.len(),
                        preferred_pdb_path
                    );
                }
                if let Ok(mut cache) = type_cache().lock() {
                    cache.insert(cache_key, types.clone());
                }
                return Ok(types);
            }
            Ok(_) => {
                if verbose {
                    eprintln!(
                        "  llvm-pdbutil preferred path returned 0 types from {}",
                        preferred_pdb_path
                    );
                }
            }
            Err(err) => {
                if verbose {
                    eprintln!("  llvm-pdbutil preferred path failed: {}", err);
                }
            }
        }
    }

    let symbols = load_pdb_symbols(dll_path, sym_path, sym_server, pdb_path, verbose, reload)?;
    // SAFETY: loaded DbgHelp exports are checked for null and transmuted to their documented signatures;
    // all symbol/type buffers and callback state remain live for each synchronous call.
    let result = unsafe {
        let lib = LoadLibraryA(c"dbghelp.dll".as_ptr() as *const u8);
        if lib.is_null() {
            return Err("dbghelp.dll unavailable".to_owned());
        }

        macro_rules! proc {
            ($name:literal, $ty:ty) => {{
                let p = get_proc(lib, concat!($name, "\0").as_bytes());
                if p.is_null() {
                    return Err(format!("missing dbghelp export {}", $name));
                }
                std::mem::transmute::<*const c_void, $ty>(p)
            }};
        }

        let sym_initialize: FnSymInitialize = proc!("SymInitialize", FnSymInitialize);
        let sym_cleanup: FnSymCleanup = proc!("SymCleanup", FnSymCleanup);
        let sym_set_options: FnSymSetOptions = proc!("SymSetOptions", FnSymSetOptions);
        let sym_load_module_ex: FnSymLoadModuleEx = proc!("SymLoadModuleEx", FnSymLoadModuleEx);
        let sym_enum_types: FnSymEnumTypes = proc!("SymEnumTypes", FnSymEnumTypes);
        let sym_get_type_info: FnSymGetTypeInfo = proc!("SymGetTypeInfo", FnSymGetTypeInfo);
        let sym_get_module_info: FnSymGetModuleInfo =
            proc!("SymGetModuleInfo64", FnSymGetModuleInfo);
        let sym_set_search: FnSymSetSearchPath = proc!("SymSetSearchPath", FnSymSetSearchPath);

        sym_set_options(0x00000002 | 0x00000004 | 0x00000010);

        let resolved_pdb_path = resolve_pdb_path(dll_path, sym_server, pdb_path, verbose, reload);
        let sp = build_search_path(dll_path, sym_path, sym_server, &resolved_pdb_path);
        let sp_c = CString::new(sp.clone()).map_err(|_| "invalid symbol path".to_owned())?;
        let h_proc = GetCurrentProcess();
        if sym_initialize(h_proc, sp_c.as_ptr() as *const u8, 0) == 0 {
            return Err("SymInitialize failed".to_owned());
        }
        struct Cleanup(*mut c_void, FnSymCleanup);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // SAFETY: the function pointer was resolved from DbgHelp and the process was initialized.
                unsafe {
                    (self.1)(self.0);
                }
            }
        }
        let _cleanup = Cleanup(h_proc, sym_cleanup);
        sym_set_search(h_proc, sp_c.as_ptr() as *const u8);

        let img_c = CString::new(dll_path).map_err(|_| "invalid module path".to_owned())?;
        let module_base = sym_load_module_ex(
            h_proc,
            std::ptr::null_mut(),
            img_c.as_ptr() as *const u8,
            std::ptr::null(),
            0,
            0,
            std::ptr::null_mut(),
            0,
        );
        if module_base == 0 {
            return Err(format!("SymLoadModuleEx failed for {}", dll_path));
        }
        if verbose {
            log_loaded_module(h_proc, module_base, sym_get_module_info);
        }

        let mut pending: Vec<u32> = symbols
            .iter()
            .filter_map(|sym| (sym.type_id != 0).then_some(sym.type_id))
            .collect();
        let mut enum_seeds: Vec<TypeSeed> = Vec::new();
        let mut type_ctx = TypeEnumContext {
            out: &mut enum_seeds as *mut Vec<TypeSeed>,
        };
        let type_ctx_ptr = &mut type_ctx as *mut TypeEnumContext as usize;
        let _ = sym_enum_types(h_proc, module_base, enum_type_cb, type_ctx_ptr);
        pending.extend(enum_seeds.iter().map(|seed| seed.type_id));
        pending.sort_unstable();
        pending.dedup();
        let seed_map: HashMap<u32, TypeSeed> = enum_seeds
            .into_iter()
            .filter(|seed| seed.type_id != 0)
            .map(|seed| (seed.type_id, seed))
            .collect();

        let mut seen = HashSet::new();
        let mut out = Vec::new();
        while let Some(type_id) = pending.pop() {
            if !seen.insert(type_id) {
                continue;
            }
            let (info, nested) = build_type_info(h_proc, module_base, type_id, sym_get_type_info);
            pending.extend(nested.into_iter().filter(|id| *id != 0));
            if let Some(info) = info {
                out.push(info);
            } else if let Some(seed) = seed_map.get(&type_id) {
                let name = seed.name.trim();
                if !name.is_empty() {
                    out.push(PdbTypeInfo {
                        type_id,
                        name: name.to_owned(),
                        kind: type_tag_name(seed.tag).to_owned(),
                        size: get_type_size(h_proc, module_base, type_id, sym_get_type_info)
                            .unwrap_or(0),
                        members: Vec::new(),
                    });
                }
            }
        }
        if out.is_empty() {
            let fallback_pdb = if !resolved_pdb_path.is_empty() {
                resolved_pdb_path.clone()
            } else {
                pdb_path.to_owned()
            };
            if !fallback_pdb.is_empty() {
                match load_pdb_types_via_llvm_dump(&fallback_pdb) {
                    Ok(fallback) => {
                        if verbose {
                            eprintln!(
                                "  llvm-pdbutil fallback: {} type(s) from {}",
                                fallback.len(),
                                fallback_pdb
                            );
                        }
                        if !fallback.is_empty() {
                            out = fallback;
                        }
                    }
                    Err(err) => {
                        if verbose {
                            eprintln!("  llvm-pdbutil fallback failed: {}", err);
                        }
                    }
                }
            }
        }
        out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.type_id.cmp(&b.type_id)));
        Ok(out)
    };

    if let Ok(types) = &result {
        if let Ok(mut cache) = type_cache().lock() {
            cache.insert(cache_key, types.clone());
        }
    }
    result
}
