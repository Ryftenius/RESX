#[cfg(windows)]
mod win {
    use crate::formats::pe::{parse_pe, read_u32};
    use std::collections::{HashMap, HashSet};
    use std::ffi::{c_void, CStr, CString};
    use std::path::{Path, PathBuf};
    use std::slice;
    use std::sync::{Mutex, OnceLock};

    const DEFAULT_MS_SYMBOL_SERVER: &str = "http://msdl.microsoft.com/download/symbols";
    const IMAGE_DIRECTORY_ENTRY_DEBUG: usize = 6;
    const IMAGE_DEBUG_TYPE_CODEVIEW: u32 = 2;
    const S_OK: i32 = 0;

    type FnSymInitialize = unsafe extern "system" fn(*mut c_void, *const u8, i32) -> i32;
    type FnSymCleanup = unsafe extern "system" fn(*mut c_void) -> i32;
    type FnSymSetOptions = unsafe extern "system" fn(u32) -> u32;
    type FnSymLoadModuleEx = unsafe extern "system" fn(
        *mut c_void,
        *mut c_void,
        *const u8,
        *const u8,
        u64,
        u32,
        *mut c_void,
        u32,
    ) -> u64;
    type FnSymFromName = unsafe extern "system" fn(*mut c_void, *const u8, *mut SymbolInfo) -> i32;
    type FnSymEnumSymbols =
        unsafe extern "system" fn(*mut c_void, u64, *const u8, SymEnumSymbolsProc, usize) -> i32;
    type FnSymEnumTypes =
        unsafe extern "system" fn(*mut c_void, u64, SymEnumSymbolsProc, usize) -> i32;
    type FnSymGetTypeInfo =
        unsafe extern "system" fn(*mut c_void, u64, u32, u32, *mut c_void) -> i32;
    type FnSymGetModuleInfo =
        unsafe extern "system" fn(*mut c_void, u64, *mut ImagehlpModule64) -> i32;
    type FnSymSetSearchPath = unsafe extern "system" fn(*mut c_void, *const u8) -> i32;
    type SymEnumSymbolsProc = unsafe extern "system" fn(*mut SymbolInfo, u32, usize) -> i32;

    #[link(name = "kernel32")]
    extern "system" {
        fn LoadLibraryA(name: *const u8) -> *mut c_void;
        fn GetProcAddress(module: *mut c_void, name: *const u8) -> *const c_void;
        fn GetCurrentProcess() -> *mut c_void;
        fn LocalFree(ptr: *mut c_void) -> *mut c_void;
    }

    #[link(name = "urlmon")]
    extern "system" {
        fn URLDownloadToFileW(
            p_caller: *mut c_void,
            sz_url: *const u16,
            sz_file_name: *const u16,
            dw_reserved: u32,
            lpfn_cb: *mut c_void,
        ) -> i32;
    }

    fn get_proc(module: *mut c_void, name: &[u8]) -> *const c_void {
        unsafe { GetProcAddress(module, name.as_ptr()) }
    }

    #[repr(C)]
    pub struct SymbolInfo {
        pub size_of_struct: u32,
        pub type_index: u32,
        pub reserved: [u64; 2],
        pub index: u32,
        pub size: u32,
        pub mod_base: u64,
        pub flags: u32,
        _pad: u32,
        pub value: u64,
        pub address: u64,
        pub register: u32,
        pub scope: u32,
        pub tag: u32,
        pub name_len: u32,
        pub max_name_len: u32,
        pub name: [u8; 512],
    }

    impl Default for SymbolInfo {
        fn default() -> Self {
            unsafe { std::mem::zeroed() }
        }
    }

    #[repr(C)]
    struct Guid {
        data1: u32,
        data2: u16,
        data3: u16,
        data4: [u8; 8],
    }

    #[repr(C)]
    struct ImagehlpModule64 {
        size_of_struct: u32,
        base_of_image: u64,
        image_size: u32,
        time_date_stamp: u32,
        check_sum: u32,
        num_syms: u32,
        sym_type: u32,
        module_name: [u8; 32],
        image_name: [u8; 256],
        loaded_image_name: [u8; 256],
        loaded_pdb_name: [u8; 256],
        cv_sig: u32,
        cv_data: [u8; 256 * 3],
        pdb_sig: u32,
        pdb_sig70: Guid,
        pdb_age: u32,
        pdb_unmatched: i32,
        dbg_unmatched: i32,
        line_numbers: i32,
        global_symbols: i32,
        type_info: i32,
        source_indexed: i32,
        publics: i32,
        machine_type: u32,
        reserved: u32,
    }

    impl Default for ImagehlpModule64 {
        fn default() -> Self {
            unsafe { std::mem::zeroed() }
        }
    }

    #[derive(Debug, Clone)]
    pub struct PdbSymbol {
        pub name: String,
        pub rva: u32,
        pub va: u64,
        pub kind: String,
        pub type_id: u32,
        pub type_name: String,
        pub size: u64,
    }

    #[derive(Debug, Clone)]
    pub struct PdbTypeMember {
        pub name: String,
        pub offset: u64,
        pub type_id: u32,
        pub type_name: String,
        pub kind: String,
        pub size: u64,
    }

    #[derive(Debug, Clone)]
    pub struct PdbTypeInfo {
        pub type_id: u32,
        pub name: String,
        pub kind: String,
        pub size: u64,
        pub members: Vec<PdbTypeMember>,
    }

    struct EnumContext {
        h_proc: *mut c_void,
        module_base: u64,
        sym_get_type_info: FnSymGetTypeInfo,
        out: *mut Vec<PdbSymbol>,
    }

    struct TypeEnumContext {
        out: *mut Vec<TypeSeed>,
    }

    #[derive(Debug, Clone)]
    struct TypeSeed {
        type_id: u32,
        name: String,
        tag: u32,
    }

    const TI_GET_SYMNAME: u32 = 1;
    const TI_GET_LENGTH: u32 = 2;
    const TI_GET_TYPE: u32 = 3;
    const TI_GET_TYPEID: u32 = 4;
    const TI_GET_BASETYPE: u32 = 5;
    const TI_FINDCHILDREN: u32 = 7;
    const TI_GET_OFFSET: u32 = 10;
    const TI_GET_CHILDRENCOUNT: u32 = 13;
    const TI_GET_SYMTAG: u32 = 0;
    const TI_GET_IS_REFERENCE: u32 = 31;
    const SYM_TAG_FUNCTION: u32 = 5;
    const SYM_TAG_DATA: u32 = 7;
    const SYM_TAG_PUBLIC: u32 = 10;
    const SYM_TAG_UDT: u32 = 11;
    const SYM_TAG_ENUM: u32 = 12;
    const SYM_TAG_FUNCTION_TYPE: u32 = 13;
    const SYM_TAG_POINTER_TYPE: u32 = 14;
    const SYM_TAG_ARRAY_TYPE: u32 = 15;
    const SYM_TAG_BASE_TYPE: u32 = 16;
    const SYM_TAG_TYPEDEF: u32 = 17;
    const SYM_TAG_BASE_CLASS: u32 = 18;

    #[repr(C)]
    struct TiFindChildrenHeader {
        count: u32,
        start: u32,
    }

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

            let resolved_pdb_path =
                resolve_pdb_path(dll_path, sym_server, pdb_path, verbose, reload);
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

            let resolved_pdb_path =
                resolve_pdb_path(dll_path, sym_server, pdb_path, verbose, reload);
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

            let resolved_pdb_path =
                resolve_pdb_path(dll_path, sym_server, pdb_path, verbose, reload);
            let sp = build_search_path(dll_path, sym_path, sym_server, &resolved_pdb_path);
            let sp_c = CString::new(sp.clone()).map_err(|_| "invalid symbol path".to_owned())?;
            let h_proc = GetCurrentProcess();
            if sym_initialize(h_proc, sp_c.as_ptr() as *const u8, 0) == 0 {
                return Err("SymInitialize failed".to_owned());
            }
            struct Cleanup(*mut c_void, FnSymCleanup);
            impl Drop for Cleanup {
                fn drop(&mut self) {
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
                let (info, nested) =
                    build_type_info(h_proc, module_base, type_id, sym_get_type_info);
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

    fn symbol_cache() -> &'static Mutex<HashMap<String, Vec<PdbSymbol>>> {
        static CACHE: OnceLock<Mutex<HashMap<String, Vec<PdbSymbol>>>> = OnceLock::new();
        CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn type_cache() -> &'static Mutex<HashMap<String, Vec<PdbTypeInfo>>> {
        static CACHE: OnceLock<Mutex<HashMap<String, Vec<PdbTypeInfo>>>> = OnceLock::new();
        CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn lookup_cache() -> &'static Mutex<HashMap<String, Option<u32>>> {
        static CACHE: OnceLock<Mutex<HashMap<String, Option<u32>>>> = OnceLock::new();
        CACHE.get_or_init(|| Mutex::new(HashMap::new()))
    }

    fn pdb_cache_key(dll_path: &str, sym_path: &str, sym_server: &str, pdb_path: &str) -> String {
        format!(
            "{}|{}|{}|{}",
            dll_path.to_ascii_lowercase(),
            sym_path.to_ascii_lowercase(),
            sym_server.to_ascii_lowercase(),
            pdb_path.to_ascii_lowercase()
        )
    }

    fn pdb_lookup_cache_key(
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

    fn find_symbol_rva(symbols: &[PdbSymbol], func_name: &str) -> Option<u32> {
        let want = func_name.to_ascii_lowercase();
        symbols
            .iter()
            .find(|sym| sym.name.eq_ignore_ascii_case(&want))
            .map(|sym| sym.rva)
    }

    unsafe extern "system" fn enum_symbol_cb(
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
        let name =
            String::from_utf8_lossy(&info.name[..name_len.min(info.name.len())]).into_owned();
        if !name.is_empty() {
            let type_id = get_type_id(
                ctx.h_proc,
                ctx.module_base,
                info.type_index,
                ctx.sym_get_type_info,
            );
            let type_name = type_id
                .and_then(|id| {
                    get_type_name(ctx.h_proc, ctx.module_base, id, ctx.sym_get_type_info)
                })
                .unwrap_or_default();
            let size = type_id
                .and_then(|id| {
                    get_type_size(ctx.h_proc, ctx.module_base, id, ctx.sym_get_type_info)
                })
                .unwrap_or(info.size as u64);
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

    unsafe extern "system" fn enum_type_cb(
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
        let name =
            String::from_utf8_lossy(&info.name[..name_len.min(info.name.len())]).into_owned();
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

    unsafe fn get_type_id(
        h_proc: *mut c_void,
        module_base: u64,
        type_index: u32,
        sym_get_type_info: FnSymGetTypeInfo,
    ) -> Option<u32> {
        if type_index == 0 {
            return None;
        }
        let mut type_id = 0u32;
        if sym_get_type_info(
            h_proc,
            module_base,
            type_index,
            TI_GET_TYPEID,
            &mut type_id as *mut _ as *mut c_void,
        ) == 0
        {
            return Some(type_index);
        }
        Some(type_id)
    }

    unsafe fn get_type_size(
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
        if count == 0 {
            return Vec::new();
        }
        let bytes = std::mem::size_of::<TiFindChildrenHeader>() + count as usize * 4;
        let mut buf = vec![0u8; bytes];
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
        let ids_ptr = buf
            .as_ptr()
            .add(std::mem::size_of::<TiFindChildrenHeader>()) as *const u32;
        slice::from_raw_parts(ids_ptr, count as usize).to_vec()
    }

    unsafe fn build_type_info(
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
                    get_type_size(h_proc, module_base, member_type_id, sym_get_type_info)
                        .unwrap_or(0)
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
        if type_id == 0 {
            return "void".to_owned();
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
                let inner =
                    get_type_u32(h_proc, module_base, type_id, TI_GET_TYPE, sym_get_type_info)
                        .map(|id| describe_type(h_proc, module_base, id, sym_get_type_info, seen))
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
                let inner = describe_type(h_proc, module_base, inner_id, sym_get_type_info, seen);
                let total =
                    get_type_size(h_proc, module_base, type_id, sym_get_type_info).unwrap_or(0);
                let elem =
                    get_type_size(h_proc, module_base, inner_id, sym_get_type_info).unwrap_or(0);
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
                let len =
                    get_type_size(h_proc, module_base, type_id, sym_get_type_info).unwrap_or(0);
                base_type_name(base, len).to_owned()
            }
            SYM_TAG_FUNCTION_TYPE => "function".to_owned(),
            _ => get_type_name(h_proc, module_base, type_id, sym_get_type_info)
                .unwrap_or_else(|| format!("{}#{:X}", type_tag_name(tag), type_id)),
        };
        seen.pop();
        name
    }

    fn base_type_name(base: u32, len: u64) -> &'static str {
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

    fn type_tag_name(tag: u32) -> &'static str {
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

    #[derive(Debug, Clone, Default)]
    struct LlvmDumpMember {
        name: String,
        offset: u64,
        type_id: u32,
        type_name: String,
        kind: String,
        size: u64,
    }

    #[derive(Debug, Clone, Default)]
    struct LlvmDumpRecord {
        type_id: u32,
        leaf: String,
        name: String,
        size: u64,
        field_list_id: u32,
        forward_to: u32,
        members: Vec<LlvmDumpMember>,
    }

    fn load_pdb_types_via_llvm_dump(pdb_path: &str) -> Result<Vec<PdbTypeInfo>, String> {
        let tool = find_llvm_pdbutil()
            .ok_or_else(|| "llvm-pdbutil.exe not found for fallback type parsing".to_owned())?;
        let output = std::process::Command::new(tool)
            .args(["dump", "-types", pdb_path])
            .output()
            .map_err(|e| format!("spawn llvm-pdbutil: {}", e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            return Err(if !stderr.is_empty() { stderr } else { stdout });
        }

        let text = String::from_utf8_lossy(&output.stdout);
        let mut records: HashMap<u32, LlvmDumpRecord> = HashMap::new();
        let mut current_id = 0u32;

        for line in text.lines() {
            let trimmed = line.trim();
            if let Some((type_id, leaf, name)) = parse_llvm_dump_header(trimmed) {
                current_id = type_id;
                let rec = records.entry(type_id).or_default();
                rec.type_id = type_id;
                rec.leaf = leaf;
                if rec.name.is_empty() {
                    rec.name = name;
                }
                continue;
            }
            if current_id == 0 || trimmed.is_empty() {
                continue;
            }
            let rec = match records.get_mut(&current_id) {
                Some(rec) => rec,
                None => continue,
            };
            if rec.leaf == "LF_FIELDLIST" {
                if let Some(member) = parse_llvm_dump_member(trimmed) {
                    rec.members.push(member);
                }
                continue;
            }
            if let Some(field_list_id) = parse_llvm_dump_ref(trimmed, "field list:") {
                rec.field_list_id = field_list_id;
            }
            if let Some(size) = parse_llvm_dump_size(trimmed) {
                rec.size = size;
            }
            if let Some(target) = parse_llvm_dump_forward_ref(trimmed) {
                rec.forward_to = target;
            }
        }

        let mut out = Vec::new();
        let mut seen = HashSet::new();
        let ids = records.keys().copied().collect::<Vec<_>>();
        for type_id in ids {
            let Some(rec) = records.get(&type_id) else {
                continue;
            };
            let kind = llvm_leaf_kind(&rec.leaf);
            if kind.is_empty() {
                continue;
            }
            let canonical_id = canonical_dump_type_id(type_id, &records);
            let canonical = records.get(&canonical_id).unwrap_or(rec);
            let name = canonical.name.trim();
            if name.is_empty()
                || name.contains("(__cdecl")
                || name.starts_with('<')
                || !seen.insert(format!("{}|{}", type_id, name.to_ascii_lowercase()))
            {
                continue;
            }
            let members = if canonical.field_list_id != 0 {
                records
                    .get(&canonical.field_list_id)
                    .map(|field_list| {
                        field_list
                            .members
                            .iter()
                            .map(|member| PdbTypeMember {
                                name: member.name.clone(),
                                offset: member.offset,
                                type_id: member.type_id,
                                type_name: resolve_dump_type_name(
                                    member.type_id,
                                    &member.type_name,
                                    &records,
                                ),
                                kind: member.kind.clone(),
                                size: member.size,
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            out.push(PdbTypeInfo {
                type_id,
                name: name.to_owned(),
                kind: kind.to_owned(),
                size: canonical.size,
                members,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.type_id.cmp(&b.type_id)));
        Ok(out)
    }

    fn parse_llvm_dump_header(line: &str) -> Option<(u32, String, String)> {
        let (id_part, rest) = line.split_once('|')?;
        let type_id = u32::from_str_radix(id_part.trim().trim_start_matches("0x"), 16).ok()?;
        let leaf_start = rest.find("LF_")?;
        let rest = &rest[leaf_start..];
        let leaf_end = rest.find(' ')?;
        let leaf = rest[..leaf_end].trim().to_owned();
        let name = rest
            .split('`')
            .nth(1)
            .map(|s| s.trim().to_owned())
            .unwrap_or_default();
        Some((type_id, leaf, name))
    }

    fn parse_llvm_dump_ref(line: &str, key: &str) -> Option<u32> {
        let idx = line.find(key)?;
        let tail = &line[idx + key.len()..];
        let hex = tail
            .trim_start()
            .strip_prefix("0x")
            .unwrap_or(tail.trim_start())
            .chars()
            .take_while(|ch| ch.is_ascii_hexdigit())
            .collect::<String>();
        u32::from_str_radix(&hex, 16).ok()
    }

    fn parse_llvm_dump_size(line: &str) -> Option<u64> {
        let idx = line.find("sizeof ")?;
        let tail = &line[idx + 7..];
        let digits = tail
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        digits.parse::<u64>().ok()
    }

    fn parse_llvm_dump_forward_ref(line: &str) -> Option<u32> {
        let idx = line.find("forward ref (-> 0x")?;
        let tail = &line[idx + "forward ref (-> 0x".len()..];
        let hex = tail
            .chars()
            .take_while(|ch| ch.is_ascii_hexdigit())
            .collect::<String>();
        u32::from_str_radix(&hex, 16).ok()
    }

    fn parse_llvm_dump_member(line: &str) -> Option<LlvmDumpMember> {
        if !line.starts_with("- LF_MEMBER [") {
            return None;
        }
        let name = extract_between(line, "name = `", "`")?.to_owned();
        let type_field = line
            .split_once("Type = ")
            .map(|(_, tail)| tail.split(", offset =").next().unwrap_or(tail).trim())
            .unwrap_or_default();
        let type_id = type_field
            .strip_prefix("0x")
            .and_then(|tail| {
                let hex = tail
                    .chars()
                    .take_while(|ch| ch.is_ascii_hexdigit())
                    .collect::<String>();
                u32::from_str_radix(&hex, 16).ok()
            })
            .unwrap_or(0);
        let type_name = type_field
            .split_once('(')
            .map(|(_, name)| name.trim_end_matches(')').trim())
            .unwrap_or(type_field)
            .to_owned();
        let offset = extract_after_decimal(line, "offset = ").unwrap_or(0);
        Some(LlvmDumpMember {
            name,
            offset,
            type_id,
            type_name,
            kind: "member".to_owned(),
            size: 0,
        })
    }

    fn extract_between<'a>(line: &'a str, start: &str, end: &str) -> Option<&'a str> {
        let tail = line.split_once(start)?.1;
        Some(tail.split_once(end)?.0)
    }

    fn extract_after_decimal(line: &str, key: &str) -> Option<u64> {
        let tail = line.split_once(key)?.1;
        let digits = tail
            .chars()
            .take_while(|ch| ch.is_ascii_digit())
            .collect::<String>();
        digits.parse::<u64>().ok()
    }

    fn llvm_leaf_kind(leaf: &str) -> &'static str {
        match leaf {
            "LF_STRUCTURE" => "struct",
            "LF_CLASS" => "class",
            "LF_UNION" => "union",
            "LF_ENUM" => "enum",
            "LF_TYPEDEF" => "typedef",
            _ => "",
        }
    }

    fn canonical_dump_type_id(type_id: u32, records: &HashMap<u32, LlvmDumpRecord>) -> u32 {
        let mut current = type_id;
        let mut seen = HashSet::new();
        while seen.insert(current) {
            let Some(rec) = records.get(&current) else {
                break;
            };
            if rec.forward_to == 0 {
                break;
            }
            current = rec.forward_to;
        }
        current
    }

    fn resolve_dump_type_name(
        type_id: u32,
        fallback_name: &str,
        records: &HashMap<u32, LlvmDumpRecord>,
    ) -> String {
        if !fallback_name.trim().is_empty() {
            return fallback_name.trim().to_owned();
        }
        let canonical_id = canonical_dump_type_id(type_id, records);
        records
            .get(&canonical_id)
            .or_else(|| records.get(&type_id))
            .map(|rec| rec.name.trim().to_owned())
            .filter(|name| !name.is_empty())
            .unwrap_or_else(|| {
                if type_id == 0 {
                    "unknown".to_owned()
                } else {
                    format!("type_0x{:X}", type_id)
                }
            })
    }

    fn find_llvm_pdbutil() -> Option<String> {
        let candidates = [
            r"C:\Program Files\LLVM\bin\llvm-pdbutil.exe",
            r"C:\Program Files (x86)\LLVM\bin\llvm-pdbutil.exe",
        ];
        for candidate in candidates {
            if Path::new(candidate).is_file() {
                return Some(candidate.to_owned());
            }
        }
        Some("llvm-pdbutil.exe".to_owned())
    }

    fn tag_name(tag: u32) -> &'static str {
        match tag {
            SYM_TAG_FUNCTION => "function",
            SYM_TAG_DATA => "data",
            SYM_TAG_PUBLIC => "public",
            _ => "symbol",
        }
    }

    unsafe fn log_loaded_module(
        h_proc: *mut c_void,
        module_base: u64,
        sym_get_module_info: FnSymGetModuleInfo,
    ) {
        let mut info = ImagehlpModule64 {
            size_of_struct: std::mem::size_of::<ImagehlpModule64>() as u32,
            ..Default::default()
        };
        if sym_get_module_info(h_proc, module_base, &mut info) == 0 {
            eprintln!(
                "  Loaded symbols: module=0x{:X} (SymGetModuleInfo64 unavailable)",
                module_base
            );
            return;
        }

        let loaded_pdb = c_buf_to_string(&info.loaded_pdb_name);
        let loaded_image = c_buf_to_string(&info.loaded_image_name);
        let module_name = c_buf_to_string(&info.module_name);
        let sym_type = sym_type_name(info.sym_type);

        eprintln!(
            "  Loaded symbols: module={} base=0x{:X} type={} symbols={}",
            if module_name.is_empty() {
                "<unknown>"
            } else {
                &module_name
            },
            info.base_of_image,
            sym_type,
            info.num_syms
        );
        if !loaded_image.is_empty() {
            eprintln!("  Loaded image: {}", loaded_image);
        }
        if !loaded_pdb.is_empty() {
            eprintln!("  Loaded PDB:   {}", loaded_pdb);
        }
    }

    fn c_buf_to_string(buf: &[u8]) -> String {
        let ptr = buf.as_ptr() as *const i8;
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .trim()
            .to_owned()
    }

    fn sym_type_name(sym_type: u32) -> &'static str {
        match sym_type {
            1 => "coff",
            2 => "codeview",
            3 => "pdb",
            4 => "export",
            5 => "deferred",
            6 => "sym",
            7 => "dia",
            8 => "virtual",
            _ => "none",
        }
    }

    fn resolve_pdb_path(
        dll_path: &str,
        sym_server: &str,
        pdb_path: &str,
        verbose: bool,
        reload: bool,
    ) -> String {
        if !pdb_path.is_empty() {
            return pdb_path.to_owned();
        }

        match ensure_exact_pdb_cached(dll_path, sym_server, verbose, reload) {
            Ok(Some(path)) => path,
            Ok(None) => String::new(),
            Err(err) => {
                if verbose {
                    eprintln!("  Exact PDB fetch unavailable: {}", err);
                }
                String::new()
            }
        }
    }

    fn ensure_exact_pdb_cached(
        dll_path: &str,
        sym_server: &str,
        verbose: bool,
        reload: bool,
    ) -> Result<Option<String>, String> {
        let raw =
            std::fs::read(dll_path).map_err(|e| format!("read image for debug info: {}", e))?;
        let pe = parse_pe(&raw).map_err(|e| e.0)?;
        let info = match extract_codeview_info(&pe, &raw) {
            Some(info) => info,
            None => return Ok(None),
        };

        let cache_dir = default_symbol_cache_dir();
        std::fs::create_dir_all(&cache_dir).map_err(|e| format!("create symbol cache: {}", e))?;

        let cache_path = Path::new(&cache_dir)
            .join(&info.pdb_name)
            .join(&info.guid_age)
            .join(&info.pdb_name);
        if cache_path.is_file() && !reload {
            return Ok(Some(cache_path.to_string_lossy().into_owned()));
        }

        if let Some(parent) = cache_path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create pdb cache dir: {}", e))?;
        }

        let server = effective_symbol_server(sym_server);
        if server.is_empty() {
            return Ok(None);
        }

        let temp_path = temp_download_path(&cache_path);
        let mut last_err = String::new();
        for download_url in candidate_symbol_urls(&server, &info.pdb_name, &info.guid_age) {
            if verbose {
                eprintln!("  PDB download URL: {}", download_url);
                eprintln!("  PDB cache path:   {}", cache_path.display());
            }
            match download_to_file(&download_url, &temp_path) {
                Ok(()) => {
                    std::fs::rename(&temp_path, &cache_path)
                        .or_else(|_| {
                            std::fs::copy(&temp_path, &cache_path)?;
                            std::fs::remove_file(&temp_path)
                        })
                        .map_err(|e| format!("store cached pdb: {}", e))?;
                    return Ok(Some(cache_path.to_string_lossy().into_owned()));
                }
                Err(err) => {
                    last_err = format!("download {}: {}", download_url, err);
                    let _ = std::fs::remove_file(&temp_path);
                }
            }
        }
        Err(last_err)
    }

    struct CodeViewInfo {
        pdb_name: String,
        guid_age: String,
    }

    fn extract_codeview_info(pe: &crate::formats::pe::PeFile, raw: &[u8]) -> Option<CodeViewInfo> {
        let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_DEBUG);
        if dir_rva == 0 || dir_size < 28 {
            return None;
        }

        let mut off = pe.rva_to_offset(dir_rva)?;
        let end = off.checked_add(dir_size as usize)?.min(raw.len());
        while off + 28 <= end {
            let debug_type = read_u32(raw, off + 12);
            let size_of_data = read_u32(raw, off + 16) as usize;
            let ptr_to_raw = read_u32(raw, off + 24) as usize;
            if debug_type == IMAGE_DEBUG_TYPE_CODEVIEW && ptr_to_raw + size_of_data <= raw.len() {
                if let Some(info) = parse_rsds(&raw[ptr_to_raw..ptr_to_raw + size_of_data]) {
                    return Some(info);
                }
            }
            off += 28;
        }
        None
    }

    fn parse_rsds(raw: &[u8]) -> Option<CodeViewInfo> {
        if raw.len() < 24 || &raw[..4] != b"RSDS" {
            return None;
        }

        let guid = format!(
            "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
            raw[7], raw[6], raw[5], raw[4],
            raw[9], raw[8],
            raw[11], raw[10],
            raw[12], raw[13], raw[14], raw[15], raw[16], raw[17], raw[18], raw[19],
        );
        let age = read_u32(raw, 20);
        let pdb_full = cstr_from_bytes(&raw[24..]);
        let pdb_name = Path::new(&pdb_full)
            .file_name()?
            .to_string_lossy()
            .into_owned();
        Some(CodeViewInfo {
            pdb_name,
            guid_age: format!("{}{}", guid, age),
        })
    }

    fn cstr_from_bytes(raw: &[u8]) -> String {
        let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        String::from_utf8_lossy(&raw[..end]).into_owned()
    }

    fn effective_symbol_server(sym_server: &str) -> String {
        let candidate = if sym_server.is_empty() {
            DEFAULT_MS_SYMBOL_SERVER
        } else {
            sym_server
        };
        if candidate.starts_with("http://") || candidate.starts_with("https://") {
            candidate.to_owned()
        } else if let Some(url) = candidate.rsplit('*').next() {
            if url.starts_with("http://") || url.starts_with("https://") {
                url.to_owned()
            } else {
                String::new()
            }
        } else {
            String::new()
        }
    }

    fn candidate_symbol_urls(server: &str, pdb_name: &str, guid_age: &str) -> Vec<String> {
        let mut servers = Vec::new();
        push_unique(&mut servers, server.trim_end_matches('/').to_owned());
        if let Some(http) = msdl_http_variant(server) {
            push_unique(&mut servers, http);
        }
        servers
            .into_iter()
            .map(|base| format!("{}/{}/{}/{}", base, pdb_name, guid_age, pdb_name))
            .collect()
    }

    fn temp_download_path(final_path: &Path) -> PathBuf {
        let mut out = final_path.to_path_buf();
        let ext = final_path
            .extension()
            .and_then(|s| s.to_str())
            .unwrap_or_default();
        if ext.is_empty() {
            out.set_extension("download");
        } else {
            out.set_extension(format!("{}.download", ext));
        }
        out
    }

    fn download_to_file(url: &str, path: &Path) -> Result<(), String> {
        let url_w = wide_null(url);
        let path_w = wide_null(&path.to_string_lossy());
        let hr = unsafe {
            URLDownloadToFileW(
                std::ptr::null_mut(),
                url_w.as_ptr(),
                path_w.as_ptr(),
                0,
                std::ptr::null_mut(),
            )
        };
        if hr == S_OK {
            return Ok(());
        }

        download_via_powershell(url, path).map_err(|ps_err| {
            format!(
                "URLDownloadToFileW failed with HRESULT 0x{:08X}; PowerShell fallback failed: {}",
                hr as u32, ps_err
            )
        })
    }

    fn download_via_powershell(url: &str, path: &Path) -> Result<(), String> {
        let path_str = path.to_string_lossy();
        let script = format!(
            "$ProgressPreference='SilentlyContinue'; Invoke-WebRequest -Uri '{}' -OutFile '{}'",
            ps_single_quote(url),
            ps_single_quote(&path_str),
        );
        let output = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-Command",
                &script,
            ])
            .output()
            .map_err(|e| format!("spawn powershell: {}", e))?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let detail = if !stderr.is_empty() { stderr } else { stdout };
            Err(if detail.is_empty() {
                format!("exit code {}", output.status)
            } else {
                detail
            })
        }
    }

    fn wide_null(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    fn ps_single_quote(s: &str) -> String {
        s.replace('\'', "''")
    }

    fn msdl_http_variant(server: &str) -> Option<String> {
        if server.contains("msdl.microsoft.com/download/symbols") {
            Some("http://msdl.microsoft.com/download/symbols".to_owned())
        } else {
            None
        }
    }

    fn push_unique(entries: &mut Vec<String>, value: String) {
        if !value.is_empty()
            && !entries
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&value))
        {
            entries.push(value);
        }
    }

    fn build_search_path(
        dll_path: &str,
        sym_path: &str,
        sym_server: &str,
        pdb_path: &str,
    ) -> String {
        let mut local_entries = Vec::new();
        let mut server_entries = Vec::new();
        let mut seen = HashSet::new();

        let cache_dir = default_symbol_cache_dir();
        let default_server = if sym_server.is_empty() {
            DEFAULT_MS_SYMBOL_SERVER.to_owned()
        } else {
            sym_server.to_owned()
        };

        if !pdb_path.is_empty() {
            if let Some(dir) = Path::new(pdb_path).parent() {
                push_entry(
                    &mut local_entries,
                    &mut seen,
                    dir.to_string_lossy().into_owned(),
                );
            }
        }

        if let Some(dir) = Path::new(dll_path).parent() {
            push_entry(
                &mut local_entries,
                &mut seen,
                dir.to_string_lossy().into_owned(),
            );
        }

        for raw in [
            sym_path,
            &std::env::var("_NT_SYMBOL_PATH").unwrap_or_default(),
            &std::env::var("_NT_ALT_SYMBOL_PATH").unwrap_or_default(),
        ] {
            for token in raw.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                if is_server_entry(token) {
                    push_entry(&mut server_entries, &mut seen, token.to_owned());
                } else {
                    push_entry(&mut local_entries, &mut seen, token.to_owned());
                }
            }
        }

        if !cache_dir.is_empty() {
            let _ = std::fs::create_dir_all(&cache_dir);
            push_entry(&mut local_entries, &mut seen, cache_dir.clone());
        }

        if !default_server.is_empty() {
            let default_server_entry = format!("srv*{}*{}", cache_dir, default_server);
            if !server_entries
                .iter()
                .any(|entry| entry.contains(&default_server))
            {
                push_entry(&mut server_entries, &mut seen, default_server_entry);
            }
        }

        local_entries.extend(server_entries);
        local_entries.join(";")
    }

    fn default_symbol_cache_dir() -> String {
        if let Ok(path) = std::env::var("RESX_SYMBOL_CACHE") {
            let trimmed = path.trim();
            if !trimmed.is_empty() {
                return trimmed.to_owned();
            }
        }

        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            let trimmed = local_app_data.trim();
            if !trimmed.is_empty() {
                return Path::new(trimmed)
                    .join("resx")
                    .join("symbols")
                    .to_string_lossy()
                    .into_owned();
            }
        }

        if let Ok(temp) = std::env::var("TEMP") {
            let trimmed = temp.trim();
            if !trimmed.is_empty() {
                return Path::new(trimmed)
                    .join("resx")
                    .join("symbols")
                    .to_string_lossy()
                    .into_owned();
            }
        }

        r"C:\Symbols".to_owned()
    }

    fn is_server_entry(entry: &str) -> bool {
        let lower = entry.to_ascii_lowercase();
        lower.contains("srv*")
            || lower.contains("symsrv")
            || lower.starts_with("http://")
            || lower.starts_with("https://")
    }

    fn push_entry(entries: &mut Vec<String>, seen: &mut HashSet<String>, value: String) {
        if seen.insert(value.to_ascii_lowercase()) {
            entries.push(value);
        }
    }
}

#[cfg(windows)]
pub use win::{load_pdb_symbol, load_pdb_symbols, load_pdb_types, PdbSymbol, PdbTypeInfo};

#[cfg(not(windows))]
pub fn load_pdb_symbol(
    _dll_path: &str,
    _func_name: &str,
    _sym_path: &str,
    _sym_server: &str,
    _pdb_path: &str,
    _image_base: u64,
    _verbose: bool,
    _reload: bool,
) -> Option<u32> {
    None
}

#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub struct PdbSymbol {
    pub name: String,
    pub rva: u32,
    pub va: u64,
    pub kind: String,
    pub type_id: u32,
    pub type_name: String,
    pub size: u64,
}

#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub struct PdbTypeMember {
    pub name: String,
    pub offset: u64,
    pub type_id: u32,
    pub type_name: String,
    pub kind: String,
    pub size: u64,
}

#[cfg(not(windows))]
#[derive(Debug, Clone)]
pub struct PdbTypeInfo {
    pub type_id: u32,
    pub name: String,
    pub kind: String,
    pub size: u64,
    pub members: Vec<PdbTypeMember>,
}

#[cfg(not(windows))]
pub fn load_pdb_symbols(
    _dll_path: &str,
    _sym_path: &str,
    _sym_server: &str,
    _pdb_path: &str,
    _verbose: bool,
    _reload: bool,
) -> Result<Vec<PdbSymbol>, String> {
    Err("PDB symbol enumeration is only supported on Windows".to_owned())
}

#[cfg(not(windows))]
pub fn load_pdb_types(
    _dll_path: &str,
    _sym_path: &str,
    _sym_server: &str,
    _pdb_path: &str,
    _verbose: bool,
    _reload: bool,
) -> Result<Vec<PdbTypeInfo>, String> {
    Err("PDB type enumeration is only supported on Windows".to_owned())
}
