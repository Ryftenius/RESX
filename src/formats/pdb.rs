#[cfg(windows)]
mod win {
    use crate::formats::pe::{parse_pe, read_u32};
    use std::collections::HashSet;
    use std::ffi::{c_void, CStr, CString};
    use std::path::{Path, PathBuf};
    use std::slice;

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
        pub type_name: String,
        pub size: u64,
    }

    struct EnumContext {
        h_proc: *mut c_void,
        module_base: u64,
        sym_get_type_info: FnSymGetTypeInfo,
        out: *mut Vec<PdbSymbol>,
    }

    const TI_GET_SYMNAME: u32 = 1;
    const TI_GET_LENGTH: u32 = 2;
    const TI_GET_TYPEID: u32 = 4;
    const SYM_TAG_FUNCTION: u32 = 5;
    const SYM_TAG_DATA: u32 = 7;
    const SYM_TAG_PUBLIC: u32 = 10;

    pub fn load_pdb_symbol(
        dll_path: &str,
        func_name: &str,
        sym_path: &str,
        sym_server: &str,
        pdb_path: &str,
        image_base: u64,
        verbose: bool,
    ) -> Option<u32> {
        unsafe {
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

            let resolved_pdb_path = resolve_pdb_path(dll_path, sym_server, pdb_path, verbose);
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
        }
    }

    pub fn load_pdb_symbols(
        dll_path: &str,
        sym_path: &str,
        sym_server: &str,
        pdb_path: &str,
        verbose: bool,
    ) -> Result<Vec<PdbSymbol>, String> {
        unsafe {
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

            let resolved_pdb_path = resolve_pdb_path(dll_path, sym_server, pdb_path, verbose);
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
        }
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
                type_name,
                size,
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

    fn resolve_pdb_path(dll_path: &str, sym_server: &str, pdb_path: &str, verbose: bool) -> String {
        if !pdb_path.is_empty() {
            return pdb_path.to_owned();
        }

        match ensure_exact_pdb_cached(dll_path, sym_server, verbose) {
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
        if cache_path.is_file() {
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
pub use win::{load_pdb_symbol, load_pdb_symbols, PdbSymbol};

#[cfg(not(windows))]
pub fn load_pdb_symbol(
    _dll_path: &str,
    _func_name: &str,
    _sym_path: &str,
    _sym_server: &str,
    _pdb_path: &str,
    _image_base: u64,
    _verbose: bool,
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
    pub type_name: String,
    pub size: u64,
}

#[cfg(not(windows))]
pub fn load_pdb_symbols(
    _dll_path: &str,
    _sym_path: &str,
    _sym_server: &str,
    _pdb_path: &str,
    _verbose: bool,
) -> Result<Vec<PdbSymbol>, String> {
    Err("PDB symbol enumeration is only supported on Windows".to_owned())
}
