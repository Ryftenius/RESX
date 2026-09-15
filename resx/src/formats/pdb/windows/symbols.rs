use super::*;

pub(super) fn tag_name(tag: u32) -> &'static str {
    match tag {
        SYM_TAG_FUNCTION => "function",
        SYM_TAG_DATA => "data",
        SYM_TAG_PUBLIC => "public",
        _ => "symbol",
    }
}

pub(super) unsafe fn log_loaded_module(
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

pub(super) fn c_buf_to_string(buf: &[u8]) -> String {
    let end = buf.iter().position(|byte| *byte == 0).unwrap_or(buf.len());
    String::from_utf8_lossy(&buf[..end]).trim().to_owned()
}

pub(super) fn sym_type_name(sym_type: u32) -> &'static str {
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

pub(super) fn resolve_pdb_path(
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

pub(super) fn ensure_exact_pdb_cached(
    dll_path: &str,
    sym_server: &str,
    verbose: bool,
    reload: bool,
) -> Result<Option<String>, String> {
    let raw = std::fs::read(dll_path).map_err(|e| format!("read image for debug info: {}", e))?;
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

pub(super) struct CodeViewInfo {
    pdb_name: String,
    guid_age: String,
}

pub(super) fn extract_codeview_info(
    pe: &crate::formats::pe::PeFile,
    raw: &[u8],
) -> Option<CodeViewInfo> {
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

pub(super) fn parse_rsds(raw: &[u8]) -> Option<CodeViewInfo> {
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

pub(super) fn cstr_from_bytes(raw: &[u8]) -> String {
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

pub(super) fn effective_symbol_server(sym_server: &str) -> String {
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

pub(super) fn candidate_symbol_urls(server: &str, pdb_name: &str, guid_age: &str) -> Vec<String> {
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

pub(super) fn temp_download_path(final_path: &Path) -> PathBuf {
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

pub(super) fn download_to_file(url: &str, path: &Path) -> Result<(), String> {
    let url_w = wide_null(url);
    let path_w = wide_null(&path.to_string_lossy());
    // SAFETY: both UTF-16 buffers are NUL terminated and remain live for the synchronous call.
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

pub(super) fn download_via_powershell(url: &str, path: &Path) -> Result<(), String> {
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

pub(super) fn wide_null(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(super) fn ps_single_quote(s: &str) -> String {
    s.replace('\'', "''")
}

pub(super) fn msdl_http_variant(server: &str) -> Option<String> {
    if server.contains("msdl.microsoft.com/download/symbols") {
        Some("http://msdl.microsoft.com/download/symbols".to_owned())
    } else {
        None
    }
}

pub(super) fn push_unique(entries: &mut Vec<String>, value: String) {
    if !value.is_empty()
        && !entries
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(&value))
    {
        entries.push(value);
    }
}

pub(super) fn build_search_path(
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

pub(super) fn default_symbol_cache_dir() -> String {
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

pub(super) fn is_server_entry(entry: &str) -> bool {
    let lower = entry.to_ascii_lowercase();
    lower.contains("srv*")
        || lower.contains("symsrv")
        || lower.starts_with("http://")
        || lower.starts_with("https://")
}

pub(super) fn push_entry(entries: &mut Vec<String>, seen: &mut HashSet<String>, value: String) {
    if seen.insert(value.to_ascii_lowercase()) {
        entries.push(value);
    }
}
