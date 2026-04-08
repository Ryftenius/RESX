#[derive(Debug, Clone)]
pub struct EdrCheckResult {
    pub loaded_from_memory: bool,
    pub in_memory_available: bool,
    pub blocked_by_policy: bool,
    pub compared_len: usize,
    pub modified: bool,
    pub disk_bytes: Vec<u8>,
    pub memory_bytes: Vec<u8>,
    pub diff_offsets: Vec<usize>,
}

#[cfg(windows)]
mod win {
    use std::ffi::{c_void, OsStr};
    use std::os::windows::ffi::OsStrExt;

    use super::EdrCheckResult;

    #[link(name = "kernel32")]
    extern "system" {
        fn GetModuleHandleW(lpModuleName: *const u16) -> *mut c_void;
        fn LoadLibraryExW(
            lpLibFileName: *const u16,
            hFile: *mut c_void,
            dwFlags: u32,
        ) -> *mut c_void;
        fn FreeLibrary(hLibModule: *mut c_void) -> i32;
    }

    const DONT_RESOLVE_DLL_REFERENCES: u32 = 0x00000001;

    pub fn check_prologue(
        dll_path: &str,
        target_rva: u32,
        disk_bytes: &[u8],
        compare_len: usize,
        allow_image_mapping: bool,
    ) -> Result<EdrCheckResult, String> {
        if compare_len == 0 || disk_bytes.is_empty() {
            return Ok(EdrCheckResult {
                loaded_from_memory: false,
                in_memory_available: false,
                blocked_by_policy: false,
                compared_len: 0,
                modified: false,
                disk_bytes: Vec::new(),
                memory_bytes: Vec::new(),
                diff_offsets: Vec::new(),
            });
        }

        let wide = to_wide(dll_path);
        let mut loaded_from_memory = false;
        let mut should_free = false;
        let mut module = unsafe { GetModuleHandleW(wide.as_ptr()) };
        if module.is_null() {
            if !allow_image_mapping {
                return Ok(EdrCheckResult {
                    loaded_from_memory,
                    in_memory_available: false,
                    blocked_by_policy: true,
                    compared_len: 0,
                    modified: false,
                    disk_bytes: disk_bytes[..compare_len.min(disk_bytes.len())].to_vec(),
                    memory_bytes: Vec::new(),
                    diff_offsets: Vec::new(),
                });
            }
            module = unsafe {
                LoadLibraryExW(
                    wide.as_ptr(),
                    std::ptr::null_mut(),
                    DONT_RESOLVE_DLL_REFERENCES,
                )
            };
            if module.is_null() {
                return Ok(EdrCheckResult {
                    loaded_from_memory,
                    in_memory_available: false,
                    blocked_by_policy: false,
                    compared_len: 0,
                    modified: false,
                    disk_bytes: disk_bytes[..compare_len.min(disk_bytes.len())].to_vec(),
                    memory_bytes: Vec::new(),
                    diff_offsets: Vec::new(),
                });
            }
            loaded_from_memory = true;
            should_free = true;
        }

        let len = compare_len.min(disk_bytes.len());
        let memory_ptr = (module as usize)
            .checked_add(target_rva as usize)
            .ok_or_else(|| "in-memory RVA overflow".to_owned())?
            as *const u8;
        let memory_bytes = unsafe { std::slice::from_raw_parts(memory_ptr, len) }.to_vec();
        let disk = disk_bytes[..len].to_vec();
        let mut diff_offsets = Vec::new();
        for idx in 0..len {
            if disk[idx] != memory_bytes[idx] {
                diff_offsets.push(idx);
            }
        }

        if should_free {
            unsafe {
                FreeLibrary(module);
            }
        }

        Ok(EdrCheckResult {
            loaded_from_memory,
            in_memory_available: true,
            blocked_by_policy: false,
            compared_len: len,
            modified: !diff_offsets.is_empty(),
            disk_bytes: disk,
            memory_bytes,
            diff_offsets,
        })
    }

    fn to_wide(s: &str) -> Vec<u16> {
        OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }
}

#[cfg(windows)]
pub use win::check_prologue;

#[cfg(not(windows))]
pub fn check_prologue(
    _dll_path: &str,
    _target_rva: u32,
    _disk_bytes: &[u8],
    _compare_len: usize,
    _allow_image_mapping: bool,
) -> Result<EdrCheckResult, String> {
    Ok(EdrCheckResult {
        loaded_from_memory: false,
        in_memory_available: false,
        blocked_by_policy: false,
        compared_len: 0,
        modified: false,
        disk_bytes: Vec::new(),
        memory_bytes: Vec::new(),
        diff_offsets: Vec::new(),
    })
}
