//! Read only an already-loaded, reference-pinned module. Never load a target.
use super::EdrCheckResult;
use std::ffi::c_void;

#[repr(C)]
struct ModuleInfo {
    base: *mut c_void,
    size: u32,
    entry: *mut c_void,
}

#[link(name = "kernel32")]
extern "system" {
    fn GetModuleHandleExW(flags: u32, name: *const u16, module: *mut *mut c_void) -> i32;
    fn FreeLibrary(module: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn K32GetModuleInformation(
        process: *mut c_void,
        module: *mut c_void,
        info: *mut ModuleInfo,
        size: u32,
    ) -> i32;
    fn ReadProcessMemory(
        process: *mut c_void,
        address: *const c_void,
        buffer: *mut c_void,
        size: usize,
        read: *mut usize,
    ) -> i32;
}

struct PinnedModule(*mut c_void);
impl Drop for PinnedModule {
    fn drop(&mut self) {
        // SAFETY: the handle came from a successful reference-incrementing GetModuleHandleExW call.
        unsafe {
            FreeLibrary(self.0);
        }
    }
}

pub fn check_prologue(
    path: &str,
    rva: u32,
    disk_bytes: &[u8],
    compare_len: usize,
    _allow_mapping: bool,
) -> Result<EdrCheckResult, String> {
    if path.encode_utf16().any(|unit| unit == 0) {
        return Err("Embedded NUL in module path".into());
    }
    let length = compare_len.min(disk_bytes.len()).min(4096);
    let disk = disk_bytes[..length].to_vec();
    let unavailable = || EdrCheckResult {
        loaded_from_memory: false,
        in_memory_available: false,
        blocked_by_policy: true,
        compared_len: 0,
        modified: false,
        disk_bytes: disk.clone(),
        memory_bytes: Vec::new(),
        diff_offsets: Vec::new(),
    };
    if length == 0 {
        return Ok(unavailable());
    }
    let name: Vec<u16> = path.encode_utf16().chain(Some(0)).collect();
    let mut module = std::ptr::null_mut();
    // flags=0 increments the module reference count, preventing concurrent unload.
    // SAFETY: `name` is NUL terminated and `module` is a valid output pointer.
    if unsafe { GetModuleHandleExW(0, name.as_ptr(), &mut module) } == 0 {
        return Ok(unavailable());
    }
    let pinned = PinnedModule(module);
    // SAFETY: GetCurrentProcess takes no pointers and returns a process pseudo-handle.
    let process = unsafe { GetCurrentProcess() };
    let mut info = ModuleInfo {
        base: std::ptr::null_mut(),
        size: 0,
        entry: std::ptr::null_mut(),
    };
    // SAFETY: the module is pinned and `info` is a correctly sized writable structure.
    if unsafe {
        K32GetModuleInformation(
            process,
            pinned.0,
            &mut info,
            std::mem::size_of::<ModuleInfo>() as u32,
        )
    } == 0
    {
        return Err("Cannot establish mapped-module bounds".into());
    }
    if (rva as usize)
        .checked_add(length)
        .is_none_or(|end| end > info.size as usize)
    {
        return Err("Runtime read exceeds mapped-module bounds".into());
    }
    let address = (info.base as usize)
        .checked_add(rva as usize)
        .ok_or("Runtime address overflow")?;
    let mut bytes = vec![0u8; length];
    let mut read = 0;
    // SAFETY: the address range was checked against the pinned module and the destination has `length` bytes.
    if unsafe {
        ReadProcessMemory(
            process,
            address as *const c_void,
            bytes.as_mut_ptr().cast(),
            length,
            &mut read,
        )
    } == 0
        || read != length
    {
        return Err("Runtime range is not fully readable".into());
    }
    let differences: Vec<_> = disk
        .iter()
        .zip(&bytes)
        .enumerate()
        .filter_map(|(i, (a, b))| (a != b).then_some(i))
        .collect();
    Ok(EdrCheckResult {
        loaded_from_memory: false,
        in_memory_available: true,
        blocked_by_policy: false,
        compared_len: length,
        modified: !differences.is_empty(),
        disk_bytes: disk,
        memory_bytes: bytes,
        diff_offsets: differences,
    })
}
