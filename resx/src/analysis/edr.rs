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
#[path = "runtime_memory.rs"]
mod win;

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
