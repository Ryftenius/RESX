//! Small reviewed native hashing boundary. Callers receive an owned digest string.

#[cfg(windows)]
pub fn sha256(bytes: &[u8]) -> Result<String, String> {
    use std::ffi::c_void;

    if bytes.len() > u32::MAX as usize {
        return Err("SHA256 input exceeds the Windows CNG call limit".into());
    }

    #[link(name = "bcrypt")]
    extern "system" {
        fn BCryptOpenAlgorithmProvider(
            handle: *mut *mut c_void,
            id: *const u16,
            implementation: *const u16,
            flags: u32,
        ) -> i32;
        fn BCryptHash(
            handle: *mut c_void,
            secret: *const u8,
            secret_size: u32,
            input: *const u8,
            input_size: u32,
            output: *mut u8,
            output_size: u32,
        ) -> i32;
        fn BCryptCloseAlgorithmProvider(handle: *mut c_void, flags: u32) -> i32;
    }

    let mut handle = std::ptr::null_mut();
    let name: Vec<u16> = "SHA256\0".encode_utf16().collect();
    // SAFETY: `handle` and `name` are valid for the call; the implementation pointer is optional.
    if unsafe { BCryptOpenAlgorithmProvider(&mut handle, name.as_ptr(), std::ptr::null(), 0) } < 0 {
        return Err("SHA256 provider unavailable".into());
    }

    let mut digest = [0u8; 32];
    // SAFETY: CNG reads exactly `bytes.len()` bytes and writes into the 32-byte digest buffer.
    let status = unsafe {
        BCryptHash(
            handle,
            std::ptr::null(),
            0,
            bytes.as_ptr(),
            bytes.len() as u32,
            digest.as_mut_ptr(),
            digest.len() as u32,
        )
    };
    // SAFETY: `handle` came from a successful BCryptOpenAlgorithmProvider call.
    unsafe {
        BCryptCloseAlgorithmProvider(handle, 0);
    }
    if status < 0 {
        return Err("SHA256 failed".into());
    }
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(not(windows))]
pub fn sha256(_: &[u8]) -> Result<String, String> {
    Err("Windows CNG hashing requires Windows".into())
}
