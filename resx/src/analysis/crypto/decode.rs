//! Explicit local AES-CBC decryption using the OS crypto provider.
//! Keys are supplied by the operator; no process or credential scanning occurs.
#[cfg(windows)]
pub fn aes_cbc(input: &[u8], key: &[u8], iv: &[u8], padding: bool) -> Result<Vec<u8>, String> {
    use std::ffi::c_void;
    type Handle = *mut c_void;
    #[link(name = "bcrypt")]
    unsafe extern "system" {
        fn BCryptOpenAlgorithmProvider(
            handle: *mut Handle,
            algorithm: *const u16,
            provider: *const u16,
            flags: u32,
        ) -> i32;
        fn BCryptSetProperty(
            handle: Handle,
            name: *const u16,
            value: *const u8,
            length: u32,
            flags: u32,
        ) -> i32;
        fn BCryptGenerateSymmetricKey(
            algorithm: Handle,
            key: *mut Handle,
            object: *mut u8,
            object_length: u32,
            secret: *const u8,
            secret_length: u32,
            flags: u32,
        ) -> i32;
        fn BCryptDecrypt(
            key: Handle,
            input: *const u8,
            length: u32,
            padding: *mut c_void,
            iv: *mut u8,
            iv_length: u32,
            output: *mut u8,
            capacity: u32,
            written: *mut u32,
            flags: u32,
        ) -> i32;
        fn BCryptDestroyKey(key: Handle) -> i32;
        fn BCryptCloseAlgorithmProvider(algorithm: Handle, flags: u32) -> i32;
    }
    struct Owned(Handle, bool);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: `Owned` is constructed only from a successful CNG handle creation call.
            unsafe {
                if self.1 {
                    BCryptDestroyKey(self.0);
                } else {
                    BCryptCloseAlgorithmProvider(self.0, 0);
                }
            }
        }
    }
    fn check(status: i32) -> Result<(), String> {
        if status < 0 {
            Err(format!(
                "AES provider operation failed: 0x{:08X}",
                status as u32
            ))
        } else {
            Ok(())
        }
    }
    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain([0]).collect()
    }
    if !matches!(key.len(), 16 | 24 | 32) || iv.len() != 16 {
        return Err("AES-CBC requires a 16/24/32-byte key and a 16-byte IV".into());
    }
    if input.len() > crate::analysis::codec::MAX_OUTPUT
        || !input.len().is_multiple_of(16)
        || (padding && input.is_empty())
    {
        return Err("AES-CBC input must contain complete blocks within 16 MiB".into());
    }
    let mut algorithm = std::ptr::null_mut();
    // SAFETY: the output pointer is valid and the UTF-16 algorithm name is NUL terminated.
    check(unsafe {
        BCryptOpenAlgorithmProvider(&mut algorithm, wide("AES").as_ptr(), std::ptr::null(), 0)
    })?;
    let algorithm = Owned(algorithm, false);
    let mode = wide("ChainingModeCBC");
    // SAFETY: the algorithm handle is live and both property buffers remain valid for the call.
    check(unsafe {
        BCryptSetProperty(
            algorithm.0,
            wide("ChainingMode").as_ptr(),
            mode.as_ptr().cast(),
            (mode.len() * 2) as u32,
            0,
        )
    })?;
    let mut key_handle = std::ptr::null_mut();
    // SAFETY: the algorithm handle and key slice are valid and their bounded lengths fit `u32`.
    check(unsafe {
        BCryptGenerateSymmetricKey(
            algorithm.0,
            &mut key_handle,
            std::ptr::null_mut(),
            0,
            key.as_ptr(),
            key.len() as u32,
            0,
        )
    })?;
    let key_handle = Owned(key_handle, true);
    let mut mutable_iv = iv.to_vec();
    let mut result = vec![0; input.len() + 16];
    let mut written = 0;
    // SAFETY: all input/output buffers are live for the call and capacities match the supplied lengths.
    check(unsafe {
        BCryptDecrypt(
            key_handle.0,
            input.as_ptr(),
            input.len() as u32,
            std::ptr::null_mut(),
            mutable_iv.as_mut_ptr(),
            16,
            result.as_mut_ptr(),
            result.len() as u32,
            &mut written,
            u32::from(padding),
        )
    })?;
    if written as usize > input.len() {
        return Err("AES provider returned an invalid output extent".into());
    }
    result.truncate(written as usize);
    Ok(result)
}

#[cfg(not(windows))]
pub fn aes_cbc(_: &[u8], _: &[u8], _: &[u8], _: bool) -> Result<Vec<u8>, String> {
    Err("AES-CBC decoding requires the Windows CNG backend".into())
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn cbc_known_answer_and_invalid_parameters() {
        let hex = |s: &str| crate::analysis::codec::decode("hex", s.as_bytes()).unwrap();
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let iv = hex("000102030405060708090a0b0c0d0e0f");
        let ciphertext = hex("7649abac8119b246cee98e9b12e9197d");
        assert_eq!(
            aes_cbc(&ciphertext, &key, &iv, false).unwrap(),
            hex("6bc1bee22e409f96e93d7e117393172a")
        );
        assert!(aes_cbc(&ciphertext[..15], &key, &iv, false).is_err());
        assert!(aes_cbc(&ciphertext, &key[..15], &iv, false).is_err());
        assert!(aes_cbc(&ciphertext, &key, &iv[..15], false).is_err());
    }
}
