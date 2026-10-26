//! Optional, bounded local-device metadata and open-access observation.
use crate::analysis::driver::devices::LiveSecurity;

pub(super) fn observe(image: &std::path::Path, endpoint: &str) -> LiveSecurity {
    let result = (|| {
        normalize(endpoint)?;
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut child = std::process::Command::new(exe);
        child.arg("ioctl").arg(image).args([
            "--device-security",
            endpoint,
            "--device-security-worker",
            "--json",
            "--quiet",
            "--no-pdb",
        ]);
        let output = crate::core::process::capture(
            &mut child,
            std::time::Duration::from_secs(15),
            256 * 1024,
        )?;
        if !output.status.success() {
            return Err(format!("Device-security worker failed: {}", output.status));
        }
        let report: LiveSecurity = serde_json::from_slice(&output.stdout)
            .map_err(|e| format!("Invalid device-security response: {e}"))?;
        if report.requested_path != endpoint
            || report.user_open_probes.len() > 4
            || report.matched_endpoint_ids.len() > 64
        {
            return Err("Device-security response failed bounds/identity validation".into());
        }
        Ok(report)
    })();
    result.unwrap_or_else(|error| LiveSecurity {
        requested_path: endpoint.into(),
        error: Some(error),
        ..Default::default()
    })
}

fn normalize(path: &str) -> Result<String, String> {
    if path.len() > 2048 || path.chars().any(char::is_control) {
        return Err("Device path is empty, too long or contains control characters".into());
    }
    let lower = path.to_ascii_lowercase();
    let result = if lower.starts_with("\\device\\") {
        format!("\\\\?\\GLOBALROOT{path}")
    } else if lower.starts_with("\\\\.\\") || lower.starts_with("\\\\?\\globalroot\\device\\") {
        path.to_owned()
    } else {
        return Err("Use a local \\Device\\... or \\\\.\\... device path; UNC/network paths are not supported".into());
    };
    let lower = result.to_ascii_lowercase();
    if lower.ends_with('\\')
        || path
            .strip_prefix("\\\\.\\")
            .unwrap_or(path)
            .split('\\')
            .any(|part| part == "." || part == "..")
        || path
            .strip_prefix("\\\\.\\")
            .is_some_and(|alias| alias.is_empty() || alias.contains('\\'))
        || lower.contains("\\mup\\")
        || lower.ends_with("\\mup")
        || lower.contains("lanmanredirector")
        || lower.contains("webdavredirector")
        || lower.starts_with("\\\\.\\unc\\")
    {
        return Err("A specific local device endpoint is required".into());
    }
    Ok(result)
}

pub(super) fn query(endpoint: &str) -> LiveSecurity {
    let mut result=LiveSecurity {requested_path:endpoint.into(),descriptor_source:"Security descriptor of the opened endpoint handle; not a kernel DEVICE_OBJECT memory read".into(),..Default::default()};
    match normalize(endpoint) {
        Ok(path) => result.opened_path = path,
        Err(error) => {
            result.error = Some(error);
            return result;
        }
    }
    #[cfg(windows)]
    windows::query(&mut result);
    #[cfg(not(windows))]
    {
        result.error = Some("Live device security requires Windows".into());
    }
    result.limitations.extend([
        "No IOCTL is sent. Open results concern the tested token and requested access bits only; driver dispatch checks and IOCTL success remain untested.".into(),
        "SDDL can come from an endpoint's query-security implementation. A denied or unsupported query is unknown security, not a permissive DACL.".into(),
    ]);
    result
}

#[cfg(windows)]
mod windows {
    use super::*;
    use crate::analysis::driver::devices::OpenProbe;
    use std::{
        ffi::c_void,
        ptr::{null, null_mut},
    };
    type Handle = *mut c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *const c_void,
            creation: u32,
            flags: u32,
            template: Handle,
        ) -> Handle;
        fn CloseHandle(handle: Handle) -> i32;
        fn GetCurrentProcess() -> Handle;
        fn GetLastError() -> u32;
        fn LocalFree(memory: Handle) -> Handle;
        fn QueryDosDeviceW(name: *const u16, target: *mut u16, length: u32) -> u32;
    }
    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn OpenProcessToken(process: Handle, access: u32, token: *mut Handle) -> i32;
        fn GetTokenInformation(
            token: Handle,
            class: u32,
            buffer: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
        fn DuplicateToken(token: Handle, level: u32, new_token: *mut Handle) -> i32;
        fn ImpersonateLoggedOnUser(token: Handle) -> i32;
        fn RevertToSelf() -> i32;
        fn ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text: *const u16,
            revision: u32,
            sd: *mut Handle,
            size: *mut u32,
        ) -> i32;
        fn AccessCheck(
            sd: *const c_void,
            token: Handle,
            desired: u32,
            mapping: *mut GenericMapping,
            privileges: *mut c_void,
            privilege_length: *mut u32,
            granted: *mut u32,
            status: *mut i32,
        ) -> i32;
        fn ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd: *const c_void,
            revision: u32,
            information: u32,
            text: *mut *mut u16,
            length: *mut u32,
        ) -> i32;
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn RtlValidRelativeSecurityDescriptor(sd: *const c_void, length: u32, required: u32) -> u8;
        fn NtQueryObject(
            handle: Handle,
            class: u32,
            buffer: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
        fn NtQuerySecurityObject(
            handle: Handle,
            information: u32,
            buffer: *mut c_void,
            length: u32,
            returned: *mut u32,
        ) -> i32;
    }
    #[repr(C)]
    struct GenericMapping {
        read: u32,
        write: u32,
        execute: u32,
        all: u32,
    }
    fn dacl_probes(report: &mut LiveSecurity, token: Handle) {
        let Some(sddl) = report.sddl.as_deref() else {
            return;
        };
        let sddl = wide(sddl);
        let mut sd = null_mut();
        let mut size = 0;
        // SAFETY: sddl is NUL-terminated; sd and size are writable output slots.
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                1,
                &mut sd,
                &mut size,
            )
        } == 0
        {
            return;
        }
        for access in [0, 1, 2, 3] {
            if access == 0 {
                report.user_open_probes.push(OpenProbe {
                    access,
                    opened: None,
                    dacl_allowed: None,
                    win32_error: None,
                });
                continue;
            }
            let mut mapping = GenericMapping {
                read: 0x120089,
                write: 0x120116,
                execute: 0x1200a0,
                all: 0x1f01ff,
            };
            let mut privileges = [0u64; 512];
            let mut length = 4096;
            let mut granted = 0;
            let mut status = 0;
            // SAFETY: sd is API-owned, token is live, and all output buffers have the declared sizes.
            let okay = unsafe {
                AccessCheck(
                    sd,
                    token,
                    access,
                    &mut mapping,
                    privileges.as_mut_ptr().cast(),
                    &mut length,
                    &mut granted,
                    &mut status,
                )
            };
            report.user_open_probes.push(OpenProbe {
                access,
                opened: None,
                dacl_allowed: (okay != 0).then_some(status != 0),
                win32_error: (okay == 0).then(last_error),
            });
        }
        // SAFETY: sd was allocated by the successful conversion and is no longer used.
        unsafe {
            LocalFree(sd);
        }
        report.limitations.push("These are DACL-only AccessCheck results for the real linked token, not successful device opens. Mandatory integrity, driver create policy and zero-access opens remain untested.".into());
    }
    struct Owned(Handle);
    impl Drop for Owned {
        fn drop(&mut self) {
            // SAFETY: Owned uniquely holds a successful API handle, never a pseudo-handle.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
    struct Impersonation;
    impl Drop for Impersonation {
        fn drop(&mut self) {
            // SAFETY: the guard exists only after successful impersonation on this worker thread.
            unsafe {
                RevertToSelf();
            }
        }
    }
    fn last_error() -> u32 {
        // SAFETY: GetLastError reads only this thread's error state.
        unsafe { GetLastError() }
    }
    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(Some(0)).collect()
    }
    fn open(path: &[u16], access: u32) -> Result<Owned, u32> {
        // OPEN_EXISTING, sharing read/write/delete, asynchronous handle: no
        // implicit synchronous-I/O access requirement and no data operation.
        // SAFETY: path is a live NUL-terminated UTF-16 buffer; optional pointers are null.
        let handle =
            unsafe { CreateFileW(path.as_ptr(), access, 7, null(), 3, 0x40000000, null_mut()) };
        if handle as isize == -1 {
            Err(last_error())
        } else {
            Ok(Owned(handle))
        }
    }
    fn scalar(token: Handle, class: u32) -> Option<u32> {
        let mut value = 0u32;
        let mut returned = 0;
        // SAFETY: token is live; value and returned are writable u32 slots with matching lengths.
        (unsafe {
            GetTokenInformation(
                token,
                class,
                (&mut value as *mut u32).cast(),
                4,
                &mut returned,
            )
        } != 0
            && returned == 4)
            .then_some(value)
    }
    fn integrity(token: Handle) -> Option<u32> {
        let mut buffer = [0u64; 64];
        let mut returned = 0;
        // SAFETY: the aligned buffer provides exactly the 512 bytes passed to the API.
        if unsafe { GetTokenInformation(token, 25, buffer.as_mut_ptr().cast(), 512, &mut returned) }
            == 0
            || !(16..=512).contains(&returned)
        {
            return None;
        }
        let base = buffer.as_ptr() as usize;
        let sid = buffer[0] as usize;
        if sid < base || sid.checked_add(8)? > base + returned as usize {
            return None;
        }
        // SID header and subauthority bytes are validated within this returned
        // buffer before reading the mandatory-integrity RID.
        // SAFETY: returned was checked against the size of this initialized buffer.
        let bytes =
            unsafe { std::slice::from_raw_parts(buffer.as_ptr().cast::<u8>(), returned as usize) };
        let offset = sid - base;
        let count = bytes[offset + 1] as usize;
        if bytes[offset] != 1 || count == 0 || count > 15 {
            return None;
        }
        let end = offset.checked_add(8 + 4 * count)?;
        Some(u32::from_le_bytes(
            bytes.get(end - 4..end)?.try_into().ok()?,
        ))
    }
    fn object_name(handle: Handle) -> Option<String> {
        let mut data = vec![0u64; 8192];
        let mut returned = 0;
        // SAFETY: handle is owned and data is an aligned 64 KiB writable buffer.
        if unsafe { NtQueryObject(handle, 1, data.as_mut_ptr().cast(), 65536, &mut returned) } < 0
            || !(16..=65536).contains(&returned)
        {
            return None;
        }
        // SAFETY: returned is within the allocated buffer; bytes have alignment one.
        let raw =
            unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), returned as usize) };
        let len = u16::from_le_bytes(raw[0..2].try_into().ok()?) as usize;
        let max = u16::from_le_bytes(raw[2..4].try_into().ok()?) as usize;
        let pointer = u64::from_le_bytes(raw[8..16].try_into().ok()?) as usize;
        let offset = pointer.checked_sub(data.as_ptr() as usize)?;
        if len > max || len > 32768 || !len.is_multiple_of(2) {
            return None;
        }
        let text = raw.get(offset..offset.checked_add(len)?)?;
        String::from_utf16(
            &text
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| u16::from_le_bytes([p[0], p[1]]))
                .collect::<Vec<_>>(),
        )
        .ok()
    }
    fn descriptor(handle: Handle) -> Result<String, String> {
        let mut data = vec![0u64; 8192];
        let mut returned = 0;
        // OWNER, GROUP and DACL. Audit SACL and mandatory-label policy are not
        // inferred from their absence in this deliberately limited query.
        // SAFETY: handle is live; data is an aligned 64 KiB writable buffer.
        let status = unsafe {
            NtQuerySecurityObject(handle, 7, data.as_mut_ptr().cast(), 65536, &mut returned)
        };
        if status < 0 {
            return Err(format!("Security query NTSTATUS 0x{:08X}", status as u32));
        }
        if !(20..=65536).contains(&returned) {
            return Err("Invalid security descriptor size".into());
        }
        // SAFETY: the length-aware validator receives only the returned, bounded byte span.
        if unsafe { RtlValidRelativeSecurityDescriptor(data.as_ptr().cast(), returned, 7) } == 0 {
            return Err("Invalid security descriptor".into());
        }
        let mut text = null_mut();
        let mut length = 0;
        // SAFETY: the relative descriptor passed length-aware validation; outputs are writable.
        if unsafe {
            ConvertSecurityDescriptorToStringSecurityDescriptorW(
                data.as_ptr().cast(),
                1,
                7,
                &mut text,
                &mut length,
            )
        } == 0
        {
            return Err(format!("SDDL conversion error {}", last_error()));
        }
        let result = if !text.is_null() && length > 0 && length <= 32768 {
            // SAFETY: the successful conversion owns length UTF-16 units until LocalFree.
            String::from_utf16(
                unsafe { std::slice::from_raw_parts(text, length as usize) }
                    .split(|c| *c == 0)
                    .next()
                    .unwrap_or_default(),
            )
            .map_err(|_| "Invalid SDDL text".into())
        } else {
            Err("SDDL exceeds output bounds".into())
        };
        if !text.is_null() {
            // SAFETY: text is the allocation returned by the conversion and has not been freed.
            unsafe {
                LocalFree(text.cast());
            }
        }
        result
    }
    pub(super) fn query(report: &mut LiveSecurity) {
        if cfg!(target_pointer_width = "32") {
            report.error = Some("Live device security currently requires Windows x64".into());
            return;
        }
        let path = wide(&report.opened_path);
        if let Some(alias) = report
            .requested_path
            .strip_prefix("\\\\.\\")
            .filter(|s| !s.contains('\\'))
        {
            let alias = wide(alias);
            let mut target = vec![0u16; 32768];
            // SAFETY: alias is terminated and target has the declared writable UTF-16 capacity.
            let n = unsafe {
                QueryDosDeviceW(alias.as_ptr(), target.as_mut_ptr(), target.len() as u32)
            };
            if n > 0 && n <= target.len() as u32 {
                report.dos_target = String::from_utf16(
                    target[..n as usize]
                        .split(|c| *c == 0)
                        .next()
                        .unwrap_or_default(),
                )
                .ok();
            }
        }
        if report
            .dos_target
            .as_deref()
            .is_some_and(|target| normalize(target).is_err())
        {
            report.error =
                Some("DOS alias does not resolve to an accepted local device endpoint".into());
            return;
        }
        match open(&path, 0x20000) {
            Ok(handle) => {
                report.object_name = object_name(handle.0);
                match descriptor(handle.0) {
                    Ok(s) => report.sddl = Some(s),
                    Err(e) => report.error = Some(e),
                };
            }
            Err(error) => report.error = Some(format!("READ_CONTROL open failed: Win32 {error}")),
        }
        report.limitations.push("Only owner/group/DACL are queried; audit SACL and integrity labels are not included in this SDDL. Actual open probes use Windows access checks.".into());
        let mut current = null_mut();
        // SAFETY: the current-process pseudo-handle is valid; current is a writable handle slot.
        if unsafe { OpenProcessToken(GetCurrentProcess(), 0x000a, &mut current) } == 0 {
            report
                .limitations
                .push(format!("Token query failed: {}", last_error()));
            return;
        }
        let current = Owned(current);
        let elevated = scalar(current.0, 20);
        let mut linked: Handle = null_mut();
        let mut returned = 0;
        let linked = if elevated == Some(1)
            // SAFETY: current is live; linked has pointer-sized storage and returned is writable.
            && unsafe {
                GetTokenInformation(
                    current.0,
                    19,
                    (&mut linked as *mut Handle).cast(),
                    std::mem::size_of::<Handle>() as u32,
                    &mut returned,
                )
            } != 0
            && !linked.is_null()
        {
            Some(Owned(linked))
        } else {
            None
        };
        let token = linked.as_ref().unwrap_or(&current);
        report.token = if linked.is_some() {
            "linked non-elevated token of the current account"
        } else {
            "current process token"
        }
        .into();
        report.token_elevated = scalar(token.0, 20).map(|n| n != 0);
        report.token_integrity_rid = integrity(token.0);
        if report.token_elevated != Some(false)
            || report.token_integrity_rid.is_none_or(|rid| rid > 0x2000)
        {
            report.limitations.push("A non-elevated token at medium integrity or lower was unavailable; standard-user accessibility is unknown.".into());
            return;
        }
        if scalar(token.0, 8) == Some(2) && scalar(token.0, 9).is_some_and(|level| level < 2) {
            dacl_probes(report, token.0);
            return;
        }
        let mut impersonation = null_mut();
        // SAFETY: token is live and impersonation is a writable handle output slot.
        if unsafe { DuplicateToken(token.0, 2, &mut impersonation) } == 0 {
            let error = last_error();
            dacl_probes(report, token.0);
            report
                .limitations
                .push(format!("Cannot duplicate test token: {error}"));
            return;
        }
        let impersonation = Owned(impersonation);
        // SAFETY: the duplicated token remains owned until after the revert guard runs.
        if unsafe { ImpersonateLoggedOnUser(impersonation.0) } == 0 {
            report
                .limitations
                .push(format!("Cannot impersonate test token: {}", last_error()));
            return;
        }
        let _restore = Impersonation;
        for access in [0, 1, 2, 3] {
            match open(&path, access) {
                Ok(handle) => {
                    if report.object_name.is_none() {
                        report.object_name = object_name(handle.0);
                    }
                    report.user_open_probes.push(OpenProbe {
                        access,
                        opened: Some(true),
                        dacl_allowed: None,
                        win32_error: None,
                    });
                }
                Err(error) => report.user_open_probes.push(OpenProbe {
                    access,
                    opened: Some(false),
                    dacl_allowed: None,
                    win32_error: Some(error),
                }),
            }
        }
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn dacl_evaluation_distinguishes_allow_deny_and_unperformed_opens() {
            let mut process_token = null_mut();
            // SAFETY: current process is valid and output slots own pointer-sized writable storage.
            let opened =
                unsafe { OpenProcessToken(GetCurrentProcess(), 0x000a, &mut process_token) };
            assert_ne!(opened, 0);
            let process_token = Owned(process_token);
            let mut token = null_mut();
            // SAFETY: process_token is live and token is a writable handle output.
            assert_ne!(unsafe { DuplicateToken(process_token.0, 1, &mut token) }, 0);
            let token = Owned(token);
            let mut report = LiveSecurity {
                sddl: Some("O:SYG:SYD:(D;;0x2;;;WD)(A;;0x1;;;WD)".into()),
                ..Default::default()
            };
            dacl_probes(&mut report, token.0);
            assert_eq!(
                report
                    .user_open_probes
                    .iter()
                    .map(|p| p.dacl_allowed)
                    .collect::<Vec<_>>(),
                [None, Some(true), Some(false), Some(false)]
            );
            assert!(report
                .user_open_probes
                .iter()
                .all(|p| p.opened.is_none() && p.win32_error.is_none()));
        }
        #[test]
        fn relative_descriptor_validator_rejects_out_of_buffer_offsets() {
            let mut data = [0u32; 5];
            data[0] = 0x80000001; // revision 1, self-relative, no components
            data[1] = 0xfffffff0; // owner outside returned bytes
                                  // SAFETY: the length-aware validator receives a live aligned 20-byte buffer.
            let valid = unsafe { RtlValidRelativeSecurityDescriptor(data.as_ptr().cast(), 20, 7) };
            assert_eq!(valid, 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_explicit_local_device_paths_are_accepted() {
        assert_eq!(
            normalize("\\Device\\Null").unwrap(),
            "\\\\?\\GLOBALROOT\\Device\\Null"
        );
        assert!(normalize("\\\\.\\Example").is_ok());
        for path in [
            "",
            "C:\\x",
            "\\\\host\\share",
            "\\\\.\\UNC\\host\\share",
            "\\Device\\Mup\\host\\share",
            "\\\\.\\foo\0bar",
            "\\\\.\\MappedShare\\file",
            "\\Device\\Null\\..\\Mup",
        ] {
            assert!(normalize(path).is_err(), "{path:?}");
        }
    }
}
