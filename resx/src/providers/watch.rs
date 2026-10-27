//! Nonblocking source invalidation. Unsupported sources fall back to rescanning.

use std::path::Path;

#[cfg(windows)]
pub(super) struct DirectoryWatch(isize);

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn FindFirstChangeNotificationW(
        path: *const u16,
        subtree: i32,
        filter: u32,
    ) -> *mut std::ffi::c_void;
    fn FindNextChangeNotification(handle: *mut std::ffi::c_void) -> i32;
    fn FindCloseChangeNotification(handle: *mut std::ffi::c_void) -> i32;
    fn WaitForSingleObject(handle: *mut std::ffi::c_void, milliseconds: u32) -> u32;
}

#[cfg(windows)]
impl DirectoryWatch {
    pub fn new(root: &Path) -> Option<Self> {
        use std::os::windows::ffi::OsStrExt;
        let mut path: Vec<u16> = root.as_os_str().encode_wide().collect();
        if path.contains(&0) {
            return None;
        }
        path.push(0);
        // File/directory names, size and last write. Reads do not invalidate it.
        const FILTER: u32 = 0x1 | 0x2 | 0x8 | 0x10;
        // SAFETY: path is NUL-terminated and remains alive during the call.
        let handle = unsafe { FindFirstChangeNotificationW(path.as_ptr(), 1, FILTER) } as isize;
        (handle != -1 && handle != 0).then(|| Self(handle))
    }

    /// None means notification failed; the caller must rescan from now on.
    pub fn changed(&mut self) -> Option<bool> {
        // SAFETY: this object exclusively owns a live notification handle.
        match unsafe { WaitForSingleObject(self.0 as *mut _, 0) } {
            258 => Some(false), // WAIT_TIMEOUT
            0 => {
                // Rearm before scanning, so edits during a scan remain signalled.
                // SAFETY: the handle is a live, signalled change notification.
                (unsafe { FindNextChangeNotification(self.0 as *mut _) } != 0).then_some(true)
            }
            _ => None,
        }
    }
}

#[cfg(windows)]
impl Drop for DirectoryWatch {
    fn drop(&mut self) {
        // SAFETY: this object owns the handle and closes it exactly once.
        unsafe { FindCloseChangeNotification(self.0 as *mut _) };
    }
}

#[cfg(not(windows))]
pub(super) struct DirectoryWatch;

#[cfg(not(windows))]
impl DirectoryWatch {
    pub fn new(_: &Path) -> Option<Self> {
        None
    }

    pub fn changed(&mut self) -> Option<bool> {
        None
    }
}
