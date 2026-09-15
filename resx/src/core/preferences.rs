use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const REGISTRY_PATH: &str = "Software\\Ryftenius\\RESX";

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Preferences {
    pub command_style: String,
    pub entry_macro: String,
    pub rentry_macro: String,
    pub invoke_profiles: BTreeMap<String, Vec<String>>,
}

impl Default for Preferences {
    fn default() -> Self {
        Self {
            command_style: "standard".to_owned(),
            entry_macro: "entry".to_owned(),
            rentry_macro: "rentry".to_owned(),
            invoke_profiles: BTreeMap::new(),
        }
    }
}

impl Preferences {
    pub fn load() -> Self {
        let Some(text) = registry::read_string("Settings") else {
            return Self::default();
        };
        serde_json::from_str(&text).unwrap_or_default()
    }

    pub fn save(&self) -> Result<(), String> {
        validate_style(&self.command_style)?;
        validate_macro(&self.entry_macro)?;
        validate_macro(&self.rentry_macro)?;
        if self.entry_macro.eq_ignore_ascii_case(&self.rentry_macro) {
            return Err("entry and rentry macro names must differ".to_owned());
        }
        let text = serde_json::to_string(self).map_err(|error| error.to_string())?;
        registry::write_string("Settings", &text)
    }

    pub fn profile_key(image: &str, function: &str) -> String {
        format!(
            "{}|{}",
            image.to_ascii_lowercase(),
            function.to_ascii_lowercase()
        )
    }
}

pub fn validate_style(value: &str) -> Result<(), String> {
    if matches!(value.to_ascii_lowercase().as_str(), "standard" | "slash") {
        Ok(())
    } else {
        Err("command style must be standard or slash".to_owned())
    }
}

pub fn validate_macro(value: &str) -> Result<(), String> {
    if (1..=32).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        Ok(())
    } else {
        Err("macro names must be 1-32 ASCII letters, digits, '_' or '-'".to_owned())
    }
}

#[cfg(windows)]
mod registry {
    use super::REGISTRY_PATH;
    use std::ffi::c_void;

    type Hkey = *mut c_void;
    const HKEY_CURRENT_USER: Hkey = 0x8000_0001usize as Hkey;
    const KEY_QUERY_VALUE: u32 = 0x0001;
    const KEY_SET_VALUE: u32 = 0x0002;
    const REG_OPTION_NON_VOLATILE: u32 = 0;
    const REG_SZ: u32 = 1;

    #[link(name = "Advapi32")]
    unsafe extern "system" {
        fn RegOpenKeyExW(
            root: Hkey,
            subkey: *const u16,
            options: u32,
            access: u32,
            out: *mut Hkey,
        ) -> i32;
        fn RegCreateKeyExW(
            root: Hkey,
            subkey: *const u16,
            reserved: u32,
            class: *mut u16,
            options: u32,
            access: u32,
            security: *const c_void,
            out: *mut Hkey,
            disposition: *mut u32,
        ) -> i32;
        fn RegQueryValueExW(
            key: Hkey,
            name: *const u16,
            reserved: *mut u32,
            kind: *mut u32,
            data: *mut u8,
            size: *mut u32,
        ) -> i32;
        fn RegSetValueExW(
            key: Hkey,
            name: *const u16,
            reserved: u32,
            kind: u32,
            data: *const u8,
            size: u32,
        ) -> i32;
        fn RegCloseKey(key: Hkey) -> i32;
    }

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().chain(std::iter::once(0)).collect()
    }

    pub fn read_string(name: &str) -> Option<String> {
        let path = wide(REGISTRY_PATH);
        let name = wide(name);
        let mut key = std::ptr::null_mut();
        // SAFETY: both strings are NUL terminated and `key` is a valid output pointer.
        if unsafe {
            RegOpenKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                KEY_QUERY_VALUE,
                &mut key,
            )
        } != 0
        {
            return None;
        }
        let mut kind = 0u32;
        let mut size = 0u32;
        // SAFETY: the key is live and the size/type outputs are writable; no data buffer is requested.
        let first = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                std::ptr::null_mut(),
                &mut size,
            )
        };
        if first != 0 || kind != REG_SZ || !(2..=4 * 1024 * 1024).contains(&size) {
            // SAFETY: the key was opened successfully and is closed exactly once on this path.
            unsafe { RegCloseKey(key) };
            return None;
        }
        let mut bytes = vec![0u8; size as usize];
        // SAFETY: `bytes` has the queried capacity and all other pointers remain live for the call.
        let status = unsafe {
            RegQueryValueExW(
                key,
                name.as_ptr(),
                std::ptr::null_mut(),
                &mut kind,
                bytes.as_mut_ptr(),
                &mut size,
            )
        };
        // SAFETY: the key was opened successfully and is closed exactly once on this path.
        unsafe { RegCloseKey(key) };
        if status != 0 || size as usize > bytes.len() {
            return None;
        }
        let units: Vec<u16> = bytes[..size as usize]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .take_while(|unit| *unit != 0)
            .collect();
        String::from_utf16(&units).ok()
    }

    pub fn write_string(name: &str, value: &str) -> Result<(), String> {
        let path = wide(REGISTRY_PATH);
        let name = wide(name);
        let value = wide(value);
        let mut key = std::ptr::null_mut();
        let mut disposition = 0u32;
        // SAFETY: the path is NUL terminated and both output pointers refer to writable stack values.
        let status = unsafe {
            RegCreateKeyExW(
                HKEY_CURRENT_USER,
                path.as_ptr(),
                0,
                std::ptr::null_mut(),
                REG_OPTION_NON_VOLATILE,
                KEY_QUERY_VALUE | KEY_SET_VALUE,
                std::ptr::null(),
                &mut key,
                &mut disposition,
            )
        };
        if status != 0 {
            return Err(format!(
                "cannot create HKCU\\{REGISTRY_PATH}: Win32 error {status}"
            ));
        }
        let byte_len = value
            .len()
            .checked_mul(2)
            .and_then(|size| u32::try_from(size).ok())
            .ok_or_else(|| "registry value is too large".to_owned())?;
        // SAFETY: the key is live and `value` contains `byte_len` initialized UTF-16 bytes.
        let status = unsafe {
            RegSetValueExW(
                key,
                name.as_ptr(),
                0,
                REG_SZ,
                value.as_ptr().cast(),
                byte_len,
            )
        };
        // SAFETY: the key was created successfully and is closed exactly once.
        unsafe { RegCloseKey(key) };
        if status == 0 {
            Ok(())
        } else {
            Err(format!(
                "cannot write HKCU\\{REGISTRY_PATH}: Win32 error {status}"
            ))
        }
    }
}

#[cfg(not(windows))]
mod registry {
    pub fn read_string(_name: &str) -> Option<String> {
        None
    }
    pub fn write_string(_name: &str, _value: &str) -> Result<(), String> {
        Err("RESX registry preferences are available on Windows only".to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::{validate_macro, validate_style, Preferences};

    #[test]
    fn preference_validation_is_bounded() {
        assert!(validate_style("slash").is_ok());
        assert!(validate_style("wat").is_err());
        assert!(validate_macro("real_entry").is_ok());
        assert!(validate_macro("bad name").is_err());
        assert!(Preferences::profile_key("C:\\A.DLL", "Foo").ends_with("|foo"));
    }
}
