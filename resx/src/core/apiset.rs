//! API set contract resolution (`api-ms-win-*`, `ext-ms-*` to a host DLL) from the
//! local `apisetschema.dll`. Schema version 6 (Windows 10 and later) is supported;
//! other versions resolve nothing. Every offset is bounds-checked.

use std::collections::HashMap;
use std::sync::OnceLock;

/// Lowercase contract name without its final `-N` version component, to host DLL.
type Schema = HashMap<String, String>;

static SCHEMA: OnceLock<Schema> = OnceLock::new();

/// Whether `name` is an API set contract rather than a file.
pub fn is_contract(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.starts_with("api-") || lower.starts_with("ext-")
}

/// The DLL that hosts the API set contract `name` (with or without `.dll`), when the
/// local schema maps it to one.
pub fn host_for(name: &str) -> Option<String> {
    if !is_contract(name) {
        return None;
    }
    let schema = SCHEMA.get_or_init(load_system_schema);
    let key = contract_key(name)?;
    schema.get(&key).cloned()
}

/// `api-ms-win-core-registry-l1-1-0.dll` -> `api-ms-win-core-registry-l1-1`: schema
/// entries match up to the final hyphen.
fn contract_key(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let stem = lower.strip_suffix(".dll").unwrap_or(&lower);
    let cut = stem.rfind('-')?;
    Some(stem[..cut].to_owned())
}

fn load_system_schema() -> Schema {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let path = std::path::Path::new(&root)
        .join("System32")
        .join("apisetschema.dll");
    let Ok(raw) = crate::core::input::read_image(&path) else {
        return Schema::new();
    };
    let Ok(pe) = crate::formats::pe::parse_pe(&raw) else {
        return Schema::new();
    };
    pe.sections
        .iter()
        .find(|s| s.name.trim_end_matches('\0') == ".apiset")
        .and_then(|s| {
            let start = s.raw_offset as usize;
            raw.get(start..start.checked_add(s.raw_size as usize)?)
        })
        .map(parse_schema)
        .unwrap_or_default()
}

fn u32_at(data: &[u8], offset: usize) -> Option<u32> {
    let bytes = data.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn utf16_at(data: &[u8], offset: u32, length: u32) -> Option<String> {
    let start = offset as usize;
    let bytes = data.get(start..start.checked_add(length as usize)?)?;
    if bytes.len() % 2 != 0 || bytes.len() > 1024 {
        return None;
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect();
    String::from_utf16(&units).ok()
}

/// Parse a version 6 `API_SET_NAMESPACE`. The default (unconditional) host of each
/// contract is its last value entry with no importing-module name.
pub(crate) fn parse_schema(data: &[u8]) -> Schema {
    const ENTRY_SIZE: usize = 24;
    const VALUE_SIZE: usize = 20;
    const MAX_ENTRIES: u32 = 65_536;
    let mut schema = Schema::new();
    if u32_at(data, 0) != Some(6) {
        return schema;
    }
    let (Some(count), Some(entry_offset)) = (u32_at(data, 12), u32_at(data, 16)) else {
        return schema;
    };
    for index in 0..count.min(MAX_ENTRIES) as usize {
        let Some(entry) = index
            .checked_mul(ENTRY_SIZE)
            .and_then(|o| o.checked_add(entry_offset as usize))
        else {
            break;
        };
        let (Some(name_offset), Some(name_length), Some(hashed_length)) = (
            u32_at(data, entry + 4),
            u32_at(data, entry + 8),
            u32_at(data, entry + 12),
        ) else {
            break;
        };
        let (Some(value_offset), Some(value_count)) =
            (u32_at(data, entry + 16), u32_at(data, entry + 20))
        else {
            break;
        };
        // The hashed length covers the name up to its final hyphen.
        let Some(name) = utf16_at(data, name_offset, hashed_length.min(name_length)) else {
            continue;
        };
        let mut host = None;
        for value in 0..value_count.min(64) as usize {
            let Some(at) = value
                .checked_mul(VALUE_SIZE)
                .and_then(|o| o.checked_add(value_offset as usize))
            else {
                break;
            };
            let (Some(importer_length), Some(host_offset), Some(host_length)) = (
                u32_at(data, at + 8),
                u32_at(data, at + 12),
                u32_at(data, at + 16),
            ) else {
                break;
            };
            if importer_length == 0 && host_length > 0 {
                host = utf16_at(data, host_offset, host_length);
            }
        }
        if let Some(host) = host.filter(|h| crate::core::input::is_safe_basename(h)) {
            schema.insert(name.to_ascii_lowercase(), host);
        }
    }
    schema
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(s: &str) -> Vec<u8> {
        s.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    /// A one-entry version 6 schema mapping `api-ms-win-core-registry-l1-1` to
    /// `kernelbase.dll`.
    fn sample() -> Vec<u8> {
        let name = utf16("api-ms-win-core-registry-l1-1-0");
        let hashed = utf16("api-ms-win-core-registry-l1-1").len() as u32;
        let host = utf16("kernelbase.dll");
        let header = 28usize;
        let entry_at = header;
        let value_at = entry_at + 24;
        let name_at = value_at + 20;
        let host_at = name_at + name.len();
        let mut data = vec![0u8; host_at + host.len()];
        let put = |data: &mut Vec<u8>, at: usize, v: u32| {
            data[at..at + 4].copy_from_slice(&v.to_le_bytes())
        };
        put(&mut data, 0, 6);
        put(&mut data, 12, 1);
        put(&mut data, 16, entry_at as u32);
        put(&mut data, entry_at + 4, name_at as u32);
        put(&mut data, entry_at + 8, name.len() as u32);
        put(&mut data, entry_at + 12, hashed);
        put(&mut data, entry_at + 16, value_at as u32);
        put(&mut data, entry_at + 20, 1);
        put(&mut data, value_at + 12, host_at as u32);
        put(&mut data, value_at + 16, host.len() as u32);
        data[name_at..name_at + name.len()].copy_from_slice(&name);
        data[host_at..].copy_from_slice(&host);
        data
    }

    #[test]
    fn parses_a_v6_schema_and_keys_by_contract_without_its_last_version() {
        let schema = parse_schema(&sample());
        let key = contract_key("API-MS-WIN-CORE-REGISTRY-L1-1-0.dll").unwrap();
        assert_eq!(schema.get(&key).map(String::as_str), Some("kernelbase.dll"));
    }

    #[test]
    fn hostile_schemas_resolve_nothing_instead_of_panicking() {
        let mut data = sample();
        assert!(parse_schema(&data[..10]).is_empty());
        data[0] = 2;
        assert!(parse_schema(&data).is_empty());
        let mut huge = sample();
        huge[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
        huge[24 + 28 + 4..24 + 28 + 8].copy_from_slice(&u32::MAX.to_le_bytes());
        let _ = parse_schema(&huge);
    }

    #[test]
    fn only_contract_names_are_looked_up() {
        assert!(is_contract("api-ms-win-core-synch-l1-2-0.dll"));
        assert!(is_contract("ext-ms-win-ntuser-window-l1-1-0"));
        assert!(!is_contract("kernel32.dll"));
        assert!(host_for("kernel32.dll").is_none());
    }
}
