use super::constants::IMAGE_DIRECTORY_ENTRY_IMPORT;
use super::types::{read_u16, read_u32, read_u64, ImportDll, ImportEntry, PeFile, MAX_PE_ENTRIES};
use std::collections::HashMap;

pub fn read_imports(pe: &PeFile, raw: &[u8]) -> Vec<ImportDll> {
    let (rva, size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
    let Some(directory) = pe.rva_slice(raw, rva, size as usize).filter(|_| rva != 0) else {
        return Vec::new();
    };
    let width = if pe.arch == 64 { 8usize } else { 4usize };
    let ordinal_flag = if width == 8 { 1u64 << 63 } else { 1u64 << 31 };
    let mut remaining = MAX_PE_ENTRIES;
    let mut string_budget = 4 * 1024 * 1024usize;
    let mut dlls = Vec::new();
    for descriptor in directory.as_chunks::<20>().0.iter().take(4096) {
        if remaining == 0 || string_budget == 0 {
            break;
        }
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let ilt = read_u32(descriptor, 0);
        let name_rva = read_u32(descriptor, 12);
        let iat = read_u32(descriptor, 16);
        if iat == 0 {
            continue;
        }
        let Some(name) = pe.rva_string(raw, name_rva).filter(|s| !s.is_empty()) else {
            continue;
        };
        let Some(budget) = string_budget.checked_sub(name.len()) else {
            break;
        };
        string_budget = budget;
        let Some(thunks) = pe.rva_bytes(raw, if ilt != 0 { ilt } else { iat }) else {
            continue;
        };
        let mut entries = Vec::new();
        for (index, bytes) in thunks.chunks_exact(width).take(remaining).enumerate() {
            let value = if width == 8 {
                read_u64(bytes, 0)
            } else {
                u64::from(read_u32(bytes, 0))
            };
            if value == 0 {
                break;
            }
            remaining -= 1;
            let Some(slot_rva) = u32::try_from(index * width)
                .ok()
                .and_then(|delta| iat.checked_add(delta))
            else {
                break;
            };
            if pe.rva_slice(raw, slot_rva, width).is_none() {
                break;
            }
            let by_ord = value & ordinal_flag != 0;
            let (entry_name, ordinal, hint) = if by_ord {
                let ordinal = (value & 0xffff) as u16;
                (format!("#{ordinal}"), ordinal, 0)
            } else {
                let Some(hint_rva) = u32::try_from(value).ok() else {
                    break;
                };
                let Some(hint_bytes) = pe.rva_slice(raw, hint_rva, 2) else {
                    break;
                };
                let Some(entry_name) = hint_rva
                    .checked_add(2)
                    .and_then(|rva| pe.rva_string(raw, rva))
                    .filter(|s| !s.is_empty())
                else {
                    break;
                };
                (entry_name, 0, read_u16(hint_bytes, 0))
            };
            let Some(budget) = string_budget.checked_sub(entry_name.len()) else {
                string_budget = 0;
                break;
            };
            string_budget = budget;
            entries.push(ImportEntry {
                name: entry_name,
                ordinal,
                hint,
                by_ord,
                slot_rva,
            });
        }
        dlls.push(ImportDll { dll: name, entries });
    }
    dlls
}

pub fn resolve_iat_slot(pe: &PeFile, raw: &[u8], slot_rva: u32) -> Option<(String, String)> {
    for dll in read_imports(pe, raw) {
        if let Some(entry) = dll
            .entries
            .into_iter()
            .find(|entry| entry.slot_rva == slot_rva)
        {
            return Some((dll.dll, entry.name));
        }
    }
    None
}

pub fn import_slot_map_by_rva(pe: &PeFile, raw: &[u8]) -> HashMap<u32, (String, String)> {
    let mut slots = HashMap::new();
    for dll in read_imports(pe, raw) {
        for entry in dll.entries {
            slots.insert(entry.slot_rva, (dll.dll.clone(), entry.name));
        }
    }
    slots
}

pub fn import_slot_map_by_va(pe: &PeFile, raw: &[u8]) -> HashMap<u64, (String, String)> {
    let mut slots = HashMap::new();
    for dll in read_imports(pe, raw) {
        let name = dll
            .dll
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(&dll.dll)
            .to_ascii_lowercase();
        let name = name.strip_suffix(".dll").unwrap_or(&name);
        for entry in dll.entries {
            if let Some(va) = pe.image_base.checked_add(u64::from(entry.slot_rva)) {
                slots.insert(va, (name.to_owned(), entry.name));
            }
        }
    }
    slots
}

pub fn find_iat_slots_by_name(
    pe: &PeFile,
    raw: &[u8],
    target_name: &str,
) -> Vec<(u32, String, String)> {
    let mut out = Vec::new();
    for dll in read_imports(pe, raw) {
        for entry in dll.entries {
            if entry.name.eq_ignore_ascii_case(target_name.trim()) {
                out.push((entry.slot_rva, dll.dll.clone(), entry.name));
            }
        }
    }
    out
}
