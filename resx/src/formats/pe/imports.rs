use super::constants::IMAGE_DIRECTORY_ENTRY_IMPORT;
use super::types::{read_cstr, read_u16, read_u32, read_u64, ImportDll, ImportEntry, PeFile};
use std::collections::HashMap;

pub fn read_imports(pe: &PeFile, raw: &[u8]) -> Vec<ImportDll> {
    let (dir_rva, _) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if dir_rva == 0 {
        return Vec::new();
    }

    let mut off = match pe.rva_to_offset(dir_rva) {
        Some(o) => o,
        None => return Vec::new(),
    };

    let mut dlls = Vec::new();
    loop {
        if off + 20 > raw.len() {
            break;
        }
        let ilt_rva = read_u32(raw, off);
        let name_rva = read_u32(raw, off + 12);
        let iat_rva = read_u32(raw, off + 16);
        off += 20;

        if name_rva == 0 && ilt_rva == 0 {
            break;
        }

        let name_off = match pe.rva_to_offset(name_rva) {
            Some(o) => o,
            None => continue,
        };
        let dll_name = read_cstr(raw, name_off);
        let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let mut thunk_off = match pe.rva_to_offset(thunk_rva) {
            Some(o) => o,
            None => continue,
        };

        let ord_flag_64 = 1u64 << 63;
        let ord_flag_32 = 1u64 << 31;
        let name_mask = if pe.arch == 64 {
            ord_flag_64 - 1
        } else {
            ord_flag_32 - 1
        };
        let mut entries = Vec::new();
        let mut slot_idx = 0u32;

        loop {
            let thunk = if pe.arch == 64 {
                let v = read_u64(raw, thunk_off);
                thunk_off += 8;
                v
            } else {
                let v = read_u32(raw, thunk_off) as u64;
                thunk_off += 4;
                v
            };
            if thunk == 0 {
                break;
            }

            let is_ord = (pe.arch == 64 && thunk & ord_flag_64 != 0)
                || (pe.arch == 32 && thunk & ord_flag_32 != 0);

            if is_ord {
                let ord = (thunk & 0xFFFF) as u16;
                entries.push(ImportEntry {
                    name: format!("#{}", ord),
                    ordinal: ord,
                    hint: 0,
                    by_ord: true,
                    slot_rva: iat_rva + slot_idx * if pe.arch == 64 { 8 } else { 4 },
                });
            } else {
                let hint_rva = (thunk & name_mask) as u32;
                let hint_off = match pe.rva_to_offset(hint_rva) {
                    Some(o) => o,
                    None => break,
                };
                let hint = read_u16(raw, hint_off);
                let name = read_cstr(raw, hint_off + 2);
                entries.push(ImportEntry {
                    name,
                    ordinal: 0,
                    hint,
                    by_ord: false,
                    slot_rva: iat_rva + slot_idx * if pe.arch == 64 { 8 } else { 4 },
                });
            }
            slot_idx += 1;
        }

        dlls.push(ImportDll {
            dll: dll_name,
            entries,
        });
    }

    dlls
}

pub fn resolve_iat_slot(pe: &PeFile, raw: &[u8], slot_rva: u32) -> Option<(String, String)> {
    let (dir_rva, _) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if dir_rva == 0 {
        return None;
    }

    let mut off = pe.rva_to_offset(dir_rva)?;
    let ptr_size = if pe.arch == 64 { 8u32 } else { 4u32 };
    let ord_flag_64 = 1u64 << 63;
    let ord_flag_32 = 1u64 << 31;
    let name_mask = if pe.arch == 64 {
        ord_flag_64 - 1
    } else {
        ord_flag_32 - 1
    };

    loop {
        if off + 20 > raw.len() {
            break;
        }
        let ilt_rva = read_u32(raw, off);
        let name_rva = read_u32(raw, off + 12);
        let iat_rva = read_u32(raw, off + 16);
        off += 20;

        if name_rva == 0 && ilt_rva == 0 {
            break;
        }
        if iat_rva == 0 || slot_rva < iat_rva {
            continue;
        }

        let name_off = match pe.rva_to_offset(name_rva) {
            Some(o) => o,
            None => continue,
        };
        let dll_name = read_cstr(raw, name_off);
        let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let mut ilt_off = match pe.rva_to_offset(thunk_rva) {
            Some(o) => o,
            None => continue,
        };

        let mut slot_idx = 0u32;
        loop {
            let thunk = if pe.arch == 64 {
                let v = read_u64(raw, ilt_off);
                ilt_off += 8;
                v
            } else {
                let v = read_u32(raw, ilt_off) as u64;
                ilt_off += 4;
                v
            };
            if thunk == 0 {
                break;
            }

            let this_slot_rva = iat_rva + slot_idx * ptr_size;
            if this_slot_rva == slot_rva {
                let is_ord = (pe.arch == 64 && thunk & ord_flag_64 != 0)
                    || (pe.arch == 32 && thunk & ord_flag_32 != 0);
                let func_name = if is_ord {
                    format!("#{}", thunk & 0xFFFF)
                } else {
                    let hint_rva = (thunk & name_mask) as u32;
                    match pe.rva_to_offset(hint_rva) {
                        Some(ho) => read_cstr(raw, ho + 2),
                        None => format!("ord_{}", thunk & 0xFFFF),
                    }
                };
                return Some((dll_name, func_name));
            }
            slot_idx += 1;
        }
    }
    None
}

pub fn import_slot_map_by_va(pe: &PeFile, raw: &[u8]) -> HashMap<u64, (String, String)> {
    let mut slots = HashMap::new();
    for dll in read_imports(pe, raw) {
        let dll_base = normalize_dll_base(&dll.dll);
        for entry in dll.entries {
            slots.insert(
                pe.image_base + entry.slot_rva as u64,
                (dll_base.clone(), entry.name),
            );
        }
    }
    slots
}

fn normalize_dll_base(path_or_name: &str) -> String {
    path_or_name
        .rsplit(&['/', '\\'][..])
        .next()
        .unwrap_or(path_or_name)
        .trim_end_matches(".dll")
        .trim_end_matches(".DLL")
        .to_lowercase()
}

pub fn find_iat_slots_by_name(
    pe: &PeFile,
    raw: &[u8],
    target_name: &str,
) -> Vec<(u32, String, String)> {
    let (dir_rva, _) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_IMPORT);
    if dir_rva == 0 {
        return Vec::new();
    }

    let mut out = Vec::new();
    let mut off = match pe.rva_to_offset(dir_rva) {
        Some(v) => v,
        None => return out,
    };
    let ptr_size = if pe.arch == 64 { 8u32 } else { 4u32 };
    let ord_flag_64 = 1u64 << 63;
    let ord_flag_32 = 1u64 << 31;
    let name_mask = if pe.arch == 64 {
        ord_flag_64 - 1
    } else {
        ord_flag_32 - 1
    };
    let want = target_name.trim().to_ascii_lowercase();

    loop {
        if off + 20 > raw.len() {
            break;
        }
        let ilt_rva = read_u32(raw, off);
        let name_rva = read_u32(raw, off + 12);
        let iat_rva = read_u32(raw, off + 16);
        off += 20;

        if name_rva == 0 && ilt_rva == 0 {
            break;
        }
        if iat_rva == 0 {
            continue;
        }

        let name_off = match pe.rva_to_offset(name_rva) {
            Some(o) => o,
            None => continue,
        };
        let dll_name = read_cstr(raw, name_off);
        let thunk_rva = if ilt_rva != 0 { ilt_rva } else { iat_rva };
        let mut ilt_off = match pe.rva_to_offset(thunk_rva) {
            Some(o) => o,
            None => continue,
        };

        let mut slot_idx = 0u32;
        loop {
            let thunk = if pe.arch == 64 {
                let v = read_u64(raw, ilt_off);
                ilt_off += 8;
                v
            } else {
                let v = read_u32(raw, ilt_off) as u64;
                ilt_off += 4;
                v
            };
            if thunk == 0 {
                break;
            }

            let is_ord = (pe.arch == 64 && thunk & ord_flag_64 != 0)
                || (pe.arch == 32 && thunk & ord_flag_32 != 0);
            let func_name = if is_ord {
                format!("#{}", thunk & 0xFFFF)
            } else {
                let hint_rva = (thunk & name_mask) as u32;
                match pe.rva_to_offset(hint_rva) {
                    Some(ho) => read_cstr(raw, ho + 2),
                    None => format!("ord_{}", thunk & 0xFFFF),
                }
            };

            if func_name.eq_ignore_ascii_case(&want) {
                let slot_rva = iat_rva + slot_idx * ptr_size;
                out.push((slot_rva, dll_name.clone(), func_name));
            }
            slot_idx += 1;
        }
    }

    out
}
