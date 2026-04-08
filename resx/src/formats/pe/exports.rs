use std::collections::HashSet;

use super::constants::IMAGE_DIRECTORY_ENTRY_EXPORT;
use super::types::{read_cstr, read_u16, read_u32, Export, PeFile};

pub fn read_exports(pe: &PeFile, raw: &[u8]) -> Vec<Export> {
    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if dir_rva == 0 {
        return Vec::new();
    }

    let off = match pe.rva_to_offset(dir_rva) {
        Some(o) => o,
        None => return Vec::new(),
    };
    if off + 40 > raw.len() {
        return Vec::new();
    }

    let base = read_u32(raw, off + 16);
    let num_funcs = read_u32(raw, off + 20) as usize;
    let num_names = read_u32(raw, off + 24) as usize;
    let addr_funcs = read_u32(raw, off + 28);
    let addr_names = read_u32(raw, off + 32);
    let addr_ords = read_u32(raw, off + 36);

    let funcs_off = match pe.rva_to_offset(addr_funcs) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let names_off = match pe.rva_to_offset(addr_names) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let ords_off = match pe.rva_to_offset(addr_ords) {
        Some(o) => o,
        None => return Vec::new(),
    };

    let mut func_rvas = vec![0u32; num_funcs];
    for (i, dst) in func_rvas.iter_mut().enumerate() {
        *dst = read_u32(raw, funcs_off + i * 4);
    }

    let mut exports = Vec::with_capacity(num_names);
    let mut name_set = HashSet::new();

    for i in 0..num_names {
        let name_rva = read_u32(raw, names_off + i * 4);
        let ord_idx = read_u16(raw, ords_off + i * 2) as usize;
        if ord_idx >= num_funcs {
            continue;
        }

        let name_off = match pe.rva_to_offset(name_rva) {
            Some(o) => o,
            None => continue,
        };
        let name = read_cstr(raw, name_off);
        let f_rva = func_rvas[ord_idx];
        let ordinal = base + ord_idx as u32;

        let forward_to = if f_rva >= dir_rva && f_rva < dir_rva + dir_size {
            pe.rva_to_offset(f_rva)
                .map(|o| read_cstr(raw, o))
                .unwrap_or_default()
        } else {
            String::new()
        };

        name_set.insert(ord_idx);
        exports.push(Export {
            name,
            ordinal,
            rva: f_rva,
            forward_to,
        });
    }

    for (i, func_rva) in func_rvas.iter().copied().enumerate().take(num_funcs) {
        if !name_set.contains(&i) && func_rva != 0 {
            exports.push(Export {
                name: format!("#{}", base + i as u32),
                ordinal: base + i as u32,
                rva: func_rva,
                forward_to: String::new(),
            });
        }
    }

    exports.sort_by_key(|e| e.ordinal);
    exports
}

pub fn attribute_to_func(rva: u32, exports: &[Export]) -> Option<&Export> {
    if exports.is_empty() {
        return None;
    }
    let idx = exports.partition_point(|e| e.rva <= rva);
    if idx == 0 {
        None
    } else {
        Some(&exports[idx - 1])
    }
}
