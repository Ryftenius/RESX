use std::collections::HashSet;

use super::constants::IMAGE_DIRECTORY_ENTRY_EXPORT;
use super::types::{read_u16, read_u32, Export, PeFile, MAX_PE_ENTRIES};

pub fn read_exports(pe: &PeFile, raw: &[u8]) -> Vec<Export> {
    let (dir_rva, dir_size) = pe.data_dir(IMAGE_DIRECTORY_ENTRY_EXPORT);
    if dir_rva == 0 {
        return Vec::new();
    }

    let header = match pe.rva_slice(raw, dir_rva, 40).filter(|_| dir_size >= 40) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let off = 0;

    let base = read_u32(header, off + 16);
    let num_funcs = read_u32(header, off + 20) as usize;
    let num_names = read_u32(header, off + 24) as usize;
    if num_funcs > MAX_PE_ENTRIES
        || num_names > MAX_PE_ENTRIES
        || base.checked_add(num_funcs as u32).is_none()
    {
        return Vec::new();
    }
    let addr_funcs = read_u32(header, off + 28);
    let addr_names = read_u32(header, off + 32);
    let addr_ords = read_u32(header, off + 36);

    let funcs = match pe.rva_slice(raw, addr_funcs, num_funcs * 4) {
        Some(o) => o,
        None => return Vec::new(),
    };
    let names = match if num_names == 0 {
        Some(&[][..])
    } else {
        pe.rva_slice(raw, addr_names, num_names * 4)
    } {
        Some(o) => o,
        None => return Vec::new(),
    };
    let ords = match if num_names == 0 {
        Some(&[][..])
    } else {
        pe.rva_slice(raw, addr_ords, num_names * 2)
    } {
        Some(o) => o,
        None => return Vec::new(),
    };

    let mut func_rvas = vec![0u32; num_funcs];
    for (i, dst) in func_rvas.iter_mut().enumerate() {
        *dst = read_u32(funcs, i * 4);
    }

    let mut exports = Vec::with_capacity(num_names);
    let mut name_set = HashSet::new();
    let mut string_budget = 4 * 1024 * 1024usize;
    let forward = |rva: u32| -> String {
        if rva >= dir_rva && u64::from(rva) < u64::from(dir_rva) + u64::from(dir_size) {
            let remaining = (u64::from(dir_rva) + u64::from(dir_size) - u64::from(rva)) as usize;
            pe.rva_slice(raw, rva, remaining)
                .and_then(|bytes| super::types::read_cstr_checked(bytes, 0, 4096))
                .unwrap_or_default()
        } else {
            String::new()
        }
    };

    for i in 0..num_names {
        let name_rva = read_u32(names, i * 4);
        let ord_idx = read_u16(ords, i * 2) as usize;
        if ord_idx >= num_funcs {
            continue;
        }

        let Some(name) = pe.rva_string(raw, name_rva).filter(|s| !s.is_empty()) else {
            continue;
        };
        let Some(budget) = string_budget.checked_sub(name.len()) else {
            break;
        };
        string_budget = budget;
        let f_rva = func_rvas[ord_idx];
        if f_rva == 0 || pe.image_base.checked_add(u64::from(f_rva)).is_none() {
            continue;
        }
        let ordinal = base + ord_idx as u32;

        let forward_to = forward(f_rva);
        let Some(budget) = string_budget.checked_sub(forward_to.len()) else {
            break;
        };
        string_budget = budget;

        name_set.insert(ord_idx);
        exports.push(Export {
            name,
            ordinal,
            rva: f_rva,
            forward_to,
        });
    }

    for (i, func_rva) in func_rvas.iter().copied().enumerate().take(num_funcs) {
        if !name_set.contains(&i)
            && func_rva != 0
            && pe.image_base.checked_add(u64::from(func_rva)).is_some()
        {
            let forward_to = forward(func_rva);
            let Some(budget) = string_budget.checked_sub(forward_to.len() + 16) else {
                break;
            };
            string_budget = budget;
            exports.push(Export {
                name: format!("#{}", base + i as u32),
                ordinal: base + i as u32,
                rva: func_rva,
                forward_to,
            });
        }
    }

    exports.sort_by_key(|e| e.ordinal);
    exports
}

pub fn attribute_to_func(rva: u32, exports: &[Export]) -> Option<&Export> {
    exports
        .iter()
        .filter(|e| e.rva != 0 && e.rva <= rva)
        .max_by_key(|e| e.rva)
}

/// Export locations sorted by RVA for repeated ownership queries. The original
/// export order is retained as a tie breaker: predecessor lookup chooses the
/// last export at an RVA, while successor lookup chooses the first.
#[derive(Debug, Clone)]
pub struct ExportOwnerIndex {
    positions: Vec<usize>,
}

impl ExportOwnerIndex {
    pub fn new(exports: &[Export]) -> Self {
        let mut positions: Vec<usize> = (0..exports.len())
            .filter(|&index| exports[index].rva != 0)
            .collect();
        positions.sort_by_key(|&index| (exports[index].rva, index));
        Self { positions }
    }

    pub fn at_or_before<'a>(&self, exports: &'a [Export], rva: u32) -> Option<&'a Export> {
        let end = self
            .positions
            .partition_point(|&index| exports[index].rva <= rva);
        end.checked_sub(1)
            .map(|index| &exports[self.positions[index]])
    }

    pub fn first_in_range<'a>(
        &self,
        exports: &'a [Export],
        begin: u32,
        end: u32,
    ) -> Option<&'a Export> {
        let index = self
            .positions
            .partition_point(|&index| exports[index].rva < begin);
        self.positions
            .get(index)
            .map(|&position| &exports[position])
            .filter(|export| export.rva < end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn export(name: &str, ordinal: u32, rva: u32) -> Export {
        Export {
            name: name.to_owned(),
            ordinal,
            rva,
            forward_to: String::new(),
        }
    }

    #[test]
    fn attribute_to_func_uses_nearest_rva_not_ordinal_order() {
        let exports = vec![
            export("OrdinalLowRvaHigh", 1, 0x3000),
            export("OrdinalMidRvaLow", 2, 0x1000),
            export("OrdinalHighRvaMid", 3, 0x2000),
        ];

        let owner = attribute_to_func(0x2100, &exports).expect("owner");

        assert_eq!(owner.name, "OrdinalHighRvaMid");
    }

    #[test]
    fn export_owner_index_preserves_predecessor_and_range_ties() {
        let exports = vec![
            export("zero", 1, 0),
            export("high", 2, 0x3000),
            export("first-mid", 3, 0x2000),
            export("low", 4, 0x1000),
            export("last-mid", 5, 0x2000),
        ];
        let index = ExportOwnerIndex::new(&exports);
        for rva in [0, 0xfff, 0x1000, 0x1fff, 0x2000, 0x2fff, 0x3000] {
            assert_eq!(
                index.at_or_before(&exports, rva).map(|e| e.name.as_str()),
                attribute_to_func(rva, &exports).map(|e| e.name.as_str()),
                "rva 0x{rva:X}"
            );
        }
        assert_eq!(
            index
                .first_in_range(&exports, 0x2000, 0x3000)
                .map(|e| e.name.as_str()),
            Some("first-mid")
        );
        assert_eq!(
            index
                .first_in_range(&exports, 0x1001, 0x2001)
                .map(|e| e.name.as_str()),
            Some("first-mid")
        );
        assert!(index.first_in_range(&exports, 0x3001, 0x4000).is_none());
    }
}
