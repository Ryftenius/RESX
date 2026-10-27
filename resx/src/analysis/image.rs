//! Shared facts for one immutable image. No file lookup, configuration or rendering.
//!
//! Callers own the bytes and the PE parsed from those bytes. The borrow keeps both
//! unchanged for this session, so cached results need no process-wide identity key.

use std::collections::HashMap;
use std::sync::OnceLock;

use crate::formats::pe::{
    self, Export, ImportDll, PeFile, PeLoadConfigInfo, PeRuntimeFunctionInfo, PeTlsInfo,
};

pub struct ImageFacts<'a> {
    pe: &'a PeFile,
    raw: &'a [u8],
    imports: OnceLock<Vec<ImportDll>>,
    import_slots: OnceLock<HashMap<u32, (usize, usize)>>,
    exports: OnceLock<Vec<Export>>,
    runtime_functions: OnceLock<Vec<PeRuntimeFunctionInfo>>,
    tls: OnceLock<Option<PeTlsInfo>>,
    load_config: OnceLock<Option<PeLoadConfigInfo>>,
}

impl<'a> ImageFacts<'a> {
    /// `pe` must describe `raw`, as returned by `formats::pe::parse_pe(raw)`.
    /// Construction performs no analysis; each result is computed on first use.
    pub fn new(pe: &'a PeFile, raw: &'a [u8]) -> Self {
        Self {
            pe,
            raw,
            imports: OnceLock::new(),
            import_slots: OnceLock::new(),
            exports: OnceLock::new(),
            runtime_functions: OnceLock::new(),
            tls: OnceLock::new(),
            load_config: OnceLock::new(),
        }
    }

    pub fn pe(&self) -> &PeFile {
        self.pe
    }

    pub fn raw(&self) -> &[u8] {
        self.raw
    }

    pub fn imports(&self) -> &[ImportDll] {
        self.imports
            .get_or_init(|| pe::read_imports(self.pe, self.raw))
    }

    /// Preserve the parser's first-match rule for overlapping/malformed IAT slots.
    pub fn import_at_rva(&self, rva: u32) -> Option<(&str, &str)> {
        let slots = self.import_slots.get_or_init(|| {
            let mut slots = HashMap::new();
            for (dll_index, dll) in self.imports().iter().enumerate() {
                for (entry_index, entry) in dll.entries.iter().enumerate() {
                    slots
                        .entry(entry.slot_rva)
                        .or_insert((dll_index, entry_index));
                }
            }
            slots
        });
        let &(dll_index, entry_index) = slots.get(&rva)?;
        let dll = &self.imports()[dll_index];
        Some((&dll.dll, &dll.entries[entry_index].name))
    }

    pub fn exports(&self) -> &[Export] {
        self.exports
            .get_or_init(|| pe::read_exports(self.pe, self.raw))
    }

    pub fn runtime_functions(&self) -> &[PeRuntimeFunctionInfo] {
        self.runtime_functions
            .get_or_init(|| pe::read_runtime_functions(self.pe, self.raw))
    }

    pub fn tls(&self) -> Option<&PeTlsInfo> {
        self.tls
            .get_or_init(|| pe::read_tls_info(self.pe, self.raw))
            .as_ref()
    }

    pub fn load_config(&self) -> Option<&PeLoadConfigInfo> {
        self.load_config
            .get_or_init(|| pe::read_load_config(self.pe, self.raw))
            .as_ref()
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::formats::pe::{PeSection, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ};
    pub(crate) fn image() -> PeFile {
        PeFile {
            arch: 64,
            machine: 0x8664,
            timestamp: 0,
            coff_characteristics: 0x2022,
            major_linker_version: 0,
            minor_linker_version: 0,
            image_base: 0x180000000,
            entry_point: 0x1000,
            size_of_image: 0x3000,
            size_of_headers: 0x200,
            section_alignment: 0x1000,
            file_alignment: 0x200,
            checksum: 0,
            subsystem: 3,
            dll_characteristics: 0,
            sections: vec![PeSection {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x1000,
                raw_offset: 0x200,
                raw_size: 0x200,
                characteristics: IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
                entropy: 0.0,
            }],
            data_dirs: vec![(0, 0); 16],
            anomalies: Vec::new(),
        }
    }

    pub(crate) fn imported_image() -> (PeFile, Vec<u8>) {
        let mut pe = image();
        let mut raw = vec![0; 0x400];
        pe.data_dirs[pe::IMAGE_DIRECTORY_ENTRY_IMPORT] = (0x1100, 40);
        raw[0x300..0x304].copy_from_slice(&0x1140u32.to_le_bytes());
        raw[0x30c..0x310].copy_from_slice(&0x1180u32.to_le_bytes());
        raw[0x310..0x314].copy_from_slice(&0x1160u32.to_le_bytes());
        raw[0x340..0x348].copy_from_slice(&0x11a0u64.to_le_bytes());
        raw[0x360..0x368].copy_from_slice(&0x11a0u64.to_le_bytes());
        raw[0x380..0x38d].copy_from_slice(b"KERNEL32.dll\0");
        raw[0x3a2..0x3a8].copy_from_slice(b"Sleep\0");
        (pe, raw)
    }

    #[test]
    fn import_lookup_is_lazy_and_preserves_first_match() {
        let (pe, raw) = imported_image();
        let facts = ImageFacts::new(&pe, &raw);
        assert!(facts.imports.get().is_none());
        let mut imports = pe::read_imports(&pe, &raw);
        assert_eq!(imports.len(), 1);
        let mut duplicate = imports[0].clone();
        duplicate.dll = "duplicate.dll".into();
        imports.push(duplicate);
        facts.imports.set(imports).unwrap();
        assert_eq!(facts.import_at_rva(0x1160), Some(("KERNEL32.dll", "Sleep")));
        assert_eq!(facts.import_at_rva(0x1168), None);
        assert!(facts.exports.get().is_none());
        assert!(facts.runtime_functions.get().is_none());
        assert!(facts.tls.get().is_none());
        assert!(facts.load_config.get().is_none());
    }

    #[test]
    fn indexed_imports_match_parser_lookup() {
        let (pe, raw) = imported_image();
        let facts = ImageFacts::new(&pe, &raw);
        for rva in [0, 0x115f, 0x1160, 0x1161, 0x1168, u32::MAX] {
            let indexed = facts
                .import_at_rva(rva)
                .map(|(dll, name)| (dll.to_owned(), name.to_owned()));
            assert_eq!(indexed, pe::resolve_iat_slot(&pe, &raw, rva));
        }
    }
}
