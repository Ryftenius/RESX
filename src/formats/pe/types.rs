use std::fmt;

use super::constants::{IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ, IMAGE_SCN_MEM_WRITE};

#[derive(Debug, Clone)]
pub struct PeSection {
    pub name: String,
    pub virtual_address: u32,
    pub virtual_size: u32,
    pub raw_offset: u32,
    pub raw_size: u32,
    pub characteristics: u32,
    pub entropy: f64,
}

impl PeSection {
    pub fn contains_rva(&self, rva: u32) -> bool {
        let span = self.virtual_size.max(self.raw_size);
        span != 0 && rva >= self.virtual_address && rva < self.virtual_address.saturating_add(span)
    }

    pub fn protection_string(&self) -> String {
        let mut out = String::new();
        if self.characteristics & IMAGE_SCN_MEM_READ != 0 {
            out.push('R');
        }
        if self.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
            out.push('W');
        }
        if self.characteristics & IMAGE_SCN_MEM_EXECUTE != 0 {
            out.push('X');
        }
        if out.is_empty() {
            out.push('-');
        }
        out
    }

    pub fn protection_name(&self) -> String {
        protection_name_from_flags(self.characteristics)
    }

    pub fn normal_expectation(&self) -> &'static str {
        match self.name.to_ascii_lowercase().as_str() {
            ".text" | "text" => "RX",
            ".data" | "data" | ".bss" | "bss" | ".tls" | "tls" => "RW",
            ".rdata" | "rdata" | ".pdata" | "pdata" | ".edata" | "edata" | ".rsrc" | "rsrc"
            | ".reloc" | "reloc" => "R",
            ".idata" | "idata" => "R/RW",
            _ => "varies",
        }
    }

    pub fn normal_expectation_name(&self) -> &'static str {
        match self.normal_expectation() {
            "RX" => "Read+Execute",
            "RW" => "Read+Write",
            "R" => "Read",
            "R/RW" => "Read or Read+Write",
            _ => "Varies",
        }
    }

    pub fn unusual_protection_reason(&self) -> Option<String> {
        let name = self.name.to_ascii_lowercase();
        let prot = self.protection_string();

        if prot.contains('W') && prot.contains('X') {
            return Some("section is both writable and executable".to_owned());
        }

        match name.as_str() {
            ".text" | "text" if prot.contains('W') => Some(".text is writable".to_owned()),
            ".rdata" | "rdata" | ".pdata" | "pdata" | ".edata" | "edata" | ".rsrc" | "rsrc"
            | ".reloc" | "reloc"
                if prot.contains('W') || prot.contains('X') =>
            {
                Some(format!("{} has unexpected {}", self.name, prot))
            }
            ".data" | "data" | ".bss" | "bss" | ".tls" | "tls" if prot.contains('X') => {
                Some(format!("{} is executable", self.name))
            }
            ".idata" | "idata" if prot.contains('X') => Some(".idata is executable".to_owned()),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeAnomaly {
    pub severity: String,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone)]
pub struct PeFile {
    pub arch: u32,
    pub machine: u16,
    pub timestamp: u32,
    pub coff_characteristics: u16,
    pub major_linker_version: u8,
    pub minor_linker_version: u8,
    pub image_base: u64,
    pub entry_point: u32,
    pub size_of_image: u32,
    pub size_of_headers: u32,
    pub section_alignment: u32,
    pub file_alignment: u32,
    pub checksum: u32,
    pub subsystem: u16,
    pub dll_characteristics: u16,
    pub sections: Vec<PeSection>,
    pub data_dirs: Vec<(u32, u32)>,
    pub anomalies: Vec<PeAnomaly>,
}

impl PeFile {
    pub fn rva_to_offset(&self, rva: u32) -> Option<usize> {
        self.rva_to_section(rva).map(|s| {
            let delta = rva - s.virtual_address;
            (s.raw_offset + delta) as usize
        })
    }

    pub fn rva_to_section(&self, rva: u32) -> Option<&PeSection> {
        self.sections.iter().find(|s| s.contains_rva(rva))
    }

    pub fn data_dir(&self, idx: usize) -> (u32, u32) {
        self.data_dirs.get(idx).copied().unwrap_or((0, 0))
    }

    pub fn header_corruption_detected(&self) -> bool {
        self.anomalies
            .iter()
            .any(|a| a.severity == "high" || a.severity == "warn")
    }
}

#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub ordinal: u32,
    pub rva: u32,
    pub forward_to: String,
}

#[derive(Debug, Clone)]
pub struct ImportEntry {
    pub name: String,
    pub ordinal: u16,
    pub hint: u16,
    pub by_ord: bool,
}

#[derive(Debug, Clone)]
pub struct ImportDll {
    pub dll: String,
    pub entries: Vec<ImportEntry>,
}

#[derive(Debug, Clone)]
pub struct PeDebugEntry {
    pub debug_type: u32,
    pub size_of_data: u32,
}

impl PeDebugEntry {
    pub fn type_name(&self) -> &'static str {
        match self.debug_type {
            0 => "Unknown",
            1 => "COFF",
            2 => "CodeView",
            3 => "FPO",
            4 => "Misc",
            5 => "Exception",
            6 => "Fixup",
            7 => "OmapToSrc",
            8 => "OmapFromSrc",
            9 => "Borland",
            11 => "CLSID",
            12 => "VCFeature",
            16 => "Repro",
            _ => "Other",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PeCodeViewInfo {
    pub pdb_path: String,
    pub pdb_name: String,
    pub guid_age: String,
}

#[derive(Debug, Clone, Default)]
pub struct PeDebugInfo {
    pub entries: Vec<PeDebugEntry>,
    pub codeview: Option<PeCodeViewInfo>,
}

#[derive(Debug, Clone)]
pub struct PeClrInfo {
    pub major_runtime_version: u16,
    pub minor_runtime_version: u16,
    pub metadata_rva: u32,
    pub metadata_size: u32,
    pub flags: u32,
    pub entry_point_token_or_rva: u32,
    pub metadata_version: String,
}

#[derive(Debug, Clone)]
pub struct PeLoadConfigInfo {
    pub size: u32,
    pub security_cookie: u64,
    pub se_handler_count: u64,
    pub guard_cf_function_count: u64,
    pub guard_flags: u32,
    pub guard_eh_continuation_count: u64,
    pub guard_xfg_check_function_pointer: u64,
}

#[derive(Debug)]
pub struct PeError(pub String);

impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for PeError {}

pub fn read_u16(raw: &[u8], off: usize) -> u16 {
    if off + 2 > raw.len() {
        return 0;
    }
    u16::from_le_bytes([raw[off], raw[off + 1]])
}

pub fn read_u32(raw: &[u8], off: usize) -> u32 {
    if off + 4 > raw.len() {
        return 0;
    }
    u32::from_le_bytes(raw[off..off + 4].try_into().unwrap())
}

pub fn read_u64(raw: &[u8], off: usize) -> u64 {
    if off + 8 > raw.len() {
        return 0;
    }
    u64::from_le_bytes(raw[off..off + 8].try_into().unwrap())
}

pub fn read_cstr(raw: &[u8], off: usize) -> String {
    if off >= raw.len() {
        return String::new();
    }
    let end = raw[off..]
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(raw.len() - off);
    String::from_utf8_lossy(&raw[off..off + end]).into_owned()
}

pub(crate) fn anomaly(severity: &str, kind: &str, detail: String) -> PeAnomaly {
    PeAnomaly {
        severity: severity.to_owned(),
        kind: kind.to_owned(),
        detail,
    }
}

fn protection_name_from_flags(characteristics: u32) -> String {
    let read = characteristics & IMAGE_SCN_MEM_READ != 0;
    let write = characteristics & IMAGE_SCN_MEM_WRITE != 0;
    let exec = characteristics & IMAGE_SCN_MEM_EXECUTE != 0;

    match (read, write, exec) {
        (true, false, false) => "Read".to_owned(),
        (true, true, false) => "Read+Write".to_owned(),
        (true, false, true) => "Read+Execute".to_owned(),
        (true, true, true) => "Read+Write+Execute".to_owned(),
        (false, true, false) => "Write".to_owned(),
        (false, true, true) => "Write+Execute".to_owned(),
        (false, false, true) => "Execute".to_owned(),
        _ => "None".to_owned(),
    }
}
