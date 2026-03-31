use std::fmt;

const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const IMAGE_SCN_MEM_READ: u32 = 0x4000_0000;
const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

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

#[derive(Debug)]
pub struct PeError(pub String);
impl fmt::Display for PeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for PeError {}
macro_rules! pe_err {
    ($($arg:tt)*) => { PeError(format!($($arg)*)) }
}

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

pub fn parse_pe(raw: &[u8]) -> Result<PeFile, PeError> {
    if raw.len() < 64 {
        return Err(pe_err!("File too small to be a PE"));
    }
    if &raw[0..2] != b"MZ" {
        return Err(pe_err!("Not a PE file (no MZ header)"));
    }

    let e_lfanew = read_u32(raw, 0x3C) as usize;
    if e_lfanew + 4 > raw.len() {
        return Err(pe_err!("e_lfanew out of bounds"));
    }
    if &raw[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return Err(pe_err!("Missing PE signature"));
    }

    let mut anomalies = Vec::new();
    if e_lfanew < 0x40 {
        anomalies.push(anomaly(
            "warn",
            "header",
            format!("e_lfanew is unusually small: 0x{:X}", e_lfanew),
        ));
    }

    let coff_off = e_lfanew + 4;
    if coff_off + 20 > raw.len() {
        return Err(pe_err!("COFF header out of bounds"));
    }

    let machine = read_u16(raw, coff_off);
    let timestamp = read_u32(raw, coff_off + 4);
    let coff_characteristics = read_u16(raw, coff_off + 18);
    let num_sections = read_u16(raw, coff_off + 2) as usize;
    let opt_hdr_size = read_u16(raw, coff_off + 16) as usize;

    if num_sections == 0 {
        anomalies.push(anomaly(
            "high",
            "section-count",
            "PE has zero sections".to_owned(),
        ));
    } else if num_sections > 96 {
        anomalies.push(anomaly(
            "warn",
            "section-count",
            format!("PE has an unusually high section count: {}", num_sections),
        ));
    }

    let opt_hdr_off = coff_off + 20;
    if opt_hdr_off + 2 > raw.len() {
        return Err(pe_err!("Optional header out of bounds"));
    }

    let pe_magic = read_u16(raw, opt_hdr_off);
    let (
        arch,
        image_base,
        num_data_dirs,
        data_dir_off,
        entry_point,
        section_alignment,
        file_alignment,
        size_of_image,
        size_of_headers,
        checksum,
        subsystem,
        dll_characteristics,
    ) = match pe_magic {
        0x020B => {
            if opt_hdr_off + 112 > raw.len() {
                return Err(pe_err!("PE32+ optional header too small"));
            }
            (
                64u32,
                read_u64(raw, opt_hdr_off + 24),
                read_u32(raw, opt_hdr_off + 108) as usize,
                opt_hdr_off + 112,
                read_u32(raw, opt_hdr_off + 16),
                read_u32(raw, opt_hdr_off + 32),
                read_u32(raw, opt_hdr_off + 36),
                read_u32(raw, opt_hdr_off + 56),
                read_u32(raw, opt_hdr_off + 60),
                read_u32(raw, opt_hdr_off + 64),
                read_u16(raw, opt_hdr_off + 68),
                read_u16(raw, opt_hdr_off + 70),
            )
        }
        0x010B => {
            if opt_hdr_off + 96 > raw.len() {
                return Err(pe_err!("PE32 optional header too small"));
            }
            (
                32u32,
                read_u32(raw, opt_hdr_off + 28) as u64,
                read_u32(raw, opt_hdr_off + 92) as usize,
                opt_hdr_off + 96,
                read_u32(raw, opt_hdr_off + 16),
                read_u32(raw, opt_hdr_off + 32),
                read_u32(raw, opt_hdr_off + 36),
                read_u32(raw, opt_hdr_off + 56),
                read_u32(raw, opt_hdr_off + 60),
                read_u32(raw, opt_hdr_off + 64),
                read_u16(raw, opt_hdr_off + 68),
                read_u16(raw, opt_hdr_off + 70),
            )
        }
        _ => return Err(pe_err!("Unknown PE magic: 0x{:04X}", pe_magic)),
    };

    let arch = match machine {
        0x8664 | 0xAA64 => 64,
        _ => match arch {
            64 => 64,
            _ => 32,
        },
    };

    if file_alignment == 0 {
        anomalies.push(anomaly(
            "high",
            "alignment",
            "file alignment is zero".to_owned(),
        ));
    }
    if section_alignment == 0 {
        anomalies.push(anomaly(
            "high",
            "alignment",
            "section alignment is zero".to_owned(),
        ));
    }
    if size_of_headers == 0 || size_of_headers as usize > raw.len() {
        anomalies.push(anomaly(
            "warn",
            "headers",
            format!("SizeOfHeaders is suspicious: 0x{:X}", size_of_headers),
        ));
    }
    if size_of_image < size_of_headers {
        anomalies.push(anomaly(
            "warn",
            "image-size",
            format!(
                "SizeOfImage (0x{:X}) is smaller than SizeOfHeaders (0x{:X})",
                size_of_image, size_of_headers
            ),
        ));
    }

    let mut data_dirs = Vec::new();
    let max_dd = num_data_dirs.min(16);
    for i in 0..max_dd {
        let off = data_dir_off + i * 8;
        if off + 8 > raw.len() {
            anomalies.push(anomaly(
                "warn",
                "data-directory",
                format!("data directory {} extends beyond optional header", i),
            ));
            break;
        }
        let rva = read_u32(raw, off);
        let sz = read_u32(raw, off + 4);
        data_dirs.push((rva, sz));
    }
    while data_dirs.len() < 16 {
        data_dirs.push((0, 0));
    }

    let sections_off = opt_hdr_off + opt_hdr_size;
    let mut sections = Vec::with_capacity(num_sections);
    let mut raw_ranges: Vec<(u32, u32, String)> = Vec::new();
    for i in 0..num_sections {
        let s = sections_off + i * 40;
        if s + 40 > raw.len() {
            anomalies.push(anomaly(
                "warn",
                "section-header",
                format!("section header {} is truncated", i),
            ));
            break;
        }

        let name = parse_section_name(&raw[s..s + 8]);
        let virtual_size = read_u32(raw, s + 8);
        let virtual_address = read_u32(raw, s + 12);
        let raw_size = read_u32(raw, s + 16);
        let raw_offset = read_u32(raw, s + 20);
        let characteristics = read_u32(raw, s + 36);

        if raw_size != 0 {
            let end = raw_offset.saturating_add(raw_size);
            if end as usize > raw.len() {
                anomalies.push(anomaly(
                    "warn",
                    "section-bounds",
                    format!(
                        "section {} raw range 0x{:X}-0x{:X} exceeds file size 0x{:X}",
                        name,
                        raw_offset,
                        end,
                        raw.len()
                    ),
                ));
            } else {
                raw_ranges.push((raw_offset, end, name.clone()));
            }
        }
        if virtual_address == 0 && name != ".text" {
            anomalies.push(anomaly(
                "info",
                "section-rva",
                format!("section {} starts at RVA 0", name),
            ));
        }
        if virtual_size == 0 && raw_size != 0 {
            anomalies.push(anomaly(
                "info",
                "section-size",
                format!(
                    "section {} has zero virtual size but non-zero raw size",
                    name
                ),
            ));
        }

        let entropy = calc_entropy(raw, raw_offset as usize, raw_size as usize);
        sections.push(PeSection {
            name,
            virtual_address,
            virtual_size,
            raw_offset,
            raw_size,
            characteristics,
            entropy,
        });
    }

    raw_ranges.sort_by_key(|(start, _, _)| *start);
    for pair in raw_ranges.windows(2) {
        let (a_start, a_end, a_name) = &pair[0];
        let (b_start, _, b_name) = &pair[1];
        if b_start < a_end {
            anomalies.push(anomaly(
                "warn",
                "section-overlap",
                format!(
                    "raw sections {} and {} overlap (0x{:X}-0x{:X})",
                    a_name, b_name, a_start, a_end
                ),
            ));
        }
    }

    let pe = PeFile {
        arch,
        machine,
        timestamp,
        coff_characteristics,
        image_base,
        entry_point,
        size_of_image,
        size_of_headers,
        section_alignment,
        file_alignment,
        checksum,
        subsystem,
        dll_characteristics,
        sections,
        data_dirs,
        anomalies,
    };

    if pe.entry_point != 0 && pe.rva_to_section(pe.entry_point).is_none() {
        let mut pe = pe;
        pe.anomalies.push(anomaly(
            "warn",
            "entry-point",
            format!(
                "entry point RVA 0x{:08X} does not fall inside any section",
                pe.entry_point
            ),
        ));
        return Ok(pe);
    }

    Ok(pe)
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

pub fn read_exports(pe: &PeFile, raw: &[u8]) -> Vec<Export> {
    let (dir_rva, dir_size) = pe.data_dir(0);
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
    let mut name_set = std::collections::HashSet::new();

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

pub fn read_imports(pe: &PeFile, raw: &[u8]) -> Vec<ImportDll> {
    let (dir_rva, _) = pe.data_dir(1);
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
        let mut entries = Vec::new();

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
                });
            } else {
                let hint_rva = (thunk & 0x7FFF_FFFF) as u32;
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
                });
            }
        }

        dlls.push(ImportDll {
            dll: dll_name,
            entries,
        });
    }

    dlls
}

pub fn resolve_iat_slot(pe: &PeFile, raw: &[u8], slot_rva: u32) -> Option<(String, String)> {
    let (dir_rva, _) = pe.data_dir(1);
    if dir_rva == 0 {
        return None;
    }

    let mut off = pe.rva_to_offset(dir_rva)?;
    let ptr_size = if pe.arch == 64 { 8u32 } else { 4u32 };
    let ord_flag_64 = 1u64 << 63;
    let ord_flag_32 = 1u64 << 31;

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
                    let hint_rva = (thunk & 0x7FFF_FFFF) as u32;
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

fn anomaly(severity: &str, kind: &str, detail: String) -> PeAnomaly {
    PeAnomaly {
        severity: severity.to_owned(),
        kind: kind.to_owned(),
        detail,
    }
}

fn parse_section_name(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_owned()
}

fn calc_entropy(raw: &[u8], offset: usize, size: usize) -> f64 {
    if size == 0 || offset >= raw.len() {
        return 0.0;
    }
    let end = offset.saturating_add(size).min(raw.len());
    let slice = &raw[offset..end];
    if slice.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in slice {
        counts[b as usize] += 1;
    }

    let len = slice.len() as f64;
    let mut entropy = 0.0f64;
    for count in counts {
        if count == 0 {
            continue;
        }
        let p = count as f64 / len;
        entropy -= p * p.log2();
    }
    entropy
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
