//! Structural checks for directories consumed by RESX. Opaque payloads are not
//! handed to external parsers by these checks (for example PKCS#7 or CLR IL).
use super::{anomaly, read_u16, read_u32, read_u64, PeAnomaly, PeFile};
use std::collections::BTreeSet;

type Check<T = ()> = Result<T, &'static str>;

struct Budget {
    entries: usize,
    strings: usize,
}
impl Budget {
    fn new() -> Self {
        Self {
            entries: 131_072,
            strings: 16 * 1024 * 1024,
        }
    }
    fn entry(&mut self) -> Check {
        self.entries = self
            .entries
            .checked_sub(1)
            .ok_or("directory traversal budget exceeded")?;
        Ok(())
    }
    fn string(&mut self, size: usize) -> Check {
        self.strings = self
            .strings
            .checked_sub(size)
            .ok_or("directory string budget exceeded")?;
        Ok(())
    }
}

fn region<'a>(pe: &PeFile, raw: &'a [u8], index: usize) -> Check<&'a [u8]> {
    let (rva, size) = pe.data_dir(index);
    pe.rva_slice(raw, rva, size as usize)
        .ok_or("directory range is not unambiguously file-backed")
}

fn name<'a>(bytes: &'a [u8], offset: usize, budget: &mut Budget) -> Check<&'a str> {
    let bytes = bytes
        .get(offset..)
        .ok_or("string offset is outside its region")?;
    let end = bytes
        .iter()
        .take(4096)
        .position(|&b| b == 0)
        .ok_or("string lacks a bounded terminator")?;
    budget.string(end + 1)?;
    std::str::from_utf8(&bytes[..end]).map_err(|_| "string contains invalid UTF-8")
}

fn rva_name<'a>(pe: &PeFile, raw: &'a [u8], rva: u32, budget: &mut Budget) -> Check<&'a str> {
    name(
        pe.rva_bytes(raw, rva).ok_or("string RVA is unbacked")?,
        0,
        budget,
    )
}

pub(super) fn mapped(pe: &PeFile, rva: u32, size: u32) -> bool {
    if size == 0 {
        return true;
    }
    let Some(end) = rva.checked_add(size).filter(|&end| end <= pe.size_of_image) else {
        return false;
    };
    if rva < pe.size_of_headers {
        return end <= pe.size_of_headers
            && !pe.sections.iter().any(|s| {
                s.virtual_address < end
                    && u64::from(s.virtual_address) + u64::from(s.virtual_size.max(s.raw_size))
                        > u64::from(rva)
            });
    }
    let Some(section) = pe.rva_to_section(rva) else {
        return false;
    };
    end <= section
        .virtual_address
        .saturating_add(section.virtual_size.max(section.raw_size))
        && pe
            .sections
            .iter()
            .filter(|s| {
                s.virtual_address < end
                    && s.virtual_address
                        .saturating_add(s.virtual_size.max(s.raw_size))
                        > rva
            })
            .count()
            == 1
}

fn exports(pe: &PeFile, raw: &[u8], budget: &mut Budget) -> Check {
    let bytes = region(pe, raw, 0)?;
    if bytes.len() < 40 {
        return Err("export header is truncated");
    }
    let functions = read_u32(bytes, 20) as usize;
    let names = read_u32(bytes, 24) as usize;
    if functions > 65_536
        || names > 65_536
        || read_u32(bytes, 16).checked_add(functions as u32).is_none()
    {
        return Err("export counts or ordinals exceed limits");
    }
    let funcs = pe
        .rva_slice(raw, read_u32(bytes, 28), functions * 4)
        .ok_or("export address array is truncated")?;
    if read_u32(bytes, 12) != 0 {
        rva_name(pe, raw, read_u32(bytes, 12), budget)?;
    }
    let (start, size) = pe.data_dir(0);
    for entry in funcs.as_chunks::<4>().0 {
        budget.entry()?;
        let rva = read_u32(entry, 0);
        if rva == 0 {
            continue;
        }
        if rva >= start && u64::from(rva) < u64::from(start) + u64::from(size) {
            let forward = name(bytes, (rva - start) as usize, budget)?;
            if !forward.contains('.') {
                return Err("forwarded export lacks a module/symbol separator");
            }
        } else if !mapped(pe, rva, 1) {
            return Err("export address is outside the mapped image");
        }
    }
    if names != 0 {
        let ptrs = pe
            .rva_slice(raw, read_u32(bytes, 32), names * 4)
            .ok_or("export name array is truncated")?;
        let ords = pe
            .rva_slice(raw, read_u32(bytes, 36), names * 2)
            .ok_or("export ordinal array is truncated")?;
        for index in 0..names {
            budget.entry()?;
            if usize::from(read_u16(ords, index * 2)) >= functions {
                return Err("export name ordinal exceeds the address array");
            }
            if rva_name(pe, raw, read_u32(ptrs, index * 4), budget)?.is_empty() {
                return Err("export has an empty name");
            }
        }
    }
    Ok(())
}

fn thunks(
    pe: &PeFile,
    raw: &[u8],
    lookup: u32,
    iat: u32,
    va_names: bool,
    budget: &mut Budget,
) -> Check {
    let width = if pe.arch == 64 { 8 } else { 4 };
    let table = pe
        .rva_bytes(raw, lookup)
        .ok_or("import lookup table is unbacked")?;
    for (index, slot) in table.chunks_exact(width).take(65_536).enumerate() {
        budget.entry()?;
        let value = if width == 8 {
            read_u64(slot, 0)
        } else {
            u64::from(read_u32(slot, 0))
        };
        let slot_rva = iat
            .checked_add((index * width) as u32)
            .ok_or("IAT slot address overflows")?;
        if pe.rva_slice(raw, slot_rva, width).is_none() {
            return Err("IAT slot is unbacked");
        }
        if value == 0 {
            return Ok(());
        }
        let ordinal = if width == 8 { 1u64 << 63 } else { 1u64 << 31 };
        if value & ordinal != 0 {
            if value & !(ordinal | 0xffff) != 0 {
                return Err("import ordinal contains reserved bits");
            }
        } else {
            let value = if va_names {
                value
                    .checked_sub(pe.image_base)
                    .ok_or("import name VA precedes image base")?
            } else {
                value
            };
            let rva = u32::try_from(value).map_err(|_| "import name address exceeds an RVA")?;
            let bytes = pe
                .rva_bytes(raw, rva)
                .ok_or("import hint/name is unbacked")?;
            if bytes.len() < 3 || name(bytes, 2, budget)?.is_empty() {
                return Err("import hint/name is invalid");
            }
        }
    }
    Err("import lookup table lacks a terminator within its budget")
}

fn imports(pe: &PeFile, raw: &[u8], delay: bool, budget: &mut Budget) -> Check {
    let bytes = region(pe, raw, if delay { 13 } else { 1 })?;
    let stride = if delay { 32 } else { 20 };
    for descriptor in bytes.chunks_exact(stride).take(4096) {
        budget.entry()?;
        if descriptor.iter().all(|&b| b == 0) {
            return Ok(());
        }
        let attrs = if delay { read_u32(descriptor, 0) } else { 1 };
        if delay && attrs & !1 != 0 {
            return Err("delay import uses unknown descriptor attributes");
        }
        let address = |offset| -> Check<u32> {
            let value = read_u32(descriptor, offset);
            if value == 0 || attrs & 1 != 0 {
                return Ok(value);
            }
            u64::from(value)
                .checked_sub(pe.image_base)
                .and_then(|rva| u32::try_from(rva).ok())
                .ok_or("delay import VA is outside image addressing")
        };
        let dll = address(if delay { 4 } else { 12 })?;
        let iat = address(if delay { 12 } else { 16 })?;
        let lookup = address(if delay { 16 } else { 0 })?;
        if rva_name(pe, raw, dll, budget)?.is_empty() || iat == 0 {
            return Err("import descriptor lacks a name or IAT");
        }
        // An already-bound IAT with no lookup table has no recoverable names.
        if !delay && lookup == 0 && read_u32(descriptor, 4) != 0 {
            return Err("bound import lacks its original lookup table; names cannot be validated");
        }
        thunks(
            pe,
            raw,
            if lookup == 0 { iat } else { lookup },
            iat,
            attrs & 1 == 0,
            budget,
        )?;
    }
    Err("import descriptor table lacks a terminator within its declared extent")
}

fn resources(pe: &PeFile, raw: &[u8], budget: &mut Budget) -> Check {
    let bytes = region(pe, raw, 2)?;
    let mut pending = vec![(0usize, 0usize)];
    let mut visited = BTreeSet::new();
    while let Some((offset, depth)) = pending.pop() {
        budget.entry()?;
        if depth > 32 || !visited.insert(offset) || visited.len() > 4096 {
            return Err("resource tree cycles, aliases, or depth/node budget exceeded");
        }
        let header = bytes
            .get(offset..)
            .and_then(|b| b.get(..16))
            .ok_or("resource directory is truncated")?;
        let count = usize::from(read_u16(header, 12)) + usize::from(read_u16(header, 14));
        let entries = bytes
            .get(offset + 16..)
            .and_then(|b| b.get(..count * 8))
            .ok_or("resource entries are truncated")?;
        for entry in entries.as_chunks::<8>().0 {
            budget.entry()?;
            let id = read_u32(entry, 0);
            if id & 0x8000_0000 != 0 {
                let name_offset = (id & 0x7fff_ffff) as usize;
                let text = bytes
                    .get(name_offset..)
                    .filter(|b| b.len() >= 2)
                    .ok_or("resource name offset is invalid")?;
                let count = usize::from(read_u16(text, 0));
                if count > 4096 {
                    return Err("resource name exceeds string limit");
                }
                budget.string(count * 2)?;
                let text = text
                    .get(2..2 + count * 2)
                    .ok_or("resource UTF-16 name is truncated")?;
                if char::decode_utf16(
                    text.as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_le_bytes([p[0], p[1]])),
                )
                .any(|c| c.is_err())
                {
                    return Err("resource name has invalid UTF-16");
                }
            }
            let target = read_u32(entry, 4);
            let offset = (target & 0x7fff_ffff) as usize;
            if target & 0x8000_0000 != 0 {
                if pending.len() >= 4096 {
                    return Err("resource work queue budget exceeded");
                }
                pending.push((offset, depth + 1));
            } else {
                let data = bytes
                    .get(offset..)
                    .and_then(|b| b.get(..16))
                    .ok_or("resource data entry is truncated")?;
                if read_u32(data, 12) != 0
                    || pe
                        .rva_slice(raw, read_u32(data, 0), read_u32(data, 4) as usize)
                        .is_none()
                {
                    return Err("resource data range or reserved field is invalid");
                }
            }
        }
    }
    Ok(())
}

fn relocations(pe: &PeFile, raw: &[u8], budget: &mut Budget) -> Check {
    let bytes = region(pe, raw, 5)?;
    let mut offset = 0;
    while offset < bytes.len() {
        budget.entry()?;
        let header = bytes
            .get(offset..)
            .filter(|b| b.len() >= 8)
            .ok_or("relocation block header is truncated")?;
        let page = read_u32(header, 0);
        let size = read_u32(header, 4) as usize;
        if size < 8 || !size.is_multiple_of(2) || page & 0xfff != 0 {
            return Err("relocation block has invalid size or page alignment");
        }
        let block = header
            .get(..size)
            .ok_or("relocation block exceeds its directory")?;
        let mut index = 8;
        while index < size {
            budget.entry()?;
            let entry = read_u16(block, index);
            index += 2;
            let kind = entry >> 12;
            let width = match kind {
                0 => continue,
                1 | 2 if pe.machine == 0x14c => 2,
                3 if matches!(pe.machine, 0x14c | 0x8664) => 4,
                4 if pe.machine == 0x14c => {
                    if index + 2 > size {
                        return Err("HIGHADJ relocation lacks its paired value");
                    }
                    index += 2;
                    2
                }
                10 if matches!(pe.machine, 0x8664 | 0xaa64) => 8,
                _ => return Err("unsupported relocation type for this machine"),
            };
            let rva = page
                .checked_add(u32::from(entry & 0xfff))
                .ok_or("relocation target overflows")?;
            if !mapped(pe, rva, width) {
                return Err("relocation target is outside an unambiguous mapped range");
            }
        }
        offset += size;
    }
    Ok(())
}

fn certificates(pe: &PeFile, raw: &[u8], budget: &mut Budget) -> Check {
    let (offset, size) = pe.data_dir(4);
    let bytes = raw
        .get(offset as usize..)
        .and_then(|b| b.get(..size as usize))
        .ok_or("certificate file extent is invalid")?;
    let mut offset = 0usize;
    while offset < bytes.len() {
        budget.entry()?;
        let header = bytes
            .get(offset..)
            .filter(|b| b.len() >= 8)
            .ok_or("certificate header is truncated")?;
        let size = read_u32(header, 0) as usize;
        if size < 8 || size > header.len() || !matches!(read_u16(header, 4), 0x100 | 0x200) {
            return Err("certificate size or revision is invalid");
        }
        let end = offset + size;
        offset = (end + 7) & !7;
        if offset > bytes.len() && end != bytes.len() {
            return Err("certificate alignment exceeds directory extent");
        }
    }
    Ok(())
}

fn bound_imports(pe: &PeFile, raw: &[u8], budget: &mut Budget) -> Check {
    let bytes = region(pe, raw, 11)?;
    let mut offset = 0;
    while offset + 8 <= bytes.len() {
        budget.entry()?;
        let entry = &bytes[offset..offset + 8];
        if entry.iter().all(|&b| b == 0) {
            return Ok(());
        }
        name(bytes, usize::from(read_u16(entry, 4)), budget)?;
        let count = usize::from(read_u16(entry, 6));
        offset += 8;
        let forwarders = bytes
            .get(offset..)
            .and_then(|b| b.get(..count * 8))
            .ok_or("bound import forwarder list is truncated")?;
        for entry in forwarders.as_chunks::<8>().0 {
            budget.entry()?;
            name(bytes, usize::from(read_u16(entry, 4)), budget)?;
        }
        offset += count * 8;
    }
    Err("bound import descriptor table lacks a terminator")
}

fn debug(pe: &PeFile, raw: &[u8], budget: &mut Budget) -> Check {
    let table = region(pe, raw, 6)?;
    if table.len() % 28 != 0 {
        return Err("debug directory has a partial record");
    }
    for entry in table.as_chunks::<28>().0 {
        budget.entry()?;
        let size = read_u32(entry, 16) as usize;
        let rva = read_u32(entry, 20);
        let offset = read_u32(entry, 24) as usize;
        if size == 0 {
            continue;
        }
        let data = raw
            .get(offset..)
            .and_then(|b| b.get(..size))
            .ok_or("debug file extent is invalid")?;
        if rva != 0 && pe.rva_to_offset(rva) != Some(offset) {
            return Err("debug RVA and file offset disagree");
        }
        if rva != 0 && pe.rva_slice(raw, rva, size).is_none() {
            return Err("debug RVA extent is invalid");
        }
        if read_u32(entry, 12) == 2 {
            let name_offset = match data.get(..4) {
                Some(b"RSDS") => 24,
                Some(b"NB10") => 16,
                _ => return Err("unsupported CodeView record signature"),
            };
            name(data, name_offset, budget)?;
        }
    }
    Ok(())
}

fn tls(pe: &PeFile, raw: &[u8]) -> Check {
    let bytes = region(pe, raw, 9)?;
    let width = if pe.arch == 64 { 8 } else { 4 };
    if bytes.len() < width * 4 + 8 {
        return Err("TLS header is truncated");
    }
    let pointer = |offset| {
        if width == 8 {
            read_u64(bytes, offset)
        } else {
            u64::from(read_u32(bytes, offset))
        }
    };
    let start = pointer(0);
    let end = pointer(width);
    let initialized = end
        .checked_sub(start)
        .ok_or("TLS raw data end precedes start")?;
    if start != 0 || end != 0 {
        let rva = start
            .checked_sub(pe.image_base)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or("TLS raw data VA is invalid")?;
        if initialized > 512 * 1024 * 1024 || pe.rva_slice(raw, rva, initialized as usize).is_none()
        {
            return Err("TLS raw data is unbacked or exceeds budget");
        }
    }
    let index = pointer(width * 2)
        .checked_sub(pe.image_base)
        .and_then(|value| u32::try_from(value).ok())
        .ok_or("TLS index VA is invalid")?;
    if !mapped(pe, index, 4) {
        return Err("TLS index does not address a mapped DWORD");
    }
    let zero_fill = read_u32(bytes, width * 4);
    if initialized + u64::from(zero_fill) > 512 * 1024 * 1024 {
        return Err("TLS allocation exceeds the analysis size limit");
    }
    let characteristics = read_u32(bytes, width * 4 + 4);
    if characteristics & !0x00f0_0000 != 0 || characteristics & 0x00f0_0000 == 0x00f0_0000 {
        return Err("TLS characteristics contain reserved bits");
    }
    Ok(())
}

fn load_config(pe: &PeFile, raw: &[u8], budget: &mut Budget) -> Check {
    let directory = region(pe, raw, 10)?;
    if directory.len() < 4 {
        return Err("load configuration size is missing");
    }
    let size = read_u32(directory, 0) as usize;
    let bytes = directory
        .get(..size)
        .filter(|b| b.len() >= 4)
        .ok_or("load configuration declared size is invalid")?;
    let width = if pe.arch == 64 { 8 } else { 4 };
    let pointer = |offset| {
        if width == 8 {
            read_u64(bytes, offset)
        } else {
            u64::from(read_u32(bytes, offset))
        }
    };
    let tables: &[(usize, usize, bool)] = if width == 8 {
        &[
            (96, 104, false),
            (128, 136, true),
            (160, 168, true),
            (176, 184, true),
            (264, 272, true),
        ]
    } else {
        &[
            (64, 68, false),
            (80, 84, true),
            (104, 108, true),
            (112, 116, true),
            (164, 168, true),
        ]
    };
    let guard_flags = if bytes.len() >= if width == 8 { 148 } else { 92 } {
        read_u32(bytes, if width == 8 { 144 } else { 88 })
    } else {
        0
    };
    for &(table_offset, count_offset, is_guard) in tables {
        if count_offset + width > bytes.len() {
            continue;
        }
        let count = pointer(count_offset);
        if count == 0 {
            continue;
        }
        if count > 65_536 {
            return Err("load configuration table count exceeds budget");
        }
        let stride = 4 + if is_guard {
            ((guard_flags >> 28) & 15) as usize
        } else {
            0
        };
        let rva = pointer(table_offset)
            .checked_sub(pe.image_base)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or("load configuration table VA is invalid")?;
        let table = pe
            .rva_slice(raw, rva, count as usize * stride)
            .ok_or("load configuration table is truncated")?;
        let mut previous = None;
        for entry in table.chunks_exact(stride) {
            budget.entry()?;
            let target = read_u32(entry, 0);
            if !mapped(pe, target, 1) || previous.is_some_and(|previous| target < previous) {
                return Err("load configuration table targets are unmapped or unsorted");
            }
            previous = Some(target);
        }
    }
    Ok(())
}

fn clr(pe: &PeFile, raw: &[u8], budget: &mut Budget) -> Check {
    let header = region(pe, raw, 14)?;
    if header.len() < 72 || read_u32(header, 0) < 72 || read_u32(header, 0) as usize > header.len()
    {
        return Err("CLR header is truncated or has an invalid declared size");
    }
    let metadata = pe
        .rva_slice(raw, read_u32(header, 8), read_u32(header, 12) as usize)
        .ok_or("CLR metadata extent is unbacked")?;
    if metadata.len() < 20 || read_u32(metadata, 0) != 0x424a_5342 {
        return Err("CLR metadata header signature is invalid");
    }
    let version_length = read_u32(metadata, 12) as usize;
    if version_length == 0 || version_length > 4096 || !version_length.is_multiple_of(4) {
        return Err("CLR version string length is invalid");
    }
    let version = metadata
        .get(16..16 + version_length)
        .ok_or("CLR version string is truncated")?;
    name(version, 0, budget)?;
    let mut offset = 16 + version_length;
    let stream_header = metadata
        .get(offset..offset + 4)
        .ok_or("CLR stream count is missing")?;
    let count = usize::from(read_u16(stream_header, 2));
    if count > 64 {
        return Err("CLR stream count exceeds budget");
    }
    offset += 4;
    let mut names = BTreeSet::new();
    let mut ranges = Vec::new();
    for _ in 0..count {
        budget.entry()?;
        let stream = metadata
            .get(offset..)
            .filter(|bytes| bytes.len() >= 9)
            .ok_or("CLR stream header is truncated")?;
        let start = read_u32(stream, 0) as usize;
        let size = read_u32(stream, 4) as usize;
        let stream_name = name(&stream[..stream.len().min(40)], 8, budget)?;
        if !names.insert(stream_name) {
            return Err("CLR stream names are duplicated");
        }
        let end = start
            .checked_add(size)
            .filter(|&end| end <= metadata.len())
            .ok_or("CLR stream exceeds metadata extent")?;
        if size != 0 {
            ranges.push((start, end));
        }
        offset += 8 + ((stream_name.len() + 1 + 3) & !3);
    }
    ranges.sort_unstable();
    if ranges.iter().any(|&(start, _)| start < offset)
        || ranges.windows(2).any(|pair| pair[1].0 < pair[0].1)
    {
        return Err("CLR streams overlap headers or other streams");
    }
    // Remaining CLR header directories have independent RVA/size pairs.
    for pair in header[24..72].as_chunks::<8>().0 {
        let (rva, size) = (read_u32(pair, 0), read_u32(pair, 4));
        if (rva != 0 || size != 0) && pe.rva_slice(raw, rva, size as usize).is_none() {
            return Err("CLR auxiliary directory is unbacked");
        }
    }
    Ok(())
}

pub(super) fn check(pe: &PeFile, raw: &[u8]) -> Vec<PeAnomaly> {
    let mut out = Vec::new();
    let mut budget = Budget::new();
    for index in [0, 1, 2, 4, 5, 6, 7, 9, 10, 11, 12, 13, 14, 15] {
        if pe.data_dir(index) == (0, 0) {
            continue;
        }
        let result = match index {
            0 => exports(pe, raw, &mut budget),
            1 => imports(pe, raw, false, &mut budget),
            2 => resources(pe, raw, &mut budget),
            4 => certificates(pe, raw, &mut budget),
            5 => relocations(pe, raw, &mut budget),
            6 => debug(pe, raw, &mut budget),
            9 => tls(pe, raw),
            10 => load_config(pe, raw, &mut budget),
            11 => bound_imports(pe, raw, &mut budget),
            12 => {
                if pe.data_dir(12).1.is_multiple_of(pe.arch / 8) {
                    Ok(())
                } else {
                    Err("IAT size is not a pointer-width multiple")
                }
            }
            13 => imports(pe, raw, true, &mut budget),
            14 => clr(pe, raw, &mut budget),
            _ => Err("reserved directory is nonzero"),
        };
        if let Err(reason) = result {
            out.push(anomaly(
                "warn",
                "directory-validation",
                format!("Directory {index}: {reason}"),
            ));
        }
    }
    out
}
