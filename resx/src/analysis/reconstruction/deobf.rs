use std::collections::BTreeSet;

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Mnemonic};
use serde::Serialize;

use crate::analysis::strings::{analyze_strings, StringsOptions};
use crate::formats::pe::PeFile;

#[derive(Debug, Clone, Serialize)]
pub struct DeobfReport {
    pub image: String,
    pub summary: String,
    pub base64: Vec<Base64Candidate>,
    pub xor: Vec<XorCandidate>,
    pub code: Vec<CodeObfuscationHint>,
    pub next_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Base64Candidate {
    pub rva: Option<String>,
    pub file_offset: String,
    pub encoded: String,
    pub decoded_preview: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct XorCandidate {
    pub file_offset: String,
    pub key: String,
    pub decoded_preview: String,
    pub printable_ratio: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct CodeObfuscationHint {
    pub rva: String,
    pub section: String,
    pub rule: String,
    pub score: u32,
    pub evidence: Vec<String>,
}

pub fn analyze_deobf(image: &str, pe: Option<&PeFile>, raw: &[u8], limit: usize) -> DeobfReport {
    let base64 = base64_candidates(pe, raw, limit);
    let xor = xor_candidates(raw, limit);
    let code = pe.map(|pe| code_hints(pe, raw, limit)).unwrap_or_default();
    let summary = format!(
        "{} base64 decode(s), {} XOR candidate(s), {} code obfuscation hint(s)",
        base64.len(),
        xor.len(),
        code.len()
    );
    let next_steps = vec![
        "Use decoded previews as search terms with `resx strings <image> --interesting`.".to_owned(),
        "For XOR hits, carve a small range around the offset and confirm the key against surrounding bytes.".to_owned(),
        "For code hints, dump the RVA with `resx dump <image> --at <rva> --hostile --strings --funcs`.".to_owned(),
    ];
    DeobfReport {
        image: image.to_owned(),
        summary,
        base64,
        xor,
        code,
        next_steps,
    }
}

fn base64_candidates(pe: Option<&PeFile>, raw: &[u8], limit: usize) -> Vec<Base64Candidate> {
    let opts = StringsOptions {
        min_len: 12,
        limit: 4096,
        ascii: true,
        wide: false,
        interesting_only: false,
        ..Default::default()
    };
    let mut out = Vec::new();
    for item in analyze_strings("", pe, raw, &opts).strings {
        let trimmed = item.value.trim();
        if trimmed.len() < 16 || !trimmed.len().is_multiple_of(4) || !is_base64_charset(trimmed) {
            continue;
        }
        let Some(decoded) = decode_base64(trimmed) else {
            continue;
        };
        if decoded.len() < 4 || printable_ratio(&decoded) < 0.65 {
            continue;
        }
        out.push(Base64Candidate {
            rva: item.rva,
            file_offset: item.file_offset,
            encoded: trimmed.chars().take(120).collect(),
            decoded_preview: preview_bytes(&decoded, 160),
        });
        if limit > 0 && out.len() >= limit {
            break;
        }
    }
    out
}

fn xor_candidates(raw: &[u8], limit: usize) -> Vec<XorCandidate> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let max_scan = raw.len().min(8 * 1024 * 1024);
    let window = 48usize;
    let step = 16usize;
    let mut offset = 0usize;
    while offset + window <= max_scan {
        let chunk = &raw[offset..offset + window];
        for key in 1u8..=255 {
            let decoded: Vec<u8> = chunk.iter().map(|b| b ^ key).collect();
            let ratio = printable_ratio(&decoded);
            if ratio < 0.86 || !decoded.iter().any(|b| b.is_ascii_alphabetic()) {
                continue;
            }
            let preview = preview_bytes(&decoded, 96);
            if preview.trim().len() < 12 {
                continue;
            }
            let dedup = format!("{key:02X}|{preview}");
            if !seen.insert(dedup) {
                continue;
            }
            out.push(XorCandidate {
                file_offset: format!("0x{:08X}", offset),
                key: format!("0x{key:02X}"),
                decoded_preview: preview,
                printable_ratio: format!("{ratio:.2}"),
            });
            if limit > 0 && out.len() >= limit {
                return out;
            }
        }
        offset += step;
    }
    out
}

fn code_hints(pe: &PeFile, raw: &[u8], limit: usize) -> Vec<CodeObfuscationHint> {
    let mut out = Vec::new();
    for section in &pe.sections {
        if !section.is_executable() || section.raw_size == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        if start >= raw.len() {
            continue;
        }
        let len = (section.raw_size as usize).min(raw.len().saturating_sub(start));
        let bytes = &raw[start..start + len];
        let mut decoder = Decoder::with_ip(
            pe.arch,
            bytes,
            pe.image_base + section.virtual_address as u64,
            DecoderOptions::NONE,
        );
        let mut formatter = IntelFormatter::new();
        let mut window = Vec::new();
        while decoder.can_decode() {
            let instr = decoder.decode();
            if instr.len() == 0 {
                break;
            }
            window.push(instr);
            if window.len() > 24 {
                window.remove(0);
            }
            if window.len() < 16 {
                continue;
            }
            let bit_ops = window
                .iter()
                .filter(|instr| {
                    matches!(
                        instr.mnemonic(),
                        Mnemonic::Xor
                            | Mnemonic::Rol
                            | Mnemonic::Ror
                            | Mnemonic::Shl
                            | Mnemonic::Shr
                            | Mnemonic::Sar
                            | Mnemonic::Not
                            | Mnemonic::Neg
                    )
                })
                .count();
            let indirect = window
                .iter()
                .filter(|instr| {
                    matches!(instr.mnemonic(), Mnemonic::Call | Mnemonic::Jmp)
                        && instr.op_count() > 0
                        && matches!(
                            instr.op0_kind(),
                            iced_x86::OpKind::Register | iced_x86::OpKind::Memory
                        )
                })
                .count();
            if bit_ops < 8 && indirect == 0 {
                continue;
            }
            let rva = window[0].ip().wrapping_sub(pe.image_base) as u32;
            let score = bit_ops as u32 * 2 + indirect as u32 * 5;
            let mut evidence = Vec::new();
            for instr in window.iter().take(6) {
                let mut text = String::new();
                formatter.format(instr, &mut text);
                evidence.push(format!(
                    "0x{:08X}: {}",
                    instr.ip().wrapping_sub(pe.image_base) as u32,
                    text
                ));
            }
            out.push(CodeObfuscationHint {
                rva: format!("0x{rva:08X}"),
                section: section.name.clone(),
                rule: if indirect > 0 {
                    "indirect-dispatch-window".to_owned()
                } else {
                    "bitwise-density-window".to_owned()
                },
                score,
                evidence,
            });
            if limit > 0 && out.len() >= limit {
                break;
            }
        }
    }
    out
}

fn is_base64_charset(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
}

fn decode_base64(value: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0u32;
    for b in value.bytes() {
        if b == b'=' {
            break;
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a' + 26,
            b'0'..=b'9' => b - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }
    Some(out)
}

fn printable_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let printable = bytes
        .iter()
        .filter(|&&b| (0x20..=0x7E).contains(&b) || matches!(b, b'\r' | b'\n' | b'\t'))
        .count();
    printable as f64 / bytes.len() as f64
}

fn preview_bytes(bytes: &[u8], limit: usize) -> String {
    bytes
        .iter()
        .take(limit)
        .map(|b| {
            if (0x20..=0x7E).contains(b) || *b == b'\t' {
                *b as char
            } else {
                '.'
            }
        })
        .collect()
}
