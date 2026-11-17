//! Shared bounded string evidence. Offsets always refer to the supplied bytes.
use serde::Serialize;

pub const MAX_SCAN: usize = 16 * 1024 * 1024;
pub const MAX_CONFIGURED_SCAN: usize = 128 * 1024 * 1024;
pub const MAX_STRINGS: usize = 32768;
pub const MAX_STRING: usize = 4096;
pub const MAX_TEXT: usize = 8 * 1024 * 1024;

#[derive(Clone, Debug, Serialize)]
pub struct Text {
    pub offset: usize,
    pub encoding: &'static str,
    pub value: String,
    pub truncated: bool,
}

#[derive(Debug, Serialize)]
pub struct Scan {
    pub strings: Vec<Text>,
    pub scanned_bytes: usize,
    pub filtered_out: usize,
    pub long_strings_truncated: usize,
    pub truncated: bool,
}

pub fn scan(raw: &[u8], minimum: usize, ascii: bool, wide: bool) -> Scan {
    scan_filtered(raw, minimum, ascii, wide, MAX_SCAN, |_, _| true)
}

/// Reject candidates before they consume count and text budgets.
pub fn scan_filtered(
    raw: &[u8],
    minimum: usize,
    ascii: bool,
    wide: bool,
    max_scan: usize,
    accept: impl Fn(&str, &str) -> bool,
) -> Scan {
    let minimum = minimum.clamp(1, MAX_STRING);
    let bytes = &raw[..raw.len().min(max_scan.min(MAX_CONFIGURED_SCAN))];
    let mut result = Scan {
        strings: Vec::new(),
        scanned_bytes: bytes.len(),
        filtered_out: 0,
        long_strings_truncated: 0,
        truncated: bytes.len() != raw.len(),
    };
    let mut total = 0;
    for (stride, alignment) in [(1, 0), (2, 0), (2, 1)] {
        if (stride == 1 && !ascii) || (stride == 2 && !wide) {
            continue;
        }
        let mut at = alignment;
        while at + stride <= bytes.len() {
            let start = at;
            let mut units = Vec::new();
            let mut characters = 0;
            while at + stride <= bytes.len() {
                let unit = if stride == 1 {
                    u16::from(bytes[at])
                } else {
                    u16::from_le_bytes([bytes[at], bytes[at + 1]])
                };
                let printable = if stride == 1 {
                    (0x20..=0x7e).contains(&unit) || unit == 9
                } else {
                    unit >= 0x20
                        && unit != 0x7f
                        && !(0x80..=0x9f).contains(&unit)
                        && unit != 0xffff
                        && unit != 0xfffe
                };
                if !printable {
                    break;
                }
                if units.len() < MAX_STRING {
                    units.push(unit);
                }
                characters += 1;
                at += stride;
            }
            if characters >= minimum {
                if let Ok(value) = String::from_utf16(&units) {
                    let encoding = if stride == 1 { "ascii" } else { "utf16le" };
                    if !accept(encoding, &value) {
                        result.filtered_out += 1;
                        at += stride;
                        continue;
                    }
                    if result.strings.len() == MAX_STRINGS || total + value.len() > MAX_TEXT {
                        result.truncated = true;
                        return result;
                    }
                    total += value.len();
                    let truncated = characters > MAX_STRING;
                    result.long_strings_truncated += usize::from(truncated);
                    result.strings.push(Text {
                        offset: start,
                        encoding,
                        value,
                        truncated,
                    });
                }
            }
            at += stride;
        }
    }
    result.strings.sort_by_key(|entry| entry.offset);
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn giant_runs_and_many_small_strings_have_hard_budgets() {
        let result = scan(&vec![b'a'; MAX_SCAN + 1], 6, true, false);
        assert!(result.truncated);
        assert_eq!(result.strings.len(), 1);
        assert_eq!(result.strings[0].value.len(), MAX_STRING);
        assert_eq!(result.long_strings_truncated, 1);
        let result = scan(&b"abcdef\0".repeat(MAX_STRINGS + 1), 6, true, false);
        assert!(result.truncated);
        assert_eq!(result.strings.len(), MAX_STRINGS);
    }

    #[test]
    fn rejected_wide_candidates_do_not_consume_the_result_budget() {
        let mut raw = Vec::new();
        for _ in 0..MAX_STRINGS + 1 {
            raw.extend_from_slice(&[0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0, 0]);
        }
        for unit in "goodwide".encode_utf16().chain([0]) {
            raw.extend_from_slice(&unit.to_le_bytes());
        }
        let result = scan_filtered(&raw, 3, false, true, MAX_SCAN, |_, value| {
            value == "goodwide"
        });
        assert!(result.filtered_out > MAX_STRINGS);
        assert!(result.strings.iter().any(|entry| entry.value == "goodwide"));
        assert!(!result.truncated);
    }

    #[test]
    fn wide_text_at_odd_offset_preserves_bytes() {
        let mut data = vec![0];
        for value in "pipe-\u{03bb}".encode_utf16().chain([0]) {
            data.extend(value.to_le_bytes());
        }
        let result = scan(&data, 6, false, true);
        assert!(result
            .strings
            .iter()
            .any(|s| s.offset == 1 && s.value == "pipe-\u{03bb}" && !s.truncated));
    }

    #[test]
    fn invalid_surrogates_do_not_become_replacement_text() {
        let data: Vec<u8> = [0x61u16, 0x62, 0x63, 0x64, 0xd800, 0]
            .into_iter()
            .flat_map(u16::to_le_bytes)
            .collect();
        assert!(!scan(&data, 4, false, true)
            .strings
            .iter()
            .any(|s| s.offset == 0));
    }
}
