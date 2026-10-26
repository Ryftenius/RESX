//! Module and API names handed to resolvers: literals in the image, strings built on
//! the stack, and strings decoded at run time. Decoding is a bounded brute force over
//! simple ciphers, and a candidate counts only when it names a real export or module,
//! so arbitrary bytes do not decode into findings.

use crate::formats::pe::PeFile;

use super::dictionary::{self, Dictionary};

/// Longest name considered, in characters.
const MAX_NAME: usize = 128;
/// Shortest decoded name accepted; shorter dictionary hits are too likely by chance.
const MIN_DECODED: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::analysis) enum Want {
    Api,
    Module,
    /// Any printable text, for showing string arguments.
    Text,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::analysis) enum How {
    /// A literal in the image.
    Literal,
    /// Built on the stack from immediates.
    StackString,
    /// Decoded at run time; the scheme that reproduces it, e.g. `xor 0x5A`.
    Decoded(String),
}

/// A printable literal at `va`: ASCII, or UTF-16LE when `wide`. Callers do not always
/// know the width (a custom resolver's argument), so a one-character result in the
/// requested width falls back to the other.
pub(super) fn literal(pe: &PeFile, raw: &[u8], va: u64, wide: bool, want: Want) -> Option<String> {
    let rva = u32::try_from(va.checked_sub(pe.image_base)?).ok()?;
    let bytes = pe.rva_bytes(raw, rva)?;
    match terminated(bytes, wide, want) {
        Some(text) if text.len() > 1 => Some(text),
        first => terminated(bytes, !wide, want)
            .filter(|text| text.len() > 1)
            .or(first),
    }
}

/// The NUL-terminated string at the start of `bytes`, when every character is one a
/// name of this kind can contain.
pub(super) fn terminated(bytes: &[u8], wide: bool, want: Want) -> Option<String> {
    let mut text = String::new();
    let step = if wide { 2 } else { 1 };
    for unit in bytes.chunks_exact(step).take(MAX_NAME + 1) {
        let code = if wide {
            u16::from_le_bytes([unit[0], unit[1]])
        } else {
            u16::from(unit[0])
        };
        if code == 0 {
            return (!text.is_empty()).then_some(text);
        }
        let ch = char::from_u32(u32::from(code)).filter(|&ch| name_char(ch, want))?;
        text.push(ch);
    }
    None
}

fn name_char(ch: char, want: Want) -> bool {
    match want {
        Want::Api => ch.is_ascii_alphanumeric() || matches!(ch, '_' | '@' | '?' | '$'),
        Want::Module => {
            ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | '\\' | '/' | ':' | ' ')
        }
        Want::Text => ch.is_ascii_graphic() || matches!(ch, ' ' | '\t' | '\r' | '\n'),
    }
}

/// A NUL-terminated printable string at the start of `bytes`, ASCII or UTF-16LE,
/// with whether it is wide. Short runs are not taken for text.
pub(super) fn text(bytes: &[u8]) -> Option<(String, bool)> {
    let wide = bytes.len() >= 4 && bytes[1] == 0 && bytes[0] != 0;
    terminated(bytes, wide, Want::Text)
        .filter(|text| text.len() >= 3)
        .map(|text| (text, wide))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scheme {
    Xor(u16),
    RollingXor(u16),
    /// plain = cipher + key
    Add(u16),
    /// plain = cipher - key
    Sub(u16),
}

impl Scheme {
    fn apply(self, unit: u16, index: usize, mask: u16) -> u16 {
        let i = index as u16;
        match self {
            Scheme::Xor(key) => unit ^ key,
            Scheme::RollingXor(key) => unit ^ key.wrapping_add(i) & mask,
            Scheme::Add(key) => unit.wrapping_add(key) & mask,
            Scheme::Sub(key) => unit.wrapping_sub(key) & mask,
        }
    }

    fn describe(self) -> String {
        match self {
            Scheme::Xor(key) => format!("xor 0x{key:02X}"),
            Scheme::RollingXor(key) => format!("rolling xor 0x{key:02X}+i"),
            Scheme::Add(key) => format!("add 0x{key:02X}"),
            Scheme::Sub(key) => format!("sub 0x{key:02X}"),
        }
    }
}

/// The name `cipher` decodes to under one of the simple schemes, with the scheme.
/// `keys` are immediates seen near the decode; they are tried first and also as
/// repeating multi-byte XOR keys.
pub(super) fn crack(cipher: &[u8], keys: &[u64], want: Want) -> Option<(String, String)> {
    if cipher.len() < MIN_DECODED {
        return None;
    }
    let dictionary = dictionary::get();
    if dictionary.apis.is_empty() && dictionary.modules.is_empty() {
        return None;
    }
    // Bytes that already read as a name are plain text. Without this, XOR 0x20 turns
    // any lowercase module literal into a case-flipped "decoded" one.
    let plain = [false, true]
        .into_iter()
        .filter_map(|wide| longest_name(cipher, wide, want, dictionary))
        .map(|text| text.len())
        .max()
        .unwrap_or(0);
    let mut best: Option<(String, String)> = None;
    let mut consider = |candidate: Option<String>, scheme: String| {
        if let Some(text) = candidate {
            if best
                .as_ref()
                .is_none_or(|(current, _)| text.len() > current.len())
            {
                best = Some((text, scheme));
            }
        }
    };

    for key in keys
        .iter()
        .copied()
        .filter(|&key| key > 0xFF && key <= u64::from(u32::MAX))
    {
        let pattern: Vec<u8> = key
            .to_le_bytes()
            .into_iter()
            .take_while(|&byte| byte != 0)
            .collect();
        if pattern.len() >= 2 {
            let decoded: Vec<u8> = cipher
                .iter()
                .enumerate()
                .map(|(i, byte)| byte ^ pattern[i % pattern.len()])
                .collect();
            consider(
                longest_name(&decoded, false, want, dictionary),
                format!("xor key 0x{key:X}"),
            );
        }
    }

    let hinted: Vec<u16> = keys
        .iter()
        .filter(|&&key| key > 0 && key <= 0xFFFF)
        .map(|&key| key as u16)
        .collect();
    let byte_keys = hinted
        .iter()
        .copied()
        .filter(|&key| key <= 0xFF)
        .chain(1..=0xFF);
    for key in byte_keys {
        for scheme in [
            Scheme::Xor(key),
            Scheme::RollingXor(key),
            Scheme::Add(key),
            Scheme::Sub(key),
        ] {
            let decoded: Vec<u8> = cipher
                .iter()
                .enumerate()
                .map(|(i, &byte)| scheme.apply(u16::from(byte), i, 0xFF) as u8)
                .collect();
            consider(
                longest_name(&decoded, false, want, dictionary),
                scheme.describe(),
            );
        }
    }
    let units: Vec<u16> = cipher
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    if units.len() >= MIN_DECODED {
        for key in hinted.iter().copied().chain(1..=0xFF) {
            for scheme in [
                Scheme::Xor(key),
                Scheme::RollingXor(key),
                Scheme::Add(key),
                Scheme::Sub(key),
            ] {
                let decoded: Vec<u8> = units
                    .iter()
                    .enumerate()
                    .flat_map(|(i, &unit)| scheme.apply(unit, i, 0xFFFF).to_le_bytes())
                    .collect();
                consider(
                    longest_name(&decoded, true, want, dictionary),
                    format!("{} (UTF-16)", scheme.describe()),
                );
            }
        }
    }
    best.filter(|(text, _)| text.len() > plain)
}

/// The longest prefix of `decoded` that is a known export or module name. A cipher
/// region often runs past its string into unrelated bytes, so the name need not be
/// terminated.
fn longest_name(decoded: &[u8], wide: bool, want: Want, dictionary: &Dictionary) -> Option<String> {
    let step = if wide { 2 } else { 1 };
    let mut text = String::new();
    for unit in decoded.chunks_exact(step).take(MAX_NAME) {
        if wide && unit[1] != 0 {
            break;
        }
        let ch = char::from(unit[0]);
        if !name_char(ch, want) {
            break;
        }
        text.push(ch);
    }
    while text.len() >= MIN_DECODED {
        let known = match want {
            Want::Api => dictionary.is_api(&text),
            Want::Module => dictionary.is_module(&text),
            Want::Text => false,
        };
        if known {
            return Some(text);
        }
        text.pop();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literals_stop_at_the_terminator_and_reject_binary() {
        assert_eq!(
            terminated(b"VirtualAlloc\0junk", false, Want::Api).as_deref(),
            Some("VirtualAlloc")
        );
        assert_eq!(
            terminated(
                b"k\0e\0r\0n\0e\0l\x003\x002\0.\0d\0l\0l\0\0\0",
                true,
                Want::Module
            )
            .as_deref(),
            Some("kernel32.dll")
        );
        assert!(terminated(b"Virtual\x01Alloc\0", false, Want::Api).is_none());
        assert!(terminated(b"kernel32.dll\0", false, Want::Api).is_none());
    }

    #[test]
    #[cfg(windows)]
    fn simple_ciphers_decode_to_known_names() {
        let xor: Vec<u8> = b"CreateThread\0".iter().map(|b| b ^ 0x5A).collect();
        assert_eq!(
            crack(&xor, &[], Want::Api),
            Some(("CreateThread".to_owned(), "xor 0x5A".to_owned()))
        );
        let rolling: Vec<u8> = b"VirtualProtect\0"
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ 0x31u8.wrapping_add(i as u8))
            .collect();
        assert_eq!(
            crack(&rolling, &[], Want::Api).map(|(_, scheme)| scheme),
            Some("rolling xor 0x31+i".to_owned())
        );
        let caesar: Vec<u8> = b"user32.dll\0".iter().map(|b| b.wrapping_add(3)).collect();
        assert_eq!(
            crack(&caesar, &[], Want::Module),
            Some(("user32.dll".to_owned(), "sub 0x03".to_owned()))
        );
        let noise: Vec<u8> = (0u8..32).map(|i| i.wrapping_mul(73) ^ 0xA5).collect();
        assert!(crack(&noise, &[], Want::Api).is_none());
        // Plain text is not a cipher, even where a case flip yields a known name.
        assert!(crack(
            b"n\0o\0r\0m\0a\0l\0i\0z\0.\0d\0l\0l\0\0\0",
            &[],
            Want::Module
        )
        .is_none());
        assert!(crack(b"kernel32.dll\0", &[], Want::Module).is_none());
    }
}
