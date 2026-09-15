#![forbid(unsafe_code)]

//! Bounded RFC 1950/1951/1952 decoding. No sample code is executed.
pub const MAX_OUTPUT: usize = 16 * 1024 * 1024;

struct Bits<'a> {
    data: &'a [u8],
    bit: usize,
}
impl Bits<'_> {
    fn take(&mut self, count: usize) -> Result<u32, String> {
        if count > 16
            || self
                .bit
                .checked_add(count)
                .is_none_or(|n| n > self.data.len() * 8)
        {
            return Err("Truncated DEFLATE bit stream".into());
        }
        let mut value = 0;
        for n in 0..count {
            value |= u32::from((self.data[self.bit / 8] >> (self.bit % 8)) & 1) << n;
            self.bit += 1;
        }
        Ok(value)
    }
    fn aligned(&mut self) {
        self.bit = (self.bit + 7) & !7;
    }
}

struct Huffman {
    count: [u32; 16],
    first: [u32; 16],
    offset: [usize; 16],
    symbols: Vec<u16>,
}
impl Huffman {
    fn new(lengths: &[u8], single: bool, empty: bool) -> Result<Self, String> {
        let mut result = Self {
            count: [0; 16],
            first: [0; 16],
            offset: [0; 16],
            symbols: Vec::new(),
        };
        for &length in lengths {
            if length > 15 {
                return Err("Invalid Huffman length".into());
            }
            if length != 0 {
                result.count[length as usize] += 1;
            }
        }
        let used: u32 = result.count.iter().sum();
        if used == 0 {
            if empty {
                return Ok(result);
            }
            return Err("Empty Huffman tree".into());
        }
        let mut left = 1i32;
        let mut code = 0;
        for length in 1..16 {
            left = left * 2 - result.count[length] as i32;
            if left < 0 {
                return Err("Oversubscribed Huffman tree".into());
            }
            code = (code + result.count[length - 1]) * 2;
            result.first[length] = code;
            result.offset[length] = result.symbols.len();
            for (symbol, &value) in lengths.iter().enumerate() {
                if value as usize == length {
                    result.symbols.push(symbol as u16);
                }
            }
        }
        if left != 0 && !(single && used == 1 && result.count[1] == 1) {
            return Err("Incomplete Huffman tree".into());
        }
        Ok(result)
    }
    fn decode(&self, bits: &mut Bits<'_>) -> Result<usize, String> {
        let mut code = 0;
        for length in 1..16 {
            code = (code << 1) | bits.take(1)?;
            if let Some(index) = code.checked_sub(self.first[length]) {
                if index < self.count[length] {
                    return Ok(self.symbols[self.offset[length] + index as usize] as usize);
                }
            }
        }
        Err("Invalid Huffman code".into())
    }
}

fn dynamic(bits: &mut Bits<'_>) -> Result<(Huffman, Huffman), String> {
    let literals = bits.take(5)? as usize + 257;
    let distances = bits.take(5)? as usize + 1;
    let codes = bits.take(4)? as usize + 4;
    if literals > 286 {
        return Err("Reserved DEFLATE literal count".into());
    }
    let order = [
        16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
    ];
    let mut lengths = [0u8; 19];
    for &index in &order[..codes] {
        lengths[index] = bits.take(3)? as u8;
    }
    let tree = Huffman::new(&lengths, false, false)?;
    let mut values: Vec<u8> = Vec::new();
    while values.len() < literals + distances {
        let symbol = tree.decode(bits)?;
        let (value, amount) = match symbol {
            0..=15 => (symbol as u8, 1),
            16 => (
                *values
                    .last()
                    .ok_or("Huffman repeat has no previous length")?,
                bits.take(2)? as usize + 3,
            ),
            17 => (0, bits.take(3)? as usize + 3),
            18 => (0, bits.take(7)? as usize + 11),
            _ => return Err("Invalid code-length symbol".into()),
        };
        if values.len() + amount > literals + distances {
            return Err("Huffman repeat exceeds declared table".into());
        }
        values.resize(values.len() + amount, value);
    }
    if values[256] == 0 {
        return Err("Missing end-of-block symbol".into());
    }
    Ok((
        Huffman::new(&values[..literals], true, false)?,
        Huffman::new(&values[literals..], true, true)?,
    ))
}

fn inflate(data: &[u8], limit: usize, window: usize) -> Result<(Vec<u8>, usize), String> {
    let mut bits = Bits { data, bit: 0 };
    let mut output = Vec::new();
    let mut blocks = 0;
    loop {
        blocks += 1;
        if blocks > 65536 {
            return Err("DEFLATE block budget exceeded".into());
        }
        let final_block = bits.take(1)? != 0;
        let kind = bits.take(2)?;
        if kind == 0 {
            bits.aligned();
            let length = bits.take(16)? as usize;
            let complement = bits.take(16)? as usize;
            if length ^ complement != 0xffff {
                return Err("Stored block length complement mismatch".into());
            }
            if output.len() + length > limit {
                return Err("Decoded output/expansion budget exceeded".into());
            }
            let start = bits.bit / 8;
            output.extend_from_slice(
                data.get(start..start + length)
                    .ok_or("Truncated stored block")?,
            );
            bits.bit += length * 8;
        } else if kind == 1 || kind == 2 {
            let (literals, distances) = if kind == 1 {
                let lengths: Vec<_> = (0..288)
                    .map(|s| match s {
                        0..=143 => 8,
                        144..=255 => 9,
                        256..=279 => 7,
                        _ => 8,
                    })
                    .collect();
                (
                    Huffman::new(&lengths, false, false)?,
                    Huffman::new(&[5; 32], false, false)?,
                )
            } else {
                dynamic(&mut bits)?
            };
            loop {
                let symbol = literals.decode(&mut bits)?;
                if symbol < 256 {
                    if output.len() == limit {
                        return Err("Decoded output/expansion budget exceeded".into());
                    }
                    output.push(symbol as u8);
                } else if symbol == 256 {
                    break;
                } else {
                    const LENGTH: [usize; 29] = [
                        3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59,
                        67, 83, 99, 115, 131, 163, 195, 227, 258,
                    ];
                    const LENGTH_BITS: [usize; 29] = [
                        0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5,
                        5, 5, 5, 0,
                    ];
                    if symbol > 285 {
                        return Err("Reserved length symbol".into());
                    }
                    let length =
                        LENGTH[symbol - 257] + bits.take(LENGTH_BITS[symbol - 257])? as usize;
                    let distance = distances.decode(&mut bits)?;
                    const DISTANCE: [usize; 30] = [
                        1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513,
                        769, 1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
                    ];
                    if distance >= 30 {
                        return Err("Reserved distance symbol".into());
                    }
                    let extra = if distance < 4 { 0 } else { distance / 2 - 1 };
                    let back = DISTANCE[distance] + bits.take(extra)? as usize;
                    if back > output.len() || back > window {
                        return Err(
                            "DEFLATE distance exceeds available output or declared window".into(),
                        );
                    }
                    if output.len() + length > limit {
                        return Err("Decoded output/expansion budget exceeded".into());
                    }
                    for _ in 0..length {
                        output.push(output[output.len() - back]);
                    }
                }
            }
        } else {
            return Err("Reserved DEFLATE block type".into());
        }
        if final_block {
            break;
        }
    }
    Ok((output, bits.bit.div_ceil(8)))
}

pub fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb88320u32 & (0u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}
fn adler32(bytes: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in bytes.chunks(5552) {
        for &byte in chunk {
            a += u32::from(byte);
            b += a;
        }
        a %= 65521;
        b %= 65521;
    }
    (b << 16) | a
}

pub fn decode(codec: &str, input: &[u8]) -> Result<Vec<u8>, String> {
    if input.len() > MAX_OUTPUT {
        return Err("Encoded input exceeds 16 MiB".into());
    }
    let limit = input.len().saturating_mul(256).clamp(4096, MAX_OUTPUT);
    match codec {
        "deflate" => {
            let (output, used) = inflate(input, limit, 32768)?;
            if used != input.len() {
                return Err("Trailing DEFLATE data".into());
            }
            Ok(output)
        }
        "zlib" => {
            if input.len() < 6
                || input[0] & 15 != 8
                || input[0] >> 4 > 7
                || !u16::from_be_bytes([input[0], input[1]]).is_multiple_of(31)
            {
                return Err("Invalid zlib header".into());
            }
            if input[1] & 0x20 != 0 {
                return Err("zlib preset dictionary is unavailable".into());
            }
            let window = 1usize << ((input[0] >> 4) + 8);
            let (output, used) = inflate(&input[2..], limit, window)?;
            if used + 6 != input.len() {
                return Err("zlib extent/trailer mismatch".into());
            }
            if adler32(&output) != u32::from_be_bytes(input[input.len() - 4..].try_into().unwrap())
            {
                return Err("zlib Adler-32 mismatch".into());
            }
            Ok(output)
        }
        "gzip" => {
            if input.len() < 18 || input[..3] != [0x1f, 0x8b, 8] || input[3] & 0xe0 != 0 {
                return Err("Invalid gzip header".into());
            }
            let flags = input[3];
            let mut at = 10usize;
            if flags & 4 != 0 {
                let n = u16::from_le_bytes(
                    input
                        .get(at..at + 2)
                        .ok_or("Truncated gzip extra length")?
                        .try_into()
                        .unwrap(),
                ) as usize;
                at += 2 + n;
            }
            for flag in [8, 16] {
                if flags & flag != 0 {
                    let tail = input.get(at..).ok_or("Truncated gzip field")?;
                    at += tail
                        .iter()
                        .take(4096)
                        .position(|b| *b == 0)
                        .ok_or("Unterminated/oversized gzip field")?
                        + 1;
                }
            }
            if flags & 2 != 0 {
                let expected = u16::from_le_bytes(
                    input
                        .get(at..at + 2)
                        .ok_or("Truncated gzip header checksum")?
                        .try_into()
                        .unwrap(),
                );
                if crc32(&input[..at]) as u16 != expected {
                    return Err("gzip header checksum mismatch".into());
                }
                at += 2;
            }
            let (output, used) =
                inflate(input.get(at..).ok_or("Truncated gzip body")?, limit, 32768)?;
            let end = at + used;
            if end + 8 != input.len() {
                return Err("gzip trailing members/data are unsupported".into());
            }
            if crc32(&output) != u32::from_le_bytes(input[end..end + 4].try_into().unwrap())
                || output.len() as u32 != u32::from_le_bytes(input[end + 4..].try_into().unwrap())
            {
                return Err("gzip checksum/size mismatch".into());
            }
            Ok(output)
        }
        "hex" => {
            let bytes: Vec<_> = input
                .iter()
                .copied()
                .filter(|b| !b.is_ascii_whitespace())
                .collect();
            if bytes.len() % 2 != 0 {
                return Err("Odd-length hex input".into());
            }
            bytes
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| {
                    let h = (p[0] as char).to_digit(16).ok_or("Invalid hex digit")?;
                    let l = (p[1] as char).to_digit(16).ok_or("Invalid hex digit")?;
                    Ok((h * 16 + l) as u8)
                })
                .collect()
        }
        "base64" => base64(input),
        _ => Err("Unsupported codec".into()),
    }
}

fn base64(input: &[u8]) -> Result<Vec<u8>, String> {
    let data: Vec<_> = input
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if data.len() % 4 != 0 {
        return Err("Base64 length must be a multiple of four".into());
    }
    let mut out = Vec::new();
    for (index, p) in data.as_chunks::<4>().0.iter().enumerate() {
        let last = (index + 1) * 4 == data.len();
        let digit = |b: u8| -> Result<u32, String> {
            match b {
                b'A'..=b'Z' => Ok(u32::from(b - b'A')),
                b'a'..=b'z' => Ok(u32::from(b - b'a' + 26)),
                b'0'..=b'9' => Ok(u32::from(b - b'0' + 52)),
                b'+' => Ok(62),
                b'/' => Ok(63),
                _ => Err("Invalid base64 digit".into()),
            }
        };
        let a = digit(p[0])?;
        let b = digit(p[1])?;
        let c = if p[2] == b'=' { 0 } else { digit(p[2])? };
        let d = if p[3] == b'=' { 0 } else { digit(p[3])? };
        if (p[2] == b'=' && (p[3] != b'=' || b & 15 != 0))
            || (p[3] == b'=' && p[2] != b'=' && c & 3 != 0)
            || (!last && (p[2] == b'=' || p[3] == b'='))
        {
            return Err("Noncanonical base64 padding".into());
        }
        out.push(((a << 2) | (b >> 4)) as u8);
        if p[2] != b'=' {
            out.push(((b << 4) | (c >> 2)) as u8);
        }
        if p[3] != b'=' {
            out.push(((c << 6) | d) as u8);
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn known_vectors_and_corrupt_trailers() {
        let input = decode("hex", b"789ccb48cdc9c957c84090003a2e067d").unwrap();
        assert_eq!(decode("zlib", &input).unwrap(), b"hello hello hello");
        let mut corrupt = input;
        *corrupt.last_mut().unwrap() ^= 1;
        assert!(decode("zlib", &corrupt).unwrap_err().contains("Adler"));
        assert_eq!(decode("base64", b"aGVsbG8=").unwrap(), b"hello");
        assert!(decode("base64", b"Zh==").is_err());
        assert!(decode("base64", b"Zg==AAAA").is_err());
    }
    #[test]
    fn malformed_trees_and_truncation_reject() {
        assert!(Huffman::new(&[1, 1, 1], false, false).is_err());
        assert!(Huffman::new(&[2, 2], true, false).is_err());
        assert!(decode("deflate", &[7]).is_err());
        assert!(decode("deflate", &[1, 2, 0, 0, 0]).is_err());
        let input = decode("hex", b"789ccb48cdc9c957c84090003a2e067d").unwrap();
        for length in 0..input.len() {
            assert!(decode("zlib", &input[..length]).is_err());
        }
    }

    #[test]
    fn zlib_window_is_enforced_even_with_a_valid_output_checksum() {
        // A non-final stored block of 257 bytes, followed by a fixed block:
        // length 3, distance 257, end-of-block. This needs more than 256 history bytes.
        let mut deflate = vec![0, 1, 1, 0xfe, 0xfe];
        deflate.extend([b'A'; 257]);
        let mut bits = Vec::new();
        for (value, width) in [(3u32, 3), (64, 7), (1, 5), (0, 7), (0, 7)] {
            for bit in 0..width {
                bits.push(((value >> bit) & 1) as u8);
            }
        }
        for group in bits.chunks(8) {
            deflate.push(
                group
                    .iter()
                    .enumerate()
                    .fold(0, |byte, (bit, value)| byte | (value << bit)),
            );
        }
        assert_eq!(decode("deflate", &deflate).unwrap(), vec![b'A'; 260]);
        let mut framed = vec![0x08, 0x1d];
        framed.extend(deflate);
        framed.extend(adler32(&[b'A'; 260]).to_be_bytes());
        assert!(decode("zlib", &framed)
            .unwrap_err()
            .contains("declared window"));
        framed[..2].copy_from_slice(&[0x78, 0x01]);
        assert_eq!(decode("zlib", &framed).unwrap(), vec![b'A'; 260]);
    }
}
