use serde::Serialize;

use crate::formats::pe::PeFile;

#[derive(Debug, Clone, Serialize)]
pub struct EntropyReport {
    pub image: String,
    pub scope: String,
    pub window_size: usize,
    pub stride: usize,
    pub summary: EntropySummary,
    pub windows: Vec<EntropyWindow>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropySummary {
    pub window_count: usize,
    pub avg_entropy: f64,
    pub min_entropy: f64,
    pub max_entropy: f64,
    pub high_entropy_windows: usize,
    pub low_entropy_windows: usize,
    pub zero_heavy_windows: usize,
    pub ascii_heavy_windows: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct EntropyWindow {
    pub rva: String,
    pub end_rva: String,
    pub file_offset: String,
    pub section: String,
    pub size: usize,
    pub entropy: f64,
    pub ascii_ratio: f64,
    pub zero_ratio: f64,
    pub unique_ratio: f64,
    pub flags: Vec<String>,
}

pub fn analyze_entropy(
    image: &str,
    pe: &PeFile,
    raw: &[u8],
    window_size: usize,
    stride: usize,
    include_all_sections: bool,
) -> EntropyReport {
    let window_size = window_size.clamp(64, 1024 * 1024);
    let stride = stride.clamp(1, window_size);
    let mut windows = Vec::new();

    for section in &pe.sections {
        if !include_all_sections && !section.is_executable() {
            continue;
        }
        if section.raw_size == 0 {
            continue;
        }
        let start = section.raw_offset as usize;
        if start >= raw.len() {
            continue;
        }
        let mapped_size = if section.virtual_size == 0 {
            section.raw_size
        } else {
            section.virtual_size.min(section.raw_size)
        };
        let len = (mapped_size as usize).min(raw.len().saturating_sub(start));
        if len == 0 {
            continue;
        }
        let mut pos = 0usize;
        while pos < len {
            let win_len = window_size.min(len - pos);
            if win_len < 32 {
                break;
            }
            let bytes = &raw[start + pos..start + pos + win_len];
            let rva = section.virtual_address.saturating_add(pos as u32);
            let entropy = shannon_entropy(bytes);
            let ascii_ratio = ratio(
                bytes
                    .iter()
                    .filter(|&&b| (0x20..=0x7E).contains(&b))
                    .count(),
                win_len,
            );
            let zero_ratio = ratio(bytes.iter().filter(|&&b| b == 0).count(), win_len);
            let unique_ratio = unique_ratio(bytes);
            let flags = classify(entropy, ascii_ratio, zero_ratio, unique_ratio);
            windows.push(EntropyWindow {
                rva: format!("0x{rva:08X}"),
                end_rva: format!("0x{:08X}", rva.saturating_add(win_len as u32)),
                file_offset: format!("0x{:X}", start + pos),
                section: section.name.clone(),
                size: win_len,
                entropy: round3(entropy),
                ascii_ratio: round3(ascii_ratio),
                zero_ratio: round3(zero_ratio),
                unique_ratio: round3(unique_ratio),
                flags,
            });
            if pos + win_len >= len {
                break;
            }
            pos = pos.saturating_add(stride);
        }
    }

    let summary = summarize(&windows);
    EntropyReport {
        image: image.to_owned(),
        scope: if include_all_sections {
            "all-sections".to_owned()
        } else {
            "executable-sections".to_owned()
        },
        window_size,
        stride,
        summary,
        windows,
    }
}

fn summarize(windows: &[EntropyWindow]) -> EntropySummary {
    if windows.is_empty() {
        return EntropySummary {
            window_count: 0,
            avg_entropy: 0.0,
            min_entropy: 0.0,
            max_entropy: 0.0,
            high_entropy_windows: 0,
            low_entropy_windows: 0,
            zero_heavy_windows: 0,
            ascii_heavy_windows: 0,
        };
    }
    let mut min_entropy = f64::MAX;
    let mut max_entropy = f64::MIN;
    let mut total = 0.0;
    let mut high_entropy_windows = 0usize;
    let mut low_entropy_windows = 0usize;
    let mut zero_heavy_windows = 0usize;
    let mut ascii_heavy_windows = 0usize;
    for w in windows {
        min_entropy = min_entropy.min(w.entropy);
        max_entropy = max_entropy.max(w.entropy);
        total += w.entropy;
        if w.entropy >= 7.15 {
            high_entropy_windows += 1;
        }
        if w.entropy <= 2.0 {
            low_entropy_windows += 1;
        }
        if w.zero_ratio >= 0.25 {
            zero_heavy_windows += 1;
        }
        if w.ascii_ratio >= 0.65 {
            ascii_heavy_windows += 1;
        }
    }
    EntropySummary {
        window_count: windows.len(),
        avg_entropy: round3(total / windows.len() as f64),
        min_entropy: round3(min_entropy),
        max_entropy: round3(max_entropy),
        high_entropy_windows,
        low_entropy_windows,
        zero_heavy_windows,
        ascii_heavy_windows,
    }
}

fn classify(entropy: f64, ascii_ratio: f64, zero_ratio: f64, unique_ratio: f64) -> Vec<String> {
    let mut flags = Vec::new();
    if entropy >= 7.15 {
        flags.push("high-entropy".to_owned());
    } else if entropy <= 2.0 {
        flags.push("low-entropy".to_owned());
    }
    if zero_ratio >= 0.25 {
        flags.push("zero-heavy".to_owned());
    }
    if ascii_ratio >= 0.65 {
        flags.push("ascii-heavy".to_owned());
    }
    if unique_ratio >= 0.75 && entropy >= 6.5 {
        flags.push("byte-diverse".to_owned());
    }
    flags
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&count| count != 0)
        .map(|&count| {
            let p = count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn unique_ratio(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut seen = [false; 256];
    let mut count = 0usize;
    for &b in bytes {
        let slot = &mut seen[b as usize];
        if !*slot {
            *slot = true;
            count += 1;
        }
    }
    count as f64 / bytes.len().min(256) as f64
}

fn ratio(count: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        count as f64 / total as f64
    }
}

fn round3(value: f64) -> f64 {
    let rounded = (value * 1000.0).round() / 1000.0;
    if rounded == 0.0 {
        0.0
    } else {
        rounded
    }
}
