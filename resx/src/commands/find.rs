use std::io::Write;

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter, Mnemonic, Register};
use serde::Serialize;

use crate::core::{color::Colors, config::Config, search::find_dll_path};
use crate::formats::pe::parse_pe;

const MATCH_BUDGET: usize = 65_536;

#[derive(Serialize)]
struct Match {
    rva: u32,
    file_offset: u64,
    section: String,
    mode: &'static str,
    text: String,
    transform: Option<String>,
}

#[derive(Serialize)]
struct Report {
    image: String,
    query: String,
    mode: String,
    decoded_instructions: usize,
    instruction_budget: usize,
    truncated: bool,
    matches: Vec<Match>,
}

pub fn run(image: &str, cfg: &Config, w: &mut dyn Write, c: &Colors) -> Result<(), String> {
    if image.is_empty() || cfg.find_pattern.trim().is_empty() {
        return Err(
            "Use `resx find <image> <query> [--find-mode raw|decoded|semantic] [--find-encoded]`"
                .into(),
        );
    }
    let path = find_dll_path(image, cfg)?;
    let raw = crate::core::input::read_image(&path).map_err(|e| e.to_string())?;
    let pe = parse_pe(&raw).map_err(|e| e.0)?;
    if !matches!(pe.machine, 0x14c | 0x8664) {
        return Err("Instruction finder supports x86 and x64 PE images".into());
    }
    let query = cfg.find_pattern.trim();
    let mode = effective_mode(&cfg.find_mode, query);
    let mut matches = Vec::new();
    let mut decoded = 0usize;
    let mut truncated = false;

    for section in pe.sections.iter().filter(|section| section.is_executable()) {
        let start = section.raw_offset as usize;
        let len = (section.raw_size as usize).min(raw.len().saturating_sub(start));
        if len == 0 || start >= raw.len() {
            continue;
        }
        let bytes = &raw[start..start + len];
        if mode == "raw" {
            let needle = parse_hex(query)?;
            raw_matches(bytes, &needle, section, "raw", None, &mut matches);
            if cfg.find_encoded {
                encoded_matches(bytes, &needle, section, &mut matches);
            }
        } else {
            let mut decoder = Decoder::with_ip(
                pe.arch,
                bytes,
                pe.image_base + section.virtual_address as u64,
                DecoderOptions::NONE,
            );
            let mut formatter = IntelFormatter::new();
            let mut instructions = Vec::new();
            while decoder.can_decode() && (cfg.find_budget == 0 || decoded < cfg.find_budget) {
                let instruction = decoder.decode();
                if instruction.is_invalid() {
                    continue;
                }
                let mut text = String::new();
                formatter.format(&instruction, &mut text);
                instructions.push((instruction, normalize(&text)));
                decoded += 1;
            }
            if decoder.can_decode() {
                truncated = true;
            }
            decoded_matches(
                &instructions,
                query,
                mode,
                section,
                pe.image_base,
                &mut matches,
            );
        }
        if matches.len() >= MATCH_BUDGET {
            matches.truncate(MATCH_BUDGET);
            truncated = true;
            break;
        }
        if cfg.find_budget > 0 && decoded >= cfg.find_budget {
            truncated = true;
            break;
        }
    }
    let report = Report {
        image: path.display().to_string(),
        query: query.into(),
        mode: mode.into(),
        decoded_instructions: decoded,
        instruction_budget: cfg.find_budget,
        truncated,
        matches,
    };
    if cfg.json {
        serde_json::to_writer_pretty(&mut *w, &report).map_err(|e| e.to_string())?;
        writeln!(w).ok();
    } else {
        writeln!(
            w,
            "{} {}",
            c.bold(&c.b_cyan("Instruction search:")),
            c.b_white(query)
        )
        .ok();
        writeln!(
            w,
            "  mode={}  matches={}  decoded={}",
            c.yellow(mode),
            c.ok(&report.matches.len().to_string()),
            report.decoded_instructions
        )
        .ok();
        let visible = if cfg.verbose {
            report.matches.len()
        } else {
            report.matches.len().min(64)
        };
        for item in report.matches.iter().take(visible) {
            let transform = item
                .transform
                .as_ref()
                .map(|v| format!(" [{}]", v))
                .unwrap_or_default();
            writeln!(
                w,
                "  {} {} {}{}",
                c.ok("✓"),
                c.b_blue(&format!("RVA 0x{:08X}", item.rva)),
                c.b_white(&item.text),
                c.magenta(&transform)
            )
            .ok();
        }
        if visible < report.matches.len() {
            writeln!(
                w,
                "  {}",
                c.dim(&format!(
                    "... {} more match(es); use --verbose or --json",
                    report.matches.len() - visible
                ))
            )
            .ok();
        }
        if report.truncated {
            writeln!(w, "{}", c.warn(&format!("search stopped at a bounded limit (instructions={}, matches={}); override with --find-budget <n|unlimited>", cfg.find_budget, MATCH_BUDGET))).ok();
        }
        if cfg.verbose {
            writeln!(
                w,
                "  image={} budget={} executable sections only",
                c.dim(&report.image),
                if cfg.find_budget == 0 {
                    "unlimited".to_owned()
                } else {
                    cfg.find_budget.to_string()
                }
            )
            .ok();
        }
    }
    Ok(())
}

fn effective_mode(requested: &str, query: &str) -> &'static str {
    if requested != "auto" {
        return match requested {
            "raw" => "raw",
            "decoded" => "decoded",
            _ => "semantic",
        };
    }
    let compact: String = query.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.len() >= 2
        && compact.len().is_multiple_of(2)
        && compact.chars().all(|c| c.is_ascii_hexdigit())
    {
        "raw"
    } else if semantic_kind(query).is_some() {
        "semantic"
    } else {
        "decoded"
    }
}

fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    let compact: String = input
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ':')
        .collect();
    if compact.is_empty()
        || !compact.len().is_multiple_of(2)
        || !compact.chars().all(|c| c.is_ascii_hexdigit())
    {
        return Err("raw query must be an even-length hexadecimal byte sequence".into());
    }
    (0..compact.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&compact[i..i + 2], 16).map_err(|_| "invalid raw hex query".into())
        })
        .collect()
}

fn raw_matches(
    bytes: &[u8],
    needle: &[u8],
    section: &crate::formats::pe::PeSection,
    mode: &'static str,
    transform: Option<String>,
    out: &mut Vec<Match>,
) {
    if needle.is_empty() || needle.len() > bytes.len() {
        return;
    }
    for (offset, window) in bytes.windows(needle.len()).enumerate() {
        if window == needle {
            out.push(Match {
                rva: section.virtual_address + offset as u32,
                file_offset: section.raw_offset as u64 + offset as u64,
                section: section.name.clone(),
                mode,
                text: needle
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" "),
                transform: transform.clone(),
            });
            if out.len() >= MATCH_BUDGET {
                return;
            }
        }
    }
}

fn encoded_matches(
    bytes: &[u8],
    needle: &[u8],
    section: &crate::formats::pe::PeSection,
    out: &mut Vec<Match>,
) {
    // A transform must cover the complete supplied pattern. This is deliberately not a sliding symbolic executor.
    for key in 1u16..=255 {
        let k = key as u8;
        for (name, encoded) in [
            (
                format!("xor 0x{k:02X}"),
                needle.iter().map(|b| b ^ k).collect::<Vec<_>>(),
            ),
            (
                format!("add 0x{k:02X}"),
                needle.iter().map(|b| b.wrapping_sub(k)).collect(),
            ),
            (
                format!("sub 0x{k:02X}"),
                needle.iter().map(|b| b.wrapping_add(k)).collect(),
            ),
        ] {
            raw_matches(bytes, &encoded, section, "raw", Some(name), out);
            if out.len() >= MATCH_BUDGET {
                return;
            }
        }
    }
    let not = needle.iter().map(|b| !b).collect::<Vec<_>>();
    raw_matches(bytes, &not, section, "raw", Some("not".into()), out);
    for bits in 1..8 {
        let encoded = needle
            .iter()
            .map(|b| b.rotate_right(bits))
            .collect::<Vec<_>>();
        raw_matches(
            bytes,
            &encoded,
            section,
            "raw",
            Some(format!("rol {bits}")),
            out,
        );
    }
    if needle.len() > 1 {
        let mut reversed = needle.to_vec();
        reversed.reverse();
        raw_matches(
            bytes,
            &reversed,
            section,
            "raw",
            Some("reverse bytes".into()),
            out,
        );
    }
}

fn decoded_matches(
    insns: &[(iced_x86::Instruction, String)],
    query: &str,
    mode: &str,
    section: &crate::formats::pe::PeSection,
    image_base: u64,
    out: &mut Vec<Match>,
) {
    let sequence = query
        .split(';')
        .map(normalize)
        .filter(|v| !v.is_empty())
        .collect::<Vec<_>>();
    if mode == "decoded" {
        for i in 0..insns.len() {
            if i + sequence.len() <= insns.len()
                && sequence
                    .iter()
                    .enumerate()
                    .all(|(n, q)| insns[i + n].1 == *q)
            {
                push_instruction(&insns[i], section, image_base, "decoded", query, out);
            }
        }
    } else if let Some(kind) = semantic_kind(query) {
        for (index, item) in insns.iter().enumerate() {
            let hit = match kind {
                "syscall" => matches!(item.0.mnemonic(), Mnemonic::Syscall | Mnemonic::Sysenter),
                "syscall-stub" => {
                    index + 2 < insns.len()
                        && item.0.mnemonic() == Mnemonic::Mov
                        && item.0.op0_register() == Register::R10
                        && item.0.op1_register() == Register::RCX
                        && insns[index + 1].0.mnemonic() == Mnemonic::Mov
                        && insns[index + 1].0.op0_register() == Register::EAX
                        && insns[index + 2..insns.len().min(index + 10)]
                            .iter()
                            .any(|candidate| {
                                matches!(
                                    candidate.0.mnemonic(),
                                    Mnemonic::Syscall | Mnemonic::Sysenter
                                )
                            })
                }
                "vm" => {
                    let m = format!("{:?}", item.0.mnemonic()).to_ascii_lowercase();
                    matches!(
                        item.0.mnemonic(),
                        Mnemonic::Cpuid | Mnemonic::Rdtsc | Mnemonic::Rdtscp | Mnemonic::Xgetbv
                    ) || m.starts_with("vm")
                        || m.starts_with("svm")
                }
                "privileged" => matches!(
                    item.0.mnemonic(),
                    Mnemonic::Cli
                        | Mnemonic::Sti
                        | Mnemonic::Hlt
                        | Mnemonic::Lgdt
                        | Mnemonic::Lidt
                        | Mnemonic::Lldt
                        | Mnemonic::Ltr
                        | Mnemonic::Invlpg
                        | Mnemonic::Rdmsr
                        | Mnemonic::Wrmsr
                ),
                _ => false,
            };
            if hit {
                push_instruction(item, section, image_base, "semantic", &item.1, out);
            }
        }
    }
}

fn semantic_kind(query: &str) -> Option<&'static str> {
    match normalize(query).as_str() {
        "syscall" | "syscalls" => Some("syscall"),
        "syscall stub" | "syscall stubs" | "syscall-style stubs" => Some("syscall-stub"),
        "vm" | "vm instructions" | "virtualization" => Some("vm"),
        "privileged" | "privileged instructions" => Some("privileged"),
        _ => None,
    }
}
fn normalize(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}
fn push_instruction(
    item: &(iced_x86::Instruction, String),
    section: &crate::formats::pe::PeSection,
    image_base: u64,
    mode: &'static str,
    text: &str,
    out: &mut Vec<Match>,
) {
    let rva = item.0.ip().saturating_sub(image_base) as u32;
    let within = rva.saturating_sub(section.virtual_address) as u64;
    let offset = section.raw_offset as u64 + within;
    out.push(Match {
        rva,
        file_offset: offset,
        section: section.name.clone(),
        mode,
        text: text.into(),
        transform: None,
    });
}
