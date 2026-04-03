use std::io::Write;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};

use iced_x86::Mnemonic;

use crate::analysis::disasm::{is_jcc, is_jmp, is_ret, is_sys, Instruction};
use crate::analysis::yara::YaraMatch;
use crate::core::color::Colors;
use crate::core::config::Config;
use crate::formats::pe::{Export, ImportDll, PeAnomaly, PeFile};

pub struct ProgressBar {
    pub total: usize,
    done: AtomicUsize,
    active: bool,
    color: bool,
}

struct AsyncLane {
    done: AtomicUsize,
    label: Mutex<String>,
}

pub struct AsyncProgress {
    total: usize,
    done: AtomicUsize,
    lanes: Vec<AsyncLane>,
    active: bool,
    color: bool,
    render_lock: Mutex<()>,
    render_every: usize,
}

impl AsyncProgress {
    pub fn new(total: usize, lanes: usize, active: bool, color: bool) -> Self {
        let lane_count = lanes.max(1);
        let active = active && total > 0;
        let lanes = (0..lane_count)
            .map(|_| AsyncLane {
                done: AtomicUsize::new(0),
                label: Mutex::new(String::new()),
            })
            .collect();
        if active {
            for _ in 0..=lane_count {
                eprintln!();
            }
            let _ = std::io::stderr().flush();
        }
        Self {
            total,
            done: AtomicUsize::new(0),
            lanes,
            active,
            color,
            render_lock: Mutex::new(()),
            render_every: (total / 64).max(1),
        }
    }

    pub fn tick(&self, lane: usize, label: &str) {
        if !self.active {
            return;
        }
        let lane = lane.min(self.lanes.len().saturating_sub(1));
        let done = self.done.fetch_add(1, Ordering::Relaxed) + 1;
        self.lanes[lane].done.fetch_add(1, Ordering::Relaxed);
        *self.lanes[lane].label.lock().unwrap() = label.to_owned();
        if done == self.total || done.is_multiple_of(self.render_every) {
            self.render();
        }
    }

    fn render(&self) {
        let _g = self.render_lock.lock().unwrap();
        eprint!("\x1b[{}A", self.lanes.len() + 1);
        let done = self.done.load(Ordering::Relaxed).min(self.total);
        let beam = render_beam(30, done, self.color);
        if self.color {
            eprint!(
                "\r\x1b[2K  {}  {:>6}/{:<6}  \x1b[2mtotal jobs\x1b[0m\n",
                beam, done, self.total
            );
        } else {
            eprint!(
                "\r\x1b[2K  {}  {:>6}/{:<6}  total jobs\n",
                beam, done, self.total
            );
        }

        for (idx, lane) in self.lanes.iter().enumerate() {
            let lane_done = lane.done.load(Ordering::Relaxed);
            let lane_beam = render_beam(18, lane_done, self.color);
            let label = lane.label.lock().unwrap().clone();
            let label = trunc_label(&label, 42);
            if self.color {
                eprint!(
                    "\r\x1b[2K  {}  \x1b[2mworker {:>2}\x1b[0m  {:>6}  \x1b[2m{:<42}\x1b[0m\n",
                    lane_beam,
                    idx + 1,
                    lane_done,
                    label
                );
            } else {
                eprint!(
                    "\r\x1b[2K  {}  worker {:>2}  {:>6}  {:<42}\n",
                    lane_beam,
                    idx + 1,
                    lane_done,
                    label
                );
            }
        }
        let _ = std::io::stderr().flush();
    }

    pub fn finish(&self) {
        if !self.active {
            return;
        }
        let _g = self.render_lock.lock().unwrap();
        eprint!(
            "\x1b[{}A\x1b[{}M",
            self.lanes.len() + 1,
            self.lanes.len() + 1
        );
        let _ = std::io::stderr().flush();
    }
}

impl ProgressBar {
    pub fn new(total: usize, active: bool, color: bool) -> Self {
        Self {
            total,
            active,
            color,
            done: AtomicUsize::new(0),
        }
    }

    pub fn tick(&self, label: &str) {
        if !self.active {
            return;
        }
        let n = self.done.fetch_add(1, Ordering::Relaxed) + 1;
        let beam = render_beam(30, n, self.color);
        let label = trunc_label(label, 38);
        eprint!("\r  {}  {:>5}/{:<5}  {:<38}", beam, n, self.total, label);
    }

    pub fn finish(&self) {
        if !self.active {
            return;
        }
        eprint!("\r{}\r", " ".repeat(85));
        let _ = std::io::Write::flush(&mut std::io::stderr());
    }
}

fn trunc_label(s: &str, max_chars: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() <= max_chars {
        s.to_owned()
    } else {
        chars[chars.len() - max_chars..].iter().collect()
    }
}

fn render_beam(width: usize, n: usize, color: bool) -> String {
    let cycle = if width > 1 { 2 * (width - 1) } else { 1 };
    let p = n % cycle;
    let pos = if p < width { p } else { cycle - p };
    if color {
        format!(
            "\x1b[2m{}\x1b[0m\x1b[96m●\x1b[0m\x1b[2m{}\x1b[0m",
            "·".repeat(pos),
            "·".repeat(width - pos - 1),
        )
    } else {
        (0..width)
            .map(|i| if i == pos { '●' } else { '·' })
            .collect()
    }
}

pub struct StageProgress {
    total: usize,
    done: usize,
    active: bool,
    color: bool,
}

impl StageProgress {
    pub fn new(total: usize, active: bool, color: bool) -> Self {
        Self {
            total: total.max(1),
            done: 0,
            active,
            color,
        }
    }

    pub fn tick(&mut self, label: &str) {
        if !self.active {
            return;
        }
        self.done = (self.done + 1).min(self.total);
        let beam = render_beam(30, self.done, self.color);
        let label = trunc_label(label, 38);
        eprint!(
            "\r  {}  {:>2}/{:<2}  {:<38}",
            beam, self.done, self.total, label
        );
        let _ = std::io::stderr().flush();
    }

    pub fn finish(&self) {
        if !self.active {
            return;
        }
        eprint!("\r{}\r", " ".repeat(85));
        let _ = std::io::stderr().flush();
    }
}

pub(crate) fn apply_insn_color(insn: &Instruction, s: &str, c: &Colors) -> String {
    let m = insn.iced.mnemonic();
    if insn.bytes.len() == 1 && insn.bytes[0] == 0xCC {
        return c.dim(s);
    }
    if is_ret(m) {
        return c.b_red(s);
    }
    if is_sys(m) {
        return c.b_mag(s);
    }
    if m == Mnemonic::Call {
        return c.b_yellow(s);
    }
    if is_jmp(m) {
        return c.yellow(s);
    }
    if is_jcc(m) {
        return c.b_cyan(s);
    }
    if matches!(m, Mnemonic::Cmp | Mnemonic::Test) {
        return c.magenta(s);
    }
    if matches!(m, Mnemonic::Push | Mnemonic::Pop) {
        return c.dim(s);
    }
    if matches!(
        m,
        Mnemonic::Add
            | Mnemonic::Sub
            | Mnemonic::Imul
            | Mnemonic::And
            | Mnemonic::Or
            | Mnemonic::Xor
            | Mnemonic::Shl
            | Mnemonic::Shr
            | Mnemonic::Sar
            | Mnemonic::Inc
            | Mnemonic::Dec
            | Mnemonic::Neg
            | Mnemonic::Not
    ) {
        return c.green(s);
    }
    if m == Mnemonic::Nop {
        return c.dim(s);
    }
    c.b_white(s)
}

pub(crate) fn highlight_symbolic_text(text: &str, c: &Colors) -> String {
    let mut out = String::new();
    let mut token = String::new();

    for ch in text.chars() {
        if is_symbol_char(ch) {
            token.push(ch);
            continue;
        }
        if !token.is_empty() {
            out.push_str(&highlight_symbol_token(&token, c));
            token.clear();
        }
        out.push(ch);
    }

    if !token.is_empty() {
        out.push_str(&highlight_symbol_token(&token, c));
    }

    out
}

fn is_symbol_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '!' | '?' | '@' | '$' | '.' | '+' | '-')
}

#[derive(Clone, Copy)]
struct SymbolStyle {
    prefix: &'static str,
    colorize: fn(&Colors, &str) -> String,
}

fn subsystem_symbol_style(label: &str) -> Option<SymbolStyle> {
    const STYLES: &[SymbolStyle] = &[
        SymbolStyle {
            prefix: "FsRtl",
            colorize: Colors::b_cyan,
        },
        SymbolStyle {
            prefix: "Psp",
            colorize: Colors::green,
        },
        SymbolStyle {
            prefix: "Sep",
            colorize: Colors::b_mag,
        },
        SymbolStyle {
            prefix: "Cmp",
            colorize: Colors::magenta,
        },
        SymbolStyle {
            prefix: "Rtl",
            colorize: Colors::cyan,
        },
        SymbolStyle {
            prefix: "Etw",
            colorize: Colors::green,
        },
        SymbolStyle {
            prefix: "Hal",
            colorize: Colors::yellow,
        },
        SymbolStyle {
            prefix: "Ke",
            colorize: Colors::b_blue,
        },
        SymbolStyle {
            prefix: "Ki",
            colorize: Colors::b_blue,
        },
        SymbolStyle {
            prefix: "Mm",
            colorize: Colors::b_cyan,
        },
        SymbolStyle {
            prefix: "Cm",
            colorize: Colors::magenta,
        },
        SymbolStyle {
            prefix: "Io",
            colorize: Colors::b_yellow,
        },
        SymbolStyle {
            prefix: "Po",
            colorize: Colors::yellow,
        },
        SymbolStyle {
            prefix: "Cc",
            colorize: Colors::cyan,
        },
        SymbolStyle {
            prefix: "Ex",
            colorize: Colors::green,
        },
        SymbolStyle {
            prefix: "Ps",
            colorize: Colors::b_cyan,
        },
        SymbolStyle {
            prefix: "Se",
            colorize: Colors::b_mag,
        },
        SymbolStyle {
            prefix: "Ob",
            colorize: Colors::b_white,
        },
        SymbolStyle {
            prefix: "Base",
            colorize: Colors::b_cyan,
        },
    ];

    STYLES.iter().copied().find(|style| {
        label.starts_with(style.prefix)
            && label
                .as_bytes()
                .get(style.prefix.len())
                .is_some_and(|b| b.is_ascii_uppercase())
    })
}

fn is_nt_symbol(label: &str) -> bool {
    (label.starts_with("Nt") || label.starts_with("Zw"))
        && label
            .as_bytes()
            .get(2)
            .is_some_and(|b| b.is_ascii_uppercase())
}

fn looks_named_symbol(label: &str) -> bool {
    label.len() > 3
        && label.chars().any(|ch| ch.is_ascii_uppercase())
        && label.chars().any(|ch| ch.is_ascii_lowercase())
}

fn highlight_symbol_token(token: &str, c: &Colors) -> String {
    if let Some((dll, sym)) = token.split_once('!') {
        let right = highlight_symbol_token(sym, c);
        return format!("{}!{}", c.dim(dll), right);
    }

    if let Some(rest) = token.strip_prefix("_imp_") {
        return format!("{}{}", c.dim("_imp_"), highlight_symbol_token(rest, c));
    }

    if is_nt_symbol(token) {
        return c.b_red(token);
    }
    if token.starts_with("sub_") {
        return c.yellow(token);
    }
    if let Some(style) = subsystem_symbol_style(token) {
        return (style.colorize)(c, token);
    }
    if looks_named_symbol(token) {
        return c.b_white(token);
    }

    token.to_owned()
}

pub fn print_insns(w: &mut dyn Write, insns: &[Instruction], cfg: &Config, c: &Colors) {
    let addr_w = if cfg.addr_width == 0 {
        8
    } else {
        cfg.addr_width
    };
    let byte_col_w = if cfg.byte_col_width == 0 {
        10
    } else {
        cfg.byte_col_width
    };

    for insn in insns {
        let addr = c.cyan(&format!("{:0>width$X}", insn.rva, width = addr_w));

        let byte_str = if cfg.show_bytes {
            let hex: Vec<String> = insn.bytes.iter().map(|b| format!("{:02X}", b)).collect();
            let raw = hex.join(" ");
            let pad_w = byte_col_w * 3 - 1;
            let padded = if raw.len() < pad_w {
                format!("{}{}", raw, " ".repeat(pad_w - raw.len()))
            } else {
                raw[..pad_w.min(raw.len())].to_owned()
            };
            format!("{}  ", c.dim(&padded))
        } else {
            String::new()
        };

        let mnem = apply_insn_color(insn, &format!("{:<10}", insn.mnemonic), c);
        let ops = highlight_symbolic_text(&insn.operands, c);

        let mut line = format!("  {}  {}{} {}", addr, byte_str, mnem, ops);
        if !insn.comment.is_empty() {
            line.push_str(&format!(
                "{}{}",
                c.dim("  ; "),
                highlight_symbolic_text(&insn.comment, c)
            ));
        }
        if cfg.show_offsets {
            line.push_str(&c.dim(&format!("  [off: 0x{:X}]", insn.file_off)));
        }
        writeln!(w, "{}", line).ok();
    }
}

pub fn print_eat(w: &mut dyn Write, exports: &[Export], dll_name: &str, c: &Colors) {
    writeln!(w).ok();
    writeln!(
        w,
        "{}",
        c.bold(&c.b_yellow(&format!(
            "Export Table: {} ({} exports)",
            dll_name,
            exports.len()
        )))
    )
    .ok();
    writeln!(
        w,
        "  {:<6}  {:<10}  {}",
        c.bold("ORD"),
        c.bold("RVA"),
        c.bold("NAME")
    )
    .ok();
    for e in exports {
        let suffix = if !e.forward_to.is_empty() {
            c.dim(&format!("  → {} [fwd]", e.forward_to))
        } else {
            String::new()
        };
        writeln!(
            w,
            "  {:<6}  0x{:08X}  {}{}",
            e.ordinal,
            e.rva,
            c.b_white(&e.name),
            suffix
        )
        .ok();
    }
}

pub fn print_iat(w: &mut dyn Write, imps: &[ImportDll], dll_name: &str, c: &Colors) {
    let total: usize = imps.iter().map(|d| d.entries.len()).sum();
    writeln!(w).ok();
    writeln!(
        w,
        "{}",
        c.bold(&c.b_blue(&format!(
            "Import Table: {} ({} DLLs, {} imports)",
            dll_name,
            imps.len(),
            total
        )))
    )
    .ok();
    for d in imps {
        writeln!(w, "  {} {}", c.bold(&c.cyan("DLL:")), c.b_yellow(&d.dll)).ok();
        for e in &d.entries {
            let hint = if !e.by_ord {
                c.dim(&format!("  (hint: 0x{:03X})", e.hint))
            } else {
                String::new()
            };
            writeln!(w, "    {}{}", c.b_white(&e.name), hint).ok();
        }
    }
}

pub fn print_sections(w: &mut dyn Write, pe: &PeFile, c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_blue("Sections:"))).ok();
    writeln!(
        w,
        "  {:<10} {:<10} {:<10} {:<10} {:<4} {:<22} {:<22} {:<8} {}",
        c.bold("NAME"),
        c.bold("RVA"),
        c.bold("VSIZE"),
        c.bold("RAW"),
        c.bold("TAG"),
        c.bold("PROTECTION"),
        c.bold("EXPECTED"),
        c.bold("ENTROPY"),
        c.bold("NOTES")
    )
    .ok();
    for s in &pe.sections {
        let notes = s.unusual_protection_reason().unwrap_or_default();
        let notes = if notes.is_empty() {
            String::new()
        } else {
            c.warn(&notes)
        };
        writeln!(
            w,
            "  {:<10} 0x{:08X} 0x{:08X} 0x{:08X} {:<4} {:<22} {:<22} {:<8.3} {}",
            c.b_white(&s.name),
            s.virtual_address,
            s.virtual_size,
            s.raw_size,
            s.protection_string(),
            s.protection_name(),
            s.normal_expectation_name(),
            s.entropy,
            notes
        )
        .ok();
    }
}

pub fn print_pe_anomalies(w: &mut dyn Write, anomalies: &[PeAnomaly], c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_mag("PE Header / Layout Check:"))).ok();
    if anomalies.is_empty() {
        writeln!(w, "{}", c.ok("No header or section anomalies detected")).ok();
        return;
    }
    for a in anomalies {
        let sev = match a.severity.as_str() {
            "high" => c.b_red("HIGH"),
            "warn" => c.b_yellow("WARN"),
            _ => c.cyan("INFO"),
        };
        writeln!(w, "  [{}] {}: {}", sev, c.b_white(&a.kind), a.detail).ok();
    }
}

pub fn print_yara_matches(w: &mut dyn Write, matches: &[YaraMatch], c: &Colors) {
    writeln!(w).ok();
    writeln!(w, "{}", c.bold(&c.b_red("YARA Matches:"))).ok();
    if matches.is_empty() {
        writeln!(w, "{}", c.dim("  (none)")).ok();
        return;
    }
    for m in matches {
        let prefix = if m.namespace.is_empty() {
            m.rule.clone()
        } else {
            format!("{}:{}", m.namespace, m.rule)
        };
        let tags = if m.tags.is_empty() {
            String::new()
        } else {
            format!(" [{}]", m.tags.join(", "))
        };
        writeln!(w, "  {}{}  {}", c.b_yellow(&prefix), tags, c.dim(&m.file)).ok();
    }
}

pub fn print_c_recomp(w: &mut dyn Write, source: &str, c: &Colors) {
    for line in source.lines() {
        writeln!(w, "{}", highlight_c_line(line, c)).ok();
    }
}

fn highlight_c_line(line: &str, c: &Colors) -> String {
    let (code, comment) = if let Some(idx) = line.find("//") {
        (&line[..idx], Some(&line[idx..]))
    } else {
        (line, None)
    };

    let mut out = String::new();
    let chars: Vec<char> = code.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let ch = chars[i];
        if ch.is_ascii_alphanumeric() || ch == '_' {
            let start = i;
            i += 1;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let token: String = chars[start..i].iter().collect();
            out.push_str(&highlight_c_token(&token, c));
            continue;
        }
        if ch == '"' {
            let start = i;
            i += 1;
            while i < chars.len() {
                if chars[i] == '\\' {
                    i += 2;
                    continue;
                }
                if chars[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            let token: String = chars[start..i.min(chars.len())].iter().collect();
            out.push_str(&c.green(&token));
            continue;
        }
        out.push(ch);
        i += 1;
    }

    if let Some(comment) = comment {
        out.push_str(&c.dim(comment));
    }

    out
}

fn highlight_c_token(token: &str, c: &Colors) -> String {
    if matches!(
        token,
        "if" | "else" | "return" | "goto" | "void" | "unsigned" | "struct"
    ) {
        return c.b_mag(token);
    }
    if matches!(
        token,
        "NTSTATUS"
            | "__fastcall"
            | "__stdcall"
            | "PUSH"
            | "POP"
            | "__syscall"
            | "__sysenter"
            | "__interrupt"
    ) {
        return c.b_cyan(token);
    }
    if token.starts_with("label_") {
        return c.b_yellow(token);
    }
    if token.starts_with("0x") || token.chars().all(|ch| ch.is_ascii_digit()) {
        return c.yellow(token);
    }
    token.to_owned()
}
