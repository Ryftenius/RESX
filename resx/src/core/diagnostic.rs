//! Bounded process-local developer diagnostics.
//!
//! Diagnostic output is intentionally separate from analyst output and is
//! enabled only by the global `--diagnostic` switch.

use std::fmt;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

use sha2::{Digest, Sha256};

use crate::core::color::Colors;

static ENABLED: AtomicBool = AtomicBool::new(false);
static TRACE_ENABLED: AtomicBool = AtomicBool::new(false);
static COLOR: AtomicBool = AtomicBool::new(false);
static NEXT_EVENT: AtomicU64 = AtomicU64::new(1);
static START: OnceLock<Instant> = OnceLock::new();
static BINARY_SHA256: OnceLock<String> = OnceLock::new();

pub const SCHEMA_VERSION: &str = "1";
pub const BUILD_COMMIT: &str = match option_env!("RESX_GIT_COMMIT") {
    Some(value) => value,
    None => "unknown",
};

#[derive(Clone, Copy)]
pub enum Severity {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Self::Trace => "TRACE",
            Self::Debug => "DEBUG",
            Self::Info => "INFO",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
        }
    }
}

pub fn init(enabled: bool, trace_enabled: bool, color: bool) {
    let _ = START.set(Instant::now());
    ENABLED.store(enabled, Ordering::Release);
    TRACE_ENABLED.store(enabled && trace_enabled, Ordering::Release);
    COLOR.store(enabled && color, Ordering::Release);
    if enabled {
        let _ = BINARY_SHA256.set(hash_current_binary());
    }
}

pub fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

pub fn trace_enabled() -> bool {
    TRACE_ENABLED.load(Ordering::Acquire)
}

pub fn binary_sha256() -> &'static str {
    BINARY_SHA256.get().map_or("unavailable", String::as_str)
}

pub struct Event {
    severity: Severity,
    subsystem: &'static str,
    event_id: &'static str,
    file: &'static str,
    line: u32,
    fields: Vec<(&'static str, String)>,
}

impl Event {
    pub fn new(
        severity: Severity,
        subsystem: &'static str,
        event_id: &'static str,
        file: &'static str,
        line: u32,
    ) -> Self {
        Self {
            severity,
            subsystem,
            event_id,
            file,
            line,
            fields: Vec::with_capacity(10),
        }
    }

    pub fn field(mut self, name: &'static str, value: impl fmt::Display) -> Self {
        if self.fields.len() < 16 {
            self.fields.push((name, sanitize(&value.to_string())));
        }
        self
    }

    pub fn emit(self, message: impl fmt::Display) {
        if !enabled() || matches!(self.severity, Severity::Trace) && !trace_enabled() {
            return;
        }
        let sequence = NEXT_EVENT.fetch_add(1, Ordering::Relaxed);
        let elapsed = START
            .get()
            .map_or(0.0, |start| start.elapsed().as_secs_f64() * 1000.0);
        let timestamp = utc_timestamp();
        let rust_thread = format!("{:?}", std::thread::current().id());
        let colors = Colors::new(COLOR.load(Ordering::Acquire));
        let severity = match self.severity {
            Severity::Trace => colors.dim(self.severity.label()),
            Severity::Debug => colors.b_blue(self.severity.label()),
            Severity::Info => colors.b_cyan(self.severity.label()),
            Severity::Warn => colors.b_yellow(self.severity.label()),
            Severity::Error => colors.b_red(self.severity.label()),
        };
        let mut fields = String::new();
        for (name, value) in self.fields {
            fields.push(' ');
            fields.push_str(name);
            fields.push('=');
            fields.push_str(&value);
        }
        eprintln!(
            "{timestamp} mono_ms={elapsed:.3} {severity} schema={} subsystem={} source={}:{} resx_pid={} os_tid={} rust_thread_id={} event={} sequence={}{} message={}",
            SCHEMA_VERSION,
            self.subsystem,
            self.file.replace('\\', "/"),
            self.line,
            std::process::id(),
            os_thread_id(),
            rust_thread,
            self.event_id,
            sequence,
            fields,
            sanitize(&message.to_string())
        );
    }
}

fn hash_current_binary() -> String {
    let Ok(path) = std::env::current_exe() else {
        return "unavailable".to_owned();
    };
    let Ok(bytes) = std::fs::read(path) else {
        return "unavailable".to_owned();
    };
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(windows)]
fn os_thread_id() -> u64 {
    #[link(name = "kernel32")]
    extern "system" {
        fn GetCurrentThreadId() -> u32;
    }
    // SAFETY: GetCurrentThreadId has no parameters and returns the caller's ID.
    u64::from(unsafe { GetCurrentThreadId() })
}

#[cfg(not(windows))]
fn os_thread_id() -> u64 {
    0
}

fn sanitize(value: &str) -> String {
    let escaped = value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\r', '\n', '\t'], " ");
    if escaped.bytes().any(|byte| byte.is_ascii_whitespace()) {
        format!("\"{escaped}\"")
    } else {
        escaped
    }
}

#[cfg(windows)]
fn utc_timestamp() -> String {
    #[repr(C)]
    #[derive(Default)]
    struct SystemTime {
        year: u16,
        month: u16,
        day_of_week: u16,
        day: u16,
        hour: u16,
        minute: u16,
        second: u16,
        milliseconds: u16,
    }
    #[link(name = "kernel32")]
    extern "system" {
        fn GetSystemTime(value: *mut SystemTime);
    }
    let mut value = SystemTime::default();
    // SAFETY: GetSystemTime writes exactly one caller-owned SYSTEMTIME.
    unsafe { GetSystemTime(&mut value) };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        value.year,
        value.month,
        value.day,
        value.hour,
        value.minute,
        value.second,
        value.milliseconds
    )
}

#[cfg(not(windows))]
fn utc_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_millis());
    format!("unix-ms:{millis}Z")
}

#[macro_export]
macro_rules! diagnostic_event {
    ($severity:expr, $subsystem:expr, $event_id:expr) => {
        $crate::core::diagnostic::Event::new($severity, $subsystem, $event_id, file!(), line!())
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_fields_are_single_line_and_bounded() {
        assert_eq!(sanitize("a\nb"), "\"a b\"");
        let mut event = Event::new(Severity::Trace, "test", "bounded", file!(), line!());
        for index in 0..32 {
            event = event.field("value", index);
        }
        assert_eq!(event.fields.len(), 16);
    }
}
