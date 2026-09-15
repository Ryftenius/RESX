#[derive(Clone, Copy)]
pub struct Colors {
    pub on: bool,
}

impl Colors {
    pub fn new(on: bool) -> Self {
        Colors { on }
    }

    fn apply(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("{}{}\x1b[0m", code, s)
        } else {
            s.to_owned()
        }
    }

    pub fn bold(&self, s: &str) -> String {
        self.apply("\x1b[1m", s)
    }
    pub fn dim(&self, s: &str) -> String {
        self.apply("\x1b[2m", s)
    }
    pub fn green(&self, s: &str) -> String {
        self.apply("\x1b[32m", s)
    }
    pub fn yellow(&self, s: &str) -> String {
        self.apply("\x1b[33m", s)
    }
    pub fn magenta(&self, s: &str) -> String {
        self.apply("\x1b[35m", s)
    }
    pub fn cyan(&self, s: &str) -> String {
        self.apply("\x1b[36m", s)
    }
    pub fn b_red(&self, s: &str) -> String {
        self.apply("\x1b[91m", s)
    }
    pub fn b_yellow(&self, s: &str) -> String {
        self.apply("\x1b[93m", s)
    }
    pub fn b_blue(&self, s: &str) -> String {
        self.apply("\x1b[94m", s)
    }
    pub fn b_mag(&self, s: &str) -> String {
        self.apply("\x1b[95m", s)
    }
    pub fn b_cyan(&self, s: &str) -> String {
        self.apply("\x1b[96m", s)
    }
    pub fn b_white(&self, s: &str) -> String {
        self.apply("\x1b[97m", s)
    }

    /// Shared terminal semantics. Renderers should use these instead of
    /// inventing command-specific colour meanings.
    pub fn heading(&self, s: &str) -> String {
        self.bold(&self.b_cyan(s))
    }
    pub fn label(&self, s: &str) -> String {
        self.b_cyan(s)
    }
    pub fn address(&self, s: &str) -> String {
        self.cyan(s)
    }
    pub fn bytes(&self, s: &str) -> String {
        self.dim(s)
    }
    pub fn selected_marker(&self, s: &str) -> String {
        self.bold(&self.b_red(s))
    }
    pub fn value(&self, s: &str) -> String {
        self.b_white(s)
    }
    pub fn success(&self, s: &str) -> String {
        self.ok(s)
    }
    pub fn warning(&self, s: &str) -> String {
        self.b_yellow(s)
    }
    pub fn failure(&self, s: &str) -> String {
        self.b_red(s)
    }
    pub fn severity_tag(&self, severity: &str) -> String {
        let label = format!("[{}]", severity.to_ascii_uppercase());
        match severity.to_ascii_lowercase().as_str() {
            "fatal" | "error" | "high" => self.failure(&label),
            "warn" | "warning" | "medium" => self.warning(&label),
            "debug" | "trace" => self.dim(&label),
            "success" | "ok" => self.success(&label),
            _ => self.b_cyan(&label),
        }
    }

    /// Colour a textual assembly instruction using the same mnemonic classes
    /// as the normal disassembly renderer. This is used for runtime evidence
    /// whose exact bytes are retained in JSON rather than an Instruction.
    pub fn assembly(&self, text: &str) -> String {
        let mnemonic = text
            .split_ascii_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        match mnemonic.as_str() {
            "ret" | "retf" | "iret" | "iretd" | "iretq" | "int" | "int3" => self.b_red(text),
            "syscall" | "sysenter" | "sysexit" | "sysret" => self.b_mag(text),
            "call" => self.b_yellow(text),
            "jmp" => self.yellow(text),
            value if value.starts_with('j') || matches!(value, "loop" | "loope" | "loopne") => {
                self.b_cyan(text)
            }
            "cmp" | "test" => self.magenta(text),
            "push" | "pop" | "nop" => self.dim(text),
            "add" | "sub" | "imul" | "mul" | "div" | "idiv" | "and" | "or" | "xor" | "shl"
            | "shr" | "sar" | "rol" | "ror" | "inc" | "dec" | "neg" | "not" => self.green(text),
            "invalid" | "db" => self.b_red(text),
            _ => self.b_white(text),
        }
    }

    pub fn info(&self, s: &str) -> String {
        s.to_owned()
    }
    pub fn ok(&self, s: &str) -> String {
        self.apply("\x1b[92m", s)
    }
    pub fn warn(&self, s: &str) -> String {
        format!("{} {}", self.apply("\x1b[93m", "Warning:"), s)
    }
    pub fn err_msg(&self, s: &str) -> String {
        format!("{} {}", self.apply("\x1b[91m", "Error:"), s)
    }
}

pub fn enable_windows_ansi() -> bool {
    #[cfg(windows)]
    // SAFETY: each Win32 call receives a validated console handle and writable stack output pointer.
    unsafe {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> *mut c_void;
            fn GetConsoleMode(hConsoleHandle: *mut c_void, lpMode: *mut u32) -> i32;
            fn SetConsoleMode(hConsoleHandle: *mut c_void, dwMode: u32) -> i32;
        }
        let h = GetStdHandle(0xFFFFFFF5_u32);
        if h.is_null() || h as usize == usize::MAX {
            return false;
        }
        let mut mode = 0u32;
        if GetConsoleMode(h, &mut mode) == 0 {
            return false;
        }
        SetConsoleMode(h, mode | 0x0004) != 0
    }
    #[cfg(not(windows))]
    {
        true
    }
}

pub fn is_terminal() -> bool {
    #[cfg(windows)]
    // SAFETY: each Win32 call receives a validated console handle and writable stack output pointer.
    unsafe {
        use std::ffi::c_void;
        #[link(name = "kernel32")]
        extern "system" {
            fn GetStdHandle(nStdHandle: u32) -> *mut c_void;
            fn GetConsoleMode(hConsoleHandle: *mut c_void, lpMode: *mut u32) -> i32;
        }
        let h = GetStdHandle(0xFFFFFFF5_u32);
        if h.is_null() || h as usize == usize::MAX {
            return false;
        }
        let mut mode = 0u32;
        GetConsoleMode(h, &mut mode) != 0
    }
    #[cfg(not(windows))]
    {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::Colors;

    #[test]
    fn semantic_styles_preserve_plain_output_when_disabled() {
        let colors = Colors::new(false);
        assert_eq!(colors.selected_marker(">"), ">");
        assert_eq!(colors.address("0003D193"), "0003D193");
        assert_eq!(colors.bytes("FF E2"), "FF E2");
        assert_eq!(colors.assembly("jmp rdx"), "jmp rdx");
        assert_eq!(colors.severity_tag("warn"), "[WARN]");
    }

    #[test]
    fn assembly_and_selection_have_distinct_terminal_styles() {
        let colors = Colors::new(true);
        assert!(colors.selected_marker(">").contains("\x1b[91m"));
        assert!(colors.address("0003D193").contains("\x1b[36m"));
        assert!(colors.bytes("FF E2").contains("\x1b[2m"));
        assert!(colors.assembly("jmp rdx").contains("\x1b[33m"));
        assert!(colors.assembly("syscall").contains("\x1b[95m"));
        assert!(colors.severity_tag("warn").contains("\x1b[93m"));
        assert!(colors.severity_tag("error").contains("\x1b[91m"));
    }
}
