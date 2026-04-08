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

    pub fn info(&self, s: &str) -> String {
        format!("{} {}", self.apply("\x1b[96m", "[*]"), s)
    }
    pub fn ok(&self, s: &str) -> String {
        format!("{} {}", self.apply("\x1b[92m", "[+]"), s)
    }
    pub fn warn(&self, s: &str) -> String {
        format!("{} {}", self.apply("\x1b[93m", "[!]"), s)
    }
    pub fn err_msg(&self, s: &str) -> String {
        format!("{} {}", self.apply("\x1b[91m", "[!]"), s)
    }
}

pub fn enable_windows_ansi() -> bool {
    #[cfg(windows)]
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
