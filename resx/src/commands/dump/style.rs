use crate::analysis::disasm::ApiCall;
use crate::core::color::Colors;

/// and b_white (named internals) so each role stays visually distinct.
fn dll_palette(c: &Colors, idx: usize, s: &str) -> String {
    match idx % 5 {
        0 => c.cyan(s),
        1 => c.green(s),
        2 => c.magenta(s),
        3 => c.b_cyan(s),
        _ => c.b_blue(s),
    }
}

/// True for Nt*/Zw* Windows native-API names (syscall stubs, lowest UM layer).
pub(super) fn is_nt_api(label: &str) -> bool {
    (label.starts_with("Nt") || label.starts_with("Zw"))
        && label
            .as_bytes()
            .get(2)
            .is_some_and(|b| b.is_ascii_uppercase())
}

/// Color the mnemonic: CALL -> b_yellow, JMP -> yellow  (matches disasm listing).
pub(super) fn color_kind(kind: &str, c: &Colors) -> String {
    if kind == "call" {
        c.b_yellow("CALL")
    } else if kind == "syscall" {
        c.b_red("SYSCALL")
    } else {
        c.yellow("JMP")
    }
}

pub(super) fn short_dll_name(name: &str) -> &str {
    name.strip_suffix(".dll")
        .or_else(|| name.strip_suffix(".DLL"))
        .or_else(|| name.strip_suffix(".exe"))
        .or_else(|| name.strip_suffix(".EXE"))
        .or_else(|| name.strip_suffix(".sys"))
        .or_else(|| name.strip_suffix(".SYS"))
        .unwrap_or(name)
}

#[derive(Clone, Copy)]
struct KernelSubsystemStyle {
    prefix: &'static str,
    colorize: fn(&Colors, &str) -> String,
}

fn subsystem_style(label: &str) -> Option<KernelSubsystemStyle> {
    const STYLES: &[KernelSubsystemStyle] = &[
        KernelSubsystemStyle {
            prefix: "FsRtl",
            colorize: Colors::b_cyan,
        },
        KernelSubsystemStyle {
            prefix: "Psp",
            colorize: Colors::green,
        },
        KernelSubsystemStyle {
            prefix: "Sep",
            colorize: Colors::b_mag,
        },
        KernelSubsystemStyle {
            prefix: "Cmp",
            colorize: Colors::magenta,
        },
        KernelSubsystemStyle {
            prefix: "Rtl",
            colorize: Colors::cyan,
        },
        KernelSubsystemStyle {
            prefix: "Etw",
            colorize: Colors::green,
        },
        KernelSubsystemStyle {
            prefix: "Hal",
            colorize: Colors::yellow,
        },
        KernelSubsystemStyle {
            prefix: "Ke",
            colorize: Colors::b_blue,
        },
        KernelSubsystemStyle {
            prefix: "Ki",
            colorize: Colors::b_blue,
        },
        KernelSubsystemStyle {
            prefix: "Mm",
            colorize: Colors::b_cyan,
        },
        KernelSubsystemStyle {
            prefix: "Cm",
            colorize: Colors::magenta,
        },
        KernelSubsystemStyle {
            prefix: "Io",
            colorize: Colors::b_yellow,
        },
        KernelSubsystemStyle {
            prefix: "Po",
            colorize: Colors::yellow,
        },
        KernelSubsystemStyle {
            prefix: "Cc",
            colorize: Colors::cyan,
        },
        KernelSubsystemStyle {
            prefix: "Ex",
            colorize: Colors::green,
        },
        KernelSubsystemStyle {
            prefix: "Ps",
            colorize: Colors::b_cyan,
        },
        KernelSubsystemStyle {
            prefix: "Se",
            colorize: Colors::b_mag,
        },
        KernelSubsystemStyle {
            prefix: "Ob",
            colorize: Colors::b_white,
        },
    ];

    STYLES.iter().copied().find(|style| {
        label.starts_with(style.prefix)
            && label
                .as_bytes()
                .get(style.prefix.len())
                .is_some_and(|b: &u8| b.is_ascii_uppercase())
    })
}

/// Colour a call target:
///   Nt*/Zw* (any origin) -> b_red    - syscall stub, highest visual priority; tag becomes [syscall]
///   IAT import           -> dim(dll.dll!) + palette-color(FuncName), one shade per DLL
///   Named internal       -> subsystem color when recognized, else b_white
///   sub_XXXXXXXX         -> yellow    - anonymous, address-only
///   Indirect (call rax)  -> dim       - unresolvable
pub(super) fn color_target(
    call: &ApiCall,
    c: &Colors,
    dll_map: &mut std::collections::HashMap<String, usize>,
) -> String {
    let nt = is_nt_api(&call.label);
    if call.is_import {
        let dll_name = short_dll_name(&call.dll);
        let key = dll_name.to_ascii_lowercase();
        let n = dll_map.len();
        let idx = *dll_map.entry(key).or_insert(n);
        let func = if nt {
            c.b_red(&call.label)
        } else {
            dll_palette(c, idx, &call.label)
        };
        format!("{}{}", c.dim(&format!("{}!", dll_name)), func)
    } else if call.is_indirect {
        c.dim(&call.label)
    } else if nt {
        c.b_red(&call.label)
    } else if call.label.starts_with("sub_") {
        c.yellow(&call.label)
    } else if let Some(style) = subsystem_style(&call.label) {
        (style.colorize)(c, &call.label)
    } else {
        c.b_white(&call.label)
    }
}
