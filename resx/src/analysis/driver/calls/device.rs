//! Named kernel ABI contracts. No string-only device or SDDL guesses.
use super::{semantic, PeFile, State, Stored, Value};
use crate::analysis::apis::Spec;

const CATEGORY: &str = "device-registration";
const CREATE_ARGS: &[(&str, usize)] = &[
    ("driver_object", 8),
    ("extension_size", 4),
    ("device_name", 8),
    ("device_type", 4),
    ("characteristics", 4),
    ("exclusive", 1),
    ("device_object_out", 8),
];
const SECURE_ARGS: &[(&str, usize)] = &[
    ("driver_object", 8),
    ("extension_size", 4),
    ("device_name", 8),
    ("device_type", 4),
    ("characteristics", 4),
    ("exclusive", 1),
    ("default_sddl", 8),
    ("device_class_guid", 8),
    ("device_object_out", 8),
];
const LINK_ARGS: &[(&str, usize)] = &[("symbolic_link", 8), ("target_name", 8)];
const INIT_ARGS: &[(&str, usize)] = &[("destination", 8), ("source", 8)];

pub(super) fn spec(dll: &str, name: &str) -> Option<Spec> {
    let kernel = dll.eq_ignore_ascii_case("ntoskrnl.exe");
    let secure = kernel || dll.eq_ignore_ascii_case("wdmsec.sys");
    let args = match name {
        "IoCreateDevice" if kernel => CREATE_ARGS,
        "IoCreateDeviceSecure" | "WdmlibIoCreateDeviceSecure" if secure => SECURE_ARGS,
        "IoCreateSymbolicLink" | "IoCreateUnprotectedSymbolicLink" if kernel => LINK_ARGS,
        "RtlInitUnicodeString" if kernel => INIT_ARGS,
        _ => return None,
    };
    Some(Spec {
        category: CATEGORY,
        args,
        text: &[],
        returns_handle: false,
    })
}

pub(super) fn strings(
    pe: &PeFile,
    raw: &[u8],
    state: &State,
    args: &[super::Argument],
    details: &mut serde_json::Value,
) {
    let Some(strings) = details["strings"].as_array_mut() else {
        return;
    };
    for arg in args.iter().filter(|arg| {
        matches!(
            arg.name.as_str(),
            "device_name" | "symbolic_link" | "target_name" | "default_sddl"
        )
    }) {
        if let Some(value) = semantic::unicode_string(pe, raw, state, &arg.value) {
            strings.push(serde_json::json!({"argument":arg.name,"value":value,"encoding":"counted-utf16le","source":arg.value}));
        }
    }
}

// The named constructors copy their string inputs. Model only their declared
// caller-local output, instead of treating every const input as an escaping
// mutable pointer. A malformed/unknown RtlInitUnicodeString remains conservative.
pub(super) fn effects(
    pe: &PeFile,
    raw: &[u8],
    state: &State,
    name: &str,
    site: u32,
) -> Option<Vec<(i64, Stored)>> {
    if name != "RtlInitUnicodeString" {
        return Some(Vec::new());
    }
    let Value::StackAddress { offset, .. } = state.argument(0, 8) else {
        return None;
    };
    let source = state.argument(1, 8);
    let length = if source.constant() == Some(0) {
        0
    } else {
        semantic::text(pe, raw, state, &source, true)?
            .encode_utf16()
            .count()
            .checked_mul(2)?
    };
    let max = if source.constant() == Some(0) {
        0
    } else {
        length.checked_add(2)?
    };
    Some(vec![
        (
            offset,
            Stored {
                width: 2,
                value: Value::Constant {
                    value: length as u64,
                    origin_rva: site,
                },
            },
        ),
        (
            offset.checked_add(2)?,
            Stored {
                width: 2,
                value: Value::Constant {
                    value: max as u64,
                    origin_rva: site,
                },
            },
        ),
        (
            offset.checked_add(8)?,
            Stored {
                width: 8,
                value: source,
            },
        ),
    ])
}
