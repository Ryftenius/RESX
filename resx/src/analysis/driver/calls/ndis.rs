//! x64 WDK 10.0.26100.0 ndis/oidrequest.h. Reads static fields, never follows
//! InformationBuffer or treats an NDIS binding/filter handle as a device object.
use super::{Argument, PeFile, State, Value, IMAGE_SCN_MEM_WRITE};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct RequestEvidence {
    pub revision: u8,
    pub declared_size: u16,
    pub request_type: u32,
    pub operation: &'static str,
    pub oid: Option<u32>,
    pub fields: Vec<Argument>,
    pub status: &'static str,
}

fn field(pe: &PeFile, raw: &[u8], state: &State, base: &Value, delta: u32, width: usize) -> Value {
    match base {
        Value::StackAddress { offset, .. } => {
            let Some(start) = offset.checked_add(i64::from(delta)) else {
                return Value::Unknown;
            };
            let Some((&stored_start, stored)) = state.stack.range(..=start).next_back() else {
                return Value::Unknown;
            };
            let Some(inside) = start
                .checked_sub(stored_start)
                .and_then(|value| usize::try_from(value).ok())
            else {
                return Value::Unknown;
            };
            if !matches!(stored.width, 1 | 2 | 4 | 8)
                || inside
                    .checked_add(width)
                    .is_none_or(|end| end > stored.width)
            {
                return Value::Unknown;
            }
            if inside == 0 && width == stored.width {
                return stored.value.clone();
            }
            if let Value::Constant { value, origin_rva } = stored.value {
                let mask = u64::MAX >> ((8 - width) * 8);
                return Value::Constant {
                    value: (value >> (inside * 8)) & mask,
                    origin_rva,
                };
            }
            Value::Unknown
        }
        Value::ImageAddress { rva, .. } => {
            let Some(start) = rva.checked_add(delta) else {
                return Value::Unknown;
            };
            if pe
                .rva_to_section(start)
                .is_none_or(|section| section.characteristics & IMAGE_SCN_MEM_WRITE != 0)
            {
                return Value::Unknown;
            }
            let Some(bytes) = pe.rva_slice(raw, start, width) else {
                return Value::Unknown;
            };
            let mut scalar = [0u8; 8];
            scalar[..width].copy_from_slice(bytes);
            Value::Constant {
                value: u64::from_le_bytes(scalar),
                origin_rva: start,
            }
        }
        _ => Value::Unknown,
    }
}

pub(super) fn recover(
    pe: &PeFile,
    raw: &[u8],
    state: &State,
    base: &Value,
) -> Option<RequestEvidence> {
    decode(|delta, width| field(pe, raw, state, base, delta, width))
}

fn decode(mut read: impl FnMut(u32, usize) -> Value) -> Option<RequestEvidence> {
    let object_type = read(0, 1).constant()?;
    let revision = u8::try_from(read(1, 1).constant()?).ok()?;
    let declared_size = u16::try_from(read(2, 2).constant()?).ok()?;
    // Revision 1's last field ends at 236; sizeof includes tail padding (240).
    // Revision 2 extends through Flags, at 248. Other revisions stay unknown.
    if object_type != 0x96 || !matches!((revision, declared_size), (1, 236 | 240) | (2, 248)) {
        return None;
    }
    let request_type = u32::try_from(read(4, 4).constant()?).ok()?;
    let operation = match request_type {
        0 => "query_information",
        1 => "set_information",
        2 => "query_statistics",
        12 => "method",
        _ => return None,
    };
    let mut fields = Vec::new();
    for (name, offset, width) in [
        ("port_number", 8, 4),
        ("timeout_seconds", 12, 4),
        ("request_id", 16, 8),
        ("request_handle", 24, 8),
        ("oid", 32, 4),
        ("information_buffer", 40, 8),
    ] {
        fields.push(Argument {
            name: name.into(),
            value: read(offset, width),
        });
    }
    let oid = fields
        .iter()
        .find(|field| field.name == "oid")?
        .value
        .constant()
        .and_then(|value| u32::try_from(value).ok());
    if request_type == 12 {
        for (name, offset) in [
            ("input_buffer_length", 48),
            ("output_buffer_length", 52),
            ("method_id", 56),
        ] {
            fields.push(Argument {
                name: name.into(),
                value: read(offset, 4),
            });
        }
    } else {
        fields.push(Argument {
            name: "information_buffer_length".into(),
            value: read(48, 4),
        });
    }
    Some(RequestEvidence { revision, declared_size, request_type, operation, oid, fields,
        status: "static x64 layout; individual fields may be unknown; buffer contents, execution, completion and kernel-object identity unobserved" })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request(bytes: &[u8]) -> Option<RequestEvidence> {
        decode(|offset, width| {
            let Some(slice) = bytes.get(offset as usize..offset as usize + width) else {
                return Value::Unknown;
            };
            let mut value = [0; 8];
            value[..width].copy_from_slice(slice);
            Value::Constant {
                value: u64::from_le_bytes(value),
                origin_rva: offset,
            }
        })
    }
    #[test]
    fn header_and_union_discriminant_gate_oid_interpretation() {
        let mut bytes = [0u8; 248];
        bytes[..4].copy_from_slice(&[0x96, 2, 248, 0]);
        bytes[32..36].copy_from_slice(&0x10101u32.to_le_bytes());
        for (kind, expected) in [
            (0, "query_information"),
            (1, "set_information"),
            (2, "query_statistics"),
            (12, "method"),
        ] {
            bytes[4] = kind;
            let result = request(&bytes).unwrap();
            assert_eq!(result.operation, expected);
            assert_eq!(result.oid, Some(0x10101));
            assert_eq!(
                result.fields.iter().any(|f| f.name == "method_id"),
                kind == 12
            );
        }
        bytes[4] = 13;
        assert!(request(&bytes).is_none());
        bytes[4] = 0;
        bytes[0] = 0x95;
        assert!(request(&bytes).is_none());
        bytes[0] = 0x96;
        bytes[1] = 3;
        assert!(request(&bytes).is_none());
        bytes[1] = 2;
        bytes[2] = 56;
        assert!(request(&bytes).is_none());
        bytes[1] = 1;
        bytes[2] = 236;
        assert!(request(&bytes).is_some());
        bytes[2] = 240;
        assert!(request(&bytes).is_some());
    }
    #[test]
    fn missing_fields_stay_unknown_and_incomplete_headers_are_rejected() {
        let bytes = [0x96, 2, 248, 0, 0, 0, 0, 0];
        let result = request(&bytes).unwrap();
        assert!(result.oid.is_none());
        assert!(result
            .fields
            .iter()
            .all(|field| field.value == Value::Unknown));
        for length in 0..8 {
            assert!(request(&bytes[..length]).is_none());
        }
    }
}
