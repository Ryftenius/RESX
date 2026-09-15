//! Interpret only fully known static fields; every read has an explicit budget.
use super::{Argument, PeFile, State, Value, IMAGE_SCN_MEM_WRITE};
use crate::analysis::apis::Spec;
use serde_json::{json, Value as Json};

pub(super) fn bytes(
    pe: &PeFile,
    raw: &[u8],
    state: &State,
    value: &Value,
    length: usize,
) -> Option<Vec<u8>> {
    if length > 4096 {
        return None;
    }
    match value {
        Value::StackAddress { offset, .. } => {
            let mut out = Vec::with_capacity(length);
            for i in 0..length {
                let at = offset.checked_add(i as i64)?;
                let (&start, stored) = state.stack.range(..=at).next_back()?;
                let inside = usize::try_from(at.checked_sub(start)?).ok()?;
                if inside >= stored.width || stored.width > 8 {
                    return None;
                }
                out.push((stored.value.constant()? >> (inside * 8)) as u8);
            }
            Some(out)
        }
        Value::Constant { value, origin_rva } => {
            let rva = pe.va_to_rva(*value)?;
            bytes(
                pe,
                raw,
                state,
                &Value::ImageAddress {
                    rva,
                    origin_rva: *origin_rva,
                },
                length,
            )
        }
        Value::ImageAddress { rva, .. } => {
            if pe.rva_to_section(*rva)?.characteristics & IMAGE_SCN_MEM_WRITE != 0 {
                return None;
            }
            Some(pe.rva_slice(raw, *rva, length)?.to_vec())
        }
        _ => None,
    }
}

fn shifted(value: &Value, delta: usize) -> Option<Value> {
    match value {
        Value::StackAddress { offset, origin_rva } => Some(Value::StackAddress {
            offset: offset.checked_add(delta as i64)?,
            origin_rva: *origin_rva,
        }),
        Value::ImageAddress { rva, origin_rva } => Some(Value::ImageAddress {
            rva: rva.checked_add(delta as u32)?,
            origin_rva: *origin_rva,
        }),
        Value::Constant { value, origin_rva } => Some(Value::Constant {
            value: value.checked_add(delta as u64)?,
            origin_rva: *origin_rva,
        }),
        _ => None,
    }
}

pub(super) fn text(
    pe: &PeFile,
    raw: &[u8],
    state: &State,
    value: &Value,
    wide: bool,
) -> Option<String> {
    let mut units = Vec::new();
    for index in 0..512 {
        let data = bytes(
            pe,
            raw,
            state,
            &shifted(value, index * if wide { 2 } else { 1 })?,
            if wide { 2 } else { 1 },
        )?;
        let unit = if wide {
            u16::from_le_bytes([data[0], data[1]])
        } else {
            u16::from(data[0])
        };
        if unit == 0 {
            return if wide {
                String::from_utf16(&units).ok()
            } else {
                String::from_utf8(units.into_iter().map(|v| v as u8).collect()).ok()
            };
        }
        units.push(unit);
    }
    None
}

fn unicode_string(pe: &PeFile, raw: &[u8], state: &State, pointer: &Value) -> Option<String> {
    let header = bytes(pe, raw, state, pointer, 4)?;
    let length = u16::from_le_bytes([header[0], header[1]]) as usize;
    let maximum = u16::from_le_bytes([header[2], header[3]]) as usize;
    if length > maximum || length > 1024 || !length.is_multiple_of(2) {
        return None;
    }
    let buffer = match shifted(pointer, 8)? {
        Value::StackAddress { offset, .. } => state
            .stack
            .get(&offset)
            .filter(|s| s.width == 8)?
            .value
            .clone(),
        other => Value::Constant {
            value: u64::from_le_bytes(bytes(pe, raw, state, &other, 8)?.try_into().ok()?),
            origin_rva: 0,
        },
    };
    let body = bytes(pe, raw, state, &buffer, length)?;
    String::from_utf16(
        &body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| u16::from_le_bytes([p[0], p[1]]))
            .collect::<Vec<_>>(),
    )
    .ok()
}

fn socket_address(data: &[u8]) -> Option<Json> {
    let family = u16::from_le_bytes(data.get(..2)?.try_into().ok()?);
    let port = u16::from_be_bytes(data.get(2..4)?.try_into().ok()?);
    let host = match family {
        2 if data.len() >= 16 => {
            std::net::Ipv4Addr::from(<[u8; 4]>::try_from(&data[4..8]).ok()?).to_string()
        }
        23 if data.len() >= 28 => {
            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&data[8..24]).ok()?).to_string()
        }
        _ => return None,
    };
    Some(
        json!({"family":family,"host":host,"port":port,"scope_id":if family==23 {Some(u32::from_le_bytes(data[24..28].try_into().ok()?))} else {None},"status":"static argument; connection and C2 role unobserved"}),
    )
}

pub(super) fn details(
    pe: &PeFile,
    raw: &[u8],
    state: &State,
    api: &str,
    spec: Option<Spec>,
    args: &[Argument],
) -> Json {
    let get = |name: &str| args.iter().find(|a| a.name == name).map(|a| &a.value);
    let mut texts = Vec::new();
    if let Some(spec) = spec {
        for &(index, wide) in spec.text {
            if let Some(argument) = args.get(index) {
                if let Some(value) = text(pe, raw, state, &argument.value, wide) {
                    texts.push(json!({"argument":argument.name,"value":value,"encoding":if wide {"utf16le"} else {"utf8"},"source":argument.value}));
                }
            }
        }
    }
    let mut endpoint = Json::Null;
    if let (Some(address), Some(length)) = (
        get("address"),
        get("address_length").and_then(Value::constant),
    ) {
        if let Ok(length) = usize::try_from(length) {
            endpoint = bytes(pe, raw, state, address, length)
                .and_then(|b| socket_address(&b))
                .unwrap_or(Json::Null);
        }
    }
    if api.ends_with("AlpcConnectPort") {
        if let Some(name) = get("port_name").and_then(|p| unicode_string(pe, raw, state, p)) {
            texts.push(json!({"argument":"port_name","value":name,"encoding":"counted-utf16le","source":get("port_name")}));
        }
    }
    let chaining_mode = if api == "BCryptSetProperty"
        && texts
            .iter()
            .any(|t| t["argument"] == "property" && t["value"] == "ChainingMode")
    {
        get("input_length")
            .and_then(Value::constant)
            .filter(|length| *length <= 1024 && *length >= 2 && *length % 2 == 0)
            .and_then(|length| bytes(pe, raw, state, get("input_buffer")?, length as usize))
            .and_then(|b| {
                if b[b.len() - 2..] != [0, 0] {
                    return None;
                }
                String::from_utf16(
                    &b[..b.len() - 2]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_le_bytes([p[0], p[1]]))
                        .collect::<Vec<_>>(),
                )
                .ok()
            })
    } else {
        None
    };
    let algorithm_id = get("algorithm_id").and_then(Value::constant);
    let algorithm_name = algorithm_id.and_then(|id| match id {
        0x660e => Some("AES-128"),
        0x660f => Some("AES-192"),
        0x6610 => Some("AES-256"),
        0x6801 => Some("RC4"),
        0x8004 => Some("SHA-1"),
        0x800c => Some("SHA-256"),
        _ => None,
    });
    let predecessors: Vec<_> = args.iter().filter_map(|a| match &a.value {
        Value::ApiResult { api,call_site,.. } | Value::ApiOutput { api,call_site,.. } => Some(json!({"argument":a.name,"producer_api":api,"producer_rva":call_site,"status":"static return/output provenance; success and object identity unobserved"})),
        _=>None,
    }).collect();
    let mut guids = Vec::new();
    for name in ["class_id", "interface_id"] {
        if let Some(data) = get(name).and_then(|v| bytes(pe, raw, state, v, 16)) {
            let hex = data.iter().map(|b| format!("{b:02x}")).collect::<String>();
            guids.push(json!({"argument":name,"windows_layout_hex":hex}));
        }
    }
    json!({"strings":texts,"socket_address":endpoint,"chaining_mode":chaining_mode,"algorithm_id":algorithm_id,"algorithm_name":algorithm_name,"guid_arguments":guids,"predecessors":predecessors,
        "status":"bounded static x64 argument evidence; path execution, API success, peer identity and cryptographic correctness unobserved"})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sockaddr_obeys_family_length_and_network_byte_order() {
        let data = [2, 0, 0x1f, 0x90, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0];
        assert_eq!(socket_address(&data).unwrap()["port"], 8080);
        assert_eq!(socket_address(&data).unwrap()["host"], "127.0.0.1");
        assert!(socket_address(&data[..8]).is_none());
        let mut invalid = data;
        invalid[0] = 99;
        assert!(socket_address(&invalid).is_none());
    }
}
