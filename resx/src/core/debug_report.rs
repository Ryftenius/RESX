use std::io::Write;
use std::path::{Path, PathBuf};

use serde_json::json;
use sha2::{Digest, Sha256};

pub fn write(
    path: &Path,
    args: &[String],
    target: Option<&Path>,
    include_target: bool,
    elapsed_ms: u128,
) -> Result<(), String> {
    if path
        .extension()
        .and_then(|v| v.to_str())
        .is_none_or(|v| !v.eq_ignore_ascii_case("zip"))
    {
        return Err("--debug-report must name a .zip file".into());
    }
    let mut entries = Vec::<(String, Vec<u8>)>::new();
    let mut target_entry = None;
    if let Some(target) = target {
        if let Ok(bytes) = std::fs::read(target) {
            let pe = crate::formats::pe::parse_pe(&bytes).ok();
            target_entry = Some(
                json!({"file_name":target.file_name().and_then(|v|v.to_str()),"size":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes)),"architecture":pe.as_ref().map(|p|p.arch),"entry_rva":pe.as_ref().map(|p|format!("0x{:08X}",p.entry_point)),"sections":pe.as_ref().map(|p|p.sections.len())}),
            );
            if include_target {
                if bytes.len() > 64 * 1024 * 1024 {
                    return Err("debug-report target inclusion is capped at 64 MiB".into());
                }
                entries.push(("target.bin".into(), bytes));
            }
        }
    }
    let report = json!({"schema":"resx-debug-report-v1","resx_version":env!("CARGO_PKG_VERSION"),"command":args.iter().skip(1).map(|v|sanitize_arg(v)).collect::<Vec<_>>(),"host":{"os":std::env::consts::OS,"architecture":std::env::consts::ARCH},"elapsed_ms":elapsed_ms,"target":target_entry,"target_included":include_target,"redaction":"absolute paths, usernames, machine name, environment, memory contents, and unique host identifiers omitted"});
    entries.insert(
        0,
        (
            "report.json".into(),
            serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?,
        ),
    );
    write_stored_zip(path, &entries)
}

fn sanitize_arg(arg: &str) -> String {
    if arg.starts_with('-') {
        return arg.to_owned();
    }
    let path = PathBuf::from(arg);
    if path.is_absolute() || arg.contains('\\') || arg.contains('/') {
        path.file_name()
            .and_then(|v| v.to_str())
            .unwrap_or("<path>")
            .to_owned()
    } else {
        arg.to_owned()
    }
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb8_8320 } else { 0 };
        }
    }
    !crc
}
fn write_stored_zip(path: &Path, entries: &[(String, Vec<u8>)]) -> Result<(), String> {
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    let mut central = Vec::new();
    let mut offset = 0u32;
    for (name, data) in entries {
        let name = name.as_bytes();
        let size = u32::try_from(data.len()).map_err(|_| "debug report entry too large")?;
        let crc = crc32(data);
        let mut local = Vec::new();
        local.extend(0x0403_4b50u32.to_le_bytes());
        local.extend(20u16.to_le_bytes());
        local.extend([0u8; 8]);
        local.extend(crc.to_le_bytes());
        local.extend(size.to_le_bytes());
        local.extend(size.to_le_bytes());
        local.extend((name.len() as u16).to_le_bytes());
        local.extend(0u16.to_le_bytes());
        local.extend(name);
        output
            .write_all(&local)
            .and_then(|_| output.write_all(data))
            .map_err(|e| e.to_string())?;
        central.extend(0x0201_4b50u32.to_le_bytes());
        central.extend(20u16.to_le_bytes());
        central.extend(20u16.to_le_bytes());
        central.extend([0u8; 8]);
        central.extend(crc.to_le_bytes());
        central.extend(size.to_le_bytes());
        central.extend(size.to_le_bytes());
        central.extend((name.len() as u16).to_le_bytes());
        central.extend([0u8; 12]);
        central.extend(offset.to_le_bytes());
        central.extend(name);
        offset = offset
            .checked_add(
                u32::try_from(local.len() + data.len())
                    .map_err(|_| "debug report ZIP too large")?,
            )
            .ok_or("debug report ZIP too large")?;
    }
    let central_offset = offset;
    output.write_all(&central).map_err(|e| e.to_string())?;
    let mut end = Vec::new();
    end.extend(0x0605_4b50u32.to_le_bytes());
    end.extend([0u8; 4]);
    end.extend((entries.len() as u16).to_le_bytes());
    end.extend((entries.len() as u16).to_le_bytes());
    end.extend((central.len() as u32).to_le_bytes());
    end.extend(central_offset.to_le_bytes());
    end.extend(0u16.to_le_bytes());
    output.write_all(&end).map_err(|e| e.to_string())
}
