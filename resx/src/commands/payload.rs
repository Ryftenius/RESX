#![forbid(unsafe_code)]

//! Explicit, bounded local transformations with a complete artifact ledger.
use crate::analysis::codec;
use crate::core::{
    config::{Cli, Config},
    json::versioned_object,
};
use serde_json::json;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn local_path(path: &Path) -> Result<PathBuf, String> {
    let absolute = std::path::absolute(path).map_err(|e| e.to_string())?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if !matches!(absolute.components().next(),Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(),std::path::Prefix::Disk(_)|std::path::Prefix::VerbatimDisk(_)))
        {
            return Err("Payload files require local disk paths".into());
        }
        let mut current = PathBuf::new();
        for component in absolute.components() {
            current.push(component.as_os_str());
            if matches!(component, std::path::Component::Prefix(_)) {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&current).map_err(|e| e.to_string())?;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err("Payload paths cannot traverse reparse points".into());
            }
        }
    }
    std::fs::canonicalize(absolute).map_err(|e| e.to_string())
}

fn destination(path: &str) -> Result<PathBuf, String> {
    let path = Path::new(path);
    let parent = local_path(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )
    .map_err(|e| e.to_string())?;
    #[cfg(windows)]
    if !matches!(parent.components().next(),Some(std::path::Component::Prefix(prefix)) if matches!(prefix.kind(),std::path::Prefix::Disk(_)|std::path::Prefix::VerbatimDisk(_)))
    {
        return Err("Payload output requires a local disk directory".into());
    }
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.is_empty() && !s.contains(':'))
        .ok_or("Invalid payload directory name")?;
    let output = parent.join(name);
    if output.exists() {
        return Err("Payload directory already exists; choose a new directory".into());
    }
    Ok(output)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())
}

fn identify(bytes: &[u8]) -> Option<&'static str> {
    if bytes.starts_with(&[0x1f, 0x8b, 8]) {
        Some("gzip")
    } else if bytes.len() >= 2
        && bytes[0] & 15 == 8
        && bytes[0] >> 4 <= 7
        && u16::from_be_bytes([bytes[0], bytes[1]]).is_multiple_of(31)
    {
        Some("zlib")
    } else {
        None
    }
}

pub fn run(cli: &Cli, cfg: &Config, output: &mut dyn Write) -> Result<(), String> {
    let destination = destination(
        cli.payload_dir
            .as_deref()
            .ok_or("payload requires --payload-dir <new-directory>")?,
    )?;
    let source =
        std::fs::File::open(local_path(Path::new(&cfg.dll))?).map_err(|e| e.to_string())?;
    if !source.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("Payload input must be a regular file".into());
    }
    let mut raw = Vec::new();
    source
        .take(codec::MAX_OUTPUT as u64 + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() > codec::MAX_OUTPUT {
        return Err("Payload input exceeds 16 MiB".into());
    }
    let start = usize::try_from(cli.payload_offset.unwrap_or(0)).map_err(|e| e.to_string())?;
    let length = cli
        .payload_length
        .map(usize::try_from)
        .transpose()
        .map_err(|e| e.to_string())?
        .unwrap_or(raw.len().saturating_sub(start));
    let end = start.checked_add(length).ok_or("Payload extent overflow")?;
    let mut bytes = raw
        .get(start..end)
        .ok_or("Payload extent is outside the input")?
        .to_vec();
    let source_hash = crate::core::hash::sha256(&raw)?;
    let requested = cli.codec.as_deref().unwrap_or("auto");
    if requested != "aes-cbc" && (cli.key_file.is_some() || cli.iv_hex.is_some() || cli.pkcs7) {
        return Err("Key, IV and padding options require --codec aes-cbc".into());
    }
    let mut layers = Vec::new();
    let mut artifacts = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    let mut total = 0usize;
    for depth in 0..8 {
        let input_hash = crate::core::hash::sha256(&bytes)?;
        if !seen.insert(input_hash.clone()) {
            return Err("Repeated payload layer rejected".into());
        }
        let method = if depth == 0 && requested != "auto" {
            Some(requested)
        } else {
            identify(&bytes)
        };
        let Some(method) = method else {
            break;
        };
        let decoded = if method == "aes-cbc" {
            struct Key(Vec<u8>);
            impl Drop for Key {
                fn drop(&mut self) {
                    zeroize::Zeroize::zeroize(&mut self.0);
                }
            }
            let file = std::fs::File::open(local_path(Path::new(
                cli.key_file
                    .as_deref()
                    .ok_or("AES-CBC requires --key-file with raw key bytes")?,
            ))?)
            .map_err(|e| e.to_string())?;
            if !file.metadata().map_err(|e| e.to_string())?.is_file() {
                return Err("Key source must be a regular local file".into());
            }
            let mut key = Key(Vec::new());
            file.take(33)
                .read_to_end(&mut key.0)
                .map_err(|e| e.to_string())?;
            let iv = codec::decode(
                "hex",
                cli.iv_hex
                    .as_deref()
                    .ok_or("AES-CBC requires --iv-hex")?
                    .as_bytes(),
            )?;
            crate::analysis::crypto_decode::aes_cbc(&bytes, &key.0, &iv, cli.pkcs7)?
        } else {
            codec::decode(method, &bytes)?
        };
        total = total
            .checked_add(decoded.len())
            .ok_or("Payload budget overflow")?;
        if total > 32 * 1024 * 1024 {
            return Err("Aggregate payload output exceeds 32 MiB".into());
        }
        let hash = crate::core::hash::sha256(&decoded)?;
        if cfg.verbose && !cfg.quiet {
            eprintln!(
                "RESX: layer {depth}: {method}, {} -> {} bytes, SHA256={hash}",
                bytes.len(),
                decoded.len()
            );
        }
        let name = format!("layer-{depth:02}-{hash}.bin");
        layers.push(json!({"depth":depth,"codec":method,"input_sha256":input_hash,"output_sha256":hash,"input_size":bytes.len(),"output_size":decoded.len(),"file":name,"validation":if matches!(method,"gzip"|"zlib") {"format checksum and extent verified"} else if method=="aes-cbc" {"Explicit key/IV and OS AES-CBC operation; CBC does not authenticate plaintext"} else {"complete encoding grammar and extent verified"}}));
        artifacts.push((name, decoded.clone()));
        bytes = decoded;
    }
    if layers.is_empty() {
        return Err("No supported compression framing found; specify --codec base64, hex, deflate, zlib or gzip for an explicit transformation".into());
    }
    let limited = layers.len() == 8 && identify(&bytes).is_some();
    let text = crate::analysis::text::scan(&bytes, 6, true, true);
    let configuration = if bytes.len() <= 1024 * 1024 {
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .filter(|v| v.is_object() || v.is_array())
    } else {
        None
    };
    let pe = crate::formats::pe::parse_pe(&bytes).ok();
    let metadata=pe.as_ref().map(|p|json!({"machine":p.machine,"image_base":p.image_base,"entry_rva":p.entry_point,"section_count":p.sections.len(),"header_corruption":p.header_corruption_detected(),"interpretation":"Decoded PE metadata; loadability and behavioral equivalence untested"}));
    // Decode and validate everything before creating any output. Names are
    // generated from hashes, never from input archive/path strings.
    std::fs::create_dir(&destination).map_err(|e| e.to_string())?;
    for (name, artifact) in &artifacts {
        write_new(&destination.join(name), artifact)?;
    }
    let fingerprint = if pe
        .as_ref()
        .is_some_and(|p| !p.header_corruption_detected() && matches!(p.machine, 0x8664 | 0x14c))
    {
        let mut profile_cfg = cfg.clone();
        profile_cfg.no_pdb = true;
        profile_cfg.diff_max_functions = profile_cfg.diff_max_functions.clamp(1, 1024);
        let path = destination.join(&artifacts.last().unwrap().0);
        match crate::analysis::diff::profile_image_for_index(&path, &profile_cfg) {
            Ok(profile) => {
                json!({"status":"profiled","basis":"Existing normalized code/CFG/API/constant corpus fingerprints","profile":profile,"interpretation":"Structural similarity is not execution equivalence or family attribution"})
            }
            Err(error) => json!({"status":"unavailable","error":error}),
        }
    } else {
        json!({"status":"not-applicable","reason":"Final bytes are not a validated supported native PE"})
    };
    let report = json!({"source_sha256":source_hash,"source_range":{"offset":start,"size":length},"layers":layers,"layer_limit_reached":limited,"final_sha256":crate::core::hash::sha256(&bytes)?,"decoded_bytes":bytes.len(),"strings":text,"configuration":configuration,"pe":metadata,"structural_fingerprint":fingerprint,
        "decompression_performed":layers.iter().any(|l|l["codec"]=="zlib" || l["codec"]=="gzip" || l["codec"]=="deflate"),"target_executed":false,"executable_reconstructed":false,
        "limitations":["Automatic framing supports zlib and single-member gzip; explicit codecs also support raw DEFLATE, canonical base64, hex and AES-CBC with supplied key/IV","No implicit key guessing, protector decoder, C2 attribution or execution-equivalence claim","Checksums establish format consistency, not authenticated origin; AES-CBC alone does not authenticate plaintext","At most eight layers, 16 MiB per input/output, 32 MiB aggregate output and bounded expansion"]});
    let report = serde_json::to_vec_pretty(&versioned_object("payload", &report))
        .map_err(|e| e.to_string())?;
    if cfg.verbose && !cfg.quiet {
        eprintln!(
            "RESX: retained {} layers in {}; manifest=payload.json; layer_limit_reached={limited}",
            artifacts.len(),
            destination.display()
        );
    }
    write_new(&destination.join("payload.json"), &report)?;
    output
        .write_all(&report)
        .and_then(|_| output.write_all(b"\n"))
        .map_err(|e| e.to_string())
}
