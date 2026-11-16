use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

/// Validate an untrusted filename component before joining it to a trusted root.
/// This is deliberately independent of the host's path syntax.
pub fn is_safe_basename(name: &str) -> bool {
    if name.is_empty()
        || name.len() > 255
        || name.trim() != name
        || name.ends_with('.')
        || name
            .chars()
            .any(|c| c.is_control() || "<>:\"/\\|?*".contains(c))
    {
        return false;
    }
    let stem = name
        .split('.')
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_ascii_uppercase();
    if matches!(
        stem.as_str(),
        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
    ) {
        return false;
    }
    !["COM", "LPT"].iter().any(|prefix| {
        stem.strip_prefix(prefix).is_some_and(|tail| {
            matches!(
                tail,
                "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
            )
        })
    })
}

/// Bound allocation even when a file grows after metadata is read.
pub fn read_image(path: impl AsRef<Path>) -> io::Result<Vec<u8>> {
    let file = File::open(path)?;
    let metadata = file.metadata()?;
    let limit = crate::formats::pe::MAX_PE_BYTES;
    if !metadata.is_file() || metadata.len() > limit as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Expected a regular image file no larger than 512 MiB",
        ));
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(metadata.len() as usize)
        .map_err(io::Error::other)?;
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Image grew beyond the 512 MiB limit",
        ));
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_filenames_cannot_select_devices_streams_or_paths() {
        for name in [
            "",
            ".",
            "..",
            "../a.dll",
            "C:evil",
            "a:stream",
            "\\\\host\\a",
            "NUL.pdb",
            "con .pdb",
            "LPT1",
            "COM¹.dll",
            "a.",
            "a ",
            "a\n.dll",
            "CONOUT$",
        ] {
            assert!(!is_safe_basename(name), "{name:?}");
        }
        for name in [
            "kernel32.dll",
            "api-ms-win-core-memory-l1-1-0",
            "my symbols.pdb",
            "Å.pdb",
        ] {
            assert!(is_safe_basename(name), "{name:?}");
        }
    }
}
