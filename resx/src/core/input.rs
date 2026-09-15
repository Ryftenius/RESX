use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

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
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Image grew beyond the 512 MiB limit",
        ));
    }
    Ok(bytes)
}
