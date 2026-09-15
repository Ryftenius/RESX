//! Windows status-code classification and symbolic decoding.

#[cfg(windows)]
include!(concat!(env!("OUT_DIR"), "/ntstatus_codes.rs"));

#[cfg(not(windows))]
pub static NTSTATUS_CODES: &[(u32, &str)] = &[
    (0x00000000, "STATUS_SUCCESS"),
    (0x00000103, "STATUS_PENDING"),
    (0x80000005, "STATUS_BUFFER_OVERFLOW"),
    (0xC0000005, "STATUS_ACCESS_VIOLATION"),
    (0xC000000D, "STATUS_INVALID_PARAMETER"),
    (0xC0000022, "STATUS_ACCESS_DENIED"),
    (0xC0000023, "STATUS_BUFFER_TOO_SMALL"),
    (0xC00000BB, "STATUS_NOT_SUPPORTED"),
];

pub fn ntstatus_name(value: u32) -> Option<&'static str> {
    NTSTATUS_CODES
        .binary_search_by_key(&value, |(code, _)| *code)
        .ok()
        .map(|index| NTSTATUS_CODES[index].1)
}

pub fn ntstatus_severity(value: u32) -> &'static str {
    match value >> 30 {
        0 => "success",
        1 => "informational",
        2 => "warning",
        _ => "error",
    }
}

pub fn is_inferred_ntstatus(image: &str, function: &str) -> bool {
    std::path::Path::new(image)
        .file_stem()
        .is_some_and(|stem| stem.eq_ignore_ascii_case("ntdll"))
        && (function.starts_with("Nt") || function.starts_with("Zw"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ntstatus_names_and_severity() {
        assert_eq!(ntstatus_name(0), Some("STATUS_SUCCESS"));
        assert_eq!(ntstatus_name(0xC0000022), Some("STATUS_ACCESS_DENIED"));
        assert_eq!(ntstatus_severity(0x40000000), "informational");
        assert_eq!(ntstatus_severity(0x80000000), "warning");
        assert_eq!(ntstatus_severity(0xC0000000), "error");
        #[cfg(windows)]
        assert!(NTSTATUS_CODES.len() > 2_500);
    }
}
