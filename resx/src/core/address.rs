#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddressSource {
    Rva,
    Va,
    FileOffset,
}

pub fn split_address_source_prefix(raw: &str) -> (Option<AddressSource>, &str) {
    let trimmed = raw.trim();
    let Some((prefix, value)) = trimmed.split_once(':') else {
        return (None, trimmed);
    };
    let source = match prefix.to_ascii_lowercase().as_str() {
        "rva" => AddressSource::Rva,
        "va" => AddressSource::Va,
        "fo" | "file" | "offset" | "fileoff" | "file-offset" => AddressSource::FileOffset,
        _ => return (None, trimmed),
    };
    (Some(source), value.trim())
}

pub fn parse_u64_literal(raw: &str) -> Option<u64> {
    let value = raw.trim().trim_end_matches(',');
    if value.is_empty() || value.starts_with('-') {
        return None;
    }
    let value = value.trim_start_matches('+').replace('_', "");
    let hex = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .or_else(|| value.strip_suffix('h'))
        .or_else(|| value.strip_suffix('H'));
    if let Some(hex) = hex {
        u64::from_str_radix(hex, 16).ok()
    } else {
        value.parse::<u64>().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::{parse_u64_literal, split_address_source_prefix, AddressSource};

    #[test]
    fn parses_common_integer_literal_forms() {
        assert_eq!(parse_u64_literal("0x2A"), Some(42));
        assert_eq!(parse_u64_literal("2ah"), Some(42));
        assert_eq!(parse_u64_literal("+4_2"), Some(42));
        assert_eq!(parse_u64_literal("-1"), None);
    }

    #[test]
    fn recognizes_address_source_aliases() {
        assert_eq!(
            split_address_source_prefix("file-offset: 0x400"),
            (Some(AddressSource::FileOffset), "0x400")
        );
        assert_eq!(
            split_address_source_prefix("VA:0x140001000"),
            (Some(AddressSource::Va), "0x140001000")
        );
        assert_eq!(
            split_address_source_prefix("symbol:name"),
            (None, "symbol:name")
        );
    }
}
