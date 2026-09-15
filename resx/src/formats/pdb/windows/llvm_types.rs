use super::*;

#[derive(Debug, Clone, Default)]
pub(super) struct LlvmDumpMember {
    name: String,
    offset: u64,
    type_id: u32,
    type_name: String,
    kind: String,
    size: u64,
}

#[derive(Debug, Clone, Default)]
pub(super) struct LlvmDumpRecord {
    type_id: u32,
    leaf: String,
    name: String,
    size: u64,
    field_list_id: u32,
    forward_to: u32,
    members: Vec<LlvmDumpMember>,
}

pub(super) fn load_pdb_types_via_llvm_dump(pdb_path: &str) -> Result<Vec<PdbTypeInfo>, String> {
    let tool = find_llvm_pdbutil()
        .ok_or_else(|| "llvm-pdbutil.exe not found for fallback type parsing".to_owned())?;
    let output = std::process::Command::new(tool)
        .args(["dump", "-types", pdb_path])
        .output()
        .map_err(|e| format!("spawn llvm-pdbutil: {}", e))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        return Err(if !stderr.is_empty() { stderr } else { stdout });
    }

    let text = String::from_utf8_lossy(&output.stdout);
    let mut records: HashMap<u32, LlvmDumpRecord> = HashMap::new();
    let mut current_id = 0u32;

    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((type_id, leaf, name)) = parse_llvm_dump_header(trimmed) {
            current_id = type_id;
            let rec = records.entry(type_id).or_default();
            rec.type_id = type_id;
            rec.leaf = leaf;
            if rec.name.is_empty() {
                rec.name = name;
            }
            continue;
        }
        if current_id == 0 || trimmed.is_empty() {
            continue;
        }
        let rec = match records.get_mut(&current_id) {
            Some(rec) => rec,
            None => continue,
        };
        if rec.leaf == "LF_FIELDLIST" {
            if let Some(member) = parse_llvm_dump_member(trimmed) {
                rec.members.push(member);
            }
            continue;
        }
        if let Some(field_list_id) = parse_llvm_dump_ref(trimmed, "field list:") {
            rec.field_list_id = field_list_id;
        }
        if let Some(size) = parse_llvm_dump_size(trimmed) {
            rec.size = size;
        }
        if let Some(target) = parse_llvm_dump_forward_ref(trimmed) {
            rec.forward_to = target;
        }
    }

    let mut out = Vec::new();
    let mut seen = HashSet::new();
    let ids = records.keys().copied().collect::<Vec<_>>();
    for type_id in ids {
        let Some(rec) = records.get(&type_id) else {
            continue;
        };
        let kind = llvm_leaf_kind(&rec.leaf);
        if kind.is_empty() {
            continue;
        }
        let canonical_id = canonical_dump_type_id(type_id, &records);
        let canonical = records.get(&canonical_id).unwrap_or(rec);
        let name = canonical.name.trim();
        if name.is_empty()
            || name.contains("(__cdecl")
            || name.starts_with('<')
            || !seen.insert(format!("{}|{}", type_id, name.to_ascii_lowercase()))
        {
            continue;
        }
        let members = if canonical.field_list_id != 0 {
            records
                .get(&canonical.field_list_id)
                .map(|field_list| {
                    field_list
                        .members
                        .iter()
                        .map(|member| PdbTypeMember {
                            name: member.name.clone(),
                            offset: member.offset,
                            type_id: member.type_id,
                            type_name: resolve_dump_type_name(
                                member.type_id,
                                &member.type_name,
                                &records,
                            ),
                            kind: member.kind.clone(),
                            size: member.size,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        out.push(PdbTypeInfo {
            type_id,
            name: name.to_owned(),
            kind: kind.to_owned(),
            size: canonical.size,
            members,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name).then_with(|| a.type_id.cmp(&b.type_id)));
    Ok(out)
}

pub(super) fn parse_llvm_dump_header(line: &str) -> Option<(u32, String, String)> {
    let (id_part, rest) = line.split_once('|')?;
    let type_id = u32::from_str_radix(id_part.trim().trim_start_matches("0x"), 16).ok()?;
    let leaf_start = rest.find("LF_")?;
    let rest = &rest[leaf_start..];
    let leaf_end = rest.find(' ')?;
    let leaf = rest[..leaf_end].trim().to_owned();
    let name = rest
        .split('`')
        .nth(1)
        .map(|s| s.trim().to_owned())
        .unwrap_or_default();
    Some((type_id, leaf, name))
}

pub(super) fn parse_llvm_dump_ref(line: &str, key: &str) -> Option<u32> {
    let idx = line.find(key)?;
    let tail = &line[idx + key.len()..];
    let hex = tail
        .trim_start()
        .strip_prefix("0x")
        .unwrap_or(tail.trim_start())
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    u32::from_str_radix(&hex, 16).ok()
}

pub(super) fn parse_llvm_dump_size(line: &str) -> Option<u64> {
    let idx = line.find("sizeof ")?;
    let tail = &line[idx + 7..];
    let digits = tail
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse::<u64>().ok()
}

pub(super) fn parse_llvm_dump_forward_ref(line: &str) -> Option<u32> {
    let idx = line.find("forward ref (-> 0x")?;
    let tail = &line[idx + "forward ref (-> 0x".len()..];
    let hex = tail
        .chars()
        .take_while(|ch| ch.is_ascii_hexdigit())
        .collect::<String>();
    u32::from_str_radix(&hex, 16).ok()
}

pub(super) fn parse_llvm_dump_member(line: &str) -> Option<LlvmDumpMember> {
    if !line.starts_with("- LF_MEMBER [") {
        return None;
    }
    let name = extract_between(line, "name = `", "`")?.to_owned();
    let type_field = line
        .split_once("Type = ")
        .map(|(_, tail)| tail.split(", offset =").next().unwrap_or(tail).trim())
        .unwrap_or_default();
    let type_id = type_field
        .strip_prefix("0x")
        .and_then(|tail| {
            let hex = tail
                .chars()
                .take_while(|ch| ch.is_ascii_hexdigit())
                .collect::<String>();
            u32::from_str_radix(&hex, 16).ok()
        })
        .unwrap_or(0);
    let type_name = type_field
        .split_once('(')
        .map(|(_, name)| name.trim_end_matches(')').trim())
        .unwrap_or(type_field)
        .to_owned();
    let offset = extract_after_decimal(line, "offset = ").unwrap_or(0);
    Some(LlvmDumpMember {
        name,
        offset,
        type_id,
        type_name,
        kind: "member".to_owned(),
        size: 0,
    })
}

fn extract_between<'a>(line: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let tail = line.split_once(start)?.1;
    Some(tail.split_once(end)?.0)
}

pub(super) fn extract_after_decimal(line: &str, key: &str) -> Option<u64> {
    let tail = line.split_once(key)?.1;
    let digits = tail
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    digits.parse::<u64>().ok()
}

pub(super) fn llvm_leaf_kind(leaf: &str) -> &'static str {
    match leaf {
        "LF_STRUCTURE" => "struct",
        "LF_CLASS" => "class",
        "LF_UNION" => "union",
        "LF_ENUM" => "enum",
        "LF_TYPEDEF" => "typedef",
        _ => "",
    }
}

pub(super) fn canonical_dump_type_id(type_id: u32, records: &HashMap<u32, LlvmDumpRecord>) -> u32 {
    let mut current = type_id;
    let mut seen = HashSet::new();
    while seen.insert(current) {
        let Some(rec) = records.get(&current) else {
            break;
        };
        if rec.forward_to == 0 {
            break;
        }
        current = rec.forward_to;
    }
    current
}

pub(super) fn resolve_dump_type_name(
    type_id: u32,
    fallback_name: &str,
    records: &HashMap<u32, LlvmDumpRecord>,
) -> String {
    if !fallback_name.trim().is_empty() {
        return fallback_name.trim().to_owned();
    }
    let canonical_id = canonical_dump_type_id(type_id, records);
    records
        .get(&canonical_id)
        .or_else(|| records.get(&type_id))
        .map(|rec| rec.name.trim().to_owned())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            if type_id == 0 {
                "unknown".to_owned()
            } else {
                format!("type_0x{:X}", type_id)
            }
        })
}

pub(super) fn find_llvm_pdbutil() -> Option<String> {
    let candidates = [
        r"C:\Program Files\LLVM\bin\llvm-pdbutil.exe",
        r"C:\Program Files (x86)\LLVM\bin\llvm-pdbutil.exe",
    ];
    for candidate in candidates {
        if Path::new(candidate).is_file() {
            return Some(candidate.to_owned());
        }
    }
    Some("llvm-pdbutil.exe".to_owned())
}
