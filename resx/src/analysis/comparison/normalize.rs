use super::*;

pub(super) fn options_report(
    mode: &str,
    threshold: u8,
    include_weak: bool,
    max_functions: usize,
) -> DiffOptionsReport {
    DiffOptionsReport {
        mode: mode.to_owned(),
        threshold,
        include_weak,
        max_functions,
    }
}

pub(super) fn vec_to_set(values: &[String]) -> BTreeSet<String> {
    values.iter().cloned().collect()
}

pub(super) fn normalize_instruction(
    insn: &Instruction,
    pe: &PeFile,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
    block_ids: &BTreeMap<u32, usize>,
) -> NormalizedInstruction {
    let opcode = format!("{:?}", insn.iced.mnemonic()).to_ascii_lowercase();
    let mut parts = vec![opcode.clone()];
    let mut constants = Vec::new();

    for idx in 0..insn.iced.op_count() {
        let op = match insn.iced.op_kind(idx) {
            OpKind::Register => format!("reg:{}", register_class(insn.iced.op_register(idx))),
            OpKind::Memory => normalize_memory(&insn.iced, pe, import_slots, string_rvas),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64 => {
                let target = insn.iced.near_branch_target();
                let label = pe
                    .va_to_rva(target)
                    .and_then(|rva| block_ids.get(&rva).copied().map(|id| format!("block:{id}")))
                    .unwrap_or_else(|| classify_address(target, pe, import_slots, string_rvas));
                format!("branch:{label}")
            }
            _ => {
                if let Some(value) = immediate_value(&insn.iced, idx) {
                    let class = classify_immediate(value, pe, import_slots, string_rvas);
                    constants.push(class.clone());
                    format!("imm:{class}")
                } else {
                    "op:?".to_owned()
                }
            }
        };
        parts.push(op);
    }

    NormalizedInstruction {
        opcode,
        text: parts.join("|"),
        constants,
    }
}

pub(super) struct NormalizedInstruction {
    pub(super) opcode: String,
    pub(super) text: String,
    pub(super) constants: Vec<String>,
}

pub(super) fn normalize_memory(
    instr: &iced_x86::Instruction,
    pe: &PeFile,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
) -> String {
    let base = instr.memory_base();
    if matches!(
        base,
        Register::RSP | Register::RBP | Register::ESP | Register::EBP
    ) {
        return format!(
            "mem:stack:{}",
            displacement_class(instr.memory_displacement64())
        );
    }
    if matches!(base, Register::RIP | Register::EIP) {
        return format!(
            "mem:rip:{}",
            classify_address(instr.ip_rel_memory_address(), pe, import_slots, string_rvas)
        );
    }
    if base == Register::None && instr.memory_index() == Register::None {
        return format!(
            "mem:absolute:{}",
            classify_address(instr.memory_displacement64(), pe, import_slots, string_rvas)
        );
    }
    format!(
        "mem:{}:{}",
        register_class(base),
        displacement_class(instr.memory_displacement64())
    )
}

pub(super) fn classify_immediate(
    value: u64,
    pe: &PeFile,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
) -> String {
    let address_class = classify_address(value, pe, import_slots, string_rvas);
    if address_class != "absolute" {
        return address_class;
    }
    match value {
        0 => "zero".to_owned(),
        1 => "one".to_owned(),
        2..=16 => "small".to_owned(),
        17..=0xFF => "byte".to_owned(),
        0x100..=0xFFFF => {
            if value.is_power_of_two() {
                "pow2".to_owned()
            } else {
                "word".to_owned()
            }
        }
        0x8000_0000..=0xFFFF_FFFF => {
            let v = value as u32;
            if (v & 0xC000_0000) == 0xC000_0000 || (v & 0x8000_0000) == 0x8000_0000 {
                "status".to_owned()
            } else {
                "dword".to_owned()
            }
        }
        _ => "qword".to_owned(),
    }
}

pub(super) fn classify_address(
    value: u64,
    pe: &PeFile,
    import_slots: &BTreeMap<u32, String>,
    string_rvas: &BTreeSet<u32>,
) -> String {
    let rva = pe.va_to_rva(value).or_else(|| {
        u32::try_from(value)
            .ok()
            .filter(|rva| pe.rva_to_section(*rva).is_some())
    });
    let Some(rva) = rva else {
        return "absolute".to_owned();
    };
    if import_slots.contains_key(&rva) {
        return "import-slot".to_owned();
    }
    if string_rvas.contains(&rva) {
        return "string".to_owned();
    }
    if let Some(section) = pe.rva_to_section(rva) {
        if section.is_executable() {
            return "code".to_owned();
        }
        let name = section.name.to_ascii_lowercase();
        if name.contains("rdata") || name.contains("rsrc") {
            return "readonly-data".to_owned();
        }
        return "data".to_owned();
    }
    "absolute".to_owned()
}

pub(super) fn displacement_class(value: u64) -> &'static str {
    if value == 0 {
        "zero"
    } else if value <= 0x7F {
        "small"
    } else if value <= 0xFFFF {
        "medium"
    } else {
        "large"
    }
}

pub(super) fn register_class(reg: Register) -> &'static str {
    let name = format!("{:?}", reg).to_ascii_lowercase();
    if name == "none" {
        "none"
    } else if name.starts_with("xmm") {
        "xmm"
    } else if name.starts_with("ymm") {
        "ymm"
    } else if name.starts_with("zmm") {
        "zmm"
    } else if matches!(name.as_str(), "cs" | "ds" | "es" | "fs" | "gs" | "ss") {
        "seg"
    } else if name.starts_with('r')
        && !name.ends_with('d')
        && !name.ends_with('w')
        && !name.ends_with('l')
    {
        "gpr64"
    } else if name.starts_with('e') || name.ends_with('d') {
        "gpr32"
    } else if name.ends_with('w')
        || matches!(
            name.as_str(),
            "ax" | "bx" | "cx" | "dx" | "si" | "di" | "sp" | "bp"
        )
    {
        "gpr16"
    } else if name.ends_with('l')
        || name.ends_with('h')
        || matches!(name.as_str(), "al" | "bl" | "cl" | "dl")
    {
        "gpr8"
    } else {
        "reg"
    }
}

pub(super) fn immediate_value(instr: &iced_x86::Instruction, idx: u32) -> Option<u64> {
    match instr.op_kind(idx) {
        OpKind::Immediate8 => Some(instr.immediate8() as u64),
        OpKind::Immediate16 => Some(instr.immediate16() as u64),
        OpKind::Immediate32 | OpKind::Immediate32to64 => Some(instr.immediate32() as u64),
        OpKind::Immediate64 => Some(instr.immediate64()),
        _ => None,
    }
}

pub(super) fn normalized_api_call(call: &crate::analysis::disasm::ApiCall) -> Option<String> {
    if call.is_import || !call.dll.is_empty() {
        let dll = call.dll.trim().to_ascii_lowercase();
        let name = normalize_api_name(&call.label);
        return Some(if dll.is_empty() {
            name
        } else {
            format!("{dll}!{name}")
        });
    }
    let name = normalize_api_name(&call.label);
    if name.starts_with("sub_") || name.is_empty() {
        None
    } else {
        Some(name)
    }
}

pub(super) fn normalize_api_name(name: &str) -> String {
    let tail = name
        .rsplit(['!', ':'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('_');
    let tail = tail
        .strip_suffix('A')
        .or_else(|| tail.strip_suffix('W'))
        .unwrap_or(tail);
    tail.to_ascii_lowercase()
}

pub(super) fn normalized_name(name: &str) -> String {
    let tail = name
        .rsplit(['!', ':'])
        .next()
        .unwrap_or(name)
        .trim_start_matches('_');
    if tail.starts_with("sub_") || tail.starts_with("fn_") {
        String::new()
    } else {
        tail.to_ascii_lowercase()
    }
}

pub(super) fn name_similarity(left: &str, right: &str) -> f64 {
    let l = normalized_name(left);
    let r = normalized_name(right);
    if l.is_empty() || r.is_empty() {
        return 0.0;
    }
    if l == r {
        1.0
    } else if l.contains(&r) || r.contains(&l) {
        0.65
    } else {
        0.0
    }
}

pub(super) fn function_ref(fp: &FunctionFingerprint) -> FunctionRef {
    FunctionRef {
        name: fp.name.clone(),
        rva: hex32(fp.rva),
        section: fp.section.clone(),
        source: fp.source.clone(),
        confidence: fp.confidence,
        size_bytes: fp.size_bytes,
        insn_count: fp.insn_count,
        block_count: fp.block_count,
        edge_count: fp.edge_count,
        semantic_hash: hex64(fp.semantic_hash),
        cfg_hash: hex64(fp.cfg_hash),
        api_hash: hex64(fp.api_hash),
        fuzzy_hash: hex64(fp.fuzzy_hash),
        noise: fp.noise,
        noise_reason: fp.noise_reason.clone(),
        trait_tags: fp.trait_tags.clone(),
    }
}

pub(super) fn function_size(insns: &[Instruction]) -> usize {
    match (insns.first(), insns.last()) {
        (Some(first), Some(last)) => last
            .rva
            .saturating_sub(first.rva)
            .saturating_add(last.bytes.len() as u32) as usize,
        _ => 0,
    }
}

pub(super) fn decode_config(cfg: &Config, mode: &str) -> Config {
    let mut out = cfg.clone();
    match mode {
        "quick" => {
            out.max_bytes = out.max_bytes.clamp(512, 2048);
            out.max_insns = out.max_insns.clamp(64, 256);
        }
        "deep" => {
            out.max_bytes = out.max_bytes.max(16 * 1024);
            out.max_insns = out.max_insns.max(2048);
        }
        _ => {
            out.max_bytes = out.max_bytes.max(4096);
            out.max_insns = out.max_insns.max(512);
        }
    }
    out
}

pub(super) fn normalize_mode(raw: &str) -> String {
    match raw.to_ascii_lowercase().as_str() {
        "quick" => "quick".to_owned(),
        "deep" => "deep".to_owned(),
        _ => "balanced".to_owned(),
    }
}

pub(super) fn left_pdb(cfg: &Config) -> &str {
    if cfg.left_pdb_file.is_empty() {
        &cfg.pdb_file
    } else {
        &cfg.left_pdb_file
    }
}

pub(super) fn right_pdb(cfg: &Config) -> &str {
    if cfg.right_pdb_file.is_empty() {
        &cfg.pdb_file
    } else {
        &cfg.right_pdb_file
    }
}

pub(super) fn import_slot_map(imports: &[ImportDll]) -> BTreeMap<u32, String> {
    let mut out = BTreeMap::new();
    for dll in imports {
        for entry in &dll.entries {
            out.insert(
                entry.slot_rva,
                format!(
                    "{}!{}",
                    dll.dll.to_ascii_lowercase(),
                    normalize_api_name(&entry.name)
                ),
            );
        }
    }
    out
}

pub(super) fn import_name_set(imports: &[ImportDll]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for dll in imports {
        for entry in &dll.entries {
            out.insert(format!(
                "{}!{}",
                dll.dll.to_ascii_lowercase(),
                normalize_api_name(&entry.name)
            ));
        }
    }
    out
}

pub(super) fn export_name_set(exports: &[Export]) -> BTreeSet<String> {
    exports
        .iter()
        .filter(|e| !e.name.is_empty())
        .map(|e| normalized_name(&e.name))
        .filter(|name| !name.is_empty())
        .collect()
}

pub(super) fn string_set(data: &PeDataSummary) -> BTreeSet<String> {
    data.strings
        .iter()
        .map(|s| s.value.trim().to_owned())
        .filter(|s| s.len() >= 4)
        .take(4096)
        .collect()
}

pub(super) fn tier(score: u8) -> &'static str {
    match score {
        98..=100 => "exact",
        80..=97 => "strong",
        65..=79 => "changed",
        50..=64 => "weak",
        _ => "low",
    }
}

pub(super) fn coverage(matched: usize, total: usize) -> u8 {
    if total == 0 {
        0
    } else {
        (((matched as f64 / total as f64) * 100.0).round() as u8).min(100)
    }
}

pub(super) fn ratio(a: f64, b: f64) -> f64 {
    if a <= 0.0 && b <= 0.0 {
        1.0
    } else if a <= 0.0 || b <= 0.0 {
        0.0
    } else {
        a.min(b) / a.max(b)
    }
}

pub(super) fn score_float(value: f64) -> u8 {
    (value.clamp(0.0, 1.0) * 100.0).round() as u8
}

pub(super) fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

pub(super) fn set_similarity(left: &BTreeSet<String>, right: &BTreeSet<String>) -> f64 {
    if left.is_empty() && right.is_empty() {
        1.0
    } else {
        let common = left.intersection(right).count();
        let total = left.union(right).count();
        if total == 0 {
            0.0
        } else {
            common as f64 / total as f64
        }
    }
}

pub(super) fn multiset_jaccard(left: &[String], right: &[String]) -> f64 {
    let l = count_map(left.iter().map(String::as_str));
    let r = count_map(right.iter().map(String::as_str));
    counted_jaccard(&l, &r)
}

pub(super) fn multiset_jaccard_u64(left: &[u64], right: &[u64]) -> f64 {
    let l = count_map(left.iter().copied());
    let r = count_map(right.iter().copied());
    counted_jaccard(&l, &r)
}

fn count_map<T, I>(items: I) -> HashMap<T, usize>
where
    T: Eq + std::hash::Hash,
    I: IntoIterator<Item = T>,
{
    let mut map = HashMap::new();
    for item in items {
        *map.entry(item).or_insert(0) += 1;
    }
    map
}

fn counted_jaccard<T>(left: &HashMap<T, usize>, right: &HashMap<T, usize>) -> f64
where
    T: Eq + std::hash::Hash,
{
    if left.is_empty() && right.is_empty() {
        return 1.0;
    }
    let mut intersection = 0usize;
    let mut union = 0usize;
    let keys = left.keys().chain(right.keys()).collect::<HashSet<_>>();
    for key in keys {
        let l = left.get(key).copied().unwrap_or(0);
        let r = right.get(key).copied().unwrap_or(0);
        intersection += l.min(r);
        union += l.max(r);
    }
    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}

pub(super) fn ngrams(tokens: &[String], n: usize) -> Vec<String> {
    if tokens.is_empty() {
        return Vec::new();
    }
    if tokens.len() < n {
        return vec![tokens.join("|")];
    }
    tokens
        .windows(n)
        .map(|window| window.join("|"))
        .collect::<Vec<_>>()
}

pub(super) fn bucket(value: u64) -> &'static str {
    match value {
        0 => "0",
        1 => "1",
        2..=3 => "2-3",
        4..=7 => "4-7",
        8..=15 => "8-15",
        16..=31 => "16-31",
        32..=63 => "32-63",
        _ => "64+",
    }
}

pub(super) fn stable_hash_tokens<'a, I, S>(tokens: I) -> u64
where
    I: IntoIterator<Item = S>,
    S: AsRef<str> + 'a,
{
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for token in tokens {
        for byte in token.as_ref().as_bytes() {
            hash ^= *byte as u64;
            hash = hash.wrapping_mul(0x1000_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x1000_0000_01b3);
    }
    hash
}

pub(super) fn stable_hash_one(token: &str) -> u64 {
    stable_hash_tokens([token])
}

pub(super) fn simhash_tokens<'a, I, S>(tokens: I) -> u64
where
    I: IntoIterator<Item = S>,
    S: AsRef<str> + 'a,
{
    let mut weights = [0i32; 64];
    let mut seen = false;
    for token in tokens {
        seen = true;
        let hash = stable_hash_one(token.as_ref());
        for (idx, weight) in weights.iter_mut().enumerate() {
            if (hash >> idx) & 1 == 1 {
                *weight += 1;
            } else {
                *weight -= 1;
            }
        }
    }
    if !seen {
        return 0;
    }
    weights.iter().enumerate().fold(0u64, |acc, (idx, weight)| {
        if *weight >= 0 {
            acc | (1u64 << idx)
        } else {
            acc
        }
    })
}

pub(super) fn hamming_hex64(left: &str, right: &str) -> u8 {
    let Some(l) = parse_hex64(left) else {
        return 64;
    };
    let Some(r) = parse_hex64(right) else {
        return 64;
    };
    (l ^ r).count_ones() as u8
}

pub(super) fn hamming64(left: u64, right: u64) -> u8 {
    (left ^ right).count_ones() as u8
}

pub(super) fn capped_delta(left: &BTreeSet<String>, right: &BTreeSet<String>) -> Vec<String> {
    left.difference(right).take(64).cloned().collect()
}

pub(super) fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            out.push(value);
        }
    }
    out
}

pub(super) fn parse_hex32(raw: &str) -> Option<u32> {
    let s = raw.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u32::from_str_radix(hex, 16).ok()
}

pub(super) fn parse_hex64(raw: &str) -> Option<u64> {
    let s = raw.trim();
    let hex = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    u64::from_str_radix(hex, 16).ok()
}

pub(super) fn hex32(value: u32) -> String {
    format!("0x{:08X}", value)
}

pub(super) fn hex64(value: u64) -> String {
    format!("0x{:016X}", value)
}
