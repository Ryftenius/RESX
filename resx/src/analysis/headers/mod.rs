//! Official API signatures from the Windows SDK headers, as an opt-in enrichment.
//!
//! `resx config --headers <dir>` points RESX at an SDK include directory. The C API
//! headers there (`um`, `shared`, `ucrt`, `km`) are scanned once into an index of
//! prototypes, typedefs, enums and integer constants, cached per user, and used to
//! name and type the arguments of API calls: `VirtualAlloc(lpAddress=NULL,
//! dwSize=0x1000, flAllocationType=MEM_COMMIT|MEM_RESERVE, flProtect=PAGE_READWRITE)`.
//! Nothing is read from the headers unless they are configured.

mod families;
mod parse;

use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

pub use parse::{Direction, Param, Prototype};
use parse::{TypeDef, TypeKind};

/// Bumped when the parser or index layout changes, so stale caches are rebuilt.
const FORMAT: u32 = 2;
/// Include subdirectories holding C API declarations, in precedence order.
const SCANNED: &[&str] = &["um", "shared", "ucrt", "km"];

#[derive(Default, Serialize, Deserialize)]
pub struct HeaderIndex {
    pub root: String,
    prototypes: HashMap<String, Prototype>,
    typedefs: HashMap<String, TypeDef>,
    /// Enum type → its enumerators, in declaration order.
    enums: HashMap<String, Vec<(String, i64)>>,
    constants: HashMap<String, u64>,
    /// `#define CreateFile CreateFileW` and the like.
    aliases: HashMap<String, String>,
    #[serde(skip)]
    families: families::Candidates,
}

/// A recovered argument value at a call site.
#[derive(Clone, Debug, PartialEq, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ArgValue {
    Unknown,
    Int(u64),
    /// An address inside the image that does not hold a string.
    ImageAddress(u64),
    /// Executable image address used as a callback according to the API contract.
    Callback {
        va: u64,
        rva: u32,
        typedef: String,
        evidence: String,
    },
    Text {
        text: String,
        wide: bool,
    },
    /// A buffer in the caller's frame, by offset from its entry stack pointer.
    Stack(i64),
    /// A pointer resolved at run time, by API name.
    Api(String),
    Module(String),
    Import(String),
    /// A value loaded from a writable global.
    Global(u64),
    /// The caller's own parameter.
    Param(u8),
}

/// Header-backed interpretation of statically recovered call arguments.
#[derive(Clone, Debug, Serialize)]
pub struct CallSignature {
    pub declaration: String,
    pub call: String,
    pub source: String,
    pub arguments: Vec<ArgValue>,
}

/// Recover arguments once per function, only when an identified API has a header.
pub fn enrich_calls(
    index: &HeaderIndex,
    pe: &crate::formats::pe::PeFile,
    raw: &[u8],
    insns: &[crate::analysis::disasm::Instruction],
    calls: &[crate::analysis::disasm::ApiCall],
) -> HashMap<u32, CallSignature> {
    let known: Vec<_> = calls
        .iter()
        .filter_map(|call| {
            // A local symbol sharing an SDK name does not establish an API call.
            if !call.is_import && call.dynamic.is_none() {
                return None;
            }
            Some((call, index.prototype(&call.label)?))
        })
        .collect();
    if known.is_empty() {
        return HashMap::new();
    }
    let decoded: Vec<_> = insns.iter().map(|insn| insn.iced).collect();
    let arguments = crate::analysis::resolution::call_arguments(pe, raw, &decoded);
    known
        .into_iter()
        .map(|(call, prototype)| {
            let mut args = arguments.get(&call.rva).cloned().unwrap_or_default();
            index.classify_callbacks(prototype, &mut args, pe, raw);
            (
                call.rva,
                CallSignature {
                    declaration: index.declaration(prototype),
                    call: index.render_call(
                        prototype,
                        &args,
                        if pe.machine == 0x014c { 4 } else { 8 },
                    ),
                    source: prototype.header.clone(),
                    arguments: args,
                },
            )
        })
        .collect()
}

/// How a parameter type is passed and shown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Class {
    Void,
    Float {
        bytes: u8,
    },
    Int {
        bytes: u8,
    },
    Bool {
        bytes: u8,
    },
    /// NTSTATUS, HRESULT and kin.
    Status,
    /// Pointer-sized integers and handles.
    PtrSized {
        handle: bool,
    },
    Pointer {
        text: Option<bool>,
    },
    FunctionPointer,
    Enum(String),
    Record {
        bytes: Option<u8>,
    },
}

impl Class {
    /// Stack slots of the given width the value takes as an argument.
    fn slots(&self, ptr: u8) -> usize {
        match self {
            Class::Int { bytes: 8 }
            | Class::Float { bytes: 8 }
            | Class::Record { bytes: Some(8) }
                if ptr == 4 =>
            {
                2
            }
            _ => 1,
        }
    }
}

impl HeaderIndex {
    pub fn prototype(&self, name: &str) -> Option<&Prototype> {
        let name = name.rsplit('!').next().unwrap_or(name);
        if let Some(prototype) = self.prototypes.get(name) {
            return Some(prototype);
        }
        if let Some(target) = self.aliases.get(name) {
            if let Some(prototype) = self.prototypes.get(target) {
                return Some(prototype);
            }
        }
        // Nt* and Zw* share their declarations.
        let swapped = if let Some(rest) = name.strip_prefix("Zw") {
            format!("Nt{rest}")
        } else {
            let rest = name.strip_prefix("Nt")?;
            format!("Zw{rest}")
        };
        self.prototypes.get(&swapped)
    }

    pub fn prototype_count(&self) -> usize {
        self.prototypes.len()
    }

    pub fn constant_count(&self) -> usize {
        self.constants.len()
    }

    pub fn constant(&self, name: &str) -> Option<u64> {
        self.constants.get(name).copied()
    }

    /// Resolves a type through its typedefs to how it is passed and shown.
    pub fn classify(&self, ty: &str) -> Class {
        let mut text: String = ty
            .split_whitespace()
            .filter(|word| !matches!(*word, "const" | "volatile" | "struct" | "union" | "enum"))
            .collect::<Vec<_>>()
            .join(" ");
        for _ in 0..16 {
            if let Some(base) = text.strip_suffix('*') {
                let base = base.trim_end();
                return Class::Pointer {
                    text: self.char_width(base),
                };
            }
            if let Some(class) = primitive(&text) {
                return class;
            }
            let Some(typedef) = self.typedefs.get(&text) else {
                return Class::Record { bytes: None };
            };
            match typedef.kind {
                TypeKind::Pointer => {
                    return Class::Pointer {
                        text: self.char_width(&typedef.target),
                    }
                }
                TypeKind::Function => return Class::FunctionPointer,
                TypeKind::Handle => return Class::PtrSized { handle: true },
                TypeKind::Enum => return Class::Enum(text),
                TypeKind::Record => return Class::Record { bytes: None },
                TypeKind::Alias => {
                    if self.enums.contains_key(&text) {
                        return Class::Enum(text);
                    }
                    text = typedef
                        .target
                        .split_whitespace()
                        .filter(|word| !matches!(*word, "const" | "volatile" | "struct" | "enum"))
                        .collect::<Vec<_>>()
                        .join(" ");
                }
            }
        }
        Class::Record { bytes: None }
    }

    /// `Some(false)` for a pointer to char, `Some(true)` for wide char, else `None`.
    fn char_width(&self, base: &str) -> Option<bool> {
        let mut text = base.trim().trim_start_matches("const ").to_owned();
        for _ in 0..16 {
            match text.as_str() {
                "char" | "signed char" | "unsigned char" => return Some(false),
                "wchar_t" | "__wchar_t" => return Some(true),
                _ => {}
            }
            match self.typedefs.get(&text) {
                Some(typedef) if typedef.kind == TypeKind::Alias => {
                    text = typedef.target.trim_start_matches("const ").to_owned();
                }
                _ => return None,
            }
        }
        None
    }

    fn enumerator(&self, enum_name: &str, value: u64) -> Option<&str> {
        self.enums
            .get(enum_name)?
            .iter()
            .find(|(_, v)| *v as u64 & 0xFFFF_FFFF == value & 0xFFFF_FFFF)
            .map(|(name, _)| name.as_str())
    }

    /// The call written out with the prototype's parameter names and each argument
    /// rendered for its type, e.g. `VirtualAlloc(lpAddress=NULL, ...)`. `args` are
    /// argument slots as the caller passed them; `ptr` is the image's pointer width.
    pub fn render_call(&self, prototype: &Prototype, args: &[ArgValue], ptr: u8) -> String {
        let mut parts = Vec::new();
        let mut slot = 0;
        for param in &prototype.params {
            let class = self.classify(&param.ty);
            let value = args.get(slot).cloned().unwrap_or(ArgValue::Unknown);
            let value = match (&value, class.slots(ptr), args.get(slot + 1)) {
                _ if matches!(class, Class::Float { .. }) => ArgValue::Unknown,
                (ArgValue::Int(low), 2, Some(ArgValue::Int(high))) => {
                    ArgValue::Int(low & 0xFFFF_FFFF | high << 32)
                }
                _ => value,
            };
            slot += class.slots(ptr);
            parts.push(format!(
                "{}={}",
                param.name,
                self.render_value(&prototype.name, param, &class, &value, ptr)
            ));
        }
        if prototype.variadic {
            parts.push("...".to_owned());
        }
        format!("{}({})", prototype.name, parts.join(", "))
    }

    fn render_value(
        &self,
        api: &str,
        param: &Param,
        class: &Class,
        value: &ArgValue,
        ptr: u8,
    ) -> String {
        let width_mask = |bytes: u8| match bytes {
            1 => 0xFF,
            2 => 0xFFFF,
            4 => 0xFFFF_FFFF,
            _ => u64::MAX,
        };
        match value {
            ArgValue::Int(raw) => {
                let bytes = match class {
                    Class::Int { bytes } | Class::Bool { bytes } => *bytes,
                    Class::Status | Class::Enum(_) => 4,
                    _ => ptr,
                };
                let value = raw & width_mask(bytes);
                if let Some(text) = self.families.decode(api, &param.name, value) {
                    return text;
                }
                // NtCurrentProcess() and NtCurrentThread() pseudo-handles.
                let handle = param.ty.trim() == "HANDLE"
                    || matches!(class, Class::PtrSized { handle: true });
                match class {
                    _ if handle && value == width_mask(ptr) => "(HANDLE)-1".to_owned(),
                    _ if handle && value == width_mask(ptr) - 1 => "(HANDLE)-2".to_owned(),
                    Class::Pointer { .. }
                    | Class::FunctionPointer
                    | Class::PtrSized { handle: true }
                        if value == 0 =>
                    {
                        "NULL".to_owned()
                    }
                    Class::Bool { .. } if value <= 1 => {
                        if value == 1 { "TRUE" } else { "FALSE" }.to_owned()
                    }
                    Class::Enum(name) => self
                        .enumerator(name, value)
                        .map_or_else(|| number(value), str::to_owned),
                    Class::Status => crate::core::status::ntstatus_name(value as u32)
                        .map_or_else(|| number(value), str::to_owned),
                    _ => number(value),
                }
            }
            ArgValue::Text { text, wide } => {
                let quoted = format!("{text:?}");
                if *wide {
                    format!("L{quoted}")
                } else {
                    quoted
                }
            }
            ArgValue::ImageAddress(va) => format!("&data_{va:X}"),
            ArgValue::Callback { rva, .. } => format!("&fn_0x{rva:08X}"),
            ArgValue::Stack(offset) => format!("&local_{:X}", offset.unsigned_abs()),
            ArgValue::Api(name) | ArgValue::Import(name) => name.clone(),
            ArgValue::Module(name) => format!("<{name}>"),
            ArgValue::Global(va) => format!("[data_{va:X}]"),
            ArgValue::Param(index) => format!("arg{}", index + 1),
            ArgValue::Unknown => "?".to_owned(),
        }
    }

    pub(crate) fn classify_callbacks(
        &self,
        prototype: &Prototype,
        args: &mut [ArgValue],
        pe: &crate::formats::pe::PeFile,
        raw: &[u8],
    ) {
        let ptr = if pe.machine == 0x014c { 4 } else { 8 };
        let mut slot = 0;
        for param in &prototype.params {
            let class = self.classify(&param.ty);
            if class == Class::FunctionPointer {
                if let Some(ArgValue::ImageAddress(va)) = args.get(slot) {
                    let va = *va;
                    if let Some(rva) = va
                        .checked_sub(pe.image_base)
                        .and_then(|v| u32::try_from(v).ok())
                    {
                        if pe
                            .sections
                            .iter()
                            .any(|s| s.is_executable() && s.contains_rva(rva))
                            && pe
                                .rva_bytes(raw, rva)
                                .is_some_and(|bytes| !bytes.is_empty())
                        {
                            args[slot] = ArgValue::Callback {
                                va,
                                rva,
                                typedef: param.ty.clone(),
                                evidence: "API-contract inference; file-backed executable target; not runtime-verified".into(),
                            };
                        }
                    }
                }
            }
            slot += class.slots(ptr);
        }
    }

    /// The prototype as a C declaration with its SAL directions, for `resx api`.
    pub fn declaration(&self, prototype: &Prototype) -> String {
        let mut out = format!("{} {}(", prototype.returns, prototype.name);
        if prototype.params.is_empty() && !prototype.variadic {
            out.push_str("void");
        }
        for (i, param) in prototype.params.iter().enumerate() {
            out.push_str(if i == 0 { "\n    " } else { ",\n    " });
            let direction = match param.direction {
                Direction::In => "_In_",
                Direction::Out => "_Out_",
                Direction::InOut => "_Inout_",
                Direction::Reserved => "_Reserved_",
                Direction::Unspecified => "",
            };
            let direction = if param.optional && !direction.is_empty() {
                format!("{}opt_", direction)
            } else {
                direction.to_owned()
            };
            if !direction.is_empty() {
                out.push_str(&direction);
                out.push(' ');
            }
            out.push_str(&format!("{} {}", param.ty, param.name));
            if let Some(size) = &param.size {
                out.push_str(&format!("  /* {size} */"));
            }
        }
        if prototype.variadic {
            out.push_str(if prototype.params.is_empty() {
                "..."
            } else {
                ",\n    ..."
            });
        }
        if !prototype.params.is_empty() || prototype.variadic {
            out.push('\n');
        }
        out.push_str(");");
        out
    }

    /// The constant families a parameter's values are decoded with.
    pub fn families(&self, api: &str, param: &str) -> Vec<&'static str> {
        families::describe(api, param)
    }

    /// The enumerators of an enum-typed parameter, for `resx api`.
    pub fn enum_of(&self, ty: &str) -> Option<(&str, usize)> {
        match self.classify(ty) {
            Class::Enum(name) => self
                .enums
                .get_key_value(&name)
                .map(|(name, values)| (name.as_str(), values.len())),
            _ => None,
        }
    }
}

fn number(value: u64) -> String {
    if value < 10 {
        value.to_string()
    } else {
        format!("0x{value:X}")
    }
}

fn primitive(text: &str) -> Option<Class> {
    let int = |bytes| Some(Class::Int { bytes });
    match text {
        "void" | "VOID" => Some(Class::Void),
        "BOOL" | "WINBOOL" => Some(Class::Bool { bytes: 4 }),
        "BOOLEAN" | "bool" => Some(Class::Bool { bytes: 1 }),
        "NTSTATUS" | "HRESULT" | "LSTATUS" => Some(Class::Status),
        "char" | "signed char" | "unsigned char" | "__int8" | "unsigned __int8" => int(1),
        "short" | "signed short" | "unsigned short" | "short int" | "unsigned short int"
        | "wchar_t" | "__wchar_t" | "__int16" | "unsigned __int16" => int(2),
        "int" | "signed" | "unsigned" | "signed int" | "unsigned int" | "long" | "signed long"
        | "unsigned long" | "long int" | "unsigned long int" | "__int32" | "unsigned __int32" => {
            int(4)
        }
        "__int64" | "unsigned __int64" | "long long" | "unsigned long long" => int(8),
        "float" => Some(Class::Float { bytes: 4 }),
        "double" | "long double" => Some(Class::Float { bytes: 8 }),
        "__int3264" | "unsigned __int3264" | "size_t" | "ptrdiff_t" | "intptr_t" | "uintptr_t" => {
            Some(Class::PtrSized { handle: false })
        }
        _ if text.starts_with("_W64 ") => {
            primitive(&text[5..]).map(|_| Class::PtrSized { handle: false })
        }
        _ if text.ends_with("_PTR")
            || matches!(text, "SIZE_T" | "SSIZE_T" | "WPARAM" | "LPARAM" | "LRESULT") =>
        {
            Some(Class::PtrSized { handle: false })
        }
        _ => None,
    }
}

/// The directory holding `um/windows.h` for `dir`: an SDK version directory, its
/// `Include` parent, the kit root, or (for convenience) any directory from which the
/// newest installed Windows 10/11 SDK is found.
pub fn resolve_root(dir: &Path) -> Option<PathBuf> {
    let has_headers = |path: &Path| path.join("um").join("windows.h").is_file();
    if has_headers(dir) {
        return Some(dir.to_path_buf());
    }
    let newest = |include: &Path| -> Option<PathBuf> {
        let mut versions: Vec<PathBuf> = std::fs::read_dir(include)
            .ok()?
            .flatten()
            .map(|entry| entry.path())
            .filter(|path| has_headers(path))
            .collect();
        versions.sort();
        versions.pop()
    };
    newest(dir).or_else(|| newest(&dir.join("Include")))
}

/// An installed Windows SDK, for pointing out where Windows.h lives when the
/// configured directory (an MSVC toolset, say) does not have it.
pub fn installed_sdk() -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(dir) = std::env::var_os("WindowsSdkDir") {
        candidates.push(PathBuf::from(dir));
    }
    for var in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Some(dir) = std::env::var_os(var) {
            candidates.push(PathBuf::from(dir).join("Windows Kits").join("10"));
        }
    }
    candidates.iter().find_map(|dir| resolve_root(dir))
}

/// The index for the headers the user configured, loaded once per process.
pub fn configured(dir: Option<&str>) -> Option<Arc<HeaderIndex>> {
    let dir = dir.filter(|dir| !dir.is_empty())?;
    static LOADED: Mutex<Option<(String, Option<Arc<HeaderIndex>>)>> = Mutex::new(None);
    let mut loaded = LOADED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some((cached, index)) = loaded.as_ref() {
        if cached == dir {
            return index.clone();
        }
    }
    let index = match load(Path::new(dir)) {
        Ok(index) => Some(Arc::new(index)),
        Err(error) => {
            eprintln!("[resx] Windows headers unavailable: {error}");
            None
        }
    };
    *loaded = Some((dir.to_owned(), index.clone()));
    index
}

/// Loads the index for `dir` from the per-user cache, building it first if the
/// headers changed since it was written.
pub fn load(dir: &Path) -> Result<HeaderIndex, String> {
    let root = resolve_root(dir).ok_or_else(|| {
        format!(
            "{} has no um\\windows.h; point --headers at a Windows SDK Include directory",
            dir.display()
        )
    })?;
    let fingerprint = fingerprint(&root);
    let cache = cache_dir().map(|dir| dir.join(format!("headers-{fingerprint:016x}.json")));
    if let Some(index) = cache
        .as_ref()
        .and_then(|path| std::fs::read(path).ok())
        .and_then(|bytes| serde_json::from_slice::<HeaderIndex>(&bytes).ok())
    {
        return Ok(index.finish());
    }
    let index = build(&root)?;
    if let Some(path) = cache {
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(bytes) = serde_json::to_vec(&index) {
            let _ = std::fs::write(path, bytes);
        }
    }
    Ok(index.finish())
}

fn cache_dir() -> Option<PathBuf> {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .map(|dir| dir.join("RESX").join("cache"))
}

fn header_files(root: &Path) -> Vec<(String, PathBuf)> {
    let mut out = Vec::new();
    for sub in SCANNED {
        let mut stack = vec![root.join(sub)];
        while let Some(dir) = stack.pop() {
            let Ok(entries) = std::fs::read_dir(&dir) else {
                continue;
            };
            let mut entries: Vec<PathBuf> = entries.flatten().map(|entry| entry.path()).collect();
            entries.sort();
            for path in entries {
                if path.is_dir() {
                    stack.push(path);
                } else if path
                    .extension()
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("h"))
                {
                    let relative = path
                        .strip_prefix(root)
                        .unwrap_or(&path)
                        .to_string_lossy()
                        .replace('\\', "/");
                    out.push((relative, path));
                }
            }
        }
    }
    out
}

fn fingerprint(root: &Path) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    FORMAT.hash(&mut hasher);
    root.to_string_lossy()
        .to_ascii_lowercase()
        .hash(&mut hasher);
    for (relative, path) in header_files(root) {
        relative.hash(&mut hasher);
        if let Ok(meta) = std::fs::metadata(&path) {
            meta.len().hash(&mut hasher);
            if let Ok(modified) = meta.modified() {
                modified.hash(&mut hasher);
            }
        }
    }
    hasher.finish()
}

fn build(root: &Path) -> Result<HeaderIndex, String> {
    let files = header_files(root);
    if files.is_empty() {
        return Err(format!("no headers under {}", root.display()));
    }
    let mut parsed = parse::Parsed::default();
    for (relative, path) in &files {
        if let Ok(bytes) = std::fs::read(path) {
            parse::parse(&String::from_utf8_lossy(&bytes), relative, &mut parsed);
        }
    }
    Ok(from_parsed(root.to_string_lossy().into_owned(), parsed))
}

fn from_parsed(root: String, parsed: parse::Parsed) -> HeaderIndex {
    let mut index = HeaderIndex {
        root,
        ..HeaderIndex::default()
    };
    for prototype in parsed.prototypes {
        index
            .prototypes
            .entry(prototype.name.clone())
            .or_insert(prototype);
    }
    for (name, typedef) in parsed.typedefs {
        index.typedefs.entry(name).or_insert(typedef);
    }

    // Constants: first definition wins, evaluated lazily so they may refer to each
    // other in any order.
    let mut raw: HashMap<String, String> = HashMap::new();
    for (name, value) in parsed.defines {
        raw.entry(name).or_insert(value);
    }
    let mut values: HashMap<String, Option<i128>> = HashMap::new();
    let names: Vec<String> = raw.keys().cloned().collect();
    for name in &names {
        let value = resolve(name, &raw, &mut values, 0);
        if let Some(value) = value {
            index.constants.insert(name.clone(), value as u64);
        } else if let Some(target) = raw.get(name) {
            if index.prototypes.contains_key(target) {
                index.aliases.insert(name.clone(), target.clone());
            }
        }
    }
    for (enum_name, enumerators) in parsed.enums {
        if index.enums.contains_key(&enum_name) {
            continue;
        }
        let mut next = 0i128;
        let mut out = Vec::new();
        for (name, expression) in enumerators {
            let value = match expression {
                Some(expression) => {
                    let known: HashMap<&str, i128> = out
                        .iter()
                        .map(|(name, value): &(String, i64)| (name.as_str(), i128::from(*value)))
                        .collect();
                    parse::evaluate(&expression, &mut |name| {
                        known
                            .get(name)
                            .copied()
                            .or_else(|| resolve(name, &raw, &mut values, 0))
                    })
                }
                None => Some(next),
            };
            let Some(value) = value else {
                break;
            };
            next = value + 1;
            out.push((name, value as i64));
        }
        for (name, value) in &out {
            index.constants.entry(name.clone()).or_insert(*value as u64);
        }
        index.enums.insert(enum_name, out);
    }
    index
}

fn resolve(
    name: &str,
    raw: &HashMap<String, String>,
    values: &mut HashMap<String, Option<i128>>,
    depth: usize,
) -> Option<i128> {
    if let Some(value) = values.get(name) {
        return *value;
    }
    if depth > 32 {
        return None;
    }
    let text = raw.get(name)?;
    // Guard against self-reference while this name is being evaluated.
    values.insert(name.to_owned(), None);
    let value = parse::evaluate(text, &mut |other| resolve(other, raw, values, depth + 1));
    values.insert(name.to_owned(), value);
    value
}

impl HeaderIndex {
    fn finish(mut self) -> Self {
        self.families = families::Candidates::build(&self.constants);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn index(text: &str) -> HeaderIndex {
        let mut parsed = parse::Parsed::default();
        parse::parse(text, "um/test.h", &mut parsed);
        from_parsed(String::new(), parsed).finish()
    }

    const SDK: &str = r#"
        typedef unsigned long DWORD;
        typedef int BOOL;
        typedef void *LPVOID, *PVOID, *HANDLE;
        typedef unsigned __int64 ULONG_PTR;
        typedef ULONG_PTR SIZE_T;
        typedef char CHAR;
        typedef wchar_t WCHAR;
        typedef CONST CHAR *LPCSTR;
        typedef CONST WCHAR *LPCWSTR;
        typedef long NTSTATUS;
        typedef unsigned long ULONG, *PULONG;
        typedef enum _PROCESSINFOCLASS { ProcessBasicInformation = 0, ProcessDebugPort = 7 } PROCESSINFOCLASS;
        #define MEM_COMMIT 0x00001000
        #define MEM_RESERVE 0x00002000
        #define PAGE_READWRITE 0x04
        #define PAGE_EXECUTE_READWRITE 0x40
        WINBASEAPI LPVOID WINAPI VirtualAlloc(_In_opt_ LPVOID lpAddress, _In_ SIZE_T dwSize,
            _In_ DWORD flAllocationType, _In_ DWORD flProtect);
        WINBASEAPI HANDLE WINAPI CreateFileW(_In_ LPCWSTR lpFileName, _In_ DWORD dwDesiredAccess);
        WINBASEAPI BOOL WINAPI SetFileTime(_In_ HANDLE hFile, _In_ unsigned __int64 when);
        #define CreateFile CreateFileW
        NTSTATUS NTAPI NtQueryInformationProcess(_In_ HANDLE ProcessHandle,
            _In_ PROCESSINFOCLASS ProcessInformationClass, _Out_ PVOID ProcessInformation,
            _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);
    "#;

    #[test]
    fn types_resolve_through_typedefs() {
        let index = index(SDK);
        assert_eq!(index.classify("LPVOID"), Class::Pointer { text: None });
        assert_eq!(
            index.classify("LPCWSTR"),
            Class::Pointer { text: Some(true) }
        );
        assert_eq!(
            index.classify("const char*"),
            Class::Pointer { text: Some(false) }
        );
        assert_eq!(index.classify("SIZE_T"), Class::PtrSized { handle: false });
        assert_eq!(index.classify("DWORD"), Class::Int { bytes: 4 });
        assert_eq!(
            index.classify("PROCESSINFOCLASS"),
            Class::Enum("PROCESSINFOCLASS".into())
        );
        assert_eq!(index.classify("NTSTATUS"), Class::Status);
    }

    #[test]
    fn calls_render_with_names_flags_and_strings() {
        let index = index(SDK);
        let alloc = index.prototype("KERNEL32!VirtualAlloc").unwrap();
        assert!(index
            .render_call(alloc, &[ArgValue::Int(0), ArgValue::Int(0)], 8)
            .starts_with("VirtualAlloc(lpAddress=NULL, dwSize=0,"));
        let rendered = index.render_call(
            alloc,
            &[
                ArgValue::Int(0),
                ArgValue::Int(0x1000),
                ArgValue::Int(0x3000),
                ArgValue::Int(0x40),
            ],
            8,
        );
        assert_eq!(
            rendered,
            "VirtualAlloc(lpAddress=NULL, dwSize=0x1000, flAllocationType=MEM_COMMIT|MEM_RESERVE, flProtect=PAGE_EXECUTE_READWRITE)"
        );
        let create = index.prototype("CreateFile").unwrap();
        assert_eq!(
            index.render_call(
                create,
                &[
                    ArgValue::Text {
                        text: "C:\\x.txt".into(),
                        wide: true
                    },
                    ArgValue::Unknown
                ],
                8
            ),
            r#"CreateFileW(lpFileName=L"C:\\x.txt", dwDesiredAccess=?)"#
        );
        let query = index.prototype("ZwQueryInformationProcess").unwrap();
        let rendered = index.render_call(
            query,
            &[
                ArgValue::Int(u64::MAX),
                ArgValue::Int(7),
                ArgValue::Stack(-0x48),
                ArgValue::Int(4),
                ArgValue::Int(0),
            ],
            8,
        );
        assert_eq!(
            rendered,
            "NtQueryInformationProcess(ProcessHandle=(HANDLE)-1, ProcessInformationClass=ProcessDebugPort, ProcessInformation=&local_48, ProcessInformationLength=4, ReturnLength=NULL)"
        );
    }

    #[test]
    fn x86_passes_64_bit_values_in_two_slots() {
        let index = index(SDK);
        let set = index.prototype("SetFileTime").unwrap();
        assert_eq!(
            index.render_call(
                set,
                &[ArgValue::Int(4), ArgValue::Int(0x10), ArgValue::Int(0x2)],
                4
            ),
            "SetFileTime(hFile=4, when=0x200000010)"
        );
    }

    #[test]
    fn declarations_show_sal_directions() {
        let index = index(SDK);
        let declaration = index.declaration(index.prototype("VirtualAlloc").unwrap());
        assert!(declaration.starts_with("LPVOID VirtualAlloc(\n    _In_opt_ LPVOID lpAddress,"));
        assert!(declaration.ends_with("_In_ DWORD flProtect\n);"));
    }

    #[test]
    fn installed_sdk_prototypes_match_common_api_contracts() {
        let Some(root) = installed_sdk() else {
            return;
        };
        // Parse directly: validation must not write a user-wide cache or preferences.
        let index = build(&root).unwrap().finish();
        let alloc = index.prototype("VirtualAlloc").unwrap();
        assert_eq!(alloc.params.len(), 4);
        assert_eq!(alloc.params[1].name, "dwSize");
        assert_eq!(
            index.classify(&alloc.params[1].ty),
            Class::PtrSized { handle: false }
        );
        assert_eq!(index.constant("MEM_COMMIT"), Some(0x1000));
        assert_eq!(index.constant("PAGE_READWRITE"), Some(4));
        assert_eq!(index.prototype("CreateFileW").unwrap().params.len(), 7);
        assert_eq!(index.prototype("GetProcAddress").unwrap().params.len(), 2);
        assert_eq!(index.prototype("VirtualProtect").unwrap().params.len(), 4);
        assert_eq!(index.prototype("GetModuleHandleW").unwrap().params.len(), 1);
    }

    #[test]
    fn callback_classification_requires_a_typed_file_backed_executable_target() {
        let index = index(
            r#"
            typedef DWORD (WINAPI *PTHREAD_START_ROUTINE)(LPVOID parameter);
            typedef PTHREAD_START_ROUTINE LPTHREAD_START_ROUTINE;
            HANDLE WINAPI CreateThread(LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter);
        "#,
        );
        let proto = index.prototype("CreateThread").unwrap();
        assert_eq!(
            index.classify("LPTHREAD_START_ROUTINE"),
            Class::FunctionPointer
        );
        for (arch, machine) in [(64, 0x8664), (32, 0x014c)] {
            let mut pe = crate::formats::pe::PeFile {
                arch,
                machine,
                image_base: 0x400000,
                timestamp: 0,
                coff_characteristics: 0,
                major_linker_version: 0,
                minor_linker_version: 0,
                entry_point: 0x1000,
                size_of_image: 0x2000,
                size_of_headers: 0,
                section_alignment: 0x1000,
                file_alignment: 0x200,
                checksum: 0,
                subsystem: 3,
                dll_characteristics: 0,
                sections: Vec::new(),
                data_dirs: vec![(0, 0); 16],
                anomalies: Vec::new(),
            };
            pe.sections.push(crate::formats::pe::PeSection {
                name: ".text".into(),
                virtual_address: 0x1000,
                virtual_size: 0x100,
                raw_offset: 0,
                raw_size: 0x80,
                characteristics: crate::formats::pe::IMAGE_SCN_MEM_EXECUTE,
                entropy: 0.0,
            });
            let raw = [0xC3; 0x80];
            let address = pe.image_base + 0x1010;
            let mut args = [
                ArgValue::ImageAddress(address),
                ArgValue::ImageAddress(address),
            ];
            index.classify_callbacks(proto, &mut args, &pe, &raw);
            assert!(
                matches!(&args[0], ArgValue::Callback { rva: 0x1010, typedef, evidence, .. }
            if typedef == "LPTHREAD_START_ROUTINE" && evidence.contains("API-contract inference"))
            );
            assert_eq!(
                args[1],
                ArgValue::ImageAddress(address),
                "data parameter stays data even in executable memory"
            );
            assert!(index
                .render_call(proto, &args, (arch / 8) as u8)
                .contains("lpStartAddress=&fn_0x00001010"));
            for value in [
                ArgValue::Unknown,
                ArgValue::Int(0),
                ArgValue::ImageAddress(0),
                ArgValue::ImageAddress(pe.image_base + 0x1080),
                ArgValue::ImageAddress(u64::MAX),
            ] {
                let mut args = [value.clone()];
                index.classify_callbacks(proto, &mut args, &pe, &raw);
                assert_eq!(args[0], value);
            }
            pe.sections[0].characteristics = 0;
            let mut args = [ArgValue::ImageAddress(address)];
            index.classify_callbacks(proto, &mut args, &pe, &raw);
            assert_eq!(args[0], ArgValue::ImageAddress(address));
            assert!(index
                .render_call(proto, &[ArgValue::Int(0)], (arch / 8) as u8)
                .contains("lpStartAddress=NULL"));
        }
    }

    #[test]
    fn captures_x64_and_x86_call_arguments_without_reusing_volatile_registers() {
        for (arch, machine, code, first, second) in [
            (
                64,
                0x8664,
                &[
                    0x31, 0xc9, // xor ecx, ecx
                    0xba, 0x00, 0x10, 0x00, 0x00, // mov edx, 1000h
                    0x41, 0xb8, 0x00, 0x30, 0x00, 0x00, // mov r8d, 3000h
                    0x41, 0xb9, 0x04, 0x00, 0x00, 0x00, // mov r9d, 4
                    0xff, 0xd0, 0xff, 0xd0, 0xc3,
                ][..],
                19,
                21,
            ),
            (
                32,
                0x014c,
                &[
                    0x6a, 4, 0x68, 0x00, 0x30, 0x00, 0x00, 0x68, 0x00, 0x10, 0x00, 0x00, 0x6a, 0,
                    0xff, 0xd0, 0xff, 0xd0, 0xc3,
                ][..],
                14,
                16,
            ),
        ] {
            let pe = crate::formats::pe::PeFile {
                arch,
                machine,
                image_base: 0x400000,
                timestamp: 0,
                coff_characteristics: 0,
                major_linker_version: 0,
                minor_linker_version: 0,
                entry_point: 0x1000,
                size_of_image: 0x2000,
                size_of_headers: 0,
                section_alignment: 0x1000,
                file_alignment: 0x200,
                checksum: 0,
                subsystem: 3,
                dll_characteristics: 0,
                sections: Vec::new(),
                data_dirs: vec![(0, 0); 16],
                anomalies: Vec::new(),
            };
            let insns: Vec<_> = iced_x86::Decoder::with_ip(
                arch,
                code,
                pe.image_base + 0x1000,
                iced_x86::DecoderOptions::NONE,
            )
            .into_iter()
            .collect();
            let arguments = crate::analysis::resolution::call_arguments(&pe, &[], &insns);
            assert_eq!(
                &arguments[&(0x1000 + first)][..4],
                &[
                    ArgValue::Int(0),
                    ArgValue::Int(0x1000),
                    ArgValue::Int(0x3000),
                    ArgValue::Int(4)
                ]
            );
            if arch == 64 {
                assert_eq!(
                    &arguments[&(0x1000 + second)][..4],
                    &[const { ArgValue::Unknown }; 4]
                );
                let branching = [
                    0xb9, 1, 0, 0, 0, 0x85, 0xc0, 0x74, 5, 0xb9, 2, 0, 0, 0, 0xff, 0xd0, 0xc3,
                ];
                let insns: Vec<_> = iced_x86::Decoder::with_ip(
                    arch,
                    &branching,
                    pe.image_base + 0x1000,
                    iced_x86::DecoderOptions::NONE,
                )
                .into_iter()
                .collect();
                let args = crate::analysis::resolution::call_arguments(&pe, &[], &insns);
                assert_eq!(
                    args[&0x100e][0],
                    ArgValue::Unknown,
                    "neither branch's RCX is a proven value at the join"
                );
                let escaped = [
                    0x48, 0x83, 0xec, 0x28, // sub rsp, 28h
                    0xc7, 0x44, 0x24, 0x20, 7, 0, 0, 0, // local = 7
                    0x48, 0x8d, 0x4c, 0x24, 0x20, // rcx = &local
                    0xff, 0xd0, // call rax, may overwrite local
                    0x8b, 0x4c, 0x24, 0x20, // ecx = local
                    0xff, 0xd0, 0xc3,
                ];
                let insns: Vec<_> = iced_x86::Decoder::with_ip(
                    arch,
                    &escaped,
                    pe.image_base + 0x1000,
                    iced_x86::DecoderOptions::NONE,
                )
                .into_iter()
                .collect();
                let args = crate::analysis::resolution::call_arguments(&pe, &[], &insns);
                assert_eq!(
                    args[&0x1017][0],
                    ArgValue::Unknown,
                    "an escaped output buffer must not retain its pre-call value"
                );
            }
        }
    }
}
