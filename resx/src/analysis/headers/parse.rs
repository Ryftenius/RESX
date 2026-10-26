//! A tolerant declaration scanner for Windows SDK headers.
//!
//! This is not a C preprocessor: conditional blocks are not evaluated, so every
//! branch is read and the first declaration of a name wins. That is enough for the
//! SDK, whose function prototypes, typedefs and constants are written out plainly,
//! and it never executes or expands anything. SAL annotations are removed from
//! types but their meaning (direction, optionality, buffer size) is kept.

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    #[default]
    Unspecified,
    In,
    Out,
    InOut,
    Reserved,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default, skip_serializing_if = "is_unspecified")]
    pub direction: Direction,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional: bool,
    /// Element or byte count from `_In_reads_(n)`, `_Out_writes_bytes_(n)` and kin.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<String>,
}

fn is_unspecified(direction: &Direction) -> bool {
    *direction == Direction::Unspecified
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prototype {
    pub name: String,
    pub returns: String,
    pub params: Vec<Param>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub variadic: bool,
    /// Header path relative to the include root, e.g. `um/memoryapi.h`.
    pub header: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TypeKind {
    Alias,
    Pointer,
    Record,
    Enum,
    Handle,
    Function,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeDef {
    pub kind: TypeKind,
    /// What the name stands for: the aliased or pointed-to type text.
    pub target: String,
}

type Enumerators = Vec<(String, Option<String>)>;

#[derive(Default)]
pub struct Parsed {
    pub prototypes: Vec<Prototype>,
    pub typedefs: Vec<(String, TypeDef)>,
    /// Enum type name, then its enumerators with their value expressions.
    pub enums: Vec<(String, Enumerators)>,
    /// Object-like `#define NAME value`, the value as written.
    pub defines: Vec<(String, String)>,
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Ident(String),
    Num(String),
    Punct(char),
    Str,
}

/// Calling conventions and storage decorations that are not part of a type.
const DECORATIONS: &[&str] = &[
    "extern",
    "static",
    "inline",
    "__inline",
    "__forceinline",
    "FORCEINLINE",
    "__kernel_entry",
    "WINAPI",
    "NTAPI",
    "APIENTRY",
    "CALLBACK",
    "WINAPIV",
    "PASCAL",
    "__stdcall",
    "__cdecl",
    "__fastcall",
    "__vectorcall",
    "_stdcall",
    "_cdecl",
    "STDAPICALLTYPE",
    "STDMETHODCALLTYPE",
    "WSAAPI",
    "NET_API_FUNCTION",
    "RPC_ENTRY",
    "SEC_ENTRY",
    "SEC_FAR",
    "FAR",
    "NEAR",
    "far",
    "near",
    "UNALIGNED",
    "__unaligned",
    "__RPC_FAR",
    "__ptr64",
    "__ptr32",
    "POINTER_32",
    "POINTER_64",
    "volatile",
    "IN",
    "OUT",
    "OPTIONAL",
    "NOTHROW",
    "WINAPI_INLINE",
];

const NOT_TYPES: &[&str] = &[
    "typedef",
    "struct",
    "union",
    "enum",
    "class",
    "namespace",
    "template",
    "using",
    "return",
    "static_assert",
    "C_ASSERT",
    "operator",
    "if",
    "while",
    "for",
    "sizeof",
];

/// Removes comments and line continuations, keeping line structure and literals.
fn clean(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'/' if bytes.get(i + 1) == Some(&b'/') => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    // A continuation keeps a line comment going.
                    if bytes[i] == b'\\' && bytes.get(i + 1) == Some(&b'\n') {
                        i += 1;
                    }
                    i += 1;
                }
            }
            b'/' if bytes.get(i + 1) == Some(&b'*') => {
                i += 2;
                while i < bytes.len() && !(bytes[i] == b'*' && bytes.get(i + 1) == Some(&b'/')) {
                    if bytes[i] == b'\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
                i += 2;
                out.push(' ');
            }
            b'\\' if bytes.get(i + 1) == Some(&b'\n') => i += 2,
            b'\\' if bytes.get(i + 1) == Some(&b'\r') && bytes.get(i + 2) == Some(&b'\n') => i += 3,
            b'"' | b'\'' => {
                let quote = bytes[i];
                let start = i;
                i += 1;
                while i < bytes.len() && bytes[i] != quote && bytes[i] != b'\n' {
                    if bytes[i] == b'\\' {
                        i += 1;
                    }
                    i += 1;
                }
                i = (i + 1).min(bytes.len());
                out.push_str(&text[start..i]);
            }
            b'\r' => i += 1,
            _ => {
                let len = utf8_len(bytes[i]);
                out.push_str(&text[i..(i + len).min(text.len())]);
                i += len;
            }
        }
    }
    out
}

fn utf8_len(lead: u8) -> usize {
    match lead {
        0xF0..=0xFF => 4,
        0xE0..=0xEF => 3,
        0xC0..=0xDF => 2,
        _ => 1,
    }
}

fn tokenize(text: &str) -> Vec<Tok> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < chars.len() {
        let ch = chars[i];
        if ch.is_whitespace() {
            i += 1;
        } else if ch.is_ascii_alphabetic() || ch == '_' {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '_') {
                i += 1;
            }
            let ident: String = chars[start..i].iter().collect();
            // L"..." and u8"..." literals.
            if i < chars.len() && (chars[i] == '"' || chars[i] == '\'') && ident.len() <= 2 {
                continue;
            }
            out.push(Tok::Ident(ident));
        } else if ch.is_ascii_digit() {
            let start = i;
            while i < chars.len() && (chars[i].is_ascii_alphanumeric() || chars[i] == '.') {
                i += 1;
            }
            out.push(Tok::Num(chars[start..i].iter().collect()));
        } else if ch == '"' || ch == '\'' {
            i += 1;
            while i < chars.len() && chars[i] != ch {
                if chars[i] == '\\' {
                    i += 1;
                }
                i += 1;
            }
            i += 1;
            out.push(Tok::Str);
        } else {
            out.push(Tok::Punct(ch));
            i += 1;
        }
    }
    out
}

pub fn parse(text: &str, header: &str, out: &mut Parsed) {
    let cleaned = clean(text);
    let mut code = String::with_capacity(cleaned.len());
    for line in cleaned.lines() {
        let trimmed = line.trim_start();
        if let Some(directive) = trimmed.strip_prefix('#') {
            let directive = directive.trim_start();
            if let Some(rest) = directive.strip_prefix("define") {
                define(rest, out);
            }
            code.push('\n');
        } else {
            code.push_str(line);
            code.push('\n');
        }
    }
    let tokens = tokenize(&code);
    for statement in statements(&tokens) {
        declaration(statement, header, out);
    }
}

fn define(rest: &str, out: &mut Parsed) {
    if !rest.starts_with([' ', '\t']) {
        return;
    }
    let rest = rest.trim_start();
    let name_len = rest
        .find(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .unwrap_or(rest.len());
    let (name, value) = rest.split_at(name_len);
    // A function-like macro has its parameter list right after the name.
    if name.is_empty() || value.starts_with('(') {
        return;
    }
    let value = value.trim();
    if !value.is_empty() && value.len() <= 256 {
        out.defines.push((name.to_owned(), value.to_owned()));
    }
}

/// Top-level statements: `;`-terminated runs, with brace blocks kept inside the
/// statement they belong to. `extern "C" {` blocks are transparent, and function
/// bodies end the statement they follow.
fn statements(tokens: &[Tok]) -> Vec<&[Tok]> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            Tok::Punct(';') => {
                out.push(&tokens[start..i]);
                start = i + 1;
            }
            Tok::Punct('{') => {
                let opener = &tokens[start..i];
                let transparent = matches!(opener, [Tok::Ident(ext), Tok::Str] if ext == "extern")
                    || matches!(opener, [Tok::Ident(kw), ..] if kw == "namespace");
                if transparent {
                    start = i + 1;
                } else {
                    let end = matching(tokens, i);
                    let is_body = opener.contains(&Tok::Punct(')'))
                        && !opener.iter().any(|tok| {
                            matches!(tok, Tok::Ident(kw) if matches!(kw.as_str(), "typedef" | "struct" | "union" | "enum" | "class"))
                        });
                    if is_body {
                        start = end + 1;
                    }
                    i = end;
                }
            }
            // Closing a transparent block.
            Tok::Punct('}') => start = i + 1,
            _ => {}
        }
        i += 1;
    }
    out
}

fn matching(tokens: &[Tok], open: usize) -> usize {
    let (left, right) = match tokens[open] {
        Tok::Punct('(') => ('(', ')'),
        Tok::Punct('[') => ('[', ']'),
        _ => ('{', '}'),
    };
    let mut depth = 0;
    for (i, tok) in tokens.iter().enumerate().skip(open) {
        if *tok == Tok::Punct(left) {
            depth += 1;
        } else if *tok == Tok::Punct(right) {
            depth -= 1;
            if depth == 0 {
                return i;
            }
        }
    }
    tokens.len() - 1
}

fn is_sal(ident: &str) -> bool {
    let bytes = ident.as_bytes();
    (bytes.len() > 2
        && bytes[0] == b'_'
        && bytes[1].is_ascii_uppercase()
        && bytes[bytes.len() - 1] == b'_')
        // Legacy SAL is a whole stem or a stem with a suffix: `__in`, `__in_opt`, but
        // not `__int64`.
        || [
            "__in", "__out", "__inout", "__deref", "__reserved", "__checkReturn", "__success",
            "__field", "__bcount", "__ecount", "__nullterminated", "__typefix", "__callback",
            "__range", "__format_string", "__analysis", "__post", "__pre", "__declspec",
            "__allocator", "__restrict", "__drv",
        ]
        .iter()
        .any(|stem| {
            ident
                .strip_prefix(stem)
                .is_some_and(|rest| rest.is_empty() || rest.starts_with('_'))
        })
        || (ident.starts_with("DECLSPEC_") && ident.len() > 9)
        || ident == "__attribute__"
}

fn is_api_decoration(ident: &str) -> bool {
    // WINBASEAPI, NTSYSCALLAPI, WINADVAPI, WINUSERAPI and the like.
    ident.len() > 3
        && ident.ends_with("API")
        && ident
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        && ident != "WSAAPI"
        || DECORATIONS.contains(&ident)
}

struct Sal {
    direction: Direction,
    optional: bool,
    size: Option<String>,
}

/// Drops SAL and decorations, returning the remaining tokens and what the SAL said.
fn strip(tokens: &[Tok]) -> (Vec<Tok>, Sal) {
    let mut out = Vec::new();
    let mut sal = Sal {
        direction: Direction::Unspecified,
        optional: false,
        size: None,
    };
    let mut i = 0;
    while i < tokens.len() {
        match &tokens[i] {
            Tok::Ident(ident) if is_sal(ident) => {
                let lower = ident.to_ascii_lowercase();
                let has_args = tokens.get(i + 1) == Some(&Tok::Punct('('));
                let end = if has_args { matching(tokens, i + 1) } else { i };
                let direction = if lower.starts_with("_inout") || lower.starts_with("__inout") {
                    Some(Direction::InOut)
                } else if lower.starts_with("_in_") || lower.starts_with("__in") {
                    Some(Direction::In)
                } else if lower.starts_with("_out") || lower.starts_with("__out") {
                    Some(Direction::Out)
                } else if lower.starts_with("_reserved") || lower.starts_with("__reserved") {
                    Some(Direction::Reserved)
                } else {
                    None
                };
                if let Some(direction) = direction {
                    if sal.direction == Direction::Unspecified {
                        sal.direction = direction;
                    }
                    sal.optional |= lower.contains("opt");
                    if has_args
                        && sal.size.is_none()
                        && ["reads", "writes", "bcount", "ecount", "updates"]
                            .iter()
                            .any(|kind| lower.contains(kind))
                    {
                        sal.size = Some(join(&tokens[i + 2..end]));
                    }
                }
                i = end + 1;
            }
            Tok::Ident(ident) if ident == "IN" => {
                sal.direction = match sal.direction {
                    Direction::Out => Direction::InOut,
                    _ => Direction::In,
                };
                i += 1;
            }
            Tok::Ident(ident) if ident == "OUT" => {
                sal.direction = match sal.direction {
                    Direction::In => Direction::InOut,
                    _ => Direction::Out,
                };
                i += 1;
            }
            Tok::Ident(ident) if ident == "OPTIONAL" => {
                sal.optional = true;
                i += 1;
            }
            Tok::Ident(ident) if is_api_decoration(ident) => i += 1,
            Tok::Ident(ident) if ident == "CONST" => {
                out.push(Tok::Ident("const".to_owned()));
                i += 1;
            }
            tok => {
                out.push(tok.clone());
                i += 1;
            }
        }
    }
    (out, sal)
}

/// Type text: identifiers separated by spaces, `*` attached.
fn join(tokens: &[Tok]) -> String {
    let mut out = String::new();
    for tok in tokens {
        match tok {
            Tok::Ident(text) | Tok::Num(text) => {
                if !out.is_empty() && !out.ends_with(['(', '[', ' ']) {
                    out.push(' ');
                }
                out.push_str(text);
            }
            Tok::Punct('*') => out.push('*'),
            Tok::Punct(ch) => {
                if matches!(ch, '(' | ')' | ',' | '[' | ']') {
                    out.push(*ch);
                    if *ch == ',' {
                        out.push(' ');
                    }
                } else {
                    out.push(' ');
                    out.push(*ch);
                    out.push(' ');
                }
            }
            Tok::Str => {}
        }
    }
    out.trim().to_owned()
}

fn declaration(statement: &[Tok], header: &str, out: &mut Parsed) {
    match statement.first() {
        Some(Tok::Ident(kw)) if kw == "typedef" => typedef(&statement[1..], out),
        Some(Tok::Ident(kw)) if kw == "DECLARE_HANDLE" => {
            if let [_, Tok::Punct('('), Tok::Ident(name), Tok::Punct(')')] = statement {
                out.typedefs.push((
                    name.clone(),
                    TypeDef {
                        kind: TypeKind::Handle,
                        target: "void*".to_owned(),
                    },
                ));
            }
        }
        Some(Tok::Ident(kw)) if kw == "enum" => {
            // `enum NAME { ... };` declares an enum type usable as `enum NAME`.
            if let (Some(Tok::Ident(name)), Some(open)) = (
                statement.get(1),
                statement.iter().position(|tok| *tok == Tok::Punct('{')),
            ) {
                let close = matching(statement, open);
                out.enums
                    .push((name.clone(), enumerators(&statement[open + 1..close])));
            }
        }
        _ => {
            if let Some(prototype) = prototype(statement, header) {
                out.prototypes.push(prototype);
            }
        }
    }
}

fn prototype(statement: &[Tok], header: &str) -> Option<Prototype> {
    if statement.len() < 3 {
        return None;
    }
    let (tokens, _) = strip(statement);
    if tokens.iter().any(|tok| {
        matches!(tok, Tok::Punct('=' | '{'))
            || matches!(tok, Tok::Ident(kw) if NOT_TYPES.contains(&kw.as_str()))
    }) {
        return None;
    }
    // STDAPI and STDAPI_(type) expand to an HRESULT or `type` return.
    let mut tokens = tokens;
    let mut returns_override = None;
    if let Some(Tok::Ident(first)) = tokens.first() {
        if first == "STDAPI" {
            returns_override = Some("HRESULT".to_owned());
            tokens.remove(0);
        } else if first == "STDAPI_" && tokens.get(1) == Some(&Tok::Punct('(')) {
            let close = matching(&tokens, 1);
            returns_override = Some(join(&tokens[2..close]));
            tokens.drain(..=close);
        }
    }
    let open = tokens.iter().position(|tok| *tok == Tok::Punct('('))?;
    let Some(Tok::Ident(name)) = open.checked_sub(1).map(|i| &tokens[i]) else {
        return None;
    };
    if !name
        .chars()
        .next()
        .is_some_and(|ch| ch.is_ascii_alphabetic() || ch == '_')
    {
        return None;
    }
    let close = matching(&tokens, open);
    // Nothing but trailing qualifiers may follow the parameter list.
    if tokens[close + 1..].iter().any(|tok| {
        !matches!(tok, Tok::Ident(kw) if matches!(kw.as_str(), "const" | "throw" | "noexcept"))
            && !matches!(tok, Tok::Punct('(' | ')'))
    }) {
        return None;
    }
    let returns = match returns_override {
        Some(returns) if open == 1 => returns,
        Some(_) => return None,
        None => join(&tokens[..open - 1]),
    };
    if returns.is_empty() || returns.contains(['(', ')', '[']) {
        return None;
    }
    let (params, variadic) = params(&statement_params(statement)?)?;
    Some(Prototype {
        name: name.clone(),
        returns,
        params,
        variadic,
        header: header.to_owned(),
    })
}

/// The parameter list of the declaration, from the original tokens so that SAL on
/// each parameter is still there.
fn statement_params(statement: &[Tok]) -> Option<Vec<Tok>> {
    // The parameter list is the last top-level parenthesized group.
    let mut depth = 0;
    let mut last = None;
    for (i, tok) in statement.iter().enumerate() {
        match tok {
            Tok::Punct('(') => {
                if depth == 0 {
                    last = Some(i);
                }
                depth += 1;
            }
            Tok::Punct(')') => depth -= 1,
            _ => {}
        }
    }
    let open = last?;
    let close = matching(statement, open);
    Some(statement[open + 1..close].to_vec())
}

fn split_commas(tokens: &[Tok]) -> Vec<&[Tok]> {
    let mut out = Vec::new();
    let mut depth = 0;
    let mut start = 0;
    for (i, tok) in tokens.iter().enumerate() {
        match tok {
            Tok::Punct('(' | '[' | '{') => depth += 1,
            Tok::Punct(')' | ']' | '}') => depth -= 1,
            Tok::Punct(',') if depth == 0 => {
                out.push(&tokens[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if start < tokens.len() {
        out.push(&tokens[start..]);
    }
    out
}

fn params(tokens: &[Tok]) -> Option<(Vec<Param>, bool)> {
    let mut out = Vec::new();
    let mut variadic = false;
    for (index, raw) in split_commas(tokens).into_iter().enumerate() {
        let (tokens, sal) = strip(raw);
        if tokens.iter().all(|tok| *tok == Tok::Punct('.')) && !tokens.is_empty() {
            variadic = true;
            continue;
        }
        if tokens.len() == 1 && matches!(&tokens[0], Tok::Ident(t) if t == "void" || t == "VOID") {
            continue;
        }
        if tokens.is_empty() {
            return None;
        }
        let (name, ty) = param_name_and_type(&tokens, index);
        out.push(Param {
            name,
            ty,
            direction: sal.direction,
            optional: sal.optional,
            size: sal.size,
        });
    }
    Some((out, variadic))
}

fn param_name_and_type(tokens: &[Tok], index: usize) -> (String, String) {
    // Function pointer: `type (callconv *name)(args)`.
    if let Some(open) = tokens.iter().position(|tok| *tok == Tok::Punct('(')) {
        let close = matching(tokens, open);
        if let Some(Tok::Ident(name)) = tokens[open..close]
            .iter()
            .rev()
            .find(|tok| matches!(tok, Tok::Ident(_)))
        {
            return (name.clone(), format!("{}(*)(...)", join(&tokens[..open])));
        }
    }
    // Array: `type name[N]` is passed as a pointer.
    let (core, array) = match tokens.iter().position(|tok| *tok == Tok::Punct('[')) {
        Some(at) => (&tokens[..at], true),
        None => (tokens, false),
    };
    let mut ty_tokens = core;
    let mut name = format!("arg{}", index + 1);
    if core.len() >= 2 {
        if let Some(Tok::Ident(last)) = core.last() {
            name = last.clone();
            ty_tokens = &core[..core.len() - 1];
        }
    }
    let mut ty = join(ty_tokens);
    if array {
        ty.push('*');
    }
    (name, ty)
}

fn enumerators(body: &[Tok]) -> Vec<(String, Option<String>)> {
    split_commas(body)
        .into_iter()
        .filter_map(|item| match item {
            [Tok::Ident(name)] => Some((name.clone(), None)),
            [Tok::Ident(name), Tok::Punct('='), value @ ..] => {
                Some((name.clone(), Some(join(value))))
            }
            _ => None,
        })
        .collect()
}

fn typedef(tokens: &[Tok], out: &mut Parsed) {
    let (tokens, _) = strip(tokens);
    if tokens.is_empty() {
        return;
    }
    if let Some(open) = tokens.iter().position(|tok| *tok == Tok::Punct('{')) {
        let close = matching(&tokens, open);
        let is_enum = matches!(&tokens[0], Tok::Ident(kw) if kw == "enum");
        let tag = match tokens.get(1) {
            Some(Tok::Ident(tag)) if open == 2 => Some(tag.clone()),
            _ => None,
        };
        let declarators = split_commas(&tokens[close + 1..]);
        let mut primary = None;
        for declarator in declarators {
            let stars = declarator
                .iter()
                .filter(|tok| **tok == Tok::Punct('*'))
                .count();
            let Some(Tok::Ident(name)) = declarator
                .iter()
                .rev()
                .find(|tok| matches!(tok, Tok::Ident(_)))
            else {
                continue;
            };
            if stars == 0 {
                primary.get_or_insert_with(|| name.clone());
                out.typedefs.push((
                    name.clone(),
                    TypeDef {
                        kind: if is_enum {
                            TypeKind::Enum
                        } else {
                            TypeKind::Record
                        },
                        target: tag.clone().unwrap_or_else(|| name.clone()),
                    },
                ));
            } else {
                out.typedefs.push((
                    name.clone(),
                    TypeDef {
                        kind: TypeKind::Pointer,
                        target: primary
                            .clone()
                            .or_else(|| tag.clone())
                            .unwrap_or_else(|| "void".to_owned()),
                    },
                ));
            }
        }
        if is_enum {
            let values = enumerators(&tokens[open + 1..close]);
            if let Some(name) = primary.or(tag.clone()) {
                out.enums.push((name, values.clone()));
            }
            if let Some(tag) = tag {
                out.enums.push((tag, values));
            }
        }
        return;
    }
    // Function pointer: `typedef ret (callconv *NAME)(args)`.
    if let Some(open) = tokens.iter().position(|tok| *tok == Tok::Punct('(')) {
        let close = matching(&tokens, open);
        if tokens[open..close].contains(&Tok::Punct('*')) {
            if let Some(Tok::Ident(name)) = tokens[open..close]
                .iter()
                .rev()
                .find(|tok| matches!(tok, Tok::Ident(_)))
            {
                out.typedefs.push((
                    name.clone(),
                    TypeDef {
                        kind: TypeKind::Function,
                        target: join(&tokens[..open]),
                    },
                ));
            }
        }
        return;
    }
    // `typedef base NAME, *PNAME, *LPNAME;`
    let declarators = split_commas(&tokens);
    let Some(first) = declarators.first() else {
        return;
    };
    let Some(name_at) = first.iter().rposition(|tok| matches!(tok, Tok::Ident(_))) else {
        return;
    };
    let base_end = first[..name_at]
        .iter()
        .rposition(|tok| *tok != Tok::Punct('*'))
        .map_or(0, |i| i + 1);
    let base = join(&first[..base_end]);
    if base.is_empty() {
        return;
    }
    for (i, declarator) in declarators.iter().enumerate() {
        let (stars, name) = if i == 0 {
            (name_at - base_end, &first[name_at])
        } else {
            let Some(at) = declarator
                .iter()
                .rposition(|tok| matches!(tok, Tok::Ident(_)))
            else {
                continue;
            };
            (
                declarator
                    .iter()
                    .filter(|tok| **tok == Tok::Punct('*'))
                    .count(),
                &declarator[at],
            )
        };
        let Tok::Ident(name) = name else {
            continue;
        };
        let array = declarator.contains(&Tok::Punct('['));
        out.typedefs.push((
            name.clone(),
            TypeDef {
                kind: if stars > 0 {
                    TypeKind::Pointer
                } else if array {
                    TypeKind::Record
                } else {
                    TypeKind::Alias
                },
                target: if stars > 1 {
                    format!("{base}{}", "*".repeat(stars - 1))
                } else {
                    base.clone()
                },
            },
        ));
    }
}

/// Evaluates a constant expression as written in a `#define` or enumerator: integer
/// literals, names `lookup` resolves, casts (ignored), unary `- ~ !` and binary
/// `* / % + - << >> & ^ |`. Anything else, or a name that does not resolve, fails.
pub fn evaluate(text: &str, lookup: &mut dyn FnMut(&str) -> Option<i128>) -> Option<i128> {
    let tokens = tokenize(text);
    let mut parser = Expr {
        tokens: &tokens,
        at: 0,
        lookup,
        depth: 0,
    };
    let value = parser.binary(0)?;
    (parser.at == tokens.len()).then_some(value)
}

struct Expr<'a, 'b> {
    tokens: &'a [Tok],
    at: usize,
    lookup: &'b mut dyn FnMut(&str) -> Option<i128>,
    depth: usize,
}

impl Expr<'_, '_> {
    fn peek(&self, offset: usize) -> Option<&Tok> {
        self.tokens.get(self.at + offset)
    }

    /// The binary operator at the cursor and its precedence, consuming nothing.
    fn operator(&self) -> Option<(&'static str, u8)> {
        let Some(Tok::Punct(ch)) = self.peek(0) else {
            return None;
        };
        let next = match self.peek(1) {
            Some(Tok::Punct(next)) => Some(*next),
            _ => None,
        };
        Some(match (ch, next) {
            ('|', Some('|')) | ('&', Some('&')) => return None,
            ('|', _) => ("|", 1),
            ('^', _) => ("^", 2),
            ('&', _) => ("&", 3),
            ('<', Some('<')) => ("<<", 4),
            ('>', Some('>')) => (">>", 4),
            ('+', _) => ("+", 5),
            ('-', _) => ("-", 5),
            ('*', _) => ("*", 6),
            ('/', _) => ("/", 6),
            ('%', _) => ("%", 6),
            _ => return None,
        })
    }

    fn binary(&mut self, min: u8) -> Option<i128> {
        self.depth += 1;
        if self.depth > 64 {
            return None;
        }
        let mut left = self.unary()?;
        while let Some((op, precedence)) = self.operator() {
            if precedence <= min {
                break;
            }
            self.at += op.len();
            let right = self.binary(precedence)?;
            left = match op {
                "|" => left | right,
                "^" => left ^ right,
                "&" => left & right,
                "<<" => left.checked_shl(u32::try_from(right).ok()?)?,
                ">>" => left.checked_shr(u32::try_from(right).ok()?)?,
                "+" => left.checked_add(right)?,
                "-" => left.checked_sub(right)?,
                "*" => left.checked_mul(right)?,
                "/" => left.checked_div(right)?,
                _ => left.checked_rem(right)?,
            };
        }
        self.depth -= 1;
        Some(left)
    }

    fn unary(&mut self) -> Option<i128> {
        match self.peek(0)?.clone() {
            Tok::Punct('-') => {
                self.at += 1;
                self.unary()?.checked_neg()
            }
            Tok::Punct('+') => {
                self.at += 1;
                self.unary()
            }
            Tok::Punct('~') => {
                self.at += 1;
                Some(!self.unary()?)
            }
            Tok::Punct('!') => {
                self.at += 1;
                Some(i128::from(self.unary()? == 0))
            }
            Tok::Punct('(') => {
                let close = matching(self.tokens, self.at);
                if self.is_cast(self.at + 1, close) {
                    self.at = close + 1;
                    return self.unary();
                }
                self.at += 1;
                let value = self.binary(0)?;
                if self.peek(0) != Some(&Tok::Punct(')')) {
                    return None;
                }
                self.at += 1;
                Some(value)
            }
            Tok::Num(text) => {
                self.at += 1;
                number(&text)
            }
            Tok::Ident(name) => {
                self.at += 1;
                (self.lookup)(&name)
            }
            _ => None,
        }
    }

    /// `(TYPE)` or `(TYPE *)` followed by an operand: names that are not constants.
    fn is_cast(&mut self, start: usize, close: usize) -> bool {
        let inner = &self.tokens[start..close];
        let operand_follows = matches!(
            self.tokens.get(close + 1),
            Some(Tok::Num(_) | Tok::Ident(_) | Tok::Punct('(' | '-' | '~'))
        );
        operand_follows
            && !inner.is_empty()
            && inner
                .iter()
                .all(|tok| matches!(tok, Tok::Ident(_) | Tok::Punct('*')))
            && inner
                .iter()
                .any(|tok| matches!(tok, Tok::Ident(name) if (self.lookup)(name).is_none()))
    }
}

/// An integer literal with any of the `u U l L i64 ui64` suffixes.
fn number(text: &str) -> Option<i128> {
    let lower = text.to_ascii_lowercase();
    let body = lower
        .trim_end_matches("i64")
        .trim_end_matches("i32")
        .trim_end_matches(['u', 'l']);
    if let Some(hex) = body.strip_prefix("0x") {
        i128::from_str_radix(hex, 16).ok()
    } else if body.len() > 1 && body.starts_with('0') {
        i128::from_str_radix(&body[1..], 8).ok()
    } else {
        body.parse().ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_expressions_follow_c_precedence_and_skip_casts() {
        let mut names = |name: &str| match name {
            "PAGE_GUARD" => Some(0x100),
            "STANDARD_RIGHTS_REQUIRED" => Some(0x000F_0000),
            "SYNCHRONIZE" => Some(0x0010_0000),
            _ => None,
        };
        assert_eq!(evaluate("0x00001000", &mut names), Some(0x1000));
        assert_eq!(
            evaluate("((DWORD)0x80000000L)", &mut names),
            Some(0x8000_0000)
        );
        assert_eq!(
            evaluate(
                "(STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE | 0xFFFF)",
                &mut names
            ),
            Some(0x001F_FFFF)
        );
        assert_eq!(evaluate("(1 << 3) + 2 * 3", &mut names), Some(14));
        assert_eq!(
            evaluate("(( HKEY ) (ULONG_PTR)((LONG)0x80000002) )", &mut names),
            Some(0x8000_0002)
        );
        assert_eq!(evaluate("-1", &mut names), Some(-1));
        assert_eq!(evaluate("0x40 | PAGE_GUARD", &mut names), Some(0x140));
        assert_eq!(evaluate("SOMETHING_ELSE", &mut names), None);
        assert_eq!(evaluate("\"text\"", &mut names), None);
    }

    fn parsed(text: &str) -> Parsed {
        let mut out = Parsed::default();
        parse(text, "um/test.h", &mut out);
        out
    }

    #[test]
    fn prototypes_keep_sal_direction_and_drop_decorations() {
        let out = parsed(
            r#"
            #ifdef __cplusplus
            extern "C" {
            #endif
            WINBASEAPI
            _Ret_maybenull_
            _Post_writable_byte_size_(dwSize)
            LPVOID
            WINAPI
            VirtualAlloc(
                _In_opt_ LPVOID lpAddress,
                _In_ SIZE_T dwSize,   // bytes
                _In_ DWORD flAllocationType,
                _In_ DWORD flProtect
                );
            NTSYSCALLAPI NTSTATUS NTAPI NtQueryInformationProcess(
                _In_ HANDLE ProcessHandle,
                _In_ PROCESSINFOCLASS ProcessInformationClass,
                _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
                _In_ ULONG ProcessInformationLength,
                _Out_opt_ PULONG ReturnLength);
            int __cdecl printf(const char* _Format, ...);
            FORCEINLINE PVOID Inline(VOID) { return 0; }
            #ifdef __cplusplus
            }
            #endif
            "#,
        );
        let names: Vec<&str> = out.prototypes.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(
            names,
            ["VirtualAlloc", "NtQueryInformationProcess", "printf"]
        );
        let alloc = &out.prototypes[0];
        assert_eq!(alloc.returns, "LPVOID");
        assert_eq!(alloc.params[0].name, "lpAddress");
        assert_eq!(alloc.params[0].ty, "LPVOID");
        assert_eq!(alloc.params[0].direction, Direction::In);
        assert!(alloc.params[0].optional);
        let query = &out.prototypes[1];
        assert_eq!(query.params[2].direction, Direction::Out);
        assert_eq!(
            query.params[2].size.as_deref(),
            Some("ProcessInformationLength")
        );
        assert!(query.params[4].optional);
        assert!(out.prototypes[2].variadic);
        assert_eq!(out.prototypes[2].params[0].ty, "const char*");
    }

    #[test]
    fn typedefs_enums_and_defines_are_collected() {
        let out = parsed(
            r#"
            typedef unsigned long DWORD;
            typedef DWORD *PDWORD, FAR *LPDWORD;
            typedef _Null_terminated_ CONST WCHAR *LPCWSTR, *PCWSTR;
            typedef struct _MEMORY_BASIC_INFORMATION { PVOID BaseAddress; } MEMORY_BASIC_INFORMATION, *PMEMORY_BASIC_INFORMATION;
            typedef enum _PROCESSINFOCLASS {
                ProcessBasicInformation = 0,
                ProcessDebugPort = 7,
                ProcessWow64Information = 26,
                ProcessImageFileName
            } PROCESSINFOCLASS;
            typedef DWORD (WINAPI *PTHREAD_START_ROUTINE)(LPVOID lpThreadParameter);
            DECLARE_HANDLE(HKEY);
            #define PAGE_EXECUTE_READWRITE  0x40
            #define MEM_COMMIT \
                    0x00001000
            #define MAKEWORD(a, b) ((WORD)(a))
            "#,
        );
        let find = |name: &str| {
            out.typedefs
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, t)| t.clone())
                .unwrap()
        };
        assert_eq!(find("DWORD").target, "unsigned long");
        assert_eq!(find("LPDWORD").kind, TypeKind::Pointer);
        assert_eq!(find("LPDWORD").target, "DWORD");
        assert_eq!(find("PCWSTR").target, "const WCHAR");
        assert_eq!(find("PMEMORY_BASIC_INFORMATION").kind, TypeKind::Pointer);
        assert_eq!(find("PTHREAD_START_ROUTINE").kind, TypeKind::Function);
        assert_eq!(find("HKEY").kind, TypeKind::Handle);
        let (_, values) = out
            .enums
            .iter()
            .find(|(name, _)| name == "PROCESSINFOCLASS")
            .unwrap();
        assert_eq!(
            values[1],
            ("ProcessDebugPort".to_owned(), Some("7".to_owned()))
        );
        assert_eq!(values[3], ("ProcessImageFileName".to_owned(), None));
        assert!(out
            .defines
            .contains(&("PAGE_EXECUTE_READWRITE".to_owned(), "0x40".to_owned())));
        assert!(out
            .defines
            .contains(&("MEM_COMMIT".to_owned(), "0x00001000".to_owned())));
        assert!(!out.defines.iter().any(|(name, _)| name == "MAKEWORD"));
    }

    #[test]
    fn comparison_expressions_in_return_sal_are_not_initializers() {
        let out = parsed(
            r#"
            WINBASEAPI _Success_(return != FALSE) BOOL WINAPI VirtualProtect(
                _In_ LPVOID lpAddress, _In_ SIZE_T dwSize,
                _In_ DWORD flNewProtect, _Out_ PDWORD lpflOldProtect);
            WINBASEAPI _When_(lpModuleName == NULL, _Ret_notnull_)
                _When_(lpModuleName != NULL, _Ret_maybenull_)
                HMODULE WINAPI GetModuleHandleW(_In_opt_ LPCWSTR lpModuleName);
        "#,
        );
        assert_eq!(out.prototypes.len(), 2);
        assert_eq!(out.prototypes[0].name, "VirtualProtect");
        assert_eq!(out.prototypes[0].params[3].direction, Direction::Out);
        assert_eq!(out.prototypes[1].name, "GetModuleHandleW");
    }
}
