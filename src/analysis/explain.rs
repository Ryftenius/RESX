use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExplainMode {
    Auto,
    Prefix,
    Api,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExplainChunk {
    pub kind: String,
    pub token: String,
    pub meaning: String,
    #[serde(skip_serializing)]
    pub phrase: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExplainPrefix {
    pub key: String,
    pub title: String,
    pub kind: String,
    pub layer: String,
    pub summary: String,
    pub notes: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ExplainResult {
    pub query: String,
    pub mode: String,
    pub exact_match: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<ExplainPrefix>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub remainder: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub chunks: Vec<ExplainChunk>,
    pub summary: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ExplainDb {
    prefixes: Vec<PrefixEntry>,
    verbs: Vec<GlossaryEntry>,
    objects: Vec<GlossaryEntry>,
    exact_symbols: Vec<ExactSymbolEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct PrefixEntry {
    key: String,
    title: String,
    kind: String,
    layer: String,
    summary: String,
    routine_phrase: String,
    #[serde(default)]
    notes: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct GlossaryEntry {
    key: String,
    summary: String,
    phrase: String,
}

#[derive(Clone, Debug, Deserialize)]
struct ExactSymbolEntry {
    symbol: String,
    summary: String,
    #[serde(default)]
    notes: Vec<String>,
}

fn db() -> &'static ExplainDb {
    static DB: OnceLock<ExplainDb> = OnceLock::new();
    DB.get_or_init(|| {
        serde_json::from_str(include_str!("data/explain.json"))
            .expect("bundled explain glossary must parse")
    })
}

pub fn explain_symbol(term: &str, mode: ExplainMode) -> ExplainResult {
    let query = term.trim();
    let database = db();

    if query.is_empty() {
        return ExplainResult {
            query: String::new(),
            mode: "unknown".to_owned(),
            exact_match: false,
            prefix: None,
            remainder: String::new(),
            chunks: Vec::new(),
            summary: "No symbol provided.".to_owned(),
            notes: Vec::new(),
        };
    }

    if mode != ExplainMode::Api {
        if let Some(prefix) = find_exact_prefix(database, query) {
            return ExplainResult {
                query: query.to_owned(),
                mode: "prefix".to_owned(),
                exact_match: true,
                prefix: Some(to_result_prefix(prefix)),
                remainder: String::new(),
                chunks: Vec::new(),
                summary: prefix.summary.clone(),
                notes: prefix.notes.clone(),
            };
        }
    }

    let exact_symbol = if mode != ExplainMode::Prefix {
        find_exact_symbol(database, query)
    } else {
        None
    };
    let prefix = if mode == ExplainMode::Prefix {
        None
    } else {
        find_symbol_prefix(database, query)
    };

    let remainder = prefix
        .as_ref()
        .map(|entry| query[entry.key.len()..].to_owned())
        .unwrap_or_else(|| query.to_owned());
    let chunks = explain_body(database, &remainder);
    let notes = exact_symbol
        .as_ref()
        .map(|entry| entry.notes.clone())
        .or_else(|| prefix.as_ref().map(|entry| entry.notes.clone()))
        .unwrap_or_default();

    let summary = if let Some(exact) = exact_symbol {
        exact.summary.clone()
    } else if let Some(prefix_entry) = prefix.as_ref() {
        build_symbol_summary(prefix_entry, &chunks, &remainder)
    } else if !chunks.is_empty() {
        build_chunk_summary(&chunks, None)
    } else {
        format!(
            "Could not fully classify `{}` from the built-in glossary; the name may be project-specific or a private helper.",
            query
        )
    };

    ExplainResult {
        query: query.to_owned(),
        mode: classify_mode(mode, prefix.is_some(), !remainder.is_empty()),
        exact_match: exact_symbol.is_some(),
        prefix: prefix.map(to_result_prefix),
        remainder: if prefix.is_some() {
            remainder
        } else {
            String::new()
        },
        chunks,
        summary,
        notes,
    }
}

fn classify_mode(mode: ExplainMode, has_prefix: bool, has_remainder: bool) -> String {
    match mode {
        ExplainMode::Prefix => "prefix".to_owned(),
        ExplainMode::Api => "api".to_owned(),
        ExplainMode::Auto => {
            if has_prefix && has_remainder {
                "api".to_owned()
            } else if has_prefix {
                "prefix".to_owned()
            } else {
                "symbol".to_owned()
            }
        }
    }
}

fn build_symbol_summary(prefix: &PrefixEntry, chunks: &[ExplainChunk], remainder: &str) -> String {
    if !chunks.is_empty() {
        let body = build_chunk_summary(chunks, Some(prefix));
        if body.ends_with('.') {
            body
        } else {
            format!("{}.", body)
        }
    } else if remainder.is_empty() {
        prefix.summary.clone()
    } else {
        format!(
            "{} in the {}.",
            capitalize(&prefix.routine_phrase),
            prefix.layer
        )
    }
}

fn build_chunk_summary(chunks: &[ExplainChunk], prefix: Option<&PrefixEntry>) -> String {
    let verb_phrase = chunks
        .iter()
        .find(|chunk| chunk.kind == "verb")
        .map(|chunk| chunk.phrase.clone());
    let object_parts: Vec<&str> = chunks
        .iter()
        .filter(|chunk| chunk.kind != "verb")
        .map(|chunk| chunk.phrase.as_str())
        .collect();

    let mut sentence = if let Some(verb) = verb_phrase {
        if object_parts.is_empty() {
            capitalize(&verb)
        } else {
            capitalize(&format!("{} {}", verb, object_parts.join(" ")))
        }
    } else if !object_parts.is_empty() {
        capitalize(&object_parts.join(" "))
    } else {
        "Explains the symbol name using built-in glossary matches".to_owned()
    };

    if let Some(prefix_entry) = prefix {
        sentence.push_str(&format!(" via the {}.", prefix_entry.layer));
    }
    sentence
}

fn explain_body(database: &ExplainDb, body: &str) -> Vec<ExplainChunk> {
    if body.is_empty() {
        return Vec::new();
    }

    let tokens = split_camel(body);
    let mut chunks = Vec::new();
    let mut idx = 0usize;
    while idx < tokens.len() {
        if let Some((end, entry)) = longest_match(&tokens, idx, &database.verbs) {
            chunks.push(ExplainChunk {
                kind: "verb".to_owned(),
                token: tokens[idx..end].join(""),
                meaning: entry.summary.clone(),
                phrase: entry.phrase.clone(),
            });
            idx = end;
            continue;
        }
        if let Some((end, entry)) = longest_match(&tokens, idx, &database.objects) {
            chunks.push(ExplainChunk {
                kind: "object".to_owned(),
                token: tokens[idx..end].join(""),
                meaning: entry.summary.clone(),
                phrase: entry.phrase.clone(),
            });
            idx = end;
            continue;
        }

        chunks.push(ExplainChunk {
            kind: "token".to_owned(),
            token: tokens[idx].clone(),
            meaning: tokens[idx].clone(),
            phrase: tokens[idx].clone(),
        });
        idx += 1;
    }
    chunks
}

fn longest_match<'a>(
    tokens: &[String],
    start: usize,
    entries: &'a [GlossaryEntry],
) -> Option<(usize, &'a GlossaryEntry)> {
    let mut best: Option<(usize, &'a GlossaryEntry)> = None;
    for end in (start + 1..=tokens.len()).rev() {
        let candidate = tokens[start..end].join("");
        if let Some(entry) = entries.iter().find(|entry| entry.key == candidate) {
            best = Some((end, entry));
            break;
        }
    }
    best
}

fn find_exact_prefix<'a>(database: &'a ExplainDb, query: &str) -> Option<&'a PrefixEntry> {
    database
        .prefixes
        .iter()
        .find(|entry| entry.key.eq_ignore_ascii_case(query))
}

fn find_symbol_prefix<'a>(database: &'a ExplainDb, query: &str) -> Option<&'a PrefixEntry> {
    database
        .prefixes
        .iter()
        .filter(|entry| query.len() > entry.key.len())
        .filter(|entry| query[..entry.key.len()].eq_ignore_ascii_case(&entry.key))
        .filter(|entry| {
            query
                .as_bytes()
                .get(entry.key.len())
                .is_some_and(|b| b.is_ascii_uppercase())
        })
        .max_by_key(|entry| entry.key.len())
}

fn find_exact_symbol<'a>(database: &'a ExplainDb, query: &str) -> Option<&'a ExactSymbolEntry> {
    database
        .exact_symbols
        .iter()
        .find(|entry| entry.symbol.eq_ignore_ascii_case(query))
}

fn to_result_prefix(entry: &PrefixEntry) -> ExplainPrefix {
    ExplainPrefix {
        key: entry.key.clone(),
        title: entry.title.clone(),
        kind: entry.kind.clone(),
        layer: entry.layer.clone(),
        summary: entry.summary.clone(),
        notes: entry.notes.clone(),
    }
}

fn split_camel(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let chars: Vec<char> = input.chars().collect();

    for (idx, ch) in chars.iter().copied().enumerate() {
        let prev = if idx > 0 { Some(chars[idx - 1]) } else { None };
        let next = chars.get(idx + 1).copied();
        let boundary = prev.is_some_and(|p| {
            (p.is_ascii_lowercase() && ch.is_ascii_uppercase())
                || (p.is_ascii_alphabetic() && ch.is_ascii_digit())
                || (p.is_ascii_digit() && ch.is_ascii_alphabetic())
                || (p.is_ascii_uppercase()
                    && ch.is_ascii_uppercase()
                    && next.is_some_and(|n| n.is_ascii_lowercase()))
        });

        if boundary && !current.is_empty() {
            out.push(current);
            current = String::new();
        }
        current.push(ch);
    }

    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    if let Some(first) = chars.next() {
        format!(
            "{}{}",
            first.to_ascii_uppercase(),
            chars.collect::<String>()
        )
    } else {
        String::new()
    }
}
