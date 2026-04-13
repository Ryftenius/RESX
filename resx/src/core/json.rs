use serde::Serialize;
use serde_json::{json, Value};

pub const SCHEMA_VERSION: u32 = 1;

pub fn versioned_items<T: Serialize>(key: &str, items: T) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        key: items,
    })
}

pub fn versioned_object<T: Serialize>(key: &str, value: T) -> Value {
    json!({
        "schema_version": SCHEMA_VERSION,
        key: value,
    })
}
