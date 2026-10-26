use serde::Serialize;
use serde_json::{json, Value};

pub const SCHEMA_VERSION: u32 = 1;

/// Omit optional per-call argument detail after deriving the report's findings.
pub fn omit_call_arguments(calls: &mut Value) {
    if let Some(calls) = calls.as_array_mut() {
        for call in calls {
            if let Some(call) = call.as_object_mut() {
                call.remove("arguments");
                call.remove("reconstructed_call");
                call.remove("buffer_fields");
            }
        }
    }
}

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
