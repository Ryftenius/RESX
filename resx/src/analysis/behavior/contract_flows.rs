//! Summaries follow producer identity, never merely adjacent API names.
use serde_json::{json, Value};
use std::collections::BTreeMap;
fn text<'a>(call: &'a Value, name: &str) -> Option<&'a str> {
    call["details"]["strings"]
        .as_array()?
        .iter()
        .find(|s| s["argument"] == name)?["value"]
        .as_str()
}
fn scalar(call: &Value, name: &str) -> Option<u64> {
    call["arguments"]
        .as_array()?
        .iter()
        .find(|s| s["name"] == name)?["value"]["value"]
        .as_u64()
}
fn producer<'a>(
    call: &Value,
    argument: &str,
    calls: &BTreeMap<u64, &'a Value>,
) -> Option<&'a Value> {
    let reference = call["details"]["predecessors"]
        .as_array()?
        .iter()
        .find(|p| p["argument"] == argument)?;
    let result = *calls.get(&reference["producer_rva"].as_u64()?)?;
    if result["api"] != reference["producer_api"] {
        return None;
    }
    Some(result)
}
pub fn summarize(report: &Value) -> Value {
    let Some(calls) = report["calls"].as_array() else {
        return Value::Null;
    };
    let by_rva: BTreeMap<_, _> = calls
        .iter()
        .filter_map(|call| Some((call["site_rva"].as_u64()?, call)))
        .collect();
    let mut requests = Vec::new();
    let mut channels = Vec::new();
    let mut crypto = Vec::new();
    let mut handle_consumers: BTreeMap<u64, Vec<Value>> = BTreeMap::new();
    for call in calls {
        if let Some(site) = producer(call, "handle", &by_rva).and_then(|p| p["site_rva"].as_u64()) {
            handle_consumers
                .entry(site)
                .or_default()
                .push(json!({"api":call["api"],"site_rva":call["site_rva"]}));
        }
    }
    for call in calls {
        match call["api"].as_str().unwrap_or("") {
            "WinHttpOpenRequest" => {
                if let Some(connection) =
                    producer(call, "connection", &by_rva).filter(|p| p["api"] == "WinHttpConnect")
                {
                    let scheme = scalar(call, "flags").map(|flags| {
                        if flags & 0x800000 != 0 {
                            "https"
                        } else {
                            "http"
                        }
                    });
                    requests.push(json!({"kind":"http-request-configuration","host":text(connection,"host"),"port":scalar(connection,"port"),"scheme":scheme,"method":text(call,"method"),"path":text(call,"path"),"depends_on":[connection["site_rva"],call["site_rva"]],"status":"static handle-producer correlation; request submission and C2 role unobserved"}));
                }
            }
            "CreateNamedPipeA" | "CreateNamedPipeW" | "CreateFileA" | "CreateFileW"
                if call["category"] == "ipc" =>
            {
                let server = call["api"].as_str().unwrap().starts_with("CreateNamedPipe");
                let consumers = call["site_rva"]
                    .as_u64()
                    .and_then(|site| handle_consumers.get(&site))
                    .cloned()
                    .unwrap_or_default();
                channels.push(json!({"kind":"named-pipe","name":text(call,"name"),"role":if server {"server-create"}else{"client-open"},"producer_rva":call["site_rva"],"operations":consumers,"status":"static configuration; name equality does not prove a shared live channel or peer"}));
            }
            "MapViewOfFile" => {
                if let Some(mapping) = producer(call, "mapping", &by_rva) {
                    channels.push(json!({"kind":"shared-mapping","name":text(mapping,"name"),"mapping_rva":mapping["site_rva"],"view_rva":call["site_rva"],"view_length":scalar(call,"length"),"status":"static mapping-handle provenance; sharing and peer identity unobserved"}));
                }
            }
            "BCryptSetProperty" if !call["details"]["chaining_mode"].is_null() => {
                if let Some(provider) = producer(call, "object", &by_rva)
                    .filter(|p| p["api"] == "BCryptOpenAlgorithmProvider")
                {
                    crypto.push(json!({"kind":"algorithm-mode-configuration","algorithm":text(provider,"algorithm"),"mode":call["details"]["chaining_mode"],"depends_on":[provider["site_rva"],call["site_rva"]],"status":"static conditional provider/property flow; successful encryption/decryption unobserved"}));
                }
            }
            _ => (),
        }
    }
    json!({"network_requests":requests,"ipc_channels":channels,"crypto_configurations":crypto,"identity_basis":"Exact static producer call-site references; imported provider identity and execution remain unobserved"})
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn port_443_does_not_select_tls_and_unrelated_calls_do_not_connect() {
        let connection = json!({"api":"WinHttpConnect","site_rva":10,"details":{"strings":[{"argument":"host","value":"fixture.invalid"}]},"arguments":[{"name":"port","value":{"value":443}}]});
        let request = json!({"api":"WinHttpOpenRequest","site_rva":20,"details":{"predecessors":[{"argument":"connection","producer_api":"WinHttpConnect","producer_rva":10}]},"arguments":[{"name":"flags","value":{"value":0}}]});
        let mut report = json!({"calls":[connection,request]});
        assert_eq!(summarize(&report)["network_requests"][0]["scheme"], "http");
        report["calls"][1]["details"]["predecessors"][0]["producer_rva"] = json!(11);
        assert!(summarize(&report)["network_requests"]
            .as_array()
            .unwrap()
            .is_empty());
    }
}
