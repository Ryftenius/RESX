#![cfg(windows)]
use serde_json::Value;
use std::process::Command;

fn report(category: &str) -> Value {
    let path = std::env::var_os("RESX_CAPABILITY_FIXTURE")
        .expect("Set RESX_CAPABILITY_FIXTURE to the compiled capability_contracts.dll fixture");
    let result = Command::new(env!("CARGO_BIN_EXE_resx"))
        .arg(category)
        .arg(path)
        .args(["--json", "--no-pdb", "--quiet"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    serde_json::from_slice(&result.stdout).unwrap()
}

#[test]
#[ignore = "requires the offline compiled capability_contracts.dll fixture"]
fn compiled_ipc_network_crypto_calls_preserve_arguments_and_provenance() {
    let report = report("contracts");
    let calls = report["contracts"]["calls"].as_array().unwrap();
    let call = |api: &str| {
        calls
            .iter()
            .find(|c| c["api"] == api)
            .unwrap_or_else(|| panic!("Missing {api}"))
    };
    let text = |api: &str, arg: &str, value: &str| {
        assert!(
            call(api)["details"]["strings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["argument"] == arg && s["value"] == value),
            "{api}: {arg}"
        )
    };
    let scalar = |api: &str, arg: &str, value: u64| {
        assert!(
            call(api)["arguments"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["name"] == arg && s["value"]["value"] == value),
            "{api}: {arg}"
        )
    };
    text(
        "CreateNamedPipeW",
        "name",
        r"\\.\pipe\resx-contract-fixture",
    );
    scalar("CreateNamedPipeW", "max_instances", 2);
    scalar("CreateNamedPipeW", "output_size", 1024);
    scalar("CreateNamedPipeW", "input_size", 2048);
    assert_eq!(call("ConnectNamedPipe")["category"], "ipc");
    text("CreateFileMappingW", "name", r"Local\RESX-Contract-Mapping");
    text("RpcServerUseProtseqEpW", "protocol", "ncalrpc");
    text("RpcServerUseProtseqEpW", "endpoint", "RESX-Contract-RPC");
    assert_eq!(
        call("connect")["details"]["socket_address"]["host"],
        "127.0.0.1"
    );
    assert_eq!(call("connect")["details"]["socket_address"]["port"], 8080);
    text("WinHttpConnect", "host", "fixture.invalid");
    scalar("WinHttpConnect", "port", 443);
    text("WinHttpOpenRequest", "method", "POST");
    text("WinHttpOpenRequest", "path", "/fixture");
    scalar("WinHttpOpenRequest", "flags", 0x800000);
    text("BCryptOpenAlgorithmProvider", "algorithm", "AES");
    assert_eq!(
        call("BCryptSetProperty")["details"]["chaining_mode"],
        "ChainingModeCBC"
    );
    assert_eq!(call("CryptGenKey")["details"]["algorithm_name"], "AES-256");
    assert_eq!(
        call("CoCreateInstance")["details"]["guid_arguments"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    for (consumer, producer) in [
        ("WinHttpConnect", "WinHttpOpen"),
        ("WinHttpOpenRequest", "WinHttpConnect"),
        ("ConnectNamedPipe", "CreateNamedPipeW"),
        ("MapViewOfFile", "CreateFileMappingW"),
        ("BCryptSetProperty", "BCryptOpenAlgorithmProvider"),
    ] {
        assert!(call(consumer)["details"]["predecessors"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["producer_api"] == producer
                && p["producer_rva"] == call(producer)["site_rva"]));
    }
    assert!(!calls.iter().any(|c| c["api"] == "RegCloseKey"));
    let alpc: Vec<_> = calls
        .iter()
        .filter(|c| c["api"] == "NtAlpcConnectPort")
        .collect();
    assert_eq!(alpc.len(), 2);
    assert_eq!(
        alpc.iter()
            .filter(|c| c["details"]["strings"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["argument"] == "port_name"
                    && s["value"] == r"\RPC Control\RESX-Contract-ALPC"))
            .count(),
        1
    );
    assert_eq!(
        alpc.iter()
            .filter(|c| c["details"]["strings"].as_array().unwrap().is_empty())
            .count(),
        1
    );
    let modes: Vec<_> = calls
        .iter()
        .filter(|c| c["api"] == "BCryptSetProperty")
        .collect();
    assert_eq!(
        modes
            .iter()
            .filter(|c| c["details"]["chaining_mode"].is_null())
            .count(),
        1
    );
    let hosts: Vec<_> = calls
        .iter()
        .filter(|c| c["api"] == "WinHttpConnect")
        .collect();
    assert_eq!(hosts.len(), 2);
    assert_eq!(
        hosts
            .iter()
            .filter(|c| c["details"]["strings"].as_array().unwrap().is_empty())
            .count(),
        1
    );
    let flows = &report["contracts"]["flows"];
    assert!(flows["network_requests"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["host"] == "fixture.invalid"
            && r["port"] == 443
            && r["scheme"] == "https"
            && r["method"] == "POST"
            && r["path"] == "/fixture"));
    assert!(flows["crypto_configurations"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["algorithm"] == "AES" && r["mode"] == "ChainingModeCBC"));
    assert!(flows["ipc_channels"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["kind"] == "named-pipe"
            && r["role"] == "server-create"
            && r["operations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|o| o["api"] == "ConnectNamedPipe")));
}

#[test]
#[ignore = "requires the offline compiled capability_contracts.dll fixture"]
fn category_commands_exclude_unrelated_calls() {
    for category in ["ipc", "network", "crypto"] {
        let report = report(category);
        let calls = report[category]["calls"].as_array().unwrap();
        assert!(!calls.is_empty());
        assert!(calls.iter().all(|c| c["category"] == category));
        for (key, owner) in [
            ("network_requests", "network"),
            ("ipc_channels", "ipc"),
            ("crypto_configurations", "crypto"),
        ] {
            if owner != category {
                assert!(report[category]["flows"][key]
                    .as_array()
                    .unwrap()
                    .is_empty());
            }
        }
        assert_eq!(
            report[category]["evidence_status"],
            "static; no target execution"
        );
    }
}
