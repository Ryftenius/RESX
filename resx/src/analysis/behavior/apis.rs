//! Exact library/API contracts shared by triage and argument recovery.
#[derive(Clone, Copy)]
pub struct Spec {
    pub category: &'static str,
    pub args: &'static [(&'static str, usize)],
    pub text: &'static [(usize, bool)],
    pub returns_handle: bool,
}

pub fn is_loader_api(dll: &str, name: &str) -> bool {
    let dll = dll.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    name.contains("loadlibrary")
        || name.contains("getprocaddress")
        || matches!(
            name.as_str(),
            "ldrloaddll" | "ldrgetprocedureaddress" | "ldrgetdllhandle"
        )
        || (dll.contains("ntdll") && name.starts_with("ldr"))
}

pub fn is_executable_memory_api(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "virtualalloc"
            | "virtualalloc2"
            | "virtualallocex"
            | "virtualprotect"
            | "virtualprotectex"
            | "ntallocatevirtualmemory"
            | "ntprotectvirtualmemory"
            | "zwallocatevirtualmemory"
            | "zwprotectvirtualmemory"
            | "mapviewoffile"
            | "mapviewoffileex"
            | "createmapping"
            | "createfilemappinga"
            | "createfilemappingw"
            | "flushinstructioncache"
    )
}

pub fn is_process_memory_write_api(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "writeprocessmemory" | "ntwritevirtualmemory" | "zwwritevirtualmemory"
    )
}

pub fn is_thread_context_api(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "getthreadcontext" | "setthreadcontext" | "wow64getthreadcontext" | "wow64setthreadcontext"
    )
}

pub fn invocation_behavior_tags(dll: &str, name: &str) -> Vec<&'static str> {
    let dll = dll.to_ascii_lowercase();
    let name = name.to_ascii_lowercase();
    let mut tags = Vec::new();
    if matches!(
        name.as_str(),
        "virtualalloc"
            | "virtualalloc2"
            | "virtualallocex"
            | "heapalloc"
            | "localalloc"
            | "globalalloc"
            | "ntallocatevirtualmemory"
            | "zwallocatevirtualmemory"
    ) {
        tags.push("memory allocation");
    }
    if matches!(
        name.as_str(),
        "virtualprotect" | "virtualprotectex" | "ntprotectvirtualmemory" | "zwprotectvirtualmemory"
    ) {
        tags.push("memory protection change");
    }
    if matches!(
        name.as_str(),
        "createfilemappinga"
            | "createfilemappingw"
            | "openfilemappinga"
            | "openfilemappingw"
            | "mapviewoffile"
            | "mapviewoffileex"
    ) {
        tags.push("section or mapped-memory backing");
    }
    if matches!(
        name.as_str(),
        "virtualfree"
            | "virtualfreeex"
            | "heapfree"
            | "localfree"
            | "globalfree"
            | "unmapviewoffile"
            | "ntfreevirtualmemory"
            | "zwfreevirtualmemory"
    ) {
        tags.push("memory cleanup");
    }
    if dll.contains("bcrypt")
        || dll.contains("ncrypt")
        || name.starts_with("bcrypt")
        || name.starts_with("crypt")
    {
        tags.push("cryptographic API use");
    }
    if matches!(
        name.as_str(),
        "createfilea" | "createfilew" | "writefile" | "readfile" | "deletefilea" | "deletefilew"
    ) {
        tags.push("file I/O");
    }
    if dll.contains("ws2_32")
        || dll.contains("winhttp")
        || dll.contains("wininet")
        || dll.contains("dnsapi")
    {
        tags.push("network I/O");
    }
    if name.contains("createthread") || name.contains("queueuserapc") {
        tags.push("thread or APC activity");
    }
    if is_loader_api(&dll, &name) {
        tags.push("dynamic library resolution");
    }
    tags
}
type Definition = (
    &'static str,
    &'static [(&'static str, usize)],
    &'static [(usize, bool)],
    bool,
);

pub fn lookup(dll: &str, name: &str) -> Option<Spec> {
    let name = ordinal_name(dll, name).unwrap_or(name);
    let library = dll.to_ascii_lowercase();
    let core = matches!(library.as_str(), "kernel32.dll" | "kernelbase.dll")
        || library.starts_with("api-ms-win-core-");
    let native = matches!(library.as_str(), "ntdll.dll" | "ntoskrnl.exe");
    let wide = name.ends_with('W');
    let text0 = if wide {
        &[(0, true)][..]
    } else {
        &[(0, false)][..]
    };
    let (category, args, text, returns_handle): Definition = match (library.as_str(), name) {
        (_, "CreateNamedPipeA" | "CreateNamedPipeW") if core => (
            "ipc",
            &[
                ("name", 8),
                ("open_mode", 4),
                ("pipe_mode", 4),
                ("max_instances", 4),
                ("output_size", 4),
                ("input_size", 4),
                ("timeout", 4),
                ("security_attributes", 8),
            ],
            text0,
            true,
        ),
        (_, "CreateFileA" | "CreateFileW") if core => (
            "io",
            &[
                ("name", 8),
                ("access", 4),
                ("share_mode", 4),
                ("security_attributes", 8),
                ("creation", 4),
                ("flags", 4),
                ("template", 8),
            ],
            text0,
            true,
        ),
        (_, "ConnectNamedPipe") if core => ("ipc", &[("handle", 8), ("overlapped", 8)], &[], false),
        (_, "CallNamedPipeA" | "CallNamedPipeW") if core => (
            "ipc",
            &[
                ("name", 8),
                ("input_buffer", 8),
                ("input_length", 4),
                ("output_buffer", 8),
                ("output_length", 4),
                ("bytes_read", 8),
                ("timeout", 4),
            ],
            text0,
            false,
        ),
        (_, "TransactNamedPipe") if core => (
            "ipc",
            &[
                ("handle", 8),
                ("input_buffer", 8),
                ("input_length", 4),
                ("output_buffer", 8),
                ("output_length", 4),
                ("bytes_read", 8),
                ("overlapped", 8),
            ],
            &[],
            false,
        ),
        (_, "CreateFileMappingA" | "CreateFileMappingW") if core => (
            "ipc",
            &[
                ("file", 8),
                ("security_attributes", 8),
                ("protection", 4),
                ("size_high", 4),
                ("size_low", 4),
                ("name", 8),
            ],
            if wide { &[(5, true)] } else { &[(5, false)] },
            true,
        ),
        (_, "OpenFileMappingA" | "OpenFileMappingW") if core => (
            "ipc",
            &[("access", 4), ("inherit", 4), ("name", 8)],
            if wide { &[(2, true)] } else { &[(2, false)] },
            true,
        ),
        (_, "MapViewOfFile") if core => (
            "ipc",
            &[
                ("mapping", 8),
                ("access", 4),
                ("offset_high", 4),
                ("offset_low", 4),
                ("length", 8),
            ],
            &[],
            false,
        ),
        (_, "NtAlpcConnectPort" | "ZwAlpcConnectPort") if native => (
            "ipc",
            &[
                ("port_handle_out", 8),
                ("port_name", 8),
                ("object_attributes", 8),
                ("port_attributes", 8),
                ("flags", 4),
                ("server_sid", 8),
                ("message", 8),
                ("message_length", 8),
                ("out_attributes", 8),
                ("in_attributes", 8),
                ("timeout", 8),
            ],
            &[],
            false,
        ),
        (_, "NtAlpcCreatePort" | "ZwAlpcCreatePort") if native => (
            "ipc",
            &[
                ("port_handle_out", 8),
                ("object_attributes", 8),
                ("port_attributes", 8),
            ],
            &[],
            false,
        ),
        (_, "NtAlpcSendWaitReceivePort" | "ZwAlpcSendWaitReceivePort") if native => (
            "ipc",
            &[
                ("port", 8),
                ("flags", 4),
                ("send_message", 8),
                ("send_attributes", 8),
                ("receive_message", 8),
                ("receive_length", 8),
                ("receive_attributes", 8),
                ("timeout", 8),
            ],
            &[],
            false,
        ),
        ("rpcrt4.dll", "RpcStringBindingComposeA" | "RpcStringBindingComposeW") => (
            "ipc",
            &[
                ("object_uuid", 8),
                ("protocol", 8),
                ("network_address", 8),
                ("endpoint", 8),
                ("options", 8),
                ("binding_out", 8),
            ],
            if wide {
                &[(0, true), (1, true), (2, true), (3, true), (4, true)]
            } else {
                &[(0, false), (1, false), (2, false), (3, false), (4, false)]
            },
            false,
        ),
        ("rpcrt4.dll", "RpcServerUseProtseqEpA" | "RpcServerUseProtseqEpW") => (
            "ipc",
            &[
                ("protocol", 8),
                ("max_calls", 4),
                ("endpoint", 8),
                ("security_descriptor", 8),
            ],
            if wide {
                &[(0, true), (2, true)]
            } else {
                &[(0, false), (2, false)]
            },
            false,
        ),
        ("ole32.dll" | "combase.dll", "CoCreateInstance") => (
            "ipc",
            &[
                ("class_id", 8),
                ("outer", 8),
                ("class_context", 4),
                ("interface_id", 8),
                ("object_out", 8),
            ],
            &[],
            false,
        ),
        ("ws2_32.dll", "connect" | "bind") => (
            "network",
            &[("socket", 8), ("address", 8), ("address_length", 4)],
            &[],
            false,
        ),
        ("ws2_32.dll", "socket") => (
            "network",
            &[("address_family", 4), ("socket_type", 4), ("protocol", 4)],
            &[],
            true,
        ),
        ("ws2_32.dll", "send" | "recv") => (
            "network",
            &[("socket", 8), ("buffer", 8), ("length", 4), ("flags", 4)],
            &[],
            false,
        ),
        ("ws2_32.dll", "sendto") => (
            "network",
            &[
                ("socket", 8),
                ("buffer", 8),
                ("length", 4),
                ("flags", 4),
                ("address", 8),
                ("address_length", 4),
            ],
            &[],
            false,
        ),
        ("ws2_32.dll", "getaddrinfo" | "GetAddrInfoW") => (
            "network",
            &[("host", 8), ("service", 8), ("hints", 8), ("result_out", 8)],
            if wide {
                &[(0, true), (1, true)]
            } else {
                &[(0, false), (1, false)]
            },
            false,
        ),
        ("dnsapi.dll", "DnsQuery_A" | "DnsQuery_W" | "DnsQuery_UTF8") => (
            "network",
            &[
                ("name", 8),
                ("record_type", 4),
                ("options", 4),
                ("servers", 8),
                ("records_out", 8),
                ("reserved", 8),
            ],
            if name == "DnsQuery_W" {
                &[(0, true)]
            } else {
                &[(0, false)]
            },
            false,
        ),
        ("winhttp.dll", "WinHttpOpen") => (
            "network",
            &[
                ("agent", 8),
                ("access_type", 4),
                ("proxy", 8),
                ("proxy_bypass", 8),
                ("flags", 4),
            ],
            &[(0, true), (2, true), (3, true)],
            true,
        ),
        ("winhttp.dll", "WinHttpConnect") => (
            "network",
            &[("session", 8), ("host", 8), ("port", 2), ("reserved", 4)],
            &[(1, true)],
            true,
        ),
        ("winhttp.dll", "WinHttpOpenRequest") => (
            "network",
            &[
                ("connection", 8),
                ("method", 8),
                ("path", 8),
                ("version", 8),
                ("referrer", 8),
                ("accept_types", 8),
                ("flags", 4),
            ],
            &[(1, true), (2, true), (3, true), (4, true)],
            true,
        ),
        ("winhttp.dll", "WinHttpSendRequest") => (
            "network",
            &[
                ("request", 8),
                ("headers", 8),
                ("headers_length", 4),
                ("input_buffer", 8),
                ("input_length", 4),
                ("total_length", 4),
                ("context", 8),
            ],
            &[],
            false,
        ),
        ("wininet.dll", "InternetConnectA" | "InternetConnectW") => (
            "network",
            &[
                ("session", 8),
                ("host", 8),
                ("port", 2),
                ("username", 8),
                ("password", 8),
                ("service", 4),
                ("flags", 4),
                ("context", 8),
            ],
            if wide { &[(1, true)] } else { &[(1, false)] },
            true,
        ),
        ("wininet.dll", "InternetOpenUrlA" | "InternetOpenUrlW") => (
            "network",
            &[
                ("session", 8),
                ("url", 8),
                ("headers", 8),
                ("headers_length", 4),
                ("flags", 4),
                ("context", 8),
            ],
            if wide { &[(1, true)] } else { &[(1, false)] },
            true,
        ),
        ("bcrypt.dll", "BCryptOpenAlgorithmProvider") => (
            "crypto",
            &[
                ("algorithm_out", 8),
                ("algorithm", 8),
                ("provider", 8),
                ("flags", 4),
            ],
            &[(1, true), (2, true)],
            false,
        ),
        ("bcrypt.dll", "BCryptSetProperty") => (
            "crypto",
            &[
                ("object", 8),
                ("property", 8),
                ("input_buffer", 8),
                ("input_length", 4),
                ("flags", 4),
            ],
            &[(1, true)],
            false,
        ),
        ("bcrypt.dll", "BCryptEncrypt" | "BCryptDecrypt") => (
            "crypto",
            &[
                ("key", 8),
                ("input_buffer", 8),
                ("input_length", 4),
                ("padding_info", 8),
                ("iv", 8),
                ("iv_length", 4),
                ("output_buffer", 8),
                ("output_length", 4),
                ("result_length", 8),
                ("flags", 4),
            ],
            &[],
            false,
        ),
        ("bcrypt.dll", "BCryptGenerateSymmetricKey") => (
            "crypto",
            &[
                ("algorithm", 8),
                ("key_out", 8),
                ("key_object", 8),
                ("key_object_length", 4),
                ("secret", 8),
                ("secret_length", 4),
                ("flags", 4),
            ],
            &[],
            false,
        ),
        ("bcrypt.dll", "BCryptHashData") => (
            "crypto",
            &[
                ("hash", 8),
                ("input_buffer", 8),
                ("input_length", 4),
                ("flags", 4),
            ],
            &[],
            false,
        ),
        ("advapi32.dll", "CryptEncrypt") => (
            "crypto",
            &[
                ("key", 8),
                ("hash", 8),
                ("final", 4),
                ("flags", 4),
                ("buffer", 8),
                ("length_pointer", 8),
                ("buffer_capacity", 4),
            ],
            &[],
            false,
        ),
        ("advapi32.dll", "CryptDecrypt") => (
            "crypto",
            &[
                ("key", 8),
                ("hash", 8),
                ("final", 4),
                ("flags", 4),
                ("buffer", 8),
                ("length_pointer", 8),
            ],
            &[],
            false,
        ),
        ("advapi32.dll", "CryptDeriveKey") => (
            "crypto",
            &[
                ("provider", 8),
                ("algorithm_id", 4),
                ("base_hash", 8),
                ("flags", 4),
                ("key_out", 8),
            ],
            &[],
            false,
        ),
        ("advapi32.dll", "CryptGenKey") => (
            "crypto",
            &[
                ("provider", 8),
                ("algorithm_id", 4),
                ("flags", 4),
                ("key_out", 8),
            ],
            &[],
            false,
        ),
        ("crypt32.dll", "CryptProtectData" | "CryptUnprotectData") => (
            "crypto",
            &[
                ("input_blob", 8),
                ("description", 8),
                ("entropy_blob", 8),
                ("reserved", 8),
                ("prompt", 8),
                ("flags", 4),
                ("output_blob", 8),
            ],
            &[],
            false,
        ),
        _ => return None,
    };
    Some(Spec {
        category,
        args,
        text,
        returns_handle,
    })
}

/// Winsock ABI ordinals, independently checked against the local export table.
/// This names the expected import contract, never the actual loaded provider.
pub fn ordinal_name(dll: &str, name: &str) -> Option<&'static str> {
    if !dll.eq_ignore_ascii_case("ws2_32.dll") {
        return None;
    }
    match name {
        "#2" => Some("bind"),
        "#4" => Some("connect"),
        "#16" => Some("recv"),
        "#19" => Some("send"),
        "#20" => Some("sendto"),
        "#23" => Some("socket"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn import_library_and_exact_name_both_matter() {
        assert_eq!(
            lookup("kernel32.dll", "ConnectNamedPipe").unwrap().category,
            "ipc"
        );
        assert!(lookup("user32.dll", "SendMessageW").is_none());
        assert!(lookup("pretend.dll", "BCryptDecrypt").is_none());
        assert!(lookup("advapi32.dll", "RegOpenKeyW").is_none());
        assert_eq!(lookup("WS2_32.DLL", "connect").unwrap().category, "network");
    }

    #[test]
    fn invocation_tags_share_exact_api_semantics() {
        assert!(invocation_behavior_tags("kernel32.dll", "VirtualProtect")
            .contains(&"memory protection change"));
        assert!(
            invocation_behavior_tags("kernel32.dll", "CreateFileMappingW")
                .contains(&"section or mapped-memory backing")
        );
        assert!(invocation_behavior_tags("ws2_32.dll", "connect").contains(&"network I/O"));
        assert!(!invocation_behavior_tags("pretend.dll", "MapViewish")
            .contains(&"section or mapped-memory backing"));
    }
}
