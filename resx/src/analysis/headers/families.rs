//! Which constants a parameter's values are drawn from.
//!
//! The headers declare `DWORD flProtect` but do not say that its values are the
//! `PAGE_*` constants, so that link is this table: parameter names, optionally
//! narrowed to APIs, mapped to constant name prefixes or explicit names. The
//! constants themselves, and their values, come from the parsed headers.

use std::collections::HashMap;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    /// Bits that combine: `MEM_COMMIT|MEM_RESERVE`.
    Flags,
    /// One value of a set.
    Enum,
    /// Values compared on their low 32 bits (sign-extended handle constants).
    Enum32,
    /// A device I/O control code, decomposed as CTL_CODE.
    Ioctl,
}

struct Rule {
    params: &'static [&'static str],
    /// API name prefixes the rule is limited to; empty for any API.
    apis: &'static [&'static str],
    prefixes: &'static [&'static str],
    names: &'static [&'static str],
    kind: Kind,
}

const STANDARD_RIGHTS: &[&str] = &[
    "DELETE",
    "READ_CONTROL",
    "WRITE_DAC",
    "WRITE_OWNER",
    "SYNCHRONIZE",
    "MAXIMUM_ALLOWED",
    "ACCESS_SYSTEM_SECURITY",
    "GENERIC_READ",
    "GENERIC_WRITE",
    "GENERIC_EXECUTE",
    "GENERIC_ALL",
];

/// More specific rules first; the first that matches is used.
const RULES: &[Rule] = &[
    Rule {
        params: &["dwFlags"],
        apis: &["BCryptGenRandom"],
        prefixes: &[],
        names: &[
            "BCRYPT_RNG_USE_ENTROPY_IN_BUFFER",
            "BCRYPT_USE_SYSTEM_PREFERRED_RNG",
        ],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwDesiredAccess", "DesiredAccess"],
        apis: &[
            "CreateWaitableTimer",
            "OpenWaitableTimer",
            "NtCreateTimer",
            "NtOpenTimer",
            "ZwCreateTimer",
            "ZwOpenTimer",
        ],
        prefixes: &["TIMER_"],
        names: STANDARD_RIGHTS,
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwFlags"],
        apis: &["CreateWaitableTimerEx"],
        prefixes: &["CREATE_WAITABLE_TIMER_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwIoControlCode", "IoControlCode"],
        apis: &[],
        prefixes: &["FILE_DEVICE_"],
        names: &[],
        kind: Kind::Ioctl,
    },
    Rule {
        params: &[
            "flProtect",
            "flNewProtect",
            "Protect",
            "NewProtect",
            "NewAccessProtection",
            "Win32Protect",
            "PageProtection",
            "flPageProtection",
            "dwProtect",
        ],
        apis: &[],
        prefixes: &["PAGE_"],
        names: &["SEC_COMMIT", "SEC_IMAGE", "SEC_RESERVE", "SEC_NOCACHE"],
        kind: Kind::Flags,
    },
    Rule {
        params: &[
            "flAllocationType",
            "AllocationType",
            "dwFreeType",
            "FreeType",
        ],
        apis: &[],
        prefixes: &["MEM_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwDesiredAccess", "DesiredAccess"],
        apis: &["MapViewOfFile", "OpenFileMapping", "NtMapViewOfSection"],
        prefixes: &["FILE_MAP_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwDesiredAccess", "DesiredAccess"],
        apis: &["OpenProcess", "NtOpenProcess", "ZwOpenProcess"],
        prefixes: &["PROCESS_"],
        names: STANDARD_RIGHTS,
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwDesiredAccess", "DesiredAccess"],
        apis: &["OpenThread", "NtOpenThread", "ZwOpenThread"],
        prefixes: &["THREAD_"],
        names: STANDARD_RIGHTS,
        kind: Kind::Flags,
    },
    Rule {
        params: &["DesiredAccess", "dwDesiredAccess"],
        apis: &[
            "OpenProcessToken",
            "OpenThreadToken",
            "NtOpenProcessToken",
            "NtOpenThreadToken",
            "DuplicateTokenEx",
            "NtDuplicateToken",
        ],
        prefixes: &["TOKEN_"],
        names: STANDARD_RIGHTS,
        kind: Kind::Flags,
    },
    Rule {
        params: &["samDesired", "DesiredAccess"],
        apis: &[
            "Reg",
            "NtOpenKey",
            "NtCreateKey",
            "ZwOpenKey",
            "ZwCreateKey",
        ],
        prefixes: &["KEY_"],
        names: STANDARD_RIGHTS,
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwDesiredAccess"],
        apis: &["OpenSCManager"],
        prefixes: &["SC_MANAGER_"],
        names: STANDARD_RIGHTS,
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwDesiredAccess"],
        apis: &["OpenService", "CreateService"],
        prefixes: &[],
        names: &[
            "SERVICE_ALL_ACCESS",
            "SERVICE_QUERY_CONFIG",
            "SERVICE_CHANGE_CONFIG",
            "SERVICE_QUERY_STATUS",
            "SERVICE_ENUMERATE_DEPENDENTS",
            "SERVICE_START",
            "SERVICE_STOP",
            "SERVICE_PAUSE_CONTINUE",
            "SERVICE_INTERROGATE",
            "SERVICE_USER_DEFINED_CONTROL",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
        ],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwDesiredAccess", "DesiredAccess"],
        apis: &[],
        prefixes: &[],
        names: &[
            "GENERIC_READ",
            "GENERIC_WRITE",
            "GENERIC_EXECUTE",
            "GENERIC_ALL",
            "MAXIMUM_ALLOWED",
            "ACCESS_SYSTEM_SECURITY",
            "DELETE",
            "READ_CONTROL",
            "WRITE_DAC",
            "WRITE_OWNER",
            "SYNCHRONIZE",
            "FILE_ALL_ACCESS",
            "FILE_GENERIC_READ",
            "FILE_GENERIC_WRITE",
            "FILE_GENERIC_EXECUTE",
            "FILE_READ_DATA",
            "FILE_WRITE_DATA",
            "FILE_APPEND_DATA",
            "FILE_READ_EA",
            "FILE_WRITE_EA",
            "FILE_EXECUTE",
            "FILE_READ_ATTRIBUTES",
            "FILE_WRITE_ATTRIBUTES",
        ],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwShareMode", "ShareAccess"],
        apis: &[],
        prefixes: &["FILE_SHARE_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwCreationDisposition"],
        apis: &[],
        prefixes: &[],
        names: &[
            "CREATE_NEW",
            "CREATE_ALWAYS",
            "OPEN_EXISTING",
            "OPEN_ALWAYS",
            "TRUNCATE_EXISTING",
        ],
        kind: Kind::Enum,
    },
    Rule {
        params: &["CreateDisposition", "Disposition"],
        apis: &["NtCreateFile", "ZwCreateFile", "IoCreateFile"],
        prefixes: &[],
        names: &[
            "FILE_SUPERSEDE",
            "FILE_OPEN",
            "FILE_CREATE",
            "FILE_OPEN_IF",
            "FILE_OVERWRITE",
            "FILE_OVERWRITE_IF",
        ],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwFlagsAndAttributes", "FileAttributes", "dwFileAttributes"],
        apis: &[],
        prefixes: &["FILE_ATTRIBUTE_", "FILE_FLAG_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["CreateOptions", "OpenOptions"],
        apis: &[],
        prefixes: &[],
        names: &[
            "FILE_DIRECTORY_FILE",
            "FILE_WRITE_THROUGH",
            "FILE_SEQUENTIAL_ONLY",
            "FILE_NO_INTERMEDIATE_BUFFERING",
            "FILE_SYNCHRONOUS_IO_ALERT",
            "FILE_SYNCHRONOUS_IO_NONALERT",
            "FILE_NON_DIRECTORY_FILE",
            "FILE_CREATE_TREE_CONNECTION",
            "FILE_COMPLETE_IF_OPLOCKED",
            "FILE_NO_EA_KNOWLEDGE",
            "FILE_OPEN_REMOTE_INSTANCE",
            "FILE_RANDOM_ACCESS",
            "FILE_DELETE_ON_CLOSE",
            "FILE_OPEN_BY_FILE_ID",
            "FILE_OPEN_FOR_BACKUP_INTENT",
            "FILE_NO_COMPRESSION",
            "FILE_RESERVE_OPFILTER",
            "FILE_OPEN_REPARSE_POINT",
            "FILE_OPEN_NO_RECALL",
            "FILE_OPEN_FOR_FREE_SPACE_QUERY",
        ],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwCreationFlags"],
        apis: &["CreateThread", "CreateRemoteThread"],
        prefixes: &[],
        names: &["CREATE_SUSPENDED", "STACK_SIZE_PARAM_IS_A_RESERVATION"],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwCreationFlags"],
        apis: &["CreateProcess"],
        prefixes: &[],
        names: &[
            "DEBUG_PROCESS",
            "DEBUG_ONLY_THIS_PROCESS",
            "CREATE_SUSPENDED",
            "DETACHED_PROCESS",
            "CREATE_NEW_CONSOLE",
            "NORMAL_PRIORITY_CLASS",
            "IDLE_PRIORITY_CLASS",
            "HIGH_PRIORITY_CLASS",
            "REALTIME_PRIORITY_CLASS",
            "BELOW_NORMAL_PRIORITY_CLASS",
            "ABOVE_NORMAL_PRIORITY_CLASS",
            "CREATE_NEW_PROCESS_GROUP",
            "CREATE_UNICODE_ENVIRONMENT",
            "CREATE_SEPARATE_WOW_VDM",
            "CREATE_SHARED_WOW_VDM",
            "CREATE_FORCEDOS",
            "INHERIT_PARENT_AFFINITY",
            "CREATE_PROTECTED_PROCESS",
            "EXTENDED_STARTUPINFO_PRESENT",
            "CREATE_SECURE_PROCESS",
            "CREATE_BREAKAWAY_FROM_JOB",
            "CREATE_PRESERVE_CODE_AUTHZ_LEVEL",
            "CREATE_DEFAULT_ERROR_MODE",
            "CREATE_NO_WINDOW",
        ],
        kind: Kind::Flags,
    },
    Rule {
        params: &["uType"],
        apis: &["MessageBox"],
        prefixes: &["MB_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["nCmdShow", "nShowCmd", "uCmdShow"],
        apis: &[],
        prefixes: &[],
        names: &[
            "SW_HIDE",
            "SW_SHOWNORMAL",
            "SW_SHOWMINIMIZED",
            "SW_SHOWMAXIMIZED",
            "SW_SHOWNOACTIVATE",
            "SW_SHOW",
            "SW_MINIMIZE",
            "SW_SHOWMINNOACTIVE",
            "SW_SHOWNA",
            "SW_RESTORE",
            "SW_SHOWDEFAULT",
            "SW_FORCEMINIMIZE",
        ],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwMoveMethod"],
        apis: &[],
        prefixes: &[],
        names: &["FILE_BEGIN", "FILE_CURRENT", "FILE_END"],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwFlags"],
        apis: &["LoadLibraryEx"],
        prefixes: &["LOAD_LIBRARY_"],
        names: &[
            "DONT_RESOLVE_DLL_REFERENCES",
            "LOAD_IGNORE_CODE_AUTHZ_LEVEL",
            "LOAD_WITH_ALTERED_SEARCH_PATH",
        ],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwFlags"],
        apis: &["GetModuleHandleEx"],
        prefixes: &["GET_MODULE_HANDLE_EX_FLAG_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwFlags"],
        apis: &["FormatMessage"],
        prefixes: &["FORMAT_MESSAGE_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwFlags"],
        apis: &["CreateToolhelp32Snapshot"],
        prefixes: &["TH32CS_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwFlags"],
        apis: &["WSASocket"],
        prefixes: &["WSA_FLAG_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwFlags"],
        apis: &["CryptAcquireContext"],
        prefixes: &[],
        names: &[
            "CRYPT_VERIFYCONTEXT",
            "CRYPT_NEWKEYSET",
            "CRYPT_DELETEKEYSET",
            "CRYPT_MACHINE_KEYSET",
            "CRYPT_SILENT",
            "CRYPT_DEFAULT_CONTAINER_OPTIONAL",
        ],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwOptions"],
        apis: &["DuplicateHandle"],
        prefixes: &["DUPLICATE_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["hKey"],
        apis: &["Reg", "SHReg"],
        prefixes: &[],
        names: &[
            "HKEY_CLASSES_ROOT",
            "HKEY_CURRENT_USER",
            "HKEY_LOCAL_MACHINE",
            "HKEY_USERS",
            "HKEY_PERFORMANCE_DATA",
            "HKEY_CURRENT_CONFIG",
            "HKEY_DYN_DATA",
        ],
        kind: Kind::Enum32,
    },
    Rule {
        params: &["dwOptions", "ulOptions"],
        apis: &["RegCreateKey", "RegOpenKey"],
        prefixes: &["REG_OPTION_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwType"],
        apis: &["RegSetValue", "RegSetKeyValue"],
        prefixes: &[],
        names: &[
            "REG_NONE",
            "REG_SZ",
            "REG_EXPAND_SZ",
            "REG_BINARY",
            "REG_DWORD",
            "REG_DWORD_BIG_ENDIAN",
            "REG_LINK",
            "REG_MULTI_SZ",
            "REG_RESOURCE_LIST",
            "REG_QWORD",
        ],
        kind: Kind::Enum,
    },
    Rule {
        params: &["af"],
        apis: &[
            "socket",
            "WSASocket",
            "inet_pton",
            "inet_ntop",
            "WSAStringToAddress",
        ],
        prefixes: &["AF_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["type"],
        apis: &["socket", "WSASocket"],
        prefixes: &[],
        names: &[
            "SOCK_STREAM",
            "SOCK_DGRAM",
            "SOCK_RAW",
            "SOCK_RDM",
            "SOCK_SEQPACKET",
        ],
        kind: Kind::Enum,
    },
    Rule {
        params: &["protocol"],
        apis: &["socket", "WSASocket"],
        prefixes: &["IPPROTO_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["idHook"],
        apis: &["SetWindowsHookEx"],
        prefixes: &["WH_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwProvType"],
        apis: &[],
        prefixes: &["PROV_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["Algid", "AlgId"],
        apis: &[],
        prefixes: &["CALG_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["csidl", "nFolder"],
        apis: &[],
        prefixes: &["CSIDL_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwMilliseconds"],
        apis: &[],
        prefixes: &[],
        names: &["INFINITE"],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwStartType"],
        apis: &[],
        prefixes: &[],
        names: &[
            "SERVICE_BOOT_START",
            "SERVICE_SYSTEM_START",
            "SERVICE_AUTO_START",
            "SERVICE_DEMAND_START",
            "SERVICE_DISABLED",
        ],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwServiceType"],
        apis: &[],
        prefixes: &[],
        names: &[
            "SERVICE_KERNEL_DRIVER",
            "SERVICE_FILE_SYSTEM_DRIVER",
            "SERVICE_WIN32_OWN_PROCESS",
            "SERVICE_WIN32_SHARE_PROCESS",
            "SERVICE_INTERACTIVE_PROCESS",
        ],
        kind: Kind::Flags,
    },
    Rule {
        params: &["dwAccessType"],
        apis: &["InternetOpen"],
        prefixes: &["INTERNET_OPEN_TYPE_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwAccessType"],
        apis: &["WinHttpOpen"],
        prefixes: &["WINHTTP_ACCESS_TYPE_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwService"],
        apis: &["InternetConnect"],
        prefixes: &["INTERNET_SERVICE_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["dwFlags"],
        apis: &["InternetOpenUrl", "InternetConnect", "HttpOpenRequest"],
        prefixes: &["INTERNET_FLAG_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["uFlags"],
        apis: &["ExitWindowsEx"],
        prefixes: &["EWX_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["uMode"],
        apis: &["SetErrorMode"],
        prefixes: &["SEM_"],
        names: &[],
        kind: Kind::Flags,
    },
    Rule {
        params: &["nIndex"],
        apis: &["SetWindowLong", "GetWindowLong"],
        prefixes: &["GWL_", "GWLP_"],
        names: &[],
        kind: Kind::Enum,
    },
    Rule {
        params: &["CodePage"],
        apis: &[],
        prefixes: &[],
        names: &[
            "CP_ACP",
            "CP_OEMCP",
            "CP_MACCP",
            "CP_THREAD_ACP",
            "CP_SYMBOL",
            "CP_UTF7",
            "CP_UTF8",
        ],
        kind: Kind::Enum,
    },
];

/// Names that describe a field or a limit rather than a value.
const EXCLUDED: &[&str] = &[
    "_MASK",
    "VALID",
    "RESERVED",
    "EXTENDED_PARAMETER",
    "_BITS",
    "_SHIFT",
    "_MAX",
    "_MIN",
    "_COUNT",
    "_INVALID",
];

fn rule(api: &str, param: &str) -> Option<usize> {
    let api = api.rsplit('!').next().unwrap_or(api);
    RULES.iter().position(|rule| {
        rule.params
            .iter()
            .any(|name| name.eq_ignore_ascii_case(param))
            && (rule.apis.is_empty() || rule.apis.iter().any(|prefix| api.starts_with(prefix)))
    })
}

/// The constants each rule draws from, resolved against one header index.
#[derive(Default)]
pub(super) struct Candidates {
    per_rule: Vec<Vec<(u64, String)>>,
}

impl Candidates {
    pub fn build(constants: &HashMap<String, u64>) -> Self {
        let per_rule = RULES
            .iter()
            .map(|rule| {
                let mut values: Vec<(u64, String)> = constants
                    .iter()
                    .filter(|(name, _)| {
                        rule.names.contains(&name.as_str())
                            || (rule.prefixes.iter().any(|prefix| name.starts_with(prefix))
                                && !EXCLUDED.iter().any(|part| name.contains(part)))
                    })
                    .map(|(name, value)| (*value, name.clone()))
                    .collect();
                // Deterministic choice among equal values: the shorter, then first name.
                values.sort_by(|a, b| {
                    a.0.cmp(&b.0)
                        .then(a.1.len().cmp(&b.1.len()))
                        .then(a.1.cmp(&b.1))
                });
                values
            })
            .collect();
        Self { per_rule }
    }

    pub fn decode(&self, api: &str, param: &str, value: u64) -> Option<String> {
        let index = rule(api, param)?;
        let candidates = self.per_rule.get(index)?;
        match RULES[index].kind {
            Kind::Enum => exact(candidates, value, u64::MAX),
            Kind::Enum32 => exact(candidates, value, 0xFFFF_FFFF),
            Kind::Flags => exact(candidates, value, u64::MAX).or_else(|| flags(candidates, value)),
            Kind::Ioctl => Some(ioctl(candidates, value)),
        }
    }
}

fn exact(candidates: &[(u64, String)], value: u64, mask: u64) -> Option<String> {
    candidates
        .iter()
        .find(|(candidate, _)| candidate & mask == value & mask)
        .map(|(_, name)| name.clone())
}

/// The value as a union of single and composite flags, widest first, with any bits
/// no flag covers left as a number.
fn flags(candidates: &[(u64, String)], value: u64) -> Option<String> {
    let mut ordered: Vec<&(u64, String)> = candidates
        .iter()
        .filter(|(candidate, _)| *candidate != 0)
        .collect();
    ordered.sort_by(|a, b| b.0.count_ones().cmp(&a.0.count_ones()).then(b.0.cmp(&a.0)));
    let mut remaining = value;
    let mut taken: Vec<&(u64, String)> = Vec::new();
    for candidate in ordered {
        if remaining & candidate.0 == candidate.0 && remaining != 0 {
            remaining &= !candidate.0;
            taken.push(candidate);
        }
    }
    if taken.is_empty() {
        return None;
    }
    taken.sort_by_key(|(value, _)| *value);
    let mut parts: Vec<String> = taken.iter().map(|(_, name)| name.clone()).collect();
    if remaining != 0 {
        parts.push(format!("0x{remaining:X}"));
    }
    Some(parts.join("|"))
}

fn ioctl(devices: &[(u64, String)], code: u64) -> String {
    let code = code & 0xFFFF_FFFF;
    let device = code >> 16;
    let access = (code >> 14) & 3;
    let function = (code >> 2) & 0xFFF;
    let method = [
        "METHOD_BUFFERED",
        "METHOD_IN_DIRECT",
        "METHOD_OUT_DIRECT",
        "METHOD_NEITHER",
    ][(code & 3) as usize];
    let access = [
        "FILE_ANY_ACCESS",
        "FILE_READ_ACCESS",
        "FILE_WRITE_ACCESS",
        "FILE_READ_ACCESS|FILE_WRITE_ACCESS",
    ][access as usize];
    let device = devices
        .iter()
        .find(|(value, _)| *value == device)
        .map_or_else(|| format!("0x{device:X}"), |(_, name)| name.clone());
    format!("CTL_CODE({device}, 0x{function:X}, {method}, {access})")
}

/// The constant families a parameter takes, for display.
pub(super) fn describe(api: &str, param: &str) -> Vec<&'static str> {
    let Some(index) = rule(api, param) else {
        return Vec::new();
    };
    let rule = &RULES[index];
    if rule.kind == Kind::Ioctl {
        return vec!["CTL_CODE"];
    }
    let mut out: Vec<&'static str> = rule.prefixes.to_vec();
    out.extend(
        rule.names
            .iter()
            .take(if rule.prefixes.is_empty() { 8 } else { 0 }),
    );
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates(pairs: &[(&str, u64)]) -> Candidates {
        Candidates::build(
            &pairs
                .iter()
                .map(|(name, value)| (name.to_string(), *value))
                .collect(),
        )
    }

    #[test]
    fn bcrypt_rng_flags_are_api_scoped_and_preserve_unknown_bits() {
        let c = candidates(&[
            ("BCRYPT_RNG_USE_ENTROPY_IN_BUFFER", 1),
            ("BCRYPT_USE_SYSTEM_PREFERRED_RNG", 2),
            ("BCRYPT_ALG_HANDLE_HMAC_FLAG", 8),
        ]);
        assert_eq!(
            c.decode("bcrypt!BCryptGenRandom", "dwFlags", 2).as_deref(),
            Some("BCRYPT_USE_SYSTEM_PREFERRED_RNG")
        );
        assert_eq!(
            c.decode("BCryptGenRandom", "dwFlags", 3).as_deref(),
            Some("BCRYPT_RNG_USE_ENTROPY_IN_BUFFER|BCRYPT_USE_SYSTEM_PREFERRED_RNG")
        );
        assert_eq!(
            c.decode("BCryptGenRandom", "dwFlags", 10).as_deref(),
            Some("BCRYPT_USE_SYSTEM_PREFERRED_RNG|0x8")
        );
        assert_eq!(c.decode("BCryptGenRandom", "dwFlags", 0), None);
        assert_eq!(c.decode("BCryptOpenAlgorithmProvider", "dwFlags", 2), None);
        assert_eq!(c.decode("BCryptGenRandom", "cbBuffer", 2), None);
    }

    #[test]
    fn flags_decompose_and_enums_match_exactly() {
        let c = candidates(&[
            ("PROCESS_VM_READ", 0x10),
            ("PROCESS_VM_WRITE", 0x20),
            ("PROCESS_VM_OPERATION", 0x8),
            ("PROCESS_ALL_ACCESS", 0x1F_FFFF),
            ("SYNCHRONIZE", 0x10_0000),
            ("CREATE_ALWAYS", 2),
            ("OPEN_EXISTING", 3),
            ("HKEY_LOCAL_MACHINE", 0x8000_0002),
            ("FILE_DEVICE_UNKNOWN", 0x22),
            ("TIMER_ALL_ACCESS", 0x1F0003),
            ("FILE_READ_DATA", 1),
            ("CREATE_WAITABLE_TIMER_MANUAL_RESET", 1),
        ]);
        assert_eq!(
            c.decode("CreateWaitableTimerExW", "dwDesiredAccess", 0x1F0003)
                .as_deref(),
            Some("TIMER_ALL_ACCESS")
        );
        assert_eq!(
            c.decode("CreateWaitableTimerExW", "dwFlags", 1).as_deref(),
            Some("CREATE_WAITABLE_TIMER_MANUAL_RESET")
        );
        assert_eq!(
            c.decode("KERNEL32!OpenProcess", "dwDesiredAccess", 0x38)
                .as_deref(),
            Some("PROCESS_VM_OPERATION|PROCESS_VM_READ|PROCESS_VM_WRITE")
        );
        assert_eq!(
            c.decode("OpenProcess", "dwDesiredAccess", 0x1F_FFFF)
                .as_deref(),
            Some("PROCESS_ALL_ACCESS")
        );
        assert_eq!(
            c.decode("OpenProcess", "dwDesiredAccess", 0x10_0018)
                .as_deref(),
            Some("PROCESS_VM_OPERATION|PROCESS_VM_READ|SYNCHRONIZE")
        );
        assert_eq!(
            c.decode("CreateFileW", "dwCreationDisposition", 3)
                .as_deref(),
            Some("OPEN_EXISTING")
        );
        assert_eq!(c.decode("CreateFileW", "dwCreationDisposition", 9), None);
        assert_eq!(
            c.decode("RegOpenKeyExW", "hKey", 0xFFFF_FFFF_8000_0002)
                .as_deref(),
            Some("HKEY_LOCAL_MACHINE")
        );
        assert_eq!(
            c.decode("DeviceIoControl", "dwIoControlCode", 0x0022_2004)
                .as_deref(),
            Some("CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)")
        );
        assert_eq!(c.decode("Sleep", "dwSize", 4), None);
    }
}
