use super::*;

/// C/C++ runtime import providers, matched against the normalized image base.
const CRT_DLL_PREFIXES: &[&str] = &[
    "ucrtbase",
    "msvcr",
    "msvcp",
    "vcruntime",
    "api-ms-win-crt-",
    "concrt",
    "vccorlib",
    "vcomp",
];

/// Statically linked MSVC runtime helpers. Only symbolized names can match; anonymous
/// sub_XXXXXXXX helpers are indistinguishable from user code without a PDB.
const CRT_INTERNAL_PREFIXES: &[&str] = &[
    "__scrt_",
    "__security_",
    "__report_",
    "__raise_securityfailure",
    "__GSHandlerCheck",
    "_guard_",
    "__guard_",
    "__chkstk",
    "_RTC_",
    "__CxxFrameHandler",
    "__C_specific_handler",
    "__std_",
    "_CxxThrowException",
    "__acrt_",
    "__vcrt_",
    "_initterm",
    "__isa_",
    "__dyn_tls_",
    "_invalid_parameter",
    "__local_stdio_",
    "_purecall",
    "std::_",
    "operator new",
    "operator delete",
];

const CRT_INTERNAL_NAMES: &[&str] = &[
    "memset",
    "memcpy",
    "memmove",
    "memcmp",
    "strlen",
    "wcslen",
    "atexit",
    "_onexit",
    "printf",
    "wprintf",
    "fprintf",
    "fwprintf",
    "sprintf_s",
    "swprintf_s",
    "puts",
    "_vfprintf_l",
    "_vfwprintf_l",
    "_vsprintf_l",
    "_vsnprintf_l",
    "_vswprintf_l",
    "_vsprintf_s_l",
    "_vswprintf_s_l",
];

#[derive(Debug, Clone, PartialEq, Eq)]
enum FilterTerm {
    Imports,
    WinApi,
    Crt,
    Syscall,
    Internal,
    /// Calls through dynamically resolved pointers, and the resolver calls themselves.
    Dynamic,
    /// Normalized import provider base name; a trailing `*` makes it a prefix match.
    Dll(String),
}

impl FilterTerm {
    fn parse(term: &str) -> Self {
        match term.to_ascii_lowercase().as_str() {
            "iat" | "import" | "imports" => Self::Imports,
            "winapi" | "api" => Self::WinApi,
            "crt" | "runtime" => Self::Crt,
            "syscall" | "syscalls" | "nt" => Self::Syscall,
            "internal" | "local" => Self::Internal,
            "dynamic" | "resolved" => Self::Dynamic,
            _ => Self::Dll(normalize_image_base(term)),
        }
    }

    fn matches(&self, call: &ApiCall) -> bool {
        match self {
            Self::Dynamic => call.dynamic.is_some() || call.resolves.is_some(),
            Self::Imports => call.is_import,
            Self::WinApi => call.is_import && !is_crt_dll(&call.dll),
            Self::Crt => {
                if call.is_import {
                    is_crt_dll(&call.dll)
                } else {
                    is_crt_internal(&call.label)
                }
            }
            Self::Syscall => call.kind == "syscall" || is_nt_api(&call.label),
            Self::Internal => !call.is_import,
            Self::Dll(pattern) => {
                if !call.is_import || call.dll.is_empty() {
                    return false;
                }
                let base = normalize_image_base(&call.dll);
                match pattern.strip_suffix('*') {
                    Some(prefix) => base.starts_with(prefix),
                    None => base == *pattern,
                }
            }
        }
    }
}

/// Call-tree filter (`calls --only/--exclude`, `dump --calls-only/--calls-exclude`). Included terms are OR'd; a call matching any excluded
/// term is dropped along with its subtree. Non-matching internal calls are kept only
/// as the path to a matching descendant.
#[derive(Debug, Clone)]
pub(in crate::commands::dump) struct CallFilter {
    spec: String,
    include: Vec<FilterTerm>,
    exclude: Vec<FilterTerm>,
}

impl CallFilter {
    pub(in crate::commands::dump) fn parse(spec: &str) -> Option<Self> {
        let mut include = Vec::new();
        let mut exclude = Vec::new();
        for raw in spec.split(',') {
            let raw = raw.trim();
            if let Some(negated) = raw.strip_prefix('!').or_else(|| raw.strip_prefix('-')) {
                let negated = negated.trim();
                if !negated.is_empty() {
                    exclude.push(FilterTerm::parse(negated));
                }
            } else if !raw.is_empty() {
                include.push(FilterTerm::parse(raw));
            }
        }
        if include.is_empty() && exclude.is_empty() {
            return None;
        }
        // winapi means "the OS, not the runtime": don't walk through CRT helpers to
        // reach the OS calls they make, unless CRT was asked for explicitly.
        if include.contains(&FilterTerm::WinApi)
            && !include.contains(&FilterTerm::Crt)
            && !exclude.contains(&FilterTerm::Crt)
        {
            exclude.push(FilterTerm::Crt);
        }
        Some(Self {
            spec: spec.trim().to_owned(),
            include,
            exclude,
        })
    }

    pub(in crate::commands::dump) fn spec(&self) -> &str {
        &self.spec
    }

    pub(in crate::commands::dump) fn matches(&self, call: &ApiCall) -> bool {
        self.include.is_empty() || self.include.iter().any(|term| term.matches(call))
    }

    pub(in crate::commands::dump) fn excludes(&self, call: &ApiCall) -> bool {
        self.exclude.iter().any(|term| term.matches(call))
    }
}

fn is_crt_dll(dll: &str) -> bool {
    let base = normalize_image_base(dll);
    CRT_DLL_PREFIXES
        .iter()
        .any(|prefix| base.starts_with(prefix))
}

fn is_crt_internal(label: &str) -> bool {
    let name = label.rsplit('!').next().unwrap_or(label);
    CRT_INTERNAL_NAMES.contains(&name)
        || CRT_INTERNAL_PREFIXES
            .iter()
            .any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::CallFilter;
    use crate::analysis::disasm::ApiCall;

    fn call(dll: &str, label: &str, is_import: bool) -> ApiCall {
        ApiCall {
            rva: 0x1000,
            kind: "call".to_owned(),
            target_rva: if is_import { 0 } else { 0x2000 },
            label: label.to_owned(),
            dll: dll.to_owned(),
            is_import,
            is_indirect: false,
            indirect_method: None,
            switch_cases: Vec::new(),
            dynamic: None,
            resolves: None,
        }
    }

    #[test]
    fn empty_specs_disable_filtering() {
        assert!(CallFilter::parse("").is_none());
        assert!(CallFilter::parse(" , ,!").is_none());
    }

    #[test]
    fn winapi_keeps_os_imports_and_drops_runtime() {
        let filter = CallFilter::parse("winapi").unwrap();
        let virtual_alloc = call("KERNEL32.dll", "VirtualAlloc", true);
        let stdio = call(
            "api-ms-win-crt-stdio-l1-1-0.dll",
            "__stdio_common_vfprintf",
            true,
        );
        let cookie = call("", "__security_check_cookie", false);
        let worker = call("", "sub_140001230", false);

        assert!(filter.matches(&virtual_alloc) && !filter.excludes(&virtual_alloc));
        assert!(!filter.matches(&stdio) && filter.excludes(&stdio));
        assert!(filter.excludes(&cookie));
        assert!(!filter.matches(&worker) && !filter.excludes(&worker));
    }

    #[test]
    fn iat_keeps_every_import() {
        let filter = CallFilter::parse("IAT").unwrap();
        assert!(filter.matches(&call("vcruntime140.dll", "memset", true)));
        assert!(filter.matches(&call("bcrypt.dll", "BCryptHashData", true)));
        assert!(!filter.matches(&call("", "sub_140001230", false)));
    }

    #[test]
    fn dll_terms_match_with_or_without_extension_and_by_prefix() {
        let filter = CallFilter::parse("kernel32.dll, BCRYPT").unwrap();
        assert!(filter.matches(&call("KERNEL32.dll", "VirtualProtect", true)));
        assert!(filter.matches(&call("bcrypt.dll", "BCryptGenRandom", true)));
        assert!(!filter.matches(&call("ntdll.dll", "NtClose", true)));

        let apisets = CallFilter::parse("api-ms-win-core-*").unwrap();
        assert!(apisets.matches(&call(
            "api-ms-win-core-synch-l1-2-0.dll",
            "AcquireSRWLockExclusive",
            true
        )));
        assert!(!apisets.matches(&call("kernel32.dll", "Sleep", true)));
    }

    #[test]
    fn internal_and_exclusions_compose() {
        let internal = CallFilter::parse("internal").unwrap();
        assert!(internal.matches(&call("", "sub_140001230", false)));
        assert!(!internal.matches(&call("kernel32.dll", "Sleep", true)));

        let no_crt = CallFilter::parse("!crt").unwrap();
        assert!(no_crt.matches(&call("kernel32.dll", "Sleep", true)));
        assert!(no_crt.excludes(&call("ucrtbase.dll", "malloc", true)));
        assert!(no_crt.excludes(&call("", "memcpy", false)));
    }

    #[test]
    fn explicit_crt_overrides_winapi_runtime_exclusion() {
        let filter = CallFilter::parse("winapi,crt").unwrap();
        let malloc = call("ucrtbase.dll", "malloc", true);
        assert!(filter.matches(&malloc) && !filter.excludes(&malloc));
    }

    #[test]
    fn syscall_term_matches_native_stubs() {
        let filter = CallFilter::parse("syscall").unwrap();
        assert!(filter.matches(&call("ntdll.dll", "NtProtectVirtualMemory", true)));
        assert!(!filter.matches(&call("kernel32.dll", "VirtualProtect", true)));
    }
}
