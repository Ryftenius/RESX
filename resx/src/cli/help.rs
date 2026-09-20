use crate::core::config::Cli;
use clap::CommandFactory;
use std::collections::HashMap;
use std::sync::OnceLock;

const SECTIONS: &[&str] = &[
    "inspect", "code", "evidence", "recovery", "compare", "options",
];
const COMMANDS: &[&str] = &[
    "dump",
    "xrefs",
    "cfg",
    "reconstruct-cfg",
    "intelli",
    "behavior",
    "contracts",
    "ipc",
    "network",
    "crypto",
    "strings",
    "payload",
    "driver",
    "ioctl",
    "entropy",
    "patch",
    "types",
    "peinfo",
    "sections",
    "eat",
    "iat",
    "syms",
    "pechk",
    "priority",
    "callers",
    "locate",
    "locate-sym",
    "scan",
    "diff",
    "index",
    "hunt",
    "yara",
    "find",
    "edrchk",
    "follow",
    "recomp",
    "symbols",
    "funcs",
    "refs",
    "update",
    "config",
];

/// Accept dumpbin-style `/command` and `/option:value` spellings for every clap long option.
/// Unknown slash-prefixed values are preserved so paths are never reinterpreted as flags.
pub fn normalize_cli_syntax(raw_args: &[String]) -> Vec<String> {
    if raw_args.is_empty() {
        return Vec::new();
    }
    let long_options = slash_long_options();
    let mut out = Vec::with_capacity(raw_args.len() + 2);
    out.push(raw_args[0].clone());
    for (index, argument) in raw_args.iter().enumerate().skip(1) {
        if argument == "/?" {
            out.push("--help".to_owned());
            continue;
        }
        let Some(body) = argument.strip_prefix('/') else {
            out.push(argument.clone());
            continue;
        };
        if index == 1 {
            if let Some(topic) = body
                .strip_prefix("help:")
                .or_else(|| body.strip_prefix("help="))
            {
                out.push("help".to_owned());
                if !topic.is_empty() {
                    out.push(topic.to_owned());
                }
                continue;
            }
        }
        if index == 1
            && (COMMANDS
                .iter()
                .chain(SECTIONS)
                .any(|name| body.eq_ignore_ascii_case(name))
                || body.eq_ignore_ascii_case("help")
                || body.eq_ignore_ascii_case("version"))
        {
            out.push(body.to_ascii_lowercase());
            continue;
        }
        let (key, value) = body
            .split_once(':')
            .or_else(|| body.split_once('='))
            .unwrap_or((body, ""));
        let canonical = match key.to_ascii_lowercase().as_str() {
            "v" => Some("verbose".to_owned()),
            "q" => Some("quiet".to_owned()),
            "o" => Some("out".to_owned()),
            "n" => Some("ordinal".to_owned()),
            "h" => Some("help".to_owned()),
            other => long_options.get(other).cloned(),
        };
        if let Some(canonical) = canonical {
            out.push(format!("--{canonical}"));
            if !value.is_empty() {
                out.push(value.to_owned());
            }
        } else {
            out.push(argument.clone());
        }
    }
    out
}

fn slash_long_options() -> &'static HashMap<String, String> {
    static OPTIONS: OnceLock<HashMap<String, String>> = OnceLock::new();
    OPTIONS.get_or_init(|| {
        // Clap's generated command graph is large in debug builds. Construct it on a bounded
        // worker stack so the Windows 1 MiB main-thread reserve cannot be exhausted at startup.
        std::thread::Builder::new()
            .name("resx-schema".to_owned())
            .stack_size(8 * 1024 * 1024)
            .spawn(build_slash_long_options)
            .ok()
            .and_then(|worker| worker.join().ok())
            .unwrap_or_default()
    })
}

fn build_slash_long_options() -> HashMap<String, String> {
    let mut long_options = HashMap::new();
    for argument in Cli::command().get_arguments() {
        if let Some(long) = argument.get_long() {
            let canonical = long.to_owned();
            long_options.insert(long.to_ascii_lowercase(), canonical.clone());
            for alias in argument.get_all_aliases().into_iter().flatten() {
                long_options.insert(alias.to_ascii_lowercase(), canonical.clone());
            }
            if let Some(short) = argument.get_short() {
                long_options.insert(short.to_ascii_lowercase().to_string(), canonical.clone());
            }
            for short in argument.get_all_short_aliases().into_iter().flatten() {
                long_options.insert(short.to_ascii_lowercase().to_string(), canonical.clone());
            }
        }
    }
    long_options
}

pub const APP_NAME: &str = "RESX";
pub const ORG_NAME: &str = "Ryftenius";

pub fn version_string() -> String {
    format!("{} v{}", APP_NAME, env!("CARGO_PKG_VERSION"))
}

pub fn product_banner() -> String {
    format!(
        "Ryftenius (R) RESX Reverse Engineering Suite Extended, Version {}\nCopyright (C) 2026 Ryftenius.\nSEE DEEPER",
        env!("CARGO_PKG_VERSION")
    )
}

pub fn is_help_request(raw_args: &[String]) -> bool {
    (raw_args.len() >= 2
        && (raw_args[1].eq_ignore_ascii_case("help")
            || (raw_args.len() == 2
                && SECTIONS
                    .iter()
                    .any(|name| raw_args[1].eq_ignore_ascii_case(name)))))
        || raw_args.iter().any(|arg| arg == "--help" || arg == "-h")
}

pub fn help_topic(raw_args: &[String]) -> Option<&str> {
    if raw_args.len() >= 3 && raw_args[1].eq_ignore_ascii_case("help") {
        return raw_args.get(2).map(String::as_str);
    }
    if raw_args.len() == 2
        && SECTIONS
            .iter()
            .any(|name| raw_args[1].eq_ignore_ascii_case(name))
    {
        return Some(raw_args[1].as_str());
    }
    if raw_args.len() >= 3 && raw_args.iter().any(|arg| arg == "--help" || arg == "-h") {
        let candidate = raw_args[1].as_str();
        if !candidate.starts_with('-') {
            return Some(candidate);
        }
    }
    None
}

pub fn is_version_request(raw_args: &[String]) -> bool {
    raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("version")
        || raw_args.iter().any(|arg| arg == "--version" || arg == "-V")
}

pub fn print_usage() {
    println!(
        r#"{}

Usage: resx <command> [arguments] [options]

SECTION     PURPOSE          COMMANDS
  inspect   PE and symbols   peinfo sections eat iat syms types pechk
  code      Code and flow    dump xrefs cfg reconstruct-cfg callers
  evidence  Static evidence  contracts driver ioctl ipc network crypto strings
  recovery  Decode/edit      payload patch
  compare   Compare/find     diff index hunt scan locate locate-sym
  options   Shared flags     output, symbols, verbosity and saved preferences

EXAMPLES
  resx peinfo .\driver.sys
  resx ioctl .\J58.dll --json
  resx dump kernel32.dll CreateFileW --recomp
  resx /dump kernel32.dll entry /bytes:96
  resx config --command-style slash --entry-macro ep

DETAILS
  resx code             Open the code and flow section
  resx help ioctl       Usage, examples and flags for one command
  resx ioctl --help     Same command help
  resx help options     Shared options and saved preferences"#,
        product_banner()
    );
}

pub fn example_topic<'a>(raw_args: &'a [String], cli: &'a Cli) -> &'a str {
    const KNOWN: &[&str] = &[
        "dump",
        "xrefs",
        "cfg",
        "reconstruct-cfg",
        "intelli",
        "behavior",
        "contracts",
        "ipc",
        "network",
        "crypto",
        "strings",
        "payload",
        "driver",
        "ioctl",
        "entropy",
        "patch",
        "types",
        "peinfo",
        "sections",
        "eat",
        "iat",
        "syms",
        "pechk",
        "priority",
        "callers",
        "locate",
        "locate-sym",
        "scan",
        "diff",
        "index",
        "hunt",
        "yara",
        "find",
        "edrchk",
        "follow",
        "recomp",
        "symbols",
        "funcs",
        "refs",
        "update",
        "config",
    ];
    if raw_args.len() >= 2 {
        let first = raw_args[1].as_str();
        if KNOWN.iter().any(|cmd| first.eq_ignore_ascii_case(cmd)) {
            return first;
        }
    }
    cli.dll.as_deref().unwrap_or("general")
}

pub fn preprocess_args(raw_args: &[String]) -> Vec<String> {
    if raw_args.is_empty() {
        return Vec::new();
    }
    if raw_args.len() == 1 {
        return raw_args.to_vec();
    }

    let cmd = raw_args[1].to_ascii_lowercase();
    if raw_args.iter().any(|arg| arg == "--help" || arg == "-h") {
        return raw_args.to_vec();
    }
    if raw_args.iter().any(|arg| arg == "--version" || arg == "-V") {
        return raw_args.to_vec();
    }
    if raw_args.iter().any(|arg| arg == "--example") {
        return raw_args.to_vec();
    }

    let mut rewritten = vec![raw_args[0].clone()];
    match cmd.as_str() {
        "dump" | "driver" | "ioctl" | "contracts" | "ipc" | "network" | "crypto" | "payload"
        | "strings" => rewritten.extend(raw_args.iter().skip(2).cloned()),
        "config" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--resx-config".to_owned());
        }
        "xrefs" | "refs" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--xrefs".to_string());
        }
        "types" => rewritten.extend(raw_args.iter().skip(2).cloned()),
        "cfg" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--cfg".to_string());
            rewritten.push("text".to_string());
        }
        "reconstruct-cfg" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--reconstruct-cfg".to_string());
        }
        "intelli" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--intelli".to_string());
        }
        "behavior" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--behavior".to_string());
        }
        "entropy" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--entropy".to_string());
        }
        "patch" => return rewrite_patch_command(raw_args),
        "peinfo" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--peinfo".to_string());
        }
        "sections" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--sections".to_string());
        }
        "eat" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--show-eat".to_string());
        }
        "iat" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--show-iat".to_string());
        }
        "syms" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--show-syms".to_string());
        }
        "pechk" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--pechk".to_string());
        }
        "priority" => {
            rewritten.push("--priority".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        "callers" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--follow-callers".to_string());
        }
        "locate" => {
            rewritten.push("--locate".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        "locate-sym" => {
            rewritten.push("--locate-sym".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        "scan" => {
            rewritten.push("--resx-scan".to_string());
            if let Some(root) = raw_args.get(2) {
                rewritten.push("--scan-root".to_string());
                rewritten.push(root.clone());
                rewritten.extend(raw_args.iter().skip(3).cloned());
            } else {
                rewritten.extend(raw_args.iter().skip(2).cloned());
            }
        }
        "diff" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--resx-diff".to_string());
        }
        "index" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--resx-index".to_string());
        }
        "hunt" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--resx-hunt".to_string());
        }
        "yara" => {
            if raw_args.len() >= 4 {
                rewritten.push(raw_args[2].clone());
                rewritten.push("--yara".to_string());
                rewritten.push(raw_args[3].clone());
                rewritten.extend(raw_args.iter().skip(4).cloned());
            } else {
                rewritten.extend(raw_args.iter().skip(2).cloned());
            }
        }
        "find" => {
            if raw_args.len() >= 4 {
                rewritten.push(raw_args[2].clone());
                rewritten.push("--resx-find".to_string());
                rewritten.push("--find".to_string());
                rewritten.push(raw_args[3].clone());
                rewritten.extend(raw_args.iter().skip(4).cloned());
            } else {
                rewritten.extend(raw_args.iter().skip(2).cloned());
                rewritten.push("--resx-find".to_string());
            }
        }
        "update" => {
            rewritten.push("--update".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        _ => return raw_args.to_vec(),
    }
    rewritten
}

fn rewrite_patch_command(raw_args: &[String]) -> Vec<String> {
    let mut rewritten = vec![raw_args[0].clone()];
    let Some(image) = raw_args.get(2) else {
        rewritten.push("--patch".to_string());
        return rewritten;
    };
    if image.starts_with('-') {
        rewritten.extend(raw_args.iter().skip(2).cloned());
        rewritten.push("--patch".to_string());
        return rewritten;
    }

    rewritten.push(image.clone());
    let mut idx = 3;
    if raw_args.get(idx).is_some_and(|arg| !arg.starts_with('-')) {
        rewritten.push("--at".to_string());
        rewritten.push(raw_args[idx].clone());
        idx += 1;
    }
    if raw_args.get(idx).is_some_and(|arg| !arg.starts_with('-')) {
        let mut bytes = Vec::new();
        while raw_args.get(idx).is_some_and(|arg| !arg.starts_with('-')) {
            bytes.push(raw_args[idx].clone());
            idx += 1;
        }
        rewritten.push("--patch-bytes".to_string());
        rewritten.push(bytes.join(" "));
    }

    rewritten.extend(raw_args.iter().skip(idx).cloned());
    rewritten.push("--patch".to_string());
    rewritten
}

mod examples;
pub use examples::print_examples;

fn all_help() -> String {
    // Building and rendering the generated clap graph exceeds the Windows main
    // thread's 1 MiB stack in debug builds. Keep help generation deterministic,
    // but render it on the same bounded worker-stack model used by slash syntax.
    let flags = std::thread::Builder::new()
        .name("resx-help-schema".to_owned())
        .stack_size(8 * 1024 * 1024)
        .spawn(|| {
            let mut parser = Cli::command();
            parser.render_long_help().to_string()
        })
        .ok()
        .and_then(|worker| worker.join().ok())
        .unwrap_or_else(|| "  <unable to render generated operator arguments>".to_owned());
    format!(
        r#"{}

COMPLETE COMMAND REFERENCE

Inspect
  peinfo  sections  pechk  eat  iat  syms  types

Code and flow
  dump  xrefs  refs  cfg  reconstruct-cfg  callers  follow  recomp  funcs
  intelli  behavior

Evidence and search
  contracts  driver  ioctl  ipc  network  crypto  strings  entropy
  yara  find  scan  locate  locate-sym  edrchk

Recovery and comparison
  payload  patch
  diff  index  hunt

Configuration
  priority  symbols  config  update

COMMAND HELP
  resx help <command>               Detailed usage and examples
  resx <command> --help             Same command help
  resx help all                     This complete reference

ALL OPERATOR ARGUMENTS AND FLAGS
{}

INTERNAL COMMAND-ROUTING FLAGS
  --patch  --resx-find  --resx-scan  --resx-diff  --resx-index  --resx-hunt
  --resx-config

These internal switches are shown for completeness. Use their command forms above.
Slash syntax is accepted for every long operator flag, for example /verbose and /out:file."#,
        product_banner(),
        flags.trim()
    )
}

fn section_help(topic: &str) -> Option<&'static str> {
    Some(match topic {
        "contracts" => {
            r"CONTRACTS | Bounded x64 API arguments and producer relationships
Usage: resx contracts <image> [--json] [-v]

Examples:
  resx contracts .\J58.dll --json
  resx contracts .\sample.exe -v --out contracts.json

Includes IPC, network, crypto and IOCTL/NDIS contracts. Unknown values remain
unknown; reports include instruction/call budgets. No target execution."
        }
        "ipc" => {
            r"IPC | Named pipes, ALPC, RPC, COM and shared mappings
Usage: resx ipc <image> [--json] [-v]

Examples:
  resx ipc .\service.exe --json
  resx ipc .\sample.exe -v --out ipc.json

Static names, arguments and producer references. Live peers and shared kernel
objects require runtime evidence."
        }
        "network" => {
            r"NETWORK | Endpoint candidates and HTTP/socket configuration
Usage: resx network <image> [--json] [-v]

Examples:
  resx network .\sample.exe --json
  resx network .\sample.exe -v --out endpoints.json

Recovers available host, port, method, path and sockaddr fields. No endpoint is
contacted. Endpoint presence does not establish C2 activity."
        }
        "crypto" => {
            r"CRYPTO | Imported algorithm, provider and mode configuration
Usage: resx crypto <image> [--json] [-v]

Examples:
  resx crypto .\sample.exe --json
  resx crypto .\J58.dll -v --out crypto.json

Static CNG/CAPI contracts; custom/inlined algorithms may remain unknown.
For decoding with a supplied key: resx help payload."
        }
        "strings" => {
            r"STRINGS | ASCII and UTF-16LE candidates with exact offsets
Usage: resx strings <image> [--json] [-v]

Examples:
  resx strings .\J58.dll --json
  resx strings .\sample.exe --strings-encoding ascii --strings-min-len 8
  resx strings .\sample.exe --strings-interesting --strings-limit 200
  resx strings .\sample.exe --strings-match TARGET --strings-tag success-marker

Limits: 16 MiB scanned, 8,192 candidates, 4,096 code units per candidate.
UTF-16 candidates use a text-quality filter by default; --strings-raw-wide keeps
permissive binary coincidences. --strings-encoding ascii|utf16le|both,
--strings-min-len, --strings-limit, --strings-match, and --strings-tag bound output.
TARGET_OK-like values are labeled success-marker; brace-form tokens are separate
flag-candidate findings. Text presence does not prove behavior."
        }
        "driver" => {
            r"DRIVER | Static x64 dispatch and driver capability evidence
Usage: resx driver <image> [--json] [-v]

Examples:
  resx driver .\hypervisor.sys --verbose
  resx driver C:\Windows\System32\drivers\vmbus.sys --json --out vmbus.json

driver includes conditional MajorFunction assignments, imported-API capability
groups, AMD SVM / Intel VMX evidence, and correlated NPT/EPT SLAT hook machinery
with instruction RVAs. No driver is loaded."
        }
        "ioctl" => {
            r"IOCTL | Static x64 request, dispatch, CTL_CODE and NDIS/OID evidence
Usage: resx ioctl <image> [--json] [-v]

Examples:
  resx ioctl .\J58.dll --verbose --out ioctl.txt
  resx ioctl .\driver.sys --json

Reports bounded request arguments, producer relationships, CTL_CODE candidates,
dispatch assignments and known NDIS/OID layouts. No driver is loaded and no IOCTL
is sent."
        }
        "inspect" => {
            r"INSPECT | PE headers, exports, imports and symbols
  peinfo / sections / pechk    Metadata, section layout, anomalies
  eat / iat                   Exports and imports
  syms / types                Symbols and PDB types

Examples:
  resx peinfo .\driver.sys
  resx eat .\J58.dll --json
  resx types .\driver.sys DEVICE_OBJECT --pdb .\driver.pdb"
        }
        "code" => {
            r"CODE | Disassembly and control flow
  dump                        Disassemble by name, RVA or ordinal
  xrefs / callers             Incoming references and reverse callers
  cfg / reconstruct-cfg       Function graph and image startup flow

Examples:
  resx dump kernel32.dll CreateFileW --recomp
  resx dump .\sample.exe --at 0x1200 --bytes
  resx cfg .\J58.dll --ordinal 1
  resx callers ntdll.dll NtOpenProcess --depth 2"
        }
        "evidence" => {
            r"EVIDENCE | Static findings, with provenance and limits
  contracts                   Combined API arguments and producer references
  driver / ioctl              Driver dispatch, IOCTL and NDIS/OID evidence
  ipc / network / crypto      Channel, endpoint and crypto configuration
  strings / intelli / behavior Text extraction and heuristic triage
  entropy / yara / find       Byte statistics, YARA, and instruction patterns

Examples:
  resx driver .\driver.sys --json
  resx ioctl .\J58.dll --verbose
  resx network .\sample.exe --json --out endpoints.json
  resx yara .\sample.exe .\rules.yar

Static findings do not prove execution, live peers or C2 activity."
        }
        "recovery" => {
            r#"RECOVERY | Explicit bounded decoding and editing
  payload                     Decode bytes with operator-supplied parameters
  patch                       Apply a checked byte patch to a new image

Examples:
  resx payload .\blob.bin --payload-dir .\decoded --codec zlib --json
  resx patch .\sample.exe rva:0x1200 "90 90" --dry-run

Payload decoding is bounded and records hashes for each transform layer. Patching
requires explicit bytes and can verify expected original bytes before writing."#
        }
        "compare" => {
            r"COMPARE | Structural similarity and discovery
  diff                        Compare images and function structure
  index / hunt                Build and search a fingerprint corpus
  scan                        Inventory images under a directory
  locate / locate-sym         Find exports and symbols in configured images

Examples:
  resx diff .\old.dll .\new.dll --json
  resx index .\samples --db .\samples.resxdb --no-pdb
  resx hunt .\unknown.dll --db .\samples.resxdb
  resx scan .\drivers --jsonl --max-files 100"
        }
        "options" => {
            r"OPTIONS | Shared output, symbol and saved preference flags
  --json                      Structured output
  --out <file>                Save output; evidence commands require a new file
  --verbose, -v               Coverage and diagnostics on stderr
  --diagnostic                DEBUG developer trace on stderr; implies --verbose
  --diagnostic-trace          Include bounded TRACE events; implies --diagnostic
  --disasm-context <4..32>    Instructions per verbose evidence window (default 12)
  --debug-report <report.zip> Sanitized reproducibility bundle
  --debug-report-include-target  Explicitly include target bytes (64 MiB cap)
  --analysis-budget <n|unlimited>  Alias for --max-insns
  --cfg-budget <n|unlimited>  Alias for --max-total
  --time                      Print command completion time on stderr
  --quiet, -q                 Suppress optional diagnostics; overrides verbose
  --no-color                  Disable terminal colors
  --no-pdb                    Disable symbol loading
  --pdb <file>                Use an explicit local PDB
  --path <dir>                Add an image lookup directory
  --max-subcalls <n>          Cap calls rendered per function
  --driver-flow               Add driver dispatch contracts to CFG output

Slash form:
  /dump, /json, /out:file and every other long option are accepted.
  resx config --command-style slash saves the preferred display style.

Function macros:
  entry                       Declared PE AddressOfEntryPoint
  rentry                      RESX startup/main candidate, falling back to entry
  resx config --entry-macro ep --rentry-macro realep

Examples:
  resx contracts .\J58.dll --json -v --out contracts.json
  resx peinfo .\driver.sys --json -q

Command-specific flags: resx help dump, resx help payload, etc."
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::{
        all_help, help_topic, is_help_request, normalize_cli_syntax, preprocess_args, section_help,
    };

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn help_all_contains_commands_subcommands_and_operator_flags() {
        let help = all_help();
        for required in [
            "COMPLETE COMMAND REFERENCE",
            "reconstruct-cfg",
            "--diagnostic-trace",
            "--max-insns",
            "--yara",
            "INTERNAL COMMAND-ROUTING FLAGS",
        ] {
            assert!(help.contains(required), "missing {required}");
        }
    }

    #[test]
    fn slash_commands_and_options_normalize_without_touching_paths() {
        let normalized = normalize_cli_syntax(&args(&[
            "resx",
            "/dump",
            "C:\\x\\a.dll",
            "entry",
            "/max-insns:25",
            "/limit:12",
            "/refs",
            "/json",
        ]));
        assert_eq!(
            normalized,
            args(&[
                "resx",
                "dump",
                "C:\\x\\a.dll",
                "entry",
                "--max-insns",
                "25",
                "--max-insns",
                "12",
                "--xrefs",
                "--json",
            ])
        );
        assert_eq!(
            normalize_cli_syntax(&args(&["resx", "/not-a-command/path"])),
            args(&["resx", "/not-a-command/path"])
        );
    }

    #[test]
    fn bare_sections_open_help() {
        let values = args(&["resx", "code"]);
        assert!(is_help_request(&values));
        assert_eq!(help_topic(&values), Some("code"));
    }

    #[test]
    fn exact_command_help_is_distinct_and_documents_its_flags() {
        let driver = section_help("driver").unwrap();
        let ioctl = section_help("ioctl").unwrap();
        let strings = section_help("strings").unwrap();
        assert_ne!(driver, ioctl);
        assert!(driver.starts_with("DRIVER |"));
        assert!(ioctl.starts_with("IOCTL |"));
        assert!(strings.contains("--strings-encoding"));
        assert!(strings.contains("--strings-raw-wide"));
    }

    #[test]
    fn yara_shorthand_preserves_one_image_and_routes_rules_as_options() {
        let args = ["resx", "yara", "sample.exe", "rules.yar", "--json"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(
            preprocess_args(&args),
            ["resx", "sample.exe", "--yara", "rules.yar", "--json"]
        );
    }
}
