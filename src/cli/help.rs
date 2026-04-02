use crate::core::config::Cli;

pub const APP_NAME: &str = "RESX";
pub const ORG_NAME: &str = "TITAN Softwork Solutions";

pub fn version_string() -> String {
    format!("{} v{}", APP_NAME, env!("CARGO_PKG_VERSION"))
}

pub fn is_help_request(raw_args: &[String]) -> bool {
    raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("help")
        || raw_args.iter().any(|arg| arg == "--help" || arg == "-h")
}

pub fn is_version_request(raw_args: &[String]) -> bool {
    raw_args.len() >= 2 && raw_args[1].eq_ignore_ascii_case("version")
        || raw_args.iter().any(|arg| arg == "--version" || arg == "-V")
}

pub fn print_usage() {
    eprintln!(
        r#"
{name} v{version}
by {org}

Windows binary recon CLI for exports, PDB-backed symbols, PE metadata, CFG recovery,
switch-map recovery, hook checks, caller tracing, Intelli triage, and rapid analysis.

USAGE
  resx dump <dll> <function> [options]
  resx dump <dll> --at <rva> [options]
  resx dump <dll> --ordinal <n> [options]
  resx cfg <dll> <function> [options]
  resx intelli <dll> [function] [options]

  resx peinfo <dll> [options]
  resx sections <dll> [options]
  resx eat <dll> [options]
  resx iat <dll> [options]
  resx syms <dll> [options]
  resx pechk <dll> [options]
  resx priority

  resx callers <dll> <function> [follow options]

  resx locate <funcname> [options]
  resx locate-sym <funcname> [options]
  resx explain <name> [--prefix|--api] [options]

  resx yara <dll> <rule.yar> [options]
  resx update [options]
  resx help

COMMANDS
  dump        Disassemble or reconstruct one target by name, RVA, or ordinal.
  cfg         Show a control-flow graph view for one target.
  intelli     Run heuristic triage over a target image or function.
  peinfo      Show PE metadata, version resources, signer info, and headers.
  sections    Show section layout, entropy, and protection expectations.
  eat         Dump the Export Address Table.
  iat         Dump the Import Address Table.
  syms        Dump resolved module and PDB symbols.
  pechk       Run PE header and layout anomaly checks.
  priority    Open the generated priority config used by locate and callers.
  callers     Reverse-trace callers across the priority set.
  locate      Show export-backed matches in the priority list.
  locate-sym  Show export/symbol-backed matches in the priority list.
  explain     Explain a prefix or API-style symbol name from the built-in glossary.
  yara        Scan a PE image with one or more YARA rules.
  update      Pull the latest version from the current git remote/branch.
  help        Show this help text.

DUMP / INTELLI OPTIONS
  --at <rva>                 dump by RVA instead of by function name
  --ordinal <n>              dump by export ordinal
  --recomp                   show C-like reconstruction
  --c-out <file>             write reconstruction to a C file
  --edrchk                   compare disk vs already-loaded in-memory prologue
  --unsafe-map-image         allow mapping an on-disk image into RESX for checks that need memory bytes
  --hookchk                  show static entry-hook / thunk indicators
  --intelli                  run heuristic triage
  --xrefs                    show call targets (deduplicated flat list)
  --strings                  show referenced string literals
  --funcs                    show API call map: every CALL/JMP with its resolved target
  --funcs-depth <N>          recursively trace internal subs N levels deep (implies --funcs)
  --cfg text                 show a colour-coded basic control-flow graph
  --explain                  explain the current dump target name with prefix/body glossary hints
  --prefix                   force explain-mode prefix interpretation
  --api                      force explain-mode API/symbol interpretation
  --follow-jmp               follow entry-point thunk (default: on)
  --no-follow-jmp            disable entry-point thunk following
  --rebase <addr>            compute rebased addresses

SYMBOL OPTIONS
  --pdb <file>               explicit PDB file
  --sym-path <path>          extra symbol path(s)
  --sym-server <url>         symbol server override
  --reload                   bypass in-memory/disk PDB cache and reload symbols
  --no-pdb                   disable symbol/PDB loading

FOLLOW OPTIONS
  --depth <n>                trace depth
  --max-callers <n>          cap callers per node
  --max-total <n>            cap total graph size
  --format tree|flat|list    output style
  --show-rva                 show owning function RVA
  --show-site                show call-site RVA(s)
  --filter-dll <text>        restrict caller DLL names
  --include-dir <dir>        add extra directories to scan
  --include-image <dll>      explicitly include extra images to scan
  --scan-exe                 include EXEs
  --include <glob>           include filter
  --exclude <glob>           exclude filter
  --max-dll-size <mb>        max image size
  --workers <n>              parallel workers

GLOBAL OPTIONS
  --arch <auto|x86|x64>
  --path <dir>
  --priority
  --no-system
  --no-cwd
  --no-path
  --bytes / --no-bytes
  --show-offsets
  --intel / --att
  --json
  --out <file>
  --color / --no-color
  --verbose / --quiet
  --version

EXAMPLES
  resx dump kernel32.dll CreateFileW --recomp --bytes
  resx intelli suspicious.dll
  resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
  resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
  resx callers ntdll.dll NtOpenProcess --depth 2 --format flat
  resx callers ntdll.dll NtOpenProcess --include-dir C:\Work\Drivers
  resx priority
  resx locate NtOpenProcess --include-dir C:\Work\Drivers
  resx locate-sym NtOpenProcess --include-image .\mydriver.sys
  resx explain Nt
  resx explain NtQuerySystemInformation
  resx dump ntoskrnl.exe NtQuerySystemInformation --explain
  resx syms .\J58.dll --pdb .\J58.pdb
  resx update
  resx intelli --example
"#,
        name = APP_NAME,
        version = env!("CARGO_PKG_VERSION"),
        org = ORG_NAME,
    );
}

pub fn example_topic<'a>(raw_args: &'a [String], cli: &'a Cli) -> &'a str {
    const KNOWN: &[&str] = &[
        "dump",
        "cfg",
        "intelli",
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
        "explain",
        "yara",
        "edrchk",
        "follow",
        "recomp",
        "symbols",
        "funcs",
        "update",
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
        "dump" => rewritten.extend(raw_args.iter().skip(2).cloned()),
        "cfg" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--cfg".to_string());
            rewritten.push("text".to_string());
        }
        "intelli" => {
            rewritten.extend(raw_args.iter().skip(2).cloned());
            rewritten.push("--intelli".to_string());
        }
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
        "explain" => {
            rewritten.push("--explain".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
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
        "update" => {
            rewritten.push("--update".to_string());
            rewritten.extend(raw_args.iter().skip(2).cloned());
        }
        _ => return raw_args.to_vec(),
    }
    rewritten
}

pub fn print_examples(topic: &str) {
    let topic = topic.to_ascii_lowercase();
    let body = match topic.as_str() {
        "update" => {
            r#"
UPDATE EXAMPLES
  resx update
  resx update --quiet

NOTES
  Runs git fetch/pull against the current repository remote and branch.
  Intended for source checkouts, not arbitrary installed binaries.
"#
        }
        "intelli" => {
            r#"
INTELLI EXAMPLES
  resx intelli suspicious.dll
  resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
  resx dump suspicious.dll --intelli
  resx dump suspicious.dll WinMain --intelli --json

NOTES
  `intelli` is a first-class command alias for dump-driven heuristic triage.
  It is useful when you want imports, strings, hooks, and signal tags quickly.
"#
        }
        "dump" | "recomp" | "c" => {
            r#"
DUMP EXAMPLES
  resx dump ntdll.dll NtOpenProcess
  resx dump ntdll.dll --at 0x161F40
  resx dump ntdll.dll --ordinal 451
  resx dump kernel32.dll CreateFileW --recomp --c-out CreateFileW.c
  resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
  resx dump ntoskrnl.exe KiSystemCall64 --cfg text --funcs --recomp
"#
        }
        "cfg" => {
            r#"
CFG EXAMPLES
  resx cfg ntdll.dll NtOpenProcess
  resx cfg ntoskrnl.exe NtQuerySystemInformation
  resx cfg ntdll.dll --at 0x161F40
"#
        }
        "follow" | "callers" => {
            r#"
CALLERS EXAMPLES
  resx callers kernel32.dll CreateFileW
  resx callers ntdll.dll NtOpenProcess --depth 2 --format flat
  resx callers ntdll.dll NtOpenProcess --include-dir C:\Work\Drivers
  resx callers user32.dll MessageBoxW --scan-exe --show-site --json
"#
        }
        "locate" | "locate-sym" => {
            r#"
LOCATE EXAMPLES
  resx locate OpenProcess
  resx locate NtOpenProcess
  resx locate NtOpenProcess --include-dir C:\Work\Drivers
  resx locate-sym RtlpHeapHandleError
  resx locate-sym NtOpenProcess --include-image .\mydriver.sys
"#
        }
        "explain" => {
            r#"
EXPLAIN EXAMPLES
  resx explain Nt
  resx explain Zw
  resx explain NtQuerySystemInformation
  resx explain NtQuerySystemInformation --api --json
  resx dump ntoskrnl.exe NtOpenProcess --explain

NOTES
  `explain` autodetects bare prefixes versus API-style symbols by default.
  Use `--prefix` or `--api` only when you need to force one interpretation.
"#
        }
        "priority" => {
            r#"
PRIORITY EXAMPLES
  resx priority

NOTES
  Opens the generated priority config JSON used by locate and callers.
  Edit priority directories, exact filenames, prefixes, and regexes there.
"#
        }
        "symbols" | "pdb" | "syms" => {
            r#"
SYMBOL EXAMPLES
  resx dump ntdll.dll RtlpHeapHandleError --verbose
  resx dump ntdll.dll RtlpHeapHandleError --sym-path "C:\Symbols"
  resx syms .\J58.dll --pdb .\J58.pdb
"#
        }
        _ => {
            r#"
GENERAL EXAMPLES
  resx dump ntdll.dll NtCreateFile
  resx intelli suspicious.dll
  resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
  resx callers ntdll.dll NtOpenProcess --depth 2
  resx locate-sym NtOpenProcess
  resx update
"#
        }
    };
    println!("{}", body.trim());
}
