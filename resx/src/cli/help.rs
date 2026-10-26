use crate::cli::args::{on_parser_stack, Cli};
use clap::CommandFactory;
use std::collections::HashMap;
use std::sync::OnceLock;

const SECTIONS: &[&str] = &[
    "inspect", "code", "evidence", "recovery", "compare", "options",
];

/// Help topics that are not commands themselves; each resolves to the command that
/// documents it.
const TOPIC_ALIASES: &[(&str, &str)] = &[
    ("recomp", "dump"),
    ("c", "dump"),
    ("edrchk", "dump"),
    ("hookchk", "dump"),
    ("funcs", "calls"),
    ("symbols", "syms"),
    ("pdb", "syms"),
];

/// The command grammar, flattened for the pre-parse steps that run on raw argv.
struct Grammar {
    /// Command names and aliases, lowercase, to the canonical command name.
    commands: HashMap<String, String>,
    /// Per command: long names, aliases and short names, lowercase, to the canonical
    /// long name, including the global options.
    options: HashMap<String, HashMap<String, String>>,
}

fn grammar() -> &'static Grammar {
    static GRAMMAR: OnceLock<Grammar> = OnceLock::new();
    GRAMMAR.get_or_init(|| {
        on_parser_stack(build_grammar).unwrap_or_else(|| Grammar {
            commands: HashMap::new(),
            options: HashMap::new(),
        })
    })
}

fn build_grammar() -> Grammar {
    let mut root = Cli::command();
    root.build();
    let mut commands = HashMap::new();
    let mut options = HashMap::new();
    for command in root.get_subcommands() {
        let name = command.get_name().to_owned();
        commands.insert(name.clone(), name.clone());
        for alias in command.get_all_aliases() {
            commands.insert(alias.to_ascii_lowercase(), name.clone());
        }
        let mut long_options = HashMap::new();
        for argument in command.get_arguments() {
            let Some(long) = argument.get_long() else {
                continue;
            };
            let canonical = long.to_owned();
            let mut spellings: Vec<String> = vec![long.to_owned()];
            spellings.extend(
                argument
                    .get_all_aliases()
                    .into_iter()
                    .flatten()
                    .map(str::to_owned),
            );
            spellings.extend(argument.get_short().map(String::from));
            spellings.extend(
                argument
                    .get_all_short_aliases()
                    .into_iter()
                    .flatten()
                    .map(String::from),
            );
            for spelling in spellings {
                long_options.insert(spelling.to_ascii_lowercase(), canonical.clone());
            }
        }
        options.insert(name, long_options);
    }
    Grammar { commands, options }
}

fn canonical_command(name: &str) -> Option<&'static str> {
    grammar()
        .commands
        .get(&name.to_ascii_lowercase())
        .map(String::as_str)
}

/// Accept dumpbin-style `/command` and `/option:value` spellings for every option of
/// the command being run. Unknown slash-prefixed values are preserved so paths are
/// never reinterpreted as flags.
pub fn normalize_cli_syntax(raw_args: &[String]) -> Vec<String> {
    if raw_args.is_empty() {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(raw_args.len() + 2);
    out.push(raw_args[0].clone());
    let mut command: Option<&'static str> = None;
    for (index, argument) in raw_args.iter().enumerate().skip(1) {
        if argument == "/?" {
            out.push("--help".to_owned());
            continue;
        }
        let Some(body) = argument.strip_prefix('/') else {
            if index == 1 {
                command = canonical_command(argument);
            }
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
            let lower = body.to_ascii_lowercase();
            if let Some(name) = canonical_command(&lower) {
                command = Some(name);
                out.push(lower);
                continue;
            }
            if SECTIONS.contains(&lower.as_str())
                || TOPIC_ALIASES.iter().any(|(topic, _)| *topic == lower)
                || lower == "help"
                || lower == "version"
            {
                out.push(lower);
                continue;
            }
        }
        let (key, value) = body
            .split_once(':')
            .or_else(|| body.split_once('='))
            .unwrap_or((body, ""));
        let key = key.to_ascii_lowercase();
        let canonical = if key == "h" || key == "help" {
            Some("help".to_owned())
        } else {
            grammar()
                .options
                .get(command.unwrap_or("implicit"))
                .and_then(|options| options.get(&key))
                .cloned()
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

/// Whether `command` takes the long option `flag` (any spelling): `Some(false)` when
/// only other commands take it, `None` when no command does. An argv[1] that is not a
/// command means the implicit dump/locate form.
pub fn command_takes_option(command: &str, flag: &str) -> Option<bool> {
    let grammar = grammar();
    let flag = flag.trim_start_matches('-').to_ascii_lowercase();
    let command = canonical_command(command).unwrap_or("implicit");
    if grammar
        .options
        .get(command)
        .is_some_and(|options| options.contains_key(&flag))
    {
        return Some(true);
    }
    grammar
        .options
        .values()
        .any(|options| options.contains_key(&flag))
        .then_some(false)
}

/// Prepares normalized argv for clap. Command names are case-insensitive, and the
/// pre-subcommand forms `resx <image> <target>` and `resx <name>` run through the
/// hidden `implicit` command. A near-miss of a command name is left alone so clap
/// can suggest the intended command instead of treating the typo as an image.
pub fn prepare_args(raw_args: &[String]) -> Vec<String> {
    let mut args = raw_args.to_vec();
    let Some(first) = args.get(1).cloned() else {
        return args;
    };
    if first.starts_with('-') {
        return args;
    }
    if canonical_command(&first).is_some() {
        args[1] = first.to_ascii_lowercase();
        return args;
    }
    if is_near_command(&first) {
        return args;
    }
    args.insert(1, "implicit".to_owned());
    args
}

fn is_near_command(word: &str) -> bool {
    if word.contains(['.', '\\', '/', ':', '!']) || word.len() < 3 {
        return false;
    }
    let word = word.to_ascii_lowercase();
    grammar()
        .commands
        .keys()
        .any(|name| name != "implicit" && edit_distance(&word, name) <= 1 + name.len() / 6)
}

fn edit_distance(a: &str, b: &str) -> usize {
    let b: Vec<char> = b.chars().collect();
    let mut row: Vec<usize> = (0..=b.len()).collect();
    for (i, ca) in a.chars().enumerate() {
        let mut diagonal = row[0];
        row[0] = i + 1;
        for (j, cb) in b.iter().enumerate() {
            let substitution = diagonal + usize::from(ca != *cb);
            diagonal = row[j + 1];
            row[j + 1] = substitution.min(row[j] + 1).min(row[j + 1] + 1);
        }
    }
    row[b.len()]
}

pub const APP_NAME: &str = "RESX";
pub const ORG_NAME: &str = "Ryftenius";

pub fn version_string() -> String {
    format!("{} v{}", APP_NAME, env!("CARGO_PKG_VERSION"))
}

/// Set by build.rs from the version, commit and target. A build-script output cached
/// by an older build.rs lacks it, so the ID falls back to the version alone instead
/// of failing the build.
const BUILD_ID: &str = match option_env!("RESX_BUILD_ID") {
    Some(id) => id,
    None => concat!("resx-", env!("CARGO_PKG_VERSION"), "+unknown"),
};

pub fn product_banner() -> String {
    format!(
        "Ryftenius (R) RESX Reverse Engineering Suite Extended, Version {}\nBuild ID: {}\nCopyright (C) 2026 Ryftenius.\nSEE DEEPER",
        env!("CARGO_PKG_VERSION"),
        BUILD_ID
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
  code      Code and flow    dump calls xrefs cfg reconstruct-cfg callers
  evidence  Static evidence  contracts driver ioctl ipc network crypto strings
  recovery  Decode/edit      payload patch
  compare   Compare/find     diff index hunt scan locate locate-sym
  options   Shared flags     output, symbols, verbosity and saved preferences

EXAMPLES
  resx peinfo .\driver.sys
  resx ioctl .\sample.dll --json
  resx dump kernel32.dll CreateFileW --recomp
  resx calls .\agent.exe main --depth 4 --only winapi
  resx /dump kernel32.dll entry /bytes:96

DETAILS
  resx code             Open the code and flow section
  resx help calls       Usage, examples and options for one command
  resx calls --help     Same command help
  resx help options     Shared options and saved preferences
  resx help all         Every command and option"#,
        product_banner()
    );
}

/// Resolves a help topic to the command whose generated options it shows.
fn topic_command(topic: &str) -> Option<&'static str> {
    TOPIC_ALIASES
        .iter()
        .find(|(alias, _)| alias.eq_ignore_ascii_case(topic))
        .map(|(_, command)| *command)
        .or_else(|| canonical_command(topic).filter(|name| *name != "implicit"))
}

/// Renders one command's options grouped by heading, optionally after its generated
/// usage line. Global output options are summarized once instead of repeated under
/// every command.
fn command_options(name: String, with_usage: bool) -> Option<String> {
    on_parser_stack(move || {
        let mut root = Cli::command();
        let command = root.find_subcommand_mut(&name)?.clone();
        let template = if with_usage {
            "{usage-heading} {usage}\n\n{all-args}"
        } else {
            "{all-args}"
        };
        Some(
            command
                .bin_name(format!("resx {name}"))
                .disable_help_flag(true)
                .help_template(template)
                .render_help()
                .to_string(),
        )
    })
    .flatten()
}

fn global_options() -> String {
    on_parser_stack(|| {
        Cli::command()
            .help_template("{all-args}")
            .render_help()
            .to_string()
    })
    .unwrap_or_default()
}

const GLOBAL_SUMMARY: &str =
    "Every command also accepts the output options: --json, --out <FILE>, -v, -q,
--diagnostic, --diagnostic-trace, --time, --color, --no-color, --debug-report.
See `resx help options`.";

mod examples;
pub use examples::print_examples;

fn all_help() -> String {
    let overview = on_parser_stack(|| {
        Cli::command()
            .get_subcommands()
            .filter(|command| !command.is_hide_set())
            .map(|command| {
                format!(
                    "  {:<16} {}",
                    command.get_name(),
                    command
                        .get_about()
                        .map(|about| about.to_string())
                        .unwrap_or_default()
                )
            })
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();
    let names = on_parser_stack(|| {
        Cli::command()
            .get_subcommands()
            .filter(|command| !command.is_hide_set())
            .map(|command| command.get_name().to_owned())
            .collect::<Vec<_>>()
    })
    .unwrap_or_default();

    let mut out = format!(
        "{}\n\nCOMPLETE COMMAND REFERENCE\n\n{}\n\nCOMMAND HELP\n  resx help <command>               Usage, examples and options\n  resx <command> --help             Same command help\n  resx help all                     This complete reference\n\nGLOBAL OPTIONS\n{}\n",
        product_banner(),
        overview.join("\n"),
        global_options().trim_end()
    );
    for name in names {
        if let Some(options) = command_options(name, true) {
            out.push_str(&format!("\n{}\n{}\n", "=".repeat(78), options.trim_end()));
        }
    }
    out.push_str(
        "\nSlash syntax is accepted for every long option, for example /verbose and /out:file.",
    );
    out
}

fn section_help(topic: &str) -> Option<&'static str> {
    Some(match topic {
        "inspect" => {
            r"INSPECT | PE headers, exports, imports and symbols
  peinfo / sections / pechk    Metadata, section layout, anomalies
  eat / iat                   Exports and imports
  syms / types                Symbols and PDB types

Examples:
  resx peinfo .\driver.sys
  resx eat .\sample.dll --json
  resx types .\driver.sys DEVICE_OBJECT --pdb .\driver.pdb"
        }
        "code" => {
            r"CODE | Disassembly and control flow
  dump                        Disassemble by name, RVA or ordinal
  calls                       Recursive API call tree, filterable by import source
  xrefs / callers             Incoming references and reverse callers
  cfg / reconstruct-cfg       Function graph and image startup flow

Examples:
  resx dump kernel32.dll CreateFileW --recomp
  resx dump .\sample.exe --at 0x1200 --bytes
  resx calls .\agent.exe main --depth 4 --only winapi
  resx cfg .\sample.dll --ordinal 1
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
  resx ioctl .\sample.dll --verbose
  resx network .\sample.exe --json --out endpoints.json
  resx yara .\sample.exe .\rules.yar

Static findings do not prove execution, live peers or C2 activity."
        }
        "recovery" => {
            r#"RECOVERY | Explicit bounded decoding and editing
  payload                     Decode bytes with operator-supplied parameters
  patch                       Apply a checked byte patch to a new image

Examples:
  resx payload .\blob.bin --out-dir .\decoded --codec zlib --json
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
            r"OPTIONS | Output options shared by every command, and option groups
Output (every command, before or after it):
  --json                      Structured output
  --out, -o <file>            Save output; evidence commands require a new file
  --verbose, -v               Coverage and diagnostics on stderr
  --quiet, -q                 Suppress optional diagnostics; overrides verbose
  --diagnostic                DEBUG developer trace on stderr; implies --verbose
  --diagnostic-trace          Include bounded TRACE events; implies --diagnostic
  --disasm-context <4..32>    Instructions per verbose evidence window (default 12)
  --debug-report <report.zip> Sanitized reproducibility bundle
  --debug-report-include-target  Explicitly include target bytes (64 MiB cap)
  --time                      Print command completion time on stderr
  --color, --no-color         Force or disable terminal colors

Option groups (each command lists the groups it takes under `resx help <command>`):
  Image lookup                --path, --no-system, --no-cwd, --no-path, --arch, --rebase
  Symbols                     --pdb, --sym-path, --sym-server, --reload, --no-pdb
  Target                      <TARGET>, --at, --ordinal
  Analysis                    --max-insns, --max-total, --hostile
  Listing                     --bytes, --nodis, --ssa, --rva, --offset, ...
  Call tree                   --calls, --calls-only, --calls-exclude, --max-subcalls
  Search scope                --include-dir, --include-image, --scope-file, ...

Slash form:
  /dump, /json, /out:file and every other long option are accepted.
  resx config --command-style slash saves the preferred display style.

Function macros:
  entry                       Declared PE AddressOfEntryPoint
  rentry                      RESX startup/main candidate, falling back to entry
  resx config --entry-macro ep --rentry-macro realep

Examples:
  resx contracts .\sample.dll --json -v --out contracts.json
  resx peinfo .\driver.sys --json -q"
        }
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::examples::command_help;
    use super::{
        all_help, help_topic, is_help_request, normalize_cli_syntax, prepare_args, section_help,
    };

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn help_all_lists_every_command_and_its_options() {
        let help = all_help();
        for required in [
            "COMPLETE COMMAND REFERENCE",
            "reconstruct-cfg",
            "--diagnostic-trace",
            "--max-insns",
            "Usage: resx calls",
            "--only <TERMS>",
        ] {
            assert!(help.contains(required), "missing {required}");
        }
        assert!(!help.contains("implicit"));
    }

    #[test]
    fn slash_options_resolve_against_the_command_being_run() {
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
        // `limit` is the strings cap under `strings`, not the dump instruction budget.
        assert_eq!(
            normalize_cli_syntax(&args(&["resx", "/strings", "a.dll", "/limit:5"])),
            args(&["resx", "strings", "a.dll", "--limit", "5"])
        );
        assert_eq!(
            normalize_cli_syntax(&args(&["resx", "/not-a-command/path"])),
            args(&["resx", "/not-a-command/path"])
        );
    }

    #[test]
    fn bare_image_forms_run_through_the_implicit_command() {
        assert_eq!(
            prepare_args(&args(&["resx", "kernel32.dll", "CreateFileW"])),
            args(&["resx", "implicit", "kernel32.dll", "CreateFileW"])
        );
        assert_eq!(
            prepare_args(&args(&["resx", "OpenProcess"])),
            args(&["resx", "implicit", "OpenProcess"])
        );
        assert_eq!(
            prepare_args(&args(&["resx", "DUMP", "a.dll", "x"])),
            args(&["resx", "dump", "a.dll", "x"])
        );
        // A typo stays a typo so clap can suggest the command.
        assert_eq!(
            prepare_args(&args(&["resx", "dumpp", "a.dll"])),
            args(&["resx", "dumpp", "a.dll"])
        );
    }

    #[test]
    fn bare_sections_open_help() {
        let values = args(&["resx", "code"]);
        assert!(is_help_request(&values));
        assert_eq!(help_topic(&values), Some("code"));
    }

    #[test]
    fn command_help_is_distinct_and_generates_its_options() {
        let driver = command_help("driver").unwrap();
        let ioctl = command_help("ioctl").unwrap();
        let strings = command_help("strings").unwrap();
        assert_ne!(driver, ioctl);
        assert!(driver.contains("DRIVER |"));
        assert!(ioctl.contains("IOCTL |"));
        assert!(strings.contains("--encoding"));
        assert!(strings.contains("--raw-wide"));
        assert!(
            !strings.contains("--max-insns"),
            "options are scoped per command"
        );
        assert!(command_help("funcs").unwrap().contains("Usage: resx calls"));
        assert!(section_help("options").unwrap().contains("Call tree"));
    }
}
