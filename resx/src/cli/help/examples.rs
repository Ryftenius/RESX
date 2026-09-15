use super::*;

pub fn print_examples(topic: &str) {
    let topic = topic.to_ascii_lowercase();
    if topic == "all" {
        println!("{}", all_help());
        return;
    }
    if let Some(section) = section_help(&topic) {
        println!(
            "{}\n\n{}\n\nDetails: resx help <command>",
            product_banner(),
            section
        );
        return;
    }
    let body = match topic.as_str() {
        "contracts" | "ipc" | "network" | "crypto" | "strings" => {
            r#"
CONTRACT / STRING HELP
Usage:
  resx contracts <image> --json
  resx ipc <image> --json
  resx network <image> --json
  resx crypto <image> --json
  resx strings <image> --json

These commands produce structured JSON without loading or executing the image.
API arguments use bounded x64 local-block inference and exact import contracts.
Producer references identify static call sites; successful operations, live peers,
C2 role and encryption/decryption execution are unobserved. Unknown values remain
unknown. Text scanning reports offsets, encoding, and budget/truncation limits.
"#
        }
        "payload" => {
            r#"
PAYLOAD HELP
Usage:
  resx payload <file> --payload-dir <new-dir> [--codec <name>] --json
  resx payload <file> --payload-dir <new-dir> --codec aes-cbc --key-file <raw-key> --iv-hex <32-hex-digits> [--pkcs7]

Optional --payload-offset and --payload-length select a bounded source byte range.
Automatic framing handles zlib and single-member gzip; explicit codecs also handle
raw DEFLATE, canonical base64, hex, and AES-CBC with a supplied key and IV.
Every layer has input/output hashes and a retained artifact. Format checksums are
verified. CBC alone does not authenticate plaintext. JSON configuration and native
PE structural fingerprints are reported when applicable. No target execution.
Limits: 8 layers, 16 MiB per input/output, 32 MiB aggregate, bounded expansion.
"#
        }
        "driver" | "ioctl" => {
            r#"
DRIVER HELP
Usage:
  resx driver <image> --json
  resx ioctl <image> --json

Bounded x64 static evidence includes CTL_CODE candidates, recognized IOCTL/NDIS API
arguments, selected OID layouts, and conditional MajorFunction assignments.
Values without call or object provenance remain candidates. No driver is loaded.
"#
        }
        "config" => {
            r"CONFIG | Saved RESX command preferences
Usage: resx config [--command-style standard|slash]
                   [--entry-macro NAME] [--rentry-macro NAME]

Examples:
  resx config --command-style slash
  resx /config /entry-macro:ep /rentry-macro:realep

Both command styles always work. Preferences
are stored in HKCU\Software\Ryftenius\RESX."
        }
        "update" => {
            r#"
UPDATE HELP
Usage:
  resx update [--quiet]

Examples:
  resx update
  resx update --quiet

NOTES
  Runs git fetch/pull against the current repository remote and branch.
  Intended for source checkouts, not arbitrary installed binaries.
"#
        }
        "intelli" => {
            r#"
INTELLI HELP
Usage:
  resx intelli <image> [function] [dump options]

Examples:
  resx intelli suspicious.dll
  resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
  resx dump suspicious.dll --intelli
  resx dump suspicious.dll WinMain --intelli --json
  resx intelli .\packed.dll --funcs --funcs-depth 2 --hostile --no-pdb

NOTES
  `intelli` is a first-class command alias for dump-driven heuristic triage.
  It is useful when you want imports, strings, hooks, and signal tags quickly.
"#
        }
        "behavior" => {
            r#"
BEHAVIOR HELP
Usage:
  resx behavior <image> [--json]

Examples:
  resx behavior suspicious.dll
  resx behavior suspicious.dll --json
  resx behavior .\packed-loader.dll --json --out .\packed-loader.behavior.json
  resx behavior .\driver.sys --no-pdb --path C:\Windows\System32\drivers

NOTES
  Static triage for syscall stubs, CPUID/timing/descriptor-table checks,
  trap/debug instructions, TLS callbacks, executable-memory APIs, dynamic
  loader APIs, PEB/TEB segment probes, and simple generated-code clusters.
"#
        }
        "entropy" => {
            r#"
ENTROPY HELP
Usage:
  resx entropy <image> [--entropy-window <bytes>] [--entropy-stride <bytes>] [--entropy-all] [--json]

Examples:
  resx entropy suspicious.dll
  resx entropy .\packed.exe --entropy-window 2048 --entropy-stride 1024
  resx entropy .\sample.dll --entropy-all
  resx entropy .\sample.dll --json --out .\sample.entropy.json

NOTES
  Renders an overlaid terminal plot over executable sections by default.
  The y-axis is the 0.0-8.0 entropy scale; the x-axis follows code RVA order.
  Plot symbols: * entropy, a ASCII ratio, z zero-byte ratio, u unique-byte ratio,
  # overlap. The detail table below the plot keeps per-window flags.
  Use --entropy-all to include non-executable sections.
"#
        }
        "patch" => {
            r#"
PATCH HELP
Usage:
  resx patch <image> --at <addr> --patch-bytes <hex> [patch options]
  resx patch <image> <addr> <hex> [patch options]

Examples:
  resx patch .\sample.dll --at 0x1200 --patch-bytes "90 90" --dry-run
  resx patch .\sample.dll file:0x600 "90 90" --expect "55 48" --patch-out .\sample.patched.dll
  resx patch .\driver.sys va:0x140001000 CC --patch-out .\driver.patched.sys --update-checksum
  resx patch .\sample.dll 0x1200 90 90 --in-place --expect "55 48"

Options:
  --at <addr>           RVA, PE VA, or file offset. Prefix with rva:, va:, or file: to force interpretation.
  --patch-bytes <hex>   Replacement bytes. Separators are optional for even-length hex strings.
  --expect <hex>        Require the current bytes to match before writing.
  --patch-out <file>    Patched copy path. Defaults to <name>.patched.<ext>.
  --dry-run             Validate and report without writing.
  --in-place            Modify the source image itself.
  --overwrite           Allow replacing an existing output copy.
  --update-checksum     Recalculate the PE optional-header checksum before writing.

NOTES
  This command patches bytes only. It does not assemble instructions, grow sections,
  search code caves, rewrite relocations, or preserve Authenticode signatures.
"#
        }
        "dump" | "xrefs" | "refs" | "recomp" | "c" => {
            r#"
DUMP HELP
Usage:
  resx dump <image> <function> [options]
  resx dump <image>!<function> [options]
  resx dump <image> --at <addr> [options]
  resx dump <image> --ordinal <n> [options]
  resx dump <image> entry|rentry [options]
  resx xrefs <image> <function-or-import> [options]

Examples:
  resx dump ntdll.dll NtOpenProcess
  resx dump ntdll.dll!NtOpenProcess
  resx dump ntdll.dll --at 0x161F40
  resx dump ntdll.dll --ordinal 451
  resx /dump .\sample.exe rentry /limit:96 /byte-limit:2048 /fast
  resx dump kernel32.dll CreateFileW --recomp --c-out CreateFileW.c
  resx xrefs .\driver.sys WdfDeviceCreate
  resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
  resx dump ntoskrnl.exe KiSystemCall64 --cfg text --funcs --recomp
  resx dump .\sample.dll DllMain --hostile --funcs --funcs-depth 3 --xrefs --strings
  resx dump .\sample.dll --at 0x401000 --json --no-pdb --max-insns 250

Useful options:
  --hostile, --funcs, --funcs-depth <n>, --max-subcalls <n>, --driver-flow,
  --bytes/--hex/--opcode, --nodis, --cfg text, --recomp, --xrefs, --strings,
  --edrchk, --hookchk, --pdb <file>, --verbose

QOL aliases:
  --limit/--insns, --byte-limit, --fast, --refs, --strrefs,
  --call-depth, --decompile-out
"#
        }
        "cfg" => {
            r#"
CFG HELP
Usage:
  resx cfg <image> <function>
  resx cfg <image> --at <addr>
  resx cfg <image> --ordinal <n>

Examples:
  resx cfg ntdll.dll NtOpenProcess
  resx cfg ntoskrnl.exe NtQuerySystemInformation
  resx cfg ntdll.dll --at 0x161F40
  resx cfg user32.dll --ordinal 650
  resx cfg .\packed.dll --at 0x402A10 --hostile --max-insns 900 --no-pdb
"#
        }
        "reconstruct-cfg" => {
            r#"
RECONSTRUCT-CFG HELP
Usage:
  resx reconstruct-cfg <image> [flow options]

Examples:
  resx reconstruct-cfg suspicious.dll
  resx suspicious.dll --reconstruct-cfg --depth 8 --max-total 500
  resx reconstruct-cfg suspicious.dll --thread-filter spawned
  resx reconstruct-cfg suspicious.dll --thread-filter api --api-filter GetThreadContext
  resx reconstruct-cfg .\sample.exe --json
  resx reconstruct-cfg .\packed.exe --depth 10 --max-callers 64 --max-total 800 --hostile
  resx reconstruct-cfg .\svc.dll --api-filter LoadLibrary --json --out .\svc.flow.json
  resx reconstruct-cfg .\driver.sys --driver-flow --max-subcalls 32

NOTES
  Starts at PE entry/TLS/startup handoff candidates, follows intra-image CALL/JMP
  targets, marks imports and unresolved indirect calls, and follows statically
  recovered thread/workpool callback arguments when they point back into the image.
  PDB symbols are used when available for names, prototype text, and size-backed
  decode bounds. Internal PDB/export functions, Nt APIs, Microsoft DLL imports,
  CRT/C++ runtime calls, and external DLL imports are tagged separately.
  Use --thread-filter and --api-filter for non-interactive focus.
"#
        }
        "peinfo" => {
            r#"
PEINFO HELP
Usage:
  resx peinfo <image> [--json]

Examples:
  resx peinfo .\blackbird.sys
  resx peinfo ntdll.dll
  resx peinfo .\sample.exe --json
  resx peinfo .\packed.dll --no-pdb --json --out .\packed.peinfo.json

NOTES
  Reports PE layout, subsystem, image kind, debug info, symbols, signer state,
  compiler/runtime heuristics, and hardening flags like ASLR, NX, CFG, and CET-related markers.
"#
        }
        "sections" => {
            r#"
SECTIONS HELP
Usage:
  resx sections <image> [--json]

Examples:
  resx sections ntdll.dll
  resx sections .\blackbird.sys
  resx sections .\sample.dll --json
  resx sections .\packed.dll --no-color --quiet

NOTES
  Shows section ranges, entropy, raw/virtual sizes, protections, and expected
  protection notes such as writable .text or executable data sections.
"#
        }
        "eat" => {
            r#"
EAT HELP
Usage:
  resx eat <image> [--json]

Examples:
  resx eat kernel32.dll
  resx eat ntdll.dll --json
  resx eat .\plugin.dll --json --out .\plugin.exports.json

NOTES
  Dumps export names, ordinals, RVAs, and forwarders when present.
"#
        }
        "iat" => {
            r#"
IAT HELP
Usage:
  resx iat <image> [--json]

Examples:
  resx iat kernel32.dll
  resx iat suspicious.dll --json
  resx iat .\packed.dll --json --out .\packed.imports.json

NOTES
  Dumps import DLLs, imported names/ordinals, hints, and IAT slot RVAs.
"#
        }
        "yara" => {
            r#"
YARA HELP
Usage:
  resx yara <image> <rule.yar> [--json]
  resx <image> --yara <rule.yar> [--yara <more.yar>]

Examples:
  resx yara suspicious.dll .\rules\triage.yar
  resx yara ntdll.dll .\rules\exports.yar --json
  resx .\sample.exe --yara .\rules\packer.yar --yara .\rules\anti-debug.yar --json
  resx yara .\samples\loader.dll .\rules\loader.yar --no-color --quiet

NOTES
  Accepts rule files, directories containing .yar/.yara files, and JSON saved
  configurations containing a string array of rule paths. Match output includes
  string file offsets, mapped PE RVAs/sections, metadata, and navigation actions.
"#
        }
        "find" => {
            r#"
INSTRUCTION FINDER HELP
Usage:
  resx find <image> <query> [--find-mode auto|raw|decoded|semantic] [--find-encoded] [--json]

Examples:
  resx find ntdll.dll syscall
  resx find sample.exe "syscall stubs" --find-mode semantic --verbose
  resx find sample.exe "mov r10,rcx; mov eax,2ch; syscall" --find-mode decoded
  resx find sample.exe "0f 05" --find-mode raw
  resx find sample.exe "4d 5a" --find-mode raw --find-encoded

NOTES
  Raw matching compares bytes. Decoded matching compares normalized complete
  instructions and semicolon-separated sequences. Semantic matching recognizes
  syscalls, syscall stubs, VM/anti-VM instructions, and privileged instructions.
  Encoded recovery is bounded to bytewise XOR, ADD/SUB, NOT, rotations, and
  reversal of the supplied pattern. The global instruction budget is reported.
"#
        }
        "scan" => {
            r#"
SCAN HELP
Usage:
  resx scan <path> [scan options]

Examples:
  resx scan C:\Windows\System32\drivers --jsonl --max-files 200
  resx scan .\samples --extensions exe,dll,sys --max-candidates 16
  resx scan .\samples --max-file-mb 100 --json
  resx scan .\corpus --extensions exe,dll --max-files 500 --max-candidates 32 --json
  resx scan C:\Windows\System32\drivers --extensions sys --jsonl --max-file-mb 50

NOTES
  Inventories PE images and ranks fuzz-target candidates using image kind,
  risk imports, exports, startup paths, section anomalies, and symbol names.
"#
        }
        "diff" => {
            r#"
DIFF HELP
Usage:
  resx diff <image-a> <image-b> [image-c ...] [diff options]

Examples:
  resx diff .\old.dll .\new.dll
  resx diff .\old.dll .\new.dll --json
  resx diff .\old.dll .\new.dll .\canary.dll --diff-graph
  resx diff .\old.exe .\new.exe --diff-mode deep --include-weak
  resx diff .\left.dll .\right.dll --left-pdb .\left.pdb --right-pdb .\right.pdb
  resx diff .\old.dll .\new.dll --diff-graph --diff-graph-format dot --diff-graph-out heatmap.dot
  resx diff .\old.dll .\new.dll --show-cfg-diff auto
  resx diff .\old.dll .\new.dll --show-cfg-diff TargetFunc --cfg-diff-format dot --cfg-diff-out cfg.dot
  resx diff .\v1.sys .\v2.sys --diff-mode deep --max-functions 6000 --include-weak --json
  resx diff .\left.dll .\right.dll --show-cfg-diff auto --cfg-diff-format json --no-pdb

NOTES
  Compares normalized function code, basic-block shape, calls/imports, constants,
  and metadata so small string/debug/address changes do not dominate the score.
  With three or more images, emits an all-pairs matrix after profiling each image
  once. --diff-graph adds function hotspots, section entropy deltas, and DOT/JSON
  graph output for recording or offline inspection.
  CFG diff mode pairs basic blocks and highlights exact, similar, changed,
  left-only, and right-only control-flow/code regions.
"#
        }
        "index" | "hunt" => {
            r#"
CORPUS HELP
Usage:
  resx index <dir-or-image> --db <file> [corpus options]
  resx hunt <sample> --db <file> [corpus options]

Examples:
  resx index .\samples --db .\samples.resxdb --no-pdb
  resx index C:\Windows\System32\drivers --db drivers.resxdb --extensions sys --max-files 500
  resx hunt .\unknown.dll --db .\samples.resxdb
  resx hunt .\unknown.dll --db .\samples.resxdb --diff-threshold 75 --include-weak
  resx index .\malware-family --db .\family.resxdb --extensions exe,dll --max-functions 5000 --json
  resx hunt .\new-sample.exe --db .\family.resxdb --diff-threshold 60 --max-candidates 20 --json

NOTES
  `index` stores normalized function/CFG/API fingerprints for many PE images.
  `hunt` compares one sample against that index to find variants, subsets,
  repacked builds, renamed/debug-stripped builds, and shared-code families.
"#
        }
        "follow" | "callers" => {
            r#"
CALLERS HELP
Usage:
  resx callers <image> <function> [follow options]

Examples:
  resx callers kernel32.dll CreateFileW
  resx callers ntdll.dll NtOpenProcess --depth 2 --format flat
  resx callers ntdll.dll NtOpenProcess --include-dir C:\Work\Drivers
  resx callers ntoskrnl.exe PsOpenProcess --include-dir C:\Windows\System32\drivers --scope-file *.sys
  resx callers user32.dll MessageBoxW --scan-exe --show-site --json
  resx callers ntdll.dll NtProtectVirtualMemory --include-dir .\samples --scan-exe --depth 4 --max-total 1000
  resx callers ntoskrnl.exe MmMapIoSpace --include-dir C:\Windows\System32\drivers --scope-file *.sys --format list

NOTES
  Reverse-traces callsites across the priority set plus optional include dirs/images.
  Use --show-site to print callsite RVAs and --filter-dll to narrow noisy graphs.
"#
        }
        "locate" | "locate-sym" => {
            r#"
LOCATE HELP
Usage:
  resx locate <name> [search options]
  resx locate-sym <name> [search options]

Examples:
  resx locate OpenProcess
  resx locate NtOpenProcess
  resx locate NtOpenProcess --include-dir C:\Work\Drivers
  resx locate-sym RtlpHeapHandleError
  resx locate-sym NtOpenProcess --include-image .\mydriver.sys
  resx locate VirtualProtect --include-dir .\samples --scan-exe --json
  resx locate-sym KiDispatch --include-dir C:\Symbols\private --filter-dll ntoskrnl

NOTES
  `locate` uses exports. `locate-sym` also loads available PDB symbols and can
  find private/internal names when symbols are present.
"#
        }
        "priority" => {
            r#"
PRIORITY HELP
Usage:
  resx priority

Examples:
  resx priority

NOTES
  Opens the generated priority config JSON used by locate and callers.
  Edit priority directories, exact filenames, prefixes, and regexes there.
"#
        }
        "symbols" | "pdb" | "syms" => {
            r#"
SYMBOL HELP
Usage:
  resx syms <image> [symbol options]
  resx types <image> [query] [symbol options]

Examples:
  resx dump ntdll.dll RtlpHeapHandleError --verbose
  resx dump ntdll.dll RtlpHeapHandleError --sym-path "C:\Symbols"
  resx syms ntoskrnl.exe --verbose
  resx syms .\J58.dll --pdb .\J58.pdb
  resx types ntoskrnl.exe _EPROCESS --sym-path "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols"
  resx syms .\driver.sys --pdb .\driver.pdb --json
"#
        }
        "types" => {
            r#"
TYPES HELP
Usage:
  resx types <image> [query] [symbol options]

Examples:
  resx types ntoskrnl.exe
  resx types ntoskrnl.exe _EPROCESS
  resx types .\driver.sys DEVICE_OBJECT --pdb .\driver.pdb
  resx types .\module.dll vtable --sym-path "C:\Symbols" --json

NOTES
  Browses PDB-backed type names and symbol references. Results depend on symbol
  availability; use --pdb, --sym-path, --sym-server, or --reload when needed.
"#
        }
        "pechk" => {
            r#"
PECHK HELP
Usage:
  resx pechk <image> [--json]

Examples:
  resx pechk .\sample.dll
  resx pechk .\packed.exe --json
  resx pechk C:\Windows\System32\drivers\ndis.sys --no-pdb --quiet

JSON is a dedicated bounded validation report. It omits unrelated function,
CFG, string, and indirect-flow analysis and reports truncation explicitly.

NOTES
  Runs PE header/layout anomaly checks such as invalid directories, suspicious
  section layout, odd alignment, and malformed or inconsistent metadata.
"#
        }
        "edrchk" | "hookchk" => {
            r#"
HOOK / EDR CHECK HELP
Usage:
  resx dump <image> <function> --hookchk
  resx dump <image> <function> --edrchk

Examples:
  resx dump ntdll.dll NtOpenProcess --hookchk
  resx dump ntdll.dll NtAllocateVirtualMemory --edrchk
  resx dump C:\Windows\System32\ntdll.dll NtProtectVirtualMemory --edrchk --json

NOTES
  --hookchk is static entry/thunk triage. --edrchk compares disk bytes with an
  already-loaded module prologue. --unsafe-map-image has been retired and fails
  closed.
"#
        }
        _ => {
            r#"
GENERAL HELP
Usage:
  resx <command> [arguments] [options]
  resx help <command>
  resx <command> --help

Examples:
  resx dump ntdll.dll NtCreateFile
  resx intelli suspicious.dll
  resx behavior suspicious.dll --json
  resx entropy suspicious.dll
  resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
  resx reconstruct-cfg suspicious.dll --depth 6
  resx diff .\old.dll .\new.dll
  resx index .\samples --db .\samples.resxdb --no-pdb
  resx hunt .\unknown.dll --db .\samples.resxdb
  resx callers ntdll.dll NtOpenProcess --depth 2
  resx scan C:\Windows\System32\drivers --jsonl --max-files 200
  resx locate-sym NtOpenProcess
  resx update

Command help:
  resx help dump
  resx help behavior
  resx help entropy
  resx help reconstruct-cfg
  resx help diff
"#
        }
    };
    println!("{}\n", product_banner());
    println!("{}", body.trim());
    println!("\nShared flags: resx help options | Command overview: resx help");
}
