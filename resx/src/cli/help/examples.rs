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
    if let Some(help) = command_help(&topic) {
        println!("{help}");
        return;
    }
    println!("{}\n", product_banner());
    println!("{}", GENERAL.trim());
    println!("\nShared options: resx help options | Command overview: resx help");
}

/// Usage, examples and notes for a command or topic, followed by the command's
/// generated options.
pub(in crate::cli) fn command_help(topic: &str) -> Option<String> {
    let topic = topic.to_ascii_lowercase();
    let command = topic_command(&topic)?;
    let text = topic_text(&topic).or_else(|| topic_text(command))?;
    let options = command_options(command.to_owned(), false).unwrap_or_default();
    Some(format!(
        "{}\n\n{}\n\n{}\n\n{}",
        product_banner(),
        text.trim(),
        options.trim_end(),
        GLOBAL_SUMMARY
    ))
}

const GENERAL: &str = r#"
GENERAL HELP
Usage:
  resx <command> [arguments] [options]
  resx help <command>
  resx <command> --help

Examples:
  resx dump ntdll.dll NtCreateFile
  resx calls .\agent.exe main --depth 4 --only winapi
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
  resx help calls
  resx help reconstruct-cfg
  resx help diff
  resx help all
"#;

fn topic_text(topic: &str) -> Option<&'static str> {
    Some(match topic {
        "contracts" => {
            r"CONTRACTS | Bounded x64 API arguments and producer relationships
Usage: resx contracts <image>

Examples:
  resx contracts .\sample.dll --json
  resx contracts .\sample.exe -v --out contracts.json

Includes IPC, network, crypto and IOCTL/NDIS contracts. Unknown values remain
unknown; reports include instruction/call budgets. API arguments use bounded x64
local-block inference and exact import contracts. Producer references identify
static call sites; successful operations and live peers are unobserved. No target
execution."
        }
        "ipc" => {
            r"IPC | Named pipes, ALPC, RPC, COM and shared mappings
Usage: resx ipc <image>

Examples:
  resx ipc .\service.exe --json
  resx ipc .\sample.exe -v --out ipc.json

Static names, arguments and producer references. Live peers and shared kernel
objects require runtime evidence."
        }
        "network" => {
            r"NETWORK | Endpoint candidates and HTTP/socket configuration
Usage: resx network <image>

Examples:
  resx network .\sample.exe --json
  resx network .\sample.exe -v --out endpoints.json

Recovers available host, port, method, path and sockaddr fields. No endpoint is
contacted. Endpoint presence does not establish C2 activity."
        }
        "crypto" => {
            r"CRYPTO | Imported algorithm, provider and mode configuration
Usage: resx crypto <image>

Examples:
  resx crypto .\sample.exe --json
  resx crypto .\sample.dll -v --out crypto.json

Static CNG/CAPI contracts; custom/inlined algorithms may remain unknown.
For decoding with a supplied key: resx help payload."
        }
        "strings" => {
            r"STRINGS | ASCII and UTF-16LE candidates with exact offsets
Usage: resx strings <image> [options]

Examples:
  resx strings .\sample.dll --json
  resx strings .\sample.exe --encoding ascii --min-len 8
  resx strings .\sample.exe --interesting --limit 200
  resx strings .\sample.exe --match TARGET --tag success-marker

Limits: 16 MiB scanned, 8,192 candidates, 4,096 code units per candidate.
UTF-16 candidates use a text-quality filter by default; --raw-wide keeps
permissive binary coincidences. TARGET_OK-like values are labeled success-marker;
brace-form tokens are separate flag-candidate findings. Text presence does not
prove behavior."
        }
        "driver" => {
            r"DRIVER | Static x64 dispatch and driver capability evidence
Usage: resx driver <image>

Examples:
  resx driver .\hypervisor.sys --verbose
  resx driver C:\Windows\System32\drivers\vmbus.sys --json --out vmbus.json

driver includes conditional MajorFunction assignments, imported-API capability
groups, AMD SVM / Intel VMX evidence, and correlated NPT/EPT SLAT hook machinery
with instruction RVAs. No driver is loaded."
        }
        "ioctl" => {
            r"IOCTL | Static x64 request, dispatch, CTL_CODE and NDIS/OID evidence
Usage: resx ioctl <image>

Examples:
  resx ioctl .\sample.dll --verbose --out ioctl.txt
  resx ioctl .\driver.sys --json

Reports bounded request arguments, producer relationships, CTL_CODE candidates,
dispatch assignments and known NDIS/OID layouts. Values without call or object
provenance remain candidates. No driver is loaded and no IOCTL is sent."
        }
        "payload" => {
            r"PAYLOAD | Bounded operator-directed decoding
Usage:
  resx payload <file> --out-dir <new-dir> [--codec <name>]
  resx payload <file> --out-dir <new-dir> --codec aes-cbc --key-file <raw-key> --iv-hex <32-hex-digits> [--pkcs7]

Examples:
  resx payload .\blob.bin --out-dir .\decoded --json
  resx payload .\blob.bin --out-dir .\decoded --codec base64 --offset 0x40 --length 512
  resx payload .\enc.bin --out-dir .\plain --codec aes-cbc --key-file .\key.bin --iv-hex 000102030405060708090a0b0c0d0e0f --pkcs7

--offset and --length select a bounded source byte range. Automatic framing
handles zlib and single-member gzip; explicit codecs also handle raw DEFLATE,
canonical base64, hex, and AES-CBC with a supplied key and IV. Every layer has
input/output hashes and a retained artifact. Format checksums are verified. CBC
alone does not authenticate plaintext. No target execution.
Limits: 8 layers, 16 MiB per input/output, 32 MiB aggregate, bounded expansion."
        }
        "config" => {
            r"CONFIG | Saved RESX command preferences
Usage: resx config [--command-style standard|slash] [--entry-macro NAME] [--rentry-macro NAME]

Examples:
  resx config --command-style slash
  resx /config /entry-macro:ep /rentry-macro:realep

Both command styles always work. Preferences are stored in
HKCU\Software\Ryftenius\RESX."
        }
        "api" => {
            r#"API | Windows SDK declarations
Usage: resx api <name> [--json]

Configure once: resx config --headers "C:\Program Files (x86)\Windows Kits\10\Include"
Then: resx api VirtualAlloc

Add --args to dump, calls or behavior to show parameter names, types, constants
and statically recovered arguments. They are hidden by default. Unknown values
remain '?'. --no-headers overrides --args for a run; config --headers off disables the SDK.
The declaration scanner does not evaluate C preprocessor conditions."#
        }
        "update" => {
            r"UPDATE | Update a source checkout
Usage: resx update

Examples:
  resx update
  resx update --quiet

Runs git fetch/pull against the current repository remote and branch.
Intended for source checkouts, not arbitrary installed binaries."
        }
        "priority" => {
            r"PRIORITY | Priority search configuration
Usage: resx priority

Opens the generated priority config JSON used by locate and callers. Edit priority
directories, exact filenames, prefixes, and regexes there."
        }
        "intelli" => {
            r"INTELLI | Dump-driven heuristic triage
Usage: resx intelli <image> [target] [options]

Examples:
  resx intelli suspicious.dll
  resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
  resx intelli .\packed.dll --calls 2 --hostile --no-pdb
  resx dump suspicious.dll WinMain --intelli --json

intelli takes every dump option and adds imports, strings, hooks, and signal tags."
        }
        "behavior" => {
            r"BEHAVIOR | Static behavior indicators
Usage: resx behavior <image>

Examples:
  resx behavior suspicious.dll
  resx behavior suspicious.dll --json
  resx behavior .\packed-loader.dll --json --out .\packed-loader.behavior.json
  resx behavior .\driver.sys --no-pdb --path C:\Windows\System32\drivers

Static triage for syscall stubs, CPUID/timing/descriptor-table checks, trap/debug
instructions, TLS callbacks, executable-memory APIs, dynamic loader APIs, PEB/TEB
segment probes, and simple generated-code clusters."
        }
        "entropy" => {
            r"ENTROPY | Section/window entropy visualization
Usage: resx entropy <image> [--window <bytes>] [--stride <bytes>] [--all]

Examples:
  resx entropy suspicious.dll
  resx entropy .\packed.exe --window 2048 --stride 1024
  resx entropy .\sample.dll --all
  resx entropy .\sample.dll --json --out .\sample.entropy.json

Renders an overlaid terminal plot over executable sections by default. The y-axis
is the 0.0-8.0 entropy scale; the x-axis follows code RVA order. Plot symbols:
* entropy, a ASCII ratio, z zero-byte ratio, u unique-byte ratio, # overlap. The
detail table below the plot keeps per-window flags."
        }
        "patch" => {
            r#"PATCH | Checked byte patch
Usage:
  resx patch <image> <addr> <hex> [options]
  resx patch <image> --at <addr> --bytes <hex> [options]

Examples:
  resx patch .\sample.dll 0x1200 "90 90" --dry-run
  resx patch .\sample.dll file:0x600 "90 90" --expect "55 48" --patch-out .\sample.patched.dll
  resx patch .\driver.sys va:0x140001000 CC --patch-out .\driver.patched.sys --update-checksum
  resx patch .\sample.dll 0x1200 90 90 --in-place --expect "55 48"

Addresses are RVAs, PE VAs, or file offsets; prefix with rva:, va:, or file: to
force the interpretation. Hex separators are optional for even-length strings.
This command patches bytes only. It does not assemble instructions, grow sections,
search code caves, rewrite relocations, or preserve Authenticode signatures."#
        }
        "dump" | "recomp" | "c" => {
            r#"DUMP | Targeted disassembly and report sections
Usage:
  resx dump <image> <target> [options]
  resx dump <image>!<target> [options]
  resx dump <image> --at <addr> [options]
  resx dump <image> --ordinal <n> [options]
  resx dump <image> entry|rentry [options]

Examples:
  resx dump ntdll.dll NtOpenProcess
  resx dump ntdll.dll!NtOpenProcess
  resx dump ntdll.dll --at 0x161F40
  resx dump ntdll.dll --ordinal 451
  resx /dump .\sample.exe rentry /limit:96 /byte-limit:2048 /fast
  resx dump kernel32.dll CreateFileW --recomp --c-out CreateFileW.c
  resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
  resx dump ntoskrnl.exe KiSystemCall64 --cfg text --calls --recomp
  resx dump .\sample.dll DllMain --hostile --calls 3 --xrefs --strings
  resx dump .\agent.exe main --calls 4 --calls-only winapi
  resx dump .\sample.dll --at 0x401000 --json --no-pdb --max-insns 250

--calls adds the API call map to the listing; `resx calls` shows only the tree.
--ssa adds bounded SSA, stack-slot and control-transfer annotations. PDB
prototypes are retained when available; otherwise a bounded ABI analysis infers
machine-width scalar values, pointer reads/writes and float returns. bitsN means
an N-bit value, not signedness. Unknown args/types stay unknown. --verbose adds
argument evidence RVAs and conflicting decode windows; --json includes signature
and decode_conflicts reports. Overlapping instructions are findings, not proof of
malicious intent."#
        }
        "calls" | "funcs" => {
            r"CALLS | Recursive API call tree for one function
Usage: resx calls <image> <target> [--depth N] [--only TERMS] [--exclude TERMS] [--args]

Examples:
  resx calls .\agent.exe main
  resx calls .\agent.exe main --depth 4 --only winapi
  resx calls .\agent.exe main --only bcrypt.dll,ntdll
  resx calls .\agent.exe main --only iat --exclude kernel32
  resx calls .\agent.exe main --only internal
  resx calls .\agent.exe main --only dynamic
  resx calls .\agent.exe rentry --no-pdb --only winapi --json

Terms for --only and --exclude:
  winapi      Imports outside the C/C++ runtime; runtime helpers are not traversed
  iat         Every import, runtime included
  internal    In-image calls only
  crt         ucrtbase, vcruntime*, msvcp*, api-ms-win-crt-* and runtime helpers
  syscall     Nt*/Zw* calls
  dynamic     Calls through dynamically resolved APIs, and the resolver calls
  NAME.dll    Imports from one DLL; the extension is optional, NAME* matches a prefix

A call that does not match stays in the tree only as the path to one that does;
repeat calls to a function shown earlier are tagged [expanded above]. Without a
PDB, statically linked runtime helpers are anonymous sub_ functions, so crt and
winapi recognize the runtime by its imports alone. Inside dump, the same tree is
--calls N with --calls-only and --calls-exclude.

APIs the image resolves at run time are labeled where they are called:
GetProcAddress with literal, stack-built or decoded names, hand-walked export
and import tables, and hashed lookups through the PEB loader lists. A call
through such a pointer is tagged [dynamic · how], and a resolver call gets a
resolves: line naming the API. `resx behavior` grades the techniques."
        }
        "xrefs" | "refs" => {
            r"XREFS | Incoming references to a function or import
Usage: resx xrefs <image> <target> [options]

Examples:
  resx xrefs .\driver.sys WdfDeviceCreate
  resx xrefs kernel32.dll CreateFileW --json
  resx xrefs .\sample.dll --at 0x1200

xrefs is dump with the references section on, and takes every dump option."
        }
        "cfg" => {
            r"CFG | Function control-flow graph
Usage: resx cfg <image> <target> [options]

Examples:
  resx cfg ntdll.dll NtOpenProcess
  resx cfg ntoskrnl.exe NtQuerySystemInformation
  resx cfg ntdll.dll --at 0x161F40
  resx cfg user32.dll --ordinal 650
  resx cfg .\packed.dll --at 0x402A10 --hostile --max-insns 900 --no-pdb

With --json the graph is reported inside the dump document."
        }
        "reconstruct-cfg" => {
            r"RECONSTRUCT-CFG | Startup and reachable image flow
Usage: resx reconstruct-cfg <image> [options]

Examples:
  resx reconstruct-cfg suspicious.dll
  resx reconstruct-cfg suspicious.dll --depth 8 --max-total 500
  resx reconstruct-cfg suspicious.dll --thread-filter spawned
  resx reconstruct-cfg suspicious.dll --thread-filter api --api-filter GetThreadContext
  resx reconstruct-cfg .\packed.exe --depth 10 --max-callers 64 --max-total 800 --hostile
  resx reconstruct-cfg .\svc.dll --api-filter LoadLibrary --json --out .\svc.flow.json
  resx reconstruct-cfg .\driver.sys --driver-flow --max-subcalls 32

Starts at PE entry/TLS/startup handoff candidates, follows intra-image CALL/JMP
targets, marks imports and unresolved indirect calls, and follows statically
recovered thread/workpool callback arguments when they point back into the image.
PDB symbols are used when available for names, prototype text, and size-backed
decode bounds. Internal PDB/export functions, Nt APIs, Microsoft DLL imports,
CRT/C++ runtime calls, and external DLL imports are tagged separately."
        }
        "peinfo" => {
            r"PEINFO | PE identity and hardening metadata
Usage: resx peinfo <image>

Examples:
  resx peinfo .\driver.sys
  resx peinfo ntdll.dll
  resx peinfo .\sample.exe --json
  resx peinfo .\packed.dll --no-pdb --json --out .\packed.peinfo.json

Reports PE layout, subsystem, image kind, debug info, symbols, signer state,
compiler/runtime heuristics, and hardening flags like ASLR, NX, CFG, and
CET-related markers."
        }
        "sections" => {
            r"SECTIONS | Section layout
Usage: resx sections <image>

Examples:
  resx sections ntdll.dll
  resx sections .\driver.sys
  resx sections .\sample.dll --json

Shows section ranges, entropy, raw/virtual sizes, protections, and expected
protection notes such as writable .text or executable data sections."
        }
        "eat" => {
            r"EAT | Export table
Usage: resx eat <image>

Examples:
  resx eat kernel32.dll
  resx eat ntdll.dll --json
  resx eat .\plugin.dll --json --out .\plugin.exports.json

Dumps export names, ordinals, RVAs, and forwarders when present."
        }
        "iat" => {
            r"IAT | Import table
Usage: resx iat <image>

Examples:
  resx iat kernel32.dll
  resx iat suspicious.dll --json
  resx iat .\packed.dll --json --out .\packed.imports.json

Dumps import DLLs, imported names/ordinals, hints, and IAT slot RVAs."
        }
        "pechk" => {
            r"PECHK | Structural and loader-relevant anomaly checks
Usage: resx pechk <image>

Examples:
  resx pechk .\sample.dll
  resx pechk .\packed.exe --json
  resx pechk C:\Windows\System32\drivers\ndis.sys --no-pdb --quiet

Runs PE header/layout anomaly checks such as invalid directories, suspicious
section layout, odd alignment, and malformed or inconsistent metadata. JSON is a
dedicated bounded validation report that reports truncation explicitly."
        }
        "syms" | "symbols" | "pdb" => {
            r#"SYMS | Symbols
Usage:
  resx syms <image> [symbol options]
  resx types <image> [query] [symbol options]

Examples:
  resx syms ntoskrnl.exe --verbose
  resx syms .\sample.dll --pdb .\sample.pdb
  resx syms .\driver.sys --pdb .\driver.pdb --json
  resx dump ntdll.dll RtlpHeapHandleError --sym-path "C:\Symbols"
  resx types ntoskrnl.exe _EPROCESS --sym-path "srv*C:\Symbols*https://msdl.microsoft.com/download/symbols""#
        }
        "types" => {
            r#"TYPES | PDB-backed type browsing
Usage: resx types <image> [query]

Examples:
  resx types ntoskrnl.exe
  resx types ntoskrnl.exe _EPROCESS
  resx types .\driver.sys DEVICE_OBJECT --pdb .\driver.pdb
  resx types .\module.dll vtable --sym-path "C:\Symbols" --json

Browses PDB-backed type names and symbol references. Results depend on symbol
availability; use --pdb, --sym-path, --sym-server, or --reload when needed."#
        }
        "yara" => {
            r"YARA | YARA-compatible scan
Usage: resx yara <image> <rules>...

Examples:
  resx yara suspicious.dll .\rules\triage.yar
  resx yara ntdll.dll .\rules\exports.yar --json
  resx yara .\sample.exe .\rules\packer.yar .\rules\anti-debug.yar --json
  resx dump .\sample.exe entry --yara .\rules\packer.yar

Accepts rule files, directories containing .yar/.yara files, and JSON saved
configurations containing a string array of rule paths. Match output includes
string file offsets, mapped PE RVAs/sections, metadata, and navigation actions."
        }
        "find" => {
            r#"FIND | Bytes, text, constants and instruction patterns
Usage: resx find <image> <query> [--mode auto|raw|decoded|semantic] [--encoded]

Examples:
  resx find ntdll.dll syscall
  resx find sample.exe "syscall stubs" --mode semantic --verbose
  resx find sample.exe "mov r10,rcx; mov eax,2ch; syscall" --mode decoded
  resx find sample.exe "0f 05" --mode raw
  resx find sample.exe "4d 5a" --mode raw --encoded

Raw matching compares bytes. Decoded matching compares normalized complete
instructions and semicolon-separated sequences. Semantic matching recognizes
syscalls, syscall stubs, VM/anti-VM instructions, and privileged instructions.
Encoded recovery is bounded to bytewise XOR, ADD/SUB, NOT, rotations, and reversal
of the supplied pattern. The global instruction budget is reported."#
        }
        "scan" => {
            r"SCAN | Bounded PE corpus inventory
Usage: resx scan <path> [options]

Examples:
  resx scan C:\Windows\System32\drivers --jsonl --max-files 200
  resx scan .\samples --extensions exe,dll,sys --max-candidates 16
  resx scan .\samples --max-file-mb 100 --json
  resx scan C:\Windows\System32\drivers --extensions sys --jsonl --max-file-mb 50

Inventories PE images and ranks fuzz-target candidates using image kind, risk
imports, exports, startup paths, section anomalies, and symbol names."
        }
        "diff" => {
            r"DIFF | Structural image/function comparison
Usage: resx diff <image-a> <image-b> [image-c ...] [options]

Examples:
  resx diff .\old.dll .\new.dll
  resx diff .\old.dll .\new.dll --json
  resx diff .\old.dll .\new.dll .\canary.dll --graph
  resx diff .\old.exe .\new.exe --mode deep --include-weak
  resx diff .\left.dll .\right.dll --left-pdb .\left.pdb --right-pdb .\right.pdb
  resx diff .\old.dll .\new.dll --graph --graph-format dot --graph-out heatmap.dot
  resx diff .\old.dll .\new.dll --show-cfg auto
  resx diff .\old.dll .\new.dll --show-cfg TargetFunc --cfg-format dot --cfg-out cfg.dot
  resx diff .\v1.sys .\v2.sys --mode deep --max-functions 6000 --include-weak --json

Compares normalized function code, basic-block shape, calls/imports, constants,
and metadata so small string/debug/address changes do not dominate the score.
With three or more images, emits an all-pairs matrix after profiling each image
once. --graph adds function hotspots, section entropy deltas, and DOT/JSON graph
output. --show-cfg pairs basic blocks and highlights exact, similar, changed,
left-only, and right-only control-flow/code regions."
        }
        "index" | "hunt" => {
            r"INDEX / HUNT | Fingerprint corpus
Usage:
  resx index <dir-or-image> --db <file> [options]
  resx hunt <sample> --db <file> [options]

Examples:
  resx index .\samples --db .\samples.resxdb --no-pdb
  resx index C:\Windows\System32\drivers --db drivers.resxdb --extensions sys --max-files 500
  resx hunt .\unknown.dll --db .\samples.resxdb
  resx hunt .\unknown.dll --db .\samples.resxdb --threshold 75 --include-weak
  resx hunt .\new-sample.exe --db .\family.resxdb --threshold 60 --max-candidates 20 --json

index stores normalized function/CFG/API fingerprints for many PE images. hunt
compares one sample against that index to find variants, subsets, repacked
builds, renamed/debug-stripped builds, and shared-code families."
        }
        "callers" | "follow" => {
            r"CALLERS | Reverse caller tree
Usage: resx callers <image> <function> [options]

Examples:
  resx callers kernel32.dll CreateFileW
  resx callers ntdll.dll NtOpenProcess --depth 2 --format flat
  resx callers ntdll.dll NtOpenProcess --include-dir C:\Work\Drivers
  resx callers ntoskrnl.exe PsOpenProcess --include-dir C:\Windows\System32\drivers --scope-file *.sys
  resx callers user32.dll MessageBoxW --scan-exe --show-site --json
  resx callers ntoskrnl.exe MmMapIoSpace --include-dir C:\Windows\System32\drivers --scope-file *.sys --format list

Reverse-traces call sites across the priority set plus optional include
directories and images. --show-site prints call-site RVAs; --filter-dll narrows
noisy graphs."
        }
        "locate" | "locate-sym" => {
            r"LOCATE | Find exports and symbols
Usage:
  resx locate <name> [options]
  resx locate-sym <name> [options]

Examples:
  resx locate OpenProcess
  resx locate NtOpenProcess --include-dir C:\Work\Drivers
  resx locate-sym RtlpHeapHandleError
  resx locate-sym NtOpenProcess --include-image .\mydriver.sys
  resx locate VirtualProtect --include-dir .\samples --scan-exe --json
  resx locate-sym KiDispatch --include-dir C:\Symbols\private --filter-dll ntoskrnl

locate uses exports. locate-sym also loads available PDB symbols and can find
private/internal names when symbols are present."
        }
        "edrchk" | "hookchk" => {
            r"HOOK / EDR CHECK | dump report sections
Usage:
  resx dump <image> <target> --hookchk
  resx dump <image> <target> --edrchk

Examples:
  resx dump ntdll.dll NtOpenProcess --hookchk
  resx dump ntdll.dll NtAllocateVirtualMemory --edrchk
  resx dump C:\Windows\System32\ntdll.dll NtProtectVirtualMemory --edrchk --json

--hookchk is static entry/thunk triage. --edrchk compares disk bytes with an
already-loaded module prologue."
        }
        _ => return None,
    })
}
