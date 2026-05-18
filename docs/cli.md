# RESX CLI

RESX is a Windows binary analysis CLI for PE metadata, exports/imports, PDB-backed symbols, targeted disassembly, CFG views, startup-flow reconstruction, static triage, structural diffing, corpus indexing, sample hunting, YARA scans, and caller tracing.

The CLI is intentionally terminal-first: every major command supports text output for interactive use, and analysis commands support JSON for automation.

## Build

From the repository root:

```powershell
cargo build --release
```

The release binary is written to:

```text
target/release/resx.exe
```

For local development you can run through Cargo:

```powershell
cargo run -p resx -- help
```

## Basic Usage

```powershell
resx help
resx version
resx dump <image> <function>
resx dump <image> --at <rva>
resx dump <image> --ordinal <n>
resx cfg <image> <function>
resx reconstruct-cfg <image>
resx intelli <image> [function]
resx peinfo <image>
resx scan <path>
resx diff <old-image> <new-image>
```

`<image>` may be an explicit path or a module name that RESX can resolve through the current directory, configured search paths, system locations, and priority paths.

## Command Map

| Command | Purpose |
| --- | --- |
| `dump` | Disassemble or reconstruct one function by export name, symbol name, RVA, or ordinal. |
| `cfg` | Render a control-flow graph view for one function. |
| `reconstruct-cfg` | Rebuild a best-effort startup/TLS/thread/workpool flow waterfall for one image. |
| `intelli` | Run heuristic triage over an image or one function. |
| `types` | Browse PDB-backed type names and symbol references. |
| `peinfo` | Emit PE headers, data directories, imports/exports summary, TLS/startup evidence, debug info, load config, resources, and anomaly data. |
| `sections` | Show section layout, entropy, protection, and expectation notes. |
| `eat` | Dump the Export Address Table. |
| `iat` | Dump the Import Address Table. |
| `syms` | Dump resolved export and PDB symbols. |
| `pechk` | Run PE header/layout anomaly checks. |
| `priority` | Open or create the priority config used by locate and caller tracing. |
| `callers` | Reverse-trace callers across the priority set and optional scan scope. |
| `locate` | Locate export-backed matches in the priority set. |
| `locate-sym` | Locate export and PDB symbol-backed matches. |
| `explain` | Explain Windows prefix/API-style names using the built-in glossary. |
| `scan` | Inventory EXE/DLL/SYS files and rank fuzz target candidates. |
| `diff` | Compare normalized function/control-flow structure between two or more images. |
| `index` | Build a reusable structural fingerprint corpus. |
| `hunt` | Rank corpus images related to one sample. |
| `yara` | Scan a PE image with one or more YARA rule files. |
| `update` | Pull the latest version from the current git remote/branch. |

## Output Modes

Most analysis commands support JSON:

```powershell
resx peinfo .\sample.dll --json
resx dump .\sample.dll DllMain --json
resx reconstruct-cfg .\sample.dll --json
resx scan .\samples --json
```

Use `--out <file>` to write command output to a file:

```powershell
resx peinfo .\sample.dll --json --out .\sample.peinfo.json
```

Use `--color` or `--no-color` to force text colour behaviour. FFI callers and the VS Code extension run with `--no-color`.

JSON responses use versioned envelopes where possible. Consumer code should prefer documented object keys and tolerate additional fields.

## Target Selection

Dump and CFG commands accept:

```powershell
resx dump kernel32.dll CreateFileW
resx dump ntdll.dll --at 0x161F40
resx dump kernel32.dll --ordinal 1
resx cfg ntdll.dll NtAllocateVirtualMemory
```

Useful target flags:

| Flag | Description |
| --- | --- |
| `--at <rva>` | Analyze an RVA instead of a named function. |
| `--ordinal <n>` | Analyze an export by ordinal. |
| `--rebase <addr>` | Compute displayed addresses from another image base. |
| `--arch auto|x86|x64` | Override architecture detection. |
| `--max-insns <n>` | Cap decoded instructions. |
| `--max-bytes <n>` | Cap bytes decoded from the target. |
| `--bytes` / `--no-bytes` | Show or hide instruction bytes. |
| `--intel` / `--att` | Select assembly syntax. |
| `--follow-jmp` / `--no-follow-jmp` | Follow or suppress entry thunk following. |
| `--show-offsets` | Show file offsets. |
| `--show-rva` | Show RVAs in relevant views. |

## Symbol and PDB Options

```powershell
resx syms .\driver.sys --pdb .\driver.pdb
resx dump .\app.exe WinMain --sym-path C:\Symbols --sym-server https://msdl.microsoft.com/download/symbols
resx peinfo .\sample.dll --no-pdb
```

| Flag | Description |
| --- | --- |
| `--pdb <file>` | Load an explicit PDB. |
| `--sym-path <path>` | Add a symbol path. Repeat or use path separators as needed. |
| `--sym-server <url>` | Override the symbol server. |
| `--reload` | Bypass cached PDB data and reload. |
| `--no-pdb` | Disable PDB loading. |

## Dump, Triage, and Reconstruction

```powershell
resx dump .\sample.dll DllMain --recomp --strings --xrefs
resx dump .\sample.dll DllMain --funcs --funcs-depth 2
resx intelli .\sample.dll
resx intelli .\sample.dll DllMain --hookchk --cfg text --strings
resx dump .\sample.dll DllMain --hostile
```

| Flag | Description |
| --- | --- |
| `--recomp` | Show C-like reconstruction. |
| `--c-out <file>` | Write reconstruction to a C file. |
| `--xrefs` | Show incoming intra-image CALL/JMP references. |
| `--strings` | Show referenced string literals. |
| `--funcs` | Show resolved CALL/JMP/API call map. |
| `--funcs-depth <n>` | Recursively trace internal calls to depth `n`. |
| `--cfg text` | Include a text CFG view. |
| `--edrchk` | Compare disk bytes with loaded in-memory prologue bytes. |
| `--unsafe-map-image` | Allow checks that map an on-disk image into the RESX process. |
| `--hookchk` | Show static entry-hook/thunk indicators. |
| `--intelli` | Run heuristic triage. |
| `--hostile` | Enable aggressive tracing, recursive register slicing, indirect JMP emission, and suspicion annotations. |
| `--explain` | Explain the current target name with prefix/API glossary hints. |

`--hostile` is useful for packed, obfuscated, or intentionally confusing code. It may produce more candidate edges and should be reviewed as static evidence, not proof of runtime behaviour.

## Startup Flow

```powershell
resx reconstruct-cfg .\sample.dll
resx reconstruct-cfg .\sample.dll --depth 6 --max-total 300
resx reconstruct-cfg .\sample.dll --thread-filter spawned
resx reconstruct-cfg .\sample.dll --api-filter CreateThread
resx reconstruct-cfg .\sample.dll --json
```

`reconstruct-cfg` starts from loader-visible roots such as the PE entry point and TLS callbacks, then builds a bounded static flow graph. It also annotates thread, workpool, indirect, import, and x64 exception-handler edges when they can be resolved statically.

| Flag | Description |
| --- | --- |
| `--depth <n>` | Max trace depth. |
| `--max-total <n>` | Max graph size. |
| `--thread-filter <term>` | Filter to thread-related paths. Useful values include `all`, `spawned`, and `api`. |
| `--api-filter <term>` | Filter paths/functions/APIs containing a term. |

Startup evidence in `peinfo` is intentionally conservative. Direct call/jump chains below the entry point are CFG data, not automatically "startup routines".

## Caller Tracing and Locate

```powershell
resx callers ntdll.dll NtOpenProcess --depth 2 --format flat
resx callers ntoskrnl.exe PsOpenProcess --include-dir C:\Windows\System32\drivers --scope-file *.sys
resx locate NtOpenProcess
resx locate-sym NtOpenProcess --include-image .\mydriver.sys
```

| Flag | Description |
| --- | --- |
| `--depth <n>` | Caller trace depth. |
| `--max-callers <n>` | Cap callers per node. |
| `--max-total <n>` | Cap total graph size. |
| `--format tree|flat|list` | Output style. |
| `--show-site` | Show call-site RVAs. |
| `--filter-dll <text>` | Restrict caller DLL names. |
| `--include-dir <dir>` | Add a directory of images to scan. |
| `--include-image <image>` | Add one explicit image to scan. |
| `--scan-exe` | Include EXE files in caller scanning. |
| `--include <glob>` | Include filter over the full scan list. |
| `--scope-file <glob>` | Filter files discovered through include directories. |
| `--exclude <glob>` | Exclude filter. |
| `--max-dll-size <mb>` | Skip images larger than this. |
| `--workers <n>` | Parallel worker count. |

`priority` opens the generated priority configuration. Use it to define preferred directories, module names, prefixes, and regexes for locate/caller workflows.

## PE Metadata

```powershell
resx peinfo .\sample.dll
resx sections .\sample.dll
resx eat .\sample.dll
resx iat .\sample.dll
resx pechk .\sample.dll
resx types .\sample.dll OBJECT_ATTRIBUTES
```

`peinfo` includes headers, sections, debug info, CLR data, load config, signer/version resource data where available, TLS callbacks, startup evidence, x64 runtime function/unwind summaries, and PE anomalies.

## Scan

```powershell
resx scan C:\Windows\System32\drivers --max-files 200
resx scan .\samples --json
resx scan .\samples --jsonl --extensions exe,dll,sys --max-candidates 20
```

| Flag | Description |
| --- | --- |
| `--jsonl` | Emit one JSON object per image. |
| `--extensions <list>` | Comma-separated extensions, default `exe,dll,sys`. |
| `--max-files <n>` | Cap files scanned. |
| `--max-file-mb <mb>` | Skip large images. |
| `--max-candidates <n>` | Cap fuzz candidates per image. |

Scan output is designed for triage and fuzzing prioritisation. Candidate scores are static heuristics.

## Diff, Index, and Hunt

```powershell
resx diff .\old.dll .\new.dll
resx diff .\old.dll .\new.dll --json
resx diff .\old.dll .\new.dll --show-cfg-diff auto
resx diff .\old.dll .\new.dll .\canary.dll --diff-graph
resx index .\samples --db .\samples.resxdb --no-pdb
resx hunt .\unknown.dll --db .\samples.resxdb --diff-threshold 70
```

| Flag | Description |
| --- | --- |
| `--diff-mode quick|balanced|deep` | Decode depth and cost profile. |
| `--diff-threshold <0-100>` | Minimum function match score, default `65`. |
| `--include-weak` | Include weak 50-64 candidates. |
| `--max-functions <n>` | Cap decoded functions per image. |
| `--left-pdb <file>` | Explicit PDB for the left image. |
| `--right-pdb <file>` | Explicit PDB for the right image. |
| `--show-cfg-diff <fn|rva|auto>` | Render one side-by-side CFG diff. |
| `--cfg-diff-format text|json|dot` | Output format for CFG diff. |
| `--cfg-diff-out <file>` | Write CFG diff to a file. |
| `--max-cfg-blocks <n>` | Cap CFG diff blocks. |
| `--diff-graph` | Emit a code/control-structure heatmap. |
| `--diff-graph-format text|json|dot` | Output format for diff graph. |
| `--diff-graph-out <file>` | Write graph output to a file. |
| `--db <file>` | Corpus index path for `index` and `hunt`. |

## YARA

```powershell
resx yara .\sample.dll .\rules\triage.yar
resx yara .\sample.dll .\rules\a.yar --yara .\rules\b.yar --json
```

The positional rule file is accepted by the `yara` command. Additional rule files can be supplied with repeated `--yara`.

## Search Paths and Resolution

| Flag | Description |
| --- | --- |
| `--path <dir>` | Add an image search path. |
| `--priority` | Open/edit the priority config. |
| `--no-system` | Do not search system locations. |
| `--no-cwd` | Do not search the current directory. |
| `--no-path` | Do not search `PATH`. |

## Examples

```powershell
resx dump kernel32.dll CreateFileW --recomp --bytes
resx dump kernel32.dll CreateFileW --funcs --xrefs
resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
resx cfg ntdll.dll --at 0x161F40
resx intelli suspicious.dll
resx peinfo .\blackbird.sys --json
resx syms .\J58.dll --pdb .\J58.pdb
resx reconstruct-cfg suspicious.dll --depth 6 --max-total 300
resx scan C:\Windows\System32\drivers --jsonl --max-files 200
resx diff .\old.dll .\new.dll --json
resx index .\samples --db .\samples.resxdb --no-pdb
resx hunt .\unknown.dll --db .\samples.resxdb --diff-threshold 70
resx explain NtQuerySystemInformation
```

## Verification

Before pushing CLI changes:

```powershell
cargo fmt -p resx -- --check
cargo clippy -p resx --all-targets -- -D warnings
cargo test -p resx
```
