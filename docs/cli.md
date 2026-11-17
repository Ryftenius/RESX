# CLI

```text
resx <command> [arguments] [options]
```

Every command has its own arguments and options. An option a command does not
use is an error, not a silent no-op, and a mistyped command or option gets a
suggestion:

```text
> resx dumpp .\agent.exe main
error: unrecognized subcommand 'dumpp'
  tip: a similar subcommand exists: 'dump'
```

Help is generated from the same grammar, so it always matches what a command
accepts:

| Command | Shows |
| --- | --- |
| `resx` or `resx help` | Commands grouped by section |
| `resx help <command>` or `resx <command> --help` | Usage, examples, notes, and that command's options grouped by heading |
| `resx help <section>` | One section: `inspect`, `code`, `evidence`, `recovery`, `compare`, `settings`, `options` |
| `resx help all` | Every command and option |

Unknown help topics return an error and suggest a nearby command or section.

## Option groups

Options shared by several commands live in named groups. Each command's help
lists the groups it takes, under these headings.

| Group | Options | Taken by |
| --- | --- | --- |
| Output | `--json`, `--out/-o`, `--verbose/-v`, `--quiet/-q`, `--diagnostic`, `--diagnostic-trace`, `--disasm-context`, `--debug-report`, `--time`, `--color`, `--no-color` | Every command, before or after it |
| Image lookup | `--path`, `--no-system`, `--no-cwd`, `--no-path`, `--arch`, `--rebase` | Every command that reads an image |
| Symbols | `--pdb`, `--sym-path`, `--sym-server`, `--reload`, `--no-pdb` | Every command that reads an image |
| Target | `<TARGET>`, `--at`, `--ordinal/-n` | `dump`, `calls`, `xrefs`, `cfg`, `intelli` |
| Analysis | `--max-insns`, `--max-total`, `--hostile` | Code, flow and comparison commands |
| Listing | `--bytes`, `--nodis`, `--ssa`, `--att`, `--rva`, `--offset`, `--max-bytes`, ... | `dump`, `xrefs`, `cfg`, `intelli` |
| Report sections | `--xrefs`, `--strings`, `--cfg`, `--recomp`, `--c-out`, `--intelli`, `--hookchk`, `--edrchk`, `--sections`, `--show-eat`, `--yara`, ... | `dump`, `xrefs`, `cfg`, `intelli` |
| Call tree | `--calls`, `--calls-only`, `--calls-exclude`, `--max-subcalls`, `--highlight` | `dump`, `xrefs`, `cfg`, `intelli` |
| Telemetry | `--telemetry`, `--telemetry-depth` | `dump`, `calls`, `xrefs`, `cfg`, `intelli` |
| Flow | `--depth`, `--max-callers` | `callers`, `reconstruct-cfg` |
| Search scope | `--include-dir`, `--include-image`, `--scan-exe`, `--include`, `--exclude`, `--scope-file`, `--filter-dll`, `--workers` | `callers`, `locate`, `locate-sym` |
| Matching | `--mode`, `--threshold`, `--include-weak`, `--max-functions`, `--max-candidates`, `--max-cfg-blocks` | `diff`, `index`, `hunt` |

Inside a command, options drop the prefix the command already implies:
`resx strings <image> --min-len 8`, `resx entropy <image> --window 2048`,
`resx diff <a> <b> --mode deep --graph`, `resx find <image> <query> --mode raw`.

## Output modes

| Mode | What you get |
| --- | --- |
| default | The conclusions and the limitations that matter |
| `--verbose` | Plus the evidence behind them, why function boundaries were chosen, traversal limits and sample disassembly |
| `--diagnostic` | Everything from `--verbose`, plus structured developer events |
| `--diagnostic-trace` | Developer events down to TRACE level |

Diagnostics always go to stderr. The analysis itself stays in whatever format you
picked (text, JSON or JSONL) on stdout or `--out`, so piping JSON never gets polluted.

Color is on in an interactive terminal and off when output is redirected, unless you
ask for it. Addresses, opcode bytes, mnemonics, operands, selected instructions,
warnings, errors, success markers and confidence labels each get their own style.

## Dump analysis

`dump` prints compact lowercase Intel-style disassembly and a function signature.
When PDB type information is unavailable, the signature is a bounded static ABI
inference and unknown types remain explicit. `--verbose` adds inference evidence
and conflicting-decode details. `--ssa` separately enables lightweight data-flow
annotations; it is off by default. Report sections such as `--xrefs`,
`--strings`, `--cfg text`, `--recomp` and `--calls` add to the same document.

## API arguments

Want to see what gets passed to an API? Add `--args`. Arguments stay hidden by
default in text and JSON, including `driver`, `ioctl`, and the contract commands.

```powershell
resx calls sample.exe ENTRY --only winapi --args --no-pdb
resx api VirtualAlloc
```

Set your Windows SDK Include directory with `resx config --headers <directory>`.
`api` looks up the SDK declaration; `--args` recovers call-site values.
Use `--no-headers` to skip SDK enrichment for one run.

## Call trees

`resx calls <image> <target>` prints the recursive API call tree for one
function: the calls it makes, and the calls made by the internal functions it
reaches, `--depth` levels deep (default 3). Import calls are leaves; internal
calls are traced further.

`--only` keeps matching calls, along with the internal calls on the path to
them, so a deep tree shows what the code reaches without the runtime noise.
`--exclude` drops matching calls and everything below them. Both take
comma-separated terms and can be repeated.

| Term | Matches |
| --- | --- |
| `winapi` | Imports outside the C/C++ runtime; runtime helpers are not traversed |
| `iat` | Every import, runtime included |
| `internal` | In-image calls only |
| `crt` | Runtime imports (`ucrtbase`, `vcruntime*`, `msvcp*`, `api-ms-win-crt-*`) and symbolized runtime helpers |
| `syscall` | `Nt*`/`Zw*` calls |
| `dynamic` | Calls through dynamically resolved APIs, and the resolver calls that produce them |
| `name.dll` | Imports from that DLL; the extension is optional and a trailing `*` matches a prefix |

```powershell
resx calls .\agent.exe main --depth 4 --only winapi
resx calls .\agent.exe main --only bcrypt.dll,ntdll
resx calls .\agent.exe main --only iat --exclude kernel32
resx calls .\agent.exe main --only dynamic
resx calls .\agent.exe rentry --no-pdb --only winapi --json
```

A repeat call to a function whose subtree is already shown is tagged
`[expanded above]`. Without a PDB, statically linked runtime helpers are
anonymous `sub_` functions, so `crt` and `winapi` recognize the runtime by its
imports alone.

Traced functions are decoded whole when their unwind extent is known. When a
function has more calls than `--max-subcalls` (default 64), system calls and
imports are rendered before internal calls and runtime helpers such as
`memset`, so a large function's transitions are not cut. `--max-total` bounds
how many functions one tree expands; the tree says when it is reached. In color
output, every user-to-kernel transition and its `kernel:` line is a red band.

### Telemetry reachability

`--telemetry` answers which telemetry a call can produce, and who can see it. It
searches breadth-first below the traced function: through internal calls,
imports into other system DLLs and system calls into the kernel, to
`--telemetry-depth` calls (default 10).

```powershell
resx calls KernelBase.dll CreateProcessW --depth 1 --telemetry
resx dump ntdll.dll NtWriteVirtualMemory --telemetry --json
```

| Kind | Examples | Consumers |
| --- | --- | --- |
| Kernel callbacks | `PspCallProcessNotifyRoutines`, `PsCallImageNotifyRoutines`, `ObpPreInterceptHandleCreate`, `CmpCallCallBacksEx` | Drivers registered with `PsSetCreateProcessNotifyRoutineEx`, `PsSetLoadImageNotifyRoutine`, `ObRegisterCallbacks`, `CmRegisterCallbackEx` |
| ETW Threat-Intelligence | `EtwTiLogAllocExecVm`, `EtwTiLogReadWriteVm` | Antimalware protected processes |
| ETW kernel providers | `EtwTraceProcess`, `EtwpTraceRegistry`, `EtwWrite`, `EtwTimLog*` | Kernel ETW sessions; WMI process and module trace subscriptions |
| Security auditing | `SeAuditProcessCreation`, `SepAdtLogAuditRecord` | The Security log when the audit subcategory is enabled; `EvtSubscribe` |
| Driver stacks | `IofCallDriver` | Filter drivers on the device, such as file-system minifilters |
| Change notifications | `CmpPostNotify`, `FsRtlNotifyFullReportChange` | `RegNotifyChangeKeyValue`, `ReadDirectoryChangesW`/`ExW` watchers |
| WMI, WFP, AMSI | `IoWMIWriteEvent`, `Fwpm*`, `AmsiScanBuffer` | WMI subscriptions, WFP auditing and callouts, AMSI providers |
| ETW user-mode providers | `EtwEventWriteTransfer`, TraceLogging and manifest writers | ETW sessions for the provider; emitted in the calling process |

The compact text report shows relevant candidates and a count of incidental paths hidden from the default view. A name-based heuristic marks paths through generic object cleanup, registry/file object handling, error handling, pool or scheduler tracing as incidental. Audit and exploit-mitigation paths are marked conditional. This classification is triage, not a control-flow or object-type proof. The default report groups relevant candidates by kind and shows each source, what it emits, who can consume it, and its shortest static call path. `--verbose` additionally shows the incidental paths. A live spinner on stderr shows search progress in a terminal. `--verbose` lists every source, including incidental paths, with its full path and relevance label. JSON retains all sources and adds `relevance`. With `--verbose` or `--json`, each source lists what it emits, its consumers, its origin (`kernel`, or
`in-process` when the calling process could suppress it), its call depth, and the
shortest path to it. `⇒` marks a system call and `↪` an import into another
image. When the traced API itself reads or registers for telemetry, such as
`RegNotifyChangeKeyValue`, `ReadDirectoryChangesExW`, `EvtSubscribe` or
`PsSetCreateProcessNotifyRoutineEx`, the report names it a consumer. JSON adds a
`telemetry` object to the `dump` document.

Kernel internals are recognized by name, so load ntoskrnl symbols
(`--sym-path`, `--sym-server`, or the cache) for full coverage; the report says
when they were missing. The search follows direct calls only: indirect calls,
COM, and the registered callbacks themselves are not traversed. Reachable is not
fired: whether a source emits depends on the path taken and on which providers,
sessions, callbacks and audit policies are enabled at run time.

### Dynamically resolved APIs

Calls through API pointers the image finds at run time are labeled with the API
instead of `[via rax]`, wherever the pointer is called: in the resolving
function, through a global API table filled elsewhere, or as a CFG-guarded tail
jump. The resolver call itself gets a `resolves:` line.

```text
├── 0x101F  CALL  sub_00001230 [internal]
│   resolves: kernel32!VirtualAlloc (export-table walk sub_00001230 · ror13-add hash 0x91AFCA54 · loader-list walk, djb2 hash 0x7040EE75)
├── 0x1054  CALL  kernel32!VirtualAlloc [dynamic · export-table walk sub_00001230 · ror13-add hash 0x91AFCA54 · ...]
```

Resolution is recovered statically, for x86 and x64, from:

- `GetProcAddress` and `LdrGetProcedureAddress` after `GetModuleHandle*`,
  `LoadLibrary*` or `LdrLoadDll`, including wrapper functions that forward
  their arguments, and lookups by ordinal.
- Names that are literals, built on the stack, or decoded at run time. Decoding
  covers single-byte and rolling XOR and additive ciphers over bytes or UTF-16,
  including compiler-vectorized decoders, and a decoded name counts only when it
  is a real export or module name on the analyzing system.
- Modules found by walking the PEB loader lists, functions found by parsing
  export tables or by reading import descriptors and IAT slots, whether in a
  helper function or inlined.
- Hashed names. The hash constants are inverted against the local system's
  export and module names with a catalog of common constructions (ror/rol with
  add or xor, djb2, sdbm, FNV-1/1a, CRC-32, Jenkins), widened with the rotate
  counts, multipliers and seeds found in the resolver's own code.

`resx behavior` grades the techniques an image uses, from least to most
suspicious: `loader-api-resolution` and `unrecovered-api-names` (low),
`stack-string-api-names` (medium), `encoded-api-names`, `export-table-walk`,
`import-table-walk`, `peb-module-walk` and `api-hashing` (high; a hand-walked
table without a loader-list walk or hashing is medium). Its JSON adds
`api_resolution`, a one-line verdict, and `resolved_apis`, every resolver call
with the module and API it produces, how each name was hidden, and the call
sites through the result.

`dump`, `xrefs`, `cfg` and `intelli` embed the same tree next to their other
sections: `--calls [DEPTH]` (default 1), `--calls-only` and `--calls-exclude`.
`--calls-only` or `--calls-exclude` without `--calls` traces 3 levels.

```powershell
resx dump .\agent.exe main --calls 4 --calls-only winapi --recomp
```

## Address forms

- `rva:0x1234`
- `va:0x180001234`
- `file:0x400`
- `--ordinal 12`
- `module.dll!Export`
- `entry` (declared entry point) and `rentry` (recovered startup/main candidate)

Bare hexadecimal values are interpreted according to the selected command and
reported coordinate system. Use explicit prefixes in automation.

## Input resolution

Explicit paths take precedence. Name lookup can search the current directory,
operator-provided `--path` directories, configured priority directories, PATH,
and applicable Windows system directories. `--no-cwd`, `--no-path`, and
`--no-system` disable those sources.

## Slash syntax and short forms

Every long option also has a dumpbin-style spelling, resolved against the
command being run: `/json`, `/out:file`, `/max-insns:200`.

```powershell
resx dump ntdll.dll NtClose --hex --verbose
resx /dump ntdll.dll NtClose /hex /verbose
```

`resx config --command-style slash` saves the preferred display style. Command
names are case-insensitive.

Two forms without a command remain for compatibility:

| Form | Runs |
| --- | --- |
| `resx <image> <target> [options]` | `dump` |
| `resx <name>` | `locate` |

## Earlier spellings

Option names from releases before per-command options are still accepted, so
existing scripts and FFI callers keep working. New
scripts should use the current names.

| Earlier | Current |
| --- | --- |
| `--funcs` | `--calls` |
| `--funcs-depth N`, `--call-depth N` | `--calls N` (inside `dump`), `--depth N` (`calls`) |
| `--funcs-filter a,!b`, `--call-filter` | `--calls-only a --calls-exclude b`, or `calls --only a --exclude b` |
| `strings --strings-min-len`, `--strings-limit`, `--strings-encoding`, `--strings-interesting`, `--strings-match`, `--strings-tag`, `--strings-raw-wide` | `--min-len`, `--limit`, `--encoding`, `--interesting`, `--match`, `--tag`, `--raw-wide` |
| `entropy --entropy-window`, `--entropy-stride`, `--entropy-all` | `--window`, `--stride`, `--all` |
| `find --find-mode`, `--find-encoded`, `--find-budget`, `--find <query>` | `--mode`, `--encoded`, `--budget`, `<query>` |
| `diff --diff-mode`, `--diff-threshold`, `--diff-graph`, `--diff-graph-format`, `--diff-graph-out` | `--mode`, `--threshold`, `--graph`, `--graph-format`, `--graph-out` |
| `diff --show-cfg-diff`, `--cfg-diff-format`, `--cfg-diff-out` | `--show-cfg`, `--cfg-format`, `--cfg-out` |
| `hunt --diff-threshold` | `--threshold` |
| `payload --payload-dir`, `--payload-offset`, `--payload-length` | `--out-dir`, `--offset`, `--length` |
| `patch --patch-bytes` | `--bytes`, or the hex as operands after the address |
| `yara <image> --yara <rules>` | `yara <image> <rules>...` |

Internal routing switches such as `--peinfo`, `--follow-callers`, `--locate`,
`--reconstruct-cfg` and `--resx-diff` are gone; use the command itself, for
example `resx peinfo <image>` instead of `resx <image> --peinfo`.

## Bounds and partial results

Every parser and analysis traversal has explicit limits. When a report is
truncated, it includes the relevant limit and does not present the result as a
complete image-wide conclusion.

Without `--max-insns`, a function whose unwind extent is known is decoded whole:
every instruction reachable by direct control flow inside that extent, within a
safety bound of 262,144 instructions. Other decodes keep the 500-instruction
default. An explicit `--max-insns N` is honored exactly, and `unlimited` (or
`--max-total unlimited`) means the safety bound, not a smaller cap.
Cross-reference searches sweep every executable byte of the image.

`callers` indexes at most 50,000 call sites across its scanned images by
default. If that limit is reached, the command exits with an explicit
incomplete-analysis error instead of returning a partial caller tree. Use
`--max-index-sites N` to set a limit from 1 to 250,000 for one run. This limit
also bounds expansion of wrapper callers; `--max-callers` limits only the
displayed callers per tree node.

## String evidence controls

`resx strings <image>` defaults to 2,048 results from a 32 MiB scan and filters low-quality UTF-16
binary coincidences. Use `--encoding ascii|utf16le|both`, `--min-len <n>`,
`--limit <n>`, `--scan-mb <n>`, `--match <text>`, `--tag <tag>`, or `--interesting` to narrow
evidence. `--raw-wide` restores permissive UTF-16 candidates. Values such as
`TARGET_OK` are tagged `success-marker`; only brace-form tokens are tagged
`flag-candidate`.

`resx config --strings-limit 4096` saves a result limit (1–32,768) for later
commands. `resx config --strings-scan-mb 64` saves a scan size (1–128 MiB) for
commands. `resx config --max-total 1000` saves the recursive traversal budget,
and `resx config --max-insns 1500` saves the per-function instruction budget.
`resx config --max-index-sites 100000` saves the `callers` index limit.
Use `unlimited` for the analyzer's safety bound on either analysis budget.
Command options override saved values for one run; `resx config --reset-limits`
restores the defaults. Saved nonzero analysis budgets may be at most 1,000,000.
