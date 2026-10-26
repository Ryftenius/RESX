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
| `resx help` | Commands grouped by section |
| `resx help <command>` or `resx <command> --help` | Usage, examples, notes, and that command's options grouped by heading |
| `resx help <section>` | One section: `inspect`, `code`, `evidence`, `recovery`, `compare`, `options` |
| `resx help all` | Every command and option |

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
| Flow | `--depth`, `--max-callers` | `callers`, `reconstruct-cfg` |
| Search scope | `--include-dir`, `--include-image`, `--scan-exe`, `--include`, `--exclude`, `--scope-file`, `--filter-dll`, `--workers` | `callers`, `locate`, `locate-sym` |
| Matching | `--mode`, `--threshold`, `--include-weak`, `--max-functions`, `--max-candidates`, `--max-cfg-blocks` | `diff`, `index`, `hunt` |

Inside a command, options drop the prefix the command already implies:
`resx strings <image> --min-len 8`, `resx entropy <image> --window 2048`,
`resx diff <a> <b> --mode deep --graph`, `resx find <image> <query> --mode raw`.

## Output modes

Normal output presents conclusions and important limitations. `--verbose` adds
bounded evidence, function-boundary rationale, traversal limits, and representative
disassembly. `--diagnostic` implies verbose output and adds structured developer
events. `--diagnostic-trace` increases the developer event level to TRACE.

Diagnostics go to stderr. Analysis output retains its selected text, JSON, or
JSONL format on stdout or `--out`.

Color is enabled for an interactive terminal and disabled for redirected output
unless explicitly requested. Addresses, opcode bytes, mnemonics, operands,
selected instructions, warnings, errors, success markers, and confidence labels
use distinct semantic styles.

## Dump analysis

`dump` prints compact lowercase Intel-style disassembly and a function signature.
When PDB type information is unavailable, the signature is a bounded static ABI
inference and unknown types remain explicit. `--verbose` adds inference evidence
and conflicting-decode details. `--ssa` separately enables lightweight data-flow
annotations; it is off by default. Report sections such as `--xrefs`,
`--strings`, `--cfg text`, `--recomp` and `--calls` add to the same document.

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
existing scripts, FFI callers and the VS Code extension keep working. New
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

## String evidence controls

`resx strings <image>` defaults to 200 results and filters low-quality UTF-16
binary coincidences. Use `--encoding ascii|utf16le|both`, `--min-len <n>`,
`--limit <n>`, `--match <text>`, `--tag <tag>`, or `--interesting` to narrow
evidence. `--raw-wide` restores permissive UTF-16 candidates. Values such as
`TARGET_OK` are tagged `success-marker`; only brace-form tokens are tagged
`flag-candidate`.
