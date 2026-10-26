# RESX command reference

`resx help all` is the authoritative generated list of commands and options, and
`resx help <command>` shows one command's usage, examples and options. Options are
scoped per command; see [docs/cli.md](docs/cli.md#option-groups) for the shared
option groups.

## Inspection

| Command | Purpose |
| --- | --- |
| `peinfo <image>` | PE identity, directories, toolchain and hardening metadata |
| `sections <image>` | Section layout, permissions, entropy and mapping |
| `pechk <image>` | Structural and loader-relevant anomaly checks |
| `eat <image>` | Export table |
| `iat <image>` | Import table |
| `syms <image>` | Symbols |
| `types <image> [query]` | PDB-backed type browsing |
| `api <name>` | Windows SDK declaration, parameter types and SAL directions; requires configured headers |

## Code and flow

| Command | Purpose |
| --- | --- |
| `dump <image> [target]` | Targeted disassembly and optional C-like reconstruction |
| `calls <image> <target>` | Recursive API call tree, filterable with `--only`/`--exclude` |
| `xrefs <image> <target>` | Incoming references |
| `cfg <image> <target>` | Function CFG |
| `reconstruct-cfg <image>` | Startup and reachable image flow |
| `callers <image> <target>` | Reverse caller tree |
| `intelli <image> [target]` | Bounded static intelligence report |
| `behavior <image>` | Static behavior indicators, including how APIs are resolved at run time |

Targets accept export/symbol names, `rva:0x...`, `va:0x...`,
`file:0x...`, ordinals, and `image!symbol` syntax where applicable.

`dump` omits opcode bytes unless `--bytes` is supplied. Use `--nodis` to omit
disassembly and `--verbose` for image and function-boundary details. `--calls`,
`--xrefs`, `--strings`, `--cfg text` and `--recomp` add report sections.

## Evidence

| Command | Purpose |
| --- | --- |
| `contracts <image>` | API arguments and producer relationships |
| `ipc <image>` | Named pipe, ALPC, RPC, COM and mapping evidence |
| `network <image>` | Endpoint and socket/HTTP configuration candidates |
| `crypto <image>` | CNG/CAPI algorithms, providers, modes and arguments |
| `strings <image>` | Bounded ASCII and UTF-16LE extraction |
| `driver <image>` | Driver dispatch, capabilities and virtualization primitives |
| `ioctl <image>` | IOCTL/NDIS argument and request evidence |
| `entropy <image>` | Section/window entropy visualization |

These commands report static evidence. They do not claim that an observed API,
string, instruction, or configuration executed.

## Search and comparison

| Command | Purpose |
| --- | --- |
| `yara <image> <rules>` | YARA-compatible scan |
| `find <image> <pattern>` | Bytes, text, constants and instruction patterns |
| `scan <path>` | Bounded PE corpus inventory |
| `diff <a> <b> [c...]` | Structural image/function comparison |
| `index <path> --db <file>` | Create a reusable corpus index |
| `hunt <sample> --db <file>` | Rank similar indexed images |
| `locate <name>` | Resolve image/export names |
| `locate-sym <name>` | Deeper symbol search |

## Explicit transformations

| Command | Purpose |
| --- | --- |
| `payload <file> --out-dir <dir>` | Bounded operator-directed codec/AES-CBC decoding |
| `patch <image> <address> <hex>` | Checked patch plan or new patched image |

Payload decoding records input/output hashes and enforces per-layer and aggregate
limits. Patch supports expected-byte checks, dry-run mode, separate output paths,
and optional checksum updates.

## Configuration

`priority`, `config`, `update`, and `symbols` manage local command behavior,
priority search paths, source-checkout updates, and symbol settings.

`config --headers <directory>` saves a Windows SDK Include directory for optional
enrichment of `dump`, `calls`, and `behavior`. Add `--args` to opt in for each run;
the default output omits argument enrichment. `config --headers off` disables it;
`--no-headers` overrides `--args` for one analysis. `api VirtualAlloc --json` returns the
header declaration and its source. Recovered arguments are static inferences;
unknown values remain `?`. Header preprocessing and floating-point argument
recovery are not supported.

With `--args`, SDK callback parameters pointing into file-backed executable
sections display as `&fn_0x<RVA>` rather than `&data_<VA>`. JSON preserves the VA,
RVA, callback typedef and evidence: this is API-contract inference, not a recovered
function-body prototype or proof of execution. Unresolved and non-executable
targets are not promoted to callbacks. `BCryptGenRandom` flags use the SDK's RNG
constant names and retain unknown bits numerically.

`calls --args` puts parameters in a separate `args` subtree, with one aligned parameter
per row, neutral text, and spacing between argument blocks. Long values wrap;
empty argument blocks are omitted and routine IAT provenance is hidden. Add
`--verbose` for import-resolution details and the inferred function signature.
`--no-headers` keeps the call tree while omitting SDK parameter enrichment.

## Shared options

Recovered call arguments require `--args` (or `/args`) across `dump`, `calls`,
`intelli`, `xrefs`, `cfg`, `behavior`, `driver`, `ioctl`, `contracts`, `ipc`,
`network`, and `crypto`, including JSON output where supported. Main findings
and flow summaries remain visible without it. `--no-headers` disables SDK
enrichment only; it does not disable the older driver/contract argument reports.
Explicit prototype/type lookups such as `api` still show the requested information.

Every command accepts the output options, before or after the command:

- `--json`, `--out <file>`; `scan` also takes `--jsonl`
- `--verbose`, `--diagnostic`, `--diagnostic-trace`, `--quiet`
- `--color`, `--no-color`, `--time`

Every command that reads an image also accepts the image lookup (`--path`,
`--no-system`, ...) and symbol (`--pdb`, `--no-pdb`, `--sym-path`, `--sym-server`,
`--reload`) options. Budgets such as `--max-insns`, `--max-total` and `--depth`, and
every other option, belong to the commands that use them.

`--diagnostic` implies verbose output. `--diagnostic-trace` selects TRACE
developer events. Values are emitted at actual decision points and remain bounded.

Both standard and slash command syntax are accepted:

```powershell
resx dump ntdll.dll NtClose --hex --verbose
resx /dump ntdll.dll NtClose /hex /verbose
```
