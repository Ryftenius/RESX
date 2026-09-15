# RESX command reference

`resx help all` is the authoritative generated list of commands and flags.

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

## Code and flow

| Command | Purpose |
| --- | --- |
| `dump <image> [target]` | Targeted disassembly and optional C-like reconstruction |
| `xrefs <image> <target>` | Incoming references |
| `cfg <image> <target>` | Function CFG |
| `reconstruct-cfg <image>` | Startup and reachable image flow |
| `callers <image> <target>` | Reverse caller tree |
| `intelli <image> [target]` | Bounded static intelligence report |
| `behavior <image>` | Static behavior indicators |

Targets accept export/symbol names, `rva:0x...`, `va:0x...`,
`file:0x...`, ordinals, and `image!symbol` syntax where applicable.

`dump` omits opcode bytes unless `--hex` is supplied. Use `--nodis` to omit
disassembly and `--verbose` for image and function-boundary details.

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
| `payload <file>` | Bounded operator-directed codec/AES-CBC decoding |
| `patch <image> <address> <bytes>` | Checked patch plan or new patched image |

Payload decoding records input/output hashes and enforces per-layer and aggregate
limits. Patch supports expected-byte checks, dry-run mode, separate output paths,
and optional checksum updates.

## Configuration

`priority`, `config`, `update`, and `symbols` manage local command behavior,
priority search paths, source-checkout updates, and symbol settings.

## Shared output

- `--json`, `--jsonl`, `--out <file>`
- `--verbose`, `--diagnostic`, `--diagnostic-trace`, `--quiet`
- `--color`, `--no-color`, `--time`
- `--pdb`, `--no-pdb`, `--sym-path`, `--sym-server`, `--reload`
- `--max-insns`, `--max-bytes`, `--depth`, and command-specific budgets

`--diagnostic` implies verbose output. `--diagnostic-trace` selects TRACE
developer events. Values are emitted at actual decision points and remain bounded.

Both standard and slash command syntax are accepted:

```powershell
resx dump ntdll.dll NtClose --hex --verbose
resx /dump ntdll.dll NtClose /hex /verbose
```
