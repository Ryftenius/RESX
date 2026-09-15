# RESX DLL / FFI Integration

RESX can be built as both a CLI executable and a native DLL. The DLL exports a C ABI for tools that want RESX analysis without shelling out to `resx.exe`.

The public C header is:

```text
resx/include/resx.h
```

The Rust crate exposes an `rlib` and `cdylib`:

```toml
[lib]
name = "resx"
crate-type = ["rlib", "cdylib"]
```

## Build

```powershell
cargo build -p resx --release
```

Typical outputs:

```text
target/release/resx.exe
target/release/resx.dll
target/release/resx.lib
```

The exact import-library name depends on the Rust/MSVC toolchain.

## Header Usage

Include the header from C or C++:

```c
#include "resx.h"
```

All exported functions use UTF-8 strings. Every returned `char *` is allocated by RESX and must be released with:

```c
ResxFreeString(value);
```

Never release returned strings with `free`, `delete`, `CoTaskMemFree`, or another allocator.

## Status Codes

```c
typedef enum ResxStatus {
    RSX_STATUS_OK = 0,
    RSX_STATUS_NULL_ARGUMENT = 1,
    RSX_STATUS_INVALID_UTF8 = 2,
    RSX_STATUS_INVALID_JSON = 3,
    RSX_STATUS_INVALID_OPTIONS = 4,
    RSX_STATUS_EXECUTION_ERROR = 5,
    RSX_STATUS_PANIC = 255
} ResxStatus;
```

When a function fails, it still attempts to write a JSON error envelope to the output pointer.

## Output Envelopes

Typed analysis functions return JSON by default. The success envelope contains:

```json
{
  "schema_version": 1,
  "api_version": 1,
  "status": "ok",
  "status_code": 0,
  "command": "peinfo",
  "args": ["sample.dll", "--json", "--no-color", "--quiet"],
  "resx_version": "2.0.0",
  "payload": {}
}
```

If the underlying command emitted non-JSON text, the envelope contains `text` instead of `payload`.

Error envelopes contain:

```json
{
  "schema_version": 1,
  "api_version": 1,
  "status": "error",
  "status_code": 5,
  "error": "message",
  "resx_version": "2.0.0"
}
```

## Generic Entry Points

### `ResxRunArgs`

```c
RSX_API int ResxRunArgs(size_t argc, const char *const *argv, char **out_utf8);
```

Runs the CLI router directly. `argv` may include `resx` as `argv[0]` or start with a RESX command:

```c
const char *argv[] = {"peinfo", "sample.dll", "--json"};
char *out = NULL;
int status = ResxRunArgs(3, argv, &out);
/* use out */
ResxFreeString(out);
```

This function returns captured command output directly. Use `--json` when the caller needs machine-readable output.

### `ResxRunCommandJson`

```c
RSX_API int ResxRunCommandJson(const char *request_json, char **out_json);
```

Accepts a JSON request:

```json
{
  "command": "diff",
  "args": ["old.dll", "new.dll"],
  "options": {
    "no_pdb": true,
    "diff_mode": "balanced"
  }
}
```

or:

```json
{
  "argv": ["diff", "old.dll", "new.dll", "--json"],
  "options": {
    "quiet": true
  }
}
```

It returns a JSON envelope, parsing command JSON into `payload` when possible.

## Typed Analysis Exports

| Export | Purpose |
| --- | --- |
| `ResxVersion` | Returns version text. |
| `ResxHelp` | Returns FFI help text. |
| `ResxDump` | Dump/disassemble by function name. |
| `ResxDumpAt` | Dump/disassemble by RVA. |
| `ResxDumpOrdinal` | Dump/disassemble by export ordinal. |
| `ResxCfg` | CFG view by function name. |
| `ResxCfgAt` | CFG view by RVA. |
| `ResxCfgOrdinal` | CFG view by ordinal. |
| `ResxReconstructCfg` | Startup-flow reconstruction. |
| `ResxIntelli` | Image or function triage. |
| `ResxPeInfo` | PE metadata. |
| `ResxSections` | Section table and protection analysis. |
| `ResxPeCheck` | PE anomaly checks. |
| `ResxShowEat` | Export Address Table. |
| `ResxShowIat` | Import Address Table. |
| `ResxShowSyms` | Exports/PDB symbols. |
| `ResxTypes` | PDB-backed type browser. |
| `ResxFollowCallers` | Reverse caller tracing. |
| `ResxLocate` | Export-backed locate. |
| `ResxLocateSymbols` | Export/PDB-backed locate. |
| `ResxDiff` | Structural image diff. |
| `ResxCfgDiff` | Structural diff with one CFG diff target. |
| `ResxIndex` | Build a corpus index. |
| `ResxHunt` | Compare a sample against a corpus. |
| `ResxScan` | Folder scan and fuzz target ranking. |
| `ResxYara` | YARA scan. |
| `ResxPriority` | Priority config command. |
| `ResxUpdate` | Git update command. |

## Options JSON

Typed exports accept an optional `options_json` argument. It may be `NULL`, an empty string, or a JSON object.

Use CLI flag names in snake_case or kebab-case:

```json
{
  "json": true,
  "quiet": true,
  "no_pdb": true,
  "funcs_depth": 2,
  "cfg_view": "text",
  "show_strings": true,
  "show_xrefs": true
}
```

RESX maps common FFI option aliases:

| JSON key | CLI flag |
| --- | --- |
| `at_rva` | `--at` |
| `pdb_file` | `--pdb` |
| `out_file` | `--out` |
| `show_xrefs` | `--xrefs` |
| `show_strings` | `--strings` |
| `cfg_view` | `--cfg` |
| `diff_max_functions` | `--max-functions` |
| `left_pdb_file` | `--left-pdb` |
| `right_pdb_file` | `--right-pdb` |
| `cfg_diff_target` | `--show-cfg-diff` |
| `cfg_diff_format` | `--cfg-diff-format` |
| `cfg_diff_out` | `--cfg-diff-out` |
| `corpus_db` | `--db` |
| `scan_extensions` | `--extensions` |
| `scan_dirs` | `--include-dir` |
| `scan_dlls` | `--include-image` |
| `scope_file` | `--scope-file` |
| `max_dll_mb` | `--max-dll-size` |
| `follow_format` | `--format` |
| `reconstruct_thread_filter` | `--thread-filter` |
| `reconstruct_api_filter` | `--api-filter` |

Other keys are converted from underscores to kebab-case. For example, `max_total` becomes `--max-total`.

Boolean `true` adds a flag. Boolean `false` and `null` omit it. Strings and numbers add `--flag value`. Arrays repeat the flag.

Reserved meta keys:

```text
args
argv
cli_args
extra_args
command
json
color
quiet
```

`cli_args` and `extra_args` append raw CLI arguments after structured options:

```json
{
  "no_pdb": true,
  "cli_args": ["--max-insns", "1200"]
}
```

## Default FFI Flags

Typed JSON-returning exports request:

```text
--json --no-color --quiet
```

unless overridden in `options_json`.

Use:

```json
{
  "json": false,
  "quiet": false,
  "color": true
}
```

only if you intentionally want text output.

## Minimal C Example

```c
#include <stdio.h>
#include "resx.h"

int main(void) {
    char *json = NULL;
    int status = ResxPeInfo(
        "C:\\Windows\\System32\\kernel32.dll",
        "{\"no_pdb\":true}",
        &json
    );

    if (json) {
        puts(json);
        ResxFreeString(json);
    }

    return status == RSX_STATUS_OK ? 0 : 1;
}
```

## Dump Example

```c
char *json = NULL;
int status = ResxDump(
    "C:\\Windows\\System32\\kernel32.dll",
    "CreateFileW",
    "{\"recomp\":true,\"show_strings\":true,\"show_xrefs\":true}",
    &json
);

if (status == RSX_STATUS_OK) {
    /* parse json */
}
ResxFreeString(json);
```

## Command JSON Example

```c
const char *request =
    "{"
    "\"command\":\"scan\","
    "\"args\":[\"C:\\\\Windows\\\\System32\\\\drivers\"],"
    "\"options\":{\"max_files\":100,\"json\":true}"
    "}";

char *json = NULL;
int status = ResxRunCommandJson(request, &json);
/* parse json */
ResxFreeString(json);
```

## PowerShell Smoke Test

The repository includes a DLL smoke test scaffold:

```text
examples/resx_dll_smoke.c
examples/run-resx-dll-smoke.ps1
```

Run it after building the release DLL:

```powershell
.\examples\run-resx-dll-smoke.ps1
```

## Threading and Reentrancy

The FFI layer catches panics at the boundary and returns `RSX_STATUS_PANIC`. It initializes Rayon once if worker options require it. Calls are intended to be independent; callers should not mutate or free output buffers except through `ResxFreeString`.

For high-volume integration, prefer typed exports over repeatedly constructing arbitrary CLI strings. Keep JSON parsing tolerant of added fields.

## Safety Notes

- Pass valid UTF-8 strings.
- Pass a non-null output pointer.
- Release every returned string exactly once with `ResxFreeString`.
- Do not call `ResxFreeString` on memory not returned by RESX.
- Treat all analysis as static best-effort evidence.
- Use `--unsafe-map-image` only when you understand that the command may map the target image into the RESX process.

## Verification

```powershell
cargo fmt -p resx -- --check
cargo clippy -p resx --all-targets -- -D warnings
cargo test -p resx
```
