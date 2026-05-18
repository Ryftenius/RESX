<h1 align="center">RESX</h1>
<p align="center"><b>Windows Binary Analysis & Reverse Engineering Toolkit</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/CLI-Tools-4CAF50?style=for-the-badge" />
  <img src="https://img.shields.io/github/actions/workflow/status/TITAN-Softwork-Solutions/RESX/ci.yml?style=for-the-badge&label=CI" />
  <a href="https://discord.gg/yUWyvT9JyP">
    <img src="https://img.shields.io/discord/1240608336005828668?label=TITAN%20Softworks&logo=discord&color=5865F2&style=for-the-badge" />
  </a>
</p>

RESX is a Windows binary analysis toolkit for PE inspection, export/import analysis, PDB-backed symbols, targeted disassembly, pseudo-C reconstruction, CFG recovery, startup-flow reconstruction, triage, structural diffing, corpus indexing, sample hunting, YARA scanning, and native DLL/FFI integration.

It ships as:

- A Rust CLI (`resx.exe`) for terminal and automation workflows.
- A VS Code binary viewer for `.exe`, `.dll`, and `.sys` files.
- A native DLL/FFI surface for host applications that want RESX analysis in-process.

## Documentation

- [CLI documentation](docs/cli.md)
- [VS Code extension documentation](docs/vscode-extension.md)
- [DLL / FFI integration](docs/dll.md)
- [Analysis surfaces](docs/analysis-surfaces.md)
- [JSON schemas](docs/json-schemas.md)

## What RESX Does

- PE metadata, section, data directory, debug, CLR, TLS, load config, signer/version, and anomaly inspection.
- Export Address Table and Import Address Table browsing.
- Export and PDB symbol loading, type browsing, and symbol-backed navigation.
- Targeted disassembly by name, RVA, or ordinal.
- C-like reconstruction for selected functions.
- Basic CFG rendering for selected targets.
- Startup flow reconstruction from entry point, TLS callbacks, thread/workpool callbacks, import calls, indirect edges, and x64 unwind/exception-handler evidence.
- Static triage with hook/thunk indicators, string references, API call maps, and suspicious control-flow hints.
- Hostile-mode tracing for packed or deliberately confusing binaries.
- Reverse caller tracing across priority modules and custom scan scopes.
- Structural diffing, CFG diff views, code/control heatmaps, corpus indexing, and sample hunting.
- Folder scanning with fuzz target candidate ranking.
- YARA scanning.
- Versioned JSON output for automation.

## Build The CLI

```powershell
cargo build --release
```

Run:

```powershell
.\target\release\resx.exe help
.\target\release\resx.exe version
```

Common commands:

```powershell
resx dump <image> <function>
resx dump <image> --at <rva>
resx cfg <image> <function>
resx reconstruct-cfg <image>
resx intelli <image> [function]
resx peinfo <image>
resx sections <image>
resx eat <image>
resx iat <image>
resx syms <image>
resx types <image> [query]
resx callers <image> <function>
resx locate <name>
resx locate-sym <name>
resx scan <path>
resx diff <old-image> <new-image>
resx index <dir-or-image> --db <file>
resx hunt <sample> --db <file>
resx yara <image> <rule.yar>
```

See [docs/cli.md](docs/cli.md) for the full command and option reference.

## Install The VS Code Extension

```powershell
cd resx-vscode
npm install
npm run compile
npm run package
```

Install the generated `.vsix` with:

```text
Extensions: Install from VSIX...
```

The extension contributes a custom editor for Windows binaries and command-palette workflows:

- `RESX: Refresh Binary Analysis`
- `RESX: Locate`
- `RESX: Locate Symbol`
- `RESX: Dump`
- `RESX: Reconstruct CFG`
- `RESX: Scan Folder`

The viewer includes Overview, Entry, Triage, Sections, Exports, Imports, Symbols, Types, Flow, Scan, Dump, and Dev tabs.

See [docs/vscode-extension.md](docs/vscode-extension.md) for build, packaging, settings, trust model, and workflow details.

## Use The DLL / FFI

Build the DLL:

```powershell
cargo build -p resx --release
```

Use the public header:

```text
resx/include/resx.h
```

Example C call:

```c
#include "resx.h"

char *json = NULL;
int status = RsxPeInfo(
    "C:\\Windows\\System32\\kernel32.dll",
    "{\"no_pdb\":true}",
    &json
);

if (json) {
    /* parse or print json */
    RsxFreeString(json);
}
```

See [docs/dll.md](docs/dll.md) for exported functions, status codes, option JSON, output envelopes, memory ownership, and smoke-test instructions.

## Screenshots

### VS Code Binary Viewer

![RESX VS Code overview](media/Dump_Ntoskrnl_Overview.png)

![RESX dump disassembly view](media/Dump_Disassembly_KiDispatchCallout.png)

![RESX dump API refs view](media/Dump_ApiRefs_KiDispatchCallout.png)

![RESX syscall stub view](media/Dump_ntdll_NtAllocateVirtualMemoryEx_Stub.png)

### Command Palette Workflows

![RESX dump file search](media/Dump_File_Search.png)

![RESX dump symbol search](media/Dump_Search_KiDispatchCallout.png)

![RESX locate result](media/Locate_OpenPro.png)

## JSON Automation

Use `--json` for machine-readable output:

```powershell
resx peinfo .\sample.dll --json
resx dump .\sample.dll DllMain --json
resx reconstruct-cfg .\sample.dll --json
resx scan .\samples --json
resx diff .\old.dll .\new.dll --json
```

Where possible, RESX emits versioned JSON envelopes. Consumers should tolerate additional fields across releases.

## Development Checks

Before pushing Rust changes:

```powershell
cargo fmt -p resx -- --check
cargo clippy -p resx --all-targets -- -D warnings
cargo test -p resx
```

Before pushing VS Code extension changes:

```powershell
cd resx-vscode
npx tsc -p ./ --noEmit
npx tsc -p ./tsconfig.webview.json --noEmit
node --experimental-default-type=module ./test/run-tests.mjs
```

Before packaging the extension:

```powershell
cd resx-vscode
npm run compile
npm run package
```

`resx-vscode/bin/`, `target/`, `target-resx-tests/`, generated packages, and local signing/build artifacts are ignored by git.

## Repository Layout

```text
resx/                 Rust CLI, library, FFI, analyzers, and tests
resx/include/         Public C header for DLL/FFI users
resx-vscode/          VS Code extension source and webview assets
docs/                 CLI, VS Code, DLL, schema, and analysis docs
examples/             FFI smoke-test examples
resx-palace/          Test/sample binaries used by RESX integration tests
media/                README screenshots
```

## Notes

RESX analysis is static best-effort evidence. Runtime dispatch, obfuscation, dynamically generated code, packed images, and data-dependent control flow can make static results incomplete. Use hostile-mode and startup-flow reconstruction as investigation aids, not as proof of runtime behaviour.
