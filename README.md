<h1 align="center">RESX</h1>
<p align="center"><b>Windows Binary Analysis & Reverse Engineering Toolkit</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/github/actions/workflow/status/RYFTENIUS/RESX/ci.yml?style=for-the-badge&label=CI" />
</p>

**RESX** is a Windows SRE & Binary Analysis utility designed to make **Reverse Engineers** and **Malware Analysts** lifes easier. **RESX** isn't trying to replace a fully-fledged disassembler such as [IDA](https://hex-rays.com/ida-pro), [Ghidra](https://github.com/nationalsecurityagency/ghidra) or [Binary Ninja](https://binary.ninja/), but is trying to make life easier. **RESX** provides quick PE analysis, deep function discovery and tracing (eg; finding which DLL a Windows API originates from, which also follows calls into the kernel), quick RE, binary difference fuzzing, kernel driver analysis & IOCTL recovery, intelligence and more!

## Documentation

- [CLI documentation](docs/cli.md)
- [VS Code extension documentation](docs/vscode-extension.md)
- [DLL / FFI integration](docs/dll.md)
- [Analysis surfaces](docs/analysis-surfaces.md)
- [JSON schemas](docs/json-schemas.md)
- [Contributing](CONTRIBUTING.md)
- [Security policy](SECURITY.md)

## Features

- PE metadata, section, data directory, debug, CLR, TLS, load config, signer/version, and anomaly inspection.
- Export Address Table and Import Address Table browsing.
- Export and PDB symbol loading, type browsing, and symbol-backed navigation.
- Targeted disassembly by name, RVA, or ordinal.
- Incoming call and jump xrefs for functions and imports.
- C-like reconstruction for selected functions.
- Basic CFG rendering for selected targets.
- Startup flow reconstruction from entry point, TLS callbacks, thread/workpool callbacks, import calls, indirect edges, and x64 unwind/exception-handler evidence.
- Static triage with hook/thunk indicators, string references, API call maps, and suspicious control-flow hints.
- Static behavior triage for syscall stubs, anti-analysis instructions, TLS callbacks, loader APIs, and executable-memory/JIT setup.
- Protected-file triage for packer markers, OEP handoff candidates, import rebuild leads, VM dispatcher/handler candidates, and layer-2 lift sketches.
- Terminal entropy maps over executable code with ASCII, zero-byte, unique-byte, and high/low entropy flags.
- Hostile-mode tracing for packed or deliberately confusing binaries.
- Reverse caller tracing across priority modules and custom scan scopes.
- Structural diffing, CFG diff views, code/control heatmaps, corpus indexing, and sample hunting.
- Kernel driver analysis, WDF inspection, and IOCTL recovery.
- Guarded byte patching by RVA, VA, or file offset.
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
resx xrefs <image> <function-or-import>
resx cfg <image> <function>
resx reconstruct-cfg <image>
resx intelli <image> [function]
resx behavior <image>
resx unpack <image>
resx entropy <image>
resx patch <image> --at <address> --patch-bytes <hex>
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

- `RESX: Open Binary File`
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
resx behavior .\sample.dll --json
resx unpack .\sample.dll --json
resx entropy .\sample.dll --json
resx dump .\sample.dll DllMain --json
resx reconstruct-cfg .\sample.dll --json
resx scan .\samples --json
resx diff .\old.dll .\new.dll --json
```

Where possible, RESX emits versioned JSON envelopes. Consumers should tolerate additional fields across releases.

## License

RESX is available under the [MIT License](LICENSE). You may use, modify, and distribute it provided the RYFTENIUS copyright and license notice are retained.
