# RESX Binary Viewer

RESX Binary Viewer is the Visual Studio Code extension for inspecting Windows PE binaries with the `resx` analysis engine.

It opens `.exe`, `.dll`, and `.sys` files in a custom editor and gives you a focused binary-analysis workspace inside VS Code.

## Features

- PE overview, sections, exports, imports, symbols, types, and triage views
- function dumps with CFG text, strings, xrefs, recompilation output, syscall stub annotations, and nested API call trees
- PDB loading controls and symbol search path configuration
- command palette lookup flow for `locate` and `locate-sym`
- direct open-and-jump navigation into resolved system binaries such as `ntdll.dll`

## Command Palette

Use the command palette with these commands:

- `RESX: Locate`
  Enter an API or export name such as `NtOpenProcess`.
- `RESX: Locate Symbol`
  Enter a symbol-oriented lookup such as `RtlpHeapHandleError`.
- `RESX: Dump`
  Pick a module from an autocomplete list, let the extension load exports plus PDB-backed symbols with progress, then jump straight into the dump view.

`Locate` and `Locate Symbol` resolve the target with the CLI, open the matching image, and jump directly into the resolved function or RVA.

## Screenshots

![RESX overview view](../media/Dump_Ntoskrnl_Overview.png)

![RESX disassembly view](../media/Dump_Disassembly_KiDispatchCallout.png)

![RESX API call tree](../media/Dump_ApiRefs_KiDispatchCallout.png)

![RESX syscall stub annotation](../media/Dump_ntdll_NtAllocateVirtualMemoryEx_Stub.png)

![RESX dump picker](../media/Dump_Search_KiDispatchCallout.png)

## Requirements

- Windows
- `resx.exe`

The extension resolves the analyzer in this order:

1. a bundled binary inside the extension package
2. `resx.executablePath` from user settings only, if `resx.allowCustomExecutable` is enabled

On Windows, the extension verifies the Authenticode signer before execution and only trusts the pinned TITAN Softwork Solutions signing certificate. The bundled binary is also pinned by SHA-256 through the extension trust manifest.

## Marketplace Metadata

- Publisher ID: `titan-softwork-solutions`
- Repository: `https://github.com/TITAN-Softwork-Solutions/RESX`

## Settings

- `resx.executablePath`: user-level override for a trusted `resx.exe`
- `resx.allowCustomExecutable`: opt in to user-supplied `resx.exe` overrides
- `resx.loadSymbolsOnOpen`: load PDB symbols automatically
- `resx.symbolPaths`: extra symbol search paths
- `resx.pdbFile`: explicit PDB file path

## Bundling `resx.exe`

If you want a self-contained VS Code install, place the executable in one of these locations before packaging:

- `bin/resx.exe`
- `bin/win32-x64/resx.exe`
- `bin/win32-arm64/resx.exe`

Those files will be included in the `.vsix` and used automatically.

## Development

```powershell
npm install
npm run compile
```

Press `F5` in VS Code to launch an Extension Development Host.

## Packaging

```powershell
npm run package
```

## Publishing

```powershell
npm run publish:vsce
```

You need a Visual Studio Marketplace publisher account and a Personal Access Token with Marketplace publish rights.
