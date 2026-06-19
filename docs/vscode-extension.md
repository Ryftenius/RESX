# RESX VS Code Extension

The RESX VS Code extension provides a custom binary viewer for Windows PE images (`.exe`, `.dll`, and `.sys`), plus opt-in support for PE-formatted `.bin` samples, all backed by the bundled `resx.exe`.

It is built for repeated reversing work: open a binary, inspect PE metadata, jump from exports/imports/symbols into disassembly, run targeted dumps, review startup flow, and scan folders without leaving VS Code.

## Build and Package

From the repository root:

```powershell
cd resx-vscode
npm install
npm run compile
npm run package
```

Install the generated `.vsix` through VS Code:

```text
Extensions: Install from VSIX...
```

For development type-checks without writing generated webview files:

```powershell
npx tsc -p ./ --noEmit
npx tsc -p ./tsconfig.webview.json --noEmit
node --experimental-default-type=module ./test/run-tests.mjs
```

## Bundled Analyzer

The extension uses:

```text
resx-vscode/bin/win32-x64/resx.exe
```

The bundled binary is intentionally ignored by git. Its trust metadata is:

```text
resx-vscode/bin/trust.json
```

At runtime the extension verifies the bundled binary against the pinned SHA-256 in `trust.json`. A signed binary matching the configured trusted signer is accepted, and an unsigned bundled binary is accepted only when its pinned hash matches.

If you rebuild the bundled analyzer locally:

```powershell
cargo build -p resx --release
Copy-Item ..\target\release\resx.exe .\bin\win32-x64\resx.exe -Force
Get-FileHash -Algorithm SHA256 .\bin\win32-x64\resx.exe
```

Then update `bin/trust.json` locally. The `bin/` folder is ignored, so packaging or release automation must include the intended binary.

## Security Model

By default the extension runs only the bundled analyzer.

Custom analyzer overrides are disabled unless explicitly enabled:

```json
{
  "resx.allowCustomExecutable": true,
  "resx.executablePath": "C:\\Tools\\resx.exe"
}
```

Use a custom executable only when you trust the binary. The extension performs trust checks before execution and does not permanently cache failed verification results.

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `resx.executablePath` | `""` | Machine-scope path to a trusted `resx.exe` override. |
| `resx.allowCustomExecutable` | `false` | Allows `resx.executablePath`. Disabled by default. |
| `resx.loadSymbolsOnOpen` | `false` | Automatically load PDB symbols when opening a binary. |
| `resx.symbolPaths` | `[]` | Extra symbol search paths passed as `--sym-path`. |
| `resx.pdbFile` | `""` | Explicit PDB file passed as `--pdb`. |

Symbol loading can be slow against large stores. Leave `resx.loadSymbolsOnOpen` disabled for fast opening, then use symbol-backed workflows when needed.

## Opening Binaries

The extension opens these file types by default:

```text
*.exe
*.dll
*.sys
```

For PE samples stored as `.bin`, the extension exposes RESX as an explicit editor option:

```text
*.bin
```

Open `.exe`, `.dll`, or `.sys` files normally, or use:

```text
Open With... -> RESX Binary Viewer
```

For `.bin` PE samples, use either:

```text
Open With... -> RESX Binary Viewer
RESX: Open Binary File
```

On load, the viewer runs the baseline analysis:

```text
peinfo
eat
iat
intelli
syms
types
```

If `resx.loadSymbolsOnOpen` is false, symbol and type loading uses `--no-pdb` or an empty result where appropriate so the viewer stays responsive.

## Viewer Tabs

| Tab | Data |
| --- | --- |
| Overview | PE summary, anomalies, runtime/toolchain hints, imports/exports counts. |
| Entry | PE entry point, TLS callbacks, conservative startup evidence, expected main candidates. |
| Triage | Intelli findings plus startup execution evidence. |
| Sections | Section layout, entropy, protections, and expectation warnings. |
| Exports | Export Address Table with jump-to-dump behaviour. |
| Imports | Import Address Table with grouped DLL/API references. |
| Symbols | Export/PDB symbol list and symbol navigation. |
| Types | PDB-backed type browser and symbol references. |
| Flow | On-demand `reconstruct-cfg` startup flow view. |
| Scan | On-demand folder scan and fuzz target candidate view. |
| Dump | Targeted disassembly/reconstruction results. |
| Dev | RESX command trace history for debugging extension behaviour. |

The active tab, selected dump state, sidebar widths, Flow tab, and Scan tab are persisted across viewer reloads.

## Dump Workflows

From inside the viewer, clicking an export, symbol, RVA link, call target, or xref opens a Dump view. Dump requests include:

```text
dump <target> --cfg text --funcs-depth <n> --strings --xrefs --recomp
```

The Dump view shows:

- Disassembly.
- Basic CFG output when available.
- C-like reconstruction when available.
- API call map and recursive function depth.
- String references.
- Incoming xrefs.
- Type links where PDB type data is available.

The viewer supports a hostile-mode toggle for dump requests. Hostile mode passes `--hostile`, which enables more aggressive tracing and suspicion annotations for hostile or obfuscated binaries.

## Flow Tab

The Flow tab runs:

```text
resx reconstruct-cfg <image>
```

It renders:

- Startup roots.
- Entry/TLS flow.
- Direct and import call edges.
- Thread and workpool callback edges where statically resolvable.
- x64 unwind/exception-handler edges where present.
- Function discovery and PDB status.
- Raw JSON access for deeper review.

The command runs on demand the first time the Flow tab is selected. Use the Re-run button to refresh the flow without reopening the editor.

## Scan Tab

The Scan tab can scan:

- The current binary's folder.
- A selected folder through Browse.

It runs:

```text
resx scan <folder>
```

The tab summarises discovered images, anomaly signals, and ranked fuzz target candidates. It is intended for triage and prioritisation, not proof of exploitability.

## Command Palette Commands

| Command | ID | Behaviour |
| --- | --- | --- |
| Open Binary File | `resx.openBinaryFile` | Opens a selected PE image in the RESX viewer, including `.bin` samples. |
| Refresh Binary Analysis | `resx.refreshBinary` | Re-runs analysis in the active RESX binary viewer. |
| Locate | `resx.locate` | Searches export-backed priority modules, then opens the selected result. |
| Locate Symbol | `resx.locateSymbol` | Searches exports and PDB symbols, then opens the selected result. |
| Dump | `resx.dump` | Lets you pick a module and target, then opens the binary viewer at that target. |
| Reconstruct CFG | `resx.reconstructCfg` | Runs `reconstruct-cfg` for a selected image and opens JSON output. |
| Scan Folder | `resx.scan` | Runs `scan` for a selected folder and opens JSON output. |

## Locate and Dump Picker

The command palette uses a module cache seeded with common Windows DLLs:

```text
ntdll.dll
kernel32.dll
kernelbase.dll
advapi32.dll
user32.dll
gdi32.dll
ws2_32.dll
ole32.dll
combase.dll
rpcrt4.dll
crypt32.dll
bcrypt.dll
secur32.dll
shell32.dll
shlwapi.dll
wininet.dll
winhttp.dll
netapi32.dll
iphlpapi.dll
```

It resolves modules through RESX, then uses EAT and symbol data to populate target pickers.

## Refresh Behaviour

`RESX: Refresh Binary Analysis` posts a refresh request to the active viewer. The viewer clears current analysis panels, clears caches, resets on-demand Flow/Scan state, and reruns the baseline analysis commands.

If no RESX viewer is active, the command shows an information message instead of reverting the editor.

## Generated Webview Files

Source lives in:

```text
resx-vscode/media-src/
```

Generated browser JavaScript lives in:

```text
resx-vscode/media/
```

When editing webview TypeScript, update both generated files through `npm run compile` before packaging. If a sandbox blocks writes to `media/*.js`, run:

```powershell
npx tsc -p ./tsconfig.webview.json --noEmit
```

Then compile outside the sandbox before release.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Viewer says analyzer is not trusted | Verify the bundled binary hash in `bin/trust.json`, or enable and configure a trusted custom executable. |
| PDB data is missing | Set `resx.symbolPaths`, `resx.pdbFile`, or enable `resx.loadSymbolsOnOpen`. |
| Opening is slow | Disable `resx.loadSymbolsOnOpen` and load symbols only when needed. |
| Flow tab is empty | Re-run Flow and check Dev tab command traces. |
| Scan tab scans the wrong folder | Use Browse in the Scan tab or the `RESX: Scan Folder` command. |
| `npm run compile` fails with `EPERM` | Check file permissions and sandbox restrictions around `resx-vscode/media/*.js`. |

## Release Checklist

```powershell
cd resx-vscode
npm install
npm run compile
node --experimental-default-type=module ./test/run-tests.mjs
npm run package
```

Also verify the bundled analyzer:

```powershell
.\bin\win32-x64\resx.exe --version
Get-FileHash -Algorithm SHA256 .\bin\win32-x64\resx.exe
```
