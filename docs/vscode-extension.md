# RESX VS Code Extension

The RESX VS Code extension is a binary viewer and analysis workbench for Windows PE images (`.exe`, `.dll`, `.sys`, and opt-in PE-formatted `.bin` samples), backed by the bundled `resx.exe`.

Open a binary to inspect PE metadata, exports, imports, symbols and types. Jump into disassembly with call maps, CFGs, C-like reconstruction, xrefs and callers. Run behavior triage, API contract evidence, driver and IOCTL recovery, strings, entropy, find and YARA on the same image. Diff images, hunt similar samples in a corpus, decode payloads and plan checked patches from the command palette.

Every view is static analysis. Findings describe what the code can do, not what ran.

## Build and Package

From the repository root:

```powershell
cd resx-vscode
npm install
npm run compile
npm run package
```

Install the generated `.vsix` with **Extensions: Install from VSIX...**.

Tests compile the extension, run unit tests, then run every argument list the extension builds against a real analyzer:

```powershell
npm test
```

The analyzer test uses `RESX_EXE` (default: `..\target\release\resx.exe`, then the bundled binary) and `RESX_SAMPLE` (default: `..\quiet_target.exe`). It is skipped when neither is present.

## Bundled Analyzer

The extension runs:

```text
resx-vscode/bin/win32-x64/resx.exe
```

The bundled binary is ignored by git. Its trust metadata is `resx-vscode/bin/trust.json`. At runtime the extension checks the binary against the pinned SHA-256. A binary signed by a trusted signer is accepted; an unsigned bundled binary is accepted only when its pinned hash matches.

The extension requires RESX 2.2 or later. To rebuild the bundled analyzer:

```powershell
cargo build -p resx --release
Copy-Item ..\target\release\resx.exe .\bin\win32-x64\resx.exe -Force
(Get-FileHash -Algorithm SHA256 .\bin\win32-x64\resx.exe).Hash.ToLower()
```

Put the hash in `bin/trust.json` under `bundledSha256["win32-x64/resx.exe"]`. Sign release binaries before packaging.

## Security Model

By default the extension runs only the bundled analyzer. Custom analyzers must be enabled in user settings:

```json
{
  "resx.allowCustomExecutable": true,
  "resx.executablePath": "C:\\Tools\\resx.exe"
}
```

Workspace values for these two settings are ignored.

The viewer webview never supplies command-line arguments. It requests a report by name, and the extension validates each parameter (numbers are clamped, enumerations checked, addresses and call-filter terms matched against fixed patterns) before building the argument list. Operands follow `--`, so a query or path beginning with `-` is never read as an option. Each command receives only the options it accepts.

Payload decoding always writes to a new directory. Patching writes a separate copy after a dry-run plan and a confirmation dialog; the extension never patches in place.

## Settings

| Setting | Default | Description |
| --- | --- | --- |
| `resx.executablePath` | `""` | Machine-scope path to a trusted `resx.exe` override. |
| `resx.allowCustomExecutable` | `false` | Allows `resx.executablePath`. |
| `resx.loadSymbolsOnOpen` | `false` | Load PDB symbols and types when opening a binary. |
| `resx.symbolPaths` | `[]` | Symbol search paths, joined with `;` into one `--sym-path`. |
| `resx.symbolServer` | `""` | Symbol server URL passed as `--sym-server`. |
| `resx.pdbFile` | `""` | Explicit PDB (`--pdb`) for the opened image only, not for modules reached by navigation. |
| `resx.imagePaths` | `[]` | Image lookup directories (`--path`) for navigation into imported modules and the Locate/Dump pickers. |
| `resx.apiArguments` | `false` | Recover API call arguments (`--args`) in dumps, behavior and evidence reports. Toggle per viewer. |
| `resx.useSdkHeaders` | `true` | When off, passes `--no-headers`. |
| `resx.hostile` | `false` | Start viewers in hostile mode (`--hostile`). Toggle per viewer. |
| `resx.callDepth` | `1` | Default call-map depth (`--calls N`, 1-8). |
| `resx.maxInstructions` | `500` | Per-function instruction budget (`--max-insns`); `0` is unlimited. |
| `resx.scanMaxFiles` | `200` | Images inventoried by Scan Folder (`--max-files`). |
| `resx.timeoutSeconds` | `120` | Seconds before a RESX process is stopped. |

Changing a setting updates open viewers. Per-viewer toggles (hostile, arguments, SSA, call depth, call filters) live in the viewer's **Options** panel.

## Windows SDK Headers

Recovered call arguments and API prototypes use a Windows SDK `Include` directory saved in RESX's own preferences. Run **RESX: Configure Windows SDK Headers**. It lists installed Windows Kits and runs `resx config --headers <dir>`; **Disable** runs `resx config --headers off`.

Then enable **Recover arguments** in a viewer or set `resx.apiArguments`. Without headers, `--args` still recovers argument slots but cannot name parameters.

## Opening Binaries

`.exe`, `.dll` and `.sys` open in the viewer by default. For `.bin`, `.efi`, `.scr`, `.cpl`, `.ocx` and `.drv`, use **Open With... -> RESX Binary Viewer** or **RESX: Open Binary File** (also in the explorer context menu).

On open the viewer runs `peinfo`, `eat`, `iat`, `pechk`, `intelli`, `syms` and `types`. Without `resx.loadSymbolsOnOpen`, these run with `--no-pdb` so opening stays fast. Use **Symbols** in the viewer to load PDBs on demand.

## Viewer Tabs

| Tab | RESX command | Content |
| --- | --- | --- |
| Overview | `peinfo` | PE identity, toolchain, mitigations, debug and signer metadata, anomalies. |
| Entry | `peinfo` | Entry point, TLS callbacks, startup evidence and main candidates. |
| Triage | `intelli`, `pechk` | Heuristic findings, startup execution evidence and PE validation findings. |
| Behavior | `behavior` | Findings grouped by category and severity with evidence and sites; how APIs are resolved at run time; dynamically resolved APIs and their call sites. |
| Sections | `peinfo` | Section layout, entropy and protection expectations. |
| Exports / Imports | `eat`, `iat` | Export and import tables with navigation into disassembly. |
| Symbols / Types | `syms`, `types` | PDB symbols and type browser. |
| Strings | `strings` | ASCII and UTF-16LE strings with minimum length, limit, encoding, text, tag and "interesting" filters. |
| Evidence | `contracts`, `ipc`, `network`, `crypto` | API call contracts with reconstructed calls, IPC channels, network requests, crypto configurations and string indicators. |
| Driver | `driver` | Shown for drivers: dispatch routines, IOCTL codes (device type, function, method, access, handler), dispatch candidates, capabilities, device, registry and callback APIs, virtualization evidence. |
| Entropy | `entropy` | Window entropy chart over sections; click to disassemble at a window. Window, stride and all-sections controls. |
| Search | `find`, `yara`, `diff`, `api` | Byte, text, constant and instruction search; YARA rules; compare with another image; SDK prototype lookup. |
| Flow | `reconstruct-cfg` | Startup roots, call, import, thread, workpool and exception edges. |
| Scan | `scan` | Folder inventory with risk imports and fuzz-target candidates. |
| Dump | `dump`, `callers` | Disassembly and sub-tabs (see below). |
| Dev | - | Every RESX invocation with arguments, duration, errors and stderr. |

Report tabs run the first time they are opened and offer **Re-run**, **Cancel** and **Open JSON**. Tables sort by column and filter by regular expression. Addresses open disassembly.

## Dump View

Clicking an export, import, symbol, address, call target, xref or finding opens a dump:

```text
resx dump <image> <target> --bytes --cfg text --strings --xrefs --recomp --calls <depth> [--args] [--hostile] [--ssa] [--calls-only ...] [--calls-exclude ...]
```

| Sub-tab | Content |
| --- | --- |
| Disasm | Annotated listing with branch arrows, syscall labels, type links and search. |
| API Calls | Call map to the selected depth. Dynamically resolved calls show how they were resolved; with arguments enabled, each call shows its recovered SDK call. |
| Xrefs | Incoming references. |
| Callers | Reverse caller tree (`resx callers`) across the image lookup order. Available for named functions (exports, PDB symbols, imports). |
| Strings, CFG, Recomp, Hex | String references, graph, C-like reconstruction and opcode bytes. |

The header shows the inferred or PDB prototype, overlapping-decode and dynamic-API counts, and buttons for **Callers**, **Open Recomp**, **Open JSON**, and following import slots or syscalls into their implementing module. Forwarded exports are followed automatically. Back and forward history is kept per viewer.

## Commands

| Command | Behaviour |
| --- | --- |
| Open Binary File | Opens an image in the viewer. |
| Refresh Binary Analysis | Re-runs the active viewer's analysis (also in the editor title bar). |
| Locate Export / Locate Symbol | Searches exports, or exports and PDB symbols, then opens the result. |
| Dump Function | Picks a system or workspace module and an export, symbol or RVA. |
| Behavior Triage, API Contract Evidence, Strings, Entropy, Driver and IOCTL Analysis, Find YARA and Compare, Reconstruct Startup Flow | Opens the corresponding viewer tab for the active viewer or a chosen image. |
| Compare Images (Diff) | Diffs two or more images (explorer multi-select works) with a matching profile; renders matches, changed regions, hotspots, section entropy and metadata differences. Function links open either image at the function. |
| Scan Folder | Corpus inventory in a report panel. |
| Index Folder as Corpus / Find Similar Images in Corpus | `index` a folder into a corpus database, and `hunt` ranks indexed images against a sample. |
| Decode Payload | Applies a codec (auto, zlib, gzip, deflate, base64, hex, AES-CBC with key file and IV) to a file or byte range and writes each layer to a new directory, with hashes. |
| Patch Image Bytes | Plans a patch with an optional expected-bytes check and checksum update, shows the plan, and writes a separate patched copy after confirmation. |
| Look Up Windows API Prototype | `resx api` declaration, parameters and SAL directions. |
| Configure Windows SDK Headers | Saves or disables the SDK include directory. |
| Show Analyzer Version | Shows the analyzer version and path. |

The explorer context menu offers Open, Behavior Triage, Driver (for `.sys`), Compare (multi-select), Find Similar, Patch, Decode Payload, Scan Folder and Index Folder.

## Generated Webview Files

Webview source is in `resx-vscode/media-src/` and compiles to `resx-vscode/media/`. The generated files are committed; run `npm run compile` after editing webview sources.

| Source | Role |
| --- | --- |
| `src/cli.ts` | Command catalog and option groups (mirrors `resx/src/cli/args.rs`), argument building and JSON envelope handling. |
| `src/reports.ts` | Validated plans for viewer report requests. |
| `src/editor.ts` | Binary viewer provider. |
| `src/reportPanel.ts` | Standalone report panel for diff, hunt, index, scan, payload, patch and API lookups. |
| `media-src/main.ts` | Viewer webview. |
| `media-src/reports.ts` | Report renderers shared by the viewer and the report panel. |

When RESX adds an option group or command, update `src/cli.ts` and the integration cases in `test/run-tests.mjs`.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| Analyzer is not trusted | Verify the bundled binary hash in `bin/trust.json`, or enable and configure a trusted custom executable. |
| `unexpected argument` errors in the Dev tab | The analyzer is older than the extension expects; rebuild the bundled analyzer. |
| PDB data is missing | Set `resx.symbolPaths`, `resx.symbolServer` or `resx.pdbFile`, or use the viewer's Symbols panel. |
| Arguments show as unknown | Configure SDK headers and enable Recover arguments; unrecoverable values stay `?` by design. |
| Callers is unavailable | Callers needs a named function; load PDB symbols to name internal functions, or use Xrefs. |
| Reports time out on large images | Raise `resx.timeoutSeconds` or lower `resx.maxInstructions`. |
| Driver tab missing | It appears for native-subsystem images and `.sys` files; run **RESX: Driver and IOCTL Analysis** to force it. |

## Release Checklist

```powershell
cd resx-vscode
npm install
npm test
npm run package
.\bin\win32-x64\resx.exe --version
Get-FileHash -Algorithm SHA256 .\bin\win32-x64\resx.exe
Get-AuthenticodeSignature .\bin\win32-x64\resx.exe
```
