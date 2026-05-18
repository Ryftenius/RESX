# RESX Analysis Surfaces

This document summarises the main analysis surfaces exposed by the CLI, VS Code extension, and DLL/FFI API.

## PE Metadata

Commands:

```powershell
resx peinfo <image>
resx sections <image>
resx pechk <image>
```

Data includes:

- DOS/NT headers and image identity.
- Machine type, subsystem, image base, entry point, section/file alignment, checksum, and DLL characteristics.
- Section ranges, entropy, raw/virtual sizes, protections, and expectation warnings.
- Data directory coverage.
- Debug and CodeView/PDB metadata.
- CLR metadata where present.
- Load config data such as security cookie and Guard CF/XFG fields.
- TLS callback table.
- Startup evidence such as PE entry point, TLS callbacks, CRT/XL pointers, conservative startup handoffs, and high-confidence real-main candidates.
- x64 runtime function/unwind summaries.
- Resource/version/signer metadata where available.
- Header/layout anomalies.

## Exports, Imports, and Symbols

Commands:

```powershell
resx eat <image>
resx iat <image>
resx syms <image>
resx types <image> [query]
```

RESX uses exports and PDB symbols for target resolution, function discovery, type browsing, locate workflows, and more readable disassembly/reconstruction output.

## Targeted Disassembly

Commands:

```powershell
resx dump <image> <function>
resx dump <image> --at <rva>
resx dump <image> --ordinal <n>
resx cfg <image> <function>
```

Analysis includes:

- Linear disassembly bounded by `--max-insns` and `--max-bytes`.
- Thunk and jump following.
- Function and API call maps.
- Recursive internal-call tracing with `--funcs-depth`.
- Incoming xrefs with `--xrefs`.
- Referenced strings with `--strings`.
- C-like reconstruction with `--recomp`.
- CFG rendering with `--cfg text`.
- Hostile-mode annotations with `--hostile`.

## Startup Flow Reconstruction

Command:

```powershell
resx reconstruct-cfg <image>
```

Flow reconstruction starts from loader-visible roots and bounded static evidence. It is not a full emulator.

Roots and edges may include:

- PE entry point.
- TLS callbacks.
- CRT/XL startup pointers.
- Conservative startup handoffs.
- Direct internal calls and jumps.
- Import/API calls.
- Thread creation and thread entry callbacks where statically resolvable.
- Workpool callback patterns where statically resolvable.
- Indirect edges when backed by resolvable code pointers.
- x64 unwind and exception-handler edges.

Use:

```powershell
resx reconstruct-cfg <image> --thread-filter spawned
resx reconstruct-cfg <image> --api-filter CreateThread
```

to focus large graphs.

## Intelli Triage

Command:

```powershell
resx intelli <image> [function]
```

Triage surfaces include:

- PE anomaly findings.
- Hook/thunk indicators.
- Suspicious section protections.
- Import/API signals.
- Startup execution evidence.
- Strings and function references where requested.

Findings are static signals. They are meant to prioritise review, not to prove maliciousness.

## Caller and Locate Workflows

Commands:

```powershell
resx priority
resx locate <name>
resx locate-sym <name>
resx callers <image> <function>
```

These workflows use the priority configuration plus optional include directories/images to locate and reverse-trace targets across a working set.

## Scan and Fuzz Candidate Ranking

Command:

```powershell
resx scan <path>
```

Scan walks PE files, applies size/extension limits, and emits per-image summaries plus ranked fuzz target candidates. It is intended for triage queues and harness planning.

## Structural Diff, Index, and Hunt

Commands:

```powershell
resx diff <old-image> <new-image> [more-images...]
resx index <dir-or-image> --db <file>
resx hunt <sample> --db <file>
```

Diffing uses normalized function fingerprints, basic block shape, API sets, constants, fuzzy hashes, and optional CFG diff/graph views.

Index and hunt reuse those fingerprints for corpus workflows.

## YARA

Command:

```powershell
resx yara <image> <rule.yar>
```

YARA output can be included in automation pipelines with `--json`.

## Output Contracts

Prefer JSON for automation:

```powershell
resx peinfo <image> --json
resx dump <image> <function> --json
resx scan <path> --json
```

JSON shapes are versioned where possible. Consumers should tolerate extra fields and should not depend on text formatting.
