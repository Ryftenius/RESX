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
resx xrefs <image> <function-or-import>
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

## Behavior Triage

Command:

```powershell
resx behavior <image>
```

Behavior triage scans the whole image statically for anti-analysis, loader, direct-syscall, TLS, and generated-code signals.

Findings may include:

- Direct syscall or syscall-stub-like instruction windows.
- CPUID, timing, descriptor-table, breakpoint, and trap-flag related instructions.
- TEB/PEB segment accesses that may indicate loader walking or anti-debug checks.
- TLS callbacks and early loader-invoked code.
- Dynamic loader APIs such as `LoadLibrary`, `GetProcAddress`, and `Ldr*` imports/callsites.
- Executable-memory APIs, writable executable sections, and nearby memory-write or indirect-flow clusters.

This is a static evidence surface. It can identify suspicious ingredients and code neighborhoods, but runtime-generated code still requires dynamic tracing or sandbox evidence to prove execution.

## Unpack And VM Triage

Command:

```powershell
resx unpack <image>
```

Unpack triage scans the image for protected-file signals and emits practical follow-on targets for malware-analysis workflows.

Findings may include:

- Known packer/protector section names and strings such as UPX or VMProtect/Themida markers.
- High-entropy executable sections, writable executable sections, and sparse import surfaces.
- CPUID and timing instructions often used around anti-analysis checks.
- OEP and unpacking handoff candidates, including PE entry point context and indirect branch sites.
- Runtime import-rebuild hints from loader/protection/allocation imports and embedded DLL/API strings.
- VM lifting candidates such as possible dispatch edges and stack-machine-like push/pop windows.
- Layer 2 artifacts: bounded OEP instruction windows, import rebuild plan entries, and VM sketches with register/mnemonic summaries.

This is a static lead generator. It does not dump a mapped process image or automatically devirtualize handlers; pair the reported RVAs with `resx dump`, `resx cfg`, and sandbox/debugger snapshots.

## Entropy Maps

Command:

```powershell
resx entropy <image>
```

Entropy maps render an overlaid terminal plot over sliding windows in executable sections by default. They are useful for spotting packed code, encrypted/compressed regions, zero padding, embedded text, and abrupt byte-distribution changes inside code-bearing sections.

Each row includes:

- RVA range and section name.
- A 0.0-8.0 y-axis plot where `*` is entropy, `a` is ASCII ratio, `z` is zero-byte ratio, `u` is unique-byte ratio, and `#` means curves overlap.
- ASCII ratio, zero-byte ratio, and unique-byte ratio.
- Flags such as `high-entropy`, `low-entropy`, `zero-heavy`, `ascii-heavy`, and `byte-diverse`.

Use `--entropy-window <bytes>` and `--entropy-stride <bytes>` to tune resolution. Use `--entropy-all` to include data/resource sections.

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

## Byte Patching

```powershell
resx patch <image> --at <address> --patch-bytes <hex>
```

Patches resolve RVA, PE VA, or file-offset addresses. `--expect` verifies original bytes, `--dry-run` writes nothing, and `--update-checksum` updates the PE checksum. A patched copy is the default; in-place changes require `--in-place`.

## Output Contracts

Prefer JSON for automation:

```powershell
resx peinfo <image> --json
resx dump <image> <function> --json
resx behavior <image> --json
resx entropy <image> --json
resx unpack <image> --json
resx scan <path> --json
```

JSON shapes are versioned where possible. Consumers should tolerate extra fields and should not depend on text formatting.
