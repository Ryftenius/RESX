# COMMANDS

## Identity

- Name: `RESX`
- Author: `RYFTENIUS`
- Version: `resx version` or `resx --version`

## Core

- `resx dump <dll> <function>`
- `resx dump <dll> --at <rva>`
- `resx dump <dll> --ordinal <n>`
- `resx cfg <dll> <function>`
- `resx cfg <dll> --at <rva>`
- `resx cfg <dll> --ordinal <n>`
- `resx reconstruct-cfg <dll>`
- `resx intelli <dll> [function]`
- `resx behavior <dll>`
- `resx unpack <dll>`
- `resx entropy <dll>`
- `resx diff <image-a> <image-b> [image-c ...]`
- `resx index <dir-or-image> --db <file>`
- `resx hunt <sample> --db <file>`
- `resx peinfo <dll>`
- `resx sections <dll>`
- `resx eat <dll>`
- `resx iat <dll>`
- `resx syms <dll>`
- `resx pechk <dll>`
- `resx priority`
- `resx callers <dll> <function>`
- `resx locate <name>`
- `resx locate-sym <name>`
- `resx explain <name>`
- `resx scan <path>`
- `resx yara <dll> <rule.yar>`
- `resx update`

## Dump And Analysis Flags

- `--at <rva>`
- `--ordinal <n>`
- `--recomp`
- `--c-out <file>`
- `--cfg text`
- `--reconstruct-cfg`
- `--thread-filter <term>`
- `--api-filter <term>`
- `--funcs`
- `--funcs-depth <n>`
- `--explain`
- `--prefix`
- `--api`
- `--xrefs`
- `--strings`
- `--edrchk`
- `--unsafe-map-image`
- `--hookchk`
- `--intelli`
- `--hostile`
- `--follow-jmp`
- `--no-follow-jmp`
- `--rebase <addr>`

## Intelli

- `resx intelli <dll>` runs triage against an image quickly.
- `resx intelli <dll> <function>` narrows the triage to a specific target while still allowing dump-side options like `--hookchk`, `--cfg text`, `--strings`, and `--json`.
- `intelli` is a command alias for the dump pipeline with `--intelli` enabled.

## Behavior

- `resx behavior <dll>` scans the image for static anti-analysis, loader, syscall, TLS, and executable-memory/JIT signals.
- `--json` emits a versioned `behavior` report with category, rule, severity, confidence, source, RVA, detail, and evidence fields.
- Findings are triage evidence, not proof of runtime execution.

## Unpack

- `resx unpack <dll>` performs static protected-file unpacking and VM-lifting triage.
- It reports packer/protector markers, high-entropy or writable executable sections, sparse imports, CPUID/timing checks, OEP/handoff candidates, import-rebuild hints, and possible VM dispatcher/handler sites.
- Layer 2 adds bounded OEP disassembly windows, import rebuild plan entries, and VM handler sketches with registers, mnemonics, and local instructions.
- `--json` emits a versioned `unpack` report with `protector_hints`, `oep_candidates`, `import_rebuild_hints`, `vm_candidates`, `layer2`, and `next_steps`.
- The command emits leads for malware-analysis unpacking workflows; it does not currently write a rebuilt unpacked binary.

## Entropy

- `resx entropy <dll>` renders an overlaid terminal plot over executable sections by default.
- The plot uses the 0.0-8.0 entropy scale on the y-axis and code RVA order on the x-axis. Symbols are `*` entropy, `a` ASCII ratio, `z` zero-byte ratio, `u` unique-byte ratio, and `#` overlap.
- The detail table below the plot reports each RVA window, Shannon entropy, ASCII ratio, zero-byte ratio, unique-byte pressure, and flags such as `high-entropy`, `low-entropy`, `zero-heavy`, `ascii-heavy`, and `byte-diverse`.
- `--entropy-window <bytes>` controls window size; default is `1024`.
- `--entropy-stride <bytes>` controls the step between windows; default is `512`.
- `--entropy-all` includes non-executable sections.
- `--json` emits a versioned `entropy` report with summary and per-window records.

## Explain

- `resx explain <name>` explains a prefix or API-style symbol using the built-in glossary.
- `--prefix` forces prefix-mode interpretation.
- `--api` forces API/symbol-mode interpretation.
- `dump --explain` reuses the same explanation engine inline for the current target.

## Reconstruct CFG

- `resx reconstruct-cfg <dll>` builds a bounded startup/TLS-to-exit graph.
- The graph follows intra-image calls, tail jumps, import edges, indirect-call annotations, recovered thread/workpool callbacks, and x64 unwind exception-handler edges.
- PDB symbols are used when available for names, prototypes, and size-backed decode bounds.
- `--thread-filter <term>` and `--api-filter <term>` focus the text output for non-interactive review.
- `--json` emits a versioned `reconstruct_cfg` report with roots, nested edge children, PDB status, statistics, and static-analysis notes.

## Diff

- `resx diff <image-a> <image-b> [image-c ...]` compares two or more EXE/DLL/SYS images by normalized function structure.
- With three or more images, RESX profiles each image once and emits an all-pairs structural matrix.
- It uses discovered functions, disassembly, basic-block shape, normalized opcode streams, import/API calls, constants, strings, and metadata deltas.
- It is tolerant of image-base changes, stripped debug data, many string edits, and small constant/address changes.
- It reports a runtime-filtered unique score so compiler stubs and anonymous support code do not dominate variant decisions.
- `--diff-mode quick|balanced|deep` controls decode depth and cost; default is `balanced`.
- `--diff-threshold <0-100>` sets the minimum function match score; default is `65`.
- `--include-weak` includes weak 50-64 similarity candidates.
- `--max-functions <n>` caps decoded functions per image; default is `2000`.
- `--left-pdb <file>` and `--right-pdb <file>` provide side-specific PDBs.
- `--json` emits a versioned `diff` report for two images or `diff_matrix` report for three or more images.
- `--diff-graph` adds a control/code-structure heatmap with function hotspots, per-signal scores, and PE section entropy deltas.
- `--diff-graph-format text|json|dot` selects terminal, machine-readable, or Graphviz output.
- `--diff-graph-out <file>` writes the heatmap/graph view to disk.
- `--show-cfg-diff <function|rva|auto>` renders a side-by-side basic-block diff for one matched function.
- `--cfg-diff-format text|json|dot` selects terminal, machine-readable, or Graphviz output.
- `--cfg-diff-out <file>` writes the CFG diff view to disk.
- `--max-cfg-blocks <n>` caps the number of blocks rendered per side.

## Index And Hunt

- `resx index <dir-or-image> --db <file>` builds a reusable JSON corpus of normalized function, CFG, API, constant, fuzzy, and metadata fingerprints.
- `resx hunt <sample> --db <file>` profiles one sample and ranks indexed images by shared code structure, unique-function overlap, metadata similarity, and stable signature tokens.
- `--extensions <list>`, `--max-files <n>`, `--max-file-mb <mb>`, and `--max-functions <n>` control corpus build scope.
- `--diff-threshold <0-100>`, `--include-weak`, and `--max-candidates <n>` control hunt matching and output size.
- `--no-pdb` is supported and useful for theft/malware-family hunting where samples are stripped.
- `--json` emits versioned `index` and `hunt` reports; the `--db` file is the raw reusable index.

## Scan

- `resx scan <path>` inventories `.exe`, `.dll`, and `.sys` files under a root.
- `--jsonl` emits one JSON object per image for agent and corpus workflows.
- `--extensions <list>`, `--max-files <n>`, `--max-file-mb <mb>`, and `--max-candidates <n>` control scan scope and output size.
- Results include image metadata, risk imports, anomalies, and ranked fuzz-target candidates.
- Candidate entries include `name`, `rva`, `source`, `score`, `reasons`, `input_surface`, `harness_kind`, `suggested_invocation`, and `confidence`; scores are triage hints, not exploitability claims.

## JSON Output

- JSON output uses `schema_version: 1`.
- Most commands emit `{ "schema_version": 1, "kind": "<command>", "<command>": ... }`.
- `scan --json` emits `{ "tool": "resx", "schema_version": 1, "kind": "scan", "results": [...] }`.
- `scan --jsonl` emits one image report per line without the outer scan envelope.
- See [docs/json-schemas.md](docs/json-schemas.md) for field-level notes.

## Symbol Flags

- `--pdb <file>`
- `--sym-path <path>`
- `--sym-server <url>`
- `--reload`
- `--no-pdb`

## Caller Tracing Flags

- `--depth <n>`
- `--max-callers <n>`
- `--max-total <n>`
- `--format tree|flat|list`
- `--show-rva`
- `--show-site`
- `--filter-dll <text>`
- `--include-dir <dir>`
- `--include-image <dll>`
- `--scan-exe`
- `--include <glob>`
- `--scope-file <glob>` / `--include-file <glob>`
- `--exclude <glob>`
- `--max-dll-size <mb>`
- `--workers <n>`

## Global Flags

- `--path <dir>`
- `--priority`
- `--no-system`
- `--no-cwd`
- `--no-path`
- `--arch <auto|x86|x64>`
- `--bytes`
- `--no-bytes`
- `--show-offsets`
- `--intel`
- `--att`
- `--json`
- `--out <file>`
- `--color`
- `--no-color`
- `--verbose`
- `--quiet`
- `--example`

## Newer Output Areas

- `dump --cfg text` can recover and render `Switch Map` sections for jump-table dispatchers.
- `cfg` supports function names, `--at <rva>`, and `--ordinal <n>` just like `dump`.
- `cfg` and `dump` use the same instruction and API/symbol highlighting path for call targets and comments.
- `dump --funcs` discovers direct, import, IAT-indirect, register-indirect, and switch-dispatch call targets.
- `dump --recomp` emits corrected bit-test branches and better local-call placeholders.
- `dump --recomp` uses PDB prototype text and x64 unwind metadata when available.
- `dump --funcs-depth <n>` expands nested API call depth and accepts levels `1` through `5`.
- `syms --verbose` can show exact PDB identity/load diagnostics, including RSDS-derived kernel PDB names.
- `dump` can resolve internal names from enumerated PDB symbols when exports do not contain the target.
- `dump` can surface syscall service numbers and kernel targets for `Nt*`, `Zw*`, and Win32K GUI syscall stubs.
- Extensionless system image lookup supports `.dll`, `.exe`, and `.sys`, including `user32`, `win32u`, `win32k`, `win32kbase`, `win32kfull`, and `ntoskrnl`.
- `locate` and `locate-sym` search only the priority set by default.
- `callers` uses the priority set by default.
- `--include-dir` and `--include-image` widen the scan beyond the priority set for `locate` and `callers`.
- `callers --include-dir` will scan `.dll` and `.sys` images by default, and `.exe` as well when `--scan-exe` is set.
- `--include` filters the entire callers scan list; `--scope-file` only filters files discovered through `--include-dir`.
- `priority` opens the generated priority config JSON where you can edit directories, exact names, prefixes, and regexes.
- `reconstruct-cfg` reconstructs startup flow using PE entry/TLS/startup roots, direct calls, import calls, recovered callbacks, and unwind exception edges.
- `scan` inventories PE corpora and ranks fuzz-target candidates from exports, startup paths, risky imports, and section anomalies.
- `diff` compares two or more PE images with normalized code/CFG fingerprints, reports exact/strong/changed/weak function matches, and can emit graphable entropy-backed hotspots.
- `index` and `hunt` reuse the same fingerprints across a corpus to find variants, stolen-code subsets, renamed/debug-stripped builds, and malware-family relatives.
- `resx-palace/` is the local controlled fixture corpus that exercises discovery, recursive CFG, EH, typed reconstruction, indirect control flow, and scan output.

## Examples

```powershell
resx dump ntdll.dll NtOpenProcess --cfg text --hookchk
resx cfg ntdll.dll --at 0x161F40
resx intelli suspicious.dll
resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
resx reconstruct-cfg suspicious.dll --depth 6 --max-total 300
resx dump ntoskrnl.exe KiSystemCall64 --cfg text --funcs --recomp
resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
resx dump win32u NtUserGetMessage --funcs
resx peinfo win32kfull
resx syms ntoskrnl.exe --verbose
resx callers blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub --depth 2
resx callers ntoskrnl.exe NtOpenProcess --include-dir C:\Work\Drivers --depth 2
resx callers ntoskrnl.exe PsOpenProcess --include-dir C:\Windows\System32\drivers --scope-file *.sys
resx priority
resx locate NtOpenProcess
resx locate NtOpenProcess --include-dir C:\Work\Drivers
resx locate-sym NtWriteVirtualMemory --include-image .\mydriver.sys
resx explain NtQuerySystemInformation --api
resx scan C:\Windows\System32\drivers --jsonl --max-files 200
resx diff .\old.dll .\new.dll --diff-mode deep --include-weak
resx diff .\old.dll .\new.dll .\canary.dll --diff-graph
resx diff .\old.dll .\new.dll --diff-graph --diff-graph-format dot --diff-graph-out heatmap.dot
resx diff .\old.dll .\new.dll --show-cfg-diff auto
resx diff .\old.dll .\new.dll --show-cfg-diff TargetFunc --cfg-diff-format dot --cfg-diff-out cfg.dot
resx index .\samples --db .\samples.resxdb --no-pdb
resx hunt .\unknown.dll --db .\samples.resxdb --diff-threshold 70
resx update
```
