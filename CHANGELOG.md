# Changelog

All notable public changes to RESX are recorded here.

## Unreleased

## 2.1.0 - 2026-10-27

### Feature additions

#### Windows SDK API analysis

- Added `resx config --headers <directory>` and `resx api <name>` for local Windows SDK declarations, parameter types, SAL directions, constants and typedefs, with a versioned per-user header index cache.
- Added opt-in `--args` / `/args` enrichment to dump, call trees and behavior reports, including structured JSON. `--no-headers` disables SDK enrichment for a run; `config --headers off` clears the saved SDK setting.
- Recovered bounded x86/x64 argument slots, strings, stack pointers and image addresses. Branch joins, escaped stack outputs and unknown x86 cleanup discard uncertain values; floating-point values remain unknown.
- Classified file-backed executable addresses passed to SDK callback parameters as inferred function targets, retaining the callback typedef, RVA, VA and evidence in JSON.
- Decoded API-specific constants including waitable-timer access rights and BCrypt RNG flags. Kept pointer-sized integer zero distinct from null pointers.

#### Disassembly and function recovery

- Labeled the service-number load in syscall stubs (`mov eax, 0x18  ; syscall 0x18 (24)`) for x64 `syscall`/`int 0x2e` stubs, WoW64 `call edx` stubs, and kernel `Zw*` stubs that jump to `KiServiceInternal`, with or without symbols. win32k numbers show their table index (`syscall 0x1004 (win32k #4)`). The label replaces literal guesses such as `STATUS_SUCCESS` on the service number.

#### CLI and output

- Rebuilt the command line on per-command subcommands. Each command takes only the options it uses, an unused option is reported as an error, and mistyped commands and options get a suggestion.
- Grouped shared options into named groups (Output, Image lookup, Symbols, Target, Analysis, Listing, Report sections, Call tree, Flow, Search scope, Matching) that appear under their own headings in command help.
- Generated each command's options in `resx help <command>`, `resx <command> --help`, and `resx help all` from the parser itself, so help matches what a command accepts.
- Dropped implied prefixes inside commands: `strings --min-len`, `entropy --window`, `find --mode`, `diff --mode --graph --show-cfg`, `payload --out-dir --offset`, `patch --bytes`. Earlier spellings remain accepted as aliases.
- Accepted output options before or after the command, for example `resx --json dump <image> <target>`.
- Resolved slash options against the command being run, so `/limit:5` is the result cap under `strings` and the instruction budget under `dump`.

#### Call trees

- Added `resx calls <image> <target>` for the recursive API call tree of one function, with `--depth`, `--only`, and `--exclude`.
- Added call-tree filter terms `winapi`, `iat`, `internal`, `crt`, `syscall`, and DLL names (with optional extension and trailing `*` prefix). Non-matching internal calls stay as the path to matching ones; repeats of an expanded function are tagged `[expanded above]`.
- Added `--calls [DEPTH]`, `--calls-only`, and `--calls-exclude` to `dump`, `xrefs`, `cfg`, and `intelli`.
- Filtered JSON `api_calls` to the root calls that survive the call-tree filter.
- Labeled calls through dynamically resolved APIs with the API they reach, tagged `[dynamic · how]`, and added a `resolves:` line to each resolver call. Covers `GetProcAddress`/`LdrGetProcedureAddress` with literal, stack-built, ordinal or decoded names, wrappers that forward their arguments, pointers stored in global API tables and called elsewhere, hand-walked export and import tables, PEB loader-list walks, and hashed names, for x86 and x64. JSON `api_calls` entries carry `dynamic` and `resolves`.
- Added the call-tree filter term `dynamic`.
- Recognized CFG-guarded tail jumps (`jmp [__guard_dispatch_icall_fptr]`) as indirect calls through `rax`.

#### Behavior triage

- Added the `api-resolution` category, grading how an image resolves APIs at run time: `loader-api-resolution` and `unrecovered-api-names` (low), `stack-string-api-names` (medium), and `encoded-api-names`, `export-table-walk`, `import-table-walk`, `peb-module-walk` and `api-hashing` (high). Evidence names each resolved API, how its name was hidden (cipher and key, or hash construction and constant) and where it is called. JSON adds `api_resolution`, a one-line verdict, and `resolved_apis`.
- Inverted API and module name hashes against the local system's export and module names, using rotate counts, multipliers and seeds found in the resolver's code to choose among common constructions.

#### Native library and editor integration

- Treated FFI `options_json` as a shared option bag: each typed call receives only the keys its command takes, and keys no command takes still fail with `RSX_STATUS_INVALID_OPTIONS`.

### Accuracy and correctness fixes

- Required `--args` for detailed driver, IOCTL, contract, IPC, network and crypto call arguments in text and JSON. Main findings and flow summaries remain available by default.
- Applied parsed image lookup and symbol options to the contract-family commands.
- Rendered call arguments in aligned, neutral-color subtrees with wrapping and spacing; reduced redundant headers and routine import details in call-only output.
- Collapsed repeated behavior findings into a count and three example RVAs; `--verbose` expands occurrences and evidence, and JSON retains all findings.
- Stopped labeling small untyped immediates and bit tests as NTSTATUS values. Distinctive move/compare matches are labeled possible NTSTATUS, and unrelated 64-bit values cannot match through truncation.
- Cleared progress before target-resolution output, disabled stage progress for redirected streams, and avoided interleaving it with verbose dump messages.
- Decoded functions across contiguous chained unwind fragments. MSVC shrink-wrapping opens a new `.pdata` entry where a nonvolatile register is first saved; decoding previously stopped there and dropped the rest of the function's calls.
- Reported calls through linker import thunks (`jmp [__imp_X]`, emitted for headers without `dllimport` such as `bcrypt.h`) as the import instead of an internal function that walked the whole thunk table.
- Stopped reporting unconditional jumps back into a function's own body as tail calls.
- Built the API call tree once per dump instead of once for text and once for JSON, halving kernel-image loads for syscall tracing.
- Fixed `resx --json dump <image> <target>` parsing `dump` as the image.

### Removed or retired

- Removed the internal routing switches (`--peinfo`, `--behavior`, `--entropy`, `--reconstruct-cfg`, `--follow-callers`, `--locate`, `--locate-sym`, `--patch`, `--priority`, `--update`, `--resx-find`, `--resx-scan`, `--resx-diff`, `--resx-index`, `--resx-hunt`, `--resx-config`, `--scan-root`). Use the command itself, for example `resx peinfo <image>`. `resx <image> <target>` and `resx <name>` still run `dump` and `locate`.

### Documentation

- Expanded the README into workflow dropdowns with captured API-resolution, callback, comparison, corpus, PowerShell, PE and RESX-to-SKUGGA examples.

### Validation additions

- Validated call trees and API arguments, including callback targets and Windows constants.
- Added call-tree filter tests, parser grammar and scoping tests, and a check that every earlier option spelling still parses.

## 2.0.0 - 2026-09-20

### Feature additions

#### Disassembly and function recovery

- Added reachable multi-stream x86/x64 decoding for functions containing overlapping instruction streams.
- Preserved architectural fallthrough, branch targets, alternate entry streams, and terminal control transfers without forcing one linear interpretation.
- Added lowercase Intel-style mnemonics, registers, memory operands, and `0x` hexadecimal values.
- Added bounded Win64 ABI signature inference for register arguments, entry-stack arguments, integer widths, floating-point values, aliases, pointer use, and return evidence.
- Added PDB prototype preference with static ABI inference as a bounded fallback.
- Added structured decode-conflict records for branch-into-instruction and overlapping-stream conditions.
- Added stack-frame aliases for arguments, local slots, and the return address.
- Added optional lightweight SSA and dataflow annotations through `--ssa`.
- Added explicit call, return, conditional-flow, and tail-transfer annotations.
- Added startup-flow profiles and bounded recognition of common runtime initialization patterns.
- Added richer call-map classification for imports, syscalls, thunks, callbacks, and tail calls.

#### PE analysis

- Added bounded validation for PE headers, sections, directories, mapped ranges, and file-backed ranges.
- Added hardened import, export, relocation, resource, TLS, debug, certificate, CLR, load-configuration, and exception-directory parsing.
- Added x64 unwind v1/v2 parsing, chained records, epilog scopes, saved-register data, stack allocation recovery, and canonical function ownership.
- Added startup routine and entry-flow recovery from validated metadata and executable references.
- Added structured PE anomalies with severity, evidence, and explicit uncertainty.
- Added PE triage findings for evidence-backed high-entropy code and data sections.
- Added mitigation reporting for ASLR, DEP, CFG, CET compatibility, SafeSEH where applicable, and load-configuration protections.
- Added checks preventing exported data and import slots from being decoded as function bodies.

#### Behavior and capability analysis

- Added exact API-semantic analysis for process, thread, file, registry, service, memory, synchronization, and callback activity.
- Added IPC analysis for named pipes, shared mappings, RPC, ALPC, and related producer/consumer flows.
- Added network request recovery for socket and WinHTTP-style APIs, including validated host, port, method, path, and address evidence.
- Added cryptographic configuration recovery for CNG and legacy provider APIs.
- Added driver analysis for dispatch tables, device creation, symbolic links, IOCTL handling, callbacks, and framework indicators.
- Added NDIS OID request recovery with validated structure layout and request discriminants.
- Added hypervisor-oriented evidence for VMX/SVM instructions, control structures, nested paging, and invalidation operations.
- Added cross-call producer tracking and predecessor relationships for handles and API results.
- Added structured contract flows for IPC channels, network requests, and cryptographic configurations.

#### Content, payload, and search analysis

- Added bounded string extraction with encoding validation and noise rejection.
- Added checked gzip, zlib, Base64, and related payload decoding.
- Added AES-CBC decoding with validated key, IV, block, and padding constraints.
- Added bounded payload discovery and artifact reporting.
- Added instruction, byte-pattern, symbol, and address search commands.
- Added standalone YARA-compatible scanning with focused match output.
- Added guarded PE byte patch generation with RVA, VA, and file-offset addressing.

#### Comparison and corpus workflows

- Added normalized binary profiles for structural comparison.
- Added function, import, export, section, string, behavior, and metadata comparison.
- Added CFG normalization, matching, classification, and similarity scoring.
- Added text and heatmap diff views.
- Added reusable corpus indexes and bounded similarity hunts.
- Added deterministic hashing and stable comparison tokens.

#### CLI and output

- Added unified command routing and focused per-command help.
- Added `contracts`, `driver`, `find`, `payload`, `pechk`, `settings`, and standalone `yara` commands.
- Added versioned JSON envelopes and structured JSON for dump, symbols, types, PE data, contracts, and diagnostics.
- Added global quiet, color, PDB, symbol-path, progress, and diagnostic controls.
- Added persistent validated preferences.
- Added bounded subprocess execution with deadlines and output limits.
- Added NTSTATUS decoding and status-name annotations.
- Added address resolution by export, symbol, ordinal, RVA, VA, file offset, and qualified image target.

#### Symbols and types

- Added bounded Windows PDB discovery, loading, caching, and identity validation.
- Added symbol enumeration and address lookup with deterministic precedence.
- Added LLVM-backed PDB type traversal with cycle, depth, count, and output bounds.
- Added function type, parameter, return type, pointer, array, enum, structure, and alias recovery where records are available.
- Added cache invalidation when executable identity or branch state changes.

#### Native library and editor integration

- Expanded the C ABI across dump, CFG, symbols, types, PE inspection, comparison, search, scan, patch, and settings operations.
- Added versioned JSON command dispatch and consistent status handling across exported functions.
- Added panic containment and owned output-string release contracts at the ABI boundary.
- Expanded the VS Code binary viewer with analysis navigation, persisted UI state, structured payload handling, and safer executable selection.
- Added webview views for flow, calls, strings, symbols, sections, findings, and scan results.

### Accuracy and correctness fixes

- Fixed branch targets inside another decoded instruction being discarded or mislabeled as corrupt flow.
- Fixed alternate streams losing their own instruction boundaries and fallthrough edges.
- Fixed leaf exported functions losing ownership and argument state at import tail jumps.
- Fixed stack-argument indexing after stack-frame allocation and entry-stack aliasing.
- Fixed partial register and partial stack writes being promoted to full-width values.
- Fixed call clobbers, conditional writes, and unreachable bytes producing unsupported signature claims.
- Fixed PDB prototype loss when static inference could not prove a complete signature.
- Fixed chained unwind fragments being assigned to the wrong function.
- Fixed malformed unwind, resource, relocation, import, and load-configuration records escaping declared bounds.
- Fixed header RVAs, zero-fill ranges, overlapping sections, and unavailable file bytes being treated as ordinary mapped data.
- Fixed sparse imports being reported as loader abuse without sufficient evidence.
- Fixed section names and text decoding around NUL termination, UTF-16 boundaries, and invalid surrogate pairs.
- Fixed network and cryptographic labels being inferred from unrelated names or constants.
- Fixed socket address recovery to honor family, length, and network byte order.
- Fixed import ordinals, forwarded exports, data exports, and import slots being confused with executable targets.
- Fixed JSON diagnostics contaminating stdout payloads.
- Fixed repeated literals losing distinct source offsets.
- Fixed extensionless Windows image lookup and GUI syscall-family routing.
- Fixed formatter output using uppercase mnemonics and suffix-style hexadecimal values.

### Refactors

#### Analysis layout

- Split the analysis layer into focused `algorithms`, `behavior`, `comparison`, `crypto`, `driver`, and `reconstruction` modules.
- Split disassembly into decoding, API resolution, string resolution, and xref components.
- Split reconstruction into CFG, dataflow, deobfuscation, indirect-flow, IR, recompilation, recursive CFG, signature, thunk, and rendering components.
- Split driver analysis into call-state recovery, semantic decoding, capabilities, dispatch, hypervisor, and NDIS components.
- Replaced monolithic comparison code with normalization, profiling, CFG, matching, classification, orchestration, and reporting modules.

#### PE and PDB layout

- Centralized PE validation and shared bounded-read helpers.
- Split startup metadata recovery and metadata tests into focused modules.
- Split PDB handling into platform API, cache, type, symbol, and orchestration modules.
- Consolidated function ownership around validated runtime-function metadata, chained parents, and export entry points.

#### Commands and presentation

- Split dump execution, presentation, JSON construction, and call-map handling.
- Split structural diff output into CFG, heatmap, and text components.
- Moved terminal color, progress, table, and output behavior into a dedicated presentation layer.
- Centralized address-source parsing and integer-literal handling for dump and patch commands.
- Centralized editor payload-envelope types and generation for extension and webview builds.
- Consolidated command examples and option parsing while retaining focused help pages.
- Replaced ad hoc messages with bounded structured diagnostics.

#### Reliability and resource control

- Added hard limits for decoded instructions, functions, entries, recursion, strings, parser depth, process output, and work queues.
- Replaced unchecked range arithmetic with validated offsets and lengths.
- Added deterministic ordering for symbols, findings, comparisons, and JSON output.
- Added explicit provenance and evidence-state fields instead of implicit confidence claims.
- Added fail-closed behavior when bytes, metadata, types, or control flow are unavailable.

### Removed or retired

- Removed flow-line and branch-arrow rendering and its command-line options.
- Removed legacy `explain` and `unpack` commands.
- Removed superseded monolithic disassembly, reconstruction, comparison, and output implementations.
- Removed the static explanation database.
- Removed obsolete build, packaging, smoke-test, sample, and release-output files.
- Removed bundled demonstration programs and generated fixture sources from version control.
- Removed duplicated release notes and oversized design-process documents.

### Documentation and licensing

- Restored the MIT license at the repository root.
- Added MIT license metadata to the Rust crate and VS Code extension.
- Rewrote the README around supported behavior, evidence limits, build steps, and public commands.
- Reduced and consolidated the command, CLI, analysis, JSON, DLL/FFI, VS Code, and security documentation.
- Documented opt-in SSA, signature sources, conflict records, triage findings, and JSON fields.

### Validation additions

- Added hostile PE mutation and parser safety tests.
- Added overlapping-stream and ABI signature tests.
- Added unwind v1/v2 and chained-record tests.
- Added driver, NDIS, IPC, network, crypto, and capability contract tests.
- Added independent codec, AES, and unwind oracle tests.
- Added FFI surface and versioned JSON envelope tests.
- Added system image and GUI syscall routing tests.
- Added VS Code payload and persisted-state tests.
- Added formatting, bounded-process, table-layout, preference, diagnostic, and status tests.

## 1.10.1 - 2026-07-15

- Published RESX under the MIT license.
- Updated product branding and Windows CI defaults.
- Preserved overlapping CFG fallthrough during decoding.
- Updated UTF-16 decoding for current Rust and Clippy behavior.

## 1.10.0 - 2026-06-19

- Expanded CLI analysis and release packaging.
- Added guarded PE byte patching.
- Improved PDB-backed metadata, startup analysis, string resolution, and versioned JSON output.
- Added the first VS Code binary viewer workflows and native DLL interface.
