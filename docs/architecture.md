# Architecture

RESX is being organized around shared image facts, with analysis built on top.
Commands choose the work to run and render the result.

| Layer | Responsibility |
| --- | --- |
| `formats/pe` | Parse bytes and validate PE mappings and structures. |
| `analysis/image` | Share imports, exports, unwind records, TLS, startup routines, load configuration and data summaries for one immutable image. |
| `analysis/session` | Compute and reuse analysis results when requested. Currently owns dynamic API resolution. |
| `analysis/inspection` | Select image and function reports through explicit requests, independent of the CLI or output format. |
| Analysis modules | Recover calls, arguments, behavior, driver interfaces and other evidence. |
| `providers` | Load exports and SDK headers from explicit directories or the local Windows environment. |
| Commands and presentation | Resolve inputs, select analyses and produce CLI or JSON output. |

`ImageFacts` borrows the bytes and their parsed `PeFile`. Facts are computed on
first use. `AnalysisSession` owns an `ImageFacts` and caches resolver results for
that session. Neither uses buffer addresses as persistent cache keys. A changed
image requires a new session.

External names are explicit inputs too. `AnalysisSession::new` uses no external
export dictionary. `with_exports` accepts an `ExportDictionary` built by the caller
or a lazy `ExportProvider`. `SystemExports` handles local DLL lookup at the command
boundary. Separate sessions can use different export sets without sharing results.

`HeaderIndex::from_sources` parses supplied header text without filesystem access.
`SdkHeaders` handles SDK discovery and optional disk caching. Each instance keeps
one snapshot; create another to refresh it. Commands load an index once and pass
it through behavior and call-tree argument recovery.

Provider adapters can reuse up to four source snapshots. Keys include the source
directory, file sizes and modification times; export keys also include the module
listing. Windows SDK directory notifications avoid rescanning unchanged headers;
when notifications are unavailable, requests check metadata directly. Parsing runs
outside cache locks. Active sessions keep their snapshots through cache eviction.

The FFI uses the CLI grammar for command names, aliases and JSON options. Adding
a command no longer requires a second command list in the DLL adapter.

Dump and calls translate CLI flags into report requests once. The analysis layer
returns a `FunctionReport` shared by text and JSON output. Signature, calls,
arguments, dynamic resolution, CFG, typed IR and other reports can be selected
independently by Rust callers. Argument recovery and dynamic resolution collect
the calls they need. Discovery and indirect-flow analysis reuse the session's
data summary instead of rescanning the image.
Data views borrow the same cached unwind records, so combining reports does not
retain a second copy of the unwind table.

`DecodeOptions` and `TraversalOptions` carry decoding settings and budgets without
CLI configuration. `decode_function` preserves reachable-function recovery and
only falls back to linear decoding when needed. `inspect_function` consumes those
instructions and supplied switch targets. Neither selects work by output format.
The module's Rust example shows a minimal call/signature request.

Function rendering consumes completed reports, including driver flow contracts
and resolved syscall details. CFG blocks are built once, then passed to plain or
colored renderers in `presentation/cfg`. Existing JSON fields, command defaults
and Rust compatibility entry points remain available.
JSON conversion produces an owning model, then releases the analysis session
before serialization so its caches do not overlap the output buffer's lifetime.

Behavior, dump/call trees, SDK argument recovery, driver, IOCTL and contract
analysis use these shared facts. IOCTL analysis requests its own report without
running unrelated driver classification or hypervisor analysis. Existing Rust
entry points remain available; callers doing repeated analysis should reuse the
new context APIs.

The legacy `resolution::cached` entry point now computes a fresh report. Use
`AnalysisSession::resolution` to reuse it safely.
Other legacy convenience functions retain host lookup through compatibility
adapters. Repeated library workflows should keep their providers and sessions
instead of loading a new SDK index or export dictionary for every operation.

When adding an analysis:

- Take image facts and explicit inputs. Keep file lookup and output formatting
  outside the analysis where possible.
- Request only the facts needed. Reuse existing parsers and address conversions.
- Return evidence as data. Apply output limits and colors when rendering it.
- Keep traversal budgets explicit. Cache results only for inputs that cannot
  change during their lifetime.
- Check correctness and measure the affected workflow before optimizing it.

The migration is ongoing. Cross-image call-tree traversal, kernel lookup and live
checks still sit in command adapters. Older analyses retain some CLI and formatting
dependencies. Discovery and disassembly keep their distinct traversal policies;
sharing their inputs does not mean treating those policies as interchangeable.
