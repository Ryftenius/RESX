# Architecture

RESX is built around shared facts about one image, with analysis layered on top.
Commands pick what to run and render the result. They shouldn't be doing the analysis
themselves.

| Layer | Responsibility |
| --- | --- |
| `formats/pe` | Parse bytes and validate PE mappings and structures. |
| `analysis/image` | Share imports, exports, unwind records, TLS, startup routines, load configuration and data summaries for one immutable image. |
| `analysis/session` | Compute and reuse analysis results when asked. Currently owns dynamic API resolution. |
| `analysis/inspection` | Select image and function reports through explicit requests, independent of the CLI or output format. |
| Analysis modules | Recover calls, arguments, behavior, driver interfaces and other evidence. |
| `providers` | Load exports and SDK headers from explicit directories or the local Windows install. |
| Commands and presentation | Resolve inputs, pick analyses, produce CLI or JSON output. |

## Image Facts And Sessions

`ImageFacts` borrows the bytes and their parsed `PeFile`, and computes each fact the
first time something asks for it.

`AnalysisSession` owns an `ImageFacts` and caches resolver results for that session.

Neither one uses a buffer address as a cache key. If the image changes, make a new
session.

## Providers

Anything that comes from outside the image is passed in explicitly.

- **Exports:** `AnalysisSession::new` starts with no export dictionary. `with_exports`
  takes an `ExportDictionary` you built or a lazy `ExportProvider`. `SystemExports`
  does local DLL lookup, and only at the command boundary. Two sessions can use
  different export sets without sharing results.
- **Headers:** `HeaderIndex::from_sources` parses header text you hand it, with no
  filesystem access. `SdkHeaders` finds the SDK and can cache to disk. Each instance
  holds one snapshot, so make a new one to refresh. Commands load the index once and
  pass it to behavior and call-tree argument recovery.

Provider adapters keep up to four source snapshots. The cache key is the source
directory plus file sizes and modification times, and export keys also include the
module listing. Windows SDK directory notifications skip rescanning headers that
haven't changed. Where notifications aren't available, each request checks the
metadata directly. Parsing happens outside the cache locks, and a session keeps its
snapshot even if the cache evicts it.

## Commands And Reports

The FFI uses the CLI grammar for command names, aliases and JSON options, so a new
command only gets registered once.

`dump` and `calls` turn CLI flags into report requests once. The analysis layer
returns a `FunctionReport` that both text and JSON output render from. Rust callers
can select signature, calls, arguments, dynamic resolution, CFG, typed IR and the
other reports independently.

- Argument recovery and dynamic resolution collect only the calls they need.
- Discovery and indirect-flow analysis reuse the session's data summary instead of
  rescanning the image.
- Data views borrow the cached unwind records, so combining reports doesn't keep a
  second copy of the unwind table.

`DecodeOptions` and `TraversalOptions` carry decode settings and budgets with no CLI
config attached. `decode_function` keeps reachable-function recovery and only falls
back to linear decoding when it has to. `inspect_function` takes those instructions
plus any supplied switch targets. Neither picks work based on output format. The
module's Rust example shows a minimal call/signature request.

Rendering only consumes finished reports, including driver flow contracts and
resolved syscall details. CFG blocks are built once and handed to the plain or
colored renderer in `presentation/cfg`.

JSON conversion builds an owning model, then drops the analysis session before
serializing, so the session's caches aren't alive at the same time as the output
buffer.

Behavior, dump/call trees, SDK argument recovery, driver, IOCTL and contract analysis
all run on these shared facts. IOCTL analysis asks for its own report and doesn't
drag in driver classification or hypervisor analysis.

## Compatibility

Existing JSON fields, command defaults and Rust entry points still work.

- `resolution::cached` computes a fresh report every time. Use
  `AnalysisSession::resolution` if you want it reused.
- Other old convenience functions still do host lookup through compatibility
  adapters.

If you're doing repeated analysis from a library, keep your providers and sessions
around. Don't load a new SDK index or export dictionary for every call.

## Adding An Analysis

- Take image facts and explicit inputs. Keep file lookup and output formatting out of
  the analysis where you can.
- Ask only for the facts you need. Reuse the existing parsers and address conversions.
- Return evidence as data. Apply output limits and colors when rendering.
- Keep traversal budgets explicit. Only cache results for inputs that can't change
  while the cache lives.
- Check it's correct, then measure the workflow it affects, then optimize.

## Still To Move

Not everything is on this model yet:

- Cross-image call-tree traversal, kernel lookup and live checks still live in command
  adapters.
- Some older analyses still depend on CLI config and formatting.
- Discovery and disassembly share inputs but keep their own traversal policies. That's
  on purpose, they aren't interchangeable.
