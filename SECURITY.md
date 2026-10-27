# RESX threat model

RESX analyzes untrusted binaries. A sample can control every PE header, section,
directory, string, RVA and unwind record. The threats are crashes, hangs, excessive
CPU or memory use, misleading analysis, and turning embedded names into file access
or code execution on the analyst's machine.

## Scope and trust boundaries

Static analysis reads a sample as data. It does not load that sample as an executable
module or call its code. Optional live checks are separate: prologue comparison reads
an already-loaded, pinned module; `--device-security` queries the selected local device
in a bounded worker. Opening a device can invoke its driver. These modes are not part
of the static parser boundary.

| Boundary | Required behavior |
| --- | --- |
| File bytes into PE structures | Check lengths, counts, arithmetic and backing bytes before parsing. A declared offset is not proof that data exists. |
| PE mappings into analysis | Use checked readers. Reject ambiguous overlaps and keep unavailable bytes distinct from zero-filled memory. |
| Linked structures into traversal | Detect cycles and bound work, including long acyclic chains and repeated aliases. |
| Embedded names into file lookup | Require plain module filenames. Validate PDB cache names and encode symbol-server URL segments. Sample names do not select executables. |
| Shared facts into cached results | Bind facts to an immutable image and results to its analysis session and providers. Changed bytes require a new session. |
| Reports into consumers | Escape terminal control characters, produce structured JSON, and report exhausted analysis budgets. |

Explicit input/output paths, search directories, SDK locations and symbol-server
settings are operator choices. The Windows installation, RESX executable and configured
tools must be trusted. An attacker who can replace those tools or alter the process's
environment is outside the hostile-sample boundary.

## Resource limits

- Image reads require a regular file and stop at 512 MiB, including files that grow
  while being read. PE section counts are limited to 96.
- Directory readers cap entries and strings. Unwind chains have cycle detection,
  a 32-record depth limit and shared validation work budgets.
- Behavior scanning shares a one-million-instruction budget across sections and
  retains at most 8,192 findings. Partial results include `analysis_limits` in JSON
  and a notice in text output.
- Prologue discovery shares a 16 MiB scan budget and reports when it stops early.
- Driver ownership uses indexed export and unwind lookups, so repeated aliases do
  not force a full table scan for every instruction.

These are analysis limits, not an OS sandbox or a process-wide memory ceiling.
Resource exhaustion, unchecked arithmetic and invalid slicing remain security bugs.

## Symbols and external tools

DbgHelp is loaded from the Windows system directory, with the same restriction on
dependency lookup. Its PE/PDB parsing still runs inside RESX. A trusted DLL path does
not isolate native parser defects. Use `--no-pdb` to disable optional symbol loading
for PE-only workflows.

The LLVM PDB fallback resolves an explicit tool path without searching the current
directory. It has a 30-second timeout, a 32 MiB output limit and bounded type-forwarder
traversal. The timeout and output cap do not make the tool a sandbox. Symbol fetching
is also a network and cache-write boundary; its transport and native parsing are
outside the coverage of the PE malformed-input tests.

FFI callers must provide valid pointers, lengths and buffer lifetimes, and release
RESX-owned results through the matching API. Malformed PE handling cannot make an
invalid native caller pointer safe. Release builds abort on panic; exception handling
is not a substitute for validation.

## Validation and releases

Parser regressions cover invalid ranges, EOF, overlapping mappings, cyclic structures,
arithmetic overflow and resource amplification, alongside valid-image controls.
Native DbgHelp/PDB parser internals and live-device behavior require separate testing.

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo build --release
```

Skipped environment-dependent tests are reported separately. Build outputs, PDBs,
fixtures, local paths, credentials and private research artifacts do not belong in
public commits or release archives. Diagnostics must not expose credentials or raw
environment secrets.
