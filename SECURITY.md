# Security

Ryftenius takes the security of RESX seriously. RESX is built to analyze untrusted and
hostile binaries, so every sample is treated as adversarial. A sample controls every PE
header, section, directory, string, RVA and unwind record it contains, and any of them
may be crafted to mislead the analyzer.

## Reporting a Vulnerability

**Please do not report security vulnerabilities through public GitHub issues.**

Report vulnerabilities privately through a
[GitHub Security Advisory](https://github.com/Ryftenius/RESX/security/advisories/new)
("Report a vulnerability" on the repository's **Security** tab).

To help us triage and reproduce the issue, please include as much of the following as
possible:

- The RESX version (`resx --version`) and Windows build
- The type of issue (for example crash, hang, resource exhaustion, incorrect analysis,
  path traversal or code execution)
- The exact command, options or FFI call used
- A sample or minimal PE file that reproduces the issue, or step-by-step reproduction
  instructions
- The impact of the issue, including how an attacker might exploit it

Ryftenius will acknowledge the report, investigate, and coordinate a fix and disclosure
with the reporter through the advisory.

## What Ryftenius Considers a Vulnerability

Any way for a sample to cause one of the following is treated as a security issue:

- RESX crashing or hanging
- Unbounded CPU or memory use
- Incorrect or misleading analysis results
- Embedded names or paths leading to file access or code execution on the analyst's
  machine

## Scope and Trust Boundaries

Static analysis reads a sample as data. RESX never loads a sample as an executable module
and never calls its code.

Two optional features operate outside the static analysis boundary:

- **Prologue comparison** reads a module that is already loaded and pinned.
- **`--device-security`** queries a single, operator-specified local device from a
  bounded worker. Opening a device invokes that driver's create/close path, so this is
  not a purely static check.

Within the static boundary, RESX enforces the following requirements:

| Boundary | Requirement |
| --- | --- |
| File bytes → PE structures | Lengths, counts, arithmetic and backing bytes are checked before parsing. A declared offset is not treated as evidence that the data exists. |
| PE mappings → analysis | Data is read through checked readers. Ambiguous overlaps are rejected. Unavailable bytes remain unavailable and are never treated as zero-filled. |
| Linked structures → traversal | Cycles are detected and work is bounded, including long acyclic chains and repeated aliases. |
| Embedded names → file lookup | Only plain module filenames are accepted. PDB cache names are validated and symbol-server URL segments are encoded. A sample cannot select an executable. |
| Shared facts → cached results | Facts are bound to one immutable image, and results to one analysis session and its providers. Changed bytes require a new session. |
| Reports → consumers | Terminal control characters are escaped, JSON is structured, and exhausted analysis budgets are reported. |

The Windows installation, the RESX executable and any configured tools are trusted.
Input and output paths, search directories, SDK locations and symbol-server settings are
operator choices. An attacker who can replace those tools or modify the process
environment is outside the scope of the hostile-sample boundary.

## Resource Limits

- Image reads require a regular file and stop at **512 MiB**, including files that grow
  during the read. PE section count is limited to **96**.
- Directory readers cap entries and strings. Unwind chains use cycle detection, a
  **32-record** depth limit and shared validation budgets.
- Behavior scanning shares a **one-million-instruction** budget across all sections and
  retains at most **8,192** findings. Partial results include `analysis_limits` in JSON
  and a notice in text output.
- Prologue discovery shares a **16 MiB** scan budget and reports when it stops early.
- Driver ownership uses indexed export and unwind lookups, so repeated aliases cannot
  force a full table scan per instruction.

These are analysis limits. They are not an operating-system sandbox or a process-wide
memory limit. Resource exhaustion, unchecked arithmetic and invalid slicing are still
treated as security vulnerabilities.

## Symbols and External Tools

DbgHelp is loaded only from the Windows system directory, with the same restriction
applied to its dependencies. DbgHelp's PE/PDB parsing still runs inside the RESX
process, so a trusted load path does not isolate defects in that parser. Use `--no-pdb`
to disable optional symbol loading for PE-only workflows.

The LLVM PDB fallback is resolved from an explicit tool path and never from the current
directory. It runs with a 30-second timeout, a 32 MiB output limit and bounded
type-forwarder traversal. These limits constrain the tool but do not sandbox it. Symbol
fetching also crosses a network and cache-write boundary; its transport and native
parsing are not covered by the PE malformed-input tests.

## FFI

Callers of the RESX DLL are responsible for passing valid pointers, lengths and buffer
lifetimes, and for releasing RESX-owned results through the matching API
(`ResxFreeString`). Malformed PE handling cannot make an invalid caller pointer safe.

Release builds abort on panic. Exception handling is not a substitute for validation.

## Validation and Releases

Parser regression tests cover invalid ranges, EOF, overlapping mappings, cyclic
structures, arithmetic overflow and resource amplification, alongside valid-image
controls. DbgHelp/PDB parser internals and live-device behavior require separate testing.

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo build --release
```

Skipped environment-dependent tests are reported separately.

Build outputs, PDBs, fixtures, local paths, credentials and private research artifacts
are excluded from public commits and release archives. Diagnostics do not expose
credentials or raw environment secrets.
