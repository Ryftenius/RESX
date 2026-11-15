# Security

RESX exists to pull apart binaries that don't want to be pulled apart, so every sample
is treated as hostile. A sample controls every PE header, section, directory, string,
RVA and unwind record it ships with, and it will lie in all of them.

What I care about here:

- RESX crashing or hanging
- a sample burning unbounded CPU or memory
- a sample tricking RESX into a wrong or misleading result
- a sample turning names embedded in it into file access or code execution on the analyst's machine

If you find a way to do any of those, that's a security bug.

## Reporting

Please report vulnerabilities privately through GitHub's **Report a vulnerability**
button on the Security tab, not as a public issue. Include the RESX version
(`resx --version`), the command you ran, and a sample or minimal PE that reproduces it.

## What Counts As The Sample

Static analysis reads the sample as data. It never loads it as a module and never
calls its code.

Two things sit outside that boundary and are opt-in:

- **Prologue comparison** reads a module that's already loaded and pinned.
- **`--device-security`** queries one local device you name, from a bounded worker.
  Opening a device runs that driver's create/close path, so this is not a pure static check.

Inside the static boundary, each step has a rule:

| Boundary | Rule |
| --- | --- |
| File bytes → PE structures | Check lengths, counts, arithmetic and backing bytes before parsing anything. A declared offset doesn't mean the data is actually there. |
| PE mappings → analysis | Read through checked readers. Reject ambiguous overlaps. Bytes that aren't available stay unavailable, they never become zeroes. |
| Linked structures → traversal | Detect cycles and cap the work, including long chains without a cycle and repeated aliases. |
| Embedded names → file lookup | Only plain module filenames. PDB cache names are validated and symbol-server URL segments are encoded. A sample can never pick which executable gets run. |
| Shared facts → cached results | Facts are tied to one immutable image, results to one analysis session and its providers. Changed bytes mean a new session. |
| Reports → consumers | Terminal control characters are escaped, JSON is structured, and hitting an analysis budget is reported. |

What I trust: the Windows install, the RESX executable, and any tools you configure.
Paths you pass in, search directories, SDK locations and symbol-server settings are your
choice. If an attacker can replace those tools or mess with the process environment,
they're already past the hostile-sample boundary and this document doesn't cover it.

## Limits

- Image reads need a regular file and stop at **512 MiB**, including files that grow
  while being read. PE section count is capped at **96**.
- Directory readers cap entries and strings. Unwind chains get cycle detection, a
  **32-record** depth limit and shared validation budgets.
- Behavior scanning shares a **one-million-instruction** budget across all sections and
  keeps at most **8,192** findings. If it stops early, JSON gets `analysis_limits` and
  text output gets a notice.
- Prologue discovery shares a **16 MiB** scan budget and says when it stops early.
- Driver ownership uses indexed export and unwind lookups, so a sample can't force a full
  table scan per instruction by repeating aliases.

These are analysis limits. They are not an OS sandbox and not a process-wide memory cap.
Resource exhaustion, unchecked arithmetic and bad slicing are still security bugs.

## Symbols And External Tools

DbgHelp is loaded from the Windows system directory, with dependency lookup restricted
the same way. Its PE/PDB parsing still runs inside the RESX process though, so a trusted
DLL path doesn't protect you from bugs in DbgHelp's own parser. If you don't need
symbols, `--no-pdb` turns them off.

The LLVM PDB fallback only runs from an explicit tool path, never the current directory.
It gets a 30-second timeout, a 32 MiB output cap and bounded type-forwarder traversal.
That keeps it in check, it doesn't sandbox it. Symbol fetching also touches the network
and writes to the cache, and neither the transport nor the native parsing is covered by
the PE malformed-input tests.

## FFI

If you call RESX through the DLL, you're responsible for passing valid pointers, lengths
and buffer lifetimes, and for freeing RESX-owned results through the matching API
(`ResxFreeString`). RESX can survive a malformed PE. It can't survive you handing it a
bad pointer.

Release builds abort on panic. Exception handling isn't a replacement for validation.

## Testing And Releases

Parser regression tests cover invalid ranges, EOF, overlapping mappings, cyclic
structures, arithmetic overflow and resource amplification, alongside valid images as
controls. DbgHelp/PDB internals and live-device behaviour need their own testing.

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
cargo build --release
```

Environment-dependent tests that get skipped are reported separately.

Build outputs, PDBs, fixtures, local paths, credentials and private research material
don't go into public commits or release archives. Diagnostics never print credentials
or raw environment secrets.
