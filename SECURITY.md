# RESX security model

RESX treats every image, PDB, rule file, payload, corpus database, preference,
and external-tool response as untrusted input.

The public suite performs static file analysis only. An analyzed PE is never
loaded as a module, started as a process, or called through its native ABI.

## Parser requirements

- Validate lengths, counts, offsets, RVAs, VAs, integer arithmetic, encodings,
  directory extents, and section mappings before use.
- Keep explicit byte, item, instruction, recursion, graph, file, and time budgets.
- Detect cycles in linked or recursive structures.
- Preserve unavailable and ambiguous state instead of manufacturing bytes or
  choosing one interpretation silently.
- Reject malformed JSON, duplicate keys where identity matters, control
  characters, remote/device/ADS paths, and outputs that exceed declared bounds.
- Return an error or bounded partial report for hostile input; never panic, loop
  indefinitely, or perform an out-of-bounds access.

## Output and diagnostics

Terminal rendering escapes untrusted control characters. JSON uses versioned
envelopes. Diagnostic records include product/build identity, monotonic ordering,
subsystem, severity, PID/TID, source location, budgets, decision IDs, and bounded
rejection reasons where available. Diagnostics must not contain credentials,
private keys, symbol-server tokens, or raw environment secrets.

## Build and release

Release builds use optimization, LTO, checked integer overflow, static CRT,
NX-compatible and ASLR-compatible images, and Control Flow Guard where supported.
Source and release archives must exclude PDBs, signing keys, ignored fixtures,
build directories, temporary artifacts, and local corpus databases.

The required validation baseline is:

```powershell
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets
```

Fixture-dependent and oracle tests are reported separately. A skipped test is not
reported as passed.
