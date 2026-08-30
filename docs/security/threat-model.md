# RESX Threat Model

## Security Objective

Untrusted analysis input must not execute code, gain host access, write outside explicit output paths, or compromise a process hosting the RESX DLL.

## Trust Boundaries

| Boundary | Untrusted side | Trusted side |
| --- | --- | --- |
| File parsing | PE, PDB, YARA, JSON, and corpus files | RESX parsers and analysis state |
| File output | User-controlled names and paths | Explicit output destination |
| Symbol loading | Local paths and configured symbol servers | Parsed symbol data |
| VS Code integration | Opened binaries and workspace settings | Extension host and bundled RESX binary |
| DLL / FFI | Foreign pointers, strings, and option JSON | RESX-owned memory and Rust state |

## STRIDE

| Threat | Main controls |
| --- | --- |
| Spoofing | Verify PE/PDB identity; validate the configured analyzer path; identify schema versions. |
| Tampering | Parse bytes as data; bounds-check offsets and lengths; write only to explicit paths. |
| Repudiation | Return structured errors; retain command, version, input hash, and options in reproducible workflows. |
| Information disclosure | Do not expose unrelated files, process memory, credentials, or uninitialized buffers. |
| Denial of service | Bound file size, recursion, instruction count, graph size, worker count, and allocations. |
| Elevation of privilege | Do not execute analyzed images; avoid unsafe image mapping by default; run without elevated privilege. |

## High-Risk Components

- PE, PDB, unwind, resource, and load-config parsers.
- Recursive CFG, caller tracing, corpus indexing, and diffing.
- YARA rule handling and symbol retrieval.
- VS Code custom executable overrides.
- DLL pointer validation, ownership, threading, and panic containment.

## Residual Risks

- Malformed input may still trigger parser defects or excessive resource use.
- Optional symbol servers disclose requested PDB identities to the configured server.
- `--unsafe-map-image` increases attack surface and must only be used with trusted input.
- Static analysis can be incomplete when code is packed, generated, or data-dependent.

Report suspected weaknesses through [SECURITY.md](../../SECURITY.md).
