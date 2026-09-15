# RESX fixtures

This directory contains deterministic Windows x64 fixtures for public static
analysis and parser validation.

`scripts/build.ps1` builds optimized DLL and EXE samples for:

- export, ordinal, data-export, import-slot, and function-boundary handling;
- direct and indirect control flow, switch dispatch, callbacks, TLS, and unwind;
- API argument and producer recovery;
- behavior, contract, IPC, network, crypto, driver, and IOCTL evidence;
- structural diff, corpus index, hunt, scan, and FFI coverage.

The fixtures contain no PDB requirement. Optional NDIS fixtures require matching
WDK headers and libraries:

```powershell
.\resx-fixtures\scripts\build.ps1 -WithNdis
```

Independent codec, crypto, and unwind oracles are generated separately by the
scripts in this directory. Tests that require an unavailable oracle are explicitly
ignored and must not be reported as passed.
