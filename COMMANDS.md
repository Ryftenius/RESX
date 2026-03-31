# COMMANDS

## Identity

- Name: `RESX`
- Author: `TITAN Softwork Solutions`
- Version: `resx version` or `resx --version`

## Core

- `resx dump <dll> <function>`
- `resx dump <dll> --at <rva>`
- `resx dump <dll> --ordinal <n>`
- `resx cfg <dll> <function>`
- `resx intelli <dll> [function]`
- `resx peinfo <dll>`
- `resx sections <dll>`
- `resx eat <dll>`
- `resx iat <dll>`
- `resx syms <dll>`
- `resx pechk <dll>`
- `resx callers <dll> <function>`
- `resx locate <name>`
- `resx locate-all <name>`
- `resx locate-sym <name>`
- `resx locate-all-sym <name>`
- `resx yara <dll> <rule.yar>`
- `resx update`

## Dump And Analysis Flags

- `--at <rva>`
- `--ordinal <n>`
- `--recomp`
- `--c-out <file>`
- `--cfg text`
- `--funcs`
- `--funcs-depth <n>`
- `--xrefs`
- `--strings`
- `--edrchk`
- `--unsafe-map-image`
- `--hookchk`
- `--intelli`
- `--follow-jmp`
- `--no-follow-jmp`
- `--rebase <addr>`

## Intelli

- `resx intelli <dll>` runs triage against an image quickly.
- `resx intelli <dll> <function>` narrows the triage to a specific target while still allowing dump-side options like `--hookchk`, `--cfg text`, `--strings`, and `--json`.
- `intelli` is a command alias for the dump pipeline with `--intelli` enabled.

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
- `--scan-dir <dir>`
- `--scan-dll <dll>`
- `--scan-exe`
- `--include <glob>`
- `--exclude <glob>`
- `--max-dll-size <mb>`
- `--workers <n>`

## Global Flags

- `--path <dir>`
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
- `dump --recomp` emits corrected bit-test branches and better local-call placeholders.
- `syms --verbose` can show exact PDB identity/load diagnostics, including RSDS-derived kernel PDB names.
- `dump` can resolve internal names from enumerated PDB symbols when exports do not contain the target.

## Examples

```powershell
resx dump ntdll.dll NtOpenProcess --cfg text --hookchk
resx intelli suspicious.dll
resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
resx dump ntoskrnl.exe KiSystemCall64 --cfg text --funcs --recomp
resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
resx syms ntoskrnl.exe --verbose
resx callers blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub --depth 2
resx locate-all-sym NtWriteVirtualMemory
resx update
```
