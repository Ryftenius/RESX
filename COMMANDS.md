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
- `resx cfg <dll> --at <rva>`
- `resx cfg <dll> --ordinal <n>`
- `resx intelli <dll> [function]`
- `resx peinfo <dll>`
- `resx sections <dll>`
- `resx eat <dll>`
- `resx iat <dll>`
- `resx syms <dll>`
- `resx pechk <dll>`
- `resx priority`
- `resx callers <dll> <function>`
- `resx locate <name>`
- `resx locate-sym <name>`
- `resx explain <name>`
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
- `--explain`
- `--prefix`
- `--api`
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

## Explain

- `resx explain <name>` explains a prefix or API-style symbol using the built-in glossary.
- `--prefix` forces prefix-mode interpretation.
- `--api` forces API/symbol-mode interpretation.
- `dump --explain` reuses the same explanation engine inline for the current target.

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
- `--include-dir <dir>`
- `--include-image <dll>`
- `--scan-exe`
- `--include <glob>`
- `--scope-file <glob>` / `--include-file <glob>`
- `--exclude <glob>`
- `--max-dll-size <mb>`
- `--workers <n>`

## Global Flags

- `--path <dir>`
- `--priority`
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
- `cfg` supports function names, `--at <rva>`, and `--ordinal <n>` just like `dump`.
- `cfg` and `dump` use the same instruction and API/symbol highlighting path for call targets and comments.
- `dump --recomp` emits corrected bit-test branches and better local-call placeholders.
- `dump --funcs-depth <n>` expands nested API call depth and accepts levels `1` through `5`.
- `syms --verbose` can show exact PDB identity/load diagnostics, including RSDS-derived kernel PDB names.
- `dump` can resolve internal names from enumerated PDB symbols when exports do not contain the target.
- `dump` can surface syscall service numbers and kernel targets for `Nt*` and `Zw*` stubs.
- `locate` and `locate-sym` search only the priority set by default.
- `callers` uses the priority set by default.
- `--include-dir` and `--include-image` widen the scan beyond the priority set for `locate` and `callers`.
- `callers --include-dir` will scan `.dll` and `.sys` images by default, and `.exe` as well when `--scan-exe` is set.
- `--include` filters the entire callers scan list; `--scope-file` only filters files discovered through `--include-dir`.
- `priority` opens the generated priority config JSON where you can edit directories, exact names, prefixes, and regexes.

## Examples

```powershell
resx dump ntdll.dll NtOpenProcess --cfg text --hookchk
resx cfg ntdll.dll --at 0x161F40
resx intelli suspicious.dll
resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
resx dump ntoskrnl.exe KiSystemCall64 --cfg text --funcs --recomp
resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
resx syms ntoskrnl.exe --verbose
resx callers blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub --depth 2
resx callers ntoskrnl.exe NtOpenProcess --include-dir C:\Work\Drivers --depth 2
resx callers ntoskrnl.exe PsOpenProcess --include-dir C:\Windows\System32\drivers --scope-file *.sys
resx priority
resx locate NtOpenProcess
resx locate NtOpenProcess --include-dir C:\Work\Drivers
resx locate-sym NtWriteVirtualMemory --include-image .\mydriver.sys
resx explain NtQuerySystemInformation --api
resx update
```
