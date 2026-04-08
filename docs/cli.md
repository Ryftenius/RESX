# RESX CLI

RESX provides a Windows-focused CLI for disassembly, symbol-backed inspection, call tracing, CFG recovery, pseudo-C reconstruction, PE metadata inspection, and triage.

## Repository Layout

- Workspace root: `../Cargo.toml`
- CLI crate: `../resx`

## Build

```powershell
cargo build --release
```

## Core Commands

```powershell
resx dump <dll> <function>
resx dump <dll> --at <rva>
resx dump <dll> --ordinal <n>
resx cfg <dll> <function>
resx cfg <dll> --at <rva>
resx cfg <dll> --ordinal <n>
resx intelli <dll> [function]
resx peinfo <dll>
resx sections <dll>
resx eat <dll>
resx iat <dll>
resx syms <dll>
resx pechk <dll>
resx priority
resx callers <dll> <function>
resx locate <name>
resx locate-sym <name>
resx explain <name>
resx yara <dll> <rule.yar>
resx update
resx help
resx <command> --example
```

## Common Examples

```powershell
resx dump ntdll.dll NtOpenProcess --cfg text --hookchk
resx dump kernel32.dll CreateFileW --funcs --xrefs
resx cfg ntdll.dll --at 0x161F40
resx intelli suspicious.dll
resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
resx peinfo .\blackbird.sys
resx sections ntdll.dll
resx eat kernel32.dll
resx iat kernel32.dll
resx pechk suspicious.dll
resx dump ntoskrnl.exe KiSystemCall64 --cfg text --funcs --recomp
resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
resx callers .\blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub --depth 2
resx callers ntoskrnl.exe PsOpenProcess --include-dir C:\Windows\System32\drivers --scope-file *.sys
resx locate NtOpenProcess
resx locate NtOpenProcess --include-dir C:\Work\Drivers
resx locate-sym RtlpHeapHandleError
resx explain NtQuerySystemInformation --api
resx syms ntoskrnl.exe --verbose
resx yara suspicious.dll .\rules\triage.yar
```

## Notable Capabilities

- Export and PDB-backed symbol resolution
- Targeted disassembly with `--at`, ordinal, and symbol lookup flows
- Recovered CFG text output and switch-dispatch analysis
- Nested API call expansion with `--funcs-depth 1..5`
- Syscall service number and kernel-target surfacing for `Nt*` and `Zw*` stubs
- Pseudo-C reconstruction with `--recomp`
- PE metadata, mitigation, signer, and debug-directory inspection
- Priority-based locate and caller tracing workflows

## References

- [Command reference](../COMMANDS.md)
- [VS Code extension documentation](vscode-extension.md)
