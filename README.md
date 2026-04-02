<h1 align="center">RESX</h1>
<p align="center"><b>Windows Binary Analysis & RE Toolkit</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/CLI-Tools-4CAF50?style=for-the-badge" />
  <img src="https://img.shields.io/github/actions/workflow/status/TITAN-Softwork-Solutions/RESX/ci.yml?style=for-the-badge&label=CI" />
  <a href="https://discord.gg/yUWyvT9JyP">
    <img src="https://img.shields.io/discord/1240608336005828668?label=TITAN%20Softworks&logo=discord&color=5865F2&style=for-the-badge" />
  </a>
</p>


RESX is built for fast terminal-first reversing: exports, PDB-backed symbols, targeted disassembly, pseudo-C reconstruction, CFG recovery, switch-table analysis, caller tracing, PE inspection, YARA, and triage.

## Build

```powershell
cargo build --release
```

## Version And Update

```powershell
resx version
resx update
```

`resx update` is for a git checkout. It runs a fast-forward pull against the current branch on `origin`.

PDB downloads are cached on disk and symbol enumerations are reused in-process. Use `--reload` when you want to bypass both and force a fresh symbol load.

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
```

## Why It Reads Differently

- It resolves internal targets from exports and enumerated PDB symbols instead of stopping at the export table.
- It can recover structured switch dispatchers instead of leaving you with `jmp r9`.
- It can show disassembly, call maps, CFG edges, and pseudo-C in one pass, with consistent API/symbol highlighting across `dump` and `cfg`.
- It exposes `intelli` as a first-class triage command instead of hiding it behind a flag.
- It is designed to be useful on real Windows internals work, not just “dump exports and quit.”

## Showcase

### Kernel Symbol Resolution

```text
> resx dump ntoskrnl.exe KiSystemCall64 --cfg text --funcs --recomp

[+] Found: \\?\C:\Windows\System32\ntoskrnl.exe
[*] Architecture: x64  |  ImageBase: 0x140000000
[*] Exports: 3389
[*] Not found in EAT, trying PDB symbols...
[+] KiSystemCall64 @ RVA 0x006BDE40  (from enumerated PDB symbols)

ntoskrnl.exe!KiSystemCall64  [RVA 0x006BDE40, VA 0x1406BDE40]
  006BDE40  0F 01 F8                       SWAPGS
  006BDE43  65 48 89 24 25 10 00 00 00     MOV        gs:[10h],rsp
  006BDE4C  65 48 8B 24 25 A8 01 00 00     MOV        rsp,gs:[1A8h]
  006BDE55  6A 2B                          PUSH       2Bh
  006BDE57  65 FF 34 25 10 00 00 00        PUSH       qword ptr gs:[10h]
  006BDE5F  41 53                          PUSH       r11
  ...

API Call Map for KiSystemCall64  [37 call site(s)]:
   0x6BE0A9  CALL  KiFlushBhbDuringTrapEntryOrExit [internal]
   0x6BE136  CALL  KiSynchronizeUserIsolationDomainExit [internal]
   0x6BE150  CALL  KiSaveDebugRegisterState [internal]
   0x6BE166  CALL  PsSyscallProviderDispatch [internal]
   0x6BE183  CALL  KiExceptionDispatch [internal]
```

### Intelli Triage As A Real Command

```text
> resx intelli suspicious.dll WinMain --hookchk --cfg text --strings

suspicious.dll!WinMain  [RVA 0x00017A40, VA 0x0000000180017A40]
  mov  rcx, qword ptr [rip+0x4C12]
  call qword ptr [rip+0x2130] ; WinHttpSendRequest

Hook Indicators:
  entry starts with jump thunk
  in-memory prologue differs from disk at 5 offset(s)

String References:
  https://api.example-c2.net/gate
  wss://cdn.example-c2.net/socket
  C:\Users\Public\svchost.dat

Intelli Triage:
  [network] url (string) https://api.example-c2.net/gate
  [network] websocket (string) wss://cdn.example-c2.net/socket
  [filesystem] filepath (string) C:\Users\Public\svchost.dat
  [execution] process-launch (import) CreateProcessW
```

### Switch Recovery Instead Of Raw Indirect Jumps

```text
> resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text

ntoskrnl.exe!NtQuerySystemInformation  [RVA 0x00AE0FD0, VA 0x140AE0FD0]
  00AE0FDD  8D 41 F8                       LEA        eax,[rcx-8]
  00AE0FF0  3D F6 00 00 00                 CMP        eax,0F6h
  00AE0FF5  77 53                          JA         short 0000000140AE104Ah
  00AE1000  0F B6 84 01 80 10 AE 00        MOVZX      eax,byte ptr [rcx+rax+0AE1080h]
  00AE1008  44 8B 8C 81 70 10 AE 00        MOV        r9d,[rcx+rax*4+0AE1070h]
  00AE1010  4C 03 C9                       ADD        r9,rcx
  00AE1013  41 FF E1                       JMP        r9

Switch Map:
  Selector : SystemInformationClass (SYSTEM_INFORMATION_CLASS)
  Params   : 4
  Prototype: SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength
  Bias     : 0x8
  MaxIndex : 0xF6
  Targets  : 4
  Remap    : RVA 0x00AE1080
  Table    : RVA 0x00AE1070

  NtQuerySystemInformation+0x49  [RVA 0x00AE1019]
    When  : SystemProcessorPerformanceInformation (0x8), SystemInterruptInformation (0x17), 0x2A, 0x3D, 0x53, 0x64, 0x6C, 0x8D

  NtQuerySystemInformation+0x7A  [RVA 0x00AE104A]
    When  : 0x9..0x16, 0x18..0x20, SystemExceptionInformation (0x21), 0x22..0x24
            SystemRegistryQuotaInformation (0x25), 0x26..0x29, 0x2B..0x2C, SystemLookasideInformation (0x2D)
            0x2E..0x3C, 0x3E..0x48, 0x4A..0x52, 0x54..0x63, 0x65..0x66
            SystemCodeIntegrityInformation (0x67), 0x68..0x6A, 0x6D..0x78, 0x7A..0x85
            SystemPolicyInformation (0x86), 0x87..0x8C, 0x8E..0xB3, 0xB5..0xD1, 0xD4..0xDD
            0xDF..0xE6, 0xE8..0xED, 0xF1..0xFB, SystemBasicProcessInformation (0xFC)
            SystemHandleCountInformation (0xFD)
```

### Recompiler Output That Keeps Real Conditions

```text
NTSTATUS __fastcall KiSystemCall64(
    void* param_1,
    void* param_2,
    void* param_3,
    void* param_4
) {
    if ((*(KeSmapEnabled) & 0xFF) == 0) goto label_006BDEBF;
    if ((ss::*(rbp+0xF0) & 0x1) == 0) goto label_006BDEBF;
    ...
    if ((edx & 0x2) == 0) goto label_006BE09E;
    ...
    if (*(rbx+0x3) == 0) goto label_006BE198;
    ...
    result = KiExceptionDispatch();
}
```

### CFG And Recovered Edges

```text
Control Flow Graph:
  blocks:  3
  entry :  block_00AE0FD0

block_00AE0FF7:  [6 insn]  range 0x00AE0FF7..0x00AE1013
    0x00AE1000  movzx eax,byte ptr [rcx+rax+0AE1080h]
    0x00AE1008  mov r9d,[rcx+rax*4+0AE1070h]
    0x00AE1010  add r9,rcx
    0x00AE1013  jmp r9
    edges:
      [switch] switch -> block_00AE1019 (8 case(s): 0x8, 0x17, 0x2A, 0x3D, +4 more)
      [switch] switch -> block_00AE102C (1 case(s): 0x49)
      [switch] switch -> block_00AE1039 (8 case(s): 0x6B, 0x79, 0xB4, 0xD2..0xD3, +4 more)
      [switch] switch -> block_00AE104A (many case(s): 0x9..0x16, 0x18..0x29, 0x2B..0x3C, ...)
```

### Symbol Diagnostics

```text
> resx syms ntoskrnl.exe --verbose

[*] Module loaded: ntoskrnl.exe
[*] RSDS PDB: ntkrnlmp.pdb
[*] Symbol URL: http://msdl.microsoft.com/download/symbols/ntkrnlmp.pdb/<GUIDAge>/ntkrnlmp.pdb
[*] Cache path: C:\Users\<user>\AppData\Local\resx\symbols\ntkrnlmp.pdb\<GUIDAge>\ntkrnlmp.pdb
[*] Loaded symbols: type=pdb
```

## Quick Examples

```powershell
resx dump ntdll.dll NtOpenProcess --cfg text --hookchk
resx cfg ntdll.dll --at 0x161F40
resx intelli suspicious.dll
resx intelli suspicious.dll WinMain --hookchk --cfg text --strings
resx dump ntoskrnl.exe KiSystemCall64 --cfg text --funcs --recomp
resx dump ntoskrnl.exe NtQuerySystemInformation --cfg text
resx callers .\blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub --depth 2
resx locate NtOpenProcess
resx locate NtOpenProcess --include-dir C:\Work\Drivers
resx explain NtQuerySystemInformation --api
resx syms ntoskrnl.exe --verbose
resx yara suspicious.dll .\rules\triage.yar
```

## Notes

- Semantic switch labels come from parsed SDK metadata when available. Structural switch recovery still works without the SDK.
- `intelli` is a command alias for `dump` with triage enabled, so it accepts normal dump-side options too.
- `cfg` supports the same target selectors as `dump`: function name, `--at <rva>`, or `--ordinal <n>`.
- `locate` / `locate-sym` search only the priority set by default instead of walking all of `System32` / `SysWOW64`.
- `callers` scans the priority set by default.
- Use `--include-dir` and `--include-image` when you want to widen the scan beyond the priority set for `locate` or `callers`.
- `resx priority` opens the generated priority config JSON. Edit priority directories, exact names, prefixes, and regexes there.
- `explain` is a first-class command for prefix and API-name breakdowns, and `dump --explain` reuses the same glossary engine inline.
- `--edrchk` only compares against images that are already loaded in memory by default. RESX does not provide a real sandbox/container. `--unsafe-map-image` re-enables the old fallback of mapping an on-disk image into the current process and should be treated as unsafe for untrusted samples.
- `resx update` requires a git checkout with a configured `origin`.
- Use `resx help` or `resx <command> --example` for the live command help.

See `COMMANDS.md` for the full command surface.
