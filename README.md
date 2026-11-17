<h1 align="center">RESX</h1>
<p align="center"><b>Windows Binary Analysis & Reverse Engineering Toolkit</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white&style=for-the-badge" />
  <img src="https://img.shields.io/github/actions/workflow/status/RYFTENIUS/RESX/ci.yml?style=for-the-badge&label=CI" />
</p>

**RESX** is a Windows-focused binary analysis and reverse-engineering toolkit written in Rust, built around problems I've repeatedly run into while reversing Windows binaries. It's designed to help with malware triage, recovering hidden API calls, reconstructing control flow, analyzing kernel drivers, and tracing Windows APIs through syscalls into the kernel. It also understands Windows-specific constructs, including driver interfaces, hypervisor instructions, and potential security telemetry paths.

RESX isn't intended to replace IDA Pro or Ghidra. It's a specialized toolkit that complements existing reverse-engineering workflows, with an emphasis on recovering information that would otherwise take considerable manual analysis.

## Showcase & Examples

Every example below is real RESX output. The tested examples include checked-in public fixtures where linked; Example 2 also preserves a historical IDA comparison from a separate sample. Click any title to expand it.

<table>
<tr><th colspan="2">Historical Example 2 comparison: a syscall stub built to break disassemblers</th></tr>
<tr><th>IDA Pro 9.0 + Hex-Rays</th><th>RESX 2.2.1</th></tr>
<tr>
<td valign="top">

```asm
jz   short near ptr loc_F4C5+2
jmp  short $+2
mov  r11, 9F08EB0000000FE8h
       ; F4C7: Can't disassemble
mov  eax, 0C0000022h
...
db 8Bh, 0C1h, 48h, ...  ; stub = data
```

```c
void sub_14000F460()
{
  JUMPOUT(0x14000F4C7LL);
}
```

</td>
<td valign="top">

```asm
je   short 0x14000f4c7
jmp  short 0x14000f4c5
mov  r11, 0x9f08eb0000000fe8
call 0x14000f4db   ; hidden call
jmp  short 0x14000f4d6
mov  eax, 0xc0000022  ; decoy
...
Overlapping decode streams: 10
  nop/mov/lea/cmp/imul carriers
  each with its hidden jmp

└── 0xF4C7  CALL  sub_0000F4DB
```

</td>
</tr>
</table>

| | Tested example | What RESX shows |
| --- | --- | --- |
| **1** | [Encoded APIs & manual resolution](#tested-example-1) | Seven XOR-hidden APIs, the key, the PEB and export-table walk, and every indirect call site |
| **2** | [Overlapping instruction seams vs IDA Pro](#tested-example-2) | The call IDA cannot decode, the syscall stub IDA leaves as data, and all six seams |
| **3** | [API hashing vs IDA Pro & Ghidra](#tested-example-3) | The hash algorithm, all six hidden API names, and every indirect call made through them |
| **4** | [Learning an API for implant & exploit development](#tested-example-4) | `WriteProcessMemory` from SDK prototype to its hidden reprotection, syscall number, kernel access check and EDR telemetry |

<a id="tested-example-1"></a>
<details>
<summary><h3 style="display: inline;">Tested Example 1: Encoded APIs &amp; Manual Resolution</h3></summary>

Let's say I want to analyze a binary that hides its Windows API names with XOR and resolves them by walking the PEB loader list and the module's export table. The checked-in [C sample](resx/tests/data/manual_resolver.c) allocates a page, writes an inert byte, changes the page protection, releases it, and attempts a protected-directory listing. Its [compiled EXE](resx/tests/data/manual_resolver.exe) has no PDB, and none of the seven APIs below appear in its import table.

```powershell
> resx behavior .\resx\tests\data\manual_resolver.exe --no-pdb --no-headers
Dynamic API resolution: PEB loader-list walk; manual export-table walk
[HIGH] api-resolution export-table-walk (high @ 0x0000138C)
[HIGH] api-resolution peb-module-walk (high @ 0x00001179)

Dynamically resolved APIs (7):
  0x0000155C  kernelbase!VirtualAlloc  [export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal, 1 call site]
  0x00001578  kernelbase!VirtualProtect  [export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal, 2 call sites]
  0x00001594  kernelbase!VirtualFree  [export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal, 3 call sites]
  0x000015B0  kernelbase!FindFirstFileW  [export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal, 1 call site]
  0x000015CC  kernelbase!FindNextFileW  [export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal, 1 call site]
  0x000015E8  kernelbase!FindClose  [export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal, 1 call site]
  0x00001604  kernelbase!GetLastError  [export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal, 1 call site]
```

The `calls` view connects those resolutions to the indirect calls in the sample:

```powershell
> resx calls .\resx\tests\data\manual_resolver.exe rentry --depth 8 --only dynamic --no-pdb --no-headers
      ├── 0x155C  CALL  sub_00001240
      │   resolves: kernelbase!VirtualAlloc (export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal)
      ├── 0x1678  CALL  kernelbase!VirtualAlloc [dynamic · export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal]
      ├── 0x16BA  CALL  kernelbase!VirtualProtect [dynamic · export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal]
      └── 0x17C8  CALL  kernelbase!FindClose [dynamic · export-table walk sub_00001240 · xor 0x5A · loader-list walk, literal]
```

With one small sample, RESX recovers the API names, the XOR key, the manual resolution path, and the actual indirect call sites without debug symbols. The executable page contains only `RET` and is never executed; the directory attempt returned `ACCESS_DENIED` in this test.

</details>

<a id="tested-example-2"></a>
<details>
<summary><h3 style="display: inline;">Tested Example 2: Overlapping Instruction Seams (with a historical IDA comparison)</h3></summary>

**Reproduce the overlap with the public fixture.** The checked-in [x64 assembly source](resx/tests/data/overlap_probe.asm) and [2 KB PE](resx/tests/data/overlap_probe.exe) live with the other public samples in [the test-data directory](resx/tests/data/README.md), which includes a warning and rebuild instructions. Its entry point and hidden callee are inert. From the repository root:

IDA Pro 9.0's default auto-analysis of this same public PE produces this listing for `OverlapProbe`:

```asm
.text:0000000140001009  jz   short near ptr loc_14000100D+2
.text:000000014000100B  jmp  short $+2
.text:000000014000100D  mov  r11, 9F08EB0000000FE8h
.text:0000000140001017  mov  eax, 0C0000022h
.text:000000014000101C  jmp  short $+2
.text:000000014000101E  retn
```

IDA does not decode an instruction at `0x14000100F` or create a code reference from it to `HiddenTarget`. It does identify `HiddenTarget` separately because the fixture exports that name. On the same PE, RESX shows both streams and the call:

```powershell
> resx dump .\resx\tests\data\overlap_probe.exe OverlapProbe --bytes --calls --no-pdb --no-color
OverlapProbe @ RVA 0x00001003  (ord 2)

overlap_probe.exe!OverlapProbe  [RVA 0x00001003, VA 0x140001003]
  00001009  74 04                          je         short 0x14000100f
  0000100b  eb 00                          jmp        short 0x14000100d
  0000100d  49 bb e8 0f 00 00 00 eb 08 9f  mov        r11, 0x9f08eb0000000fe8
  0000100f  e8 0f 00 00 00                 call       HiddenTarget
  00001014  eb 08                          jmp        short 0x14000101e

API Call Map for OverlapProbe  [1 call site(s)]:
  └── 0x100F  CALL  HiddenTarget
```

The `je` at `0x1009` enters two bytes into the `mov` at `0x100D`; RESX shows both decodes and follows the hidden call. These lines are excerpted from the checked-in binary's output. Both tools were run without a PDB. The fixture proves this overlap behavior, but it is **not** the syscall-stub binary used for the historical IDA Pro comparison below.

The historical comparison used an advanced sample that never calls `ntdll`. It carries its own syscall stub, and the stub is built to break disassemblers. It uses *overlapping instruction seams*: an always-taken `jz` lands two or three bytes inside a longer "carrier" instruction, so the same bytes decode as two different instruction streams. One of those streams is the code that actually runs. The other is a decoy that ends in a fake failure path. The sample has no PDB, and every name below was assigned by the tools.

IDA Pro 9.0 follows the decoy. In `sub_14000F460`, the `jz` at `0xF4C1` targets `0xF4C7`, which is the middle of a 10-byte `mov r11, imm64`. IDA marks `0xF4C7` as *Can't disassemble* and never decodes the `call` hidden there. In IDA's listing the function always returns `0xC0000022` (`STATUS_ACCESS_DENIED`), and Hex-Rays gives up:

```asm
; IDA 9.0, auto-analysis
.text:000000014000F4C1    jz      short near ptr loc_14000F4C5+2
.text:000000014000F4C3    jmp     short $+2
.text:000000014000F4C5    mov     r11, 9F08EB0000000FE8h     ; F4C7 "Can't disassemble"
.text:000000014000F4CF    mov     eax, 0C0000022h
.text:000000014000F4D4    jmp     short $+2
.text:000000014000F4D6    add     rsp, 68h
.text:000000014000F4DA    retn
.text:000000014000F4DB    db 8Bh, 0C1h, 48h, 8Bh, 0CAh  ; the real stub, left as data
.text:000000014000F4E0    dq 8B4CC18B4DD08B49h, ...
```

```c
// Hex-Rays 9.0
void sub_14000F460()
{
  JUMPOUT(0x14000F4C7LL);
}
```

Because the hidden `call` is never decoded, nothing in IDA reaches `0xF4DB`. The routine that performs the syscall is never disassembled and stays as raw `db`/`dq` bytes.

`resx dump` decodes both streams and keeps them side by side. The carrier at `0xF4C5` and the overlapping `call` at `0xF4C7` are both in the listing, and the call map follows the hidden edge into the stub:

```powershell
> resx dump .\sample.exe --at 0xF460 --bytes --calls --no-pdb  # historical sample
  0000f4be  45 85 db                       test       r11d, r11d
  0000f4c1  74 04                          je         short 0x14000f4c7  ; → loc_0000f4c7
  0000f4c3  eb 00                          jmp        short 0x14000f4c5  ; → loc_0000f4c5
  0000f4c5  49 bb e8 0f 00 00 00 eb 08 9f  mov        r11, 0x9f08eb0000000fe8
  0000f4c7  e8 0f 00 00 00                 call       0x14000f4db  ; → loc_0000f4db
  0000f4cc  eb 08                          jmp        short 0x14000f4d6  ; → loc_0000f4d6
  0000f4cf  b8 22 00 00 c0                 mov        eax, 0xc0000022  ; possible NTSTATUS: STATUS_ACCESS_DENIED
  0000f4d4  eb 00                          jmp        short 0x14000f4d6  ; → loc_0000f4d6
  0000f4d6  48 83 c4 68                    add        rsp, 0x68
  0000f4da  c3                             ret

API Call Map for fn_0x0000F460  [1 call site(s)]:
  └── 0xF4C7  CALL  sub_0000F4DB
```

The stub at `0xF4DB` moves the service number into `eax`, shifts the arguments into the native syscall ABI, and then passes through five more seams. Each one is keyed on a bit of the service number, and the carriers are `nop`, `mov`, `lea`, `cmp` and `imul`, with immediates that differ between builds. A linear decode yields junk such as `nop dword ptr [rax+rax-7844FD15h]` and `imul r11d, 0B3402EBh`, and hides every real `jmp`. With `--verbose`, RESX reports each seam it resolved, naming the carrier and the alternate `jmp` inside it, and lays the real jump directly under its carrier:

```powershell
> resx dump .\sample.exe --at 0xF4DB --bytes --verbose --no-pdb  # historical sample
  Overlapping decode streams: 10 finding(s), 10 shown
  [INFO] branch-into-instruction: stream 0x0000f533 enters 0x0000f53b inside stream instruction 0x0000f537
    0F 1F 84 00 EB 02 BB 87 | nop dword ptr [rax+rax-0x7844fd15] | alternate: jmp short 000000014000F53Fh
  [INFO] branch-into-instruction: stream 0x0000f541 enters 0x0000f547 inside stream instruction 0x0000f545
    49 BB EB 06 4F 96 D2 16 7C 1D | mov r11, 0x1d7c16d2964f06eb | alternate: jmp short 000000014000F54Fh
  ...
  0000f4db  8b c1                          mov        eax, ecx
  0000f4dd  48 8b ca                       mov        rcx, rdx
  ...
  0000f569  a8 80                          test       al, 0x80
  0000f56b  74 05                          je         short 0x14000f572  ; ... alternate stream 0x0000f572 overlaps instruction at 0x0000f56f
  0000f56d  eb 00                          jmp        short 0x14000f56f
  0000f56f  45 69 db eb 02 34 0b           imul       r11d, 0xb3402eb
  0000f572  eb 02                          jmp        short 0x14000f576  ; ... alternate stream 0x0000f572 overlaps instruction at 0x0000f56f
  0000f576  4c 8b d1                       mov        r10, rcx
  0000f579  0f 04 c3                       (bad)
```

The stub ends with a second trick. Where `syscall` (`0F 05`) belongs, the file stores `0F 04`, which is not a valid instruction, and the sample patches that byte at run time. Neither tool can decode an instruction that is not on disk: RESX reports the bytes as `(bad)`, and IDA leaves them as data. The `mov r10, rcx` immediately before it, with the service number in `eax`, is the standard x64 syscall setup, and it points straight at the patched opcode. RESX recovers the full static route from the outer function, through every seam, to that point. IDA's listing and decompiler output lose it at the first seam.

Tested with RESX 2.2.1 and IDA Pro 9.0 (Hex-Rays 9.0.0.240807), both without symbols. Seam recovery is part of `dump`'s per-function multi-stream decoding; the image-wide `xrefs` and `callers` scans do not yet follow calls hidden inside a seam.

</details>

<a id="tested-example-3"></a>
<details>
<summary><h3 style="display: inline;">Tested Example 3: API Hashing vs IDA Pro &amp; Ghidra</h3></summary>

Let's say I'm triaging a loader that hides every API it uses behind a hash. This is the shellcode staple: walk the PEB to find a module, walk its export table, and hash each export name until one matches a constant baked into the binary. No API name appears in the image, not even as an encoded string, so there is nothing to decode. The only way to name these calls is to know the hash construction and invert it.

The checked-in [C sample](resx/tests/data/hash_resolver.c) uses ROR13 over the uppercase UTF-16 module name and the ASCII export name. It resolves `LoadLibraryA` by hash, uses it to load a library whose name is built on the stack, and then resolves a function from that library by hash too. It runs recon calls that only report string lengths, and touches an inert executable page that is never run. The [compiled EXE](resx/tests/data/hash_resolver.exe) has no PDB.

IDA Pro 9.0 shows each resolution as an anonymous function pointer filled from a decimal constant. Hex-Rays does rebuild the stack string, but none of the six APIs is ever named, so every later call is `v1(...)`, `v2(...)` and so on:

```c
// IDA Pro 9.0, Hex-Rays
v0 = sub_1400010D0(1783282779LL);
v1 = (void (__fastcall *)(_QWORD *))sub_140001010(v0, 3960360590LL);
v2 = (__int64 (__fastcall *)(_QWORD, __int64, __int64, __int64, _QWORD, _DWORD))sub_140001010(v0, 2444216916LL);
v3 = (unsigned int (__fastcall *)(_BYTE *, __int64, __int64, char *))sub_140001010(v0, 2034681371LL);
v4 = (unsigned int (__fastcall *)(_BYTE *, _QWORD, __int64))sub_140001010(v0, 50738092LL);
v5 = sub_140001010(v0, 2527339173LL);
strcpy((char *)v16, "advapi32");
...
v13 = (_BYTE *)v2(0LL, 4096LL, 12288LL, 4LL, v16[0], v16[1]);
```

Ghidra 11.2.1 prints the hashes in hex but otherwise does less. The stack string stays as two integers, and the resolved pointers are untyped `code *`. Because Ghidra doesn't know the pointer at `pcVar7` is `GetComputerNameW`, it drops the size argument and folds the returned length to its initial value, `0x100`:

```c
// Ghidra 11.2.1
pcVar3 = (code *)FUN_140001010(psVar2,0xec0e4e8e);
pcVar4 = (code *)FUN_140001010(psVar2,0x91afca54);
...
local_238 = 0x61766461;
local_234 = 0x32336970;
...
iVar1 = (*pcVar7)(local_228);
uVar9 = 0;
if (iVar1 != 0) {
  uVar9 = 0x100;
}
```

Both tools need a hash-database plugin and some manual retyping to get further. RESX inverts the hashes itself. It reads the rotate count from the resolver's code, tries the matching constructions against the local system's export names, and names all six APIs, including `GetUserNameW` from the library that was loaded at run time:

```powershell
> resx behavior .\resx\tests\data\hash_resolver.exe --no-pdb --no-headers
Dynamic API resolution: PEB loader-list walk; API hashing (ror13-add); manual export-table walk; loader API by name
[HIGH] api-resolution api-hashing (high @ 0x000011F8)
  APIs or modules are looked up by hash (ror13-add)
...
Dynamically resolved APIs (7):
  0x000011F8  ?!LoadLibraryA  [export-table walk sub_00001010 · ror13-add hash 0xEC0E4E8E, 1 call site]
  0x00001208  ?!VirtualAlloc  [export-table walk sub_00001010 · ror13-add hash 0x91AFCA54, 1 call site]
  0x00001218  ?!VirtualProtect  [export-table walk sub_00001010 · ror13-add hash 0x7946C61B, 1 call site]
  0x00001228  ?!VirtualFree  [export-table walk sub_00001010 · ror13-add hash 0x30633AC, 2 call sites]
  0x00001238  ?!GetComputerNameW  [export-table walk sub_00001010 · ror13-add hash 0x96A422A5, 1 call site]
  0x0000129B  ?!GetUserNameW  [export-table walk sub_00001010 · ror13-add hash 0x5C52AA4A, 1 call site]
  0x0000798B  mscoree!CorExitProcess  [GetProcAddress]
```

The call map then follows each resolved pointer to the indirect calls that use it, so `call r14` reads as `VirtualAlloc`:

```powershell
> resx calls .\resx\tests\data\hash_resolver.exe 0x11D0 --depth 2 --only dynamic --no-pdb --no-headers
  ├── 0x1238  CALL  sub_00001010
  │   resolves: ?!GetComputerNameW (export-table walk sub_00001010 · ror13-add hash 0x96A422A5)
  ├── 0x1287  CALL  !LoadLibraryA [dynamic · export-table walk sub_00001010 · ror13-add hash 0xEC0E4E8E]
  ├── 0x129B  CALL  sub_00001010
  │   resolves: ?!GetUserNameW (export-table walk sub_00001010 · ror13-add hash 0x5C52AA4A)
  ├── 0x12C4  CALL  !GetComputerNameW [dynamic · export-table walk sub_00001010 · ror13-add hash 0x96A422A5]
  ├── 0x12F7  CALL  !GetUserNameW [dynamic · export-table walk sub_00001010 · ror13-add hash 0x5C52AA4A]
  ├── 0x1324  CALL  !VirtualAlloc [dynamic · export-table walk sub_00001010 · ror13-add hash 0x91AFCA54]
  ├── 0x134F  CALL  !VirtualProtect [dynamic · export-table walk sub_00001010 · ror13-add hash 0x7946C61B]
  ├── 0x1360  CALL  !VirtualFree [dynamic · export-table walk sub_00001010 · ror13-add hash 0x30633AC]
  └── 0x1369  CALL  !VirtualFree [dynamic · export-table walk sub_00001010 · ror13-add hash 0x30633AC]
```

Without symbols or plugins, RESX recovers the hash algorithm, every hidden API name, the resolver that produced each pointer, and every call made through it. The module hashes are not inverted yet, so modules print as `?`. `CorExitProcess` is the C runtime's own `GetProcAddress` lookup, not part of the sample's logic. The sample printed the two name lengths and released its inert page in this test.

Tested with RESX 2.2.1, IDA Pro 9.0 (Hex-Rays 9.0.0.240807) and Ghidra 11.2.1, each with default auto-analysis.

</details>

<a id="tested-example-4"></a>
<details>
<summary><h3 style="display: inline;">Tested Example 4: Learning an API for Implant &amp; Exploit Development</h3></summary>

Now let's look at it from the other side. Say I'm writing an implant or an exploit and need to write into another process. Before I use `WriteProcessMemory`, I want to know exactly what it takes, where it really lives, what it does under the hood, and what the kernel does with it, without opening a disassembler or a debugger.

First, the contract. `resx api` reads it straight from the Windows SDK headers, SAL annotations included. Note the `nSize` annotation tying `lpBuffer` to its length:

```powershell
> resx api WriteProcessMemory
BOOL WriteProcessMemory(
    _In_ HANDLE hProcess,
    _In_ LPVOID lpBaseAddress,
    _In_ LPCVOID lpBuffer  /* nSize */,
    _In_ SIZE_T nSize,
    _Out_opt_ SIZE_T* lpNumberOfBytesWritten
);
```

Next, where it lives. The `kernel32` export is only a forwarding stub, and the implementation is in `KernelBase`:

```powershell
> resx locate WriteProcessMemory
  C:\WINDOWS\System32\KernelBase.dll  KernelBase.dll!WriteProcessMemory  ord:1990  RVA:0x0008E1B0
  C:\WINDOWS\System32\kernel32.dll  kernel32.dll!WriteProcessMemory  ord:1648  RVA:0x00040A60  → api-ms-win-core-memory-l1-1-0.dll!WriteProcessMemory  [stub]
  C:\WINDOWS\SysWOW64\KernelBase.dll  KernelBase.dll!WriteProcessMemory  ord:1996  RVA:0x0024CC10
  C:\WINDOWS\SysWOW64\kernel32.dll  kernel32.dll!WriteProcessMemory  ord:1632  RVA:0x00033C80
```

Now the interesting part: what it actually calls. Filtering the call map to syscalls shows `WriteProcessMemory` is not a thin wrapper around `NtWriteVirtualMemory`. It can make two `NtProtectVirtualMemory` calls in the *target* process, and each native call is followed into the kernel routine that services it:

```powershell
> resx calls KernelBase.dll WriteProcessMemory --depth 1 --only syscall --rva
API Call Map for WriteProcessMemory  [6 of 18 call site(s) · filter: syscall]:
  ├── RVA 0x0008E24D  CALL  ntdll!NtQueryVirtualMemory
  │   kernel: ntoskrnl!NtQueryVirtualMemory
  ├── RVA 0x0008E287  CALL  ntdll!NtWriteVirtualMemory
  │   kernel: ntoskrnl!NtWriteVirtualMemory
  ├── RVA 0x0008E32E  CALL  ntdll!NtProtectVirtualMemory
  │   kernel: ntoskrnl!NtProtectVirtualMemory
  ├── RVA 0x0008E3EF  CALL  ntdll!NtProtectVirtualMemory
  │   kernel: ntoskrnl!NtProtectVirtualMemory
  ├── RVA 0x0008E4FA  CALL  ntdll!NtUnmapViewOfSection
  │   kernel: ntoskrnl!NtUnmapViewOfSection
  └── RVA 0x0008E50A  CALL  ntdll!NtClose
      kernel: ntoskrnl!NtClose
```

`resx dump KernelBase.dll WriteProcessMemory` shows why. It queries the target page and tests its protection against `0xCC`, which covers every writable protection. This excerpt has my comments added on the right:

```asm
  0008e24d  call       qword ptr [_imp_NtQueryVirtualMemory]
  0008e25f  mov        r14d, dword ptr [rbp+0xb]          ; MEMORY_BASIC_INFORMATION.Protect
  0008e263  test       r14b, 0xcc                         ; already writable?
  0008e267  je         0x18008e372                        ; no: try to make it writable
  0008e287  call       qword ptr [_imp_NtWriteVirtualMemory]
  ...
  0008e372  test       r14b, 0x30                         ; executable?
  0008e376  je         0x18008e491                        ; no: fail with STATUS_ACCESS_VIOLATION
  0008e37c  cmp        dword ptr [rbp+0xf], 0x1000000     ; MEM_IMAGE?
  0008e389  mov        eax, 0x60000080                    ; + PAGE_EXECUTE_WRITECOPY
  0008e3ef  call       qword ptr [_imp_NtProtectVirtualMemory]
  0008e40c  mov        r15b, 1                            ; remember to restore
  0008e40f  jmp        0x18008e26d                        ; back to the write
  ...
  0008e420  cmp        dword ptr [rbp+0xf], 0x20000       ; MEM_MAPPED?
  0008e429  mov        eax, 0x60000040                    ; + PAGE_EXECUTE_READWRITE
```

If the page is already writable, it writes. If it is executable image or mapped memory, it reprotects the page range in the target process, writes, then restores the original protection with the second `NtProtectVirtualMemory`. Any other read-only page fails with `ERROR_NOACCESS`. That is why `WriteProcessMemory` can patch code in a remote process when the documentation never mentions changing protection.

Down at the boundary, the `ntdll` stub gives the service number:

```powershell
> resx dump ntdll.dll NtWriteVirtualMemory
  00166b10  mov        r10, rcx
  00166b13  mov        eax, 0x3a  ; syscall 0x3A (58)
  00166b18  test       byte ptr [0x7ffe0308], 1  ; KUSER_SHARED_DATA.SystemCall
  00166b20  jne        short 0x180166b25  ; → loc_00166b25
  00166b22  syscall
  00166b24  ret
```

And in the kernel, the write is validated, performed and reported:

```powershell
> resx calls ntoskrnl.exe NtWriteVirtualMemory --depth 2 --rva
API Call Map for NtWriteVirtualMemory  [1 call site(s)]:
  └── RVA 0x009C4C0B  CALL  MiReadWriteVirtualMemory
      ├── RVA 0x009C4DAB  CALL  ObpReferenceObjectByHandleWithTag
      ├── RVA 0x009C4E1B  CALL  MiCopyVirtualMemory
      ├── RVA 0x009C4E37  CALL  PsIsProcessLoggingEnabled
      ├── RVA 0x009C4E48  CALL  ObfDereferenceObjectWithTag
      └── RVA 0x009C4EBB  CALL  EtwTiLogReadWriteVm
```

`NtWriteVirtualMemory` passes `0x20` (`PROCESS_VM_WRITE`) as the access `ObpReferenceObjectByHandleWithTag` requires of the handle. After the copy, it can report the operation through `EtwTiLogReadWriteVm`, part of the Threat-Intelligence ETW provider that EDRs subscribe to. The same trace on `NtProtectVirtualMemory` shows a direct call to `EtwTiLogProtectExecVm`. So a `WriteProcessMemory` into executable image memory can produce a protection-change event as well as the write event.

The new `--telemetry` flag follows those paths across the syscall boundary. The default report shows each relevant source's event, consumers, and call path; incidental paths remain available with `--verbose`. Excerpt:

```powershell
> resx calls KernelBase.dll WriteProcessMemory --depth 1 --only syscall --rva --telemetry
Telemetry: WriteProcessMemory
  6 candidates (2 direct, 4 conditional) · 17 incidental hidden
  2411 functions searched · depth ≤10
  ETW Threat-Intelligence (2)
    ● ntoskrnl!EtwTiLogProtectExecVm  [kernel · depth 2 · direct]
      fires    : Microsoft-Windows-Threat-Intelligence event
      consumers: consumers running as antimalware protected processes (EDR); cannot be patched from user mode
      path     : KernelBase!WriteProcessMemory ⇒ ntoskrnl!NtProtectVirtualMemory → EtwTiLogProtectExecVm
    ● ntoskrnl!EtwTiLogReadWriteVm  [kernel · depth 3 · direct]
      fires    : Microsoft-Windows-Threat-Intelligence event
      consumers: consumers running as antimalware protected processes (EDR); cannot be patched from user mode
      path     : KernelBase!WriteProcessMemory ⇒ ntoskrnl!NtWriteVirtualMemory → MiReadWriteVirtualMemory → EtwTiLogReadWriteVm
  ...
```

The two ETW-TI entries are the relevant write and reprotection paths. The audit and mitigation entries need additional runtime conditions. The 17 hidden paths include generic handle cleanup, object-type branches and failure handling; `--verbose` shows them with their call paths. This relevance filter is heuristic, and neither category proves that an event fired.

In a few commands I have the prototype, the real implementation, the hidden protection change, the service number, the access right the kernel checks and the telemetry the call can produce. All of it is read from the binaries on this machine, so it matches the Windows build the code will actually run on.

Tested with RESX 2.3.0 against the system binaries of the test machine. RVAs and service numbers differ between Windows builds.

</details>

## Workflows

<details>
<summary><h3 style="display: inline;">Binary Triage & API Call Graphs</h3></summary>

Let's say I want to quickly figure out what this binary is doing we can invoke the calls command to get a
call-graph on the Windows API's it invokes *(or any other .dll, CRT, or internal functions if you have PDB)*. This can very quickly give us a basis and structured indicators on where
to look next, depending on the program this can also reveal a significant amount of functionality without even opening
a disassembler;

```powershell
> resx /calls "SAMPLE.exe" ENTRY --depth 4 --only winapi --no-pdb --time
SAMPLE.exe!entry  [RVA 0x000023E0, VA 0x1400023E0]

API Call Map for entry  [2 of 2 call site(s) · filter: winapi]:
  ├── 0x23E4  CALL  sub_00002770
  │   ├── 0x279E  CALL  KERNEL32!GetSystemTimeAsFileTime
  │   ├── 0x27AE  CALL  KERNEL32!GetCurrentThreadId
  │   ├── 0x27BB  CALL  KERNEL32!GetCurrentProcessId
  │   └── 0x27CD  CALL  KERNEL32!QueryPerformanceCounter
  └── 0x23ED  JMP  sub_00002260 [tail call]
      ├── 0x236A  CALL  sub_000019E0
      │   ├── 0x1A23  CALL  KERNEL32!InitializeSRWLock
      │   ├── 0x1A2E  CALL  KERNEL32!InitializeConditionVariable
      │   ├── 0x1A39  CALL  sub_00001160
      │   │   ├── 0x1179  CALL  KERNEL32!CreateWaitableTimerExW
      │   │   └── 0x11B6  CALL  KERNEL32!SetWaitableTimer
      │   ├── 0x1A47  CALL  sub_000015B0
      │   │   ├── 0x15D0  CALL  KERNEL32!VirtualAlloc
      │   │   ├── 0x15F2  CALL  KERNEL32!VirtualAlloc
      │   │   └── 0x1608  CALL  KERNEL32!VirtualFree
      │   ├── 0x1A55  CALL  sub_00001630
      │   │   ├── 0x165C  CALL  KERNEL32!CreateThread
      │   │   ├── 0x1672  CALL  KERNEL32!AcquireSRWLockExclusive
      │   │   ├── 0x167F  CALL  KERNEL32!ReleaseSRWLockExclusive
      │   │   ├── 0x1689  CALL  KERNEL32!WakeConditionVariable
      │   │   ├── 0x1697  CALL  KERNEL32!WaitForSingleObject
      │   │   └── 0x16A2  CALL  KERNEL32!CloseHandle
      │   ├── 0x1A63  CALL  sub_00001770
      │   │   ├── 0x1795  CALL  KERNEL32!VirtualProtect
      │   │   └── 0x17C4  CALL  KERNEL32!VirtualProtect
      │   ├── 0x1A71  CALL  sub_000017F0
      │   │   ├── 0x1820  CALL  KERNEL32!CreateFileMappingW
      │   │   ├── 0x185A  CALL  KERNEL32!MapViewOfFile
      │   │   ├── 0x1884  CALL  KERNEL32!FlushViewOfFile
      │   │   ├── 0x18A9  CALL  KERNEL32!UnmapViewOfFile
      │   │   └── 0x18B2  CALL  KERNEL32!CloseHandle
      │   ├── 0x1A7F  CALL  sub_000013A0
      │   │   ├── 0x13BF  CALL  bcrypt!BCryptGenRandom
      │   │   ├── 0x13E7  CALL  bcrypt!BCryptOpenAlgorithmProvider
      │   │   ├── 0x142D  CALL  bcrypt!BCryptCreateHash
      │   │   ├── 0x1478  CALL  bcrypt!BCryptFinishHash
      │   │   ├── 0x1488  CALL  bcrypt!BCryptDestroyHash
      │   │   └── 0x1494  CALL  bcrypt!BCryptCloseAlgorithmProvider
      │   ├── 0x1A8D  CALL  sub_00001920
      │   │   ├── 0x1936  CALL  KERNEL32!WaitForSingleObject
      │   │   └── 0x1945  CALL  KERNEL32!CancelWaitableTimer
      │   ├── 0x1AA4  CALL  KERNEL32!GetLastError
      │   └── 0x1AD3  CALL  sub_000018D0
      │       ├── 0x18EA  CALL  KERNEL32!VirtualFree
      │       └── 0x1901  CALL  KERNEL32!CloseHandle
      ├── 0x2371  CALL  sub_00002910
      │   └── 0x2916  CALL  KERNEL32!GetModuleHandleW
      └── 0x2393  CALL  sub_00002910 [expanded above]
RESX: completed in 10ms
```

With one command, we've mapped out a significant amount of the program's functionality:

- **`VirtualAlloc`, `VirtualFree`, `VirtualProtect`**: Dynamic memory allocation and protection manipulation.
- **`CreateThread`, `WaitForSingleObject`, `SRWLock`**: Multithreaded execution and synchronization.
- **`CreateWaitableTimerExW`, `SetWaitableTimer`**: Scheduled or delayed execution.
- **`CreateFileMappingW`, `MapViewOfFile`**: Memory-mapped files or shared memory.
- **`BCryptGenRandom`, `BCryptCreateHash`**: Cryptographic randomness and hashing.
- **`QueryPerformanceCounter`, `GetSystemTimeAsFileTime`**: High-resolution timing and timestamps.
- **`GetCurrentProcessId`, `GetCurrentThreadId`, `GetModuleHandleW`**: Process, thread, and module introspection.

From this alone, we can infer that the binary performs **memory management, concurrent execution, cryptographic operations, and memory-mapped I/O**. The combination of memory protection changes and thread creation may warrant further investigation, particularly when analyzing packers, instrumentation frameworks, or malware.

</details>

<details>
<summary><h3 style="display: inline;">API-Aware Static Analysis</h3></summary>

RESX goes beyond identifying API calls. With Windows SDK integration, it can recover official parameter names, resolve Windows constants, identify function pointers, and reconstruct arguments directly from machine code, even without PDB symbols.

For example, using `--args`:

```powershell
> resx /calls "SAMPLE.exe" ENTRY --depth 5 --only winapi --no-pdb --args
```

```console
├── 0x15D0  CALL  KERNEL32!VirtualAlloc
│   └── args
│       ├── lpAddress        = NULL
│       ├── dwSize           = 0x10000
│       ├── flAllocationType = MEM_RESERVE
│       └── flProtect        = PAGE_NOACCESS
│
├── 0x165C  CALL  KERNEL32!CreateThread
│   └── args
│       ├── lpThreadAttributes = NULL
│       ├── dwStackSize        = 0
│       ├── lpStartAddress     = &fn_0x000016E0
│       ├── lpParameter        = arg1
│       ├── dwCreationFlags    = 0
│       └── lpThreadId         = NULL
│
├── 0x13BF  CALL  bcrypt!BCryptGenRandom
│   └── args
│       ├── hAlgorithm = NULL
│       ├── pbBuffer   = ?
│       ├── cbBuffer   = 0x10
│       └── dwFlags    = BCRYPT_USE_SYSTEM_PREFERRED_RNG
│
└── 0x13E7  CALL  bcrypt!BCryptOpenAlgorithmProvider
    └── args
        ├── phAlgorithm       = &local_10
        ├── pszAlgId          = L"SHA256"
        ├── pszImplementation = NULL
        └── dwFlags           = 0
```

From these calls alone, we can infer that the binary **reserves 64 KiB of virtual address space, creates a thread at a recovered function entry point, requests 16 bytes of cryptographically secure random data, and initializes a SHA-256 hashing provider**.

</details>

<details>
<summary><h3 style="display: inline;">Dynamic API Resolution &amp; Deobfuscation</h3></summary>

RESX can statically recover dynamically resolved Windows APIs, including those hidden behind **API hashing, PEB loader-list traversal, manual export-table parsing, and encoded API names**. This allows analysts to identify functionality that may be absent from a binary's conventional import table, without manually reversing the resolution routines.

**API hashing & manual export resolution**

```powershell
> resx /calls "HASHED.exe" rva:0x1770 --depth 3 --only dynamic --no-pdb
```

```console
├── 0x1779  CALL  sub_00001000
│   ├── 0x101F  CALL  sub_00001230
│   │   resolves: kernel32!VirtualAlloc (export-table walk · ror13-add hash 0x91AFCA54 · loader-list walk, djb2 hash 0x7040EE75)
│   ├── 0x102F  CALL  sub_00001230
│   │   resolves: kernel32!VirtualFree (export-table walk · ror13-add hash 0x30633AC · loader-list walk, djb2 hash 0x7040EE75)
│   ├── 0x1054  CALL  kernel32!VirtualAlloc [dynamic · export-table walk]
│   └── 0x1066  CALL  kernel32!VirtualFree [dynamic · export-table walk]
```


**Encoded API name recovery**

```powershell
> resx /calls "ENCODED.exe" rva:0x16B0 --depth 3 --only dynamic --no-pdb
```

```console
├── 0x16E0  CALL  sub_000010C0
│   ├── 0x1113  CALL  KERNEL32!GetProcAddress
│   │   resolves: kernel32!CreateThread (GetProcAddress · xor 0x5A)
│   └── 0x113B  CALL  kernel32!CreateThread [dynamic · GetProcAddress · xor 0x5A]
├── 0x16EC  CALL  sub_00001510
│   ├── 0x1629  CALL  KERNEL32!GetProcAddress
│   │   resolves: kernel32!VirtualProtect (GetProcAddress · rolling xor 0x31+i)
│   └── 0x1652  CALL  kernel32!VirtualProtect [dynamic · GetProcAddress · rolling xor 0x31+i]
```


RESX identifies the underlying Windows APIs and their resolution mechanisms, turning otherwise opaque indirect calls into actionable call-graph evidence. Both examples are recovered statically without PDB symbols.

</details>

<details>
<summary><h3 style="display: inline;">Windows Internals, Syscalls &amp; Function Disassembly</h3></summary>

RESX can also help with Windows internals. Let's locate VirtualAlloc and follow it into the kernel.

```powershell
>  resx /locate VirtualAlloc

Locations of 'VirtualAlloc':
  C:\WINDOWS\System32\KernelBase.dll  KernelBase.dll!VirtualAlloc  ord:1909  RVA:0x000B6650
  C:\WINDOWS\System32\kernel32.dll  kernel32.dll!VirtualAlloc  ord:1563  RVA:0x00033160  →
api-ms-win-core-memory-l1-1-0.dll!VirtualAlloc  [stub]
```

It doesn't stop at the userland boundary, either. Ask what `VirtualAlloc` actually does and it follows the call
through the `ntdll` syscall stub into the kernel routine that services it, in one tree:

```powershell
>  resx /calls KernelBase.dll VirtualAlloc --depth 2

KernelBase.dll!VirtualAlloc  [RVA 0x000B6650, VA 0x1800B6650]

API Call Map for VirtualAlloc  [3 call site(s)]:
  ├── 0xB668D  CALL  ntdll!NtAllocateVirtualMemory [syscall]
  │   kernel: ntoskrnl!NtAllocateVirtualMemory
  │   ├── 0x882EAE  CALL  MiAllocateVirtualMemoryPrepare
  │   ├── 0x882EFA  CALL  MiAllocateVirtualMemory
  │   ├── 0x882F49  CALL  ObfDereferenceObjectWithTag
  │   └── 0x882FE6  CALL  PsDereferencePartition
  ├── 0xB66AD  CALL  ntdll!RtlSetLastWin32Error
  └── 0xB66BF  CALL  BaseSetLastNTError
      ├── 0x22E56  CALL  ntdll!RtlNtStatusToDosError
      └── 0x22E66  CALL  ntdll!RtlSetLastWin32Error
```

And of course, you can dump functions aswell:

```powershell
>  resx /dump ntdll.dll NtAllocateVirtualMemory --cfg text

ntdll.dll!NtAllocateVirtualMemory  [RVA 0x00162040, VA 0x180162040]
  Base0/RVA: 0x00162040  |  VA: 0x180162040
  Signature [static-abi-inference]: unknown NtAllocateVirtualMemory(int64_t arg1, /* further arguments unknown */)
  00162040  mov        r10, rcx
  00162043  mov        eax, 0x18  ; syscall 0x18 (24)
  00162048  test       byte ptr [0x7ffe0308], 1  ; KUSER_SHARED_DATA.SystemCall
  00162050  jne        short 0x180162055  ; → loc_00162055
  00162052  syscall
  00162054  ret
  00162055  int        0x2e
  00162057  ret

Control Flow Graph:
  blocks:  3
  entry :  block_00162040

block_00162040  [entry]:  [4 insn]  range 0x00162040..0x00162050
    0x00162040  4C 8B D1                    mov        r10, rcx
    0x00162043  B8 18 00 00 00              mov        eax, 0x18  ; syscall 0x18 (24)
    0x00162048  F6 04 25 08 03 FE 7F 01     test       byte ptr [0x7ffe0308], 1  ; KUSER_SHARED_DATA.SystemCall
    0x00162050  75 03                       jne        short 0x180162055  ; → loc_00162055
    edges:
      [taken] jne -> block_00162055 (→ loc_00162055)
      [fallthrough] fallthrough -> block_00162052

block_00162052  [exit]:  [2 insn]  range 0x00162052..0x00162054
    0x00162052  0F 05                       syscall
    0x00162054  C3                          ret
    edges:
      [exit] return
```

That same kernel awareness drives RESX's driver analysis: dispatch routines, IOCTL codes, and VMX/SVM hypervisor primitives (`resx driver`, `resx ioctl`).

</details>

<details>
<summary><h3 style="display: inline;">IOCTL &amp; Kernel Driver Analysis</h3></summary>

RESX can statically reconstruct Windows driver communication interfaces from both **user-mode clients and kernel-mode drivers**, recovering IOCTL codes, request arguments, dispatch routines, buffer requirements, and validation logic without executing the binaries.

**User-mode: Reconstructing driver requests**

```powershell
> resx /ioctl client.dll --args
```

```console
IOCTL and NDIS recovery
Image:  client.dll
Result:  28 IOCTL code evidence record(s), 0 registered dispatch root(s)

Code          Function   Access  Method    Input B  Output B
0x8337A004    0x801      W       BUFFERED  8        0
0x8337600C    0x803      R       BUFFERED  0        1496
0x83376058    0x816      R       BUFFERED  0        ((min_u32(arg2, 64) * 1496) + 16)
```

RESX can also reconstruct the underlying `DeviceIoControl` arguments, including dynamically calculated buffer sizes:

```c
BkscGetEvents -> DeviceIoControl
call RVA 0x00003E15  IOCTL 0x83376058

DeviceIoControl(
    arg0,                               // handle
    0x83376058,                         // ioctl
    NULL,                               // input_buffer
    0,                                  // input_length
    calloc_result,                      // output_buffer
    ((min_u32(arg2, 64) * 1496) + 16),  // output_length
    &frame_minus_0x48,                  // bytes_returned
    NULL                                // overlapped
);
```


**Kernel-mode: Recovering dispatch routines and validation**

For example, analyzing Microsoft's DirectX graphics kernel driver:

```powershell
> resx /ioctl dxgkrnl.sys
```

```console
IOCTL and NDIS recovery
Image:  dxgkrnl.sys
Result:  14 IOCTL code evidence record(s), 2 registered dispatch root(s)

Dispatch RVA    Codes  Registration evidence
0x00074A50      1      IRP_MJ_DEVICE_CONTROL assignment at 0x00452519
0x003E5660      13     IRP_MJ_INTERNAL_DEVICE_CONTROL assignment at 0x00452527
```

RESX can further recover request buffer checks and trace their associated failure paths:

```console
Code        Buffer  Guard    Check RVA   Failure status  Failure RVA
0x00234003  input   == 16    0x00074B42  0xC0000206      0x00074FBF
0x00234003  output  == 8     0x00074B6B  0xC0000206      0x00074FBF
0x0023E057  input   >= 832   0x003E587E 0xC0000206      0x003E5740
```


This gives analysts a starting point for **reverse-engineering undocumented driver protocols and auditing kernel request handlers**, without manually tracing every `DeviceIoControl` invocation, dispatch-table assignment, or buffer-length comparison.







</details>

<details>
<summary><h3 style="display: inline;">Startup Flow &amp; Thread Callback Recovery</h3></summary>

Finding a `CreateThread` call is useful, but what does the thread actually do? RESX can follow a statically recovered callback into the same image and show the code behind it, instead of leaving us with just a function pointer.

Using the same sample from the API-argument example:

```powershell
resx reconstruct-cfg "SAMPLE.exe" --thread-filter spawned --depth 5 --max-total 800 --no-pdb --no-color
```

```console
Root 1/3: PE Entry Point sub_000023E0 0x000023E0 PE Entry Point [.text] <synthetic, bound .pdata 0x000023E0..0x000023F2> (AddressOfEntryPoint; declared executable entry point; transfer and execution unobserved)
`-- 0x000023ED jmp -> sub_00002260 0x00002260 [tail-jump, unknown]
    `-- 0x0000236A call -> sub_000019E0 0x000019E0 [unknown]
        `-- 0x00001A55 call -> sub_00001630 0x00001630 [unknown]
            `-- 0x0000165C call -> KERNEL32.dll!CreateThread [import, indirect, thread-spawn, microsoft-api] ; IAT [rip+0x1400030A8]; thread-start callback arg3 via r8 loaded address
                `-- thread-start -> sub_000016E0 0x000016E0 Thread Start [.text] <synthetic, bound .pdata 0x000016E0..0x000016F5, thread lane 1> (KERNEL32.dll!CreateThread @ 0x0000165C; callback recovered from KERNEL32.dll!CreateThread)
                    |-- 0x000016E9 call -> KERNEL32.dll!AcquireSRWLockExclusive [import, indirect, microsoft-api] ; IAT [rip+0x140003068]
                    |-- 0x00001710 call -> KERNEL32.dll!SleepConditionVariableSRW [import, indirect, microsoft-api] ; IAT [rip+0x140003080]
                    |-- 0x0000173E call -> sub_000011D0 0x000011D0 [unknown]
                    |   `-- truncated: max depth 5 [0x000011D0]
                    `-- 0x00001753 call -> KERNEL32.dll!ReleaseSRWLockExclusive [import, indirect, microsoft-api] ; IAT [rip+0x140003060]
```

Here we can follow the path from the executable's entry point to `CreateThread`, then into the worker at `0x16E0`. Inside that worker, RESX identifies `AcquireSRWLockExclusive`, `SleepConditionVariableSRW`, and `ReleaseSRWLockExclusive`, giving us a starting point for investigating how the thread waits on and accesses shared state.

</details>

<details>
<summary><h3 style="display: inline;">Comparing Builds &amp; Hunting Related Binaries</h3></summary>

Let's say we have two versions of a DLL and want to figure out where to look first. Comparing raw bytes can get noisy when addresses or layouts move around, so RESX can compare normalized function code, control-flow structure, API calls, and other properties instead.

```powershell
resx diff "sample.dll" "sample-v2.dll" --max-functions 200 --no-pdb --no-color
```

```console
Similarity :   90
Unique     :   87  (180 noisy matches filtered)
Coverage   :  left 97% / right 97%
Functions  :  194 matched  |  193 exact  1 strong  0 changed  0 weak
Unmatched  :  6 left-only  |  6 right-only

Changed Clusters
  left-only .text 0x00001040..0x0000135D  funcs:5  avg:-
    ResxBehaviorSignals
    ResxDeviceIoctlDispatch
    ResxParsePacket
  left-only .text 0x000073A0..0x000074C1  funcs:1  avg:-
    sub_000073A0
  right-only .text 0x00001020..0x000013EB  funcs:6  avg:-
    ResxBehaviorSignals
    ResxDeviceIoctlDispatch
    ResxParsePacket
```

In this comparison, most of the profiled functions match, while several application exports appear in unmatched clusters. That gives us a much smaller set of functions to inspect, rather than starting from scratch in both binaries.

We can also save a reusable index and compare another binary against it:

```powershell
resx index "sample.dll" --db samples.resxdb --max-functions 200 --no-pdb --no-color --quiet
resx hunt "sample-v2.dll" --db samples.resxdb --max-functions 200 --no-pdb --no-color --quiet
```

```console
1. [ 96] sample.dll  sample.dll
   unique  95 | metadata 98 | coverage left 100% / right 99% | matches 198
   tags: shared-codebase, shared-exports, variant-build
   [ 86] strong ResxIndirectCallMessage -> ResxIndirectCallMessage
   [ 73] changed ResxDeviceIoctlDispatch -> ResxDeviceIoctlDispatch
   [ 69] changed ResxParsePacket -> ResxParsePacket
   [ 68] changed ResxSwitchJumpTableDispatch -> ResxSwitchJumpTableDispatch
   [ 66] changed ResxBehaviorSignals -> ResxBehaviorSignals
```

This small demo indexes one reference DLL. The same `index` command also accepts a directory, so we can build a corpus and look for related code across a collection of binaries. The hunt output highlights related code and the functions worth comparing next.

These examples profile 200 functions per image. Increase `--max-functions` when you want to cover more of a larger binary.

</details>

<details>
<summary><h3 style="display: inline;">PowerShell Automation &amp; JSON Analysis</h3></summary>

RESX isn't limited to reading a report in the terminal. We can take its JSON output and use it directly in PowerShell, Python, or another tool, which lets us ask more specific questions about the binary.

For example, let's pull out the recovered `VirtualAlloc` and `VirtualProtect` protection arguments and check whether they request executable memory. This example uses the configured Windows SDK headers and `--args`:

```powershell
$json = resx behavior "SAMPLE.exe" --args --json --no-pdb --quiet
if ($LASTEXITCODE -ne 0) { throw "RESX analysis failed" }
$report = $json | ConvertFrom-Json

$rows = foreach ($site in $report.behavior.api_signatures.PSObject.Properties) {
    $sig = $site.Value
    if ($sig.call -notmatch '^Virtual(Alloc|Protect)\(') { continue }

    $slot = if ($sig.call.StartsWith('VirtualAlloc(')) { 3 } else { 2 }
    $arg = $sig.arguments[$slot]
    [pscustomobject]@{
        RVA        = '0x{0:X8}' -f [uint32]$site.Name
        API        = ($sig.call -split '\(', 2)[0]
        Protection = if ($arg.kind -eq 'int') {
            '0x{0:X}' -f [uint64]$arg.value
        } else { 'unknown' }
        Executable = if ($arg.kind -eq 'int') {
            (([uint64]$arg.value -band 0xF0) -ne 0)
        } else { 'unknown' }
    }
}
$rows | Format-Table -AutoSize
```

```console
RVA        API            Protection Executable
---        ---            ---------- ----------
0x000015D0 VirtualAlloc   0x1             False
0x000015F2 VirtualAlloc   0x4             False
0x00001795 VirtualProtect 0x2             False
0x000017C4 VirtualProtect unknown       unknown
```

Here we have `PAGE_NOACCESS`, `PAGE_READWRITE`, and `PAGE_READONLY`, with the final protection argument reported as `unknown`.

Because `$rows` contains PowerShell objects, we can filter or export the results without scraping coloured terminal output:

```powershell
$rows | Where-Object { $_.Executable -eq $true }
$rows | Export-Csv .\memory-protections.csv -NoTypeInformation
```

The executable-memory filter returns no rows for this sample. We can extend the script with more APIs, run it across a directory of binaries, or feed the resulting addresses straight into another RESX command.

</details>

<details>
<summary><h3 style="display: inline;">PE Structure, Section Permissions &amp; Validation</h3></summary>

Before diving into individual functions, we can also check how the image is laid out. Section permissions, entropy, and structural checks give us another way to decide what needs a closer look.

```powershell
resx sections "sample.dll" --no-pdb --no-color --quiet
```

```console
Sections:
┌────────────────┬──────────────────┬──────────────────┬──────────────────┬────────────┬────────────────┬──────────────┐
│ Name           │ RVA              │ VSize            │ Raw              │ Prot       │ Expected       │ Entropy      │
├────────────────┼──────────────────┼──────────────────┼──────────────────┼────────────┼────────────────┼──────────────┤
│ .text          │ 0x00001000       │ 0x0000D330       │ 0x0000D400       │ RX         │ RX             │ 6.408        │
│ .rdata         │ 0x0000F000       │ 0x00009B62       │ 0x00009C00       │ R          │ R              │ 4.708        │
│ .data          │ 0x00019000       │ 0x000015B8       │ 0x00000C00       │ RW         │ RW             │ 1.902        │
│ .pdata         │ 0x0001B000       │ 0x00001050       │ 0x00001200       │ R          │ R              │ 4.561        │
│ .text          │ 0x0001D000       │ 0x0000000B       │ 0x00000200       │ RX         │ RX             │ 0.183        │
│ .fptable       │ 0x0001E000       │ 0x00000100       │ 0x00000200       │ RW         │ Varies         │ 0.000        │
│ .reloc         │ 0x0001F000       │ 0x00000654       │ 0x00000800       │ R          │ R              │ 4.849        │
└────────────────┴──────────────────┴──────────────────┴──────────────────┴────────────┴────────────────┴──────────────┘
```

This gives us each section's address, size, permissions, and entropy in one view. We can see executable code in the `RX` sections and writable data in the `RW` sections, without manually decoding PE section flags.

For structural validation:

```powershell
resx pechk "sample.dll" --no-pdb --no-color
```

```console
Findings: 0
  ✓ no structural PE anomalies
```

This fixture passes the structural checks. Between the section layout, permissions, and call-graph evidence, we can quickly decide where to spend our time before opening a full disassembler.

</details>

<details>
<summary><h3 style="display: inline;">Live Analysis with SKUGGA</h3></summary>

RESX also works in conjunction with another one of my tools, ***[SKUGGA](https://github.com/Ryftenius/SKUGGA/)***, which is a lightweight process instrumentation framework. We can use RESX to find an interesting call, then run the same binary under SKUGGA to see its arguments, result, and call stack live.

Let's take `DYNAMIC.exe`. It resolves `VirtualAlloc` through `GetProcAddress`, so we start by asking RESX what that indirect call is doing:

```powershell
resx /calls "DYNAMIC.exe" rva:0x1100 --depth 1 --only kernel32 --args --no-pdb --no-color
```

```console
  ├── 0x1160  CALL  kernel32!VirtualAlloc [dynamic · GetProcAddress]
  │   └── args
  │       ├── lpAddress        = NULL
  │       ├── dwSize           = 0x1000
  │       ├── flAllocationType = MEM_COMMIT|MEM_RESERVE
  │       └── flProtect        = PAGE_READWRITE
```

RESX identifies a 4 KiB allocation with `MEM_COMMIT|MEM_RESERVE` and `PAGE_READWRITE` at RVA `0x1160`. Now we run it under SKUGGA, selecting the native allocation and free APIs and enabling call stacks:

```powershell
sk run "DYNAMIC.exe" --api NtAllocateVirtualMemory,NtFreeVirtualMemory --stack --timeout 10s
```

```console
[skugga] NtAllocateVirtualMemory hit status=0x00000000 target=self(pid=44368 name=DYNAMIC.exe) addr=0x1C97CE20000 size=0x1000 pages=1 alloc=COMMIT|RESERVE protect=RW vad=MEM_PRIVATE/UNKNOWN region=0x1C97CE20000-0x1C97CE2E000 region_size=56.00KB caller=KERNELBASE.dll+0xB6694
    #00 [system]   KERNELBASE.dll+0xB6694
    #01 [app]      DYNAMIC.exe+0x1166
    #02 [app]      DYNAMIC.exe+0x1301
    #03 [app]      DYNAMIC.exe+0x17FF
    #04 [system]   KERNEL32.DLL+0x2DDA7
    #05 [system]   ntdll.dll+0x7EE4C
```

There it is: `size=0x1000`, `alloc=COMMIT|RESERVE`, `protect=RW`, and a successful `status=0x00000000`. SKUGGA also gives us the allocated address and the path back through `KERNELBASE.dll` into our executable.

The application frame is `DYNAMIC.exe+0x1166`. We can line that up with the original call by dumping its instructions:

```powershell
resx /dump "DYNAMIC.exe" --at 0x1100 --bytes --max-insns 100 --no-pdb --no-color --quiet
```

```asm
  00001160  ff 15 2a 20 00 00              call       qword ptr [0x140003190]
  00001166  48 85 c0                       test       rax, rax
```

The call at `0x1160` is six bytes long, so `0x1166` is the return address immediately after it, the same address shown in SKUGGA's live stack. We have gone from a dynamically resolved API, to its recovered arguments, to the matching live allocation and back to the exact machine-code call site.

</details>

## Documentation

- [Full changelog](CHANGELOG.md)
- [Command reference](COMMANDS.md)
- [CLI documentation](docs/cli.md)
- [VS Code extension documentation](docs/vscode-extension.md)
- [DLL / FFI integration](docs/dll.md)
- [Analysis surfaces](docs/analysis-surfaces.md)
- [Architecture](docs/architecture.md)
- [JSON schemas](docs/json-schemas.md)
- [Security policy](SECURITY.md)
- [Contributing](CONTRIBUTING.md): contributors are welcome

## Features

- Reachable multi-stream decoding for overlapping x86/x64 instruction streams.
- Bounded Win64 ABI prototype recovery for register, stack, integer, floating-point, pointer, and return-value evidence.
- Kernel-driver, WDF, NDIS, and hypervisor-oriented analysis with IOCTL and dispatch recovery.
- Static behavior triage for syscall stubs, anti-analysis instructions, TLS callbacks, loader APIs, executable-memory setup, IPC, networking, and cryptography.
- Reverse caller tracing across priority modules and custom scan scopes.
- Startup-flow reconstruction from entry points, TLS callbacks, thread and work-pool callbacks, import calls, indirect edges, and x64 unwind or exception-handler evidence.
- Structural diffing, CFG diff views, code and control heatmaps, corpus indexing, and sample hunting.
- Integrated VS Code binary viewer for navigation, behavior triage, API evidence, drivers and IOCTLs, strings, entropy, YARA, flow, symbols, types, diffing, corpus hunting, and function analysis.
- Protected-file triage for packer markers, OEP handoff candidates, import-rebuild leads, VM dispatcher or handler candidates, and bounded payload recovery.
- C-like reconstruction and bounded CFG rendering for selected functions.
- Hardened PE32+ metadata, section, data-directory, debug, CLR, TLS, load-configuration, certificate, version, and anomaly inspection.
- Export and PDB symbol loading, type browsing, and symbol-backed navigation.
- Targeted disassembly by name, RVA, VA, file offset, or ordinal.
- Incoming call and jump xrefs for functions and imports.
- Static triage with hook and thunk indicators, string references, API-call maps, suspicious control-flow hints, and explicit decode-conflict records.
- Hostile-mode tracing for packed or deliberately confusing binaries.
- Guarded byte patching by RVA, VA, or file offset.
- YARA-compatible scanning and bounded string, byte-pattern, instruction, and symbol search.
- Folder scanning with fuzz-target candidate ranking.
- Terminal entropy maps over executable code with ASCII, zero-byte, unique-byte, and high or low entropy flags.
- Export Address Table and Import Address Table browsing.
- Native C ABI for embedding RESX analysis in other tools.
- Versioned JSON output for automation.

RESX operates on file bytes and optional symbol data. It does not load or execute the analyzed image.

## Build The CLI

```powershell
cargo build --release
```

Run:

```powershell
.\target\release\resx.exe help
.\target\release\resx.exe version
```

Common commands:

```powershell
resx dump <image> <function>
resx dump <image> --at <address>
resx xrefs <image> <function-or-import>
resx cfg <image> <function>
resx reconstruct-cfg <image>
resx intelli <image> [function]
resx behavior <image>
resx contracts <image>
resx driver <image>
resx ioctl <image>
resx ipc <image>
resx network <image>
resx crypto <image>
resx payload <image>
resx entropy <image>
resx patch <image> --at <address> --patch-bytes <hex>
resx peinfo <image>
resx pechk <image>
resx sections <image>
resx eat <image>
resx iat <image>
resx syms <image>
resx types <image> [query]
resx strings <image>
resx callers <image> <function>
resx locate <name>
resx locate-sym <name>
resx find <image> <query>
resx scan <path>
resx diff <old-image> <new-image>
resx index <dir-or-image> --db <file>
resx hunt <sample> --db <file>
resx yara <image> <rule.yar>
```

See [docs/cli.md](docs/cli.md) for the full command and option reference.

## Install The VS Code Extension

```powershell
cd resx-vscode
npm ci
npm run compile
npm run package
```

Install the generated `.vsix` with:

```console
Extensions: Install from VSIX...
```

The extension contributes a custom editor for Windows binaries. Its tabs cover Overview, Entry, Triage (with `pechk`), Behavior, Sections, Exports, Imports, Symbols, Types, Strings, Evidence (contracts, IPC, network, crypto), Driver (IOCTLs), Entropy, Search (find, YARA, compare, SDK prototypes), Flow, Scan, Dump and Dev. Dumps add call maps, xrefs, callers, CFG, C-like reconstruction and hex, with hostile mode, `--args` and call filters in the viewer's Options panel.

Command-palette and explorer workflows include Locate, Dump, Compare Images (diff), Scan Folder, Index Folder as Corpus, Find Similar Images (hunt), Decode Payload, Patch Image Bytes, Look Up Windows API Prototype and Configure Windows SDK Headers.

See [docs/vscode-extension.md](docs/vscode-extension.md) for build, packaging, settings, trust model, and workflow details.

## Use The DLL / FFI

Build the DLL:

```powershell
cargo build -p resx --release
```

Use the public header:

`resx/include/resx.h`

Example C call:

```c
#include "resx.h"

char *json = NULL;
int status = RsxPeInfo(
    "C:\\Windows\\System32\\kernel32.dll",
    "{\"no_pdb\":true}",
    &json
);

if (json) {
    /* parse or print json */
    RsxFreeString(json);
}
```

See [docs/dll.md](docs/dll.md) for exported functions, status codes, option JSON, output envelopes, memory ownership, and smoke-test instructions.

## Screenshots

### VS Code Binary Viewer

![RESX VS Code overview](media/Dump_Ntoskrnl_Overview.png)

![RESX dump disassembly view](media/Dump_Disassembly_KiDispatchCallout.png)

![RESX dump API refs view](media/Dump_ApiRefs_KiDispatchCallout.png)

![RESX syscall stub view](media/Dump_ntdll_NtAllocateVirtualMemoryEx_Stub.png)

### Command Palette Workflows

![RESX dump file search](media/Dump_File_Search.png)

![RESX dump symbol search](media/Dump_Search_KiDispatchCallout.png)

![RESX locate result](media/Locate_OpenPro.png)

## JSON Automation

Use `--json` for machine-readable output:

```powershell
resx peinfo .\sample.dll --json
resx behavior .\sample.dll --json
resx contracts .\sample.dll --json
resx driver .\sample.sys --json
resx payload .\sample.dll --json
resx entropy .\sample.dll --json
resx dump .\sample.dll DllMain --json
resx reconstruct-cfg .\sample.dll --json
resx scan .\samples --json
resx diff .\old.dll .\new.dll --json
```

Where possible, RESX emits versioned JSON envelopes. Consumers should tolerate additional fields across releases.

## License

RESX is available under the [MIT License](LICENSE). You may use, modify, and distribute it provided the RYFTENIUS copyright and license notice are retained.
