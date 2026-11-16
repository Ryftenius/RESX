# Public test binaries

This directory holds the small Windows PE samples used by the tested README examples. **Treat all binaries here as untrusted test inputs.** Inspect their source and hashes before running them, and analyze them in a lab if your policy requires one. They are deliberately constructed to exercise unusual binary-analysis paths; they are not production programs. RESX analyzes their file bytes without executing them.

| Source | Checked-in binary | Purpose |
| --- | --- | --- |
| `manual_resolver.c` | `manual_resolver.exe` | PEB export walking and encoded API names (Example 1) |
| `hash_resolver.c` | `hash_resolver.exe` | ROR13 API hashes (Example 3) |
| `overlap_probe.asm` | `overlap_probe.exe` | Branch into an x64 instruction to expose an alternate `call` (Example 2) |

`overlap_probe.exe` is a standalone, inert sample. Its entry point returns zero. The exported `OverlapProbe` has a predictable branch into a 10-byte `mov` carrier; the alternate stream calls the benign `HiddenTarget`, which also returns zero. It has no imports, network operations, dynamic patching, or syscall. Do not interpret it as proof of the separate historical syscall-stub or IDA comparison in the root README.

To reproduce the RESX output from the repository root on Windows:

```powershell
resx dump .\resx\tests\data\overlap_probe.exe OverlapProbe --bytes --calls --no-pdb --no-color
```

To rebuild with Visual Studio's x64 MSVC tools, from a Developer PowerShell at the repository root:

```powershell
New-Item -ItemType Directory -Force target\overlap-probe-build | Out-Null
ml64 /nologo /c /Fotarget\overlap-probe-build\overlap_probe.obj resx\tests\data\overlap_probe.asm
link /nologo /MACHINE:X64 /SUBSYSTEM:CONSOLE /ENTRY:main /NODEFAULTLIB /DEBUG:NONE /INCREMENTAL:NO /OPT:NOREF /EXPORT:OverlapProbe /EXPORT:HiddenTarget /OUT:target\overlap-probe-build\overlap_probe.exe target\overlap-probe-build\overlap_probe.obj
resx dump .\target\overlap-probe-build\overlap_probe.exe OverlapProbe --bytes --calls --no-pdb --no-color
```

Builds can differ in PE timestamp and linker metadata. The instruction bytes and branch/call relationship are the reproducibility contract. The checked-in binary was built with MSVC 14.44.35207. Its SHA-256 is `1b8d7262c775adb35167cbeb8cb3c4a8e517ed25ea205a72a3129e17908da2dd`.
