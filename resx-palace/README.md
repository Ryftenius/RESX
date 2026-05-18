# resx-palace

Small Windows PE sample corpus for RESX integration tests.

The corpus builds one DLL and one EXE without network access. The DLL exports
functions named to exercise parser-like, IOCTL-like, callback/thread-like,
switch/jump-table-like, and indirect-call-like RESX detection paths.

## Build

```powershell
.\resx-palace\scripts\build.ps1
```

The script looks for `cl.exe` first, then `clang-cl.exe`. Run it from a Visual
Studio Developer PowerShell, Developer Command Prompt, or an environment where
one of those compilers is already on `PATH`.

Outputs are written to `resx-palace\build\`.
