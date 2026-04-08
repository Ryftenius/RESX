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

RESX is a Windows binary analysis toolkit for terminal-first reversing, symbol-backed inspection, targeted disassembly, pseudo-C reconstruction, CFG recovery, triage, and PE inspection.

## Documentation

- [CLI documentation](docs/cli.md)
- [VS Code extension documentation](docs/vscode-extension.md)

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

## Install The VS Code Extension

See the full guide in [docs/vscode-extension.md](docs/vscode-extension.md).

Typical flow:

```powershell
cd resx-vscode
npm install
npm run compile
npm run package
```

Install the generated `.vsix` from VS Code with `Extensions: Install from VSIX...`.

## Use The CLI

See the full guide in [docs/cli.md](docs/cli.md).

Build:

```powershell
cargo build --release
```

Common commands:

```powershell
resx dump <dll> <function>
resx cfg <dll> <function>
resx intelli <dll> [function]
resx peinfo <dll>
resx locate <name>
resx locate-sym <name>
resx syms <dll>
```
