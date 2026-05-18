param(
    [string]$ResxDll = "",
    [string]$Image = "",
    [string]$Function = "NtOpenProcess",
    [switch]$NoBuild
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$Source = Join-Path $PSScriptRoot "resx_dll_smoke.c"
$OutDir = Join-Path $RepoRoot "target-resx-tests\resx-dll-smoke"
$Exe = Join-Path $OutDir "resx_dll_smoke.exe"

function Resolve-DefaultResxDll {
    $candidates = @(
        (Join-Path $RepoRoot "resx-demo\target\release\resx.dll"),
        (Join-Path $RepoRoot "target\release\resx.dll"),
        (Join-Path $RepoRoot "target-resx-tests\cargo-full\debug\deps\resx.dll"),
        (Join-Path $RepoRoot "target-resx-tests\ffi-trace\debug\deps\resx.dll")
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) {
            return (Resolve-Path -LiteralPath $candidate).Path
        }
    }
    throw "Could not find resx.dll. Build it first with: cargo build -p resx --release --lib"
}

function Resolve-DefaultImage {
    $winDir = if ($env:WINDIR -and $env:WINDIR.Trim().Length -gt 0) { $env:WINDIR } else { "C:\Windows" }
    return (Join-Path $winDir "System32\ntdll.dll")
}

function Get-VsDevCmd {
    $roots = @(
        "C:\Program Files\Microsoft Visual Studio\18\Insiders",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional",
        "C:\Program Files\Microsoft Visual Studio\2022\Community",
        "C:\Program Files\Microsoft Visual Studio\2022\BuildTools"
    )
    foreach ($root in $roots) {
        $candidate = Join-Path $root "Common7\Tools\VsDevCmd.bat"
        if (Test-Path -LiteralPath $candidate) {
            return $candidate
        }
    }

    $vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
    if (Test-Path -LiteralPath $vswhere) {
        $installPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
        if ($installPath) {
            $candidate = Join-Path $installPath "Common7\Tools\VsDevCmd.bat"
            if (Test-Path -LiteralPath $candidate) {
                return $candidate
            }
        }
    }

    throw "Could not find VsDevCmd.bat for the MSVC toolchain."
}

function Quote-CmdArg {
    param([Parameter(Mandatory)] [string]$Value)
    return '"' + ($Value -replace '"', '\"') + '"'
}

if ($ResxDll.Trim().Length -eq 0) {
    $ResxDll = Resolve-DefaultResxDll
} else {
    $ResxDll = (Resolve-Path -LiteralPath $ResxDll).Path
}

if ($Image.Trim().Length -eq 0) {
    $Image = Resolve-DefaultImage
} else {
    $Image = (Resolve-Path -LiteralPath $Image).Path
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if (-not $NoBuild) {
    $vsDevCmd = Get-VsDevCmd
    $buildLog = Join-Path $OutDir "build.log"
    $cmd = @(
        (Quote-CmdArg $vsDevCmd),
        "-arch=x64",
        "-host_arch=x64",
        ">nul",
        "&&",
        "cl",
        "/nologo",
        "/W4",
        "/WX",
        (Quote-CmdArg $Source),
        "/Fe:" + (Quote-CmdArg $Exe),
        "/Fo:" + (Quote-CmdArg (Join-Path $OutDir "resx_dll_smoke.obj"))
    ) -join " "
    Write-Host "[build] $Exe"
    & cmd.exe /d /s /c $cmd *> $buildLog
    if ($LASTEXITCODE -ne 0) {
        Get-Content -LiteralPath $buildLog
        throw "MSVC build failed. See $buildLog"
    }
}

Write-Host "[run] $Exe"
& $Exe $ResxDll $Image $Function
exit $LASTEXITCODE
