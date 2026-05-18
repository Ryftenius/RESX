param(
    [string]$OutDir = (Join-Path $PSScriptRoot "..\build"),
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$src = Join-Path $root "src"
if ([System.IO.Path]::IsPathRooted($OutDir)) {
    $out = $OutDir
} else {
    $out = Join-Path $root $OutDir
}

if ($Clean -and (Test-Path $out)) {
    Remove-Item -LiteralPath $out -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $out | Out-Null

function Import-VsDevCmd {
    if ($env:INCLUDE -like "*Windows Kits*") {
        return
    }

    $candidates = @(
        "C:\Program Files\Microsoft Visual Studio",
        "C:\Program Files (x86)\Microsoft Visual Studio"
    )

    foreach ($candidate in $candidates) {
        if (-not (Test-Path $candidate)) {
            continue
        }
        $vsDevCmd = Get-ChildItem $candidate -Recurse -Filter VsDevCmd.bat -ErrorAction SilentlyContinue |
            Select-Object -First 1 -ExpandProperty FullName
        if (-not $vsDevCmd) {
            continue
        }

        $cmd = "`"$vsDevCmd`" -arch=amd64 -host_arch=amd64 >nul && set"
        $lines = & cmd.exe /s /c $cmd
        if ($LASTEXITCODE -ne 0) {
            continue
        }
        foreach ($line in $lines) {
            $parts = $line -split "=", 2
            if ($parts.Length -eq 2) {
                Set-Item -Path "env:$($parts[0])" -Value $parts[1]
            }
        }
        return
    }
}

function Find-Compiler {
    $cl = Get-Command cl.exe -ErrorAction SilentlyContinue
    if ($cl) { return @{ Path = $cl.Source; Kind = "cl" } }

    $clang = Get-Command clang-cl.exe -ErrorAction SilentlyContinue
    if ($clang) { return @{ Path = $clang.Source; Kind = "clang-cl" } }

    throw "No supported Windows C compiler found. Run from a Visual Studio Developer shell, or put cl.exe/clang-cl.exe on PATH."
}

Import-VsDevCmd
$compiler = Find-Compiler
$common = @(
    "/nologo",
    "/W4",
    "/WX",
    "/O2",
    "/GS",
    "/guard:cf",
    "/I$src"
)

$dllSource = Join-Path $src "resx_palace_dll.c"
$variantSource = Join-Path $src "resx_palace_variant_dll.c"
$exeSource = Join-Path $src "resx_palace_exe.c"
$defFile = Join-Path $src "resx_palace.def"
$dllPath = Join-Path $out "resx_palace.dll"
$variantDllPath = Join-Path $out "resx_palace_variant.dll"
$libPath = Join-Path $out "resx_palace.lib"
$variantLibPath = Join-Path $out "resx_palace_variant.lib"
$exePath = Join-Path $out "resx_palace_probe.exe"
$dllObj = Join-Path $out "resx_palace_dll.obj"
$variantDllObj = Join-Path $out "resx_palace_variant_dll.obj"
$exeObj = Join-Path $out "resx_palace_exe.obj"

& $compiler.Path @common "/LD" "/Fo:$dllObj" $dllSource "/Fe:$dllPath" "/link" "/DEF:$defFile" "/IMPLIB:$libPath" "/OUT:$dllPath"
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $compiler.Path @common "/LD" "/Fo:$variantDllObj" $variantSource "/Fe:$variantDllPath" "/link" "/DEF:$defFile" "/IMPLIB:$variantLibPath" "/OUT:$variantDllPath"
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

& $compiler.Path @common "/Fo:$exeObj" $exeSource $libPath "/Fe:$exePath" "/link" "/OUT:$exePath"
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Host "Built:"
Write-Host "  $dllPath"
Write-Host "  $variantDllPath"
Write-Host "  $exePath"
