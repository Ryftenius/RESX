param(
    [string]$OutDir = (Join-Path $PSScriptRoot "..\build"),
    [switch]$Clean,
    [switch]$WithNdis
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

$dllSource = Join-Path $src "resx_fixtures_dll.c"
$variantSource = Join-Path $src "resx_fixtures_variant_dll.c"
$exeSource = Join-Path $src "resx_fixtures_exe.c"
$defFile = Join-Path $src "resx_fixtures.def"
$dllPath = Join-Path $out "resx_fixtures.dll"
$variantDllPath = Join-Path $out "resx_fixtures_variant.dll"
$libPath = Join-Path $out "resx_fixtures.lib"
$variantLibPath = Join-Path $out "resx_fixtures_variant.lib"
$exePath = Join-Path $out "resx_fixtures_probe.exe"
$dllObj = Join-Path $out "resx_fixtures_dll.obj"
$variantDllObj = Join-Path $out "resx_fixtures_variant_dll.obj"
$exeObj = Join-Path $out "resx_fixtures_exe.obj"

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

$dataSource = Join-Path $src "data_exports.c"
$dataObj = Join-Path $out "data_exports.obj"
$dataDll = Join-Path $out "data_exports.dll"
$dataLib = Join-Path $out "data_exports.lib"
& $compiler.Path @common "/LD" "/Fo:$dataObj" $dataSource "/Fe:$dataDll" "/link" "/IMPLIB:$dataLib" "/OUT:$dataDll"
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
Write-Host "  $dataDll"

$argumentsSource = Join-Path $src "api_arguments.c"
$argumentsObj = Join-Path $out "api_arguments.obj"
$argumentsDll = Join-Path $out "api_arguments.dll"
$argumentsLib = Join-Path $out "api_arguments.lib"
& $compiler.Path @common "/LD" "/Fo:$argumentsObj" $argumentsSource "/Fe:$argumentsDll" "/link" "/IMPLIB:$argumentsLib" "/OUT:$argumentsDll"
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "  $argumentsDll"

if ($WithNdis) {
    $kitInclude = Join-Path $env:WindowsSdkDir ('Include\' + $env:WindowsSDKVersion.TrimEnd('\') + '\km')
    $ndisLib = Join-Path $env:WindowsSdkDir ('Lib\' + $env:WindowsSDKVersion.TrimEnd('\') + '\km\x64\ndis.lib')
    if (!(Test-Path -LiteralPath (Join-Path $kitInclude 'ndis\oidrequest.h')) -or !(Test-Path -LiteralPath $ndisLib)) {
        throw 'The optional NDIS fixture requires installed WDK headers and x64 ndis.lib matching the active SDK.'
    }
    $ndisObj = Join-Path $out 'ndis_requests.obj'
    $ndisDll = Join-Path $out 'ndis_requests.dll'
    $ndisImport = Join-Path $out 'ndis_requests.lib'
    & $compiler.Path @common "/I$kitInclude" '/LD' "/Fo:$ndisObj" (Join-Path $src 'ndis_requests.c') "/Fe:$ndisDll" '/link' $ndisLib "/IMPLIB:$ndisImport" "/OUT:$ndisDll"
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    Write-Host "  $ndisDll"
}
