[CmdletBinding()]
param(
    [string]$Configuration = "release",
    [string]$OutputRoot = "publish",
    [string]$TimestampServer = "http://timestamp.digicert.com",
    [string]$SubjectName = "TITAN Softwork Solutions",
    [string]$CertificateStoreName = "My",
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [string]$PfxPassword,
    [switch]$SkipNpmCi,
    [switch]$NoSign
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$ExtensionRoot = Join-Path $RepoRoot "resx-vscode"
$CargoToml = Join-Path $RepoRoot "resx\Cargo.toml"
$ExtensionPackageJson = Join-Path $ExtensionRoot "package.json"
$BundledCliDir = Join-Path $ExtensionRoot "bin\win32-x64"
$TrustManifestPath = Join-Path $ExtensionRoot "bin\trust.json"

function Require-Tool {
    param([Parameter(Mandatory = $true)][string]$Name)

    $cmd = Get-Command $Name -ErrorAction SilentlyContinue
    if (-not $cmd) {
        if ($Name -ieq "signtool.exe") {
            $kitRoots = @()
            if (${env:ProgramFiles(x86)}) {
                $kitRoots += Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
                $kitRoots += Join-Path ${env:ProgramFiles(x86)} "Windows Kits\8.1\bin"
            }

            foreach ($kitRoot in $kitRoots) {
                if (-not (Test-Path $kitRoot)) {
                    continue
                }

                $candidates = Get-ChildItem -Path $kitRoot -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
                    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
                    Sort-Object -Property FullName -Descending
                if ($candidates.Count -gt 0) {
                    return $candidates[0].FullName
                }

                $fallback = Get-ChildItem -Path $kitRoot -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
                    Sort-Object -Property FullName -Descending |
                    Select-Object -First 1
                if ($fallback) {
                    return $fallback.FullName
                }
            }
        }
        throw "Required tool not found: $Name"
    }
    return $cmd.Source
}

function Get-VersionValue {
    param([Parameter(Mandatory = $true)][string]$Path)

    $raw = Get-Content $Path -Raw
    if ($raw -notmatch 'version\s*=\s*"([^"]+)"') {
        throw "Unable to read version from $Path"
    }
    return $matches[1]
}

function Get-ExtensionVersion {
    param([Parameter(Mandatory = $true)][string]$Path)

    $pkg = Get-Content $Path -Raw | ConvertFrom-Json
    return [string]$pkg.version
}

function Resolve-PfxPath {
    param([string]$ExplicitPath)

    if ($ExplicitPath) {
        $resolved = Resolve-Path $ExplicitPath -ErrorAction Stop
        return $resolved.Path
    }

    $matches = Get-ChildItem -Path $RepoRoot -Filter *.pfx -File
    if ($matches.Count -eq 0) {
        throw "No .pfx file found in repo root. Pass -PfxPath or place the certificate in the root."
    }
    if ($matches.Count -gt 1) {
        throw "Multiple .pfx files found in repo root. Pass -PfxPath explicitly."
    }
    return $matches[0].FullName
}

function Get-PfxPasswordValue {
    param([string]$ExplicitPassword)

    if ($ExplicitPassword) {
        return $ExplicitPassword
    }
    if ($env:RESX_PFX_PASSWORD) {
        return $env:RESX_PFX_PASSWORD
    }

    $secure = Read-Host "PFX password" -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    try {
        return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    }
    finally {
        if ($bstr -ne [IntPtr]::Zero) {
            [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
        }
    }
}

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    Write-Host ">> $FilePath $($Arguments -join ' ')" -ForegroundColor Cyan
    Push-Location $WorkingDirectory
    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code $LASTEXITCODE"
        }
    }
    finally {
        Pop-Location
    }
}

function Sign-File {
    param(
        [Parameter(Mandatory = $true)][string]$SignTool,
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$Timestamp,
        [string]$CertificatePath,
        [string]$CertificatePassword,
        [string]$StoreName,
        [string]$CertSubject,
        [string]$CertThumbprint
    )

    if (-not (Test-Path $FilePath)) {
        throw "Cannot sign missing file: $FilePath"
    }

    if ($StoreName -and ($CertThumbprint -or $CertSubject)) {
        $storeArgs = @(
            "sign",
            "/fd", "SHA256",
            "/s", $StoreName
        )
        if ($CertThumbprint) {
            $storeArgs += @("/sha1", $CertThumbprint)
        } else {
            $storeArgs += @("/n", $CertSubject)
        }
        $storeArgs += @(
            "/tr", $Timestamp,
            "/td", "SHA256",
            $FilePath
        )
        try {
            Invoke-Step -FilePath $SignTool -Arguments $storeArgs -WorkingDirectory $RepoRoot
            return
        }
        catch {
            if (-not $CertificatePath) {
                throw
            }
            Write-Warning "Store-based signing failed for $FilePath. Falling back to PFX."
        }
    }

    if (-not $CertificatePath) {
        throw "No usable signing certificate available for $FilePath"
    }

    Invoke-Step -FilePath $SignTool -Arguments @(
        "sign",
        "/fd", "SHA256",
        "/f", $CertificatePath,
        "/p", $CertificatePassword,
        "/tr", $Timestamp,
        "/td", "SHA256",
        $FilePath
    ) -WorkingDirectory $RepoRoot
}

function Write-Sha256 {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string]$OutputPath
    )

    $hash = (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
    $name = Split-Path -Leaf $FilePath
    Set-Content -Path $OutputPath -Value "$hash  $name" -Encoding ascii
}

function Get-Sha256Value {
    param([Parameter(Mandatory = $true)][string]$FilePath)

    return (Get-FileHash -Path $FilePath -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Write-TrustManifest {
    param(
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$BundledExePath,
        [string]$SignerThumbprint
    )

    $manifestDir = Split-Path -Parent $OutputPath
    if (-not (Test-Path $manifestDir)) {
        New-Item -ItemType Directory -Force -Path $manifestDir | Out-Null
    }

    $bundledHash = Get-Sha256Value -FilePath $BundledExePath
    $manifest = [ordered]@{
        signerThumbprints = @()
        bundledSha256 = [ordered]@{
            "win32-x64/resx.exe" = $bundledHash
        }
    }

    if ($SignerThumbprint) {
        $manifest.signerThumbprints = @($SignerThumbprint.ToUpperInvariant())
    }

    $json = $manifest | ConvertTo-Json -Depth 5
    Set-Content -LiteralPath $OutputPath -Value $json -Encoding utf8
}

$CargoVersion = Get-VersionValue -Path $CargoToml
$ExtensionVersion = Get-ExtensionVersion -Path $ExtensionPackageJson
$StageRoot = Join-Path $RepoRoot $OutputRoot
$StageDir = Join-Path $StageRoot "resx-$CargoVersion-publish"
$CliStage = Join-Path $StageDir "cli"
$VsixStage = Join-Path $StageDir "vscode"

$CargoExe = Join-Path $RepoRoot "target\$Configuration\resx.exe"
$BundledExe = Join-Path $BundledCliDir "resx.exe"
$VsixPath = Join-Path $ExtensionRoot "resx-vscode-$ExtensionVersion.vsix"

$Cargo = Require-Tool "cargo"
$Node = Require-Tool "npm"
$SignTool = $null
$ResolvedPfx = $null
$ResolvedPfxPassword = $null
$StoreCertAvailable = $false
$ResolvedStoreThumbprint = $null

if (-not $NoSign) {
    $SignTool = Require-Tool "signtool.exe"

    if (-not $CertificateThumbprint -and $env:RESX_CERT_THUMBPRINT) {
        $CertificateThumbprint = $env:RESX_CERT_THUMBPRINT
    }

    if ($CertificateThumbprint) {
        $ResolvedStoreThumbprint = ($CertificateThumbprint -replace '\s', '').ToUpperInvariant()
        $StoreCertAvailable = $true
    } else {
        $storeMatches = @()
        $storeCandidates = @(
            "Cert:\CurrentUser\$CertificateStoreName",
            "Cert:\LocalMachine\$CertificateStoreName"
        )
        foreach ($storePath in $storeCandidates) {
            if (Test-Path $storePath) {
                $storeMatches += Get-ChildItem -Path $storePath | Where-Object {
                    $_.Subject -like "*$SubjectName*" -and $_.HasPrivateKey
                }
            }
        }

        if ($storeMatches.Count -gt 0) {
            $selectedCert = $storeMatches |
                Sort-Object -Property NotAfter -Descending |
                Select-Object -First 1
            $ResolvedStoreThumbprint = ($selectedCert.Thumbprint -replace '\s', '').ToUpperInvariant()
            $StoreCertAvailable = $true
            Write-Host "Using store certificate thumbprint: $ResolvedStoreThumbprint" -ForegroundColor Yellow
        }
    }

    if (-not $StoreCertAvailable) {
        $ResolvedPfx = Resolve-PfxPath -ExplicitPath $PfxPath
        $ResolvedPfxPassword = Get-PfxPasswordValue -ExplicitPassword $PfxPassword
    }
}

if (Test-Path $StageDir) {
    Remove-Item -LiteralPath $StageDir -Recurse -Force
}

New-Item -ItemType Directory -Force -Path $CliStage | Out-Null
New-Item -ItemType Directory -Force -Path $VsixStage | Out-Null
New-Item -ItemType Directory -Force -Path $BundledCliDir | Out-Null

Invoke-Step -FilePath $Cargo -Arguments @("build", "-p", "resx", "--$Configuration") -WorkingDirectory $RepoRoot

if (-not (Test-Path $CargoExe)) {
    throw "Built CLI not found: $CargoExe"
}

if (-not $SkipNpmCi) {
    Invoke-Step -FilePath $Node -Arguments @("ci") -WorkingDirectory $ExtensionRoot
}

Copy-Item -LiteralPath $CargoExe -Destination $BundledExe -Force

if (-not $NoSign) {
    Sign-File -SignTool $SignTool -FilePath $CargoExe -Timestamp $TimestampServer -CertificatePath $ResolvedPfx -CertificatePassword $ResolvedPfxPassword -StoreName $CertificateStoreName -CertSubject $SubjectName -CertThumbprint $ResolvedStoreThumbprint
    Sign-File -SignTool $SignTool -FilePath $BundledExe -Timestamp $TimestampServer -CertificatePath $ResolvedPfx -CertificatePassword $ResolvedPfxPassword -StoreName $CertificateStoreName -CertSubject $SubjectName -CertThumbprint $ResolvedStoreThumbprint
}

Write-TrustManifest -OutputPath $TrustManifestPath -BundledExePath $BundledExe -SignerThumbprint $ResolvedStoreThumbprint

Invoke-Step -FilePath $Node -Arguments @("run", "compile") -WorkingDirectory $ExtensionRoot
Invoke-Step -FilePath $Node -Arguments @("run", "package") -WorkingDirectory $ExtensionRoot

if (-not (Test-Path $VsixPath)) {
    throw "VSIX not found after packaging: $VsixPath"
}

Copy-Item -LiteralPath $CargoExe -Destination (Join-Path $CliStage "resx.exe") -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "README.md") -Destination (Join-Path $CliStage "README.md") -Force
Copy-Item -LiteralPath (Join-Path $RepoRoot "COMMANDS.md") -Destination (Join-Path $CliStage "COMMANDS.md") -Force
Copy-Item -LiteralPath $VsixPath -Destination (Join-Path $VsixStage (Split-Path -Leaf $VsixPath)) -Force
Copy-Item -LiteralPath (Join-Path $ExtensionRoot "README.md") -Destination (Join-Path $VsixStage "README.md") -Force

Write-Sha256 -FilePath (Join-Path $CliStage "resx.exe") -OutputPath (Join-Path $CliStage "resx.exe.sha256")
Write-Sha256 -FilePath (Join-Path $VsixStage (Split-Path -Leaf $VsixPath)) -OutputPath (Join-Path $VsixStage "$((Split-Path -Leaf $VsixPath)).sha256")

$BundleZip = Join-Path $StageRoot "resx-$CargoVersion-publish.zip"
if (Test-Path $BundleZip) {
    Remove-Item -LiteralPath $BundleZip -Force
}
Compress-Archive -Path "$StageDir\*" -DestinationPath $BundleZip -Force
Write-Sha256 -FilePath $BundleZip -OutputPath "$BundleZip.sha256"

Write-Host ""
Write-Host "Publish artifacts ready:" -ForegroundColor Green
Write-Host "  $StageDir"
Write-Host "  $BundleZip"
Write-Host "Note: the VSIX is packaged and hashed, but not Authenticode-signed. SignTool does not support VSIX/ZIP containers." -ForegroundColor Yellow
