# mytools-osint one-line installer — Windows PowerShell
#
# Usage:
#   irm https://raw.githubusercontent.com/Azizbek16l/mytools-osint/main/scripts/install.ps1 | iex
#   $env:OSINT_VERSION = 'v4.2.1'; irm ... | iex   # pin a specific version
#
# Downloads osint-windows-x64.exe from the latest GitHub release, verifies
# SHA-256, and installs into %LOCALAPPDATA%\Programs\mytools-osint. Adds
# that dir to the per-user PATH so `osint` is immediately runnable from a
# fresh terminal. No admin rights required.

$ErrorActionPreference = 'Stop'

$Repo    = 'Azizbek16l/mytools-osint'
$Asset   = 'osint-windows-x64.exe'
$BinName = 'osint.exe'
$Version = if ($env:OSINT_VERSION) { $env:OSINT_VERSION } else { 'latest' }
$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\mytools-osint'

function Say  ($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn ($m) { Write-Host "!!  $m" -ForegroundColor Yellow }
function Ok   ($m) { Write-Host "✓   $m" -ForegroundColor Green }
function Die  ($m) { Write-Host "✗   $m" -ForegroundColor Red; exit 1 }

# ---- arch check ------------------------------------------------------------
if (-not [Environment]::Is64BitOperatingSystem) {
    Die "32-bit Windows is not supported. Use pipx or build from source."
}
if ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture -eq 'Arm64') {
    Warn "Windows ARM64 detected. The x64 build will run via emulation."
}

# ---- resolve version -------------------------------------------------------
if ($Version -eq 'latest') {
    Say 'resolving latest release tag…'
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest" `
                                 -UseBasicParsing -TimeoutSec 15
        $Version = $rel.tag_name
    } catch { Die "could not query GitHub API: $($_.Exception.Message)" }
}
if (-not $Version) { Die 'empty version tag' }

$base    = "https://github.com/$Repo/releases/download/$Version"
$url     = "$base/$Asset"
$sumsUrl = "$base/SHA256SUMS-$Version"

Say "version:  $Version"
Say "asset:    $Asset"
Say "install:  $InstallDir\$BinName"

# ---- download to temp ------------------------------------------------------
$tmp = New-Item -ItemType Directory -Path (Join-Path $env:TEMP "mytools-osint-$([guid]::NewGuid().ToString('N'))")
try {
    $bin = Join-Path $tmp $Asset
    Say "downloading…"
    Invoke-WebRequest -Uri $url -OutFile $bin -UseBasicParsing -TimeoutSec 300

    # ---- verify SHA-256 -----------------------------------------------------
    Say "fetching SHA256SUMS-$Version…"
    $sumsFile = Join-Path $tmp 'SHA256SUMS'
    $verified = $false
    try {
        Invoke-WebRequest -Uri $sumsUrl -OutFile $sumsFile -UseBasicParsing -TimeoutSec 30
        $expected = (Select-String -Path $sumsFile -Pattern "\s\*?$([regex]::Escape($Asset))$").Line -split '\s+' | Select-Object -First 1
        if ($expected) {
            $actual = (Get-FileHash -Path $bin -Algorithm SHA256).Hash.ToLower()
            if ($actual -eq $expected.ToLower()) {
                Ok "SHA-256 verified: $actual"
                $verified = $true
            } else {
                Die "SHA-256 mismatch: expected $expected, got $actual"
            }
        } else {
            Warn "asset not in SHA256SUMS — proceeding without verification"
        }
    } catch {
        Warn "SHA256SUMS not available — proceeding without verification"
    }

    # ---- install ------------------------------------------------------------
    if (-not (Test-Path $InstallDir)) {
        New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    }
    $dest = Join-Path $InstallDir $BinName
    if (Test-Path $dest) {
        Say "removing previous install…"
        Remove-Item -Force $dest
    }
    Move-Item -Path $bin -Destination $dest -Force

    # ---- add to user PATH ---------------------------------------------------
    $userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
    if (-not $userPath) { $userPath = '' }
    if ($userPath -notlike "*$InstallDir*") {
        Say "adding $InstallDir to per-user PATH…"
        $sep = if ($userPath.EndsWith(';') -or $userPath -eq '') { '' } else { ';' }
        [Environment]::SetEnvironmentVariable('Path', "$userPath$sep$InstallDir", 'User')
        $env:Path = "$env:Path;$InstallDir"  # make available in current session too
        Ok "PATH updated — fresh terminals will pick it up automatically"
    } else {
        Ok "PATH already contains install dir"
    }

    # ---- smoke test --------------------------------------------------------
    Say "verifying…"
    try {
        $out = & $dest --version --no-banner --no-color 2>&1 | Out-String
        $line = ($out -split "`n" | Where-Object { $_ -match 'mytools-osint' } | Select-Object -First 1).Trim()
        if ($line) { Ok $line }
    } catch {
        Warn "binary installed but smoke test failed — first launch self-extracts (~8-12s)"
    }

    Write-Host ''
    Ok "installation complete · try: osint github.com"
    Write-Host "   docs: https://github.com/$Repo"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
