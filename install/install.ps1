# REO installer — Windows.
#   irm https://reo.sh/install.ps1 | iex
#
# Downloads the signed REO binary, verifies its checksum, and installs it under
# %LOCALAPPDATA%\Programs\reo, adding that to your user PATH. REO itself never
# phones home; this installer is the one network step, and only at install time.

$ErrorActionPreference = 'Stop'

function Say($m) { Write-Host "> $m" -ForegroundColor Cyan }
function Die($m) { Write-Host "x $m" -ForegroundColor Red; exit 1 }

# Binaries are served from GitHub Releases. Override $env:REO_REPO to install a fork.
$Repo    = if ($env:REO_REPO) { $env:REO_REPO } else { 'zenashwoldeyes-rgb/reo' }
$Version = if ($env:REO_VERSION) { $env:REO_VERSION } else { 'latest' }
$Asset   = 'reo-x86_64-pc-windows-msvc.exe'
$Base    = if ($Version -eq 'latest') {
    "https://github.com/$Repo/releases/latest/download"
} else {
    "https://github.com/$Repo/releases/download/$Version"
}
$Url     = "$Base/$Asset"

$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\reo'
New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$Exe = Join-Path $InstallDir 'reo.exe'
$Tmp = Join-Path $env:TEMP 'reo-download.exe'

Say "Downloading REO ($Asset)"
Invoke-WebRequest -Uri $Url -OutFile $Tmp -UseBasicParsing

Say 'Verifying checksum'
$expected = (Invoke-WebRequest -Uri "$Url.sha256" -UseBasicParsing).Content.Trim().Split(' ')[0]
$actual   = (Get-FileHash -Algorithm SHA256 $Tmp).Hash.ToLower()
if ($expected -ne $actual) { Die 'checksum mismatch — refusing to install' }

Move-Item -Force $Tmp $Exe
Say "Installed to $Exe"

# Add install dir to the user PATH if it isn't already there.
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if ($userPath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable('Path', "$userPath;$InstallDir", 'User')
    Say 'Added REO to your PATH (restart your terminal to pick it up).'
}

Write-Host ''
Write-Host 'Done. Type ' -NoNewline
Write-Host 'reo' -ForegroundColor Cyan -NoNewline
Write-Host ' to begin. Everything stays on your machine.'
