# PowerShell Installer for Vivacious CLI on Windows
$ErrorActionPreference = "Stop"

Write-Host "=========================================================" -ForegroundColor Cyan
Write-Host "  Installing Vivacious CLI on Windows..." -ForegroundColor Cyan
Write-Host "=========================================================" -ForegroundColor Cyan

$InstallDir = Join-Path $HOME "AppData\Local\vivacious"
$ExePath = Join-Path $InstallDir "vivacious.exe"
$DistUrl = "https://github.com/Viavcious-cloud/vivacious-cli/releases/latest/download/vivacious-windows-x64.exe"

Write-Host "Creating installation directory: $InstallDir"
if (-not (Test-Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

Write-Host "Downloading vivacious-windows-x64.exe from GitHub Releases..."
Write-Host "Source: $DistUrl"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $DistUrl -OutFile $ExePath -UseBasicParsing

Write-Host "Registering installation directory in user's PATH..."
$UserPath = [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget]::User)

if ($UserPath -split ";" -notcontains $InstallDir) {
    $NewUserPath = "$UserPath;$InstallDir"
    [Environment]::SetEnvironmentVariable("Path", $NewUserPath, [EnvironmentVariableTarget]::User)
    Write-Host "Directory added to User PATH environment variable."
} else {
    Write-Host "Directory is already present in PATH."
}

Write-Host ""
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "🎉 Vivacious CLI has been successfully installed!" -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Please restart your terminal/PowerShell window."
Write-Host "Run 'vivacious' from any command shell to get started."

