# Correlic — Uninstall
# Usage: powershell C:\Correlic\uninstall.ps1
# Must run as Administrator

$ErrorActionPreference = "SilentlyContinue"
$Dir = "C:\Correlic"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[ERROR] Run as Administrator to uninstall." -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Correlic Uninstaller" -ForegroundColor Cyan
Write-Host ""

$confirm = Read-Host "This will remove Correlic and ALL data from $Dir. Continue? (y/n)"
if ($confirm -ne 'y') {
    Write-Host "Cancelled." -ForegroundColor Gray
    exit 0
}

Write-Host "Uninstalling Correlic..." -ForegroundColor Cyan

# 1. Stop all processes first
Stop-Service CorrelicAgent -Force 2>$null
Stop-Service neo4j -Force 2>$null
Stop-Process -Name correlic-api, correlic-telemetry -Force 2>$null
Get-Process node -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*Correlic*"
} | Stop-Process -Force 2>$null
Get-Process java -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*Correlic*"
} | Stop-Process -Force 2>$null
Start-Sleep -Seconds 2
Write-Host "  All processes stopped" -ForegroundColor Gray

# 2. Uninstall agent service (try binary first, sc.exe as fallback)
if (Test-Path "$Dir\bin\correlic-agent.exe") {
    $env:CORRELIC_CONFIG = "$Dir\agent.yaml"
    & "$Dir\bin\correlic-agent.exe" service uninstall 2>$null
} else {
    sc.exe delete CorrelicAgent 2>$null
}
Write-Host "  Agent service removed" -ForegroundColor Gray

# 3. Uninstall Neo4j service (try binary first, sc.exe as fallback)
$neo4jHome = "$Dir\neo4j"
if (Test-Path "$neo4jHome\bin\neo4j.bat") {
    $env:JAVA_HOME = "$Dir\jre"
    $env:NEO4J_HOME = $neo4jHome
    & "$neo4jHome\bin\neo4j.bat" windows-service uninstall 2>$null
} else {
    sc.exe delete neo4j 2>$null
}
Write-Host "  Neo4j service removed" -ForegroundColor Gray

# 4. Stop PostgreSQL
$pgCtl = "$Dir\pgsql\bin\pg_ctl.exe"
if (Test-Path $pgCtl) {
    & $pgCtl stop -D "$Dir\pgsql\data" -m immediate 2>$null | Out-Null
    Start-Sleep -Seconds 2
}

# 5. Remove install directory
if (Test-Path $Dir) {
    # Wait for file handles to release
    Start-Sleep -Seconds 3
    Remove-Item $Dir -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path $Dir) {
        # Retry — some files may be locked briefly by Windows
        Start-Sleep -Seconds 3
        Remove-Item $Dir -Recurse -Force -ErrorAction SilentlyContinue
    }
    if (Test-Path $Dir) {
        Write-Host "  [!] Could not fully remove $Dir — some files may be locked." -ForegroundColor Yellow
        Write-Host "       Reboot and delete manually, or run: Remove-Item $Dir -Recurse -Force" -ForegroundColor Gray
    } else {
        Write-Host "  Removed $Dir" -ForegroundColor Gray
    }
}

# 6. Clean up environment variable
[System.Environment]::SetEnvironmentVariable("CORRELIC_CONFIG", $null, "Machine")

# 7. Remove agent config from user profile
$agentConfig = "$env:USERPROFILE\.correlic"
if (Test-Path $agentConfig) {
    Remove-Item $agentConfig -Recurse -Force
    Write-Host "  Removed agent config" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Correlic has been uninstalled." -ForegroundColor Green
Write-Host ""
