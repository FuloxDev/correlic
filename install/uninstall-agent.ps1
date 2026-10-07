# ============================================================
# Correlic Windows Agent Uninstaller
# Removes the Windows ETW agent and all local files
#
# Usage: powershell -ExecutionPolicy Bypass -File uninstall-agent.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$InstallDir = "C:\Correlic"

function Write-OK($msg) {
    Write-Host "  [OK] " -ForegroundColor Green -NoNewline
    Write-Host $msg
}

function Write-Warn($msg) {
    Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
    Write-Host $msg
}

# Check Administrator
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "  [ERROR] " -ForegroundColor Red -NoNewline
    Write-Host "This script must be run as Administrator."
    exit 1
}

Write-Host ""
Write-Host "Uninstalling Correlic Agent..." -ForegroundColor Cyan
Write-Host ""

# Stop service
$svc = Get-Service CorrelicAgent -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -eq 'Running') {
        Stop-Service CorrelicAgent -Force
        Start-Sleep -Seconds 2
        Write-OK "Service stopped"
    }

    # Uninstall service via agent binary
    $agentExe = "$InstallDir\bin\correlic-agent.exe"
    if (Test-Path $agentExe) {
        & $agentExe service uninstall 2>$null
        Write-OK "Service unregistered"
    } else {
        # Fallback: remove service directly
        sc.exe delete CorrelicAgent 2>$null | Out-Null
        Write-OK "Service removed via sc.exe"
    }
} else {
    Write-Warn "CorrelicAgent service not found (may already be uninstalled)"
}

# Remove environment variable
[System.Environment]::SetEnvironmentVariable("CORRELIC_CONFIG", $null, "Machine")
Write-OK "Environment variable removed"

# Remove install directory (but NOT the shared volume C:\Correlic\agent)
$dirsToRemove = @("$InstallDir\bin", "$InstallDir\certs", "$InstallDir\config", "$InstallDir\logs")
foreach ($dir in $dirsToRemove) {
    if (Test-Path $dir) {
        Remove-Item $dir -Recurse -Force
    }
}

# Remove parent if empty (don't remove C:\Correlic\agent — that's the Docker volume)
$remaining = Get-ChildItem $InstallDir -ErrorAction SilentlyContinue
if ($remaining.Count -eq 0 -or ($remaining.Count -eq 1 -and $remaining[0].Name -eq "agent")) {
    Write-OK "Install directory cleaned"
} else {
    Write-OK "Install directory cleaned (shared volume preserved)"
}

Write-Host ""
Write-Host "Correlic Agent uninstalled." -ForegroundColor Green
Write-Host ""
