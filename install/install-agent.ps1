# ============================================================
# Correlic Windows Agent Installer
# Installs the Windows ETW agent alongside a Docker backend
#
# Prerequisites: Docker backend running with shared volume at
#   C:\Correlic\agent (contains agent.exe, certs, config)
#
# Usage: powershell -ExecutionPolicy Bypass -File install-agent.ps1
# ============================================================

$ErrorActionPreference = "Stop"
$Version = "v1.0.1"
$SourceDir = $PSScriptRoot  # Shared volume: C:\Correlic\agent
$InstallDir = "C:\Correlic"
$TotalSteps = 7

# ── Helpers ──────────────────────────────────────────────────

function Write-Header {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  Correlic Agent Installer $Version" -ForegroundColor Cyan
    Write-Host "  Windows ETW Agent for Docker Backend" -ForegroundColor Cyan
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Step($step, $msg) {
    Write-Host "[$step/$TotalSteps] " -ForegroundColor Cyan -NoNewline
    Write-Host $msg
}

function Write-OK($msg) {
    Write-Host "  [OK] " -ForegroundColor Green -NoNewline
    Write-Host $msg
}

function Write-Warn($msg) {
    Write-Host "  [!] " -ForegroundColor Yellow -NoNewline
    Write-Host $msg
}

function Write-Fail($msg) {
    Write-Host "  [ERROR] " -ForegroundColor Red -NoNewline
    Write-Host $msg
    exit 1
}

function Write-Detail($msg) {
    Write-Host "       $msg" -ForegroundColor Gray
}

# ── 1. Check Administrator ──────────────────────────────────

Write-Header

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail "This script must be run as Administrator. Right-click PowerShell and select 'Run as Administrator'."
}
Write-Step 1 "Checking prerequisites..."
Write-OK "Running as Administrator"

# ── 2. Validate source files from Docker volume ─────────────

Write-Step 2 "Validating agent package from Docker..."

$requiredFiles = @("correlic-agent.exe", "ca.crt", "client.crt", "client.key", "agent.yaml")
foreach ($f in $requiredFiles) {
    $path = Join-Path $SourceDir $f
    if (-not (Test-Path $path)) {
        Write-Fail "Missing required file: $path`n  Make sure the Docker container is running with -v C:\Correlic\agent:/opt/correlic/host-agent`n  The container may still be initializing — wait 60 seconds after docker run and try again.`n  If you recreated the Docker container, re-run this script to pick up new certificates."
    }
}
Write-OK "All agent files found in $SourceDir"

# ── 3. Check Windows version ────────────────────────────────

Write-Step 3 "Checking Windows compatibility..."

$buildNumber = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuildNumber
if ($buildNumber -lt 17763) {
    Write-Fail "Windows 10 1809 (build 17763) or later is required. Current build: $buildNumber"
}
Write-OK "Windows build $buildNumber (compatible)"

# ── 4. Copy files to install directory ───────────────────────

Write-Step 4 "Installing agent to $InstallDir..."

New-Item -ItemType Directory -Path "$InstallDir\bin" -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallDir\certs" -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallDir\config" -Force | Out-Null
New-Item -ItemType Directory -Path "$InstallDir\logs" -Force | Out-Null

Copy-Item "$SourceDir\correlic-agent.exe" "$InstallDir\bin\" -Force
Copy-Item "$SourceDir\ca.crt" "$InstallDir\certs\" -Force
Copy-Item "$SourceDir\client.crt" "$InstallDir\certs\" -Force
Copy-Item "$SourceDir\client.key" "$InstallDir\certs\" -Force
Copy-Item "$SourceDir\agent.yaml" "$InstallDir\config\" -Force

Write-OK "Files installed to $InstallDir"

# ── 5. Set environment variable ──────────────────────────────

Write-Step 5 "Configuring agent..."

# Set CORRELIC_CONFIG so the agent can find agent.yaml.
# Write to both the machine environment AND the service registry key directly.
# Machine env var can fail silently when script is piped via irm | iex,
# so the registry write is the reliable fallback.
$agentConfigPath = "$InstallDir\config\agent.yaml"
$env:CORRELIC_CONFIG = $agentConfigPath
[System.Environment]::SetEnvironmentVariable("CORRELIC_CONFIG", $agentConfigPath, "Machine")

Write-OK "CORRELIC_CONFIG set to $agentConfigPath"

# ── 6. Install Windows Service ───────────────────────────────

Write-Step 6 "Installing Windows Service..."

# Remove stale service if it exists
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
Stop-Service CorrelicAgent -Force 2>$null
& "$InstallDir\bin\correlic-agent.exe" service uninstall 2>$null
Start-Sleep -Seconds 2
$ErrorActionPreference = $prevEAP

& "$InstallDir\bin\correlic-agent.exe" service install
$svcResult = $LASTEXITCODE

if ($svcResult -ne 0) {
    Write-Fail "Service installation failed (exit code $svcResult).`n  Try running manually: & '$InstallDir\bin\correlic-agent.exe' service install"
}

Write-OK "CorrelicAgent service registered (auto-start, restart-on-failure)"

# Write CORRELIC_CONFIG directly into the service registry key.
# This ensures the service always sees it, even if the machine env var was not persisted.
$svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CorrelicAgent"
if (Test-Path $svcRegPath) {
    $existingEnv = (Get-ItemProperty $svcRegPath -Name Environment -ErrorAction SilentlyContinue).Environment
    $newEntry = "CORRELIC_CONFIG=$agentConfigPath"
    if ($existingEnv) {
        $filtered = @($existingEnv | Where-Object { $_ -notmatch '^CORRELIC_CONFIG=' })
        $filtered += $newEntry
        Set-ItemProperty $svcRegPath -Name Environment -Value $filtered -Type MultiString
    } else {
        New-ItemProperty $svcRegPath -Name Environment -Value @($newEntry) -PropertyType MultiString -Force | Out-Null
    }
}

# ── 7. Start service ─────────────────────────────────────────

Write-Step 7 "Starting agent..."

Start-Service CorrelicAgent
Start-Sleep -Seconds 3

$svc = Get-Service CorrelicAgent -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Write-OK "Agent service is running"
} else {
    Write-Warn "Service may still be starting. Check with: Get-Service CorrelicAgent"
}

# ── Done ──────────────────────────────────────────────────────

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "  Correlic Agent installed!" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Dashboard:    " -NoNewline; Write-Host "http://localhost:3001" -ForegroundColor Cyan
Write-Host "  Agent dir:    " -NoNewline; Write-Host "$InstallDir" -ForegroundColor Gray
Write-Host "  Service:      " -NoNewline; Write-Host "CorrelicAgent (auto-starts on boot)" -ForegroundColor Gray
Write-Host ""
Write-Host "  Management commands:" -ForegroundColor Gray
Write-Host "    Stop:       Stop-Service CorrelicAgent" -ForegroundColor Gray
Write-Host "    Start:      Start-Service CorrelicAgent" -ForegroundColor Gray
Write-Host "    Status:     Get-Service CorrelicAgent" -ForegroundColor Gray
Write-Host "    Logs:       Get-Content $InstallDir\logs\agent.log -Tail 50" -ForegroundColor Gray
Write-Host "    Uninstall:  powershell -File $SourceDir\uninstall-agent.ps1" -ForegroundColor Gray
Write-Host ""
Write-Host "  All data stays on this device." -ForegroundColor Green
Write-Host ""
Write-Host "  Note: If you recreate the Docker container, re-run this script" -ForegroundColor Yellow
Write-Host "  to pick up new certificates." -ForegroundColor Yellow
Write-Host ""
