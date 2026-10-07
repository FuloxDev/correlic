# Correlic — Stop All Services
# Usage: powershell C:\Correlic\stop.ps1

$ErrorActionPreference = "SilentlyContinue"
$Dir = $PSScriptRoot
if (-not $Dir) { $Dir = "C:\Correlic" }

Write-Host "Stopping Correlic services..." -ForegroundColor Cyan

# Agent Service
Stop-Service CorrelicAgent 2>$null
Write-Host "  Agent service stopped" -ForegroundColor Gray

# Backend processes
Stop-Process -Name correlic-api -Force 2>$null
Stop-Process -Name correlic-telemetry -Force 2>$null
Write-Host "  Backend stopped" -ForegroundColor Gray

# Neo4j
$neo4jHome = "$Dir\neo4j"
if (Test-Path "$neo4jHome\bin\neo4j.bat") {
    $env:JAVA_HOME = "$Dir\jre"
    $env:NEO4J_HOME = $neo4jHome

    $svc = Get-Service neo4j -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Stop-Service neo4j -Force 2>$null
    } else {
        Get-Process java -ErrorAction SilentlyContinue | Where-Object {
            $_.Path -like "*Correlic*"
        } | Stop-Process -Force 2>$null
    }
    Write-Host "  Neo4j stopped" -ForegroundColor Gray
}

# Node.js processes (UI + proxy)
Get-Process node -ErrorAction SilentlyContinue | Where-Object {
    $_.Path -like "*Correlic*"
} | Stop-Process -Force 2>$null
Write-Host "  Dashboard and proxy stopped" -ForegroundColor Gray

# PostgreSQL
$pgCtl = "$Dir\pgsql\bin\pg_ctl.exe"
if (Test-Path $pgCtl) {
    & $pgCtl stop -D "$Dir\pgsql\data" -m fast 2>$null | Out-Null
    Write-Host "  PostgreSQL stopped" -ForegroundColor Gray
}

Write-Host ""
Write-Host "All services stopped." -ForegroundColor Green
