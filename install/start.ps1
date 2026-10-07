# Correlic — Start All Services (with health checks)
# Usage: powershell C:\Correlic\start.ps1

$ErrorActionPreference = "Stop"
$Dir = $PSScriptRoot
if (-not $Dir) { $Dir = "C:\Correlic" }

function Wait-ForPort {
    param([int]$Port, [int]$TimeoutSeconds = 10)
    for ($i = 0; $i -lt $TimeoutSeconds; $i++) {
        Start-Sleep -Seconds 1
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect("localhost", $Port)
            $tcp.Close()
            return $true
        } catch {
            Write-Host "." -NoNewline -ForegroundColor Gray
        }
    }
    Write-Host ""
    return $false
}

function Test-ProcessHealth {
    param([string]$ProcessName, [int]$MinMemoryMB = 5)
    $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) { return $false }
    return ([math]::Round($proc.WorkingSet64 / 1MB, 1) -ge $MinMemoryMB)
}

Write-Host ""
Write-Host "Starting Correlic services..." -ForegroundColor Cyan
Write-Host ""

$health = @{}

# 1. PostgreSQL
$pgCtl = "$Dir\pgsql\bin\pg_ctl.exe"
$pgBin = "$Dir\pgsql\bin"
if (Test-Path $pgCtl) {
    $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
    & $pgCtl start -D "$Dir\pgsql\data" -l "$Dir\logs\pgsql.log" -w 2>$null | Out-Null
    $ErrorActionPreference = $prevEAP

    $pgReady = $false
    for ($i = 0; $i -lt 10; $i++) {
        Start-Sleep -Seconds 1
        $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
        $r = & "$pgBin\pg_isready.exe" 2>$null
        $ErrorActionPreference = $prevEAP
        if ($r -match "accepting") { $pgReady = $true; break }
    }
    if ($pgReady) {
        Write-Host "  [OK] " -ForegroundColor Green -NoNewline; Write-Host "PostgreSQL ready"
    } else {
        Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "PostgreSQL not responding"
    }
    $health["PostgreSQL"] = $pgReady
}

# 2. Neo4j
$neo4jHome = "$Dir\neo4j"
if (Test-Path "$neo4jHome\bin\neo4j.bat") {
    $env:JAVA_HOME = "$Dir\jre"
    $env:NEO4J_HOME = $neo4jHome

    $svc = Get-Service neo4j -ErrorAction SilentlyContinue
    if ($svc) {
        Start-Service neo4j -ErrorAction SilentlyContinue
    } else {
        Start-Process -FilePath "$neo4jHome\bin\neo4j.bat" -ArgumentList "console" -WindowStyle Hidden
    }

    $neo4jOK = Wait-ForPort -Port 7687 -TimeoutSeconds 20
    if ($neo4jOK) {
        Write-Host "  [OK] " -ForegroundColor Green -NoNewline; Write-Host "Neo4j ready on :7687"
    } else {
        Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "Neo4j not responding on :7687"
    }
    $health["Neo4j"] = $neo4jOK
}

Start-Sleep -Seconds 2

# 3. Backend API
if (Test-Path "$Dir\bin\start-api.cmd") {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$Dir\bin\start-api.cmd`"" -WindowStyle Hidden
} else {
    Start-Process -FilePath "$Dir\bin\correlic-api.exe" -WorkingDirectory $Dir -WindowStyle Hidden
}

$apiPortOK = Wait-ForPort -Port 8080 -TimeoutSeconds 15
$apiProcOK = Test-ProcessHealth -ProcessName "correlic-api"
$health["Backend API"] = ($apiPortOK -and $apiProcOK)

if ($apiPortOK -and $apiProcOK) {
    Write-Host "  [OK] " -ForegroundColor Green -NoNewline; Write-Host "Backend API healthy on :8080"
} elseif (-not $apiProcOK) {
    Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "Backend API process not healthy — check antivirus"
} else {
    Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "Backend API not responding on :8080"
}

# 4. Telemetry
if (Test-Path "$Dir\bin\start-telemetry.cmd") {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$Dir\bin\start-telemetry.cmd`"" -WindowStyle Hidden
} else {
    Start-Process -FilePath "$Dir\bin\correlic-telemetry.exe" -WorkingDirectory $Dir -WindowStyle Hidden
}

$telPortOK = Wait-ForPort -Port 8081 -TimeoutSeconds 15
$telProcOK = Test-ProcessHealth -ProcessName "correlic-telemetry"
$health["Telemetry"] = ($telPortOK -and $telProcOK)

if ($telPortOK -and $telProcOK) {
    Write-Host "  [OK] " -ForegroundColor Green -NoNewline; Write-Host "Telemetry healthy on :8081"
} elseif (-not $telProcOK) {
    Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "Telemetry process not healthy — check antivirus"
    Write-Host "       Add $Dir\bin\correlic-telemetry.exe to antivirus exclusions" -ForegroundColor Gray
} else {
    Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "Telemetry not responding on :8081"
}

# 5. Dashboard
if (Test-Path "$Dir\ui\start-ui.cmd") {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$Dir\ui\start-ui.cmd`"" -WorkingDirectory "$Dir\ui" -WindowStyle Hidden
} elseif (Test-Path "$Dir\ui\server.js") {
    $nodePath = "$Dir\node\node.exe"
    Start-Process -FilePath $nodePath -ArgumentList "server.js" -WorkingDirectory "$Dir\ui" -WindowStyle Hidden
}

$uiOK = Wait-ForPort -Port 3001 -TimeoutSeconds 10
$health["Dashboard"] = $uiOK

if ($uiOK) {
    Write-Host "  [OK] " -ForegroundColor Green -NoNewline; Write-Host "Dashboard healthy on :3001"
} else {
    Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "Dashboard not responding on :3001"
}

# 6. UI-Proxy
if (Test-Path "$Dir\ui-proxy\start-proxy.cmd") {
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$Dir\ui-proxy\start-proxy.cmd`"" -WindowStyle Hidden
} elseif (Test-Path "$Dir\ui-proxy\index.js") {
    $nodePath = "$Dir\node\node.exe"
    Start-Process -FilePath $nodePath -ArgumentList "index.js" -WorkingDirectory "$Dir\ui-proxy" -WindowStyle Hidden
}

$proxyOK = Wait-ForPort -Port 8788 -TimeoutSeconds 10
$health["Proxy"] = $proxyOK

if ($proxyOK) {
    Write-Host "  [OK] " -ForegroundColor Green -NoNewline; Write-Host "Proxy healthy on :8788"
} else {
    Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "Proxy not responding on :8788"
}

# 7. Agent Service (only if telemetry is healthy)
if (-not $health["Telemetry"]) {
    Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "Skipping agent — telemetry not healthy"
    Write-Host "       Fix telemetry first, then: Start-Service CorrelicAgent" -ForegroundColor Gray
    $health["Agent"] = $false
} else {
    Start-Service CorrelicAgent -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $agentSvc = Get-Service CorrelicAgent -ErrorAction SilentlyContinue
    $agentRunning = $agentSvc -and $agentSvc.Status -eq 'Running'

    if ($agentRunning) {
        # Check agent.log for backend connection confirmation
        $agentLogPath = "$Dir\logs\agent.log"
        $connected = $false
        for ($i = 0; $i -lt 10; $i++) {
            Start-Sleep -Seconds 1
            if (Test-Path $agentLogPath) {
                $logTail = Get-Content $agentLogPath -Tail 30 -ErrorAction SilentlyContinue
                if ($logTail -match "block rules updated|live ingestion enabled") {
                    $connected = $true
                    break
                }
            }
            Write-Host "." -NoNewline -ForegroundColor Gray
        }
        Write-Host ""

        if ($connected) {
            Write-Host "  [OK] " -ForegroundColor Green -NoNewline; Write-Host "Agent running, connected to backend"
        } else {
            Write-Host "  [OK] " -ForegroundColor Green -NoNewline; Write-Host "Agent running (backend sync may take a moment)"
        }
        $health["Agent"] = $true
    } else {
        Write-Host "  [!]  " -ForegroundColor Yellow -NoNewline; Write-Host "Agent service failed to start"
        Write-Host "       Check: Get-Service CorrelicAgent | Format-List *" -ForegroundColor Gray
        $health["Agent"] = $false
    }
}

# ── Health Summary ──

$failCount = ($health.Values | Where-Object { -not $_ }).Count

Write-Host ""
if ($failCount -eq 0) {
    Write-Host "Correlic is running! Dashboard: http://localhost:3001" -ForegroundColor Green
} else {
    Write-Host "Correlic started with $failCount warning(s). Dashboard: http://localhost:3001" -ForegroundColor Yellow
    Write-Host "Check logs: $Dir\logs\" -ForegroundColor Gray
}
Write-Host ""
