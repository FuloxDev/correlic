# ============================================================
# Correlic Windows Installer
# Self-hosted security observability — all data stays on your device
# Everything is bundled — zero external dependencies
#
# Usage: irm https://raw.githubusercontent.com/FuloxDev/correlic/main/install/install.ps1 | iex
# ============================================================

$ErrorActionPreference = "Stop"
$Version = "v1.0.1"
$InstallDir = "C:\Correlic"
$BaseURL = if ($env:CORRELIC_BUNDLE_BASE_URL) { $env:CORRELIC_BUNDLE_BASE_URL } else { "https://github.com/FuloxDev/correlic/releases/download/$Version" }
$BundleFile = "correlic-windows-$Version.zip"
$TotalSteps = 10

# Neo4j version (bundled in ZIP alongside PostgreSQL + Node.js)
$Neo4jVersion = "5.26.0"

# ── Helpers ──────────────────────────────────────────────────

function Write-Header {
    Write-Host ""
    Write-Host "================================================" -ForegroundColor Cyan
    Write-Host "  Correlic Installer $Version" -ForegroundColor Cyan
    Write-Host "  Security Observability - Self-Hosted" -ForegroundColor Cyan
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

function Wait-ForPort {
    param(
        [int]$Port,
        [int]$TimeoutSeconds = 15,
        [string]$ServiceName = "service"
    )
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
    param(
        [string]$ProcessName,
        [int]$MinMemoryMB = 5
    )
    $proc = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $proc) { return $false }
    $memMB = [math]::Round($proc.WorkingSet64 / 1MB, 1)
    return ($memMB -ge $MinMemoryMB)
}

# ── 1. Check Administrator ──────────────────────────────────

Write-Header

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Fail "This script must be run as Administrator. Right-click PowerShell and select 'Run as Administrator'."
}

Write-Step 1 "Checking prerequisites..."
Write-OK "Running as Administrator"

# ── 2. Download Bundle ──────────────────────────────────────

Write-Step 2 "Downloading Correlic bundle (~400MB)..."

if (Test-Path $InstallDir) {
    Write-Warn "Existing installation found at $InstallDir"
    Write-Detail "Skipping download — using existing files. Delete C:\Correlic to force fresh install."
    $skipDownload = $true
} else {
    $skipDownload = $false
}

$tempZip = "$env:TEMP\$BundleFile"
$downloadUrl = "$BaseURL/$BundleFile"

if (-not $skipDownload) {
try {
    Write-Host "       Downloading ~400MB " -ForegroundColor Gray -NoNewline

    # Start download in background job
    $job = Start-Job -ScriptBlock {
        param($url, $out)
        $ProgressPreference = 'SilentlyContinue'
        Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
    } -ArgumentList $downloadUrl, $tempZip

    # Show dots while downloading
    $elapsed = 0
    while ($job.State -eq 'Running') {
        Start-Sleep -Seconds 2
        $elapsed += 2
        if (Test-Path $tempZip) {
            $mbSoFar = [math]::Round((Get-Item $tempZip).Length / 1MB)
            Write-Host "`r       Downloading ~400MB ... ${mbSoFar}MB downloaded (${elapsed}s) " -ForegroundColor Gray -NoNewline
        } else {
            Write-Host "." -NoNewline -ForegroundColor Gray
        }
    }
    Write-Host ""

    Receive-Job $job -ErrorAction Stop
    Remove-Job $job

    if (-not (Test-Path $tempZip) -or (Get-Item $tempZip).Length -lt 1000) {
        Write-Fail "Download failed or file is empty"
    }

    $sizeMB = [math]::Round((Get-Item $tempZip).Length / 1MB)
    Write-OK "Downloaded (${sizeMB}MB)"
} catch {
    Write-Fail "Failed to download bundle from $downloadUrl - $_"
}
} else {
    Write-OK "Using existing installation"
}

# ── 3. Extract Bundle ───────────────────────────────────────

Write-Step 3 "Extracting to $InstallDir..."

if ($skipDownload) {
    Write-Detail "Stopping existing services..."
    Stop-Service CorrelicAgent -ErrorAction SilentlyContinue
    Stop-Process -Name correlic-api, correlic-telemetry -ErrorAction SilentlyContinue
    $pgCtl = "$InstallDir\pgsql\bin\pg_ctl.exe"
    if (Test-Path $pgCtl) {
        $prevEAP = $ErrorActionPreference; $ErrorActionPreference = 'SilentlyContinue'
        & $pgCtl stop -D "$InstallDir\pgsql\data" 2>$null
        $ErrorActionPreference = $prevEAP
    }
    Write-OK "Using existing files"
} else {
    Expand-Archive -Path $tempZip -DestinationPath $InstallDir -Force
    Remove-Item $tempZip -ErrorAction SilentlyContinue
    Write-OK "Extracted to $InstallDir"
}

# ── 4. Verify Neo4j + JRE (bundled in ZIP) ─────────────────

Write-Step 4 "Verifying Neo4j graph database..."

$neo4jHome = "$InstallDir\neo4j"
$jreHome = "$InstallDir\jre"

if (-not (Test-Path "$jreHome\bin\java.exe")) {
    Write-Fail "JRE not found in bundle at $jreHome\bin\java.exe — re-download the bundle."
}
Write-OK "Java Runtime found"

if (-not (Test-Path "$neo4jHome\bin\neo4j-admin.bat")) {
    Write-Fail "Neo4j not found in bundle at $neo4jHome — re-download the bundle."
}
Write-OK "Neo4j $Neo4jVersion found"

# ── 5. Generate mTLS Certificates ───────────────────────────

Write-Step 5 "Generating mTLS certificates..."

$certsDir = "$InstallDir\certs"

if (-not (Test-Path "$certsDir\ca.crt")) {
    $openssl = "$InstallDir\pgsql\bin\openssl.exe"
    if (-not (Test-Path $openssl)) {
        $openssl = (Get-Command openssl -ErrorAction SilentlyContinue).Source
    }
    if (-not $openssl) {
        Write-Fail "OpenSSL not found. Cannot generate certificates."
    }

    # Suppress all openssl stderr output (PS 5.1 requires this approach)
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    Write-Detail "Creating CA certificate..."
    & $openssl genrsa -out "$certsDir\ca.key" 4096 2>$null
    & $openssl req -new -x509 -days 3650 -key "$certsDir\ca.key" -out "$certsDir\ca.crt" -subj "/CN=Correlic CA" 2>$null

    Write-Detail "Creating server certificate..."
    & $openssl genrsa -out "$certsDir\server.key" 2048 2>$null
    & $openssl req -new -key "$certsDir\server.key" -out "$certsDir\server.csr" -subj "/CN=correlic-backend" 2>$null

    $extFile = "$certsDir\ext.cnf"
    @"
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,IP:127.0.0.1
"@ | Set-Content $extFile -Encoding ASCII

    & $openssl x509 -req -in "$certsDir\server.csr" -CA "$certsDir\ca.crt" -CAkey "$certsDir\ca.key" -CAcreateserial -out "$certsDir\server.crt" -days 3650 -extfile $extFile 2>$null

    Write-Detail "Creating client certificate..."
    & $openssl genrsa -out "$certsDir\client.key" 2048 2>$null
    & $openssl req -new -key "$certsDir\client.key" -out "$certsDir\client.csr" -subj "/CN=correlic-agent" 2>$null
    & $openssl x509 -req -in "$certsDir\client.csr" -CA "$certsDir\ca.crt" -CAkey "$certsDir\ca.key" -CAcreateserial -out "$certsDir\client.crt" -days 3650 2>$null

    $ErrorActionPreference = $prevEAP

    Remove-Item "$certsDir\*.csr", "$certsDir\*.cnf", "$certsDir\*.srl" -ErrorAction SilentlyContinue

    Write-OK "Certificates generated (CA + server + client)"
} else {
    Write-Detail "Certificates already exist, keeping existing"
}

# ── Detect PostgreSQL port ───────────────────────────────────

$pgPort = 5432
$portInUse = netstat -ano 2>$null | Select-String ":5432\s.*LISTENING"
if ($portInUse) {
    Write-Warn "Port 5432 is already in use. Trying to stop existing PostgreSQL..."
    Stop-Service postgresql* -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $portInUse = netstat -ano 2>$null | Select-String ":5432\s.*LISTENING"
    if ($portInUse) {
        $pgPort = 5433
        Write-Warn "Port 5432 still in use. Will use port $pgPort instead."
    } else {
        Write-OK "Existing PostgreSQL stopped. Using port 5432."
    }
}

# ── Detect Neo4j Bolt port ──────────────────────────────────

$neo4jBoltPort = 7687
$portInUse = netstat -ano 2>$null | Select-String ":7687\s.*LISTENING"
if ($portInUse) {
    Write-Warn "Port 7687 (Neo4j Bolt) is already in use."
    $neo4jBoltPort = 7688
    Write-Warn "Will use port $neo4jBoltPort instead."
} else {
    Write-Detail "Neo4j Bolt port 7687 available"
}

# ── 6. Generate Secrets ─────────────────────────────────────

Write-Step 6 "Generating configuration..."

$dbPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
$neo4jPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
$lmkKey = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })

# Keys are created after the database is initialised: a dashboard admin
# (API key + password) and a separate restricted key for the agent.
$apiKey = ""
$generatedApiKey = ""
$adminPassword = ""

# Use BOM-free UTF-8 for all config files (PS 5.1 -Encoding UTF8 adds BOM)
$utf8NoBom = New-Object System.Text.UTF8Encoding $false
$newInstall = -not (Test-Path "$InstallDir\.env")

if ($newInstall) {
    Write-Detail "Writing agent config..."
    $agentContent = @"
backend_url: "https://localhost:8080"
telemetry_url: "https://localhost:8081"
api_key: ""
profile: "developer"
log_level: "info"
heartbeat_interval: 30s
etw_enabled: true
process_exec_enabled: true
file_monitor_enabled: true
network_monitor_enabled: true
dns_monitor_enabled: true
block_enabled: false
tls_ca_file: $($certsDir -replace '\\','/')/ca.crt
tls_client_cert_file: $($certsDir -replace '\\','/')/client.crt
tls_client_key_file: $($certsDir -replace '\\','/')/client.key
"@
    [System.IO.File]::WriteAllText("$InstallDir\agent.yaml", $agentContent, $utf8NoBom)

    Write-Detail "Writing proxy config..."
    $proxyContent = @"
PORT=8788
BACKEND_API=https://localhost:8080
MTLS_CA=$certsDir\ca.crt
MTLS_CERT=$certsDir\client.crt
MTLS_KEY=$certsDir\client.key
"@
    [System.IO.File]::WriteAllText("$InstallDir\ui-proxy\.env", $proxyContent, $utf8NoBom)

    # NOTE: backend .env is written AFTER org creation (step 7) so the org UUID is available
    Write-OK "Agent and proxy config generated (backend .env deferred until after DB setup)"
} else {
    Write-Detail "Config already exists, keeping existing"
    $apiKey = (Get-Content "$InstallDir\agent.yaml" | Select-String 'api_key: "(.+)"').Matches.Groups[1].Value

    # Ensure Neo4j config exists in .env for existing installs
    $envContent = Get-Content "$InstallDir\.env" -Raw
    if ($envContent -notmatch "NEO4J_URI") {
        $neo4jPassword = -join ((48..57) + (65..90) + (97..122) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
        Add-Content "$InstallDir\.env" "`nNEO4J_URI=bolt://localhost:${neo4jBoltPort}`nNEO4J_USERNAME=neo4j`nNEO4J_PASSWORD=$neo4jPassword"
        Write-Detail "Added Neo4j config to existing .env"
    } else {
        $neo4jPassword = ((Get-Content "$InstallDir\.env" | Select-String "NEO4J_PASSWORD=(.+)").Matches.Groups[1].Value)
    }
}

# ── 7. Initialize Database ──────────────────────────────────

Write-Step 7 "Setting up PostgreSQL..."

$pgBin = "$InstallDir\pgsql\bin"
$pgData = "$InstallDir\pgsql\data"

if (-not (Test-Path "$pgData\PG_VERSION")) {
    Write-Detail "Initializing database cluster..."
    $j = Start-Job { param($b,$d) & "$b\initdb.exe" -D $d -U correlic -A trust -E UTF8 2>&1 } -Arg $pgBin,$pgData
    $null = Wait-Job $j -Timeout 60; Remove-Job $j -Force -ErrorAction SilentlyContinue
    Write-OK "Database cluster initialized"
}

if ($pgPort -ne 5432) {
    $pgConf = "$pgData\postgresql.conf"
    (Get-Content $pgConf) -replace "^#?port\s*=\s*\d+", "port = $pgPort" | Set-Content $pgConf
}

Write-Detail "Starting PostgreSQL on port $pgPort..."
$j = Start-Job { param($b,$d,$l,$p) & "$b\pg_ctl.exe" start -D $d -l $l -o "-p $p" 2>&1 } -Arg $pgBin,$pgData,"$InstallDir\logs\pgsql.log",$pgPort
$null = Wait-Job $j -Timeout 30; Remove-Job $j -Force -ErrorAction SilentlyContinue

$ready = $false
for ($i = 0; $i -lt 15; $i++) {
    Start-Sleep -Seconds 1
    $j = Start-Job { param($b,$p) & "$b\pg_isready.exe" -p $p 2>&1 } -Arg $pgBin,$pgPort
    $null = Wait-Job $j -Timeout 5
    $pgReady = Receive-Job $j 2>$null
    Remove-Job $j -Force -ErrorAction SilentlyContinue
    if ($pgReady -match "accepting") { $ready = $true; break }
    Write-Host "." -NoNewline -ForegroundColor Gray
}
Write-Host ""

if ($ready) {
    Write-OK "PostgreSQL running on port $pgPort"
} else {
    Write-Warn "PostgreSQL failed to start. Log:"
    Get-Content "$InstallDir\logs\pgsql.log" -Tail 5 | ForEach-Object { Write-Detail $_ }
    Write-Fail "Cannot continue without PostgreSQL."
}

Write-Detail "Creating database..."
$j = Start-Job { param($b,$p) & "$b\createdb.exe" -U correlic -p $p correlic 2>&1 } -Arg $pgBin,$pgPort
$null = Wait-Job $j -Timeout 15; Remove-Job $j -Force -ErrorAction SilentlyContinue
Write-OK "Database created"

Write-Detail "Running migrations..."
Set-Location $InstallDir
$connStr = "postgres://correlic:@localhost:${pgPort}/correlic"
$j = Start-Job { param($d,$c) $env:DATABASE_URL=$c; & "$d\bin\correlic-admin.exe" migrate up 2>&1 } -Arg $InstallDir,$connStr
$null = Wait-Job $j -Timeout 60
$migOut = Receive-Job $j 2>$null
Remove-Job $j -Force -ErrorAction SilentlyContinue
if ($migOut -match "error|fatal") { Write-Warn "Migration: $migOut" } else { Write-OK "Migrations complete" }

Write-Detail "Verifying database schema..."
$j = Start-Job { param($b,$p) & "$b\psql.exe" -U correlic -p $p -d correlic -t -A -c "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'" 2>&1 } -Arg $pgBin,$pgPort
$null = Wait-Job $j -Timeout 10
$tableCount = ((Receive-Job $j 2>$null) -replace '\s','')
Remove-Job $j -Force -ErrorAction SilentlyContinue
if ($tableCount -match '^\d+$' -and [int]$tableCount -gt 0) {
    Write-OK "Database verified ($tableCount tables)"
} else {
    Write-Warn "Could not verify database tables — migrations may not have applied"
}

Write-Detail "Creating default organization..."
$j = Start-Job { param($d,$c) $env:DATABASE_URL=$c; & "$d\bin\correlic-admin.exe" create-org --name default 2>&1 } -Arg $InstallDir,$connStr
$null = Wait-Job $j -Timeout 15
$orgOut = Receive-Job $j 2>$null
Remove-Job $j -Force -ErrorAction SilentlyContinue

# Extract org UUID from output (format: org_id=<uuid>)
$orgUUID = ""
if ($orgOut -match "org_id=([0-9a-f-]+)") {
    $orgUUID = $Matches[1]
    Write-OK "Default organization created (id: $orgUUID)"
} else {
    # Org may already exist — query from DB directly
    $j = Start-Job { param($b,$p) & "$b\psql.exe" -U correlic -p $p -d correlic -t -A -c "SELECT id FROM organizations LIMIT 1" 2>&1 } -Arg $pgBin,$pgPort
    $null = Wait-Job $j -Timeout 10
    $dbUUID = (Receive-Job $j 2>$null) | Select-String "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"
    Remove-Job $j -Force -ErrorAction SilentlyContinue
    if ($dbUUID) {
        $orgUUID = $dbUUID.Matches[0].Groups[1].Value
    }
    Write-OK "Default organization ready (id: $orgUUID)"
}

if ($orgUUID -eq "") {
    Write-Fail "Failed to create or find organization. Cannot continue."
}

# Enroll the mTLS client certificate so the proxy and agent can authenticate
if (Test-Path "$certsDir\client.crt") {
    $j = Start-Job { param($d,$c,$o,$cert) $env:DATABASE_URL=$c; & "$d\bin\correlic-admin.exe" enroll-client-cert --org-id $o --name agent-cert --cert-file $cert 2>&1 } -Arg $InstallDir,$connStr,$orgUUID,"$certsDir\client.crt"
    $null = Wait-Job $j -Timeout 15
    $enrollOut = Receive-Job $j 2>$null
    Remove-Job $j -Force -ErrorAction SilentlyContinue
    if ("$enrollOut" -match "enrolled=true|already") { Write-OK "Client certificate enrolled" } else { Write-Warn "Client certificate enrollment: $enrollOut" }
}

# Create the dashboard admin (API key + password) and a restricted agent key
if ($newInstall) {
    Write-Detail "Creating dashboard admin and agent key..."
    $j = Start-Job { param($d,$c,$o) $env:DATABASE_URL=$c; & "$d\bin\correlic-admin.exe" create-user --org-id $o --email admin@local.dev --name "Admin" --role admin 2>&1 } -Arg $InstallDir,$connStr,$orgUUID
    $null = Wait-Job $j -Timeout 15
    $adminOut = Receive-Job $j 2>$null
    Remove-Job $j -Force -ErrorAction SilentlyContinue
    $adminUserId = ""
    if ("$adminOut" -match "user_id=([0-9a-f-]+)") { $adminUserId = $Matches[1] }
    if ("$adminOut" -match "password=(\S+)") { $adminPassword = $Matches[1] }
    if ($adminUserId -ne "") {
        $j = Start-Job { param($d,$c,$o,$u) $env:DATABASE_URL=$c; & "$d\bin\correlic-admin.exe" create-api-key --org-id $o --user-id $u --name dashboard 2>&1 } -Arg $InstallDir,$connStr,$orgUUID,$adminUserId
        $null = Wait-Job $j -Timeout 15
        $keyOut = Receive-Job $j 2>$null
        Remove-Job $j -Force -ErrorAction SilentlyContinue
        if ("$keyOut" -match "api_key=([0-9a-f]+)") { $generatedApiKey = $Matches[1] }
    }
    $j = Start-Job { param($d,$c,$o) $env:DATABASE_URL=$c; & "$d\bin\correlic-admin.exe" create-service-account --org-id $o --email agent@local.dev --name "Agent" --role member 2>&1 } -Arg $InstallDir,$connStr,$orgUUID
    $null = Wait-Job $j -Timeout 15
    $saOut = Receive-Job $j 2>$null
    Remove-Job $j -Force -ErrorAction SilentlyContinue
    $saUserId = ""
    if ("$saOut" -match "user_id=([0-9a-f-]+)") { $saUserId = $Matches[1] }
    if ($saUserId -ne "") {
        $j = Start-Job { param($d,$c,$o,$u) $env:DATABASE_URL=$c; & "$d\bin\correlic-admin.exe" create-api-key --org-id $o --user-id $u --name agent --type agent 2>&1 } -Arg $InstallDir,$connStr,$orgUUID,$saUserId
        $null = Wait-Job $j -Timeout 15
        $akeyOut = Receive-Job $j 2>$null
        Remove-Job $j -Force -ErrorAction SilentlyContinue
        if ("$akeyOut" -match "api_key=([0-9a-f]+)") { $apiKey = $Matches[1] }
    }
    if ($apiKey -ne "") {
        $agentYamlPath = "$InstallDir\agent.yaml"
        if (Test-Path $agentYamlPath) {
            $yaml = Get-Content $agentYamlPath -Raw
            $yaml = $yaml -replace 'api_key: ".*"', "api_key: `"$apiKey`""
            [System.IO.File]::WriteAllText($agentYamlPath, $yaml, $utf8NoBom)
        }
        Write-OK "Agent key created and written to agent.yaml"
    } else {
        Write-Warn "Could not create the agent key: $saOut $akeyOut"
        Write-Detail "Create one later: correlic-admin create-api-key --org-id $orgUUID --user-id <user_id> --name agent --type agent"
    }
    if ($generatedApiKey -ne "") {
        $creds = "# Correlic dashboard credentials (generated by the installer). Keep this file private.`r`nDASHBOARD_URL=http://localhost:3001`r`nAPI_KEY=$generatedApiKey`r`nADMIN_EMAIL=admin@local.dev`r`nADMIN_PASSWORD=$adminPassword`r`n"
        [System.IO.File]::WriteAllText("$InstallDir\dashboard-credentials.txt", $creds, $utf8NoBom)
        Write-OK "Dashboard admin created (credentials shown at the end of the install)"
    } else {
        Write-Warn "Could not create the dashboard admin: $adminOut $keyOut"
    }
}

# Write backend .env NOW with the actual org UUID (not "default")
if ($newInstall) {
    Write-Detail "Writing backend config with org ID..."
    $envContent = @"
DATABASE_URL=postgres://correlic:$dbPassword@localhost:${pgPort}/correlic
NEO4J_URI=bolt://localhost:${neo4jBoltPort}
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=$neo4jPassword
TLS_CERT_FILE=$certsDir\server.crt
TLS_KEY_FILE=$certsDir\server.key
MTLS_CA_FILE=$certsDir\ca.crt
LLM_ENCRYPTION_KEY=$lmkKey
ALLOW_API_KEY_AUTH=true
SAMPLING_ENABLED=true
DEFAULT_ORG_ID=$orgUUID
"@
    [System.IO.File]::WriteAllText("$InstallDir\.env", $envContent, $utf8NoBom)
    Write-OK "Backend config written"
}

# Store connection string for later
$env:DATABASE_URL = $connStr

Write-OK "Database ready"

# ── 8. Initialize Neo4j ────────────────────────────────────

Write-Step 8 "Setting up Neo4j graph database..."

$neo4jHome = "$InstallDir\neo4j"
$jreHome = "$InstallDir\jre"
$env:JAVA_HOME = $jreHome
$env:NEO4J_HOME = $neo4jHome

# Write neo4j.conf (localhost-only, HTTP disabled, tuned for self-hosted)
if (-not (Test-Path "$neo4jHome\conf\neo4j.conf.bak")) {
    if (Test-Path "$neo4jHome\conf\neo4j.conf") {
        Copy-Item "$neo4jHome\conf\neo4j.conf" "$neo4jHome\conf\neo4j.conf.bak"
    }
    # Write BOM-free UTF-8 (PS 5.1 -Encoding UTF8 adds BOM which Neo4j rejects)
    $neo4jConf = @"
# Correlic Neo4j Configuration - auto-generated
server.default_listen_address=127.0.0.1
server.bolt.enabled=true
server.bolt.listen_address=:${neo4jBoltPort}
server.bolt.advertised_address=localhost:${neo4jBoltPort}
server.http.enabled=false
server.https.enabled=false
server.memory.heap.initial_size=512m
server.memory.heap.max_size=1g
server.memory.pagecache.size=512m
db.transaction.timeout=30s
server.directories.logs=logs
dbms.usage_report.enabled=false
"@
    [System.IO.File]::WriteAllText("$neo4jHome\conf\neo4j.conf", $neo4jConf, (New-Object System.Text.UTF8Encoding $false))
    Write-OK "Neo4j configuration written"
}

# Set initial password (must be done before first start)
if (-not (Test-Path "$neo4jHome\data\dbms\auth.ini")) {
    Write-Detail "Setting Neo4j initial password..."
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    & "$neo4jHome\bin\neo4j-admin.bat" dbms set-initial-password $neo4jPassword 2>$null
    $ErrorActionPreference = $prevEAP
    Write-OK "Neo4j password configured"
} else {
    Write-Detail "Neo4j auth already configured"
}

# Install Neo4j as Windows service
$neo4jSvc = Get-Service neo4j -ErrorAction SilentlyContinue
if (-not $neo4jSvc) {
    Write-Detail "Installing Neo4j Windows service..."
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    & "$neo4jHome\bin\neo4j.bat" windows-service install 2>$null
    $ErrorActionPreference = $prevEAP
    Write-OK "Neo4j service installed"
} else {
    Write-Detail "Neo4j service already registered"
}

# Start Neo4j and wait for readiness
Write-Detail "Starting Neo4j..."
Start-Service neo4j -ErrorAction SilentlyContinue
$neo4jPortOK = Wait-ForPort -Port $neo4jBoltPort -TimeoutSeconds 30 -ServiceName "Neo4j"

if ($neo4jPortOK) {
    # Verify Bolt protocol is actually responding (not just port open)
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient("localhost", $neo4jBoltPort)
        $stream = $tcp.GetStream()
        $stream.ReadTimeout = 3000
        $magic = [byte[]](0x60, 0x60, 0xB0, 0x17, 0x00, 0x00, 0x04, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
        $stream.Write($magic, 0, $magic.Length)
        $buf = New-Object byte[] 4
        $read = $stream.Read($buf, 0, 4)
        $tcp.Close()
        if ($read -gt 0) {
            Write-OK "Neo4j Bolt protocol verified on :$neo4jBoltPort"
        } else {
            Write-Warn "Neo4j port open but Bolt handshake returned empty"
        }
    } catch {
        Write-Warn "Neo4j port open but Bolt handshake failed"
        Write-Detail "Backend will retry connection on startup"
    }
} else {
    Write-Warn "Neo4j did not start within 30s. Check logs at $neo4jHome\logs\"
    Write-Detail "Backend will retry connection on startup"
}

# ── 9. Install Agent Service ────────────────────────────────

Write-Step 9 "Installing agent as Windows Service..."

# Set CORRELIC_CONFIG so the agent can find agent.yaml.
# Write to both the machine environment AND the service registry key directly.
# Machine env var can fail silently when script is piped via irm | iex,
# so the registry write is the reliable fallback.
$agentConfigPath = "$InstallDir\agent.yaml"
$env:CORRELIC_CONFIG = $agentConfigPath
[System.Environment]::SetEnvironmentVariable("CORRELIC_CONFIG", $agentConfigPath, "Machine")

# Remove stale service if it exists from a previous install
$prevEAP = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
Stop-Service CorrelicAgent -Force 2>$null
& "$InstallDir\bin\correlic-agent.exe" service uninstall 2>$null
Start-Sleep -Seconds 2
& "$InstallDir\bin\correlic-agent.exe" service install 2>$null
$svcResult = $LASTEXITCODE
$ErrorActionPreference = $prevEAP

# Write CORRELIC_CONFIG directly into the service registry key.
# This ensures the service always sees it, even if the machine env var was not persisted.
$svcRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CorrelicAgent"
if (Test-Path $svcRegPath) {
    $existingEnv = (Get-ItemProperty $svcRegPath -Name Environment -ErrorAction SilentlyContinue).Environment
    $newEntry = "CORRELIC_CONFIG=$agentConfigPath"
    if ($existingEnv) {
        # Filter out any old CORRELIC_CONFIG entries, then add the new one
        $filtered = @($existingEnv | Where-Object { $_ -notmatch '^CORRELIC_CONFIG=' })
        $filtered += $newEntry
        Set-ItemProperty $svcRegPath -Name Environment -Value $filtered -Type MultiString
    } else {
        New-ItemProperty $svcRegPath -Name Environment -Value @($newEntry) -PropertyType MultiString -Force | Out-Null
    }
}

if ($svcResult -eq 0) {
    # NOTE: Agent service is started AFTER backend services (step 10) so it can load AI patterns
    Write-OK "Agent service installed (will start after backend services)"
} else {
    Write-Warn "Agent service install failed (exit code $svcResult). You can install manually:"
    Write-Detail "Run as Admin: & '$InstallDir\bin\correlic-agent.exe' service install"
}

# ── 10. Start All Services (with health checks) ──────────────

Write-Step 10 "Starting services..."

$nodePath = "$InstallDir\node\node.exe"
$nodePathCmd = $nodePath -replace '\\', '/'
$health = @{}

# ── 10a. Backend API ──

# Create .cmd launcher for Backend API (loads .env before starting)
@"
@echo off
cd /d "$InstallDir"
for /f "usebackq tokens=1,2 delims==" %%A in ("$InstallDir\.env") do (
    if not "%%A"=="" if not "%%A"=="#" set "%%A=%%B"
)
"$InstallDir\bin\correlic-api.exe" 2>>"$InstallDir\logs\api-error.log"
"@ | Set-Content "$InstallDir\bin\start-api.cmd" -Encoding ASCII

Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$InstallDir\bin\start-api.cmd`"" -WindowStyle Hidden
Write-Detail "Starting Backend API..."

$apiPortOK = Wait-ForPort -Port 8080 -TimeoutSeconds 15 -ServiceName "Backend API"
$apiProcOK = Test-ProcessHealth -ProcessName "correlic-api"
$health["Backend API"] = ($apiPortOK -and $apiProcOK)

if ($apiPortOK -and $apiProcOK) {
    Write-OK "Backend API healthy on :8080"
} elseif (-not $apiProcOK) {
    Write-Warn "Backend API process not healthy — may be blocked by antivirus"
    Write-Detail "Add $InstallDir\bin\correlic-api.exe to antivirus exclusions"
    if (Test-Path "$InstallDir\logs\api-error.log") {
        Write-Detail "Last log entries:"
        Get-Content "$InstallDir\logs\api-error.log" -Tail 3 | ForEach-Object { Write-Detail $_ }
    }
} else {
    Write-Warn "Backend API not responding on :8080"
    Write-Detail "Check $InstallDir\logs\api-error.log"
}

# ── 10b. Telemetry ──

# Create .cmd launcher for Backend Telemetry
@"
@echo off
cd /d "$InstallDir"
for /f "usebackq tokens=1,2 delims==" %%A in ("$InstallDir\.env") do (
    if not "%%A"=="" if not "%%A"=="#" set "%%A=%%B"
)
"$InstallDir\bin\correlic-telemetry.exe" 2>>"$InstallDir\logs\telemetry-error.log"
"@ | Set-Content "$InstallDir\bin\start-telemetry.cmd" -Encoding ASCII

Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$InstallDir\bin\start-telemetry.cmd`"" -WindowStyle Hidden
Write-Detail "Starting Telemetry..."

$telPortOK = Wait-ForPort -Port 8081 -TimeoutSeconds 15 -ServiceName "Telemetry"
$telProcOK = Test-ProcessHealth -ProcessName "correlic-telemetry"
$health["Telemetry"] = ($telPortOK -and $telProcOK)

if ($telPortOK -and $telProcOK) {
    Write-OK "Telemetry healthy on :8081"
} elseif (-not $telProcOK) {
    Write-Warn "Telemetry process not healthy — may be blocked by antivirus"
    Write-Detail "Add $InstallDir\bin\correlic-telemetry.exe to antivirus exclusions"
    Write-Detail "Then restart: powershell $InstallDir\start.ps1"
    if (Test-Path "$InstallDir\logs\telemetry-error.log") {
        $telLog = Get-Content "$InstallDir\logs\telemetry-error.log" -Tail 3 -ErrorAction SilentlyContinue
        if ($telLog) { $telLog | ForEach-Object { Write-Detail $_ } }
    }
} else {
    Write-Warn "Telemetry not responding on :8081"
    Write-Detail "Check $InstallDir\logs\telemetry-error.log"
}

# ── 10c. Dashboard ──

if (Test-Path "$InstallDir\ui\server.js") {
    # Create .cmd launcher for UI
    @"
@echo off
set NODE_ENV=production
set HOSTNAME=127.0.0.1
set PROXY_BASE_URL=http://localhost:8788
set PORT=3001
"$nodePathCmd" server.js
"@ | Set-Content "$InstallDir\ui\start-ui.cmd" -Encoding ASCII

    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$InstallDir\ui\start-ui.cmd`"" -WorkingDirectory "$InstallDir\ui" -WindowStyle Hidden
    Write-Detail "Starting Dashboard..."

    $uiPortOK = Wait-ForPort -Port 3001 -TimeoutSeconds 10 -ServiceName "Dashboard"
    $health["Dashboard"] = $uiPortOK

    if ($uiPortOK) {
        Write-OK "Dashboard healthy on :3001"
    } else {
        Write-Warn "Dashboard not responding on :3001"
    }
}

# ── 10d. UI-Proxy ──

if (Test-Path "$InstallDir\ui-proxy\index.js") {
    # Create .cmd launcher for UI-Proxy (loads .env from ui-proxy dir)
    @"
@echo off
cd /d "$InstallDir\ui-proxy"
if exist ".env" (
    for /f "usebackq tokens=1,2 delims==" %%A in (".env") do (
        if not "%%A"=="" if not "%%A"=="#" set "%%A=%%B"
    )
)
"$nodePathCmd" index.js
"@ | Set-Content "$InstallDir\ui-proxy\start-proxy.cmd" -Encoding ASCII

    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$InstallDir\ui-proxy\start-proxy.cmd`"" -WindowStyle Hidden
    Write-Detail "Starting Proxy..."

    $proxyPortOK = Wait-ForPort -Port 8788 -TimeoutSeconds 10 -ServiceName "Proxy"
    $health["Proxy"] = $proxyPortOK

    if ($proxyPortOK) {
        Write-OK "Proxy healthy on :8788"
    } else {
        Write-Warn "Proxy not responding on :8788"
    }
}

# ── 10e. Agent Service ──

if (-not $health["Telemetry"]) {
    Write-Warn "Skipping agent start — telemetry is not healthy"
    Write-Detail "The agent needs telemetry on :8081 to send events and sync block rules"
    Write-Detail "Fix telemetry first, then run: Start-Service CorrelicAgent"
    $health["Agent"] = $false
} else {
    Write-Detail "Starting Agent service..."
    Start-Service CorrelicAgent -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3

    $agentSvc = Get-Service CorrelicAgent -ErrorAction SilentlyContinue
    $agentRunning = $agentSvc -and $agentSvc.Status -eq 'Running'

    if ($agentRunning) {
        # Wait for agent to confirm telemetry connection via block rule sync
        $agentLogPath = "$InstallDir\logs\agent.log"
        $syncOK = $false
        for ($i = 0; $i -lt 12; $i++) {
            Start-Sleep -Seconds 1
            if (Test-Path $agentLogPath) {
                $logTail = Get-Content $agentLogPath -Tail 30 -ErrorAction SilentlyContinue
                if ($logTail -match "block rules updated|block rules synced") {
                    $syncOK = $true
                    break
                }
                if ($logTail -match "live ingestion enabled") {
                    $syncOK = $true
                    break
                }
            }
            Write-Host "." -NoNewline -ForegroundColor Gray
        }
        Write-Host ""

        if ($syncOK) {
            Write-OK "Agent service running, connected to backend"
        } else {
            Write-Warn "Agent running but backend connection not confirmed within 12s"
            Write-Detail "This may resolve itself — check: Get-Content $agentLogPath -Tail 20"
        }
        $health["Agent"] = $agentRunning
    } else {
        Write-Warn "Agent service failed to start"
        Write-Detail "Check: Get-Service CorrelicAgent | Format-List *"
        Write-Detail "Manual start: Start-Service CorrelicAgent"
        $health["Agent"] = $false
    }
}

# ── Health Summary ──────────────────────────────────────────

Write-Host ""
Write-Host "  Service Health Check" -ForegroundColor Cyan
Write-Host ("  " + ("-" * 38)) -ForegroundColor Cyan
foreach ($svc in @("Backend API", "Telemetry", "Dashboard", "Proxy", "Agent")) {
    if ($health.ContainsKey($svc)) {
        $ok = $health[$svc]
        $icon = $(if ($ok) { "[OK]" } else { "[!!]" })
        $color = $(if ($ok) { "Green" } else { "Yellow" })
        Write-Host "  $icon " -ForegroundColor $color -NoNewline
        Write-Host $svc
    }
}

$failCount = ($health.Values | Where-Object { -not $_ }).Count

Write-Host ""
if ($failCount -eq 0) {
    Write-Host "================================================" -ForegroundColor Green
    Write-Host "  Correlic is running!" -ForegroundColor Green
    Write-Host "================================================" -ForegroundColor Green
} else {
    Write-Host "================================================" -ForegroundColor Yellow
    Write-Host "  Correlic started with $failCount warning(s)" -ForegroundColor Yellow
    Write-Host "================================================" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Review the warnings above and check logs:" -ForegroundColor Yellow
    Write-Host "    $InstallDir\logs\" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  Common fixes:" -ForegroundColor White
    Write-Host "    - Add $InstallDir\bin\*.exe to antivirus exclusions" -ForegroundColor Gray
    Write-Host "    - Restart: powershell $InstallDir\start.ps1" -ForegroundColor Gray
}
Write-Host ""
Write-Host "  Dashboard:    " -NoNewline; Write-Host "http://localhost:3001" -ForegroundColor Cyan
if ($generatedApiKey -ne "") {
    Write-Host "  Log in with:  " -NoNewline; Write-Host $generatedApiKey -ForegroundColor Cyan; Write-Host "  (API key)" -ForegroundColor Gray
    Write-Host "           or:  " -NoNewline; Write-Host "admin@local.dev / $adminPassword" -ForegroundColor Cyan
    Write-Host "                (stored in $InstallDir\dashboard-credentials.txt)" -ForegroundColor Gray
}
Write-Host "  Neo4j:        " -NoNewline; Write-Host "bolt://localhost:$neo4jBoltPort" -ForegroundColor Gray
Write-Host "  Install dir:  $InstallDir"
Write-Host "  Logs:         $InstallDir\logs"
Write-Host ""
Write-Host "  Commands:" -ForegroundColor White
Write-Host "    Start:     " -NoNewline; Write-Host "powershell $InstallDir\start.ps1" -ForegroundColor Gray
Write-Host "    Stop:      " -NoNewline; Write-Host "powershell $InstallDir\stop.ps1" -ForegroundColor Gray
Write-Host "    Uninstall: " -NoNewline; Write-Host "powershell $InstallDir\uninstall.ps1" -ForegroundColor Gray
Write-Host ""
Write-Host "  The dashboard listens on localhost only." -ForegroundColor Gray
Write-Host "  All data stays on this device. Nothing is sent externally." -ForegroundColor Green
Write-Host ""
