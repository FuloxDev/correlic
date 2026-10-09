#!/bin/bash
set -euo pipefail
# ============================================================
# Correlic Linux Installer — Standalone Binary Edition
# Self-hosted security observability — all data stays on your device
#
# Usage: curl -sSL https://raw.githubusercontent.com/FuloxDev/correlic/main/install/install.sh | sudo bash
#
# Options (pass them after `bash -s --`, e.g. `| sudo bash -s -- --without-neo4j`):
#   --without-neo4j   PostgreSQL-only profile: skips the Java and Neo4j steps and
#                     leaves NEO4J_* out of /opt/correlic/.env and the systemd units.
#                     Everything except the two graph look-back rules
#                     (ai.data_exfiltration, ai.excessive_writes) and the Neo4j
#                     timeline works on PostgreSQL alone.
#   --with-neo4j      Install the graph (the default on a fresh install; an
#                     upgrade keeps whatever profile the existing .env has).
# Environment:
#   CORRELIC_NEO4J=no|yes   Same as the flags, for `curl | sudo -E bash`.
# ============================================================

VERSION="1.0.1"
INSTALL_DIR="/opt/correlic"
# Target architecture. The amd64 bundle keeps its historical name
# (correlic-linux-v<version>.tar.gz); other architectures carry a suffix
# (correlic-linux-v<version>-arm64.tar.gz). Unsupported machines fail in step 1.
MACHINE=$(uname -m)
case "$MACHINE" in
  x86_64)        ARCH="amd64"; BUNDLE_SUFFIX="" ;;
  aarch64|arm64) ARCH="arm64"; BUNDLE_SUFFIX="-arm64" ;;
  *)             ARCH="";      BUNDLE_SUFFIX="" ;;
esac
BUNDLE_URL="${CORRELIC_BUNDLE_URL:-https://github.com/FuloxDev/correlic/releases/download/v${VERSION}/correlic-linux-v${VERSION}${BUNDLE_SUFFIX}.tar.gz}"
TOTAL_STEPS=10
CURRENT_STEP=0
TEMP_FILE=""
BACKUP_DIR=""
IS_UPGRADE=false
GENERATED_API_KEY=""

# ── Default service ports (may be reassigned if conflicts detected) ──
API_PORT=8080
TELEMETRY_PORT=8081
UI_PORT=3001
PROXY_PORT=8788

# ── Colors ───────────────────────────────────────────────────

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Output helpers ───────────────────────────────────────────

log()  { echo -e "${CYAN}[correlic]${NC} $1"; }
ok()   { echo -e "${GREEN}  [OK]${NC} $1"; }
warn() { echo -e "${YELLOW}  [!]${NC} $1"; }
detail() { echo -e "${DIM}       $1${NC}"; }

fail() {
  echo ""
  echo -e "${RED}  [ERROR]${NC} $1"
  echo ""
  if [ "$CURRENT_STEP" -gt 0 ]; then
    echo -e "  Installation failed at step $CURRENT_STEP/$TOTAL_STEPS."
    echo -e "  Fix the issue above and re-run the installer — it will resume safely."
  fi
  echo ""
  exit 1
}

step() {
  CURRENT_STEP=$1
  echo ""
  echo -e "${CYAN}[$1/$TOTAL_STEPS]${NC} ${BOLD}$2${NC}"
}

# Spinner for long-running waits
spin() {
  local pid=$1
  local msg=$2
  local chars='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r${DIM}       %s %s${NC}" "${chars:i++%${#chars}:1}" "$msg"
    sleep 0.2
  done
  printf "\r       %-60s\n" " "
}

# Wait for a service to be ready with a health check
wait_for() {
  local name=$1
  local check_cmd=$2
  local max_seconds=$3
  local elapsed=0

  while [ $elapsed -lt "$max_seconds" ]; do
    if eval "$check_cmd" >/dev/null 2>&1; then
      return 0
    fi
    printf "\r${DIM}       Waiting for %s... (%ds/%ds)${NC}" "$name" "$elapsed" "$max_seconds"
    sleep 2
    elapsed=$((elapsed + 2))
  done
  printf "\r       %-60s\n" " "
  return 1
}

# Wait for a TCP port to accept connections
wait_for_port() {
  local name=$1
  local port=$2
  local max_seconds=$3
  local elapsed=0

  while [ $elapsed -lt "$max_seconds" ]; do
    # Try nc first, fall back to /dev/tcp, then ss
    if command -v nc &>/dev/null; then
      if nc -z localhost "$port" 2>/dev/null; then return 0; fi
    elif (echo >/dev/tcp/localhost/"$port") 2>/dev/null; then
      return 0
    elif ss -tlnp 2>/dev/null | grep -q ":${port} "; then
      return 0
    fi
    printf "\r${DIM}       Waiting for %s on port %d... (%ds/%ds)${NC}" "$name" "$port" "$elapsed" "$max_seconds"
    sleep 1
    elapsed=$((elapsed + 1))
  done
  printf "\r       %-60s\n" " "
  return 1
}

# ── Stop all Correlic services (handles both naming variants) ─
# Old installs may use "correlix-*" (with X), new ones use "correlic-*"

stop_all_correlic_services() {
  for svc in correlic-api correlic-telemetry correlic-agent correlic-ui correlic-ui-proxy \
             correlix-api correlix-telemetry correlix-agent correlix-ui correlix-ui-proxy; do
    systemctl stop "$svc" 2>/dev/null || true
    systemctl disable "$svc" 2>/dev/null || true
  done
}

# ── Cleanup trap ─────────────────────────────────────────────

cleanup() {
  local exit_code=$?
  # Always clean up temp files
  if [ -n "$TEMP_FILE" ] && [ -f "$TEMP_FILE" ]; then
    rm -f "$TEMP_FILE"
  fi
  if [ -n "$BACKUP_DIR" ] && [ -d "$BACKUP_DIR" ]; then
    rm -rf "$BACKUP_DIR"
  fi
  exit "$exit_code"
}
trap cleanup EXIT

# ── Options ──────────────────────────────────────────────────
# NEO4J_CHOICE: "yes", "no" or "auto" (fresh install → yes; upgrade → whatever
# the existing .env says). Resolved into WITH_NEO4J once the install type is known.

usage() {
  echo "Usage: install.sh [--with-neo4j | --without-neo4j]"
  echo "  --without-neo4j   PostgreSQL-only profile (no Java, no Neo4j); CORRELIC_NEO4J=no does the same"
  echo "  --with-neo4j      Install the Neo4j graph as well (default on a fresh install)"
}

NEO4J_CHOICE="${CORRELIC_NEO4J:-}"
for arg in "$@"; do
  case "$arg" in
    --without-neo4j|--no-neo4j) NEO4J_CHOICE="no" ;;
    --with-neo4j)               NEO4J_CHOICE="yes" ;;
    -h|--help)                  usage; exit 0 ;;
    *)                          usage; fail "Unknown option: $arg" ;;
  esac
done
case "$(echo "$NEO4J_CHOICE" | tr '[:upper:]' '[:lower:]')" in
  ""|auto)          NEO4J_CHOICE="auto" ;;
  yes|y|true|on|1)  NEO4J_CHOICE="yes" ;;
  no|n|false|off|0) NEO4J_CHOICE="no" ;;
  *)                fail "CORRELIC_NEO4J must be yes or no (got '$NEO4J_CHOICE')" ;;
esac
WITH_NEO4J=true

# ── Header ───────────────────────────────────────────────────

echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}  Correlic Installer v${VERSION}${NC}"
echo -e "${BOLD}  Security Observability — Self-Hosted${NC}"
echo -e "${BOLD}================================================${NC}"

# ==============================================================
# 1. Check prerequisites
# ==============================================================
step 1 "Checking prerequisites..."

# Must be root
if [ "$(id -u)" -ne 0 ]; then
  fail "This script must be run as root. Use: curl -sSL https://raw.githubusercontent.com/FuloxDev/correlic/main/install/install.sh | sudo bash"
fi
ok "Running as root"

# x86_64 (amd64) or aarch64 (arm64): Apple Silicon Linux VMs, AWS Graviton,
# Raspberry Pi 5 and similar, with the same kernel 5.8+ and BTF requirements.
if [ -z "$ARCH" ]; then
  fail "Unsupported architecture: $MACHINE. Correlic requires x86_64 (amd64) or aarch64 (arm64)."
fi
ok "Architecture: $MACHINE ($ARCH)"

# Kernel 5.8+ for eBPF BTF support
KERNEL_VERSION=$(uname -r | cut -d'-' -f1)
KERNEL_MAJOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f1)
KERNEL_MINOR=$(echo "$KERNEL_VERSION" | cut -d'.' -f2)
if [ "$KERNEL_MAJOR" -lt 5 ] || { [ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 8 ]; }; then
  fail "Kernel $KERNEL_VERSION is too old. Correlic eBPF agent requires Linux kernel 5.8 or newer.
       Current kernel: $(uname -r)
       Upgrade your kernel and try again."
fi
ok "Kernel: $(uname -r)"

# OpenSSL
if ! command -v openssl &>/dev/null; then
  fail "OpenSSL is not installed. Install it first:
       Debian/Ubuntu: apt install openssl
       RHEL/Fedora:   yum install openssl"
fi
ok "OpenSSL available"

# curl
if ! command -v curl &>/dev/null; then
  fail "curl is not installed. Install it first:
       Debian/Ubuntu: apt install curl
       RHEL/Fedora:   yum install curl"
fi

# systemd
if ! command -v systemctl &>/dev/null; then
  fail "systemd is required. This installer does not support init-based systems."
fi
ok "systemd available"

# Disk space — need at least 1GB free on /opt
AVAIL_KB=$(df --output=avail /opt 2>/dev/null | tail -1 | tr -d ' ' || echo "0")
if [ "$AVAIL_KB" -lt 1048576 ] 2>/dev/null; then
  AVAIL_MB=$((AVAIL_KB / 1024))
  fail "Not enough disk space on /opt. Need at least 1GB, have ${AVAIL_MB}MB.
       Free up space and try again."
fi
ok "Disk space: $((AVAIL_KB / 1024))MB available on /opt"

# ==============================================================
# 2. Detect distro
# ==============================================================
step 2 "Detecting Linux distribution..."

DISTRO=""
PKG_MGR=""

if [ -f /etc/os-release ]; then
  # shellcheck source=/dev/null
  . /etc/os-release
  case "$ID" in
    ubuntu|debian|pop|linuxmint|kali)
      DISTRO="debian"
      PKG_MGR="apt"
      ;;
    rhel|centos|rocky|almalinux|fedora|amzn)
      DISTRO="rhel"
      if command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
      else
        PKG_MGR="yum"
      fi
      ;;
    *)
      fail "Unsupported distribution: $ID
       Supported: Ubuntu, Debian, RHEL, CentOS, Rocky, Fedora, Amazon Linux, Kali.
       For other distros, use the Docker installation method instead."
      ;;
  esac
else
  fail "Cannot detect distribution (/etc/os-release not found)."
fi

ok "Detected: ${PRETTY_NAME:-$ID} ($PKG_MGR)"

# ==============================================================
# 3. Check for existing installation & download bundle
# ==============================================================
step 3 "Downloading Correlic bundle..."

# ── Check for existing installation (upgrade vs fresh) ───────

if [ -f "$INSTALL_DIR/.env" ]; then
  IS_UPGRADE=true
  warn "Existing installation found — upgrading"

  # Create secure backup directory (not world-readable)
  BACKUP_DIR=$(mktemp -d /tmp/correlic-backup-XXXXXX)
  chmod 700 "$BACKUP_DIR"

  # Source existing secrets so we reuse them
  # shellcheck source=/dev/null
  set +u  # .env may have unset vars
  source "$INSTALL_DIR/.env"
  set -u

  # Extract DB_PASSWORD from DATABASE_URL if present
  DB_PASSWORD=""
  if [ -n "${DATABASE_URL:-}" ]; then
    DB_PASSWORD=$(echo "$DATABASE_URL" | sed -n 's|.*://[^:]*:\([^@]*\)@.*|\1|p') || true
  fi
  NEO4J_PASSWORD="${NEO4J_PASSWORD:-}"
  LLM_ENCRYPTION_KEY="${LLM_ENCRYPTION_KEY:-}"

  detail "Reusing existing secrets from .env"

  # Stop running services (systemd + stray processes)
  log "  Stopping existing services..."
  set +e

  # Stop and disable all services (handles both correlic-* and correlix-* naming)
  stop_all_correlic_services

  # Remove stale unit files from previous installs with different naming
  for unit_file in /etc/systemd/system/correlix-*.service; do
    [ -f "$unit_file" ] && rm -f "$unit_file"
  done
  systemctl daemon-reload 2>/dev/null || true

  # Kill any stray processes on known Correlic ports (may survive if not systemd-managed)
  for port in 8080 8081 3001 8788; do
    STRAY_PID=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K\d+' | head -1)
    if [ -n "$STRAY_PID" ] 2>/dev/null && [ -d "/proc/$STRAY_PID" ]; then
      STRAY_CWD=$(readlink "/proc/$STRAY_PID/cwd" 2>/dev/null || echo "")
      STRAY_CMD=$(tr '\0' ' ' < "/proc/$STRAY_PID/cmdline" 2>/dev/null || echo "")
      STRAY_EXE=$(readlink "/proc/$STRAY_PID/exe" 2>/dev/null || echo "")
      if echo "$STRAY_CWD$STRAY_CMD$STRAY_EXE" | grep -q "/opt/correlic"; then
        kill "$STRAY_PID" 2>/dev/null || true
      fi
    fi
  done
  sleep 2
  set -e
  ok "Existing services stopped"

  # Backup config and certs to secure temp directory
  cp "$INSTALL_DIR/.env" "$BACKUP_DIR/env" 2>/dev/null || true
  if [ -f "$INSTALL_DIR/agent.yaml" ]; then
    cp "$INSTALL_DIR/agent.yaml" "$BACKUP_DIR/agent.yaml" 2>/dev/null || true
  fi
  if [ -f "$INSTALL_DIR/ui-proxy.env" ]; then
    cp "$INSTALL_DIR/ui-proxy.env" "$BACKUP_DIR/ui-proxy.env" 2>/dev/null || true
  fi
  if [ -d "$INSTALL_DIR/certs" ] && [ -f "$INSTALL_DIR/certs/ca.crt" ]; then
    cp -a "$INSTALL_DIR/certs" "$BACKUP_DIR/certs" 2>/dev/null || true
    detail "Backed up certificates"
  fi
else
  log "  Fresh installation"
fi

# ── Resolve the database profile ─────────────────────────────
# auto: a fresh install gets the graph; an upgrade keeps the profile of its
# .env (an empty or missing NEO4J_URI means it was installed --without-neo4j).
case "$NEO4J_CHOICE" in
  yes) WITH_NEO4J=true ;;
  no)  WITH_NEO4J=false ;;
  *)   if [ "$IS_UPGRADE" = true ] && [ -z "${NEO4J_URI:-}" ]; then WITH_NEO4J=false; else WITH_NEO4J=true; fi ;;
esac
if [ "$WITH_NEO4J" = true ]; then
  ok "Profile: PostgreSQL + Neo4j graph"
else
  ok "Profile: PostgreSQL only (graph features off)"
  detail "Add the graph later with: --with-neo4j (or CORRELIC_NEO4J=yes)"
fi

# ── Download ─────────────────────────────────────────────────

TEMP_FILE=$(mktemp /tmp/correlic-bundle-XXXXXX.tar.gz)
log "  Downloading from $BUNDLE_URL..."

if ! curl -fSL --progress-bar "$BUNDLE_URL" -o "$TEMP_FILE"; then
  fail "Failed to download bundle from $BUNDLE_URL
       Check your internet connection and try again.
       If the problem persists, see https://github.com/FuloxDev/correlic/releases for alternatives."
fi

# Validate download
FILE_SIZE=$(stat -c%s "$TEMP_FILE" 2>/dev/null || stat -f%z "$TEMP_FILE" 2>/dev/null || echo "0")
if [ "$FILE_SIZE" -lt 10000 ]; then
  fail "Downloaded file is too small (${FILE_SIZE} bytes) — likely a failed download.
       Try again or download manually from $BUNDLE_URL"
fi

SIZE_MB=$((FILE_SIZE / 1048576))
ok "Downloaded (${SIZE_MB}MB)"

# Verify download integrity against SHA256SUMS-linux.txt from the same release
# (non-blocking if the checksum file is unavailable).
log "  Verifying download integrity..."
CHECKSUM_URL="${CORRELIC_CHECKSUMS_URL:-$(dirname "$BUNDLE_URL")/SHA256SUMS-linux.txt}"
BUNDLE_NAME=$(basename "$BUNDLE_URL")
EXPECTED_SHA=$(curl -fsSL "$CHECKSUM_URL" 2>/dev/null | awk -v f="$BUNDLE_NAME" '$2 == f || $2 == "*" f {print $1}') || true
if [ -n "${EXPECTED_SHA:-}" ]; then
  ACTUAL_SHA=$(sha256sum "$TEMP_FILE" | awk '{print $1}')
  if [ "$EXPECTED_SHA" != "$ACTUAL_SHA" ]; then
    fail "SHA256 checksum mismatch!
         Expected: $EXPECTED_SHA
         Got:      $ACTUAL_SHA
         The download may be corrupted or tampered with. Try again."
  fi
  ok "SHA256 checksum verified"
else
  warn "Checksum file not available — skipping integrity verification"
fi

# ── Extract ──────────────────────────────────────────────────

log "  Extracting to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

if ! tar -xzf "$TEMP_FILE" -C "$INSTALL_DIR" --strip-components=1; then
  fail "Failed to extract bundle. The download may be corrupted.
       Delete $TEMP_FILE and try again."
fi
rm -f "$TEMP_FILE"
TEMP_FILE=""

# ── Restore preserved config ────────────────────────────────

if [ "$IS_UPGRADE" = true ] && [ -n "$BACKUP_DIR" ]; then
  cp "$BACKUP_DIR/env" "$INSTALL_DIR/.env" 2>/dev/null || true
  cp "$BACKUP_DIR/agent.yaml" "$INSTALL_DIR/agent.yaml" 2>/dev/null || true
  cp "$BACKUP_DIR/ui-proxy.env" "$INSTALL_DIR/ui-proxy.env" 2>/dev/null || true
  if [ -d "$BACKUP_DIR/certs" ]; then
    rm -rf "$INSTALL_DIR/certs"
    mv "$BACKUP_DIR/certs" "$INSTALL_DIR/certs"
  fi
  detail "Restored existing configuration"
fi

# Make binaries executable
chmod +x "$INSTALL_DIR/bin/"* 2>/dev/null || true
# correlic-hook (Claude Code / Cursor hook) ships in bin/ next to the agent.
chmod +x "$INSTALL_DIR/bin/correlic-hook" 2>/dev/null || true
chmod +x "$INSTALL_DIR/node/bin/node" 2>/dev/null || true
mkdir -p "$INSTALL_DIR/logs"

ok "Extracted to $INSTALL_DIR"

# ==============================================================
# 4. Install PostgreSQL 16
# ==============================================================
step 4 "Setting up PostgreSQL..."

PG_INSTALLED=false
PG_VERSION_NUM=0

if command -v psql &>/dev/null; then
  PG_VERSION_NUM=$(psql --version 2>/dev/null | grep -oP '\d+' | head -1 || echo "0")
  if [ "$PG_VERSION_NUM" -ge 14 ] 2>/dev/null; then
    PG_INSTALLED=true
    ok "PostgreSQL $PG_VERSION_NUM already installed"
  else
    warn "PostgreSQL $PG_VERSION_NUM found but version 14+ is required"
  fi
fi

if [ "$PG_INSTALLED" = false ]; then
  log "  Installing PostgreSQL 16..."

  if [ "$DISTRO" = "debian" ]; then
    apt-get update -qq
    apt-get install -y -qq curl ca-certificates gnupg lsb-release >/dev/null 2>&1

    # Add PostgreSQL apt repository (--yes for idempotent re-runs)
    curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
      | gpg --dearmor --yes -o /usr/share/keyrings/postgresql-keyring.gpg 2>/dev/null

    CODENAME=$(lsb_release -cs 2>/dev/null || . /etc/os-release && echo "$VERSION_CODENAME")
    echo "deb [signed-by=/usr/share/keyrings/postgresql-keyring.gpg] http://apt.postgresql.org/pub/repos/apt ${CODENAME}-pgdg main" \
      > /etc/apt/sources.list.d/pgdg.list

    apt-get update -qq
    if ! apt-get install -y postgresql-16 2>&1 | tail -5; then
      fail "Failed to install PostgreSQL 16.
       Check the output above for errors (missing dependencies, repo issues)."
    fi
  else
    # RHEL/Fedora
    RHEL_VER=$(rpm -E %{rhel} 2>/dev/null || echo "9")
    $PKG_MGR install -y "https://download.postgresql.org/pub/repos/yum/reporpms/EL-${RHEL_VER}-${MACHINE}/pgdg-redhat-repo-latest.noarch.rpm" 2>/dev/null || true
    if ! $PKG_MGR install -y postgresql16-server postgresql16 2>&1 | tail -5; then
      fail "Failed to install PostgreSQL 16.
       Check the output above for errors."
    fi
    /usr/pgsql-16/bin/postgresql-16-setup initdb 2>/dev/null || true
    systemctl enable postgresql-16 --now 2>/dev/null || true
  fi

  # Verify installation
  if ! command -v psql &>/dev/null; then
    fail "PostgreSQL installation completed but 'psql' command not found.
       The package may not have installed correctly. Check with: dpkg -l postgresql-16"
  fi
  ok "PostgreSQL 16 installed"
fi

# Ensure PostgreSQL is running
systemctl enable postgresql --now 2>/dev/null || systemctl enable postgresql-16 --now 2>/dev/null || true

# Wait for PostgreSQL to be ready
if ! wait_for "PostgreSQL" "su - postgres -c 'pg_isready' 2>/dev/null" 20; then
  fail "PostgreSQL did not become ready within 20 seconds.
       Check status: systemctl status postgresql
       Check logs:   journalctl -u postgresql -n 20"
fi
ok "PostgreSQL is running"

# Detect PostgreSQL port
PG_PORT=5432
if command -v pg_lsclusters &>/dev/null; then
  DETECTED_PORT=$(pg_lsclusters -h 2>/dev/null | head -1 | awk '{print $3}')
  PG_PORT=${DETECTED_PORT:-5432}
elif [ -f /var/lib/pgsql/16/data/postgresql.conf ]; then
  DETECTED_PORT=$(grep "^port" /var/lib/pgsql/16/data/postgresql.conf 2>/dev/null | awk '{print $3}')
  PG_PORT=${DETECTED_PORT:-5432}
fi

# ── Configure database (only on fresh install) ──────────────

if [ "$IS_UPGRADE" = false ]; then
  DB_PASSWORD=$(openssl rand -hex 24)

  log "  Creating database user and database..."
  su - postgres -c "psql -p $PG_PORT -tc \"SELECT 1 FROM pg_roles WHERE rolname='correlic'\"" 2>/dev/null | grep -q 1 \
    || su - postgres -c "psql -p $PG_PORT -c \"CREATE USER correlic WITH PASSWORD '$DB_PASSWORD';\"" 2>/dev/null \
    || fail "Failed to create PostgreSQL user 'correlic'.
       Check PostgreSQL logs: journalctl -u postgresql -n 20"

  su - postgres -c "psql -p $PG_PORT -c \"ALTER USER correlic WITH PASSWORD '$DB_PASSWORD';\"" 2>/dev/null \
    || fail "Failed to set password for PostgreSQL user 'correlic'."

  su - postgres -c "psql -p $PG_PORT -tc \"SELECT 1 FROM pg_database WHERE datname='correlic'\"" 2>/dev/null | grep -q 1 \
    || su - postgres -c "psql -p $PG_PORT -c \"CREATE DATABASE correlic OWNER correlic;\"" 2>/dev/null \
    || fail "Failed to create database 'correlic'.
       Check PostgreSQL logs: journalctl -u postgresql -n 20"

  ok "Database user and database created (port $PG_PORT)"
else
  detail "Upgrade — skipping database user/password setup (using existing)"
fi

# ==============================================================
# 5. Install Neo4j 5
# ==============================================================
step 5 "Setting up Neo4j..."

NEO4J_BOLT_PORT=""
if [ "$WITH_NEO4J" = false ]; then
  ok "Skipped — PostgreSQL-only profile (no Java, no Neo4j)"
  detail "ai.data_exfiltration, ai.excessive_writes and the Neo4j timeline stay off; everything else runs"
fi

# Everything up to "end of the Neo4j step" runs only with the graph profile.
if [ "$WITH_NEO4J" = true ]; then

# ── Helper: determine minimum Java version for a Neo4j release ─
# Neo4j 5.x requires Java 17+, Neo4j 2025.x (11+) requires Java 21+
neo4j_required_java() {
  local neo4j_ver=$1
  if [ "$neo4j_ver" -ge 11 ] 2>/dev/null; then
    echo 21
  else
    echo 17
  fi
}

# ── Helper: detect the highest installed JDK and its JAVA_HOME ─
# Sets DETECTED_JAVA_VERSION and DETECTED_JAVA_HOME
detect_java() {
  DETECTED_JAVA_VERSION=0
  DETECTED_JAVA_HOME=""

  # Check all installed JDKs, pick the highest version
  local best_ver=0
  local best_home=""

  # Scan standard JVM directories (Debian/Ubuntu + RHEL/Fedora)
  for jvm_dir in /usr/lib/jvm /usr/java; do
    [ -d "$jvm_dir" ] || continue
    for d in "$jvm_dir"/java-*; do
      [ -x "$d/bin/java" ] || continue
      local ver
      ver=$("$d/bin/java" -version 2>&1 | head -1 | grep -oP '(?<=")\d+' | head -1 || echo "0")
      if [ "$ver" -gt "$best_ver" ] 2>/dev/null; then
        best_ver=$ver
        best_home=$d
      fi
    done
  done

  # Also check the default java on PATH (may be from alternatives)
  if command -v java &>/dev/null; then
    local path_ver
    path_ver=$(java -version 2>&1 | head -1 | grep -oP '(?<=")\d+' | head -1 || echo "0")
    if [ "$path_ver" -gt "$best_ver" ] 2>/dev/null; then
      best_ver=$path_ver
      # Resolve symlinks to find JAVA_HOME (java → /usr/bin/java → /etc/alternatives/java → /usr/lib/jvm/...)
      local real_java
      real_java=$(readlink -f "$(command -v java)" 2>/dev/null || echo "")
      if [ -n "$real_java" ]; then
        # Strip /bin/java from the end
        best_home="${real_java%/bin/java}"
      fi
    fi
  fi

  DETECTED_JAVA_VERSION=$best_ver
  DETECTED_JAVA_HOME=$best_home
}

# ── Helper: install Java to meet Neo4j requirements ────────────
# Installs the best available JDK ≥ required_version
install_java() {
  local required_ver=$1

  log "  Installing Java ${required_ver}+ (required by Neo4j $NEO4J_VERSION_NUM)..."

  if [ "$DISTRO" = "debian" ]; then
    # Try 21 first (Kali/Sid/newer), then 17 if sufficient
    if [ "$required_ver" -le 21 ] && apt-get install -y -qq openjdk-21-jre-headless >/dev/null 2>&1; then
      true
    elif [ "$required_ver" -le 17 ] && apt-get install -y -qq openjdk-17-jre-headless >/dev/null 2>&1; then
      true
    elif apt-get install -y -qq openjdk-21-jre-headless >/dev/null 2>&1; then
      # Fallback: try 21 even if required is higher (best effort)
      true
    else
      fail "Failed to install Java ${required_ver}+. Neo4j $NEO4J_VERSION_NUM requires it.
       Install manually:
       Debian/Ubuntu: apt install openjdk-21-jre-headless
       Then re-run the installer."
    fi
  else
    if [ "$required_ver" -le 21 ] && $PKG_MGR install -y -q java-21-openjdk-headless >/dev/null 2>&1; then
      true
    elif [ "$required_ver" -le 17 ] && $PKG_MGR install -y -q java-17-openjdk-headless >/dev/null 2>&1; then
      true
    else
      fail "Failed to install Java ${required_ver}+. Neo4j $NEO4J_VERSION_NUM requires it.
       Install manually:
       RHEL/Fedora: dnf install java-21-openjdk-headless
       Then re-run the installer."
    fi
  fi

  # Re-detect after install
  detect_java

  if [ "$DETECTED_JAVA_VERSION" -lt "$required_ver" ] 2>/dev/null; then
    fail "Java ${required_ver}+ is required by Neo4j $NEO4J_VERSION_NUM, but only Java $DETECTED_JAVA_VERSION was found after installation.
       Install Java ${required_ver}+ manually and re-run the installer."
  fi

  ok "Java $DETECTED_JAVA_VERSION installed (JAVA_HOME=$DETECTED_JAVA_HOME)"
}

# ── Detect existing Neo4j ──────────────────────────────────────

NEO4J_INSTALLED=false
NEO4J_VERSION_NUM=0

if command -v neo4j &>/dev/null; then
  NEO4J_VERSION_STR=$(neo4j --version 2>/dev/null || echo "0")
  NEO4J_VERSION_NUM=$(echo "$NEO4J_VERSION_STR" | grep -oP '\d+' | head -1 || echo "0")

  if [ "$NEO4J_VERSION_NUM" -ge 5 ] 2>/dev/null; then
    NEO4J_INSTALLED=true
    ok "Neo4j $NEO4J_VERSION_NUM already installed"
  elif [ "$NEO4J_VERSION_NUM" -gt 0 ] 2>/dev/null; then
    fail "Neo4j $NEO4J_VERSION_STR found but version 5+ is required.
       Please upgrade Neo4j first: https://neo4j.com/docs/operations-manual/current/upgrade/"
  fi
fi

# ── Install Neo4j if not present ───────────────────────────────

if [ "$NEO4J_INSTALLED" = false ]; then
  NEO4J_VERSION_NUM=5  # We're installing Neo4j 5

  log "  Installing Neo4j Community 5..."

  if [ "$DISTRO" = "debian" ]; then
    curl -fsSL https://debian.neo4j.com/neotechnology.gpg.key \
      | gpg --dearmor --yes -o /usr/share/keyrings/neo4j-keyring.gpg 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/neo4j-keyring.gpg] https://debian.neo4j.com stable latest" \
      > /etc/apt/sources.list.d/neo4j.list
    apt-get update -qq
    if ! apt-get install -y neo4j 2>&1 | tail -5; then
      fail "Failed to install Neo4j.
       Check the output above. You may need to accept the Neo4j license or fix repo issues."
    fi
  else
    cat > /etc/yum.repos.d/neo4j.repo <<'REPOEOF'
[neo4j]
name=Neo4j RPM Repository
baseurl=https://yum.neo4j.com/stable/5
enabled=1
gpgcheck=1
gpgkey=https://debian.neo4j.com/neotechnology.gpg.key
REPOEOF
    if ! $PKG_MGR install -y neo4j 2>&1 | tail -5; then
      fail "Failed to install Neo4j.
       Check the output above for errors."
    fi
  fi

  # Verify installation
  if ! command -v neo4j &>/dev/null; then
    fail "Neo4j installation completed but 'neo4j' command not found."
  fi

  # Re-detect actual installed version (repo may have given us a newer release)
  NEO4J_VERSION_STR=$(neo4j --version 2>/dev/null || echo "5")
  NEO4J_VERSION_NUM=$(echo "$NEO4J_VERSION_STR" | grep -oP '\d+' | head -1 || echo "5")

  ok "Neo4j $NEO4J_VERSION_NUM installed"
fi

# ── Ensure correct Java for THIS Neo4j version ────────────────
# This runs for BOTH pre-installed and freshly installed Neo4j.

REQUIRED_JAVA=$(neo4j_required_java "$NEO4J_VERSION_NUM")
detect_java

if [ "$DETECTED_JAVA_VERSION" -lt "$REQUIRED_JAVA" ] 2>/dev/null; then
  if [ "$DETECTED_JAVA_VERSION" -gt 0 ] 2>/dev/null; then
    warn "Java $DETECTED_JAVA_VERSION found, but Neo4j $NEO4J_VERSION_NUM requires Java ${REQUIRED_JAVA}+"
  fi
  install_java "$REQUIRED_JAVA"
else
  ok "Java $DETECTED_JAVA_VERSION available (meets Neo4j $NEO4J_VERSION_NUM requirement of ${REQUIRED_JAVA}+)"
fi

# ── Ensure Neo4j bolt port is available ────────────────────────

NEO4J_BOLT_PORT=7687
if ss -tlnp 2>/dev/null | grep -q ":7687 "; then
  # Check if the holder is an existing Neo4j instance
  NEO4J_PORT_HOLDER=$(ss -tlnp 2>/dev/null | grep ":7687 " | awk '{print $NF}' | head -1)
  if echo "$NEO4J_PORT_HOLDER" | grep -qi "neo4j\|java"; then
    log "  Stopping old Neo4j instance on port 7687..."
    systemctl stop neo4j 2>/dev/null || true
    # If it's not systemd-managed, kill the process directly
    if ss -tlnp 2>/dev/null | grep -q ":7687 "; then
      NEO4J_OLD_PID=$(ss -tlnp 2>/dev/null | grep ":7687 " | grep -oP 'pid=\K\d+' | head -1)
      if [ -n "$NEO4J_OLD_PID" ] 2>/dev/null; then
        kill "$NEO4J_OLD_PID" 2>/dev/null || true
        sleep 2
      fi
    fi
    ok "Old Neo4j instance stopped"
  else
    # Non-Neo4j process on 7687 — use alternate port
    warn "Port 7687 (Neo4j Bolt) is in use by non-Neo4j process: $NEO4J_PORT_HOLDER"
    NEO4J_BOLT_PORT=7688
    warn "Will use port $NEO4J_BOLT_PORT instead"
  fi
else
  detail "Neo4j Bolt port 7687 available"
fi

# ── Configure Neo4j (fresh install, or an upgrade that adds the graph) ─

if [ "$IS_UPGRADE" = false ] || [ -z "${NEO4J_PASSWORD:-}" ]; then
  NEO4J_PASSWORD=$(openssl rand -hex 16)
  neo4j-admin dbms set-initial-password "$NEO4J_PASSWORD" 2>/dev/null || true
  detail "Neo4j password configured"
else
  detail "Upgrade — skipping Neo4j password setup (using existing)"
fi

# Tune Neo4j for self-hosted (localhost-only, HTTP disabled, memory tuning)
# Also set JAVA_HOME so Neo4j uses the correct JDK even if multiple are installed
NEO4J_CONF="/etc/neo4j/neo4j.conf"
if [ -f "$NEO4J_CONF" ]; then
  cp "$NEO4J_CONF" "${NEO4J_CONF}.bak" 2>/dev/null || true
  cat > "$NEO4J_CONF" <<CONFEOF
# Correlic Neo4j Configuration — auto-generated
server.default_listen_address=127.0.0.1
server.bolt.enabled=true
server.bolt.listen_address=:${NEO4J_BOLT_PORT}
server.bolt.advertised_address=localhost:${NEO4J_BOLT_PORT}
server.http.enabled=false
server.https.enabled=false
server.memory.heap.initial_size=512m
server.memory.heap.max_size=1g
server.memory.pagecache.size=512m
db.transaction.timeout=30s
dbms.usage_report.enabled=false
CONFEOF
  detail "Neo4j configured (localhost-only, HTTP disabled, memory tuned)"
fi

# ── Set JAVA_HOME for Neo4j service ───────────────────────────
# neo4j.conf doesn't support JAVA_HOME — set it in the systemd unit environment.
# This ensures Neo4j always uses the correct JDK, even if the system default is older.
if [ -n "$DETECTED_JAVA_HOME" ]; then
  mkdir -p /etc/systemd/system/neo4j.service.d
  cat > /etc/systemd/system/neo4j.service.d/java-home.conf <<JAVAEOF
[Service]
Environment="JAVA_HOME=${DETECTED_JAVA_HOME}"
JAVAEOF
  systemctl daemon-reload
  detail "Neo4j JAVA_HOME set to $DETECTED_JAVA_HOME"
fi

# ── Pre-start verification: confirm Neo4j sees the right Java ─
# Catch misconfiguration before waiting 120s for a timeout.
log "  Verifying Neo4j can start with Java $DETECTED_JAVA_VERSION..."
NEO4J_VERIFY=$(systemctl start neo4j 2>&1; sleep 2; journalctl -u neo4j -n 5 --no-pager 2>/dev/null)
if echo "$NEO4J_VERIFY" | grep -qi "unsupported java"; then
  # Extract what Neo4j actually detected
  BAD_JAVA=$(echo "$NEO4J_VERIFY" | grep -oP 'Unsupported Java \S+' | head -1)
  systemctl stop neo4j 2>/dev/null || true

  # Last resort: try to find and set an alternative JAVA_HOME
  detect_java
  if [ "$DETECTED_JAVA_VERSION" -ge "$REQUIRED_JAVA" ] 2>/dev/null && [ -n "$DETECTED_JAVA_HOME" ]; then
    warn "$BAD_JAVA detected by Neo4j — switching JAVA_HOME to $DETECTED_JAVA_HOME (Java $DETECTED_JAVA_VERSION)"
    cat > /etc/systemd/system/neo4j.service.d/java-home.conf <<JAVAEOF
[Service]
Environment="JAVA_HOME=${DETECTED_JAVA_HOME}"
JAVAEOF
    systemctl daemon-reload
  else
    fail "$BAD_JAVA — Neo4j $NEO4J_VERSION_NUM requires Java ${REQUIRED_JAVA}+.
       Fix: Install Java ${REQUIRED_JAVA}+ and re-run the installer.
       Debian/Ubuntu: apt install openjdk-21-jre-headless
       RHEL/Fedora:   dnf install java-21-openjdk-headless"
  fi
fi

# Stop before the clean start+wait below (may already be running from verify)
systemctl stop neo4j 2>/dev/null || true

# Start Neo4j
systemctl enable neo4j --now 2>/dev/null || true

log "  Waiting for Neo4j to start (first startup may take up to 2 minutes)..."

# Quick check: if Neo4j exits immediately, don't wait the full 120s
sleep 3
if ! systemctl is-active --quiet neo4j 2>/dev/null; then
  EARLY_LOG=$(journalctl -u neo4j -n 5 --no-pager 2>/dev/null)
  if echo "$EARLY_LOG" | grep -qi "unsupported java"; then
    BAD_JAVA=$(echo "$EARLY_LOG" | grep -oP 'Unsupported Java \S+' | head -1)
    fail "Neo4j refuses to start: $BAD_JAVA.
       Neo4j $NEO4J_VERSION_NUM requires Java ${REQUIRED_JAVA}+.
       Install the correct Java version and re-run the installer:
       Debian/Ubuntu: apt install openjdk-21-jre-headless
       RHEL/Fedora:   dnf install java-21-openjdk-headless"
  fi
  # Other early failure — fall through to the timeout check below
fi

if wait_for_port "Neo4j Bolt" "$NEO4J_BOLT_PORT" 120; then
  ok "Neo4j running (bolt://localhost:$NEO4J_BOLT_PORT)"
else
  # Provide actionable diagnostics
  NEO4J_LOG=$(journalctl -u neo4j -n 10 --no-pager 2>/dev/null)
  warn "Neo4j did not respond within 120 seconds."
  detail "Check status: systemctl status neo4j"
  detail "Check logs:   journalctl -u neo4j -n 20"

  if echo "$NEO4J_LOG" | grep -qi "unsupported java"; then
    BAD_JAVA=$(echo "$NEO4J_LOG" | grep -oP 'Unsupported Java \S+' | head -1)
    fail "Neo4j cannot start: $BAD_JAVA.
       Neo4j $NEO4J_VERSION_NUM requires Java ${REQUIRED_JAVA}+.
       Install the correct Java version and re-run the installer:
       Debian/Ubuntu: apt install openjdk-21-jre-headless
       RHEL/Fedora:   dnf install java-21-openjdk-headless"
  elif echo "$NEO4J_LOG" | grep -qi "address already in use\|port.*in use"; then
    fail "Neo4j cannot bind to port $NEO4J_BOLT_PORT — another process is using it.
       Find it with: ss -tlnp | grep :$NEO4J_BOLT_PORT
       Stop the conflicting process and re-run the installer."
  elif echo "$NEO4J_LOG" | grep -qi "out of memory\|heap\|cannot allocate"; then
    fail "Neo4j failed to start due to insufficient memory.
       Correlic needs at least 2GB free RAM for Neo4j.
       Free up memory or reduce heap size in /etc/neo4j/neo4j.conf and re-run."
  else
    fail "Neo4j failed to start. Check the logs above for details.
       Common fixes:
       - Java version: apt install openjdk-21-jre-headless
       - Port conflict: ss -tlnp | grep :$NEO4J_BOLT_PORT
       - Permissions:   ls -la /var/lib/neo4j/data/
       Or install without the graph: re-run with --without-neo4j"
  fi
fi

fi  # end of the Neo4j step (WITH_NEO4J)

# ==============================================================
# 6. Generate mTLS certificates
# ==============================================================
step 6 "Setting up mTLS certificates..."

CERT_DIR="$INSTALL_DIR/certs"

if [ ! -f "$CERT_DIR/ca.crt" ]; then
  mkdir -p "$CERT_DIR"

  log "  Generating CA certificate..."
  openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null \
    || fail "Failed to generate CA key. Check OpenSSL installation."
  openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
    -out "$CERT_DIR/ca.crt" -subj "/CN=Correlic CA" 2>/dev/null \
    || fail "Failed to generate CA certificate."

  log "  Generating server certificate..."
  openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null
  openssl req -new -key "$CERT_DIR/server.key" \
    -out "$CERT_DIR/server.csr" -subj "/CN=correlic-backend" 2>/dev/null

  cat > "$CERT_DIR/ext.cnf" <<EXTEOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,DNS:correlic-backend,IP:127.0.0.1
EXTEOF

  openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/server.crt" \
    -days 3650 -extfile "$CERT_DIR/ext.cnf" 2>/dev/null \
    || fail "Failed to generate server certificate."

  log "  Generating client certificate..."
  openssl genrsa -out "$CERT_DIR/client.key" 2048 2>/dev/null
  openssl req -new -key "$CERT_DIR/client.key" \
    -out "$CERT_DIR/client.csr" -subj "/CN=correlic-agent" 2>/dev/null
  openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.crt" \
    -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/client.crt" \
    -days 3650 2>/dev/null \
    || fail "Failed to generate client certificate."

  # Cleanup temp files
  rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.cnf "$CERT_DIR"/*.srl

  chmod 600 "$CERT_DIR"/*.key
  chmod 644 "$CERT_DIR"/*.crt

  ok "Certificates generated (CA + server + client)"
else
  ok "Certificates already exist, keeping existing"
fi

# ==============================================================
# 7. Generate secrets & config
# ==============================================================
step 7 "Generating configuration..."

if [ "$IS_UPGRADE" = false ]; then
  # Fresh install — generate server secrets
  LLM_KEY=$(openssl rand -hex 32)

  # Keys are created after the database is initialised: one dashboard admin
  # (API key + password) and one restricted key for the agent.
  API_KEY=""

  if [ "$WITH_NEO4J" = true ]; then
    NEO4J_ENV="NEO4J_URI=bolt://localhost:${NEO4J_BOLT_PORT}
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=${NEO4J_PASSWORD}"
  else
    NEO4J_ENV="# Graph database (optional). An empty NEO4J_URI runs on PostgreSQL alone;
# re-run the installer with --with-neo4j to add it.
NEO4J_URI="
  fi

  log "  Writing backend config (.env)..."
  cat > "$INSTALL_DIR/.env" <<EOF
DATABASE_URL=postgres://correlic:${DB_PASSWORD}@localhost:${PG_PORT}/correlic?sslmode=disable
${NEO4J_ENV}
TLS_CERT_FILE=${INSTALL_DIR}/certs/server.crt
TLS_KEY_FILE=${INSTALL_DIR}/certs/server.key
MTLS_CA_FILE=${INSTALL_DIR}/certs/ca.crt
LLM_ENCRYPTION_KEY=${LLM_KEY}
ALLOW_API_KEY_AUTH=true
SAMPLING_ENABLED=true
DEFAULT_ORG_ID=default
EOF
  chmod 600 "$INSTALL_DIR/.env"

  log "  Writing agent config (agent.yaml)..."
  cat > "$INSTALL_DIR/agent.yaml" <<EOF
backend_url: "https://localhost:${API_PORT}"
telemetry_url: "https://localhost:${TELEMETRY_PORT}"
api_key: ""
tls_ca_file: "${INSTALL_DIR}/certs/ca.crt"
tls_client_cert_file: "${INSTALL_DIR}/certs/client.crt"
tls_client_key_file: "${INSTALL_DIR}/certs/client.key"
profile: "developer"
log_level: "info"
heartbeat_interval: 30s
ebpf_enabled: true
process_exec_enabled: true
file_monitor_enabled: true
network_monitor_enabled: true
dns_monitor_enabled: true
# Block rules (kill matching processes). Off by default; enable after you
# have reviewed your rules in the dashboard.
block_enabled: false
EOF
  chmod 600 "$INSTALL_DIR/agent.yaml"

  log "  Writing proxy config (ui-proxy.env)..."
  cat > "$INSTALL_DIR/ui-proxy.env" <<EOF
PORT=${PROXY_PORT}
BACKEND_API=https://localhost:${API_PORT}
MTLS_CA=${INSTALL_DIR}/certs/ca.crt
MTLS_CERT=${INSTALL_DIR}/certs/client.crt
MTLS_KEY=${INSTALL_DIR}/certs/client.key
EOF
  chmod 600 "$INSTALL_DIR/ui-proxy.env"

  ok "Configuration generated (fresh install)"
else
  ok "Configuration preserved from previous install"

  # Reconcile the graph settings of the preserved .env with the chosen profile:
  # bolt port changes (port conflict in step 5), a graph added by --with-neo4j,
  # or a graph switched off by --without-neo4j (NEO4J_URI emptied, password kept).
  if [ -f "$INSTALL_DIR/.env" ]; then
    OLD_NEO4J_URI=$(grep "^NEO4J_URI=" "$INSTALL_DIR/.env" 2>/dev/null | cut -d= -f2-)
    if [ "$WITH_NEO4J" = true ]; then
      NEW_NEO4J_URI="bolt://localhost:${NEO4J_BOLT_PORT}"
      if [ "$OLD_NEO4J_URI" != "$NEW_NEO4J_URI" ]; then
        if grep -q "^NEO4J_URI=" "$INSTALL_DIR/.env"; then
          sed -i "s|^NEO4J_URI=.*|NEO4J_URI=${NEW_NEO4J_URI}|" "$INSTALL_DIR/.env"
        else
          echo "NEO4J_URI=${NEW_NEO4J_URI}" >> "$INSTALL_DIR/.env"
        fi
        detail "Updated NEO4J_URI in .env (${OLD_NEO4J_URI:-unset} → $NEW_NEO4J_URI)"
      fi
      grep -q "^NEO4J_USERNAME=" "$INSTALL_DIR/.env" || echo "NEO4J_USERNAME=neo4j" >> "$INSTALL_DIR/.env"
      if ! grep -q "^NEO4J_PASSWORD=.\+" "$INSTALL_DIR/.env"; then
        sed -i "/^NEO4J_PASSWORD=/d" "$INSTALL_DIR/.env"
        echo "NEO4J_PASSWORD=${NEO4J_PASSWORD}" >> "$INSTALL_DIR/.env"
        detail "Added the Neo4j password to .env"
      fi
    elif [ -n "$OLD_NEO4J_URI" ]; then
      sed -i "s|^NEO4J_URI=.*|NEO4J_URI=|" "$INSTALL_DIR/.env"
      detail "Graph switched off: NEO4J_URI emptied in .env (NEO4J_PASSWORD kept for later)"
    fi
  fi
fi

# ==============================================================
# 8. Initialize database
# ==============================================================
step 8 "Initializing database..."

# Build DATABASE_URL for admin commands
if [ "$IS_UPGRADE" = true ] && [ -n "${DATABASE_URL:-}" ]; then
  export DATABASE_URL
else
  export DATABASE_URL="postgres://correlic:${DB_PASSWORD}@localhost:${PG_PORT}/correlic?sslmode=disable"
fi

log "  Running database migrations..."
MIGRATE_OUTPUT=$("$INSTALL_DIR/bin/correlic-admin" migrate up 2>&1) || {
  echo "$MIGRATE_OUTPUT"
  fail "Database migration failed. See output above.
       You can retry with: DATABASE_URL='$DATABASE_URL' $INSTALL_DIR/bin/correlic-admin migrate up"
}
detail "$(echo "$MIGRATE_OUTPUT" | tail -1)"

if [ "$IS_UPGRADE" = true ]; then
  detail "Upgrade — skipping org creation (using existing)"
else
  log "  Ensuring default organization exists..."
  ORG_OUTPUT=$("$INSTALL_DIR/bin/correlic-admin" create-org --name default 2>&1) || true
  if echo "$ORG_OUTPUT" | grep -qi "already exists"; then
    detail "Default organization already exists"
  elif echo "$ORG_OUTPUT" | grep -q "org_id="; then
    detail "Default organization created"
  else
    detail "$ORG_OUTPUT"
  fi
fi

# Query actual org UUID from database (match Windows installer behavior)
ORG_UUID=$(su - postgres -c "psql -p $PG_PORT -d correlic -t -A -c \"SELECT id FROM organizations LIMIT 1\"" 2>/dev/null \
  | grep -oP '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' | head -1) || true
if [ -n "${ORG_UUID:-}" ]; then
  # Update DEFAULT_ORG_ID in .env with the real UUID
  if [ -f "$INSTALL_DIR/.env" ]; then
    sed -i "s/^DEFAULT_ORG_ID=.*/DEFAULT_ORG_ID=${ORG_UUID}/" "$INSTALL_DIR/.env"
  fi
  detail "Organization ID: $ORG_UUID"

  # Enroll the mTLS client certificate so the proxy and agent can authenticate
  if [ -f "$INSTALL_DIR/certs/client.crt" ]; then
    ENROLL_OUTPUT=$("$INSTALL_DIR/bin/correlic-admin" enroll-client-cert --org-id "$ORG_UUID" --name agent-cert --cert-file "$INSTALL_DIR/certs/client.crt" 2>&1) || true
    if echo "$ENROLL_OUTPUT" | grep -qi "enrolled=true\|already"; then
      detail "Client certificate enrolled"
    else
      warn "Client certificate enrollment: $ENROLL_OUTPUT"
    fi
  fi

  # Create the dashboard admin (API key + password) and a restricted agent key
  if [ "$IS_UPGRADE" = false ]; then
    log "  Creating dashboard admin and agent key..."
    kv() { grep -E "^[[:space:]]*$1=" | head -1 | sed -E "s/^[[:space:]]*$1=//" | tr -d '[:space:]'; }
    ADMIN_OUTPUT=$("$INSTALL_DIR/bin/correlic-admin" create-user --org-id "$ORG_UUID" --email admin@local.dev --name "Admin" --role admin 2>&1) || true
    ADMIN_USER_ID=$(echo "$ADMIN_OUTPUT" | kv user_id)
    ADMIN_PASSWORD=$(echo "$ADMIN_OUTPUT" | kv password)
    if [ -n "$ADMIN_USER_ID" ]; then
      KEY_OUTPUT=$("$INSTALL_DIR/bin/correlic-admin" create-api-key --org-id "$ORG_UUID" --user-id "$ADMIN_USER_ID" --name dashboard 2>&1) || true
      GENERATED_API_KEY=$(echo "$KEY_OUTPUT" | kv api_key)
    fi
    SA_OUTPUT=$("$INSTALL_DIR/bin/correlic-admin" create-service-account --org-id "$ORG_UUID" --email agent@local.dev --name "Agent" --role member 2>&1) || true
    SA_USER_ID=$(echo "$SA_OUTPUT" | kv user_id)
    AGENT_API_KEY=""
    if [ -n "$SA_USER_ID" ]; then
      AKEY_OUTPUT=$("$INSTALL_DIR/bin/correlic-admin" create-api-key --org-id "$ORG_UUID" --user-id "$SA_USER_ID" --name agent --type agent 2>&1) || true
      AGENT_API_KEY=$(echo "$AKEY_OUTPUT" | kv api_key)
    fi
    if [ -n "$AGENT_API_KEY" ]; then
      sed -i "s|^api_key:.*|api_key: \"${AGENT_API_KEY}\"|" "$INSTALL_DIR/agent.yaml"
      ok "Agent key created and written to agent.yaml"
    else
      warn "Could not create the agent key: $SA_OUTPUT $AKEY_OUTPUT"
      detail "Create one later: correlic-admin create-api-key --org-id $ORG_UUID --user-id <user_id> --name agent --type agent"
    fi
    if [ -n "$GENERATED_API_KEY" ]; then
      cat > "$INSTALL_DIR/dashboard-credentials" <<EOF
# Correlic dashboard credentials (generated by the installer). Keep this file private.
DASHBOARD_URL=http://localhost:${UI_PORT}
API_KEY=${GENERATED_API_KEY}
ADMIN_EMAIL=admin@local.dev
ADMIN_PASSWORD=${ADMIN_PASSWORD}
EOF
      chmod 600 "$INSTALL_DIR/dashboard-credentials"
      ok "Dashboard admin created (credentials shown at the end of the install)"
    else
      warn "Could not create the dashboard admin: $ADMIN_OUTPUT $KEY_OUTPUT"
    fi
  fi
else
  warn "Could not query org UUID from database — using fallback 'default'"
fi

ok "Database initialized"

# ==============================================================
# 9. Create systemd services & start
# ==============================================================
step 9 "Installing systemd services..."

# ── Helper: check if a port is in use ─────────────────────────

port_in_use() {
  ss -tlnp 2>/dev/null | grep -q ":${1} "
}

port_holder() {
  ss -tlnp 2>/dev/null | grep ":${1} " | awk '{print $NF}' | head -1
}

# Check if a port holder is an old Correlic service.
# Matches: correlic-api, correlic-telemetry, correlic-agent, node (running from /opt/correlic/).
# ss output truncates names and sometimes garbles them, so we use multiple detection methods.
is_correlic_process() {
  local holder=$1

  # Direct name match (covers correlic-api, correlic-teleme, correlix-api, etc.)
  if echo "$holder" | grep -qiE 'correlic|correl[ix]'; then
    return 0
  fi

  # Extract PID from ss output — handle both clean and garbled formats
  # Clean: users:(("node",pid=1221,fd=18))  Garbled: (v1",pid=1222,fd=18))
  local pid
  pid=$(echo "$holder" | grep -oP 'pid=\K\d+' | head -1)
  if [ -z "$pid" ] 2>/dev/null; then
    return 1
  fi

  if [ -d "/proc/$pid" ]; then
    # Check cwd for /opt/correlic (catches node running from /opt/correlic/ui or /opt/correlic/ui-proxy)
    if readlink "/proc/$pid/cwd" 2>/dev/null | grep -q "/opt/correlic"; then
      return 0
    fi
    # Check full cmdline for /opt/correlic (catches correlic binaries and node with correlic paths)
    if tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | grep -q "/opt/correlic"; then
      return 0
    fi
    # Check the actual binary path
    if readlink "/proc/$pid/exe" 2>/dev/null | grep -q "/opt/correlic"; then
      return 0
    fi
  fi

  return 1
}

# Track ports we've already claimed during this install to avoid double-assignment
CLAIMED_PORTS=""

# Find the next available port starting from a given port.
# Checks both actual port usage (ss) and ports already claimed by this installer.
next_free_port() {
  local port=$1
  while port_in_use "$port" || echo "$CLAIMED_PORTS" | grep -qw "$port"; do
    port=$((port + 1))
  done
  CLAIMED_PORTS="$CLAIMED_PORTS $port"
  echo "$port"
}

# ── Detect port conflicts ────────────────────────────────────

CONFLICTED_PORTS=""
CORRELIC_CONFLICTS=0
EXTERNAL_CONFLICTS=0

check_conflict() {
  local port=$1
  local name=$2
  if port_in_use "$port"; then
    local holder
    holder=$(port_holder "$port")
    CONFLICTED_PORTS="$CONFLICTED_PORTS $port"
    if is_correlic_process "$holder"; then
      CORRELIC_CONFLICTS=$((CORRELIC_CONFLICTS + 1))
      warn "Port $port ($name) is in use by old Correlic service: $holder"
    else
      EXTERNAL_CONFLICTS=$((EXTERNAL_CONFLICTS + 1))
      warn "Port $port ($name) is in use by: $holder"
    fi
    return 1
  fi
  return 0
}

check_conflict "$API_PORT" "Backend API"      || true
check_conflict "$TELEMETRY_PORT" "Telemetry"  || true
check_conflict "$UI_PORT" "Dashboard"         || true
check_conflict "$PROXY_PORT" "UI Proxy"       || true

TOTAL_CONFLICTS=$((CORRELIC_CONFLICTS + EXTERNAL_CONFLICTS))

# ── Helper: stop all old Correlic services and stray processes ─
# Usage: stop_old_correlic [true]  — pass "true" to force-kill ALL processes on conflicting ports
stop_old_correlic() {
  local force=${1:-false}

  stop_all_correlic_services

  # Remove stale unit files from old naming
  for unit_file in /etc/systemd/system/correlix-*.service; do
    [ -f "$unit_file" ] && rm -f "$unit_file"
  done
  systemctl daemon-reload 2>/dev/null || true

  # Kill processes on conflicting ports
  for port in $CONFLICTED_PORTS; do
    if port_in_use "$port"; then
      HOLDER_PID=$(ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'pid=\K\d+' | head -1)
      if [ -n "$HOLDER_PID" ] 2>/dev/null; then
        if [ "$force" = "true" ] || is_correlic_process "$(port_holder "$port")"; then
          kill "$HOLDER_PID" 2>/dev/null || true
        fi
      fi
    fi
  done
  sleep 2
}

# ── Helper: patch config files with current port variables ─────
patch_configs_for_ports() {
  log "  Updating configuration files with new ports..."

  if [ -f "$INSTALL_DIR/agent.yaml" ]; then
    sed -i "s|backend_url:.*|backend_url: \"https://localhost:${API_PORT}\"|" "$INSTALL_DIR/agent.yaml"
    sed -i "s|telemetry_url:.*|telemetry_url: \"https://localhost:${TELEMETRY_PORT}\"|" "$INSTALL_DIR/agent.yaml"
  fi

  if [ -f "$INSTALL_DIR/ui-proxy.env" ]; then
    sed -i "s|^PORT=.*|PORT=${PROXY_PORT}|" "$INSTALL_DIR/ui-proxy.env"
    sed -i "s|^BACKEND_API=.*|BACKEND_API=https://localhost:${API_PORT}|" "$INSTALL_DIR/ui-proxy.env"
  fi

  detail "Config files updated"
}

# ── Resolve conflicts interactively ──────────────────────────

if [ "$TOTAL_CONFLICTS" -gt 0 ]; then
  echo ""

  # If ALL conflicts are old Correlic services, just stop them automatically
  if [ "$EXTERNAL_CONFLICTS" -eq 0 ]; then
    log "  All $CORRELIC_CONFLICTS conflicting port(s) are old Correlic services — stopping them..."
    stop_old_correlic
    ok "Old Correlic services stopped — ports freed"

  else
    # Some or all conflicts are external processes — ask the user
    echo -e "  ${YELLOW}${TOTAL_CONFLICTS} port conflict(s) detected.${NC}"
    if [ "$CORRELIC_CONFLICTS" -gt 0 ]; then
      detail "$CORRELIC_CONFLICTS are old Correlic services, $EXTERNAL_CONFLICTS are other processes."
    fi
    echo ""
    echo -e "  ${BOLD}Options:${NC}"
    echo -e "    ${CYAN}[S]${NC} Stop installation — fix port conflicts manually, then re-run"
    echo -e "    ${CYAN}[K]${NC} Kill old services — stop all old Correlic instances, reuse their ports"
    echo -e "    ${CYAN}[R]${NC} Reassign ports — keep other processes running, use next available ports"
    echo ""

    # Preview what reassignment would look like
    CLAIMED_PORTS=""
    PREVIEW_API=$(next_free_port "$API_PORT")
    PREVIEW_TELEMETRY=$(next_free_port "$TELEMETRY_PORT")
    PREVIEW_UI=$(next_free_port "$UI_PORT")
    PREVIEW_PROXY=$(next_free_port "$PROXY_PORT")

    echo -e "  ${DIM}If reassigned (R):${NC}"
    [ "$PREVIEW_API" -ne "$API_PORT" ]             && echo -e "    ${DIM}Backend API:  $API_PORT → $PREVIEW_API${NC}"
    [ "$PREVIEW_TELEMETRY" -ne "$TELEMETRY_PORT" ] && echo -e "    ${DIM}Telemetry:    $TELEMETRY_PORT → $PREVIEW_TELEMETRY${NC}"
    [ "$PREVIEW_UI" -ne "$UI_PORT" ]               && echo -e "    ${DIM}Dashboard:    $UI_PORT → $PREVIEW_UI${NC}"
    [ "$PREVIEW_PROXY" -ne "$PROXY_PORT" ]         && echo -e "    ${DIM}UI Proxy:     $PROXY_PORT → $PREVIEW_PROXY${NC}"
    echo ""

    CHOICE=""
    while [ "$CHOICE" != "s" ] && [ "$CHOICE" != "k" ] && [ "$CHOICE" != "r" ]; do
      read -r -p "  Choose [S/K/R]: " CHOICE < /dev/tty
      CHOICE=$(echo "$CHOICE" | tr '[:upper:]' '[:lower:]')
    done

    if [ "$CHOICE" = "s" ]; then
      echo ""
      echo -e "  ${YELLOW}Installation paused.${NC} Fix the port conflicts and re-run the installer."
      echo -e "  Conflicting ports:$CONFLICTED_PORTS"
      echo -e "  Find what's using a port: ${CYAN}ss -tlnp | grep :<port>${NC}"
      echo ""
      exit 0
    fi

    if [ "$CHOICE" = "k" ]; then
      # Force-kill ALL processes on conflicting ports (user explicitly chose this)
      log "  Killing all processes on conflicting ports..."
      stop_old_correlic true
      ok "All conflicting processes stopped"

      # Verify ports are free
      REMAINING=0
      port_in_use "$API_PORT"       && REMAINING=$((REMAINING + 1))
      port_in_use "$TELEMETRY_PORT" && REMAINING=$((REMAINING + 1))
      port_in_use "$UI_PORT"        && REMAINING=$((REMAINING + 1))
      port_in_use "$PROXY_PORT"     && REMAINING=$((REMAINING + 1))

      if [ "$REMAINING" -gt 0 ]; then
        warn "$REMAINING port(s) could not be freed — reassigning those ports"
        CLAIMED_PORTS=""
        port_in_use "$API_PORT"       && API_PORT=$(next_free_port "$API_PORT")
        port_in_use "$TELEMETRY_PORT" && TELEMETRY_PORT=$(next_free_port "$TELEMETRY_PORT")
        port_in_use "$UI_PORT"        && UI_PORT=$(next_free_port "$UI_PORT")
        port_in_use "$PROXY_PORT"     && PROXY_PORT=$(next_free_port "$PROXY_PORT")
        patch_configs_for_ports
        ok "Ports: API=$API_PORT, Telemetry=$TELEMETRY_PORT, Dashboard=$UI_PORT, Proxy=$PROXY_PORT"
      else
        ok "All default ports freed — using original ports"
      fi
    fi

    if [ "$CHOICE" = "r" ]; then
      # Stop old Correlic services first (they'll be replaced anyway)
      if [ "$CORRELIC_CONFLICTS" -gt 0 ]; then
        log "  Stopping old Correlic services first..."
        stop_old_correlic
        ok "Old Correlic services stopped"
      fi

      # Reassign all conflicted ports to next available
      CLAIMED_PORTS=""
      port_in_use "$API_PORT"       && API_PORT=$(next_free_port "$API_PORT")
      port_in_use "$TELEMETRY_PORT" && TELEMETRY_PORT=$(next_free_port "$TELEMETRY_PORT")
      port_in_use "$UI_PORT"        && UI_PORT=$(next_free_port "$UI_PORT")
      port_in_use "$PROXY_PORT"     && PROXY_PORT=$(next_free_port "$PROXY_PORT")

      patch_configs_for_ports
      ok "Ports reassigned: API=$API_PORT, Telemetry=$TELEMETRY_PORT, Dashboard=$UI_PORT, Proxy=$PROXY_PORT"
    fi
  fi
fi

# ── Write systemd unit files ─────────────────────────────────

log "  Creating service files..."

# The backend planes only wait for Neo4j when the graph profile is installed.
NEO4J_UNIT=""
if [ "$WITH_NEO4J" = true ]; then NEO4J_UNIT=" neo4j.service"; fi

cat > /etc/systemd/system/correlic-api.service <<EOF
[Unit]
Description=Correlic Backend API
After=network.target postgresql.service${NEO4J_UNIT}
Wants=postgresql.service${NEO4J_UNIT}

[Service]
Type=simple
EnvironmentFile=${INSTALL_DIR}/.env
Environment=PORT=${API_PORT}
ExecStart=${INSTALL_DIR}/bin/correlic-api
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=correlic-api

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/correlic-telemetry.service <<EOF
[Unit]
Description=Correlic Telemetry Ingestion
After=network.target postgresql.service${NEO4J_UNIT}
Wants=postgresql.service${NEO4J_UNIT}

[Service]
Type=simple
EnvironmentFile=${INSTALL_DIR}/.env
Environment=PORT=${TELEMETRY_PORT}
ExecStart=${INSTALL_DIR}/bin/correlic-telemetry
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=correlic-telemetry

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/correlic-agent.service <<EOF
[Unit]
Description=Correlic eBPF Agent
After=network.target correlic-api.service correlic-telemetry.service

[Service]
Type=simple
Environment=CORRELIC_CONFIG=${INSTALL_DIR}/agent.yaml
ExecStart=${INSTALL_DIR}/bin/correlic-agent
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_BPF CAP_SYS_ADMIN CAP_PERFMON CAP_SYS_RESOURCE
StandardOutput=journal
StandardError=journal
SyslogIdentifier=correlic-agent

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/correlic-ui.service <<EOF
[Unit]
Description=Correlic Dashboard (Next.js)
After=network.target correlic-api.service

[Service]
Type=simple
Environment=PORT=${UI_PORT}
Environment=HOSTNAME=127.0.0.1
Environment=NODE_ENV=production
Environment=PROXY_BASE_URL=http://localhost:${PROXY_PORT}
WorkingDirectory=${INSTALL_DIR}/ui
ExecStart=${INSTALL_DIR}/node/bin/node server.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=correlic-ui

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/correlic-ui-proxy.service <<EOF
[Unit]
Description=Correlic UI Proxy (mTLS termination)
After=network.target correlic-api.service

[Service]
Type=simple
EnvironmentFile=${INSTALL_DIR}/ui-proxy.env
WorkingDirectory=${INSTALL_DIR}/ui-proxy
ExecStart=${INSTALL_DIR}/node/bin/node index.js
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=correlic-ui-proxy

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
ok "Service files created"

# ── Enable and start services with TCP health checks ─────────
# Agent starts LAST — it needs the backend API for AI pattern loading

SERVICES="correlic-api correlic-telemetry correlic-ui correlic-ui-proxy correlic-agent"
FAILED_SERVICES=""

set +e  # Service starts may fail — we handle each one explicitly

start_service() {
  local svc=$1
  systemctl enable "$svc" >/dev/null 2>&1
  log "  Starting $svc..."
  if ! systemctl start "$svc" 2>/dev/null; then
    FAILED_SERVICES="$FAILED_SERVICES $svc"
    warn "$svc failed to start"
    detail "$(journalctl -u "$svc" -n 3 --no-pager 2>/dev/null | tail -3)"
    return 1
  fi
  return 0
}

# Backend API — wait for port with TCP health check
start_service correlic-api
if ! wait_for_port "Backend API" "$API_PORT" 15; then
  FAILED_SERVICES="$FAILED_SERVICES correlic-api"
  warn "Backend API did not bind to port $API_PORT within 15 seconds"
  detail "$(journalctl -u correlic-api -n 5 --no-pager 2>/dev/null | tail -5)"
fi

# Telemetry — wait for port
start_service correlic-telemetry
if ! wait_for_port "Telemetry" "$TELEMETRY_PORT" 10; then
  warn "Telemetry did not bind to port $TELEMETRY_PORT within 10 seconds"
fi

# UI and proxy (non-critical, no port health check needed)
start_service correlic-ui
start_service correlic-ui-proxy

# Agent LAST — only after backend API is confirmed listening
log "  Starting correlic-agent (after backend health check)..."
if wait_for_port "Backend API" "$API_PORT" 5; then
  start_service correlic-agent
else
  warn "Backend API not reachable — starting agent anyway (it will retry)"
  start_service correlic-agent
fi

set -e

# ── Report service status ────────────────────────────────────

RUNNING=0
TOTAL=5
for svc in $SERVICES; do
  if systemctl is-active --quiet "$svc" 2>/dev/null; then
    RUNNING=$((RUNNING + 1))
  fi
done

if [ "$RUNNING" -eq "$TOTAL" ]; then
  ok "All $TOTAL services running"
elif [ "$RUNNING" -gt 0 ]; then
  warn "$RUNNING/$TOTAL services running. Failed:$FAILED_SERVICES"
  warn "Check logs: journalctl -u <service-name> -n 20"
else
  fail "No services started successfully. Check logs:
       journalctl -u correlic-api -n 20
       journalctl -u correlic-agent -n 20"
fi

# ==============================================================
# 10. Summary
# ==============================================================
step 10 "Installation complete"

# Copy uninstall script
if [ -f "$INSTALL_DIR/uninstall.sh" ]; then
  chmod +x "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
fi

echo ""
echo -e "${BOLD}================================================${NC}"
if [ "$IS_UPGRADE" = true ]; then
  echo -e "${GREEN}  Correlic has been upgraded!${NC}"
else
  echo -e "${GREEN}  Correlic is running!${NC}"
fi
echo -e "${BOLD}================================================${NC}"
echo ""
echo -e "  Dashboard:    ${CYAN}http://localhost:${UI_PORT}${NC}"
if [ -n "$GENERATED_API_KEY" ]; then
  echo -e "  Log in with:  ${CYAN}${GENERATED_API_KEY}${NC}  (API key)"
  echo -e "           or:  ${CYAN}admin@local.dev / ${ADMIN_PASSWORD}${NC}"
  echo -e "                (stored in ${INSTALL_DIR}/dashboard-credentials)"
fi
echo -e "  API Proxy:    ${CYAN}http://localhost:${PROXY_PORT}${NC}  (loopback only)"
echo -e "  API (mTLS):   ${CYAN}https://localhost:${API_PORT}${NC}"
if [ "$WITH_NEO4J" = true ]; then
  echo -e "  Profile:      PostgreSQL + Neo4j graph (bolt://localhost:${NEO4J_BOLT_PORT})"
else
  echo -e "  Profile:      PostgreSQL only — add the graph later with: ${CYAN}--with-neo4j${NC}"
fi
echo -e "  Install dir:  $INSTALL_DIR"
echo ""
echo -e "  The dashboard listens on localhost only. To reach it from another machine,"
echo -e "  put a reverse proxy with TLS in front of it or use an SSH tunnel."
echo -e "  ${BOLD}All data stays on this device. Nothing is sent externally.${NC}"
echo ""
echo -e "  Commands:"
echo -e "    Status:     ${CYAN}systemctl status correlic-api correlic-agent${NC}"
echo -e "    Logs:       ${CYAN}journalctl -u correlic-api -f${NC}"
echo -e "    Stop all:   ${CYAN}systemctl stop correlic-{api,telemetry,agent,ui,ui-proxy}${NC}"
echo -e "    Start all:  ${CYAN}systemctl start correlic-{api,telemetry,agent,ui,ui-proxy}${NC}"
echo -e "    Uninstall:  ${CYAN}${INSTALL_DIR}/uninstall.sh${NC}"
echo -e "    AI hooks:   ${CYAN}${INSTALL_DIR}/bin/correlic-hook setup${NC}  (Claude Code / Cursor; see backend/docs/HOOKS.md)"
echo ""
if [ "$API_PORT" -ne 8080 ] || [ "$TELEMETRY_PORT" -ne 8081 ] || [ "$UI_PORT" -ne 3001 ] || [ "$PROXY_PORT" -ne 8788 ]; then
  echo -e "  ${YELLOW}Note: Non-default ports are in use due to port conflict resolution.${NC}"
  echo ""
fi
if [ -n "$FAILED_SERVICES" ]; then
  echo -e "  ${YELLOW}Some services failed to start:${FAILED_SERVICES}${NC}"
  echo -e "  ${YELLOW}Check logs with: journalctl -u <service-name>${NC}"
  echo ""
fi
echo -e "  ${GREEN}All data stays on this device. Nothing is sent externally.${NC}"
echo ""
