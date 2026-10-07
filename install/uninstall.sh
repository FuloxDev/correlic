#!/bin/bash
set -euo pipefail

# ============================================================
# Correlic Uninstaller
# Stops services, removes binaries, optionally removes data
# ============================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

INSTALL_DIR="/opt/correlic"

log()  { echo -e "${CYAN}[correlic]${NC} $1"; }
ok()   { echo -e "${GREEN}  [OK]${NC} $1"; }
warn() { echo -e "${YELLOW}  [!]${NC} $1"; }
fail() { echo -e "${RED}  [ERROR]${NC} $1"; exit 1; }

if [ "$(id -u)" -ne 0 ]; then
  fail "This script must be run as root."
fi

echo ""
echo -e "${BOLD}Correlic Uninstaller${NC}"
echo ""

# ----------------------------------------------------------
# 1. Stop and disable services
# ----------------------------------------------------------
log "Stopping services..."

SERVICES="correlic-api correlic-telemetry correlic-agent correlic-ui correlic-ui-proxy"
for svc in $SERVICES; do
  systemctl stop "$svc" 2>/dev/null || true
  systemctl disable "$svc" 2>/dev/null || true
  rm -f "/etc/systemd/system/${svc}.service"
done

systemctl daemon-reload
ok "Services stopped and removed"

# ----------------------------------------------------------
# 2. Remove binaries and application files
# ----------------------------------------------------------
log "Removing application files..."

# Keep data directories unless user confirms
rm -rf "$INSTALL_DIR/bin"
rm -rf "$INSTALL_DIR/ui"
rm -rf "$INSTALL_DIR/ui-proxy"
rm -rf "$INSTALL_DIR/node"
rm -rf "$INSTALL_DIR/logs"

ok "Application files removed"

# ----------------------------------------------------------
# 3. Ask about data
# ----------------------------------------------------------
echo ""
echo -e "${YELLOW}  The following data is still on disk:${NC}"
echo -e "    Certificates: $INSTALL_DIR/certs/"
echo -e "    Config:       $INSTALL_DIR/.env, $INSTALL_DIR/agent.yaml"
echo -e "    PostgreSQL:   correlic database"
echo -e "    Neo4j:        graph data"
echo ""

read -r -p "  Remove ALL data including databases? This cannot be undone. (y/N) " CONFIRM
if [ "$CONFIRM" = "y" ] || [ "$CONFIRM" = "Y" ]; then
  log "Removing all data..."

  # Remove config and certs
  rm -rf "$INSTALL_DIR"

  # Drop PostgreSQL database
  su - postgres -c "psql -c 'DROP DATABASE IF EXISTS correlic;'" 2>/dev/null || true
  su - postgres -c "psql -c 'DROP USER IF EXISTS correlic;'" 2>/dev/null || true
  ok "PostgreSQL database dropped"

  # Neo4j — clear data (leave Neo4j installed)
  if systemctl is-active --quiet neo4j 2>/dev/null; then
    systemctl stop neo4j
    rm -rf /var/lib/neo4j/data/databases/neo4j 2>/dev/null || true
    rm -rf /var/lib/neo4j/data/transactions/neo4j 2>/dev/null || true
    systemctl start neo4j
  fi
  ok "Neo4j data cleared"

  ok "All data removed"
else
  log "Keeping data. To remove later, delete $INSTALL_DIR/ and drop the correlic database."
fi

echo ""
echo -e "${GREEN}  Correlic has been uninstalled.${NC}"
echo ""
echo -e "  PostgreSQL and Neo4j packages were NOT removed."
echo -e "  To remove them: apt remove postgresql neo4j (or yum remove)"
echo ""
