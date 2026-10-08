#!/bin/bash
# Correlic all-in-one image entrypoint.
#
# First start: generates secrets and mTLS certificates, initialises PostgreSQL
# and Neo4j, runs migrations, creates the default organisation, a dashboard
# admin (API key + email/password) and a separate agent key, then starts
# every service under supervisord. Everything that must survive a container
# upgrade lives under /var/lib/correlic (the data volume).
set -euo pipefail

CORRELIC_DIR="/opt/correlic"
DATA_DIR="/var/lib/correlic"
CERTS_DIR="$DATA_DIR/certs"              # persisted with the data volume
LEGACY_CERTS_DIR="$CORRELIC_DIR/certs"   # pre-1.0.1 images kept certs in the image layer
PG_DATA="$DATA_DIR/postgresql"
NEO4J_DATA="$DATA_DIR/neo4j"             # server.directories.data in /etc/neo4j/neo4j.conf
ENV_FILE="$DATA_DIR/.env"
CREDS_FILE="$DATA_DIR/dashboard-credentials"
SENTINEL="$DATA_DIR/.initialized"
LOG_DIR="/var/log/correlic"
PG_BIN="/usr/lib/postgresql/16/bin"

log()   { echo "[correlic] $*"; }
admin() { "$CORRELIC_DIR/bin/correlic-admin" "$@"; }
# Value of "key=value" from command output, tolerant of leading spaces.
kv()    { grep -E "^[[:space:]]*$1=" | head -1 | sed -E "s/^[[:space:]]*$1=//" | tr -d '[:space:]'; }

wait_for_pg() {
    until "$PG_BIN/pg_isready" -U correlic -q 2>/dev/null; do sleep 1; done
}
wait_for_neo4j() {
    local retries=30
    while [ $retries -gt 0 ]; do
        if curl -sf http://localhost:7474 >/dev/null 2>&1; then return 0; fi
        sleep 2; retries=$((retries - 1))
    done
    log "WARNING: Neo4j did not start in time, continuing without graph DB"
    return 1
}
# The API plane requires a client certificate, so probe it with the agent cert.
api_ready() {
    curl -sf --cacert "$CERTS_DIR/ca.crt" --cert "$CERTS_DIR/client.crt" \
        --key "$CERTS_DIR/client.key" https://localhost:8080/health >/dev/null 2>&1
}

write_agent_config() {  # $1 = agent API key
    cat > "$CERTS_DIR/agent.yaml" <<YAML
backend_url: "https://localhost:8080"
telemetry_url: "https://localhost:8081"
api_key: "$1"
tls_ca_file: "$CERTS_DIR/ca.crt"
tls_client_cert_file: "$CERTS_DIR/client.crt"
tls_client_key_file: "$CERTS_DIR/client.key"
profile: "developer"
log_level: "info"
heartbeat_interval: 30s
ebpf_enabled: true
process_exec_enabled: true
file_monitor_enabled: true
network_monitor_enabled: true
dns_monitor_enabled: true
YAML
    chmod 600 "$CERTS_DIR/agent.yaml"
}

mkdir -p "$LOG_DIR" "$DATA_DIR" "$NEO4J_DATA"
chmod 755 "$LOG_DIR"
chown -R neo4j:neo4j "$NEO4J_DATA" 2>/dev/null || true

# Certificates created by a pre-1.0.1 image lived in the image layer; carry
# them into the volume if that layer is still present.
if [ ! -f "$CERTS_DIR/ca.crt" ] && [ -f "$LEGACY_CERTS_DIR/ca.crt" ]; then
    mkdir -p "$CERTS_DIR"
    cp -a "$LEGACY_CERTS_DIR"/. "$CERTS_DIR"/
fi

# ============================================================
# First-run initialization
# ============================================================
if [ ! -f "$SENTINEL" ]; then
    log "First run detected — initializing Correlic..."

    log "[1/6] Generating secrets..."
    DB_PASSWORD=$(openssl rand -hex 16)
    NEO4J_PASSWORD=$(openssl rand -hex 16)
    LLM_KEY=$(openssl rand -hex 32)
    cat > "$ENV_FILE" <<ENV
DB_PASSWORD=$DB_PASSWORD
NEO4J_PASSWORD=$NEO4J_PASSWORD
LLM_ENCRYPTION_KEY=$LLM_KEY
ENV
    chmod 600 "$ENV_FILE"

    log "[2/6] Initializing PostgreSQL..."
    mkdir -p "$PG_DATA"
    chown -R postgres:postgres "$PG_DATA"
    su - postgres -c "$PG_BIN/initdb -D $PG_DATA" 2>&1 | tail -1
    echo "local all all trust" > "$PG_DATA/pg_hba.conf"
    echo "host all all 127.0.0.1/32 md5" >> "$PG_DATA/pg_hba.conf"
    su - postgres -c "$PG_BIN/pg_ctl -D $PG_DATA -l $LOG_DIR/postgresql-init.log start" 2>&1
    sleep 2
    su - postgres -c "psql -c \"CREATE USER correlic WITH PASSWORD '$DB_PASSWORD';\"" 2>&1
    su - postgres -c "psql -c \"CREATE DATABASE correlic OWNER correlic;\"" 2>&1
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE correlic TO correlic;\"" 2>&1

    log "[3/6] Running database migrations..."
    export DATABASE_URL="postgres://correlic:$DB_PASSWORD@localhost:5432/correlic?sslmode=disable"
    admin migrate up

    # bootstrap: organisation, dashboard admin (API key + password), agent
    # service account + agent key, mTLS certificates, cert enrollment.
    log "[4/6] Creating organisation, admin user, keys and certificates..."
    BOOTSTRAP_OUT=$(admin bootstrap --name "Default" --certs-dir "$CERTS_DIR" 2>&1) || {
        echo "$BOOTSTRAP_OUT"; log "ERROR: bootstrap failed"; exit 1; }
    ORG_ID=$(echo "$BOOTSTRAP_OUT" | kv org_id)
    DASHBOARD_API_KEY=$(echo "$BOOTSTRAP_OUT" | kv api_key)
    AGENT_API_KEY=$(echo "$BOOTSTRAP_OUT" | kv agent_api_key)
    ADMIN_EMAIL=$(echo "$BOOTSTRAP_OUT" | kv email)
    ADMIN_PASSWORD=$(echo "$BOOTSTRAP_OUT" | kv password)
    if [ -z "$ORG_ID" ] || [ -z "$DASHBOARD_API_KEY" ] || [ -z "$AGENT_API_KEY" ]; then
        echo "$BOOTSTRAP_OUT"; log "ERROR: bootstrap did not print the expected org_id / api_key / agent_api_key"; exit 1
    fi
    echo "$ORG_ID" > "$DATA_DIR/.org_id"
    printf 'ORG_ID=%s\nAGENT_API_KEY=%s\n' "$ORG_ID" "$AGENT_API_KEY" >> "$ENV_FILE"
    cat > "$CREDS_FILE" <<CREDS
# Correlic dashboard credentials (generated on first start). Keep this file private.
DASHBOARD_URL=http://localhost:3001
API_KEY=$DASHBOARD_API_KEY
ADMIN_EMAIL=$ADMIN_EMAIL
ADMIN_PASSWORD=$ADMIN_PASSWORD
CREDS
    chmod 600 "$CREDS_FILE"
    chmod 600 "$CERTS_DIR"/*.key 2>/dev/null || true
    write_agent_config "$AGENT_API_KEY"

    su - postgres -c "$PG_BIN/pg_ctl -D $PG_DATA stop" 2>&1

    log "[5/6] Initializing Neo4j..."
    neo4j-admin dbms set-initial-password "$NEO4J_PASSWORD" 2>&1 || true
    chown -R neo4j:neo4j "$NEO4J_DATA" 2>/dev/null || true

    log "[6/6] Done."
    touch "$SENTINEL"
    FIRST_RUN=1
else
    FIRST_RUN=0
fi

# ============================================================
# Load secrets and export environment for all services
# ============================================================
set +u
source "$ENV_FILE"
set -u
ORG_ID="${ORG_ID:-$(cat "$DATA_DIR/.org_id" 2>/dev/null || echo "default")}"

export DATABASE_URL="postgres://correlic:${DB_PASSWORD}@localhost:5432/correlic?sslmode=disable"
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USERNAME="neo4j"
export NEO4J_PASSWORD="${NEO4J_PASSWORD}"
export TLS_CERT_FILE="$CERTS_DIR/server.crt"
export TLS_KEY_FILE="$CERTS_DIR/server.key"
export MTLS_CA_FILE="$CERTS_DIR/ca.crt"
export LLM_ENCRYPTION_KEY="${LLM_ENCRYPTION_KEY}"
export DEFAULT_ORG_ID="$ORG_ID"
export SAMPLING_ENABLED="true"
export ALLOW_API_KEY_AUTH="true"
export CORRELIC_CONFIG="$CERTS_DIR/agent.yaml"
# Optional remote key server. Unset by default: keys are validated locally only.
if [ -n "${CORRELIC_API_URL:-}" ]; then export CORRELIC_API_URL; fi

# ============================================================
# Start supervisord (PostgreSQL + Neo4j auto-start)
# ============================================================
log "Starting Correlic services..."
/usr/bin/supervisord -c /etc/supervisor/conf.d/correlic.conf &
SUPERVISOR_PID=$!

log "Waiting for PostgreSQL..."
sleep 3
wait_for_pg
log "PostgreSQL ready"
admin migrate up 2>&1 || true

# Repair: a volume initialised by a pre-1.0.1 image has no certificates and no
# agent key of its own. Recreate what is missing so an upgrade keeps working.
if [ ! -f "$CERTS_DIR/ca.crt" ]; then
    log "Certificates missing — generating and enrolling new ones..."
    bash "$CORRELIC_DIR/scripts/generate-certs.sh" "$CERTS_DIR"
    admin enroll-client-cert --org-id "$ORG_ID" --name agent-cert --cert-file "$CERTS_DIR/client.crt" 2>&1 || true
fi
if [ -z "${AGENT_API_KEY:-}" ]; then
    log "Agent key missing — creating one..."
    SA_OUT=$(admin create-service-account --org-id "$ORG_ID" --email agent@local.dev --name "Local agent" --role member 2>&1 || true)
    SA_USER_ID=$(echo "$SA_OUT" | kv user_id)
    KEY_OUT=$(admin create-api-key --org-id "$ORG_ID" --user-id "$SA_USER_ID" --name agent --type agent 2>&1 || true)
    AGENT_API_KEY=$(echo "$KEY_OUT" | kv api_key)
    if [ -n "$AGENT_API_KEY" ]; then
        sed -i '/^AGENT_API_KEY=/d' "$ENV_FILE"; echo "AGENT_API_KEY=$AGENT_API_KEY" >> "$ENV_FILE"
    else
        log "WARNING: could not create an agent key: $SA_OUT $KEY_OUT"
    fi
fi
if [ ! -f "$CERTS_DIR/agent.yaml" ] && [ -n "${AGENT_API_KEY:-}" ]; then
    write_agent_config "$AGENT_API_KEY"
fi

log "Waiting for Neo4j..."
wait_for_neo4j && log "Neo4j ready" || true

log "Starting backend services..."
supervisorctl start backend-api backend-telemetry 2>/dev/null

log "Waiting for backend API..."
retries=60
while [ $retries -gt 0 ]; do
    if api_ready; then break; fi
    sleep 1; retries=$((retries - 1))
done
if [ $retries -eq 0 ]; then
    log "WARNING: backend API did not answer /health within 60s; check $LOG_DIR/backend-api-error.log"
else
    log "Backend API ready"
fi

log "Starting agent..."
supervisorctl start agent 2>/dev/null
log "Starting dashboard..."
supervisorctl start ui-proxy ui 2>/dev/null

log ""
log "============================================"
log "  Correlic is running!"
log "============================================"
log "  Dashboard: http://localhost:3001"
log "  Version:   ${CORRELIC_VERSION:-dev}"
if [ "$FIRST_RUN" = "1" ]; then
    log ""
    log "  Dashboard login (also stored in $CREDS_FILE):"
    log "    API key:  $DASHBOARD_API_KEY"
    log "    or email: $ADMIN_EMAIL  password: $ADMIN_PASSWORD"
else
    log "  Dashboard login: see $CREDS_FILE (docker exec <container> cat $CREDS_FILE)"
fi
log ""
log "  All data stays on this device."
log "============================================"

trap "kill $SUPERVISOR_PID; wait $SUPERVISOR_PID" SIGTERM SIGINT
wait $SUPERVISOR_PID
