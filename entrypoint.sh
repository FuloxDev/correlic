#!/bin/bash
set -euo pipefail

CORRELIC_DIR="/opt/correlic"
DATA_DIR="/var/lib/correlic"
CERTS_DIR="$CORRELIC_DIR/certs"
PG_DATA="$DATA_DIR/postgresql"
NEO4J_DATA="/var/lib/neo4j/data"
ENV_FILE="$DATA_DIR/.env"
SENTINEL="$DATA_DIR/.initialized"
LOG_DIR="/var/log/correlic"
PG_BIN="/usr/lib/postgresql/16/bin"

log()  { echo "[correlic] $*"; }

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

# An API key passed in the environment always wins over a stored one.
ENV_API_KEY="${API_KEY:-}"
GENERATED_KEY=""

# ============================================================
# Ensure log dir is writable (every run, not just first)
# ============================================================
mkdir -p "$LOG_DIR"
chmod 777 "$LOG_DIR"

# ============================================================
# First-run initialization
# ============================================================
if [ ! -f "$SENTINEL" ]; then
    log "First run detected — initializing Correlic..."

    # 1. Generate secrets (DB + Neo4j passwords + LLM key encryption key)
    log "[1/7] Generating secrets..."
    DB_PASSWORD=$(openssl rand -hex 16)
    NEO4J_PASSWORD=$(openssl rand -hex 16)
    LLM_KEY=$(openssl rand -hex 32)

    cat > "$ENV_FILE" <<EOF
DB_PASSWORD=$DB_PASSWORD
NEO4J_PASSWORD=$NEO4J_PASSWORD
LLM_ENCRYPTION_KEY=$LLM_KEY
EOF
    chmod 600 "$ENV_FILE"

    # 2. Generate mTLS certificates
    log "[2/7] Generating mTLS certificates..."
    bash "$CORRELIC_DIR/scripts/generate-certs.sh" "$CERTS_DIR"

    # 3. Initialize PostgreSQL
    log "[3/7] Initializing PostgreSQL..."
    mkdir -p "$PG_DATA"
    chown -R postgres:postgres "$PG_DATA"
    su - postgres -c "$PG_BIN/initdb -D $PG_DATA" 2>&1 | tail -1

    # Configure pg_hba for local trust
    echo "local all all trust" > "$PG_DATA/pg_hba.conf"
    echo "host all all 127.0.0.1/32 md5" >> "$PG_DATA/pg_hba.conf"

    # Start PostgreSQL temporarily
    su - postgres -c "$PG_BIN/pg_ctl -D $PG_DATA -l $LOG_DIR/postgresql-init.log start" 2>&1
    sleep 2

    # Create user and database
    su - postgres -c "psql -c \"CREATE USER correlic WITH PASSWORD '$DB_PASSWORD';\"" 2>&1
    su - postgres -c "psql -c \"CREATE DATABASE correlic OWNER correlic;\"" 2>&1
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE correlic TO correlic;\"" 2>&1

    # 4. Run migrations
    log "[4/7] Running database migrations..."
    export DATABASE_URL="postgres://correlic:$DB_PASSWORD@localhost:5432/correlic?sslmode=disable"
    "$CORRELIC_DIR/bin/correlic-admin" migrate up 2>&1 || log "Migration warning (may already be up to date)"

    # 5. Create default organization and, unless one was supplied, a local API key
    log "[5/7] Creating default organization..."
    "$CORRELIC_DIR/bin/correlic-admin" create-org --name "Default" 2>&1 | tee /tmp/org.log
    ORG_ID=$(grep "org_id=" /tmp/org.log | cut -d= -f2)
    echo "$ORG_ID" > "$DATA_DIR/.org_id"
    log "Org created: $ORG_ID"

    # Enroll client certificate for mTLS agent auth
    "$CORRELIC_DIR/bin/correlic-admin" enroll-client-cert \
        --org-id "$ORG_ID" --name agent-cert \
        --cert-file "$CERTS_DIR/client.crt" 2>&1 || true

    if [ -n "$ENV_API_KEY" ]; then
        API_KEY="$ENV_API_KEY"
        log "Using API key from environment"
    else
        log "No API_KEY provided — creating a local one"
        "$CORRELIC_DIR/bin/correlic-admin" create-service-account \
            --org-id "$ORG_ID" --email agent@localhost --name "Local agent" --role admin 2>&1 | tee /tmp/sa.log
        USER_ID=$(grep "^user_id=" /tmp/sa.log | cut -d= -f2)
        "$CORRELIC_DIR/bin/correlic-admin" create-api-key \
            --org-id "$ORG_ID" --user-id "$USER_ID" --name all-in-one 2>&1 | tee /tmp/key.log
        API_KEY=$(grep "^api_key=" /tmp/key.log | cut -d= -f2)
        GENERATED_KEY="$API_KEY"
        rm -f /tmp/sa.log /tmp/key.log
    fi
    echo "API_KEY=$API_KEY" >> "$ENV_FILE"

    # Stop PostgreSQL (supervisord will manage it)
    su - postgres -c "$PG_BIN/pg_ctl -D $PG_DATA stop" 2>&1

    # 6. Initialize Neo4j
    log "[6/7] Initializing Neo4j..."
    neo4j-admin dbms set-initial-password "$NEO4J_PASSWORD" 2>&1 || true

    # 7. Write agent config + sentinel
    log "[7/7] Writing agent config..."
    cat > "$CERTS_DIR/agent.yaml" <<EOF
backend_url: "https://localhost:8080"
telemetry_url: "https://localhost:8081"
api_key: "$API_KEY"
tls_ca_file: "$CERTS_DIR/ca.crt"
tls_client_cert_file: "$CERTS_DIR/client.crt"
tls_client_key_file: "$CERTS_DIR/client.key"
profile: "developer"
log_level: "info"
process_exec_enabled: true
file_monitor_enabled: true
network_monitor_enabled: true
dns_monitor_enabled: true
EOF
    chmod 600 "$CERTS_DIR/agent.yaml"

    touch "$SENTINEL"

    log "============================================"
    log "  Correlic initialized successfully"
    log "============================================"
fi

# ============================================================
# Load secrets
# ============================================================
set +u
source "$ENV_FILE"
set -u

# Environment beats the stored key, and a key supplied later is persisted.
if [ -n "$ENV_API_KEY" ]; then
    API_KEY="$ENV_API_KEY"
    if ! grep -q "^API_KEY=$API_KEY\$" "$ENV_FILE"; then
        sed -i '/^API_KEY=/d' "$ENV_FILE"
        echo "API_KEY=$API_KEY" >> "$ENV_FILE"
    fi
fi
if [ -z "${API_KEY:-}" ]; then
    log "ERROR: no API key available. Pass -e API_KEY=... or remove the data volume to re-initialize."
    exit 1
fi

# ============================================================
# Export environment for all services
# ============================================================
ORG_ID=$(cat "$DATA_DIR/.org_id" 2>/dev/null || echo "default")

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
# Optional remote key server. Unset by default: keys are validated locally only.
if [ -n "${CORRELIC_API_URL:-}" ]; then
    export CORRELIC_API_URL
fi

# Agent config (reads from YAML, not env vars)
export CORRELIC_CONFIG="$CERTS_DIR/agent.yaml"

# UI + Proxy use API_KEY for automatic login
export API_KEY

# ============================================================
# Start supervisord (PostgreSQL + Neo4j auto-start)
# ============================================================
log "Starting Correlic services..."

/usr/bin/supervisord -c /etc/supervisor/conf.d/correlic.conf &
SUPERVISOR_PID=$!

# Wait for PostgreSQL
log "Waiting for PostgreSQL..."
sleep 3
wait_for_pg
log "PostgreSQL ready"

# Run migrations (idempotent)
"$CORRELIC_DIR/bin/correlic-admin" migrate up 2>&1 || true

# Wait for Neo4j
log "Waiting for Neo4j..."
wait_for_neo4j && log "Neo4j ready" || true

# Start backend
log "Starting backend services..."
supervisorctl start backend-api backend-telemetry 2>/dev/null

# Wait for API to be fully ready
log "Waiting for backend API..."
retries=30
while [ $retries -gt 0 ]; do
    if curl -sfk https://localhost:8080/health >/dev/null 2>&1; then break; fi
    sleep 1; retries=$((retries - 1))
done
# Extra wait for full API initialization (routes, DB connections, Neo4j)
sleep 10
log "Backend API ready"

# Start agent
log "Starting agent..."
supervisorctl start agent 2>/dev/null

# Start UI + proxy
log "Starting dashboard..."
supervisorctl start ui-proxy ui 2>/dev/null

log ""
log "============================================"
log "  Correlic is running!"
log "============================================"
log "  Dashboard: http://localhost:3001"
log "  Version:   ${CORRELIC_VERSION:-dev}"
if [ -n "$GENERATED_KEY" ]; then
    log ""
    log "  A local API key was generated for this install. The dashboard"
    log "  logs in with it automatically; it is stored in $ENV_FILE"
    log "  and in $CERTS_DIR/agent.yaml. To log in from elsewhere:"
    log "    $GENERATED_KEY"
fi
log ""
log "  All data stays on this device."
log "============================================"

# Forward signals to supervisord
trap "kill $SUPERVISOR_PID; wait $SUPERVISOR_PID" SIGTERM SIGINT

# Wait on supervisord
wait $SUPERVISOR_PID
