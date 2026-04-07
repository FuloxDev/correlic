#!/bin/bash
set -euo pipefail

CORRELIC_DIR="/opt/correlic"
DATA_DIR="/var/lib/correlic"
CERTS_DIR="$CORRELIC_DIR/certs"
PG_DATA="$DATA_DIR/postgresql"
NEO4J_DATA="$DATA_DIR/neo4j"
ENV_FILE="$DATA_DIR/.env"
SENTINEL="$DATA_DIR/.initialized"
LOG_DIR="/var/log/correlic"

log()  { echo "[correlic] $*"; }
wait_for_pg() {
    until pg_isready -U correlic -q 2>/dev/null; do sleep 1; done
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
wait_for_api() {
    local retries=30
    while [ $retries -gt 0 ]; do
        if curl -sfk https://localhost:8080/health >/dev/null 2>&1; then return 0; fi
        sleep 2; retries=$((retries - 1))
    done
    log "WARNING: Backend API health check timed out"
    return 1
}

# ============================================================
# First-run initialization
# ============================================================
if [ ! -f "$SENTINEL" ]; then
    log "First run detected — initializing Correlic..."

    # 1. Generate secrets
    log "[1/7] Generating secrets..."
    DB_PASSWORD=$(openssl rand -hex 16)
    NEO4J_PASSWORD=$(openssl rand -hex 16)
    LLM_KEY=$(openssl rand -hex 32)
    API_KEY=$(openssl rand -hex 32)

    cat > "$ENV_FILE" <<EOF
DB_PASSWORD=$DB_PASSWORD
NEO4J_PASSWORD=$NEO4J_PASSWORD
LLM_ENCRYPTION_KEY=$LLM_KEY
API_KEY=$API_KEY
EOF
    chmod 600 "$ENV_FILE"

    # 2. Generate mTLS certificates
    log "[2/7] Generating mTLS certificates..."
    bash "$CORRELIC_DIR/scripts/generate-certs.sh" "$CERTS_DIR"

    # 3. Initialize PostgreSQL
    log "[3/7] Initializing PostgreSQL..."
    chown -R postgres:postgres "$PG_DATA"
    su - postgres -c "/usr/lib/postgresql/16/bin/initdb -D $PG_DATA" 2>&1 | tail -1

    # Configure pg_hba for local trust
    echo "local all all trust" > "$PG_DATA/pg_hba.conf"
    echo "host all all 127.0.0.1/32 md5" >> "$PG_DATA/pg_hba.conf"

    # Start PostgreSQL temporarily
    su - postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PG_DATA -l $LOG_DIR/postgresql-init.log start" 2>&1
    sleep 2

    # Create user and database
    su - postgres -c "psql -c \"CREATE USER correlic WITH PASSWORD '$DB_PASSWORD';\"" 2>&1
    su - postgres -c "psql -c \"CREATE DATABASE correlic OWNER correlic;\"" 2>&1
    su - postgres -c "psql -c \"GRANT ALL PRIVILEGES ON DATABASE correlic TO correlic;\"" 2>&1

    # 4. Run migrations
    log "[4/7] Running database migrations..."
    export DATABASE_URL="postgres://correlic:$DB_PASSWORD@localhost:5432/correlic?sslmode=disable"
    "$CORRELIC_DIR/bin/correlic-admin" migrate up 2>&1 || log "Migration warning (may already be up to date)"

    # 5. Create default organization
    log "[5/7] Creating default organization..."
    ORG_OUTPUT=$("$CORRELIC_DIR/bin/correlic-admin" org create "Default" 2>&1 || true)
    ORG_API_KEY=$(echo "$ORG_OUTPUT" | grep -oP 'API Key: \K.*' || echo "$API_KEY")
    if [ -n "$ORG_API_KEY" ] && [ "$ORG_API_KEY" != "$API_KEY" ]; then
        sed -i "s/^API_KEY=.*/API_KEY=$ORG_API_KEY/" "$ENV_FILE"
        API_KEY="$ORG_API_KEY"
    fi

    # Stop PostgreSQL (supervisord will manage it)
    su - postgres -c "/usr/lib/postgresql/16/bin/pg_ctl -D $PG_DATA stop" 2>&1

    # 6. Initialize Neo4j
    log "[6/7] Initializing Neo4j..."
    chown -R neo4j:neo4j "$NEO4J_DATA"
    neo4j-admin dbms set-initial-password "$NEO4J_PASSWORD" 2>&1 || true

    # 7. Write sentinel
    log "[7/7] Initialization complete!"
    touch "$SENTINEL"

    log "============================================"
    log "  Correlic initialized successfully"
    log "============================================"
    log "  API Key: $API_KEY"
    log "  Secrets saved to: $ENV_FILE"
    log "  Certs saved to: $CERTS_DIR"
    log "============================================"
fi

# ============================================================
# Load secrets
# ============================================================
set +u
source "$ENV_FILE"
set -u

# ============================================================
# Export environment for all services
# ============================================================
export DATABASE_URL="postgres://correlic:${DB_PASSWORD}@localhost:5432/correlic?sslmode=disable"
export NEO4J_URI="bolt://localhost:7687"
export NEO4J_USERNAME="neo4j"
export NEO4J_PASSWORD="${NEO4J_PASSWORD}"
export TLS_CERT_FILE="$CERTS_DIR/server.crt"
export TLS_KEY_FILE="$CERTS_DIR/server.key"
export MTLS_CA_FILE="$CERTS_DIR/ca.crt"
export LLM_ENCRYPTION_KEY="${LLM_ENCRYPTION_KEY}"
export DEFAULT_ORG_ID="${ORG_ID:-default}"
export SAMPLING_ENABLED="true"
export ALLOW_API_KEY_AUTH="true"

# Agent env
export CORRELIC_BACKEND_URL="https://localhost:8080"
export CORRELIC_TELEMETRY_URL="https://localhost:8081"
export CORRELIC_API_KEY="${API_KEY}"
export CORRELIC_TLS_CA="$CERTS_DIR/ca.crt"
export CORRELIC_TLS_CERT="$CERTS_DIR/client.crt"
export CORRELIC_TLS_KEY="$CERTS_DIR/client.key"

# Neo4j data dir override
export NEO4J_HOME="/var/lib/neo4j"
export NEO4J_dbms_directories_data="$NEO4J_DATA"
export NEO4J_dbms_memory_heap_initial__size="256m"
export NEO4J_dbms_memory_heap_max__size="512m"

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

# Wait for API health
log "Waiting for backend API..."
wait_for_api && log "Backend API ready" || true

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
log ""
log "  All data stays on this device."
log "============================================"

# Forward signals to supervisord
trap "kill $SUPERVISOR_PID; wait $SUPERVISOR_PID" SIGTERM SIGINT

# Wait on supervisord
wait $SUPERVISOR_PID
