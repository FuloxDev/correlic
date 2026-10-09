#!/bin/bash
set -e

systemctl daemon-reload

if [ ! -f /etc/correlic/correlic.env ]; then
  echo "[correlic] First install — generating configuration..."

  CERT_DIR=/var/lib/correlic/certs
  if [ ! -f "$CERT_DIR/ca.crt" ]; then
    /etc/correlic/gen-certs.sh "$CERT_DIR" 2>/dev/null || true
    chmod 600 "$CERT_DIR"/*.key 2>/dev/null || true
    chmod 644 "$CERT_DIR"/*.crt 2>/dev/null || true
  fi

  LLM_KEY=$(openssl rand -hex 32)

  cat > /etc/correlic/correlic.env <<ENV
DATABASE_URL=postgres://correlic:CHANGE_ME@localhost:5432/correlic?sslmode=disable
# Optional Neo4j graph (adds the ai.data_exfiltration and ai.excessive_writes
# rules and the Neo4j timeline). Empty NEO4J_URI = PostgreSQL only (default).
# To enable: NEO4J_URI=bolt://localhost:7687 plus the username and password.
NEO4J_URI=
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=
TLS_CERT_FILE=${CERT_DIR}/server.crt
TLS_KEY_FILE=${CERT_DIR}/server.key
MTLS_CA_FILE=${CERT_DIR}/ca.crt
LLM_ENCRYPTION_KEY=${LLM_KEY}
ALLOW_API_KEY_AUTH=true
SAMPLING_ENABLED=true
DEFAULT_ORG_ID=default
ENV
  chmod 600 /etc/correlic/correlic.env

  cat > /etc/correlic/agent.yaml <<YAML
backend_url: "https://localhost:8080"
telemetry_url: "https://localhost:8081"
# Agent key: create with `correlic-admin create-api-key ... --type agent`
api_key: "PASTE_AGENT_KEY_HERE"
tls_ca_file: "${CERT_DIR}/ca.crt"
tls_client_cert_file: "${CERT_DIR}/client.crt"
tls_client_key_file: "${CERT_DIR}/client.key"
profile: "developer"
log_level: "info"
heartbeat_interval: 30s
ebpf_enabled: true
process_exec_enabled: true
file_monitor_enabled: true
network_monitor_enabled: true
dns_monitor_enabled: true
block_enabled: false
YAML
  chmod 600 /etc/correlic/agent.yaml

  cat > /etc/correlic/ui-proxy.env <<ENV
PORT=8788
NODE_ENV=production
BACKEND_API=https://localhost:8080
MTLS_CA=${CERT_DIR}/ca.crt
MTLS_CERT=${CERT_DIR}/client.crt
MTLS_KEY=${CERT_DIR}/client.key
ENV
  chmod 600 /etc/correlic/ui-proxy.env

  cat <<'STEPS'

  [correlic] Package installed. Next steps (run as root):

    1. Install PostgreSQL 16+ (Neo4j 5+ is an optional add-on) and create a database:
         sudo -u postgres psql -c "CREATE USER correlic WITH PASSWORD '<pw>';" -c "CREATE DATABASE correlic OWNER correlic;"
    2. Put the database URL in /etc/correlic/correlic.env (set NEO4J_URI there only if you run Neo4j)
    3. Load the env and run migrations:
         set -a; . /etc/correlic/correlic.env; set +a
         correlic-admin migrate up
    4. Create the organisation, enroll the client certificate, create the dashboard admin and the agent key:
         correlic-admin create-org --name default                                             # prints org_id=
         correlic-admin enroll-client-cert --org-id <org_id> --name agent-cert --cert-file /var/lib/correlic/certs/client.crt
         correlic-admin create-user --org-id <org_id> --email admin@local.dev --name Admin --role admin   # prints user_id= and password=
         correlic-admin create-api-key --org-id <org_id> --user-id <admin user_id> --name dashboard      # prints api_key= (dashboard login)
         correlic-admin create-service-account --org-id <org_id> --email agent@local.dev --name Agent --role member   # prints user_id=
         correlic-admin create-api-key --org-id <org_id> --user-id <agent user_id> --name agent --type agent          # prints api_key= (agent)
    5. Put the agent api_key in /etc/correlic/agent.yaml
    6. Start the services:
         systemctl enable --now correlic-api correlic-telemetry correlic-agent correlic-ui-proxy correlic-ui
    7. Open http://localhost:3001 and log in with the dashboard API key or admin@local.dev + password.

STEPS
else
  echo "[correlic] Upgrade — preserving configuration, restarting services..."
  systemctl try-restart correlic-api correlic-telemetry correlic-agent correlic-ui correlic-ui-proxy 2>/dev/null || true
fi
