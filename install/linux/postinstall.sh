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

  cat > /etc/correlic/correlic.env <<EOF
DATABASE_URL=postgres://correlic:CHANGE_ME@localhost:5432/correlic?sslmode=disable
NEO4J_URI=bolt://localhost:7687
NEO4J_USERNAME=neo4j
NEO4J_PASSWORD=CHANGE_ME
TLS_CERT_FILE=${CERT_DIR}/server.crt
TLS_KEY_FILE=${CERT_DIR}/server.key
MTLS_CA_FILE=${CERT_DIR}/ca.crt
LLM_ENCRYPTION_KEY=${LLM_KEY}
ALLOW_API_KEY_AUTH=true
SAMPLING_ENABLED=true
DEFAULT_ORG_ID=default
EOF
  chmod 600 /etc/correlic/correlic.env

  cat > /etc/correlic/agent.yaml <<EOF
backend_url: "https://localhost:8080"
telemetry_url: "https://localhost:8081"
api_key: "PASTE_GENERATED_KEY_HERE"
ebpf_enabled: true
process_exec_enabled: true
file_monitor_enabled: true
network_monitor_enabled: true
dns_monitor_enabled: true
block_enabled: true
tls_ca_file: "${CERT_DIR}/ca.crt"
tls_client_cert_file: "${CERT_DIR}/client.crt"
tls_client_key_file: "${CERT_DIR}/client.key"
EOF
  chmod 600 /etc/correlic/agent.yaml

  cat > /etc/correlic/ui-proxy.env <<EOF
PORT=8788
BACKEND_API=https://localhost:8080
BACKEND_TELEMETRY=https://localhost:8081
MTLS_CA=${CERT_DIR}/ca.crt
MTLS_CERT=${CERT_DIR}/client.crt
MTLS_KEY=${CERT_DIR}/client.key
EOF
  chmod 600 /etc/correlic/ui-proxy.env

  echo ""
  echo "  [correlic] Package installed. Next steps:"
  echo ""
  echo "    1. Install PostgreSQL 16+ and Neo4j 5+ if not already present"
  echo "    2. Edit /etc/correlic/correlic.env with your database credentials"
  echo "    3. Run migrations: correlic-admin migrate up"
  echo "    4. Create org:     correlic-admin create-org --name default            (prints org_id)"
  echo "    5. Create a key:   correlic-admin create-service-account --org-id <org_id> --email agent@localhost --role admin   (prints user_id)"
  echo "                       correlic-admin create-api-key --org-id <org_id> --user-id <user_id> --name local        (prints api_key)"
  echo "    6. Put the api_key in /etc/correlic/agent.yaml and in /etc/correlic/api-key.env as API_KEY=<key>"
  echo "    7. Start services: systemctl start correlic-api correlic-telemetry correlic-agent correlic-ui correlic-ui-proxy"
  echo ""
  echo "    Log in to the dashboard with that API key."
  echo ""
else
  echo "[correlic] Upgrade — preserving configuration, restarting services..."
  systemctl try-restart correlic-api correlic-telemetry correlic-agent correlic-ui correlic-ui-proxy 2>/dev/null || true
fi
