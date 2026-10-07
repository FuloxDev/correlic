#!/usr/bin/env bash
#
# Generate self-signed TLS certificates for local Correlic development.
# Creates: CA cert, server cert (mTLS), client cert (for ui-proxy → backend).
#
# Usage: ./scripts/generate-dev-certs.sh
# Output: .certs/ directory with all cert/key files.

set -euo pipefail

CERT_DIR="${1:-.certs}"
DAYS=365
CN_CA="Correlic Dev CA"
CN_SERVER="localhost"
CN_CLIENT="correlic-ui-proxy"

mkdir -p "$CERT_DIR"

echo "==> Generating CA key + certificate..."
openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 -key "$CERT_DIR/ca.key" -out "$CERT_DIR/ca.crt" \
    -days "$DAYS" -subj "/CN=$CN_CA" 2>/dev/null

echo "==> Generating server key + certificate (for API/telemetry servers)..."
openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/server.key" -out "$CERT_DIR/server.csr" \
    -subj "/CN=$CN_SERVER" 2>/dev/null

# SAN extension for localhost + docker service names
cat > "$CERT_DIR/server-ext.cnf" <<EOF
[v3_req]
subjectAltName = DNS:localhost,DNS:api,DNS:telemetry,IP:127.0.0.1
EOF

openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/server.crt" -days "$DAYS" \
    -extfile "$CERT_DIR/server-ext.cnf" -extensions v3_req 2>/dev/null

echo "==> Generating client key + certificate (for ui-proxy mTLS)..."
openssl genrsa -out "$CERT_DIR/client.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/client.key" -out "$CERT_DIR/client.csr" \
    -subj "/CN=$CN_CLIENT" 2>/dev/null
openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.crt" -CAkey "$CERT_DIR/ca.key" \
    -CAcreateserial -out "$CERT_DIR/client.crt" -days "$DAYS" 2>/dev/null

# Cleanup CSR and temp files
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.cnf "$CERT_DIR"/*.srl

echo ""
echo "Certificates generated in $CERT_DIR/:"
ls -la "$CERT_DIR"/*.{crt,key} 2>/dev/null
echo ""
echo "To use with docker-compose, no extra config needed — volumes mount .certs/ automatically."
echo "To use locally: export TLS_CERT_FILE=$CERT_DIR/server.crt TLS_KEY_FILE=$CERT_DIR/server.key MTLS_CA_FILE=$CERT_DIR/ca.crt"
