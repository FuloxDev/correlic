#!/bin/bash
set -euo pipefail

# Generate mTLS certificates for Correlic services
# Usage: bash generate-certs.sh [output_dir]

CERT_DIR="${1:-/opt/correlic/certs}"
mkdir -p "$CERT_DIR"

echo "[certs] Generating mTLS certificates in $CERT_DIR..."

# Generate CA (10 year validity)
openssl genrsa -out "$CERT_DIR/ca.key" 4096 2>/dev/null
openssl req -new -x509 -days 3650 -key "$CERT_DIR/ca.key" \
  -out "$CERT_DIR/ca.crt" -subj "/CN=Correlic CA" 2>/dev/null

# Generate server certificate (backend API + telemetry)
openssl genrsa -out "$CERT_DIR/server.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/server.key" \
  -out "$CERT_DIR/server.csr" -subj "/CN=correlic-backend" 2>/dev/null

cat > "$CERT_DIR/server-ext.cnf" <<EOF
authorityKeyIdentifier=keyid,issuer
basicConstraints=CA:FALSE
subjectAltName=DNS:localhost,DNS:backend-api,DNS:backend-tel,DNS:correlic-backend,IP:127.0.0.1
EOF

openssl x509 -req -in "$CERT_DIR/server.csr" -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/server.crt" \
  -days 3650 -extfile "$CERT_DIR/server-ext.cnf" 2>/dev/null

# Generate client certificate (agent + proxy)
openssl genrsa -out "$CERT_DIR/client.key" 2048 2>/dev/null
openssl req -new -key "$CERT_DIR/client.key" \
  -out "$CERT_DIR/client.csr" -subj "/CN=correlic-agent" 2>/dev/null

openssl x509 -req -in "$CERT_DIR/client.csr" -CA "$CERT_DIR/ca.crt" \
  -CAkey "$CERT_DIR/ca.key" -CAcreateserial -out "$CERT_DIR/client.crt" \
  -days 3650 2>/dev/null

# Cleanup temp files
rm -f "$CERT_DIR"/*.csr "$CERT_DIR"/*.cnf "$CERT_DIR"/*.srl

chmod 600 "$CERT_DIR"/*.key
chmod 644 "$CERT_DIR"/*.crt

echo "[certs] Done: CA + server + client certificates generated"
