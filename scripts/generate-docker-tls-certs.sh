#!/usr/bin/env bash
# Generate the mTLS certificate material for the T1 Docker authorization topology.
#
# Creates:
#   certs/docker-tls/ca.crt          — Certificate Authority (daemon trust anchor)
#   certs/docker-tls/server.crt      — Daemon certificate (CN=docker-daemon)
#   certs/docker-tls/server.key      — Daemon private key
#   certs/docker-tls/client.crt      — Backend client certificate (CN=firecrow-backend)
#   certs/docker-tls/client.key      — Backend private key
#
# Usage: scripts/generate-docker-tls-certs.sh [output-dir]
# Default output dir: certs/docker-tls (relative to repo root)
#
# The generated certs are throwaway development credentials. For production,
# replace with certificates from a proper CA. NEVER commit private keys.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-${SCRIPT_DIR}/certs/docker-tls}"
DAYS=365

mkdir -p "${OUTPUT_DIR}"
cd "${OUTPUT_DIR}"

echo "Generating mTLS certificates in ${OUTPUT_DIR}..."

# CA
openssl genrsa -out ca.key 4096 2>/dev/null
openssl req -new -x509 -days ${DAYS} -key ca.key -out ca.crt \
    -subj "/CN=firecrow-ca/O=Fire Crow" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

# Server (daemon) certificate
openssl genrsa -out server.key 4096 2>/dev/null
openssl req -new -key server.key -out server.csr \
    -subj "/CN=docker-daemon/O=Fire Crow" 2>/dev/null
openssl x509 -req -days ${DAYS} -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt \
    -extfile <(printf "subjectAltName=DNS:docker-daemon,DNS:host.docker.internal,DNS:localhost,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth") 2>/dev/null

# Client (backend) certificate
openssl genrsa -out client.key 4096 2>/dev/null
openssl req -new -key client.key -out client.csr \
    -subj "/CN=firecrow-backend/O=Fire Crow" 2>/dev/null
openssl x509 -req -days ${DAYS} -in client.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client.crt \
    -extfile <(printf "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth") 2>/dev/null

# Clean up intermediates
rm -f *.csr *.srl

# Restrict private key permissions
chmod 600 ca.key server.key client.key
chmod 644 ca.crt server.crt client.crt

echo "Certificates generated:"
ls -la
echo ""
echo "Production deployment: replace with proper CA-signed certificates."
echo "The daemon needs: ca.crt, server.crt, server.key"
echo "The backend needs: ca.crt, client.crt, client.key"
echo "NEVER commit private keys (*.key files)."
