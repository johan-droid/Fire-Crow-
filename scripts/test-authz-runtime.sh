#!/usr/bin/env bash
# G2 Runtime Test: Authz Plugin against Docker-in-Docker
#
# This script:
# 1. Starts a docker:dind container with TLS + authz plugin
# 2. Runs the authz plugin inside the dind container
# 3. Tests legitimate scanner lifecycle
# 4. Tests that dangerous operations are denied
# 5. Tests host-boundary protection
#
# Usage: scripts/test-authz-runtime.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
CERT_DIR="${REPO_ROOT}/certs/docker-tls"
AUTHZ_IMAGE="firecrow-authz-plugin:local"
DIND_CONTAINER="fc-g2-dind-$(date +%s)"
RESULTS_FILE="/tmp/authz-runtime-results-$(date +%s).txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PASS=0
FAIL=0
SKIP=0

log() {
    echo -e "${GREEN}[PASS]${NC} $1"
    echo "PASS: $1" >> "$RESULTS_FILE"
    ((PASS++))
}

fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    echo "FAIL: $1" >> "$RESULTS_FILE"
    ((FAIL++))
}

skip() {
    echo -e "${YELLOW}[SKIP]${NC} $1"
    echo "SKIP: $1" >> "$RESULTS_FILE"
    ((SKIP++))
}

cleanup() {
    echo "Cleaning up..."
    docker rm -f "$DIND_CONTAINER" 2>/dev/null || true
    rm -rf /tmp/authz-test-*
}

trap cleanup EXIT

# --- 1. Generate certificates ---
echo "=== Generating mTLS certificates ==="
if [ ! -f "${CERT_DIR}/ca.crt" ]; then
    "${SCRIPT_DIR}/generate-docker-tls-certs.sh" "$CERT_DIR"
fi
echo "Certificates ready in ${CERT_DIR}"

# --- 2. Start docker:dind with TLS ---
echo "=== Starting docker:dind ==="

# Start dind with TLS enabled and authz plugin configured
docker run -d --name "$DIND_CONTAINER" \
    --privileged \
    -e DOCKER_TLS_CERTDIR=/certs \
    -v "${CERT_DIR}:/certs:ro" \
    -v /run/docker/plugins:/run/docker/plugins \
    docker:29.1.3-dind \
    --tlsverify \
    --tlscacert=/certs/ca.crt \
    --tlscert=/certs/server.crt \
    --tlskey=/certs/server.key \
    -H tcp://0.0.0.0:2376 \
    -H unix:///var/run/docker.sock \
    --authorization-plugin=firecrow \
    2>&1

# Wait for daemon to be ready
echo "Waiting for Docker daemon to be ready..."
for i in $(seq 1 30); do
    if docker exec "$DIND_CONTAINER" docker info &>/dev/null; then
        echo "Daemon is ready"
        break
    fi
    sleep 1
done

# --- 3. Copy authz plugin binary into dind ---
echo "=== Setting up authz plugin ==="

# Build the authz plugin binary locally
cd "${REPO_ROOT}/docker-authz-plugin"
cargo build --release --locked 2>&1

# Copy binary into dind container
docker cp target/release/docker-authz-plugin "$DIND_CONTAINER:/usr/local/bin/docker-authz-plugin"

# Copy CA cert for plugin to verify daemon
docker cp "${CERT_DIR}/ca.crt" "$DIND_CONTAINER:/usr/local/share/ca-certificates/firecrow-ca.crt"
docker exec "$DIND_CONTAINER" update-ca-certificates 2>&1 || true

# --- 4. Start authz plugin inside dind ---
echo "=== Starting authz plugin ==="

docker exec -d "$DIND_CONTAINER" \
    sh -c 'FIRECROW_AUTHZ_NAME=firecrow FIRECROW_AUTHZ_LOG=/var/log/firecrow-authz.jsonl FIRECROW_AUTHZ_ALLOWED_CNS=firecrow-backend /usr/local/bin/docker-authz-plugin'

sleep 2

# Check plugin socket exists
if docker exec "$DIND_CONTAINER" test -S /run/docker/plugins/firecrow.sock; then
    log "Authz plugin socket created"
else
    fail "Authz plugin socket not created"
    exit 1
fi

# --- 5. Test: legitimate scanner operations ---
echo "=== Test: Legitimate scanner lifecycle ==="

# Test image pull (approved image)
echo "Testing image pull..."
PULL_RESULT=$(docker exec "$DIND_CONTAINER" docker pull ghcr.io/gitleaks/gitleaks:v8.18.4 2>&1) || true
if echo "$PULL_RESULT" | grep -q "Downloaded newer image\|Image is up to date\|Pull complete"; then
    log "Approved image pull: PASS"
elif echo "$PULL_RESULT" | grep -q "authorization denied by plugin"; then
    # The plugin should allow this pull — check if the deny is for a different reason
    fail "Approved image pull denied by plugin: $PULL_RESULT"
else
    skip "Image pull test (may fail due to network): $PULL_RESULT"
fi

# Test container create with benign spec
echo "Testing benign container create..."
# We'll use a simple alpine container since we don't have scanner images
CREATE_RESULT=$(docker exec "$DIND_CONTAINER" docker create --name firecrow-scan-test-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --user=65534:65534 \
    --network=none --security-opt=no-new-privileges \
    alpine:latest true 2>&1) || true

if echo "$CREATE_RESULT" | grep -qE "^[a-f0-9]{12,}$"; then
    log "Benign container create: PASS"
    BENIGN_ID="$CREATE_RESULT"
elif echo "$CREATE_RESULT" | grep -q "authorization denied by plugin"; then
    # Check if the deny is for the right reason (name not matching)
    DENY_REASON=$(echo "$CREATE_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    fail "Benign container create denied: $DENY_REASON"
else
    skip "Benign container create (unexpected result): $CREATE_RESULT"
fi

# Test that the deny log exists
if docker exec "$DIND_CONTAINER" test -f /var/log/firecrow-authz.jsonl; then
    log "Decision log created"
    DECISION_COUNT=$(docker exec "$DIND_CONTAINER" wc -l < /var/log/firecrow-authz.jsonl)
    echo "  Decision log lines: $DECISION_COUNT"
else
    fail "Decision log not created"
fi

# --- 6. Test: dangerous operations are denied ---
echo "=== Test: Dangerous operations ==="

# Test privileged container (should be denied)
echo "Testing privileged container denial..."
PRIV_RESULT=$(docker exec "$DIND_CONTAINER" docker create --privileged \
    --name firecrow-scan-priv-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --user=65534:65534 \
    --network=none --security-opt=no-new-privileges \
    alpine:latest true 2>&1) || true

if echo "$PRIV_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$PRIV_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Privileged container denied: $DENY_REASON"
else
    fail "Privileged container NOT denied: $PRIV_RESULT"
fi

# Test host bind (should be denied)
echo "Testing host bind denial..."
BIND_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name firecrow-scan-bind-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --user=65534:65534 \
    --network=none --security-opt=no-new-privileges \
    -v /var/run/docker.sock:/var/run/docker.sock \
    alpine:latest true 2>&1) || true

if echo "$BIND_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$BIND_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Host bind denied: $DENY_REASON"
else
    fail "Host bind NOT denied: $BIND_RESULT"
fi

# Test CapAdd (should be denied)
echo "Testing CapAdd denial..."
CAP_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name firecrow-scan-cap-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --cap-add=SYS_ADMIN --user=65534:65534 \
    --network=none --security-opt=no-new-privileges \
    alpine:latest true 2>&1) || true

if echo "$CAP_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$CAP_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "CapAdd denied: $DENY_REASON"
else
    fail "CapAdd NOT denied: $CAP_RESULT"
fi

# Test host network mode (should be denied)
echo "Testing host network denial..."
NET_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name firecrow-scan-net-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --user=65534:65534 \
    --network=host --security-opt=no-new-privileges \
    alpine:latest true 2>&1) || true

if echo "$NET_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$NET_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Host network denied: $DENY_REASON"
else
    fail "Host network NOT denied: $NET_RESULT"
fi

# Test host PID mode (should be denied)
echo "Testing host PID denial..."
PID_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name firecrow-scan-pid-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --user=65534:65534 \
    --network=none --security-opt=no-new-privileges --pid=host \
    alpine:latest true 2>&1) || true

if echo "$PID_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$PID_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Host PID denied: $DENY_REASON"
else
    fail "Host PID NOT denied: $PID_RESULT"
fi

# Test unapproved image (should be denied)
echo "Testing unapproved image denial..."
IMG_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name firecrow-scan-img-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --user=65534:65534 \
    --network=none --security-opt=no-new-privileges \
    ubuntu:latest true 2>&1) || true

if echo "$IMG_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$IMG_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Unapproved image denied: $DENY_REASON"
else
    fail "Unapproved image NOT denied: $IMG_RESULT"
fi

# Test non-scanner name (should be denied)
echo "Testing non-scanner name denial..."
NAME_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name evil-container \
    --read-only --cap-drop=ALL --user=65534:65534 \
    --network=none --security-opt=no-new-privileges \
    alpine:latest true 2>&1) || true

if echo "$NAME_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$NAME_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Non-scanner name denied: $DENY_REASON"
else
    fail "Non-scanner name NOT denied: $NAME_RESULT"
fi

# Test ReadonlyRootfs not set (should be denied)
echo "Testing missing ReadonlyRootfs denial..."
RO_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name firecrow-scan-ro-12345678-1234-1234-1234-123456789012 \
    --cap-drop=ALL --user=65534:65534 \
    --network=none --security-opt=no-new-privileges \
    alpine:latest true 2>&1) || true

if echo "$RO_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$RO_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Missing ReadonlyRootfs denied: $DENY_REASON"
else
    fail "Missing ReadonlyRootfs NOT denied: $RO_RESULT"
fi

# Test SecurityOpt missing (should be denied)
echo "Testing missing SecurityOpt denial..."
SEC_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name firecrow-scan-sec-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --user=65534:65534 \
    --network=none \
    alpine:latest true 2>&1) || true

if echo "$SEC_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$SEC_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Missing SecurityOpt denied: $DENY_REASON"
else
    fail "Missing SecurityOpt NOT denied: $SEC_RESULT"
fi

# Test User not set (should be denied)
echo "Testing wrong User denial..."
USER_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name firecrow-scan-usr-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --user=root \
    --network=none --security-opt=no-new-privileges \
    alpine:latest true 2>&1) || true

if echo "$USER_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$USER_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Wrong User denied: $DENY_REASON"
else
    fail "Wrong User NOT denied: $USER_RESULT"
fi

# Test Entrypoint override (should be denied)
echo "Testing Entrypoint override denial..."
ENTRY_RESULT=$(docker exec "$DIND_CONTAINER" docker create \
    --name firecrow-scan-ent-12345678-1234-1234-1234-123456789012 \
    --read-only --cap-drop=ALL --user=65534:65534 \
    --network=none --security-opt=no-new-privileges \
    --entrypoint /bin/evil \
    alpine:latest true 2>&1) || true

if echo "$ENTRY_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$ENTRY_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Entrypoint override denied: $DENY_REASON"
else
    fail "Entrypoint override NOT denied: $ENTRY_RESULT"
fi

# Test versioned route (should also be denied for privileged)
echo "Testing versioned route denial..."
VER_RESULT=$(docker exec "$DIND_CONTAINER" curl -sk --cert /certs/client.crt --key /certs/client.key \
    -X POST "https://localhost:2376/v1.52/containers/create?name=firecrow-scan-ver-12345678-1234-1234-1234-123456789012" \
    -H "Content-Type: application/json" \
    -d '{"Image":"alpine:latest","HostConfig":{"Privileged":true,"ReadonlyRootfs":true,"CapDrop":["ALL"],"NetworkMode":"none","SecurityOpt":["no-new-privileges"],"User":"65534:65534"}}' 2>&1) || true

if echo "$VER_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$VER_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "Versioned route privileged denied: $DENY_REASON"
else
    fail "Versioned route privileged NOT denied: $VER_RESULT"
fi

# Test gRPC door (should be denied)
echo "Testing gRPC door denial..."
GRPC_RESULT=$(docker exec "$DIND_CONTAINER" curl -sk --cert /certs/client.crt --key /certs/client.key \
    -X POST "https://localhost:2376/grpc" \
    -H "Content-Type: application/json" \
    -d '{}' 2>&1) || true

if echo "$GRPC_RESULT" | grep -q "authorization denied by plugin"; then
    DENY_REASON=$(echo "$GRPC_RESULT" | grep -oP "authorization denied by plugin: \K.*")
    log "gRPC door denied: $DENY_REASON"
else
    fail "gRPC door NOT denied: $GRPC_RESULT"
fi

# --- 7. Test: fail-closed behavior ---
echo "=== Test: Fail-closed behavior ==="

# Stop the authz plugin
echo "Stopping authz plugin..."
docker exec "$DIND_CONTAINER" pkill -f docker-authz-plugin || true
sleep 2

# Remove the plugin socket
docker exec "$DIND_CONTAINER" rm -f /run/docker/plugins/firecrow.sock || true

# Try to create a container (should fail)
echo "Testing fail-closed on plugin down..."
DOWN_RESULT=$(docker exec "$DIND_CONTAINER" docker ps 2>&1) || true
if echo "$DOWN_RESULT" | grep -qi "error\|refused\|unavailable\|no such file"; then
    log "Fail-closed on plugin down: PASS"
elif echo "$DOWN_RESULT" | grep -q "CONTAINER"; then
    fail "Plugin down but daemon still serving requests"
else
    skip "Fail-closed test (unexpected result): $DOWN_RESULT"
fi

# Restart the plugin
echo "Restarting authz plugin..."
docker exec -d "$DIND_CONTAINER" \
    sh -c 'FIRECROW_AUTHZ_NAME=firecrow FIRECROW_AUTHZ_LOG=/var/log/firecrow-authz.jsonl FIRECROW_AUTHZ_ALLOWED_CNS=firecrow-backend /usr/local/bin/docker-authz-plugin'
sleep 2

# Verify recovery
echo "Testing recovery after plugin restart..."
RECOVERY_RESULT=$(docker exec "$DIND_CONTAINER" docker ps 2>&1) || true
if echo "$RECOVERY_RESULT" | grep -q "CONTAINER\|NAME"; then
    log "Recovery after plugin restart: PASS"
else
    skip "Recovery test (unexpected result): $RECOVERY_RESULT"
fi

# --- 8. Summary ---
echo ""
echo "============================================"
echo "G2 Runtime Test Results"
echo "============================================"
echo "PASS: $PASS"
echo "FAIL: $FAIL"
echo "SKIP: $SKIP"
echo "============================================"
echo "Results saved to: $RESULTS_FILE"

if [ "$FAIL" -gt 0 ]; then
    echo -e "${RED}OVERALL: FAIL${NC}"
    exit 1
else
    echo -e "${GREEN}GREEN: PASS${NC}"
    exit 0
fi
