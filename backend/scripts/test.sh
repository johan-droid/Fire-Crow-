#!/usr/bin/env bash
#
# Reproducible backend test run.
#
#   ./scripts/test.sh            # unit + integration
#   ./scripts/test.sh --unit     # skip anything needing a database
#   ./scripts/test.sh --keep     # leave the containers running afterwards
#
# A clean checkout needs nothing else: this brings up PostgreSQL and Redis,
# waits for them to be healthy, runs the suite, then tears them down.
set -euo pipefail

cd "$(dirname "$0")/.."

COMPOSE_FILE="docker-compose.test.yml"
export TEST_DATABASE_URL="${TEST_DATABASE_URL:-postgres://firecrow_test:firecrow_test@127.0.0.1:55433/postgres}"
export TEST_REDIS_URL="${TEST_REDIS_URL:-redis://127.0.0.1:56480}"
export DATABASE_URL="$TEST_DATABASE_URL"

UNIT_ONLY=0
KEEP=0
for arg in "$@"; do
  case "$arg" in
    --unit) UNIT_ONLY=1 ;;
    --keep) KEEP=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if ! command -v docker >/dev/null 2>&1; then
  echo "error: docker is required for the integration suite" >&2
  echo "       install docker, or run: ./scripts/test.sh --unit" >&2
  exit 1
fi

wait_healthy() {
  local svc="$1" tries=0
  until [ "$(docker inspect -f '{{.State.Health.Status}}' "$svc" 2>/dev/null)" = "healthy" ]; do
    tries=$((tries + 1))
    if [ "$tries" -gt 60 ]; then
      echo "error: $svc did not become healthy in time" >&2
      docker logs "$svc" >&2 || true
      exit 1
    fi
    sleep 1
  done
  echo "  $svc healthy"
}

cleanup() {
  if [ "$KEEP" -eq 1 ]; then
    echo "leaving test containers running (--keep)"
    return
  fi
  docker compose -f "$COMPOSE_FILE" down -v >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> starting test services"
docker compose -f "$COMPOSE_FILE" up -d >/dev/null
wait_healthy firecrow-test-pg
wait_healthy firecrow-test-redis

if [ "$UNIT_ONLY" -eq 1 ]; then
  # `#[sqlx::test]` panics when no database URL is resolvable, so --unit must
  # select the database-free targets explicitly rather than relying on skipping.
  echo "==> unit tests only (no database)"
  cargo test --lib --bins
  cargo test --test config_security
  cargo test --test security_regressions
  echo "==> done"
  exit 0
else
  echo "==> running the full suite against PostgreSQL + Redis"
  # Sanity check: fail here with a clear message rather than letting every
  # database test skip and report a false green run.
  if ! docker exec firecrow-test-pg pg_isready -U firecrow_test -d firecrow_test >/dev/null 2>&1; then
    echo "error: test PostgreSQL is not accepting connections" >&2
    exit 1
  fi
fi

cargo test

echo "==> done"
