#!/usr/bin/env bash
#
# Fire Crow local development launcher.
#
#   ./scripts/dev.sh check    # tools, config, ports, prerequisites
#   ./scripts/dev.sh setup    # safe first-time setup (never overwrites config)
#   ./scripts/dev.sh start    # postgres container + backend + frontend
#   ./scripts/dev.sh status   # what is running and where
#   ./scripts/dev.sh logs     # tail service logs (secrets redacted)
#   ./scripts/dev.sh smoke    # safe local smoke tests (no scans, no deliveries)
#   ./scripts/dev.sh stop     # stop only what this launcher started
#
# Architecture (verified against the repo, not assumed):
# - Backend runs from backend/ via the repo's own `npm run backend`
#   (`cd backend && cargo run`). It reads backend/.env.local (dotenvy) and
#   applies migrations itself at startup, fatally if the DB is unreachable.
# - Frontend runs via `npm run frontend` (vite :3000, /api proxied to :8000).
# - PostgreSQL runs in an isolated container (postgres:16-alpine, same image
#   as docker-compose.yml) on loopback only. The tracked compose file
#   publishes no host ports, so it cannot serve a local cargo backend.
# - Runtime state (process groups, logs) lives in /tmp/firecrow-dev and never
#   in the repo, so no .gitignore changes are needed.
#
# Safety: strict mode, process-group-scoped stops (never by port or broad
# name), fail-closed production-DB guard, secrets never printed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Per-user state: a shared predictable path would let another local user plant
# stale pgid files. Logs/pgids never enter the repo, so no .gitignore needed.
STATE_DIR="${TMPDIR:-/tmp}/firecrow-dev-$UID"
BACKEND_PGID_FILE="$STATE_DIR/backend.pgid"
FRONTEND_PGID_FILE="$STATE_DIR/frontend.pgid"
BACKEND_LOG="$STATE_DIR/backend.log"
FRONTEND_LOG="$STATE_DIR/frontend.log"
DB_CONTAINER="firecrow-dev-postgres"
DB_IMAGE="postgres:16-alpine"
# Ownership marker: containers created by this launcher carry this label, so
# start/stop never operate a foreign container that merely shares the name.
DB_LABEL_KEY="firecrow-dev-launcher"
DB_LABEL="$DB_LABEL_KEY=1"
BACKEND_PORT="8000"
FRONTEND_PORT="3000"
BACKEND_ENV="$ROOT/backend/.env.local"
FRONTEND_ENV="$ROOT/frontend/.env.local"

log()  { printf '%s\n' "$*"; }
fail() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

need() {
  command -v "$1" >/dev/null 2>&1 || fail "missing required tool: $1"
}

# --- config helpers (names only on output; values never printed) ---

env_value() { # env_value FILE KEY -> value on stdout (empty if absent)
  local file="$1" key="$2" line
  line="$(grep -E "^${key}=" "$file" 2>/dev/null | tail -n 1 || true)"
  line="${line#*=}"
  line="${line%\"}"; line="${line#\"}"
  line="${line%\'}"; line="${line#\'}"
  printf '%s' "$line"
}

# Split postgres://user:pass@host:port/db into globals DB_USER/DB_HOST/DB_PORT/DB_NAME.
# The password is extracted only to hand to `docker run`; it is never echoed.
# Query strings are dropped (container creation takes bare parts; the backend
# keeps using the full URL). IPv6 loopback may be bracketed ([::1]).
parse_database_url() {
  local url="$1" rest
  rest="${url#postgres://}"
  DB_USER="${rest%%:*}"
  rest="${rest#*:}"
  DB_PASS="${rest%%@*}"
  rest="${rest#*@}"
  if [[ "$rest" == \[* ]]; then
    DB_HOST="${rest%%\]*}"
    DB_HOST="${DB_HOST#\[}"
    rest="${rest#*\]}"
  else
    DB_HOST="${rest%%[:/]*}"
    rest="${rest#"$DB_HOST"}"
  fi
  rest="${rest#:}"
  rest="${rest%%\?*}"
  if [[ "$rest" == */* ]]; then
    DB_PORT="${rest%%/*}"
    DB_NAME="${rest#*/}"
  else
    DB_PORT="$rest"
    DB_NAME=""
  fi
  DB_PORT="${DB_PORT:-5432}"
}

assert_local_database() { # fail closed on non-loopback targets
  case "$DB_HOST" in
    localhost | 127.0.0.1 | ::1) ;;
    # Never interpolate $DB_HOST here: a crafted URL can smuggle password
    # characters into the parsed host segment (e.g. user:p@ss@evil.com),
    # and this message reaches stderr/logs unredacted.
    *) fail "DATABASE_URL host is not loopback. Refusing to start: this launcher never targets shared/production databases." ;;
  esac
}

# Ownership decision as a pure function of (label value, image, port bindings)
# so it is unit-testable without docker. Grandfather rule: containers created
# before labels existed carry no label; those are adopted only when the image
# is exactly ours AND a loopback-only port binding is published (the launcher
# always passes `-p 127.0.0.1:...`, never a wildcard). Anything else is
# foreign. (An inspect failure yields empty/empty/empty: foreign, fail closed.)
db_owned_by_us() {
  local label_value="$1" image="$2" ports="$3"
  [[ "$label_value" == "1" ]] && return 0
  [[ -z "$label_value" && "$image" == "$DB_IMAGE" && "$ports" == *"127.0.0.1"* \
    && "$ports" != *"0.0.0.0"* && "$ports" != *"{:: "* ]] && return 0
  return 1
}

# db_container_is_ours -> 0 if $DB_CONTAINER is absent (nothing to guard) or
# is owned by this launcher; 1 if a foreign container holds the name.
db_container_is_ours() {
  local label_value image ports
  docker inspect "$DB_CONTAINER" >/dev/null 2>&1 || return 0
  label_value="$(docker inspect -f "{{index .Config.Labels \"$DB_LABEL_KEY\"}}" "$DB_CONTAINER" 2>/dev/null)"
  image="$(docker inspect -f '{{.Config.Image}}' "$DB_CONTAINER" 2>/dev/null)"
  ports="$(docker inspect -f '{{.HostConfig.PortBindings}}' "$DB_CONTAINER" 2>/dev/null)"
  db_owned_by_us "$label_value" "$image" "$ports"
}

port_open() { # 0 if something listens on localhost:PORT (tries both families)
  (exec 3<>"/dev/tcp/127.0.0.1/$1") >/dev/null 2>&1 && return 0
  (exec 3<>"/dev/tcp/::1/$1") >/dev/null 2>&1
}

pgid_alive() { # pgid_alive PGID -> 0 if the process group still exists
  kill -0 -- "-$1" >/dev/null 2>&1
}

# True only if some member of process group $1 matches $2 (our own command).
# Guards against a recycled pid: a stale pgid file must never kill a group
# that is no longer ours. The member list is captured before grepping so the
# grep process itself can never self-match its own command line.
group_is_ours() {
  command -v ps >/dev/null 2>&1 || return 0
  local members
  members="$(ps -o args= -g "$1" 2>/dev/null)" || return 1
  grep -Eq "$2" <<<"$members"
}

# --- commands ---

cmd_check() {
  local ok=0
  for tool in node npm cargo docker openssl curl; do
    if command -v "$tool" >/dev/null 2>&1; then
      log "ok   tool: $tool"
    else
      log "MISS tool: $tool"; ok=1
    fi
  done
  docker info >/dev/null 2>&1 && log "ok   docker daemon reachable" || { log "MISS docker daemon"; ok=1; }

  for pair in "$BACKEND_ENV:SECRET_KEY" "$BACKEND_ENV:ENCRYPTION_KEY" "$BACKEND_ENV:DATABASE_URL" "$FRONTEND_ENV:VITE_API_URL"; do
    local file="${pair%%:*}" key="${pair##*:}"
    if [[ -f "$file" ]] && [[ -n "$(env_value "$file" "$key")" ]]; then
      log "ok   config: ${file#$ROOT/} has $key"
    else
      log "MISS config: ${file#$ROOT/} missing $key (run ./scripts/dev.sh setup)"; ok=1
    fi
  done

  if [[ -f "$BACKEND_ENV" ]]; then
    parse_database_url "$(env_value "$BACKEND_ENV" 'DATABASE_URL')"
    if [[ -z "${DB_HOST:-}" ]]; then
      log "MISS config: DATABASE_URL is not a postgres:// URL"; ok=1
    else
      case "$DB_HOST" in
        localhost | 127.0.0.1 | ::1) log "ok   database target is loopback ($DB_HOST)" ;;
        # Host value intentionally not echoed: it can carry password fragments
        # from crafted URLs (see assert_local_database).
        *) log "MISS database target is not loopback — start will refuse"; ok=1 ;;
      esac
    fi
  fi

  for port in "$BACKEND_PORT" "$FRONTEND_PORT"; do
    if port_open "$port"; then
      log "WARN port $port is occupied (stop the owner or free it; dev.sh never kills by port)"
    else
      log "ok   port $port is free"
    fi
  done
  [[ -d "$ROOT/frontend/node_modules" ]] && log "ok   frontend dependencies installed" || { log "MISS frontend/node_modules (run ./scripts/dev.sh setup)"; ok=1; }
  return "$ok"
}

cmd_setup() {
  need openssl
  if [[ ! -d "$ROOT/frontend/node_modules" ]]; then
    log "installing frontend dependencies (npm --prefix frontend install)..."
    (cd "$ROOT" && npm --prefix frontend install)
  else
    log "ok   frontend dependencies already installed"
  fi

  if [[ -f "$BACKEND_ENV" ]]; then
    log "keep  existing backend/.env.local (never overwritten by setup)"
    # Pre-launcher files may be group/world-readable; secrets require 600.
    chmod 600 "$BACKEND_ENV"
  else
    log "write backend/.env.local from template with generated secrets..."
    local secret enc
    secret="$(openssl rand -base64 48)"
    enc="$(openssl rand -base64 48)"
    # Restrictive mode before any secret bytes hit the file.
    : > "$BACKEND_ENV" && chmod 600 "$BACKEND_ENV"
    {
      printf '# Local development only. Never commit. See backend/.env.example.\n'
      printf 'SECRET_KEY="%s"\n' "$secret"
      printf 'ENCRYPTION_KEY="%s"\n' "$enc"
      printf 'DATABASE_URL="postgres://firecrow:firecrow@127.0.0.1:55433/firecrow"\n'
      printf 'FRONTEND_URL="http://localhost:3000"\n'
      printf 'CORS_ORIGINS="http://localhost:3000"\n'
      printf 'HOST="127.0.0.1"\n'
      printf 'PORT="8000"\n'
      printf 'BACKEND_BASE_URL="http://localhost:8000"\n'
      printf 'DEBUG="false"\n'
    } >> "$BACKEND_ENV"
    log "wrote backend/.env.local (mode 600). OAuth/AI/email/Telegram keys intentionally omitted: those integrations stay unconfigured locally."
  fi
  for key in SECRET_KEY ENCRYPTION_KEY DATABASE_URL; do
    [[ -n "$(env_value "$BACKEND_ENV" "$key")" ]] || fail "backend/.env.local is missing $key — add it (see backend/.env.example) and re-run setup"
  done

  if [[ -f "$FRONTEND_ENV" ]]; then
    log "keep  existing frontend/.env.local (never overwritten by setup)"
  else
    {
      printf '# Local development only. Never commit. See frontend/.env.example.\n'
      printf 'VITE_API_URL="/api/v1"\n'
      printf 'VITE_APP_NAME="Fire Crow Security Console"\n'
    } > "$FRONTEND_ENV"
    log "wrote frontend/.env.local with VITE_API_URL=/api/v1 (same-origin via vite proxy)"
  fi

  if docker image inspect "$DB_IMAGE" >/dev/null 2>&1; then
    log "ok   database image $DB_IMAGE present"
  else
    log "pull  database image $DB_IMAGE (network access required)..."
    docker pull "$DB_IMAGE"
  fi

  log ""
  log "Human actions dev.sh cannot do for you:"
  log "  - GitHub OAuth locally needs a GitHub OAuth App with callback"
  log "    http://localhost:3000/auth/callback and GITHUB_CLIENT_ID/SECRET in"
  log "    backend/.env.local. Without it, login stays BLOCKED (no bypass added)."
  log "  - Without scanner engines, jobs finish as engine_unavailable."
  log "    That is honest plumbing signal, not a clean audit."
  log "  - GEMINI/email/Telegram keys stay empty: AI narrative and delivery"
  log "    report unconfigured errors instead of sending anything."
}

ensure_db() {
  parse_database_url "$(env_value "$BACKEND_ENV" 'DATABASE_URL')"
  [[ -n "${DB_HOST:-}" ]] || fail "DATABASE_URL missing or unparsable in backend/.env.local"
  assert_local_database
  [[ -n "${DB_USER:-}" && -n "${DB_PASS:-}" ]] || fail "DATABASE_URL must include a user and password for the local container"
  DB_NAME="${DB_NAME:-$DB_USER}"
  local port="${DB_PORT:-55433}"
  if docker inspect "$DB_CONTAINER" >/dev/null 2>&1; then
    db_container_is_ours || fail "container $DB_CONTAINER exists but was not created by this launcher — refusing to start it (docker rename/remove it yourself if it is expendable; its data will NOT be touched by dev.sh)"
    docker start "$DB_CONTAINER" >/dev/null
  else
    # Credentials travel via a 600 env-file, never in argv (ps-visible).
    local env_file
    env_file="$(mktemp "$STATE_DIR/db-env.XXXXXX")"
    chmod 600 "$env_file"
    {
      printf 'POSTGRES_USER=%s\n' "$DB_USER"
      printf 'POSTGRES_PASSWORD=%s\n' "$DB_PASS"
      printf 'POSTGRES_DB=%s\n' "${DB_NAME:-$DB_USER}"
    } > "$env_file"
    log "create isolated database container $DB_CONTAINER (loopback $port only)..."
    if docker run -d --name "$DB_CONTAINER" \
      --label "$DB_LABEL" \
      -p "127.0.0.1:${port}:5432" \
      --env-file "$env_file" \
      "$DB_IMAGE" >/dev/null; then
      rm -f "$env_file"
    else
      rm -f "$env_file"
      fail "could not create database container (see docker output above)"
    fi
  fi
  log "wait  postgres in $DB_CONTAINER..."
  for _ in $(seq 1 60); do
    docker exec "$DB_CONTAINER" pg_isready -U "$DB_USER" >/dev/null 2>&1 && return 0
    sleep 1
  done
  fail "postgres in $DB_CONTAINER did not become ready (docker logs $DB_CONTAINER)"
}

wait_http() { # wait_http URL SECONDS -> 0 on HTTP 2xx
  local url="$1" budget="$2" i
  for ((i = 0; i < budget; i++)); do
    curl -fs -o /dev/null --max-time 3 "$url" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

launch_group() { # launch_group NAME PGID_FILE LOGFILE CMD... (new process group)
  local name="$1" pgid_file="$2" logfile="$3"
  shift 3
  mkdir -p "$STATE_DIR"
  setsid "$@" >>"$logfile" 2>&1 &
  local leader=$!
  printf '%s' "$leader" > "$pgid_file"
  log "start $name (process group $leader, log $logfile)"
}

cmd_start() {
  need docker; need curl
  # Interrupted startup must not orphan groups or linger credential files:
  # stop what this session owns and drop any db env-file mid-creation.
  trap 'rm -f "$STATE_DIR"/db-env.* >/dev/null 2>&1; cmd_stop >/dev/null 2>&1 || true; trap - INT TERM; exit 130' INT TERM
  cmd_check >/dev/null || fail "prerequisites missing — run ./scripts/dev.sh check, then setup"
  if port_open "$BACKEND_PORT" || port_open "$FRONTEND_PORT"; then
    fail "port $BACKEND_PORT or $FRONTEND_PORT is occupied. Free it first; dev.sh never kills by port (ss -ltnp to identify the owner)."
  fi
  ensure_db
  mkdir -p "$STATE_DIR"
  : > "$BACKEND_LOG"
  : > "$FRONTEND_LOG"

  launch_group "backend" "$BACKEND_PGID_FILE" "$BACKEND_LOG" npm --prefix "$ROOT" run backend
  log "wait  backend /api/v1/health/ready (first cargo build can take minutes)..."
  if ! wait_http "http://localhost:$BACKEND_PORT/api/v1/health/ready" 600; then
    log "backend did not become ready — collecting status and stopping what was started"
    cmd_stop >/dev/null 2>&1 || true
    fail "backend failed (./scripts/dev.sh logs backend). Database migrations run at startup and are fatal without a reachable DB."
  fi

  launch_group "frontend" "$FRONTEND_PGID_FILE" "$FRONTEND_LOG" npm --prefix "$ROOT/frontend" run dev
  log "wait  frontend :$FRONTEND_PORT ..."
  wait_http "http://localhost:$FRONTEND_PORT/" 120 || log "WARN frontend not yet up — see ./scripts/dev.sh logs frontend"
  log ""
  log "up    backend  http://localhost:$BACKEND_PORT/api/v1/health/ready"
  log "up    frontend http://localhost:$FRONTEND_PORT/  (API via vite proxy /api -> :$BACKEND_PORT)"
  trap - INT TERM
}

service_status() { # service_status NAME PGID_FILE PORT HEALTH_PATH
  local name="$1" pgid_file="$2" port="$3" health="$4" state="stopped"
  if [[ -f "$pgid_file" ]] && pgid_alive "$(cat "$pgid_file")"; then
    state="running (group $(cat "$pgid_file"))"
  fi
  local http="no response"
  curl -fs -o /dev/null --max-time 3 "http://localhost:${port}${health}" >/dev/null 2>&1 && http="responding"
  log "$name: $state; :$port $health -> $http"
}

cmd_status() {
  mkdir -p "$STATE_DIR"
  service_status "backend " "$BACKEND_PGID_FILE" "$BACKEND_PORT" "/api/v1/health/ready"
  service_status "frontend" "$FRONTEND_PGID_FILE" "$FRONTEND_PORT" "/"
  if docker inspect "$DB_CONTAINER" >/dev/null 2>&1; then
    local running ownership="foreign (not ours; dev.sh will not start/stop it)"
    running="$(docker inspect -f '{{.State.Running}}' "$DB_CONTAINER")"
    db_container_is_ours && ownership="owned by this launcher"
    log "db:      container $DB_CONTAINER present, running=$running, $ownership"
  else
    log "db:      container $DB_CONTAINER absent"
  fi
}

redact() { # redact known secret shapes from log output
  sed -E -e 's#(postgres://[^:/?#]+:)[^@/?#]+@#\1[redacted]@#g' \
         -e 's#((SECRET|PASSWORD|TOKEN|PRIVATE_KEY|API_KEY|ENCRYPTION_KEY)[_A-Z]*["'"'"' ]*[:=] *["'"'"']?)([^ "'"'"',}]+)#\1[redacted]#gi'
}

cmd_logs() {
  local target="${1:-backend}"
  case "$target" in
    backend)  [[ -f "$BACKEND_LOG" ]] && redact < "$BACKEND_LOG" | tail -n 100 || log "no backend log yet" ;;
    frontend) [[ -f "$FRONTEND_LOG" ]] && redact < "$FRONTEND_LOG" | tail -n 100 || log "no frontend log yet" ;;
    db)       docker logs --tail 100 "$DB_CONTAINER" 2>&1 | redact || log "no db container" ;;
    *) fail "usage: ./scripts/dev.sh logs [backend|frontend|db]" ;;
  esac
}

cmd_stop() {
  local stopped=0
  # NAME:PGID_FILE:OWNERSHIP_PATTERN — a recorded pgid is killed only if the
  # group still runs our command (a recycled pid must never hit another group).
  for spec in "backend:$BACKEND_PGID_FILE:npm.*run backend|cargo|firecrow" "frontend:$FRONTEND_PGID_FILE:npm.*run dev|vite|node"; do
    local name="${spec%%:*}" rest="${spec#*:}"
    local file="${rest%%:*}" pattern="${rest#*:}"
    if [[ -f "$file" ]]; then
      local pgid
      pgid="$(cat "$file")"
      if [[ "$pgid" =~ ^[0-9]+$ ]] && pgid_alive "$pgid"; then
        if group_is_ours "$pgid" "$pattern"; then
          kill -- "-$pgid" 2>/dev/null || true
          sleep 1
          pgid_alive "$pgid" && kill -9 -- "-$pgid" 2>/dev/null || true
          log "stop  $name (process group $pgid)"
          stopped=1
        else
          log "skip  $name: process group $pgid no longer looks like ours (stale state?)"
        fi
      fi
      rm -f "$file"
    fi
  done
  # Only the exact container this launcher manages, and only when it is
  # ours by label (or a pre-label container with our exact image); compose
  # services have different names (firecrow-db) and are never touched.
  if docker inspect "$DB_CONTAINER" >/dev/null 2>&1; then
    if ! db_container_is_ours; then
      log "skip  db container $DB_CONTAINER: not created by this launcher (left running)"
    elif [[ "$(docker inspect -f '{{.State.Running}}' "$DB_CONTAINER")" == "true" ]]; then
      docker stop "$DB_CONTAINER" >/dev/null && log "stop  db container $DB_CONTAINER"
      stopped=1
    fi
  fi
  [[ "$stopped" == "0" ]] && log "nothing started by this launcher was running"
  return 0
}

cmd_smoke() {
  local failures=0
  log "== 1/8 configuration =="
  cmd_check || failures=$((failures + 1))
  log "== 2/8 backend process =="
  if [[ -f "$BACKEND_PGID_FILE" ]] && pgid_alive "$(cat "$BACKEND_PGID_FILE")"; then
    log "PASS backend process group alive"
  else
    log "FAIL backend not started (run ./scripts/dev.sh start)"; failures=$((failures + 1))
  fi
  log "== 3/8 database + migrations (via /ready: SELECT 1 + startup migrate) =="
  local ready
  ready="$(curl -fs --max-time 5 "http://localhost:$BACKEND_PORT/api/v1/health/ready" || true)"
  if [[ "$ready" == *'"ready"'* ]]; then
    log "PASS backend ready, database connected (migrations applied at startup)"
  else
    log "FAIL /api/v1/health/ready did not report ready: ${ready:-no response}"; failures=$((failures + 1))
  fi
  log "== 4/8 backend health endpoint =="
  local health_body
  health_body="$(curl -fs --max-time 5 "http://localhost:$BACKEND_PORT/api/v1/health" || true)"
  if [[ "$health_body" == *'"status"'* ]]; then
    log "PASS backend /health returns a status envelope"
  else
    log "FAIL backend /health did not return a status envelope"; failures=$((failures + 1))
  fi
  log "== 5/8 frontend serves + local API base =="
  if curl -fs --max-time 5 "http://localhost:$FRONTEND_PORT/" -o /dev/null; then
    log "PASS frontend :$FRONTEND_PORT serves"
  else
    log "FAIL frontend not serving"; failures=$((failures + 1))
  fi
  log "== 6/8 /api/v1 routing through vite proxy =="
  local via_proxy
  via_proxy="$(curl -fs --max-time 5 "http://localhost:$FRONTEND_PORT/api/v1/health" || true)"
  # Vite serves index.html (200, no status envelope) for unproxied paths, so a
  # bare 2xx is not proof of routing — the backend envelope is.
  if [[ "$via_proxy" == *'"status"'* ]]; then
    log "PASS :$FRONTEND_PORT/api/v1/* reaches the backend"
  else
    log "FAIL proxy routing :$FRONTEND_PORT/api/v1/health"; failures=$((failures + 1))
  fi
  log "== 7/8 frontend regression suite =="
  (cd "$ROOT/frontend" && npm test >/dev/null 2>&1) && log "PASS npm test" || { log "FAIL npm test"; failures=$((failures + 1)); }
  log "== 8/8 frontend production build =="
  (cd "$ROOT/frontend" && npm run build >/dev/null 2>&1) && log "PASS npm run build" || { log "FAIL npm run build"; failures=$((failures + 1)); }
  log ""
  log "BLOCKED (need staging/OAuth/test repo, never mocked as PASS): login, scan submission, SSE monitoring, retry, narrative, delivery."
  if [[ "$failures" -gt 0 ]]; then
    fail "smoke: $failures failing group(s)"
  fi
  log "smoke: all local groups PASS"
}

usage() {
  sed -n '2,14p' "$0"
}

# Sourced by scripts/test-dev.sh for unit tests; executed only when run directly.
if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  case "${1:-}" in
    check)  cmd_check ;;
    setup)  cmd_setup ;;
    start)  cmd_start ;;
    status) cmd_status ;;
    logs)   cmd_logs "${2:-backend}" ;;
    smoke)  cmd_smoke ;;
    stop)   cmd_stop ;;
    *) usage; exit 1 ;;
  esac
fi
