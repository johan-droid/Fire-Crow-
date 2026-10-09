#!/usr/bin/env bash
# Unit tests for scripts/dev.sh pure helpers (parsing, guards, redaction).
# No services started, no user files touched: fixtures live in mktemp dirs.
# Run: ./scripts/test-dev.sh   (bash only, no new dependencies)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$HERE/dev.sh"

PASS=0
FAIL=0
ok()   { PASS=$((PASS + 1)); printf 'ok   %s\n' "$1"; }
bad()  { FAIL=$((FAIL + 1)); printf 'FAIL %s\n' "$1"; }
expect_eq() { # expect_eq NAME GOT WANT
  if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1 (got '$2', want '$3')"; fi
}

FIX="$(mktemp -d)"
trap 'rm -rf "$FIX"' EXIT
printf 'A="1"\nB=plain\nC="quoted value"\nA="2"\n# D="commented"\n' > "$FIX/env"

expect_eq "env_value last-wins" "$(env_value "$FIX/env" 'A')" "2"
expect_eq "env_value plain" "$(env_value "$FIX/env" 'B')" "plain"
expect_eq "env_value quoted" "$(env_value "$FIX/env" 'C')" "quoted value"
expect_eq "env_value missing" "$(env_value "$FIX/env" 'ZZZ')" ""
expect_eq "env_value absent file" "$(env_value "$FIX/nope" 'A')" ""

check_url() { # check_url NAME URL WANT_USER WANT_HOST WANT_PORT WANT_NAME
  parse_database_url "$2"
  [[ "${DB_USER:-}" == "$3" ]] && [[ "${DB_HOST:-}" == "$4" ]] \
    && [[ "${DB_PORT:-}" == "$5" ]] && [[ "${DB_NAME:-}" == "$6" ]] \
    && ok "$1" || bad "$1 (got $DB_USER/$DB_HOST/$DB_PORT/$DB_NAME)"
}
check_url "standard url" "postgres://firecrow:s3cret@127.0.0.1:55433/firecrow" \
  "firecrow" "127.0.0.1" "55433" "firecrow"
check_url "default port" "postgres://u:p@localhost/db" "u" "localhost" "5432" "db"
check_url "query stripped" "postgres://u:p@127.0.0.1:5432/db?sslmode=require" \
  "u" "127.0.0.1" "5432" "db"
check_url "bracketed ipv6" "postgres://u:p@[::1]:5432/db" "u" "::1" "5432" "db"

allows() { # allows NAME URL (assert_local_database exits 0)
  parse_database_url "$2"
  if (assert_local_database) 2>/dev/null; then ok "$1"; else bad "$1 (refused loopback)"; fi
}
refuses() { # refuses NAME URL (assert_local_database exits nonzero)
  parse_database_url "$2"
  if (assert_local_database) 2>/dev/null; then bad "$1 (accepted non-loopback!)"; else ok "$1"; fi
}
allows "loopback 127.0.0.1" "postgres://u:p@127.0.0.1:5432/db"
allows "loopback localhost" "postgres://u:p@localhost/db"
allows "loopback [::1]" "postgres://u:p@[::1]/db"
refuses "production-like host" "postgres://u:p@db.internal:5432/firecrow"
refuses "public ip" "postgres://u:p@203.0.113.9/db"
refuses "credential-smuggled host" "postgres://u:p@evil.com#x@127.0.0.1/db"
refuses "at-in-host" "postgres://u:p@127.0.0.1@evil.com/db"
refuses "wrong scheme" "http://127.0.0.1/db"
refuses "empty url" ""
refuses "bare garbage" "not-a-url"

CLOSED_PORT="54329"
if port_open "$CLOSED_PORT"; then bad "closed port reported open"; else ok "closed port reported closed"; fi
node -e 'require("net").createServer().listen(18081,"127.0.0.1")' &
SRV=$!
sleep 1
if port_open "18081"; then ok "open port detected on both families"; else bad "open port missed"; fi
kill "$SRV" 2>/dev/null || true
wait "$SRV" 2>/dev/null || true

sleep 60 &
SLP=$!
# Our own pgid, not $$: this harness is usually not a group leader itself.
ME_PGID="$(ps -o pgid= -p $$ | tr -d '[:space:]')"
if group_is_ours "$ME_PGID" "sleep 60"; then ok "own group recognized"; else bad "own group not recognized"; fi
if group_is_ours "$ME_PGID" "no-such-process-xyz-123"; then bad "foreign pattern accepted"; else ok "foreign pattern rejected"; fi
kill "$SLP" 2>/dev/null || true
wait "$SLP" 2>/dev/null || true

redacted="$(printf '%s\n' \
  'DATABASE_URL="postgres://firecrow:Sup3rSecret@127.0.0.1:55433/firecrow"' \
  'SECRET_KEY="abc123"' \
  'ENCRYPTION_KEY=xyz789' \
  'GEMINI_API_KEY="AIzaKey"' \
  'GITHUB_CLIENT_SECRET=topsecret' \
  '{"status":"up","database":"connected"}' \
  'POSTGRES_USER=firecrow' | redact)"
for secret in "Sup3rSecret" "abc123" "xyz789" "AIzaKey" "topsecret"; do
  [[ "$redacted" == *"$secret"* ]] && bad "secret leaked through redact: $secret" || ok "redacted: ${secret:0:3}…"
done
[[ "$redacted" == *'"status":"up"'* ]] || bad "redact mangled benign output"
[[ "$redacted" == *'POSTGRES_USER=firecrow'* ]] || bad "redact mangled POSTGRES_USER"
[[ "$redacted" == *'postgres://firecrow:[redacted]@'* ]] || bad "redact broke URL shape"
ok "redact preserves benign output"

owns() { # owns NAME LABEL_VALUE IMAGE PORTS (db_owned_by_us exits 0)
  db_owned_by_us "$2" "$3" "$4" && ok "$1" || bad "$1 (should be ours)"
}
foreign() { # foreign NAME LABEL_VALUE IMAGE PORTS (db_owned_by_us exits nonzero)
  db_owned_by_us "$2" "$3" "$4" && bad "$1 (treated as ours!)" || ok "$1"
}
LOOPBACK_PORTS="map[5432/tcp:[{127.0.0.1 55433}]]"
owns "labeled container is ours" "1" "postgres:16-alpine" "map[]"
owns "labeled container regardless of image" "1" "other-image:9" "map[]"
owns "grandfathered pre-label container" "" "postgres:16-alpine" "$LOOPBACK_PORTS"
foreign "unlabeled foreign image" "" "redis:7-alpine" "$LOOPBACK_PORTS"
foreign "no published ports, no label" "" "postgres:16-alpine" "map[]"
foreign "wildcard-bound container" "" "postgres:16-alpine" "map[5432/tcp:[{0.0.0.0 5432}]]"
foreign "wrong label value" "0" "postgres:16-alpine" "$LOOPBACK_PORTS"
foreign "empty everything" "" "" ""

# Refusal messages must stay actionable but never echo the parsed host: a
# crafted URL can smuggle password characters into it (user:p@ss@evil).
parse_database_url 'postgres://u:fakePW123@ss@evil.example/db'
(assert_local_database 2>"$FIX/refuse.err") || true
if grep -qE 'fakePW123|ss@evil' "$FIX/refuse.err"; then
  bad "refusal leaks credential-adjacent text"
else
  ok "refusal hides host/credential text"
fi
grep -q "not loopback" "$FIX/refuse.err" \
  && ok "refusal still actionable" || bad "refusal lost its meaning"

echo ""
echo "pass=$PASS fail=$FAIL"
[[ "$FAIL" == "0" ]]
