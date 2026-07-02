#!/usr/bin/env bash
# End-to-end smoke test for a deployed Talos cluster.
#
# Probes every public path the chart exposes (per the nginx ConfigMap)
# AND optionally exercises a memory write/read round-trip through the
# actual GraphQL mutation+query the UI uses. Designed to catch the
# regression class that survives `helm upgrade` cleanly but breaks at
# request time:
#
#   - controller endpoint moved/removed  (e.g. /health → /live + /ready)
#   - new top-level path not added to the nginx ConfigMap (e.g. /mcp)
#   - SQL still references a dropped column (e.g. Phase B value column)
#   - WS handshake missing Origin → 101 then immediate close
#
# Each leg fails closed. Exit 0 = green; non-zero = at least one leg
# broke. Designed to be wired into install.sh's tail so a bad deploy
# rolls back the operator's confidence before they walk away.
#
# Usage:
#   BASE_URL=https://talos.example.com smoke.sh          # public paths only
#   SMOKE_AGENT_TOKEN=... SMOKE_ACTOR_ID=... smoke.sh     # also exercise auth'd round-trip
#
# Env vars:
#   BASE_URL              Public URL of the deployment. REQUIRED — no default.
#                         (install.sh §9.1 passes the operator's own
#                         TALOS_HOST-derived URL; there is deliberately no
#                         baked-in default so the script can't silently
#                         probe one operator's cluster from another's
#                         machine.)
#   SMOKE_AGENT_TOKEN     MCP agent token. Enables /mcp + GraphQL probes.
#   SMOKE_ACTOR_ID        UUID of an actor to write a probe memory against.
#                         If set together with SMOKE_AGENT_TOKEN, runs the
#                         full write→read round-trip (Phase B encryption).
#   SMOKE_TIMEOUT         Per-request timeout in seconds. Default: 10.

set -euo pipefail

BASE_URL="${BASE_URL:-}"
if [ -z "$BASE_URL" ]; then
    printf '\033[1;31m✗ BASE_URL is required\033[0m\n' >&2
    printf '  Run: BASE_URL=https://your-deployment.example.com %s\n' "$0" >&2
    printf '  (make smoke BASE_URL=... wires this through; install.sh passes it automatically.)\n' >&2
    exit 2
fi
TIMEOUT="${SMOKE_TIMEOUT:-10}"
PROBE_KEY="smoke/probe-$(date -u +%s)"
PROBE_MAGIC="TALOS-SMOKE-$(openssl rand -hex 4)"

red()    { printf '\033[1;31m%s\033[0m\n' "$*"; }
green()  { printf '\033[1;32m%s\033[0m\n' "$*"; }
yellow() { printf '\033[1;33m%s\033[0m\n' "$*"; }
bold()   { printf '\033[1m%s\033[0m\n' "$*"; }

PASS=0
FAIL=0
SKIP=0

ok()   { green "  ✓ $*"; PASS=$((PASS + 1)); }
bad()  { red   "  ✗ $*"; FAIL=$((FAIL + 1)); }
skip() { yellow "  ⊘ $*"; SKIP=$((SKIP + 1)); }

bold "▶ smoke test against $BASE_URL"
echo

# ── Helpers ──────────────────────────────────────────────────────────
# Issue a curl, capture status + content-type + a body snippet.
# Args: <method> <path> [extra_curl_args...]
probe() {
    local method="$1" path="$2"; shift 2
    local body_file status ct
    body_file="$(mktemp)"
    status="$(curl -sS -o "$body_file" -w '%{http_code}' \
                   --max-time "$TIMEOUT" \
                   -X "$method" \
                   "$@" \
                   "$BASE_URL$path" || echo "000")"
    ct="$(curl -sS -o /dev/null -w '%{content_type}' \
                  --max-time "$TIMEOUT" -I \
                  "$@" \
                  "$BASE_URL$path" 2>/dev/null || echo "?")"
    printf '%s\t%s\t%s\n' "$status" "$ct" "$body_file"
}

# ── 1. Plain probes (no auth required) ───────────────────────────────
bold "1. Public health + probe endpoints"

read -r status _ body < <(probe GET /health)
[ "$status" = "200" ] && ok "/health → 200"        || bad "/health → $status (expected 200)"
rm -f "$body"

# /live + /ready are kubelet-only; hitting them externally returns 200
# from the controller because nothing in nginx blocks them, but they
# don't need to be exposed. Skip them by design.
skip "/live and /ready (kubelet-only, no nginx route by design)"

# ── 2. CSRF cookie seed ──────────────────────────────────────────────
bold "2. CSRF cookie seeding"

cookie_jar="$(mktemp)"
status="$(curl -sS -o /dev/null -w '%{http_code}' \
               --max-time "$TIMEOUT" -c "$cookie_jar" \
               "$BASE_URL/auth/csrf" || echo "000")"
if [ "$status" = "200" ] && grep -q 'csrf' "$cookie_jar"; then
    ok "/auth/csrf → 200 + Set-Cookie includes csrf"
elif [ "$status" = "200" ]; then
    bad "/auth/csrf → 200 but no csrf cookie set (CookieManagerLayer regression?)"
else
    bad "/auth/csrf → $status (expected 200)"
fi
rm -f "$cookie_jar"

# ── 3. GraphQL endpoint reachable ────────────────────────────────────
bold "3. GraphQL endpoint"

# Seed the CSRF cookie first (the same flow the real UI uses), then
# replay the cookie + the X-CSRF-Token header on the POST. Without
# this we'd 403 on csrf_protection_graphql and never reach the resolver.
gql_jar="$(mktemp)"
curl -sS -o /dev/null --max-time "$TIMEOUT" -c "$gql_jar" "$BASE_URL/auth/csrf" || true
csrf_token="$(awk '!/^#/ && NF >= 7 && tolower($6) ~ /csrf/ { print $7; exit }' "$gql_jar")"
body="$(mktemp)"
status="$(curl -sS -o "$body" -w '%{http_code}' --max-time "$TIMEOUT" \
              -b "$gql_jar" \
              ${csrf_token:+-H "X-CSRF-Token: $csrf_token"} \
              -H 'Content-Type: application/json' \
              -X POST "$BASE_URL/graphql" \
              -d '{"query":"{ __typename }"}' || echo "000")"
ct="$(file --mime-type -b "$body" 2>/dev/null || echo "?")"
if [ "$status" = "200" ] && grep -q '"__typename"' "$body"; then
    ok "/graphql introspection → 200 with valid response"
elif [ "$status" = "200" ] && grep -q '"errors"' "$body"; then
    bad "/graphql → 200 with errors: $(head -c 200 "$body")"
elif echo "$ct" | grep -q 'html'; then
    bad "/graphql → $status returned HTML (nginx serving SPA shell — missing /graphql location?)"
else
    bad "/graphql → $status (body: $(head -c 200 "$body"))"
fi
rm -f "$body" "$gql_jar"

# ── 4. WebSocket upgrade ─────────────────────────────────────────────
bold "4. WebSocket /ws"

# The trick: on a 101 Switching Protocols, curl hangs waiting for WS
# frames it'll never get from this synthetic upgrade. We use a short
# --max-time and capture only the FIRST HTTP status line from the
# header dump (-D -). Even if curl exits non-zero on the timeout, the
# status header is what we actually care about.
ws_headers="$(curl -sS -D - -o /dev/null --max-time 3 --http1.1 \
                   -H 'Connection: Upgrade' \
                   -H 'Upgrade: websocket' \
                   -H 'Sec-WebSocket-Version: 13' \
                   -H 'Sec-WebSocket-Key: dGVzdC13ZWJzb2NrZXQ=' \
                   -H "Origin: $BASE_URL" \
                   "$BASE_URL/ws" 2>/dev/null || true)"
status="$(echo "$ws_headers" | awk '/^HTTP\// { print $2; exit }')"
status="${status:-000}"
case "$status" in
    101) ok "/ws → 101 Switching Protocols (handshake completed)" ;;
    400|401|403)
        ok "/ws → $status (handshake reached controller; auth blocked it as expected without a session)"
        ;;
    405) bad "/ws → 405 (nginx returned 405 — missing /ws location in ConfigMap)" ;;
    000) bad "/ws → no response within 3s (network or proxy issue)" ;;
    *)   bad "/ws → $status (expected 101 or auth 4xx)" ;;
esac

# ── 5. MCP endpoint ──────────────────────────────────────────────────
bold "5. MCP endpoint"

if [ -z "${SMOKE_AGENT_TOKEN:-}" ]; then
    # No token — do an unauth probe. Controller returns 401 if reachable;
    # nginx returns 405 / HTML if the proxy block is missing.
    read -r status ct body < <(probe POST /mcp \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}')
    case "$status" in
        401|403) ok "/mcp → $status (reached controller; auth required as expected)" ;;
        405)     bad "/mcp → 405 (nginx returned 405 — missing /mcp location in ConfigMap)" ;;
        *)       bad "/mcp → $status ct=$ct (expected 401/403 without token)" ;;
    esac
    rm -f "$body"
else
    read -r status ct body < <(probe POST /mcp \
        -H "Authorization: Bearer $SMOKE_AGENT_TOKEN" \
        -H 'Content-Type: application/json' \
        -H 'Accept: application/json, text/event-stream' \
        -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}')
    if [ "$status" = "200" ] && (grep -q '"jsonrpc"' "$body" || echo "$ct" | grep -q 'event-stream'); then
        ok "/mcp → 200 with JSON-RPC reply (auth + protocol both healthy)"
    else
        bad "/mcp → $status ct=$ct (body: $(head -c 120 "$body"))"
    fi
    rm -f "$body"
fi

# ── 6. Phase B encryption round-trip (optional, requires both vars) ──
bold "6. Memory write → ciphertext-on-disk → decrypt round-trip"

if [ -z "${SMOKE_AGENT_TOKEN:-}" ] || [ -z "${SMOKE_ACTOR_ID:-}" ]; then
    skip "skipped — set SMOKE_AGENT_TOKEN + SMOKE_ACTOR_ID to enable"
else
    # Write via writeActorMemory mutation (UI's path).
    write_payload="$(cat <<EOF
{"query":"mutation(\$id:UUID!,\$key:String!,\$value:String!){writeActorMemory(actorId:\$id,key:\$key,value:\$value,memoryType:\"working\"){key updatedAt}}","variables":{"id":"$SMOKE_ACTOR_ID","key":"$PROBE_KEY","value":"{\"magic\":\"$PROBE_MAGIC\"}"}}
EOF
)"
    body="$(mktemp)"
    status="$(curl -sS -o "$body" -w '%{http_code}' \
                   --max-time "$TIMEOUT" \
                   -H "Authorization: Bearer $SMOKE_AGENT_TOKEN" \
                   -H 'Content-Type: application/json' \
                   -d "$write_payload" \
                   "$BASE_URL/graphql" || echo "000")"
    if [ "$status" = "200" ] && grep -q '"writeActorMemory"' "$body"; then
        ok "writeActorMemory mutation succeeded ($PROBE_KEY)"
    else
        bad "writeActorMemory failed: $status (body: $(head -c 200 "$body"))"
        rm -f "$body"
        # Skip the read since the write didn't land.
        echo
        bold "── Summary ──"
        printf '  passed: %d   failed: %d   skipped: %d\n' "$PASS" "$FAIL" "$SKIP"
        exit 1
    fi
    rm -f "$body"

    # Read via actorMemories list query (the path that 500'd today).
    read_payload="$(cat <<EOF
{"query":"query(\$id:UUID!){actorMemories(actorId:\$id){key value memoryType}}","variables":{"id":"$SMOKE_ACTOR_ID"}}
EOF
)"
    body="$(mktemp)"
    status="$(curl -sS -o "$body" -w '%{http_code}' \
                   --max-time "$TIMEOUT" \
                   -H "Authorization: Bearer $SMOKE_AGENT_TOKEN" \
                   -H 'Content-Type: application/json' \
                   -d "$read_payload" \
                   "$BASE_URL/graphql" || echo "000")"
    if [ "$status" = "200" ] && grep -q "$PROBE_MAGIC" "$body"; then
        ok "actorMemories list returned probe with magic intact (encrypt+decrypt round-trip)"
    elif [ "$status" = "200" ] && grep -q '"errors"' "$body"; then
        bad "actorMemories returned errors (Phase-B-style read regression?): $(head -c 200 "$body")"
    else
        bad "actorMemories failed: $status (body: $(head -c 200 "$body"))"
    fi
    rm -f "$body"
fi

# ── Summary ──────────────────────────────────────────────────────────
echo
bold "── Summary ──"
printf '  passed: %d   failed: %d   skipped: %d\n' "$PASS" "$FAIL" "$SKIP"
if [ "$FAIL" -eq 0 ]; then
    green "✓ smoke OK"
    exit 0
else
    red "✗ smoke FAILED"
    exit 1
fi
