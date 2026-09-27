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
#   SMOKE_CONTROLLER_URL  The controller port reached directly (e.g. through
#                         `kubectl port-forward`). Enables leg 7, the route
#                         crawl (scripts/check-route-extensions.py), which
#                         cannot run through BASE_URL: nginx fronts only some
#                         paths and does not route /metrics/prometheus.
#                         PROMETHEUS_SCRAPE_TOKEN is passed through to it.
#   SMOKE_CRAWL_DELAY     Seconds between crawl requests. Default: 0.

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

# A 200 alone is not the controller: a proxy with no /health route falls
# through to the SPA, which answers every path with index.html and a 200. The
# controller's body is always `{"status": …}`, so the check reads the body.
read -r status _ body < <(probe GET /health)
if [ "$status" = "200" ] && grep -q '"status"' "$body"; then
    ok "/health → 200 (controller JSON)"
elif [ "$status" = "200" ] && grep -qiE '<!doctype|<html' "$body"; then
    bad "/health → 200 but HTML: answered by the SPA fallback, not the controller (the proxy has no /health route)"
else
    bad "/health → $status (expected 200 with the controller's JSON status body)"
fi
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

# A 101 proves only that /ws reached the controller. The controller refuses a
# disallowed Origin AFTER the upgrade (an immediate close — what a browser shows
# as "WebSocket connection failed"), so the probe goes one frame further: it
# sends graphql-ws `connection_init` with no session and reads the answer.
# `auth-required` = origin accepted, authentication reached. Stdlib Python, like
# leg 7's crawl.
if ! command -v python3 >/dev/null 2>&1; then
    skip "/ws — python3 not found (needed by scripts/lib/ws_probe.py)"
else
    ws_verdict="$(python3 "$(dirname "${BASH_SOURCE[0]}")/lib/ws_probe.py" "$BASE_URL" 2>/dev/null || true)"
    case "$ws_verdict" in
        auth-required|acked)
            ok "/ws → upgraded, Origin accepted, reached authentication ($ws_verdict)" ;;
        closed)
            bad "/ws → upgraded, then closed before authentication: the controller refused Origin $BASE_URL (is it in ALLOWED_ORIGIN?)" ;;
        "http 400"|"http 401"|"http 403")
            ok "/ws → ${ws_verdict#http } (handshake reached controller; auth blocked it as expected without a session)" ;;
        "http 405")
            bad "/ws → 405 (nginx returned 405 — missing /ws location in ConfigMap)" ;;
        *)  bad "/ws → ${ws_verdict:-no answer} (expected an upgrade that reaches authentication)" ;;
    esac
fi

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

# ── 7. Route Extension wiring (package BZ) ───────────────────────────
echo
bold "7. Every mounted route has the axum Extensions it extracts"
if [ -z "${SMOKE_CONTROLLER_URL:-}" ]; then
    skip "SMOKE_CONTROLLER_URL unset — the route crawl needs the controller port, not the public URL"
elif ! command -v python3 >/dev/null 2>&1; then
    skip "python3 not found — route crawl not run"
else
    SMOKE_REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    if ( cd "$SMOKE_REPO_ROOT" && python3 scripts/check-route-extensions.py \
            --controller-url "$SMOKE_CONTROLLER_URL" --delay "${SMOKE_CRAWL_DELAY:-0}" ); then
        ok "no route answered a missing-extension rejection"
    else
        crawl_rc=$?
        if [ "$crawl_rc" -eq 1 ]; then
            bad "a mounted route extracts an Extension its router does not provide (see above)"
        else
            bad "route crawl could not verify (exit $crawl_rc, see above)"
        fi
    fi
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
