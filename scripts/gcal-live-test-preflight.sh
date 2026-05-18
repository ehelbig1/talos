#!/usr/bin/env bash
#
# Automated pre-flight for the gcal live integration test.
# Runs every check that doesn't require a real OAuth'd Google account.
#
# What this DOES exercise:
#   - ngrok tunnel reachability
#   - controller health endpoint
#   - webhook token boundary (invalid / missing / valid-stale / wrong-channel)
#   - integration_state table reachability
#   - audit log readability
#
# What this does NOT exercise (needs manual step-through per docs/gcal-live-test.md):
#   - OAuth consent flow
#   - Real watch-channel creation against Google's API
#   - Real calendar event → push → dispatch pipeline
#
# Usage:
#   bash scripts/gcal-live-test-preflight.sh [base_url]
#
# If no base_url is given, tries $BASE_URL, then https://localhost:8000 (local-only).
# Pass your ngrok URL as arg 1 to exercise the full chain.

set -euo pipefail

BASE_URL="${1:-${BASE_URL:-http://localhost:8000}}"
PASS=0
FAIL=0

pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }

echo "▶ gcal live-test preflight against $BASE_URL"
echo ""

# ---------------------------------------------------------------------------
# 1. Controller health
# ---------------------------------------------------------------------------
echo "1. Controller health"
if curl -sSf --max-time 5 "$BASE_URL/health" >/dev/null 2>&1; then
    pass "controller responds at $BASE_URL/health"
else
    fail "controller unreachable at $BASE_URL"
    echo "     → is docker compose up? is ngrok running?"
    exit 1
fi

# ---------------------------------------------------------------------------
# 2. Admin ops gate (needed for the watch create + stop-all steps)
# ---------------------------------------------------------------------------
echo ""
echo "2. Admin ops gate"
GATE=$(docker exec talos-controller sh -c 'echo -n "$ENABLE_ADMIN_OPS"' 2>/dev/null || true)
if [[ "$GATE" == "1" || "$GATE" == "true" ]]; then
    pass "ENABLE_ADMIN_OPS=$GATE (admin harness endpoints active)"
else
    fail "ENABLE_ADMIN_OPS not set — admin harness endpoints are 404"
    echo "     → add ENABLE_ADMIN_OPS=1 to .env + recreate controller"
fi
ADMIN_LEN=$(docker exec talos-controller sh -c 'echo -n "$ADMIN_SECRET_KEY" | wc -c' 2>/dev/null || echo 0)
if [[ "$ADMIN_LEN" -ge 16 ]]; then
    pass "ADMIN_SECRET_KEY is $ADMIN_LEN chars (≥16 required)"
else
    fail "ADMIN_SECRET_KEY missing or too short ($ADMIN_LEN chars; ≥16 required)"
fi

# ---------------------------------------------------------------------------
# 3. WORKER_SHARED_KEY is set
# ---------------------------------------------------------------------------
echo ""
echo "3. WORKER_SHARED_KEY"
KEY_HEX=$(docker exec talos-controller sh -c 'echo -n "$WORKER_SHARED_KEY"' 2>/dev/null || true)
if [[ -z "$KEY_HEX" ]]; then
    fail "WORKER_SHARED_KEY not set in controller container"
    exit 1
fi
if [[ ${#KEY_HEX} -lt 32 ]]; then
    fail "WORKER_SHARED_KEY too short (${#KEY_HEX} hex chars); must be ≥32 hex = 16 bytes"
    exit 1
fi
pass "WORKER_SHARED_KEY is ${#KEY_HEX} hex chars (≥32 required)"

# ---------------------------------------------------------------------------
# 3. Signed-token boundary
# ---------------------------------------------------------------------------
echo ""
echo "4. Webhook token verification boundary"

# Generate a valid token for a fake user + channel.
GEN_OUTPUT=$(python3 <<PY
import hmac, hashlib, base64, uuid
key = bytes.fromhex("$KEY_HEX")
user = uuid.uuid4()
channel = "preflight-channel-${RANDOM}"
msg = b"gcal-webhook" + user.bytes + channel.encode()
tag = hmac.new(key, msg, hashlib.sha256).digest()[:16]
token = base64.urlsafe_b64encode(user.bytes + tag).rstrip(b"=").decode()
print(f"{channel}|{token}")
PY
)
IFS="|" read CHANNEL TOKEN <<< "$GEN_OUTPUT"

hit() {
    local ch="$1" tok="$2"
    local args=(-X POST "$BASE_URL/api/google-calendar/webhook"
                -H "X-Goog-Channel-ID: $ch"
                -H "X-Goog-Resource-State: exists"
                -H "X-Goog-Resource-ID: preflight-res")
    [[ -n "$tok" ]] && args+=(-H "X-Goog-Channel-Token: $tok")
    curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${args[@]}"
}

code=$(hit "$CHANNEL" "INVALID_TOKEN")
[[ "$code" == "403" ]] && pass "invalid token → 403" || fail "invalid token → $code (expected 403)"

code=$(hit "$CHANNEL" "")
[[ "$code" == "403" ]] && pass "missing token → 403" || fail "missing token → $code (expected 403)"

code=$(hit "$CHANNEL" "$TOKEN")
[[ "$code" == "200" ]] && pass "valid token + stale channel → 200" || fail "valid token + stale channel → $code (expected 200)"

code=$(hit "DIFFERENT_CHANNEL" "$TOKEN")
[[ "$code" == "403" ]] && pass "channel-id replay attack → 403" || fail "channel-id replay → $code (expected 403)"

# ---------------------------------------------------------------------------
# 4. integration_state table reachable
# ---------------------------------------------------------------------------
echo ""
echo "5. integration_state table reachability"
if docker exec talos-postgres psql -U talos -d talos -c \
    "SELECT count(*) FROM integration_state WHERE integration_name = 'gcal';" \
    >/dev/null 2>&1; then
    ROW_COUNT=$(docker exec talos-postgres psql -U talos -d talos -tAc \
        "SELECT count(*) FROM integration_state WHERE integration_name = 'gcal';")
    pass "integration_state reachable (current gcal row count: $ROW_COUNT)"
else
    fail "cannot query integration_state table"
fi

# ---------------------------------------------------------------------------
# 5. Audit log reachable
# ---------------------------------------------------------------------------
echo ""
echo "6. google_calendar_audit_log reachability"
if docker exec talos-postgres psql -U talos -d talos -c \
    "SELECT count(*) FROM google_calendar_audit_log;" \
    >/dev/null 2>&1; then
    AUDIT_COUNT=$(docker exec talos-postgres psql -U talos -d talos -tAc \
        "SELECT count(*) FROM google_calendar_audit_log;")
    pass "audit log reachable (current row count: $AUDIT_COUNT)"
else
    fail "cannot query google_calendar_audit_log"
fi

# ---------------------------------------------------------------------------
# 6. ngrok tunnel check (if BASE_URL is external)
# ---------------------------------------------------------------------------
echo ""
echo "7. External reachability"
if [[ "$BASE_URL" =~ ^https?://(localhost|127\.0\.0\.1) ]]; then
    echo "  ℹ️  BASE_URL is local; skipping ngrok check. For real Google delivery"
    echo "     you MUST run \`make ngrok\` and re-run this with the public URL."
else
    if curl -sSf --max-time 10 "$BASE_URL/health" | grep -q 'ok'; then
        pass "public URL $BASE_URL is reachable from internet"
    else
        fail "public URL $BASE_URL unreachable"
    fi
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "──────────────────────────────────────"
echo "  $PASS passed, $FAIL failed"
echo "──────────────────────────────────────"

if [[ $FAIL -gt 0 ]]; then
    echo ""
    echo "⚠  Pre-flight failed. Fix the above before running the manual steps"
    echo "   in docs/gcal-live-test.md."
    exit 1
fi

echo ""
echo "✅ Pre-flight passed. Now run the manual OAuth + watch + push steps"
echo "   from docs/gcal-live-test.md to complete the live integration test."
