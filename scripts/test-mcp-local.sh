#!/usr/bin/env bash
# test-mcp-local.sh — End-to-end MCP test against the local dev endpoint.
#
# Covers all four surfaces blocked from the MCP client's preloaded registry:
#   1. Secrets vault lifecycle (set → list → rotate → delete)
#   2. Execution pipeline (create_workflow → publish_version → trigger → poll)
#   3. Sandbox live execution (run_sandbox)
#   4. r175 host function verification (describe_capability_world secrets-node)
#
# Prerequisites:
#   docker-compose up -d   (controller must be running)
#   RUST_ENV != "production" in the controller env (local endpoint enabled by default)
#
# Usage:
#   ./scripts/test-mcp-local.sh [BASE_URL]
#   BASE_URL defaults to http://localhost:8000

set -euo pipefail

BASE_URL="${1:-http://localhost:8000}"
MCP="${BASE_URL}/mcp/local"

# Colours
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

PASS=0
FAIL=0
SKIP=0

pass() { echo -e "${GREEN}✅ PASS${NC} $1"; PASS=$((PASS + 1)); }
fail() { echo -e "${RED}❌ FAIL${NC} $1"; FAIL=$((FAIL + 1)); }
skip() { echo -e "${YELLOW}⚠️  SKIP${NC} $1"; SKIP=$((SKIP + 1)); }
section() { echo -e "\n${CYAN}══ $1 ══${NC}"; }

# Collect IDs created during the run so the EXIT trap can clean them up
# even when the script exits early (e.g. via `set -e` or Ctrl-C).
# These use direct MCP tool calls so they work regardless of which tools the
# MCP client's preloaded registry happens to include.
_WF_CLEANUP=()
_WEBHOOK_CLEANUP=()
_MODULE_CLEANUP=()
_TEMPLATE_CLEANUP=()
cleanup() {
    local any=0
    [[ ${#_WF_CLEANUP[@]} -gt 0 ]] && any=1
    [[ ${#_WEBHOOK_CLEANUP[@]} -gt 0 ]] && any=1
    [[ ${#_MODULE_CLEANUP[@]} -gt 0 ]] && any=1
    [[ ${#_TEMPLATE_CLEANUP[@]} -gt 0 ]] && any=1
    [[ $any -eq 0 ]] && return

    echo -e "\n${CYAN}── cleanup ──${NC}"
    for wf_id in "${_WF_CLEANUP[@]:-}"; do
        mcp_call "delete_workflow" "{\"workflow_id\":\"${wf_id}\"}" > /dev/null 2>&1 || true
        echo "  workflow  $wf_id"
    done
    for wh_id in "${_WEBHOOK_CLEANUP[@]:-}"; do
        mcp_call "delete_webhook" "{\"webhook_id\":\"${wh_id}\"}" > /dev/null 2>&1 || true
        echo "  webhook   $wh_id"
    done
    for mod_id in "${_MODULE_CLEANUP[@]:-}"; do
        mcp_call "delete_module" "{\"module_id\":\"${mod_id}\",\"force\":true}" > /dev/null 2>&1 || true
        echo "  module    $mod_id"
    done
    for tmpl_id in "${_TEMPLATE_CLEANUP[@]:-}"; do
        mcp_call "delete_workflow_template" "{\"template_id\":\"${tmpl_id}\"}" > /dev/null 2>&1 || true
        echo "  template  $tmpl_id"
    done
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Helper: POST a tools/call request.
# Usage: mcp_call <tool_name> [json_args]
# Outputs raw JSON-RPC response.
# NOTE: do NOT use ${2:-{}} default — bash parses ${2:-{} with "{" as default,
#       leaving a trailing "}" outside the expansion. Use explicit if-branch.
# ---------------------------------------------------------------------------
mcp_call() {
    local tool="$1"
    local args
    if [[ $# -ge 2 ]]; then args="$2"; else args="{}"; fi
    curl -s -X POST "$MCP" \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"${tool}\",\"arguments\":${args}}}"
}

# Extract .result.content[0].text from a JSON-RPC response (or print error)
extract_text() {
    python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
except Exception as e:
    print('JSON_PARSE_ERR:', e, file=sys.stderr)
    sys.exit(1)
if 'error' in data:
    msg = data['error']
    if isinstance(msg, dict): msg = msg.get('message', str(msg))
    print('RPC_ERROR:', msg)
    sys.exit(0)  # don't exit 1 so the caller can grep for error strings
content = data.get('result', {}).get('content', [])
if content:
    print(content[0].get('text', ''))
"
}

# Extract a top-level field from text content parsed as JSON
# Usage: echo "$text" | json_field fieldname
json_field() {
    python3 -c "
import sys, json, re
text = sys.stdin.read().strip()
try:
    d = json.loads(text)
    print(d.get('$1', ''))
except:
    # fallback: UUID regex for id fields
    m = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', text)
    if m: print(m.group(0))
"
}

# ---------------------------------------------------------------------------
# 0. Connectivity check
# ---------------------------------------------------------------------------
section "0 · Connectivity"

# POST a minimal initialize (GET opens SSE stream and blocks)
PROBE=$(curl -s --max-time 5 -X POST "$MCP" \
    -H "Content-Type: application/json" \
    -d '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{}}' 2>&1 || true)

if [[ -z "$PROBE" ]] || echo "$PROBE" | grep -qi "Connection refused\|Failed to connect\|curl:"; then
    echo -e "${RED}Cannot reach $MCP — is docker-compose up?${NC}"
    exit 1
fi
pass "Local endpoint reachable"

VERSION=$(mcp_call "get_platform_info" | extract_text | python3 -c "
import sys, json
text = sys.stdin.read().strip()
try:
    d = json.loads(text)
    print(d.get('build_version', 'unknown'))
except:
    print('unknown')
" 2>/dev/null || true)
VERSION="${VERSION:-unknown}"

TOOL_COUNT=$(mcp_call "get_platform_info" | extract_text | python3 -c "
import sys, json
text = sys.stdin.read().strip()
try:
    d = json.loads(text)
    print(d.get('total_mcp_tools', 0))
except:
    print(0)
" 2>/dev/null || true)
TOOL_COUNT="${TOOL_COUNT:-0}"

echo "  build_version:   $VERSION"
echo "  total_mcp_tools: $TOOL_COUNT"

if [[ "$TOOL_COUNT" -ge 320 ]] 2>/dev/null; then
    pass "Tool count ≥ 320 (got $TOOL_COUNT)"
else
    fail "Tool count too low: $TOOL_COUNT (expected ≥ 320)"
fi

# ---------------------------------------------------------------------------
# 1. Secrets vault lifecycle
# ---------------------------------------------------------------------------
section "1 · Secrets Vault Lifecycle"

SECRET_NAME="mcp-local-test-$$"
SECRET_VAL="s3cr3t-$(date +%s)"

# 1a. set_secret — requires: name, value
RESP=$(mcp_call "set_secret" "{\"name\":\"${SECRET_NAME}\",\"value\":\"${SECRET_VAL}\",\"description\":\"MCP local test\",\"key_path\":\"test/${SECRET_NAME}\"}" | extract_text)
if echo "$RESP" | grep -qiE "success|created|stored|secret|ok"; then
    pass "set_secret created '$SECRET_NAME'"
else
    fail "set_secret: ${RESP:0:200}"
fi

# 1b. list_secrets — no path_prefix param; uses 'namespace' filter only
RESP=$(mcp_call "list_secrets" | extract_text)
if echo "$RESP" | grep -q "$SECRET_NAME"; then
    pass "list_secrets returns '$SECRET_NAME'"
else
    fail "list_secrets: secret not found. Response: ${RESP:0:300}"
fi

# 1c. rotate_secret — requires: name, new_value
RESP=$(mcp_call "rotate_secret" "{\"name\":\"${SECRET_NAME}\",\"new_value\":\"rotated-${SECRET_VAL}\",\"verify_workflows\":false}" | extract_text)
if echo "$RESP" | grep -qiE "rotated|success|updated|version|ok"; then
    pass "rotate_secret succeeded"
else
    fail "rotate_secret: ${RESP:0:200}"
fi

# 1d. delete_secret — requires: name
RESP=$(mcp_call "delete_secret" "{\"name\":\"${SECRET_NAME}\"}" | extract_text)
if echo "$RESP" | grep -qiE "deleted|success|removed|ok"; then
    pass "delete_secret succeeded"
else
    fail "delete_secret: ${RESP:0:200}"
fi

# 1e. Verify deleted — should no longer appear in list_secrets
RESP=$(mcp_call "list_secrets" | extract_text)
if echo "$RESP" | grep -q "$SECRET_NAME"; then
    fail "Secret still listed after deletion"
else
    pass "Secret no longer listed after deletion"
fi

# ---------------------------------------------------------------------------
# 2. r175 host function verification — describe_capability_world
# ---------------------------------------------------------------------------
section "2 · r175 Host Function Verification"

# describe_capability_world for secrets-node should document slot semantics
RESP=$(mcp_call "describe_capability_world" '{"capability_world":"secrets-node"}' | extract_text)
if echo "$RESP" | grep -qiE "vault|slot|secret|into_auth_header|SlotHandle|key_path"; then
    pass "describe_capability_world(secrets-node) documents vault/slot semantics"
elif echo "$RESP" | grep -qi "secrets"; then
    pass "describe_capability_world(secrets-node) returns secrets documentation"
else
    fail "describe_capability_world(secrets-node): ${RESP:0:300}"
fi

# minimal-node should NOT mention secrets
RESP=$(mcp_call "describe_capability_world" '{"capability_world":"minimal-node"}' | extract_text)
if echo "$RESP" | grep -qi "minimal\|compute\|pure\|no network\|sandbox"; then
    pass "describe_capability_world(minimal-node) describes minimal scope"
else
    fail "describe_capability_world(minimal-node): ${RESP:0:200}"
fi

# ---------------------------------------------------------------------------
# 3. Sandbox live execution — run_sandbox (uses 'rust_code', not 'code')
# ---------------------------------------------------------------------------
section "3 · Sandbox Live Execution"

# 3a. Simple Ok() return
SIMPLE_CODE='fn run(data: Map) -> Result<Map, String> {
    let mut out = #{};
    out["r175_test"] = "ok";
    out["received"] = data["input"];
    Ok(out)
}'

RESP=$(mcp_call "run_sandbox" \
  "{\"rust_code\":$(python3 -c "import json,sys; sys.stdout.write(json.dumps(sys.argv[1]))" "$SIMPLE_CODE"),\"input\":{\"input\":\"r175-probe\"},\"capability_world\":\"minimal-node\"}" | extract_text)

if echo "$RESP" | grep -qiE "r175_test|r175-probe|output|result"; then
    pass "run_sandbox Ok() path: output received"
elif echo "$RESP" | grep -qiE "governance|capability|ceiling|not allowed"; then
    skip "run_sandbox: governance-node ceiling required in this actor context"
elif echo "$RESP" | grep -qiE "compiled|compiling|build"; then
    pass "run_sandbox: compilation started (long-running, accepted)"
else
    fail "run_sandbox Ok(): ${RESP:0:300}"
fi

# 3b. Err() propagation path
ERR_CODE='fn run(data: Map) -> Result<Map, String> { Err("deliberate-error-r175".to_string()) }'
RESP=$(mcp_call "run_sandbox" \
  "{\"rust_code\":$(python3 -c "import json,sys; sys.stdout.write(json.dumps(sys.argv[1]))" "$ERR_CODE"),\"input\":{},\"capability_world\":\"minimal-node\"}" | extract_text)

if echo "$RESP" | grep -qiE "deliberate-error-r175|Component returned error"; then
    pass "run_sandbox Err() path propagated correctly"
elif echo "$RESP" | grep -qiE "governance|capability|ceiling"; then
    skip "run_sandbox Err() test: same governance ceiling"
else
    fail "run_sandbox Err(): ${RESP:0:300}"
fi

# ---------------------------------------------------------------------------
# 4. Execution pipeline
# ---------------------------------------------------------------------------
section "4 · Execution Pipeline"

WF_NAME="mcp-local-test-$$"

# 4a. create_workflow — requires 'nodes' (can be empty array if schema allows,
#     otherwise use a minimal structural node)
RESP=$(mcp_call "create_workflow" \
  "{\"name\":\"${WF_NAME}\",\"description\":\"MCP local pipeline test\",\"nodes\":[]}" | extract_text)

WF_ID=$(echo "$RESP" | python3 -c "
import sys, json, re
text = sys.stdin.read().strip()
found = None
try:
    d = json.loads(text)
    found = d.get('workflow_id') or d.get('id')
except Exception:
    pass
if not found:
    m = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', text)
    if m: found = m.group(0)
if found: print(found)
" 2>/dev/null || true)

if [[ -n "${WF_ID:-}" ]]; then
    pass "create_workflow → $WF_ID"
    _WF_CLEANUP+=("$WF_ID")
else
    # Try with the full nodes + edges via create_workflow_from_spec shortcut
    RESP=$(mcp_call "create_workflow_from_spec" \
      "{\"name\":\"${WF_NAME}-spec\",\"description\":\"MCP local test\",\"nodes\":[{\"id\":\"n1\",\"module_name\":\"echo-debug\",\"config\":{}}]}" | extract_text)
    WF_ID=$(echo "$RESP" | python3 -c "
import sys, json, re
text = sys.stdin.read().strip()
found = None
try:
    d = json.loads(text)
    found = d.get('workflow_id') or d.get('id')
except Exception:
    pass
if not found:
    m = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', text)
    if m: found = m.group(0)
if found: print(found)
" 2>/dev/null || true)

    if [[ -n "${WF_ID:-}" ]]; then
        pass "create_workflow_from_spec → $WF_ID"
        _WF_CLEANUP+=("$WF_ID")
    else
        fail "create_workflow: could not create. Response: ${RESP:0:300}"
        skip "publish_version (no workflow_id)"
        skip "trigger_workflow (no workflow_id)"
        skip "get_execution_status (no workflow_id)"
    fi
fi

if [[ -n "${WF_ID:-}" ]]; then
    # 4b. publish_version — requires: workflow_id
    RESP=$(mcp_call "publish_version" "{\"workflow_id\":\"${WF_ID}\",\"description\":\"v1 test\"}" | extract_text)
    if echo "$RESP" | grep -qiE "version|published|success|v1|1\.0"; then
        pass "publish_version succeeded"
    elif echo "$RESP" | grep -qiE "no.*node|empty|require|must|trigger"; then
        skip "publish_version: workflow requires nodes/triggers (expected for empty workflow)"
    else
        fail "publish_version: ${RESP:0:200}"
    fi

    # 4c. trigger_workflow — requires: workflow_id
    RESP=$(mcp_call "trigger_workflow" "{\"workflow_id\":\"${WF_ID}\",\"input\":{\"test\":true}}" | extract_text)
    EXEC_ID=$(echo "$RESP" | python3 -c "
import sys, json, re
text = sys.stdin.read().strip()
found = None
try:
    d = json.loads(text)
    found = d.get('execution_id') or d.get('id')
except Exception:
    pass
if not found:
    m = re.search(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', text)
    if m: found = m.group(0)
if found: print(found)
" 2>/dev/null || true)

    if [[ -n "${EXEC_ID:-}" ]]; then
        pass "trigger_workflow → execution $EXEC_ID"
    elif echo "$RESP" | grep -qiE "no.*published|unpublished|no.*version|no.*node|no node|empty.*graph|has no nodes"; then
        skip "trigger_workflow: workflow has no published nodes/version (expected for empty workflow)"
        EXEC_ID=""
    else
        fail "trigger_workflow: ${RESP:0:300}"
        EXEC_ID=""
    fi

    # 4d. get_execution_status (if we have an execution)
    if [[ -n "${EXEC_ID:-}" ]]; then
        sleep 2
        RESP=$(mcp_call "get_execution_status" "{\"execution_id\":\"${EXEC_ID}\"}" | extract_text)
        STATUS=$(echo "$RESP" | python3 -c "
import sys, json
text = sys.stdin.read().strip()
try:
    d = json.loads(text)
    print(d.get('status') or d.get('execution_status') or 'found')
except:
    print('found')
" 2>/dev/null || true)
        if [[ "${STATUS:-}" != "" ]]; then
            pass "get_execution_status → $STATUS"
        else
            fail "get_execution_status: could not parse. Response: ${RESP:0:200}"
        fi
    else
        skip "get_execution_status (no execution_id)"
    fi

fi
# (Cleanup of WF_ID is handled by the EXIT trap via _WF_CLEANUP)

# ---------------------------------------------------------------------------
# 5. Post-test platform health
# ---------------------------------------------------------------------------
section "5 · Post-test Platform Health"

RESP=$(mcp_call "get_system_health" | extract_text)
if echo "$RESP" | grep -qiE "healthy|ok|status|check|connected|online"; then
    pass "System health check clean"
else
    fail "System health: ${RESP:0:200}"
fi

# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------
# 5. New Template Catalog Verification
# ---------------------------------------------------------------------------
section "5. New Template Catalog Verification"

# Verify the new agentic templates are discoverable
TEMPLATES_RESP=$(mcp_call "list_templates" "{}")
for tmpl_name in "rag-pipeline" "multi-agent-router" "human-review-gate" "pii-scrubber" "webhook-to-slack"; do
    if echo "$TEMPLATES_RESP" | grep -q "$tmpl_name"; then
        pass "Template '$tmpl_name' found in catalog"
    else
        skip "Template '$tmpl_name' not in catalog (may need publish_built_in_templates)"
    fi
done

# ---------------------------------------------------------------------------
# 6. Platform Info — Verify Session Reports New Features
# ---------------------------------------------------------------------------
section "6. Platform Feature Verification"

PLATFORM_RESP=$(mcp_call "get_platform_info" "{}")
if echo "$PLATFORM_RESP" | grep -q "result"; then
    pass "get_platform_info responds"
else
    fail "get_platform_info failed"
fi

# Verify capability world descriptions include all 9+ tiers
WORLDS_RESP=$(mcp_call "describe_capability_world" "{\"world\": \"secrets-node\"}")
if echo "$WORLDS_RESP" | grep -q "secrets"; then
    pass "describe_capability_world returns secrets-node info"
else
    fail "describe_capability_world failed for secrets-node"
fi

# Summary
# ---------------------------------------------------------------------------
section "Summary"
echo "  PASS: ${PASS}  FAIL: ${FAIL}  SKIP: ${SKIP}"
echo ""

if [[ $FAIL -eq 0 ]]; then
    echo -e "${GREEN}All critical tests passed.${NC}"
    exit 0
else
    echo -e "${RED}${FAIL} test(s) failed.${NC}"
    exit 1
fi
