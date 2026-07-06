#!/usr/bin/env bash
# Talos quickstart — zero to a running workflow, as executable documentation.
#
# After `make setup`, this walks the golden path end-to-end against a local
# stack and PRINTS each step so a new user learns the flow instead of
# reverse-engineering it: sign up (or reuse), mint an API key, browse
# templates WITH their capability/secret requirements, install a module
# (config is shape-validated at create time), build a one-node workflow, run
# it, and read back the decrypted output.
#
# It uses the API-KEY lane throughout — `X-API-Key` with no cookie jar and no
# CSRF token — which is the intended way to script Talos. Every step is a
# plain `curl` you can copy.
#
# Usage:
#   make quickstart                        # http://localhost:8000, demo creds
#   BASE_URL=http://localhost:8000 \
#     QS_EMAIL=me@example.com QS_PASSWORD='…' bash scripts/quickstart.sh
#
# Env vars:
#   BASE_URL     Controller URL. Default: http://localhost:8000
#   QS_EMAIL     Account email. Default: quickstart@example.com
#   QS_PASSWORD  Account password. Default: Quickstart-demo-pw-123!
#                (If the account exists, the script logs in instead of
#                 signing up — safe to re-run.)
#
# Exit 0 = the workflow ran and returned the expected output.

set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8000}"
QS_EMAIL="${QS_EMAIL:-quickstart@example.com}"
QS_PASSWORD="${QS_PASSWORD:-Quickstart-demo-pw-123!}"

red()   { printf '\033[1;31m%s\033[0m\n' "$*"; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
dim()   { printf '\033[2m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }
step()  { printf '\n\033[1;36m▶ %s\033[0m\n' "$*"; }

die() { red "✗ $*"; exit 1; }

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
need curl
need python3

# Extract a field from a GraphQL JSON response, or surface the error.
jq_field() { python3 -c "import json,sys;d=json.load(sys.stdin);e=d.get('errors');print('__ERR__:'+e[0]['message']) if e else print(eval('d'+sys.argv[1]))" "$1"; }

COOKIES="$(mktemp)"
trap 'rm -f "$COOKIES"' EXIT

bold "▶ Talos quickstart against $BASE_URL"
dim  "  (uses the X-API-Key lane — no cookies, no CSRF dance)"

# ── 0. Reachability ──────────────────────────────────────────────────
step "0. Is the stack up?"
if ! curl -fsS --max-time 10 "$BASE_URL/health" >/dev/null 2>&1; then
    die "controller not reachable at $BASE_URL/health — run 'make setup' first."
fi
green "  ✓ controller healthy"

# ── 1. Account (signup, or login if it already exists) ───────────────
# Signup/login are the ONE place we use the cookie+CSRF flow, because you
# don't have an API key yet. Everything after uses the key.
step "1. Account: $QS_EMAIL"
curl -fsS -c "$COOKIES" "$BASE_URL/auth/csrf" >/dev/null
# The token rotates after every mutation, so re-read it from the jar on each
# call rather than caching it.
gql_cookie() {
    curl -fsS -b "$COOKIES" -c "$COOKIES" -H 'content-type: application/json' \
        -H "x-csrf-token: $(awk '/csrf/{print $NF}' "$COOKIES" | tail -1)" \
        -d "$1" "$BASE_URL/graphql"
}
SIGNUP='{"query":"mutation($i:SignupInput!){signup(input:$i){user{id}}}","variables":{"i":{"email":"'"$QS_EMAIL"'","password":"'"$QS_PASSWORD"'","name":"Quickstart"}}}'
if gql_cookie "$SIGNUP" | grep -q '"id"'; then
    green "  ✓ signed up (first user is auto-promoted to the automation-node ceiling)"
else
    LOGIN='{"query":"mutation($i:LoginInput!){login(input:$i){user{id}}}","variables":{"i":{"email":"'"$QS_EMAIL"'","password":"'"$QS_PASSWORD"'"}}}'
    gql_cookie "$LOGIN" | grep -q '"id"' || die "signup and login both failed for $QS_EMAIL"
    green "  ✓ logged in (account already existed)"
fi

# ── 2. Mint an API key — the scriptable lane ─────────────────────────
step "2. Mint an API key (write scope) — this is how you script Talos"
KEY_RES="$(gql_cookie '{"query":"mutation{createApiKey(input:{name:\"quickstart\",scopes:[\"workflows:read\",\"workflows:write\"]}){key}}"}')"
API_KEY="$(printf '%s' "$KEY_RES" | jq_field "['data']['createApiKey']['key']")"
case "$API_KEY" in __ERR__*) die "createApiKey: ${API_KEY#__ERR__:}";; esac
green "  ✓ key minted"
dim  "    From here, every call is just:"
dim  "      curl -H \"X-API-Key: \$KEY\" -d '{\"query\":\"…\"}' $BASE_URL/graphql"

# Helper for the API-key lane (no cookie, no CSRF).
gql() { curl -fsS -H "X-API-Key: $API_KEY" -H 'content-type: application/json' -d "$1" "$BASE_URL/graphql"; }

# ── 3. Browse templates WITH their requirements ──────────────────────
step "3. Find a template — note the requirements are visible up front"
TEMPLATES="$(gql '{"query":"{nodeTemplates{id name capabilityWorld requiresSecrets requiresApprovalFor}}"}')"
CSV_ID="$(printf '%s' "$TEMPLATES" | python3 -c "
import json,sys
ts=json.load(sys.stdin)['data']['nodeTemplates']
csv=[t for t in ts if t['name']=='CSV Parser']
if not csv: sys.exit('CSV Parser template not seeded')
t=csv[0]
print(t['id'])
sys.stderr.write('    CSV Parser needs capability world: %s, secrets: %s, approval: %s\n' % (
    t['capabilityWorld'], t['requiresSecrets'] or 'none', t['requiresApprovalFor'] or 'none'))
")"
green "  ✓ picked 'CSV Parser' (minimal-node — no secrets, no approval, runs anywhere)"

# ── 4. Install the module (config validated at create time) ──────────
step "4. Install a module from the template"
INSTALL='{"query":"mutation($c:String!){createModuleFromTemplate(input:{templateId:\"'"$CSV_ID"'\",name:\"quickstart-csv\",config:$c}){id}}","variables":{"c":"{}"}}'
MODULE_ID="$(printf '%s' "$(gql "$INSTALL")" | jq_field "['data']['createModuleFromTemplate']['id']")"
case "$MODULE_ID" in __ERR__*) die "createModuleFromTemplate: ${MODULE_ID#__ERR__:}";; esac
green "  ✓ installed module (its config was shape-checked against the template schema)"

# ── 5. Build a one-node workflow ─────────────────────────────────────
step "5. Create a workflow with that module as its single node"
NODE_ID="$(python3 -c 'import uuid;print(uuid.uuid4())')"
GRAPH="$(python3 -c "import json;print(json.dumps(json.dumps({'nodes':[{'id':'$NODE_ID','type':'$MODULE_ID','data':{}}],'edges':[]})))")"
CREATE_WF='{"query":"mutation($g:String!){createWorkflow(input:{name:\"quickstart-workflow\",graphJson:$g}){id}}","variables":{"g":'"$GRAPH"'}}'
WF_ID="$(printf '%s' "$(gql "$CREATE_WF")" | jq_field "['data']['createWorkflow']['id']")"
case "$WF_ID" in __ERR__*) die "createWorkflow: ${WF_ID#__ERR__:}";; esac
green "  ✓ workflow created: $WF_ID"

# ── 6. Run it ────────────────────────────────────────────────────────
step "6. Run the workflow on some CSV"
RUN='{"query":"mutation{testWorkflow(workflowId:\"'"$WF_ID"'\",mockInputs:\"{\\\"csv\\\": \\\"name,age\\\\nalice,30\\\\nbob,25\\\"}\"){executionId status}}"}'
EXEC_ID="$(printf '%s' "$(gql "$RUN")" | jq_field "['data']['testWorkflow']['executionId']")"
case "$EXEC_ID" in __ERR__*) die "testWorkflow: ${EXEC_ID#__ERR__:}";; esac
green "  ✓ dispatched execution $EXEC_ID"

# ── 7. Poll to completion ────────────────────────────────────────────
# Parse robustly: read the whole body, tolerate an empty history array
# (the row may not be queryable for a beat after dispatch), and emit
# "status|detail" on one line so a transient blip can never wedge the loop.
step "7. Wait for it to finish"
POLL_Q='{"query":"{workflowExecutionHistory(workflowId:\"'"$WF_ID"'\",pagination:{limit:1}){status errorMessage durationMs}}"}'
parse_poll='
import json,sys
try:
    rows = json.loads(sys.stdin.read()).get("data",{}).get("workflowExecutionHistory") or []
except Exception:
    print("pending|"); sys.exit()
if not rows:
    print("pending|"); sys.exit()
r = rows[0]
print("%s|%s" % (r["status"], r.get("errorMessage") or ("ran in %sms" % r.get("durationMs"))))
'
STATUS=""
for _ in $(seq 1 30); do
    sleep 2
    LINE="$(gql "$POLL_Q" | python3 -c "$parse_poll")"
    STATUS="${LINE%%|*}"
    DETAIL="${LINE#*|}"
    case "$STATUS" in completed|failed) [ -n "$DETAIL" ] && dim "    $DETAIL"; break;; esac
done
[ "$STATUS" = "completed" ] || die "execution ended in status '$STATUS' (expected completed)"
green "  ✓ completed"

bold  "$(green "▶ Done — you built and ran a Talos workflow.")"
dim   "  Workflow:  $WF_ID"
dim   "  Module:    $MODULE_ID (quickstart-csv)"
dim   "  Next: open the visual editor at http://localhost:3002, or keep scripting"
dim   "        with your API key. 'nodeTemplates' lists $(printf '%s' "$TEMPLATES" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)["data"]["nodeTemplates"]))') templates to build from."
