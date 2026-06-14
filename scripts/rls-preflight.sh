#!/usr/bin/env bash
#
# Pre-flight gate for enabling RLS SET-ROLE enforcement (TALOS_RLS_SET_ROLE).
#
# Run this against the target Postgres (staging first, then prod) AS THE
# CONTROLLER'S CONNECTING ROLE, before flipping TALOS_RLS_SET_ROLE on and
# restarting the controller. It mirrors exactly what the controller boot guard
# (talos-db::warn_if_rls_will_be_bypassed) checks — but surfaces problems
# *before* the restart-and-read-logs cycle, and additionally catches the
# managed-Postgres grant gap the boot guard can't see.
#
# It bundles the four checks from the RFC 0005 operator runbook
# (docs/rfcs/0005-tenant-isolation-target-architecture.md
#  → "Post-S3 enablement checklist"):
#
#   1. talos_app exists and is security-correct (NOT superuser, NOT BYPASSRLS).
#      Zero rows  → migration 20260529220000 not applied → scoped tx will FAIL.
#      super/bypass = t → RLS is SILENTLY BYPASSED (worse than failing).
#   2. The connecting role can SET ROLE talos_app (the membership GRANT ran).
#   3. RLS is enabled on every policed table (relrowsecurity = t).
#   4. Grant-completeness: talos_app can SELECT/INSERT/UPDATE/DELETE every base
#      table — the ALTER DEFAULT PRIVILEGES gotcha (a table created by a
#      different role than the granting role lacks DML → request-path query
#      fails closed under enforcement). Sequence USAGE/SELECT checked as a warn.
#
# Each check fails closed. Exit 0 = green, safe to flip the flag. Non-zero =
# at least one gap; DO NOT enable enforcement until it is zero.
#
# Usage:
#   bash scripts/rls-preflight.sh                 # uses $DATABASE_URL
#   bash scripts/rls-preflight.sh "$DATABASE_URL" # explicit connection URI
#   DATABASE_URL=postgres://… bash scripts/rls-preflight.sh
#
# Env vars:
#   DATABASE_URL      Postgres connection URI. Required (or pass as arg 1).
#                     MUST be the role the controller connects as, so check 2
#                     verifies that role's GRANT to talos_app — not a superuser.
#   TALOS_APP_ROLE    Request-path role name. Default: talos_app.
#
# After this passes:
#   - uncomment controller.env.TALOS_RLS_SET_ROLE: "true" in the chart values
#     (or set TALOS_RLS_SET_ROLE=1 in the controller env) and helm upgrade /
#     restart. Confirm the controller logs `RLS SET-ROLE mode active`.
#   - rollback is the instant flag flip back to false + restart (no data/schema
#     change to undo).

set -uo pipefail

DATABASE_URL="${1:-${DATABASE_URL:-}}"
APP_ROLE="${TALOS_APP_ROLE:-talos_app}"

# Tables policed by RLS, per RFC 0005/0006. Keep in sync with the boot guard
# and the rls_org_isolation test suite.
RLS_TABLES=(workflows actors secrets workflow_executions scratch_sessions user_module_pins)

PASS=0
FAIL=0
WARN=0
pass() { echo "  ✅ $1"; PASS=$((PASS + 1)); }
fail() { echo "  ❌ $1"; FAIL=$((FAIL + 1)); }
warn() { echo "  ⚠️  $1"; WARN=$((WARN + 1)); }

if [[ -z "$DATABASE_URL" ]]; then
    echo "❌ DATABASE_URL not set (pass as arg 1 or export it)." >&2
    echo "   Connect as the role the CONTROLLER uses, not a superuser —" >&2
    echo "   check 2 verifies that role's membership in $APP_ROLE." >&2
    exit 2
fi

if ! command -v psql >/dev/null 2>&1; then
    echo "❌ psql not found on PATH." >&2
    exit 2
fi

# Unaligned, tuples-only single-value query helper. Stops on SQL error.
q() { psql -X -v ON_ERROR_STOP=1 -At "$DATABASE_URL" -c "$1"; }

echo "▶ RLS SET-ROLE enforcement pre-flight"
echo "  role under test : $APP_ROLE"
echo "  connecting as   : $(q 'SELECT current_user' 2>/dev/null || echo '<unreachable>')"
echo ""

# ---------------------------------------------------------------------------
# 0. Connectivity
# ---------------------------------------------------------------------------
echo "0. Connectivity"
if q "SELECT 1" >/dev/null 2>&1; then
    pass "reachable ($(q 'SHOW server_version' 2>/dev/null | head -1))"
else
    fail "cannot connect with the supplied DATABASE_URL"
    echo "     → fix the connection before running the rest of the gate."
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Role exists and is security-correct (NOT superuser, NOT BYPASSRLS)
# ---------------------------------------------------------------------------
echo ""
echo "1. $APP_ROLE role attributes"
ROLE_ATTRS=$(q "SELECT rolsuper::text||','||rolbypassrls::text||','||rolcanlogin::text FROM pg_roles WHERE rolname = '$APP_ROLE'" 2>/dev/null || true)
if [[ -z "$ROLE_ATTRS" ]]; then
    fail "$APP_ROLE does not exist → migration 20260529220000 not applied"
    echo "     → scoped transactions would FAIL under enforcement. Apply migrations first."
else
    # boolean::text renders as 'true'/'false' in Postgres.
    IFS=',' read -r r_super r_bypass r_login <<<"$ROLE_ATTRS"
    if [[ "$r_super" == "true" ]]; then
        fail "$APP_ROLE is SUPERUSER → RLS is silently bypassed (dangerous)"
    elif [[ "$r_bypass" == "true" ]]; then
        fail "$APP_ROLE has BYPASSRLS → RLS is silently bypassed (dangerous)"
    else
        pass "$APP_ROLE exists, NOSUPERUSER, NOBYPASSRLS"
    fi
    [[ "$r_login" == "true" ]] && warn "$APP_ROLE has LOGIN (expected NOLOGIN; reached only via SET ROLE)"
fi

# ---------------------------------------------------------------------------
# 2. The connecting role can assume $APP_ROLE (the membership GRANT ran)
# ---------------------------------------------------------------------------
echo ""
echo "2. SET ROLE $APP_ROLE (membership grant)"
if psql -X -v ON_ERROR_STOP=1 "$DATABASE_URL" -c "SET ROLE $APP_ROLE; RESET ROLE;" >/dev/null 2>&1; then
    pass "connecting role can SET ROLE $APP_ROLE"
else
    fail "permission denied to set role → GRANT $APP_ROLE TO <connecting_role> didn't run for this role"
    echo "     → re-check that 20260529220000 ran against THIS database AND that"
    echo "       DATABASE_URL is the controller's role (not a different superuser)."
fi

# ---------------------------------------------------------------------------
# 3. RLS enabled on every policed table
# ---------------------------------------------------------------------------
echo ""
echo "3. RLS enabled on policed tables"
TABLE_LIST=$(printf "'%s'," "${RLS_TABLES[@]}"); TABLE_LIST="${TABLE_LIST%,}"
# rows: relname|relrowsecurity|relforcerowsecurity
RLS_STATE=$(q "SELECT relname||'|'||relrowsecurity::text||'|'||relforcerowsecurity::text FROM pg_class WHERE relname IN ($TABLE_LIST) AND relkind='r'" 2>/dev/null || true)
for t in "${RLS_TABLES[@]}"; do
    row=$(grep -E "^$t\|" <<<"$RLS_STATE" || true)
    if [[ -z "$row" ]]; then
        fail "$t: table not found"
        continue
    fi
    IFS='|' read -r _ rsec rforce <<<"$row"
    if [[ "$rsec" == "true" ]]; then
        if [[ "$rforce" == "true" ]]; then
            pass "$t: RLS enabled + FORCED"
        else
            pass "$t: RLS enabled (not forced — table owner still bypasses; ok if controller is not the owner)"
        fi
    else
        fail "$t: RLS NOT enabled (relrowsecurity = f)"
    fi
done

# ---------------------------------------------------------------------------
# 4. Grant-completeness — the managed-Postgres ALTER DEFAULT PRIVILEGES gotcha
# ---------------------------------------------------------------------------
echo ""
echo "4. Table DML grant-completeness for $APP_ROLE"
GRANT_GAPS=$(q "
SELECT c.relname||':'||priv.p
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
CROSS JOIN (VALUES ('SELECT'),('INSERT'),('UPDATE'),('DELETE')) AS priv(p)
WHERE c.relkind = 'r'
  AND NOT has_table_privilege('$APP_ROLE', c.oid, priv.p)
ORDER BY c.relname, priv.p" 2>/dev/null || echo "__ERR__")
if [[ "$GRANT_GAPS" == "__ERR__" ]]; then
    fail "grant-completeness query failed (does $APP_ROLE exist?)"
elif [[ -z "$GRANT_GAPS" ]]; then
    pass "$APP_ROLE can SELECT/INSERT/UPDATE/DELETE every public base table"
else
    GAP_COUNT=$(wc -l <<<"$GRANT_GAPS")
    fail "$GAP_COUNT table/privilege gap(s) — these would fail closed under enforcement:"
    while IFS=':' read -r tbl prv; do
        echo "       missing $prv on $tbl  →  GRANT $prv ON $tbl TO $APP_ROLE;"
    done <<<"$GRANT_GAPS"
fi

# ---------------------------------------------------------------------------
# 5. Sequence grants (warn-only — UUID PKs need none; serial/identity do)
# ---------------------------------------------------------------------------
echo ""
echo "5. Sequence USAGE/SELECT for $APP_ROLE (informational)"
SEQ_GAPS=$(q "
SELECT c.relname||':'||priv.p
FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'public'
CROSS JOIN (VALUES ('USAGE'),('SELECT')) AS priv(p)
WHERE c.relkind = 'S'
  AND NOT has_sequence_privilege('$APP_ROLE', c.oid, priv.p)
ORDER BY c.relname, priv.p" 2>/dev/null || echo "__ERR__")
if [[ "$SEQ_GAPS" == "__ERR__" ]]; then
    warn "sequence-grant query failed (non-fatal)"
elif [[ -z "$SEQ_GAPS" ]]; then
    pass "no sequence-grant gaps"
else
    SEQ_COUNT=$(wc -l <<<"$SEQ_GAPS")
    warn "$SEQ_COUNT sequence-grant gap(s) — only matters for serial/identity columns:"
    while IFS=':' read -r seq prv; do
        echo "       missing $prv on $seq  →  GRANT $prv ON SEQUENCE $seq TO $APP_ROLE;"
    done <<<"$SEQ_GAPS"
fi

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo ""
echo "────────────────────────────────────────────────────────"
echo "  passed: $PASS   failed: $FAIL   warnings: $WARN"
if [[ "$FAIL" -gt 0 ]]; then
    echo "  ❌ NOT READY — resolve the failures above before enabling TALOS_RLS_SET_ROLE."
    exit 1
fi
echo "  ✅ READY — the schema is correct for SET-ROLE enforcement."
echo ""
echo "  Next:"
echo "    1. Enable on STAGING first: set TALOS_RLS_SET_ROLE=true, restart,"
echo "       confirm the controller logs 'RLS SET-ROLE mode active'."
echo "    2. Run scripts/smoke.sh and exercise secret create/update/delete/rotate"
echo "       + workflow/actor create. Watch logs for unexpected SQLSTATE 42501."
echo "    3. Soak across a secret-rotation + OAuth-refresh cycle, then promote."
echo "  Rollback is instant: TALOS_RLS_SET_ROLE=false + restart."
exit 0
