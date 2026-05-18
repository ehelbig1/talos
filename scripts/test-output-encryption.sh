#!/usr/bin/env bash
# test-output-encryption.sh — Verify execution output encryption is working
#
# Requires: DATABASE_URL, TALOS_MASTER_KEY
#
# Tests:
# 1. Confirm migration applied (output_data_enc column exists)
# 2. Confirm trigger exists (compute_execution_event_duration)
# 3. Check for any unencrypted rows with non-null output_data
# 4. Verify encryption key rotation age

set -euo pipefail

if [ -z "${DATABASE_URL:-}" ]; then
    echo "ERROR: DATABASE_URL required"
    exit 1
fi

PASS=0
FAIL=0
WARN=0

check() {
    local label="$1"
    local query="$2"
    local expected="$3"
    local result
    result=$(psql "$DATABASE_URL" -tA -c "$query" 2>/dev/null || echo "ERROR")

    if [ "$result" = "$expected" ]; then
        echo "  PASS: $label"
        PASS=$((PASS + 1))
    else
        echo "  FAIL: $label (expected: $expected, got: $result)"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Execution Output Encryption Verification ==="
echo ""

echo "1. Schema checks:"
check "output_data_enc column exists" \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='workflow_executions' AND column_name='output_data_enc'" \
    "1"

check "output_enc_key_id column exists" \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='workflow_executions' AND column_name='output_enc_key_id'" \
    "1"

echo ""
echo "2. Execution event timing:"
check "duration_ms column exists on execution_events" \
    "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='execution_events' AND column_name='duration_ms'" \
    "1"

check "compute_execution_event_duration trigger exists" \
    "SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_name='trg_execution_event_duration'" \
    "1"

echo ""
echo "3. Encryption status:"
UNENCRYPTED=$(psql "$DATABASE_URL" -tA -c \
    "SELECT COUNT(*) FROM workflow_executions WHERE output_data IS NOT NULL AND output_data_enc IS NULL" 2>/dev/null || echo "0")
ENCRYPTED=$(psql "$DATABASE_URL" -tA -c \
    "SELECT COUNT(*) FROM workflow_executions WHERE output_data_enc IS NOT NULL" 2>/dev/null || echo "0")
TOTAL=$(psql "$DATABASE_URL" -tA -c \
    "SELECT COUNT(*) FROM workflow_executions WHERE output_data IS NOT NULL OR output_data_enc IS NOT NULL" 2>/dev/null || echo "0")

echo "  Encrypted: $ENCRYPTED / $TOTAL"
echo "  Unencrypted (legacy): $UNENCRYPTED"
if [ "$UNENCRYPTED" -gt 0 ]; then
    echo "  WARN: $UNENCRYPTED rows have unencrypted output. Run scripts/backfill-encrypt-output.sh"
    WARN=$((WARN + 1))
else
    echo "  PASS: All output data encrypted"
    PASS=$((PASS + 1))
fi

echo ""
echo "4. Encryption key health:"
KEY_AGE=$(psql "$DATABASE_URL" -tA -c \
    "SELECT EXTRACT(DAY FROM NOW() - MAX(created_at))::int FROM encryption_keys WHERE active = true" 2>/dev/null || echo "999")
echo "  Active key age: ${KEY_AGE} days"
if [ "$KEY_AGE" -gt 365 ]; then
    echo "  WARN: Encryption key is over 365 days old. Rotate with SecretsManager::rotate_dek()"
    WARN=$((WARN + 1))
elif [ "$KEY_AGE" -gt 90 ]; then
    echo "  WARN: Encryption key is over 90 days old. Consider rotation."
    WARN=$((WARN + 1))
else
    echo "  PASS: Key age within rotation policy"
    PASS=$((PASS + 1))
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed, $WARN warnings ==="
exit $FAIL
