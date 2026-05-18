#!/usr/bin/env bash
# =============================================================================
# SOC 2 Evidence Collection Script
# =============================================================================
#
# Exports audit log data and verifies security controls for SOC 2 evidence.
#
# Requirements:
#   - DATABASE_URL environment variable (PostgreSQL connection string)
#   - psql client installed
#   - Write access to ./evidence/ directory
#
# Usage:
#   export DATABASE_URL="postgresql://user:pass@host:5432/talos"
#   ./scripts/soc2/collect-evidence.sh
#
# Output:
#   evidence/YYYYMMDD_HHMMSS/
#     audit_events.csv
#     auth_audit_log.csv
#     secret_audit_log.csv
#     admin_event_log.csv
#     immutability_triggers.txt
#     encryption_key_status.txt
#     control_verification.txt
#     collection_metadata.txt
# =============================================================================

set -euo pipefail

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RETENTION_DAYS="${EVIDENCE_RETENTION_DAYS:-90}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TIMESTAMP="$(date -u '+%Y%m%d_%H%M%S')"
EVIDENCE_DIR="${REPO_ROOT}/evidence/${TIMESTAMP}"

# ---------------------------------------------------------------------------
# Pre-flight checks
# ---------------------------------------------------------------------------
if [ -z "${DATABASE_URL:-}" ]; then
    echo "ERROR: DATABASE_URL environment variable is required." >&2
    echo "  Example: export DATABASE_URL=\"postgresql://user:pass@host:5432/talos\"" >&2
    exit 1
fi

if ! command -v psql &>/dev/null; then
    echo "ERROR: psql client is not installed or not in PATH." >&2
    exit 1
fi

# Verify database connectivity
if ! psql "$DATABASE_URL" -c "SELECT 1" &>/dev/null; then
    echo "ERROR: Cannot connect to database. Check DATABASE_URL." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Setup
# ---------------------------------------------------------------------------
mkdir -p "$EVIDENCE_DIR"
echo "SOC 2 Evidence Collection"
echo "========================="
echo "Timestamp:      $TIMESTAMP"
echo "Retention:      $RETENTION_DAYS days"
echo "Output:         $EVIDENCE_DIR"
echo ""

CUTOFF_DATE="$(date -u -v-${RETENTION_DAYS}d '+%Y-%m-%d' 2>/dev/null || date -u -d "${RETENTION_DAYS} days ago" '+%Y-%m-%d')"
echo "Cutoff date:    $CUTOFF_DATE"
echo ""

PASS=0
FAIL=0
WARN=0

record_pass() {
    PASS=$((PASS + 1))
    echo "  [PASS] $1"
}

record_fail() {
    FAIL=$((FAIL + 1))
    echo "  [FAIL] $1" >&2
}

record_warn() {
    WARN=$((WARN + 1))
    echo "  [WARN] $1"
}

# ---------------------------------------------------------------------------
# 1. Export audit log tables (last N days)
# ---------------------------------------------------------------------------
echo "--- Exporting audit logs (last ${RETENTION_DAYS} days) ---"

export_table() {
    local table="$1"
    local output_file="$2"
    local count

    # Check if table exists
    if ! psql "$DATABASE_URL" -tAc "SELECT 1 FROM information_schema.tables WHERE table_name = '${table}'" 2>/dev/null | grep -q 1; then
        record_warn "Table '${table}' does not exist -- skipping export"
        return
    fi

    psql "$DATABASE_URL" \
        --no-align \
        --field-separator=',' \
        --pset footer=off \
        -c "\\COPY (SELECT * FROM ${table} WHERE created_at >= '${CUTOFF_DATE}'::timestamptz ORDER BY created_at DESC) TO STDOUT WITH (FORMAT CSV, HEADER TRUE)" \
        > "$output_file" 2>/dev/null

    count=$(wc -l < "$output_file" | tr -d ' ')
    # Subtract header line
    if [ "$count" -gt 0 ]; then
        count=$((count - 1))
    fi

    if [ "$count" -ge 0 ]; then
        record_pass "Exported ${count} rows from ${table}"
    else
        record_warn "No rows found in ${table} for the retention period"
    fi
}

export_table "audit_events"     "$EVIDENCE_DIR/audit_events.csv"
export_table "auth_audit_log"   "$EVIDENCE_DIR/auth_audit_log.csv"
export_table "secret_audit_log" "$EVIDENCE_DIR/secret_audit_log.csv"
export_table "admin_event_log"  "$EVIDENCE_DIR/admin_event_log.csv"

echo ""

# ---------------------------------------------------------------------------
# 2. Verify immutability triggers
# ---------------------------------------------------------------------------
echo "--- Verifying immutability triggers ---"

EXPECTED_TRIGGERS=(
    "trg_audit_events_immutable"
    "trg_auth_audit_log_immutable"
    "trg_secret_audit_log_immutable"
    "trg_admin_event_log_immutable"
)

{
    echo "Immutability Trigger Verification"
    echo "================================="
    echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""

    for trigger_name in "${EXPECTED_TRIGGERS[@]}"; do
        result=$(psql "$DATABASE_URL" -tAc \
            "SELECT trigger_name, event_manipulation, action_timing, event_object_table
             FROM information_schema.triggers
             WHERE trigger_name = '${trigger_name}'
             ORDER BY event_manipulation" 2>/dev/null)

        if [ -n "$result" ]; then
            record_pass "Trigger '${trigger_name}' exists"
            echo "  Trigger: ${trigger_name}" >> "$EVIDENCE_DIR/immutability_triggers.txt.tmp"
            echo "  Details: ${result}" >> "$EVIDENCE_DIR/immutability_triggers.txt.tmp"
            echo "" >> "$EVIDENCE_DIR/immutability_triggers.txt.tmp"
        else
            record_fail "Trigger '${trigger_name}' is MISSING"
            echo "  MISSING: ${trigger_name}" >> "$EVIDENCE_DIR/immutability_triggers.txt.tmp"
            echo "" >> "$EVIDENCE_DIR/immutability_triggers.txt.tmp"
        fi
    done

    # Also verify the shared trigger function exists
    func_exists=$(psql "$DATABASE_URL" -tAc \
        "SELECT routine_name FROM information_schema.routines
         WHERE routine_name = 'prevent_audit_modification'
         AND routine_type = 'FUNCTION'" 2>/dev/null)

    if [ -n "$func_exists" ]; then
        record_pass "Function 'prevent_audit_modification' exists"
    else
        record_fail "Function 'prevent_audit_modification' is MISSING"
    fi
} 2>&1

# Compose final file
{
    echo "Immutability Trigger Verification"
    echo "================================="
    echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""
    cat "$EVIDENCE_DIR/immutability_triggers.txt.tmp" 2>/dev/null || true
} > "$EVIDENCE_DIR/immutability_triggers.txt"
rm -f "$EVIDENCE_DIR/immutability_triggers.txt.tmp"

echo ""

# ---------------------------------------------------------------------------
# 3. Check encryption key rotation status
# ---------------------------------------------------------------------------
echo "--- Checking encryption key status ---"

{
    echo "Encryption Key Status"
    echo "====================="
    echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
    echo ""

    # Check if encryption_keys table exists
    if ! psql "$DATABASE_URL" -tAc "SELECT 1 FROM information_schema.tables WHERE table_name = 'encryption_keys'" 2>/dev/null | grep -q 1; then
        echo "WARNING: encryption_keys table does not exist"
        record_fail "encryption_keys table not found"
    else
        # Count total keys
        total_keys=$(psql "$DATABASE_URL" -tAc "SELECT COUNT(*) FROM encryption_keys" 2>/dev/null | tr -d ' ')
        echo "Total encryption keys: ${total_keys}"

        # Active key details
        active_key=$(psql "$DATABASE_URL" -tAc \
            "SELECT id, algorithm, created_at, active
             FROM encryption_keys
             WHERE active = true
             ORDER BY created_at DESC
             LIMIT 1" 2>/dev/null)

        if [ -n "$active_key" ]; then
            echo "Active key: ${active_key}"
            record_pass "Active encryption key exists"
        else
            echo "WARNING: No active encryption key found"
            record_fail "No active encryption key"
        fi

        # Check rotation age
        key_age_days=$(psql "$DATABASE_URL" -tAc \
            "SELECT EXTRACT(DAY FROM NOW() - created_at)::int
             FROM encryption_keys
             WHERE active = true
             ORDER BY created_at DESC
             LIMIT 1" 2>/dev/null | tr -d ' ')

        if [ -n "$key_age_days" ]; then
            echo "Active key age: ${key_age_days} days"

            if [ "$key_age_days" -gt 365 ]; then
                record_fail "Active encryption key is older than 365 days (${key_age_days} days) -- rotation recommended"
                echo "RECOMMENDATION: Rotate encryption key (> 365 days old)"
            elif [ "$key_age_days" -gt 90 ]; then
                record_warn "Active encryption key is ${key_age_days} days old -- consider rotation"
                echo "NOTE: Key is ${key_age_days} days old (rotation recommended every 90 days)"
            else
                record_pass "Encryption key age is within 90-day rotation window (${key_age_days} days)"
            fi
        fi

        # Check for plaintext secrets (should be zero)
        echo ""
        echo "Plaintext Secret Check"
        echo "----------------------"

        # Verify secrets table has encrypted values (encrypted_value column should exist)
        has_encrypted=$(psql "$DATABASE_URL" -tAc \
            "SELECT column_name FROM information_schema.columns
             WHERE table_name = 'secrets' AND column_name = 'encrypted_value'" 2>/dev/null | tr -d ' ')

        if [ -n "$has_encrypted" ]; then
            record_pass "Secrets table uses encrypted_value column"
        else
            record_warn "Could not verify encrypted_value column in secrets table"
        fi
    fi
} > "$EVIDENCE_DIR/encryption_key_status.txt" 2>&1

echo ""

# ---------------------------------------------------------------------------
# 4. Run control verification SQL
# ---------------------------------------------------------------------------
echo "--- Running control verification ---"

VERIFY_SQL="${SCRIPT_DIR}/verify-controls.sql"

if [ -f "$VERIFY_SQL" ]; then
    psql "$DATABASE_URL" -f "$VERIFY_SQL" > "$EVIDENCE_DIR/control_verification.txt" 2>&1
    if [ $? -eq 0 ]; then
        record_pass "Control verification SQL executed successfully"
    else
        record_warn "Control verification SQL completed with warnings"
    fi
else
    record_warn "verify-controls.sql not found at ${VERIFY_SQL}"
fi

echo ""

# ---------------------------------------------------------------------------
# 5. Collection metadata
# ---------------------------------------------------------------------------
{
    echo "SOC 2 Evidence Collection Metadata"
    echo "==================================="
    echo ""
    echo "Collection timestamp: ${TIMESTAMP}"
    echo "Collection date (UTC): $(date -u '+%Y-%m-%d %H:%M:%S')"
    echo "Retention window: ${RETENTION_DAYS} days"
    echo "Cutoff date: ${CUTOFF_DATE}"
    echo "Collector: $(whoami)@$(hostname)"
    echo "Script version: 1.0"
    echo "Script path: ${SCRIPT_DIR}/collect-evidence.sh"
    echo ""
    echo "Database connection: [REDACTED]"
    echo "PostgreSQL version: $(psql "$DATABASE_URL" -tAc 'SELECT version()' 2>/dev/null | head -1)"
    echo ""
    echo "Files collected:"
    ls -la "$EVIDENCE_DIR/" | tail -n +2
    echo ""
    echo "Results: ${PASS} passed, ${FAIL} failed, ${WARN} warnings"
} > "$EVIDENCE_DIR/collection_metadata.txt"

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
echo "==========================="
echo "Collection Summary"
echo "==========================="
echo "  Passed:   ${PASS}"
echo "  Failed:   ${FAIL}"
echo "  Warnings: ${WARN}"
echo ""
echo "Evidence written to: ${EVIDENCE_DIR}/"
echo ""

ls -la "$EVIDENCE_DIR/"

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "WARNING: ${FAIL} check(s) failed. Review output above and remediate before audit."
    exit 1
fi

exit 0
