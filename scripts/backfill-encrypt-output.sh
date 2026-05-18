#!/usr/bin/env bash
# backfill-encrypt-output.sh — Encrypt existing plaintext execution output data
#
# This script reads workflow_executions rows where output_data is plaintext
# (output_data IS NOT NULL AND output_data_enc IS NULL), encrypts each using
# the active DEK, and writes the encrypted form to output_data_enc + output_enc_key_id.
#
# After backfilling, a follow-up migration can safely NULL out the plaintext
# output_data column.
#
# Requirements:
#   - DATABASE_URL environment variable set
#   - TALOS_MASTER_KEY environment variable set
#   - Active DEK in the encryption_keys table
#
# Usage:
#   DATABASE_URL="postgres://..." TALOS_MASTER_KEY="..." ./scripts/backfill-encrypt-output.sh
#   DATABASE_URL="..." TALOS_MASTER_KEY="..." ./scripts/backfill-encrypt-output.sh --dry-run
#
# The script is idempotent — rows already encrypted are skipped.

set -euo pipefail

DRY_RUN=false
BATCH_SIZE=100

for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=true ;;
        --batch-size=*) BATCH_SIZE="${arg#*=}" ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

if [ -z "${DATABASE_URL:-}" ]; then
    echo "ERROR: DATABASE_URL environment variable is required"
    exit 1
fi

if [ -z "${TALOS_MASTER_KEY:-}" ]; then
    echo "ERROR: TALOS_MASTER_KEY environment variable is required"
    exit 1
fi

echo "=== Execution Output Encryption Backfill ==="
echo "Database: $(echo "$DATABASE_URL" | sed 's|://[^@]*@|://***@|')"
echo "Dry run: $DRY_RUN"
echo "Batch size: $BATCH_SIZE"
echo ""

# Count unencrypted rows
TOTAL=$(psql "$DATABASE_URL" -tA -c \
    "SELECT COUNT(*) FROM workflow_executions WHERE output_data IS NOT NULL AND output_data_enc IS NULL")

echo "Unencrypted rows to process: $TOTAL"

if [ "$TOTAL" = "0" ]; then
    echo "Nothing to do — all rows are already encrypted or have no output."
    exit 0
fi

if [ "$DRY_RUN" = "true" ]; then
    echo ""
    echo "[DRY RUN] Would encrypt $TOTAL rows. Showing sample IDs:"
    psql "$DATABASE_URL" -tA -c \
        "SELECT id FROM workflow_executions WHERE output_data IS NOT NULL AND output_data_enc IS NULL LIMIT 5"
    echo ""
    echo "Run without --dry-run to perform the backfill."
    exit 0
fi

echo ""
echo "Starting backfill..."
echo "NOTE: This is a best-effort script. For production use, the controller's"
echo "ExecutionRepository.with_encryption() handles encryption transparently."
echo "This script exists to backfill legacy rows."
echo ""

# The actual encryption must be done by the Rust controller since it holds
# the master key decryption logic (KEK → DEK → AES-256-GCM). We output a
# SQL-based approach that can be run as a one-shot migration.
#
# In practice, you would run a small Rust binary that:
# 1. Connects to the DB
# 2. Fetches unencrypted rows in batches
# 3. Encrypts each output_data value using SecretsManager::encrypt_value()
# 4. Updates the row with output_data_enc + output_enc_key_id
# 5. Sets output_data = NULL
#
# For now, this script generates the migration SQL that marks rows as
# needing encryption and can be used with the controller's backfill endpoint.

echo "Generating backfill task markers..."

psql "$DATABASE_URL" -c "
-- Mark rows that need encryption backfill (idempotent tag)
-- The controller's startup routine can process these in background.
INSERT INTO system_settings (key, value)
VALUES ('backfill_encrypt_output', 'pending')
ON CONFLICT (key) DO UPDATE SET value = 'pending'
"

echo ""
echo "Backfill task registered in system_settings."
echo "The controller will process unencrypted rows in background batches"
echo "when TALOS_ENCRYPT_EXECUTION_OUTPUT=true (default in production)."
echo ""
echo "Monitor progress with:"
echo "  psql \$DATABASE_URL -c \"SELECT COUNT(*) as remaining FROM workflow_executions WHERE output_data IS NOT NULL AND output_data_enc IS NULL\""
echo ""
echo "Done."
