#!/usr/bin/env bash
# Verify the migration baseline (RFC 0009): prove that
#   baseline schema.sql  +  _sqlx_migrations seed  +  tail migrations (> cutpoint)
# produces a schema BYTE-IDENTICAL to running the full migration chain.
#
# This is the gate that makes the baseline trustworthy. If it fails, the
# baseline has drifted from the chain (dump ordering, a new migration that
# changed something below the cutpoint, or a bad checksum) and MUST NOT be
# used by any install path. Wire this into quality.yml before phase 2.
#
# Requires TWO disposable, empty Postgres databases (pgvector image).
#
# Usage:
#   CHAIN_DATABASE_URL=postgres://…/verify_chain \
#   BASELINE_DATABASE_URL=postgres://…/verify_baseline \
#     bash scripts/verify-schema-baseline.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
BASELINE_DIR="migrations/.baseline"

red()   { printf '\033[1;31m%s\033[0m\n' "$*" >&2; }
green() { printf '\033[1;32m%s\033[0m\n' "$*"; }
bold()  { printf '\033[1m%s\033[0m\n' "$*"; }

: "${CHAIN_DATABASE_URL:?set CHAIN_DATABASE_URL to a DISPOSABLE empty Postgres}"
: "${BASELINE_DATABASE_URL:?set BASELINE_DATABASE_URL to a SECOND DISPOSABLE empty Postgres}"
command -v psql    >/dev/null || { red "psql not found"; exit 1; }
command -v pg_dump >/dev/null || { red "pg_dump not found"; exit 1; }
command -v sqlx    >/dev/null || { red "sqlx-cli not found"; exit 1; }

for f in schema.sql seed_sqlx_migrations.sql CUTPOINT; do
    [ -f "$BASELINE_DIR/$f" ] || { red "missing $BASELINE_DIR/$f — run 'make schema-baseline' first"; exit 1; }
done
# shellcheck disable=SC1091
cutpoint="$(sed -n 's/^cutpoint_version=//p' "$BASELINE_DIR/CUTPOINT")"
[ -n "$cutpoint" ] || { red "could not read cutpoint_version from CUTPOINT"; exit 1; }
bold "▶ verifying baseline at cutpoint $cutpoint"

# Path A: full chain.
bold "▶ [A] applying full chain"
DATABASE_URL="$CHAIN_DATABASE_URL" sqlx migrate run --source migrations

# Path B: baseline snapshot + seed, then only the tail (> cutpoint).
bold "▶ [B] loading baseline snapshot + seed, then applying the tail"
psql "$BASELINE_DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$BASELINE_DIR/schema.sql"
psql "$BASELINE_DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$BASELINE_DIR/seed_sqlx_migrations.sql"
# sqlx migrate run on path B must skip <= cutpoint (seeded) and run only the tail.
DATABASE_URL="$BASELINE_DATABASE_URL" sqlx migrate run --source migrations

# Compare the resulting schemas. Same dump flags as the generator so any
# difference is a real schema difference, not dump-format noise.
dump() { pg_dump --schema-only --no-owner --no-privileges --no-comments "$1"; }
tmp_a="$(mktemp)"; tmp_b="$(mktemp)"
trap 'rm -f "$tmp_a" "$tmp_b"' EXIT
dump "$CHAIN_DATABASE_URL"    > "$tmp_a"
dump "$BASELINE_DATABASE_URL" > "$tmp_b"

if diff -u "$tmp_a" "$tmp_b" > /tmp/baseline-schema.diff 2>&1; then
    green "✓ baseline+seed+tail schema is IDENTICAL to the full chain (cutpoint $cutpoint)"
    exit 0
else
    red "✗ SCHEMA DRIFT — baseline does not reproduce the full chain. Baseline is NOT safe to use."
    red "  diff (chain A vs baseline B) written to /tmp/baseline-schema.diff:"
    head -40 /tmp/baseline-schema.diff >&2
    red "  → regenerate with 'make schema-baseline', or a tail migration changed something below the cutpoint."
    exit 1
fi
