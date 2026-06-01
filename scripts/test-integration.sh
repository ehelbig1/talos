#!/usr/bin/env bash
#
# Run the env-gated integration tests against disposable Redis + Postgres, then
# tear the datastores down. These tests no-op under a plain `cargo test`
# (they return early unless TALOS_TEST_*_URL is set), so without this target
# they never actually run.
#
# Two Postgres databases are provisioned on one pgvector instance:
#   * `talos`    — the FULL migrated schema (`sqlx migrate run`), for tests that
#                  query real tables (RLS isolation, crash-recovery, …).
#   * `talos_sc` — an empty DB, for SELF-CONTAINED tests that DROP/CREATE their
#                  own minimal schema (so they can't clobber the migrated one).
# Plus a disposable Redis for the idempotency atomicity test.
#
# Requires Docker and sqlx-cli (`cargo install sqlx-cli`).
#
# Usage:  bash scripts/test-integration.sh   (or: make test-integration)
set -euo pipefail

REDIS_PORT="${TALOS_IT_REDIS_PORT:-16399}"
PG_PORT="${TALOS_IT_PG_PORT:-15435}"
REDIS_NAME="talos-it-redis"
PG_NAME="talos-it-pgvector"
PG_USER="postgres"
PG_PASS="test"

cleanup() {
    docker rm -f "$REDIS_NAME" "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup # remove any stale containers from a previous interrupted run

command -v sqlx >/dev/null 2>&1 \
    || { echo "✗ sqlx-cli missing — install: cargo install sqlx-cli --locked"; exit 1; }

echo "▶ starting disposable Redis + pgvector…"
docker run -d --rm --name "$REDIS_NAME" -p "${REDIS_PORT}:6379" redis:7-alpine >/dev/null
docker run -d --rm --name "$PG_NAME" \
    -e "POSTGRES_USER=${PG_USER}" -e "POSTGRES_PASSWORD=${PG_PASS}" -e POSTGRES_DB=talos \
    -p "${PG_PORT}:5432" pgvector/pgvector:pg17 >/dev/null

echo "▶ waiting for Postgres…"
for _ in $(seq 1 60); do
    docker exec "$PG_NAME" pg_isready >/dev/null 2>&1 && break
    sleep 1
done
docker exec "$PG_NAME" pg_isready >/dev/null 2>&1 || { echo "Postgres never became ready"; exit 1; }

PG_BASE="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}"
MIGRATED_URL="${PG_BASE}/talos"
SELFCONTAINED_URL="${PG_BASE}/talos_sc"

echo "▶ applying migrations to 'talos'…"
DATABASE_URL="$MIGRATED_URL" sqlx migrate run --source migrations >/dev/null
echo "▶ creating empty 'talos_sc' for self-contained tests…"
docker exec "$PG_NAME" psql -U "$PG_USER" -d talos -c "CREATE DATABASE talos_sc" >/dev/null

export TALOS_TEST_REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"

# crate : integration-test-binary : datastore (redis | migrated | selfcontained)
TESTS=(
    "talos-idempotency:redis_integration:redis"
    "talos-idempotency:middleware_integration:redis"
    "talos-tenancy:rls_integration:selfcontained"
    "talos-actor-repository:budget_guard_integration:selfcontained"
    "talos-db:rls_helper_enforcement:migrated"
    "talos-db:rls_org_isolation:migrated"
    "talos-organizations:personal_org_resolution:migrated"
    "talos-advanced-repository:scratch_rls:migrated"
    "talos-execution-repository:crash_recovery:migrated"
    "talos-memory:integration:migrated"
)

rc=0
for entry in "${TESTS[@]}"; do
    crate="${entry%%:*}"
    rest="${entry#*:}"
    test="${rest%%:*}"
    store="${rest##*:}"
    case "$store" in
        redis)         db="" ;;
        migrated)      db="$MIGRATED_URL" ;;
        selfcontained) db="$SELFCONTAINED_URL" ;;
    esac
    echo
    echo "▶ ${crate} :: ${test}  [${store}]"
    if ! TALOS_TEST_DATABASE_URL="$db" cargo test -p "$crate" --test "$test"; then
        rc=1
    fi
done

echo
if [ "$rc" -eq 0 ]; then
    echo "✓ integration tests passed"
else
    echo "✗ one or more integration tests failed"
fi
exit "$rc"
