#!/usr/bin/env bash
#
# Run the SELF-CONTAINED, env-gated integration tests against disposable
# Redis + Postgres, then tear the datastores down. These tests are normally
# SKIPPED by `cargo test` / `make test` (they no-op unless TALOS_TEST_*_URL is
# set), so without this target they never actually run.
#
# "Self-contained" = the test creates (and drops) its own schema, so a plain
# empty Postgres is enough — no migration pipeline required.
#
# NOT run here (yet): the migration-dependent integration tests
#   talos-execution-repository/crash_recovery, talos-memory/integration,
#   talos-advanced-repository/scratch_rls, talos-db/rls_helper_enforcement,
#   talos-db/rls_org_isolation, talos-organizations/personal_org_resolution
# which query the real migrated schema (users/secrets/workflows/…) and the
# `talos_app` role, so they need `sqlx migrate run` against a pgvector image
# first. Wiring those in is a follow-up.
#
# Usage:  bash scripts/test-integration.sh   (or: make test-integration)
set -euo pipefail

REDIS_PORT="${TALOS_IT_REDIS_PORT:-16399}"
PG_PORT="${TALOS_IT_PG_PORT:-15433}"
REDIS_NAME="talos-it-redis"
PG_NAME="talos-it-pg"

cleanup() {
    docker rm -f "$REDIS_NAME" "$PG_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup # remove any stale containers from a previous interrupted run

echo "▶ starting disposable Redis + Postgres…"
docker run -d --rm --name "$REDIS_NAME" -p "${REDIS_PORT}:6379" redis:7-alpine >/dev/null
docker run -d --rm --name "$PG_NAME" \
    -e POSTGRES_PASSWORD=test -e POSTGRES_DB=talos \
    -p "${PG_PORT}:5432" postgres:16-alpine >/dev/null

echo "▶ waiting for Postgres…"
for _ in $(seq 1 30); do
    if docker exec "$PG_NAME" pg_isready >/dev/null 2>&1; then break; fi
    sleep 1
done
docker exec "$PG_NAME" pg_isready >/dev/null 2>&1 || { echo "Postgres never became ready"; exit 1; }

export TALOS_TEST_REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"
# The self-contained PG tests connect as a superuser and create their own
# non-superuser role via SET ROLE to exercise RLS enforcement.
export TALOS_TEST_DATABASE_URL="postgres://postgres:test@127.0.0.1:${PG_PORT}/talos"

# crate : integration-test-binary
SELF_CONTAINED=(
    "talos-idempotency:redis_integration"
    "talos-tenancy:rls_integration"
    "talos-actor-repository:budget_guard_integration"
)

rc=0
for entry in "${SELF_CONTAINED[@]}"; do
    crate="${entry%%:*}"
    test="${entry##*:}"
    echo
    echo "▶ ${crate} :: ${test}"
    if ! cargo test -p "$crate" --test "$test"; then
        rc=1
    fi
done

echo
if [ "$rc" -eq 0 ]; then
    echo "✓ self-contained integration tests passed"
else
    echo "✗ one or more integration tests failed"
fi
exit "$rc"
