#!/usr/bin/env bash
#
# Run the env-gated integration tests against disposable Redis + Postgres + NATS,
# then tear the datastores down. These tests no-op under a plain `cargo test`
# (they return early unless TALOS_TEST_*_URL is set), so without this target
# they never actually run. NATS backs the RFC 0010 P3 (D3b) envelope-sealing
# claim-protocol tests (the full dispatch→claim→seal→open loop over a real broker).
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
NATS_PORT="${TALOS_IT_NATS_PORT:-14222}"
REDIS_NAME="talos-it-redis"
PG_NAME="talos-it-pgvector"
NATS_NAME="talos-it-nats"
PG_USER="postgres"
PG_PASS="test"

cleanup() {
    docker rm -f "$REDIS_NAME" "$PG_NAME" "$NATS_NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup # remove any stale containers from a previous interrupted run

command -v sqlx >/dev/null 2>&1 \
    || { echo "✗ sqlx-cli missing — install: cargo install sqlx-cli --locked"; exit 1; }

echo "▶ starting disposable Redis + pgvector + NATS…"
docker run -d --rm --name "$REDIS_NAME" -p "${REDIS_PORT}:6379" redis:7-alpine >/dev/null
docker run -d --rm --name "$PG_NAME" \
    -e "POSTGRES_USER=${PG_USER}" -e "POSTGRES_PASSWORD=${PG_PASS}" -e POSTGRES_DB=talos \
    -p "${PG_PORT}:5432" pgvector/pgvector:pg17 >/dev/null
# NATS for the RFC 0010 P3 (D3b) claim-protocol integration tests (envelope-seal
# responder↔worker handshake + the engine-nats full dispatch→claim→open loop).
docker run -d --rm --name "$NATS_NAME" -p "${NATS_PORT}:4222" nats:2.10-alpine >/dev/null

echo "▶ waiting for Postgres…"
for _ in $(seq 1 60); do
    docker exec "$PG_NAME" pg_isready >/dev/null 2>&1 && break
    sleep 1
done
docker exec "$PG_NAME" pg_isready >/dev/null 2>&1 || { echo "Postgres never became ready"; exit 1; }

PG_BASE="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}"
MIGRATED_URL="${PG_BASE}/talos"
SELFCONTAINED_URL="${PG_BASE}/talos_sc"
# Dedicated migrated DB for the controller DB-harness binaries (see CTRL_TESTS
# below). They DELETE global tables in setup, so they get their own DB to stay
# isolated from the shared 'talos' migrated tests.
CTL_URL="${PG_BASE}/talos_ctl"

echo "▶ applying migrations to 'talos'…"
DATABASE_URL="$MIGRATED_URL" sqlx migrate run --source migrations >/dev/null
echo "▶ creating empty 'talos_sc' for self-contained tests…"
docker exec "$PG_NAME" psql -U "$PG_USER" -d talos -c "CREATE DATABASE talos_sc" >/dev/null
echo "▶ creating + migrating 'talos_ctl' for the controller DB-harness binaries…"
docker exec "$PG_NAME" psql -U "$PG_USER" -d talos -c "CREATE DATABASE talos_ctl" >/dev/null
DATABASE_URL="$CTL_URL" sqlx migrate run --source migrations >/dev/null

export TALOS_TEST_REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"
export TALOS_TEST_NATS_URL="nats://127.0.0.1:${NATS_PORT}"

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
    "talos-system-repo:revocation_query:migrated"
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

# ── RFC 0010 P3 (D3b) envelope-sealing claim protocol ───────────────────────
# These are gated on TALOS_TEST_NATS_URL / TALOS_TEST_REDIS_URL (exported above)
# and no-op under a plain `cargo test`. They exercise the claim protocol against
# a REAL broker: the crypto seal/open, the Redis lease CAS, the responder↔worker
# handshake, and the FULL dispatch→claim→seal→open loop through the real
# NatsNodeDispatcher (asserting no plaintext ever crosses the wire).
#   * `talos-envelope-seal`      — lib (RedisLease CAS) + `nats_claim_integration`
#   * `talos-workflow-engine-nats` — the `full_claim_loop_over_live_nats` lib test
echo
echo "▶ RFC 0010 P3 claim protocol :: talos-envelope-seal  [nats + redis]"
if ! cargo test -p talos-envelope-seal; then
    rc=1
fi
echo
echo "▶ RFC 0010 P3 claim protocol :: talos-workflow-engine-nats full loop  [nats]"
if ! cargo test -p talos-workflow-engine-nats --lib full_claim_loop; then
    rc=1
fi

# ── Controller DB-harness binaries ──────────────────────────────────────────
# These predate the TALOS_TEST_DATABASE_URL convention: they read DATABASE_URL
# directly via controller::db::init_pool, need a non-zero TALOS_MASTER_KEY
# (SecretsManager rejects all-zero), and DELETE global tables in
# setup_test_context — so they run SINGLE-THREADED against their OWN migrated DB
# ('talos_ctl') to stay isolated from the shared-'talos' migrated tests above.
# Brought into CI after their stale 2FA-context drift was fixed (PR #193); the
# JWT secret is a hard-coded literal in the harness, so only the master key is
# needed here. 64 hex = 32 bytes, non-zero.
CTRL_MASTER_KEY="00000000000000000000000000000000000000000000000000000000deadbeef"
CTRL_TESTS=(
    "api_key_tests"
    "api_auth_integration_test"
    "integration_mcp_tests"
    "auth_concurrency_tests"
    "security_isolation_tests"
    "governance_tests"
    "scheduler_tests"
    "workflow_version_tests"
    "env_vars"
)
# 'talos_ctl' is now the migrated TEMPLATE: setup_test_context clones it into a
# private per-test database (controller/tests/common::isolated_db_pool), so the
# binaries run multi-threaded with no shared-state cleanup. The one exception is
# env_vars, which mutates the global DATABASE_URL/ALLOWED_ORIGIN process env and
# must keep its tests single-threaded within the shared test process.
for ctest in "${CTRL_TESTS[@]}"; do
    threadflag=()
    [ "$ctest" = "env_vars" ] && threadflag=(--test-threads=1)
    echo
    echo "▶ controller :: ${ctest}  [migrated:talos_ctl template → per-test isolated DB]"
    if ! DATABASE_URL="$CTL_URL" TALOS_MASTER_KEY="$CTRL_MASTER_KEY" \
        cargo test -p controller --test "$ctest" -- "${threadflag[@]}"; then
        rc=1
    fi
done

# ── Testcontainers-based controller binaries ────────────────────────────────
# These self-provision their OWN Postgres via testcontainers (controller/tests/
# test_helpers) — they IGNORE DATABASE_URL and the shared 'talos*' DBs above, so
# they only need a Docker daemon (already used by this script) + a non-zero
# TALOS_MASTER_KEY for any SecretsManager construction. Run single-threaded:
# each binary shares one container across its tests and several do global writes.
# All currently green (47 tests across auth / oauth / org-RBAC / registry-access /
# secrets — security-critical surfaces); gated here so they can't silently rot
# the way the DB-harness + Phase-5 binaries did. The test_helpers harness shares
# only the container (one fresh pool per test) so they no longer flake.
TC_TESTS=(
    "auth_tests"
    "oauth_tests"
    "oauth_scoped_token_tests"
    "organization_tests"
    "registry_access_tests"
    "registry_tests"
    "secrets_tests"
)
for tctest in "${TC_TESTS[@]}"; do
    echo
    echo "▶ controller :: ${tctest}  [testcontainers, single-threaded]"
    if ! TALOS_MASTER_KEY="$CTRL_MASTER_KEY" \
        cargo test -p controller --test "$tctest" -- --test-threads=1; then
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
