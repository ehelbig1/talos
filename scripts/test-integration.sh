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

# Build a migrated DB. RFC 0009 phase 2: by default, load the baseline
# snapshot (`migrations/.baseline/schema.sql` + the `_sqlx_migrations`
# seed) and let `sqlx migrate run` apply only the post-cutpoint tail —
# collapsing the 265-migration replay into one psql load. Safe because
# quality.yml's "Migration baseline verifier" job proves baseline+seed+tail
# is byte-identical to the full chain on every PR. Set
# TALOS_USE_SCHEMA_BASELINE=0 to force the full-chain replay (e.g. when
# debugging a suspected baseline drift the verifier hasn't caught yet).
# psql runs inside the pg container (`docker exec -i`) so the host needs
# no postgres client.
migrate_db() { # $1 = db name, $2 = database url
    if [ "${TALOS_USE_SCHEMA_BASELINE:-1}" != "0" ] && [ -f migrations/.baseline/schema.sql ]; then
        echo "▶ building '$1' from schema baseline + tail (TALOS_USE_SCHEMA_BASELINE=0 for full chain)…"
        docker exec -i "$PG_NAME" psql -q -v ON_ERROR_STOP=1 -U "$PG_USER" -d "$1" \
            < migrations/.baseline/schema.sql >/dev/null
        docker exec -i "$PG_NAME" psql -q -v ON_ERROR_STOP=1 -U "$PG_USER" -d "$1" \
            < migrations/.baseline/seed_sqlx_migrations.sql >/dev/null
    else
        echo "▶ applying full migration chain to '$1'…"
    fi
    DATABASE_URL="$2" sqlx migrate run --source migrations >/dev/null
}

migrate_db talos "$MIGRATED_URL"
echo "▶ creating empty 'talos_sc' for self-contained tests…"
docker exec "$PG_NAME" psql -U "$PG_USER" -d talos -c "CREATE DATABASE talos_sc" >/dev/null
echo "▶ creating 'talos_ctl' for the controller DB-harness binaries…"
docker exec "$PG_NAME" psql -U "$PG_USER" -d talos -c "CREATE DATABASE talos_ctl" >/dev/null
migrate_db talos_ctl "$CTL_URL"

export TALOS_TEST_REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"
export TALOS_TEST_NATS_URL="nats://127.0.0.1:${NATS_PORT}"

# crate : integration-test-binary : datastore (redis | migrated | selfcontained)
TESTS=(
    "talos-idempotency:redis_integration:redis"
    "talos-idempotency:middleware_integration:redis"
    "talos-tenancy:rls_integration:selfcontained"
    "talos-actor-repository:budget_guard_integration:selfcontained"
    # Sibling of budget_guard_integration, same self-contained schema shape.
    # It was written after the June-2026 "every binary runs in CI" sweep and
    # never got an entry, so the write-ceiling GRANT guard (the trigger that
    # refuses a bulk `readonly -> write` escalation) had zero live coverage.
    "talos-actor-repository:write_ceiling_guard_integration:selfcontained"
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
    # #609's closing provenance test (measurement PR 3, D7). Gated here on
    # arrival rather than later: it is the ONLY coverage of the promoted-vs-
    # latest attribution in SQL, and an ungated integration binary is one that
    # silently rots (the PR #181/#182 lesson).
    "ml_measurement_provenance_tests"
    # ── The ml_* / report-quality siblings (gated 2026-07-30) ───────────────
    # Every one of these was written AFTER the June-2026 "100% of tests/-dir
    # binaries run in CI" sweep and landed in a directory that no runner
    # enumerated, so they compiled at authoring time and then ran NOWHERE.
    # Most of them were last EDITED before #520/#527/#607/#609 reworked
    # talos-ml, and three of the four defects found when they were finally
    # executed had been sitting latent for weeks.
    # `ml_registry_tenancy_tests` is the load-bearing one: it is the ONLY
    # guard on the app-layer
    # `AND user_id = $2` predicate in ModelRegistry::{resolve_by_name,
    # resolve_by_id,list_models} — cross-tenant model resolution on the
    # talos.ml.predict serving path is invisible to RLS on a superuser pool.
    # Check 64 (scripts/lint-structural.sh) now fails the lint if a new
    # tests/*.rs binary appears without a runner entry, so this class of
    # decay can't silently re-open.
    "ml_registry_tenancy_tests"
    "ml_correction_tests"
    "ml_dedupe_tests"
    "ml_lifecycle_tests"
    "ml_backend_selection_tests"
    "report_quality_signals_tests"
    "ml_digest_tests"
    "ml_delete_tests"
    "ml_fewshot_tests"
    "ml_provision_tests"
    # ── Tenancy / crypto / status-drift siblings (gated 2026-07-30) ─────────
    # Same story: isolated-DB-harness binaries that never had a runner entry.
    # Three guard a security boundary directly — github_app_tenancy_tests
    # (cross-user GitHub App installation-token minting), oauth_flow_tests
    # (state-token single-use + provider scoping, i.e. the OAuth CSRF gate),
    # integration_state_crypto_tests (per-slot AAD threading). The other
    # three are correctness/drift guards: memory_get_entry_tests (the
    # agent-memory get-entry read path), module_execution_status_tests and
    # execution_status_transition_tests (both exist precisely to fail when a
    # schema/enum or status-guard pair diverges).
    "github_app_tenancy_tests"
    "oauth_flow_tests"
    "integration_state_crypto_tests"
    "memory_get_entry_tests"
    "module_execution_status_tests"
    "execution_status_transition_tests"
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
    # ${arr[@]+…} guard: bash 3.2 (macOS default) treats an EMPTY array
    # expansion as unbound under `set -u` and aborts the whole script here.
    if ! DATABASE_URL="$CTL_URL" TALOS_MASTER_KEY="$CTRL_MASTER_KEY" \
        cargo test -p controller --test "$ctest" -- ${threadflag[@]+"${threadflag[@]}"}; then
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
    # ── Per-org root-DEK (v4) cutover binaries (gated 2026-07-30) ───────────
    # These four are the ONLY end-to-end coverage that encryption-at-rest
    # actually writes format v4 under the right org's root DEK (actor_memory
    # write + re-encrypt sweep, module_executions payloads, workflow output).
    # Their own header comments asserted "Env-gated (runs in quality.yml)" —
    # which was FALSE: no runner named them. The comments now say what is
    # true. They use the testcontainers harness (test_helpers), not the
    # DATABASE_URL harness, so they belong in this block.
    "actor_memory_dek_tests"
    "actor_memory_sweep_dek_tests"
    "module_payload_dek_tests"
    "workflow_output_dek_tests"
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
