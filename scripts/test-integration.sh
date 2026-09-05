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

# ── Reaping the TC_TESTS harness containers ────────────────────────────────
#
# The 14 TC_TESTS binaries at the bottom of this script self-provision their own
# Postgres through controller/tests/test_helpers, which holds the handle in a
# `static`. Statics are never dropped, testcontainers 0.23.3 has no reaper, and
# `AutoRemove` is hardcoded false — so before this each binary left one live
# Postgres behind and one run of this script leaked >= 14 of them.
#
# The harness now reaps its own container via `libc::atexit`, which covers a
# clean exit AND a failing/panicking test. It CANNOT cover SIGKILL (an agent
# killed on a rate limit, `kill -9`), so this is the bounded-blast-radius
# backstop for that case.
#
# Every container the harness starts carries `talos.test-harness=controller`;
# when TALOS_TEST_RUN_ID is exported it ALSO carries `talos.test-run=<id>`. The
# exit trap sweeps only THIS run's id, so a concurrent run in another worktree
# is untouched — two concurrent agent sessions is exactly how ~50 containers
# accumulated. `make test-clean` is the deliberate sweep of every run's.
#
# Filtered on the LABEL, never the IMAGE: the dev stack's talos-postgres,
# talos-postgres-backup and talos-vault-backup all run the same
# pgvector/pgvector:pg17 image an image filter would match.
TALOS_TEST_RUN_ID="it-$$-$(date +%s)"
export TALOS_TEST_RUN_ID

cleanup() {
    docker rm -f "$REDIS_NAME" "$PG_NAME" "$NATS_NAME" >/dev/null 2>&1 || true
    local ids
    ids=$(docker ps -aq --filter "label=talos.test-run=${TALOS_TEST_RUN_ID}" 2>/dev/null) || return 0
    [ -n "$ids" ] || return 0
    # shellcheck disable=SC2086  # word splitting is the point: a list of ids
    docker rm -f $ids >/dev/null 2>&1 || true
    echo "▶ reaped $(printf '%s\n' "$ids" | wc -l | tr -d ' ') leaked test-harness container(s) from this run"
}
trap cleanup EXIT
cleanup # remove any stale containers from a previous interrupted run

# Pre-existing harness containers are REPORTED, never removed here. Removing
# every `talos.test-harness=controller` container at start-of-run would kill a
# CONCURRENT run's live container — and two concurrent agent sessions is
# precisely how ~50 of these accumulated. `make test-clean` is the deliberate,
# developer-invoked sweep of every run's; this line is what makes the backlog
# visible instead of silent.
stale_harness=$(docker ps -aq --filter label=talos.test-harness=controller 2>/dev/null | wc -l | tr -d ' ')
if [ "${stale_harness:-0}" -gt 0 ]; then
    echo "⚠ ${stale_harness} test-harness container(s) left by earlier runs (SIGKILL leaves no exit hook) — 'make test-clean' removes them"
fi

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

# ── Readiness gates ─────────────────────────────────────────────────────────
#
# All three probes target the MAPPED TCP PORT from the host, never the
# container's local socket, and each one proves the property the next command
# actually depends on.
#
# The Postgres gate used to be `docker exec "$PG_NAME" pg_isready`, which talks
# to the container's UNIX SOCKET. The official entrypoint runs a TEMPORARY
# server on the socket ONLY — `docker-entrypoint.sh` starts it with
# `-c listen_addresses=''` to run initdb and any init scripts, then
# `docker_temp_server_stop`s it and starts the real one. So the socket probe
# returns READY against a server that is about to shut down, the loop breaks,
# and the next command races the shutdown. Observed on PR #717 as
#
#     ▶ waiting for Postgres…
#     psql: FATAL:  the database system is shutting down
#
# on a branch that touches no script, no Makefile and no workflow — while the
# same job was green on a sibling PR and on main. Measured directly against a
# fresh pgvector:pg17 container: there is a window in which the socket probe
# reports READY and a TCP probe does not. `listen_addresses=''` is what makes
# the TCP probe immune — the temp server cannot answer it at all.
#
# `pg_isready` only proves the postmaster ACCEPTS connections, so the gate ends
# with a real `SELECT 1`: authentication, the default database and query
# execution are what every following command needs.
#
# Redis and NATS previously had NO gate whatsoever — started with `docker run
# -d` and used ~100 lines later. That is the same defect one step worse, and it
# is a latent flake on a loaded runner rather than a safe omission.
wait_for() {
    local label="$1" attempts="$2"; shift 2
    echo "▶ waiting for ${label}…"
    for _ in $(seq 1 "$attempts"); do
        "$@" >/dev/null 2>&1 && return 0
        sleep 1
    done
    echo "✗ ${label} never became ready"
    return 1
}

wait_for "Postgres (TCP ${PG_PORT})" 60 \
    docker exec "$PG_NAME" pg_isready -h 127.0.0.1 -p 5432 -U "$PG_USER" || exit 1
wait_for "Postgres (accepting queries)" 30 \
    docker exec -e PGPASSWORD="$PG_PASS" "$PG_NAME" \
        psql -h 127.0.0.1 -U "$PG_USER" -d talos -c 'SELECT 1' || exit 1

wait_for "Redis (TCP ${REDIS_PORT})" 30 \
    docker exec "$REDIS_NAME" redis-cli -h 127.0.0.1 ping || exit 1

# NATS ships no client binary in the alpine image; its monitoring port is not
# published, so probe the client port's TCP reachability from the host instead.
wait_for "NATS (TCP ${NATS_PORT})" 30 \
    bash -c "printf '' >/dev/tcp/127.0.0.1/${NATS_PORT}" || exit 1

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
    # The attributed stale-execution sweep. Both properties it pins are SQL
    # properties — "the last node that started and never reported" is a LATERAL
    # over execution_events, and "the row finalized between the read and the
    # write" is a status-guarded UPDATE — so only a live database can evaluate
    # them. The wording itself is unit-tested in src/stale_sweep.rs.
    "talos-execution-repository:stale_execution_sweep:migrated"
    # Preview-vs-action scope pins: the per-user predicate on the pinned-module
    # wasm write (a user-scoped read used to drive a cross-tenant UPDATE) and the
    # age filter on the cleanup DELETE (which the find_unreferenced_modules
    # survey has and the DELETE had lost). Both are SQL properties — a live
    # database is the only thing that can evaluate a WHERE clause.
    "talos-module-repository:preview_action_scope:migrated"
    # Can user B resolve user A's private module by NAME? `modules.name` is
    # unique only per user, and the two lookups behind
    # `plan_and_execute_workflow`'s `module_name` resolution carried no owner
    # predicate at all — a caller-supplied string became another tenant's
    # module id (and, through the by-name row read, its description and
    # required secrets). RLS cannot stand in for the predicate here: the
    # policy keys on `org_id`, permits when `app.current_org_ids` is unset,
    # and the app role carries `rolbypassrls`. Every property is a WHERE or
    # ORDER BY clause, so only a live database can evaluate one.
    "talos-module-repository:module_lookup_tenancy:migrated"
    # "the row is absent" vs "we could not look". `ChannelStore::get_entry`
    # folded `execute_op`'s Err(KeyNotFound) into an anyhow string, so
    # Ok(None) was unreachable and three probe handlers answered a pool
    # timeout with 404 "Watch not found" while three stop_watch paths
    # answered one with Ok(()). Both halves are properties of a live
    # database (a real SELECT missing a row; a real pool refusing).
    "talos-integration-helpers:absence_vs_failure:migrated"
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

# ── #661 error-as-absence :: the tier-2 expose_secret daily cap  [redis] ────
# A Redis GET FAILURE used to read as "no counter yet today", which both allowed
# the expose AND ran set_ex(key,1,86400), destroying the day's accumulated
# count. The test induces a real per-command failure (the key is made a LIST, so
# GET returns WRONGTYPE while the connection stays healthy) and asserts the call
# returns Err AND leaves the key untouched. Named here, not merely gated on
# TALOS_TEST_REDIS_URL, so it is real coverage rather than a green skip (the
# workspace `--lib` run in quality.yml has no Redis and skips it).
echo
echo "▶ #661 expose-limit error-as-absence :: talos-worker-runtime  [redis]"
if ! cargo test -p talos-worker-runtime --lib expose_limit_absence_tests; then
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
    # `updated_at` must date a user edit, not a maintenance write. Drives the
    # REAL trigger with the REAL statements the background jobs issue, on the
    # `common` (DATABASE_URL) harness — so it belongs here, not in TC_TESTS.
    "updated_at_maintenance_tests"
    # "scored" and "unscored" are decided from TWO timestamp columns with two
    # writers that each stamp only their own. Drives the background
    # recompute's VERBATIM statement plus the on-demand write-back method, on
    # the `common` (DATABASE_URL) harness — CTRL_TESTS, not TC_TESTS (64b).
    "readiness_scored_state_tests"
    # A sub-workflow leaves no `workflow_executions` row, so the hygiene
    # report's dormant list recommended deleting the flagship's daily child.
    # Renders the REAL recommendation from a REAL HygieneReport; `common`
    # harness, so CTRL_TESTS (64b).
    "dormant_child_workflow_tests"
    # The same blindness on the OTHER draft population #758 called latent: the
    # 7-day `stale_draft_workflows` list, which feeds fix_all's IRREVERSIBLE
    # auto-delete and session_start's auto-archive. Drives the REAL fix_all
    # planning path AND `confirm=true` against a real row; `common` harness,
    # so CTRL_TESTS (64b).
    "stale_draft_child_workflow_tests"
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
    # The 2026-07-30 promotion-legibility binary: drives run_policy_tick for
    # real so the ROTATION cursor and the EVAL-ATTEMPT clock are read back as
    # two separate columns. Pure tests of `should_evaluate` cannot catch a
    # caller that feeds it the wrong column — which is exactly the defect that
    # left one model five days and 161 examples past its last policy verdict.
    "ml_promotion_legibility_tests"
    # #750: the write-ceiling enforcement posture's DB round trip. Uses the
    # `common` DATABASE_URL harness, so it belongs in CTRL_TESTS and not
    # TC_TESTS (sub-leg 64b). It is the only coverage of the parts BETWEEN the
    # pure summariser and the worker's body shape: that the registration write
    # persists both bits, unswapped, on both the `register` and `register_tofu`
    # arms, and that a re-registration overwrites a stale claim including back
    # to NULL.
    "worker_write_ceiling_reporting_tests"
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
    # What `module_executions.duration_ms` MEANS (2026-08-31). The engine
    # measures each dispatch monotonically and a BEFORE UPDATE trigger used to
    # overwrite it with a wall-clock subtraction, so on a suspending host the
    # column recorded sleep as work. The discarding was done by the DATABASE —
    # no pure-Rust test can see it, and only a real Postgres carrying the real
    # trigger can prove a supplied duration survives AND an unsupplied one is
    # still derived.
    "module_execution_duration_tests"
    # What `module_executions.error_type` MEANS (2026-09-04). The column had
    # five writers and none covered a module that RAN and FAILED, so 59 of 59
    # failed rows stored NULL while `ModuleExecution.errorType` published the
    # field over GraphQL. Needs a real Postgres because the derivation is
    # bound inside `record_completed`'s UPDATE: a pure-Rust test proves the
    # classifier, only the round trip proves the value is bound and survives.
    "module_execution_error_type_tests"
    "execution_archive_read_tests"
    # The same question one table over (2026-08-31). `execution_events.
    # duration_ms` was derived by a BEFORE INSERT trigger from two event
    # timestamps while the engine already held a monotonic `Instant` reading
    # at two of the three emit sites. Same reason a real Postgres is required:
    # the discarding is the DATABASE's, and the sentinel/derivation split can
    # only be observed through the round trip.
    "execution_event_duration_tests"
    # Where a wasm.log line lands, and what the writer reports when it lands
    # nowhere (2026-07-30). Needs a real Postgres because the thing under test
    # IS the `WHERE EXISTS` guard on the log INSERT — the predicate that
    # silently discarded every Loop-body iteration's logs while `add_log`
    # returned Ok. A mock cannot fail the way the real statement failed.
    "wasm_log_routing_tests"
    # The `__memory_write__` write-ceiling gate (#750). Needs a real Postgres
    # because the property under test is "no actor_memory ROW" — the thing a
    # silent drop and a correct refusal both produce, distinguished only by the
    # refusal record. Drives the real engine + real ControllerNodeHook.
    # `common` harness ⇒ CTRL_TESTS, not TC_TESTS (sub-leg 64b).
    "write_ceiling_memory_write_tests"
    # Sibling of the above, deliberately a SEPARATE binary: the engine strips a
    # refused envelope before the hook sees it, so the hook's own gate is
    # unreachable from that binary (mutation-proved: neutering it leaves that
    # binary green). This one calls the hook directly, the way test_module
    # does. Also a separate PROCESS, because the memory crypto hook is a
    # process-wide OnceLock.
    "write_ceiling_hook_gate_tests"
    # #754: the THIRD surface of the same control — the signed-RPC mutation
    # routes (`talos.memory.op` Set/Delete, `talos.integration_state.op`
    # Set/Delete, a mutating `talos.database.query`). Deliberately a separate
    # binary again, for the same OnceLock reason as the two above, and because
    # it is the only one that drives a real NATS round trip: it publishes a
    # SIGNED request at the live subscriber and asserts on the DATABASE. Needs
    # `TALOS_TEST_NATS_URL` — exported above for both loops — in addition to
    # the `common` DATABASE_URL harness, so CTRL_TESTS and not TC_TESTS
    # (sub-leg 64b). Fails on pristine main by assertion (`left: 1, right: 0`).
    "rpc_write_ceiling_tests"
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
    # ── Module-payload retention sweep (added 2026-08-27) ───────────────────
    # Proves what the sweep REFUSES to touch: non-terminal rows, and the whole
    # completed corpus of a rarely-run module (the case an age-only policy
    # would silently empty). Nulling an AEAD payload is irreversible, so these
    # are the only guards there are.
    "module_payload_retention_tests"
    # ── Module-execution ROW retention sweep (added 2026-08-28) ─────────────
    # The strictly-more-destructive sibling of the sweep above: it DELETEs rows
    # and CASCADEs their `module_execution_logs` children, leaving NO tombstone
    # — so unlike the payload sweep there is nothing queryable after the fact to
    # tell a deleted execution from one that never ran. Proves what it refuses
    # to touch: non-terminal rows, rows whose parent workflow execution is still
    # alive, and the completed replay corpus of a rarely-run module (whose
    # oldest rows ARE its whole corpus).
    "module_execution_retention_tests"
    # ── Execution retention: ONE path, two tiers (added 2026-09-04) ─────────
    # The archive had held 0 rows across the platform's entire history: a
    # 6-hourly plain DELETE spawned before the daily archival sweep deleted
    # exactly the rows archival existed to move, and the archival statement
    # could not have worked anyway (32 live columns vs 25 archive columns is a
    # PARSE-time error, raised on every tick since 2026-03-26 and discarded by
    # `if let Ok(r) = result`). Nothing could tell: `list_archived_executions`
    # reported "none" forever and no metric or log moved.
    # `archive_schema_parity_in_the_database` is the standing gate the three
    # hand-written `sync_archive_*` migrations never had — it fails the moment
    # a column is added to workflow_executions and not to the archive.
    "execution_retention_tests"
    # ── Archived is not absent (added 2026-09-04) ───────────────────────────
    # #746's first successful archival pass moved 96 executions into
    # `workflow_executions_archive`; within the hour every by-id reader
    # answered "Execution not found or access denied" for one of them — a
    # sentence whose BOTH clauses are false for an archived row. These drive
    # the three-way `ExecutionRepository::lookup_execution` and, more
    # importantly, the RLS backstop the archive never had: measured before
    # this change, `workflow_executions_archive` had relrowsecurity=false and
    # zero policies while holding real tenant ciphertext, so the app-layer
    # `AND user_id = $2` was the only tenancy guard on it.
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
