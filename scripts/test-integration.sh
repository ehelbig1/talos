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
#         TALOS_IT_SHARD=2/3 …   run one third of the work items (quality.yml)
#         TALOS_IT_LIST_ONLY=1 … print this shard's work items and exit (no Docker)
set -euo pipefail

# ── Sharding ────────────────────────────────────────────────────────────────
# TALOS_IT_SHARD=i/n runs every n-th work item starting at item i (1-based),
# so quality.yml can split this suite across n runners. The work list below is
# built in a fixed order, so the shards partition it exactly: every item runs on
# exactly one shard, and `1/1` (the default, `make test-integration` locally) is
# the whole suite. The services and databases above are cheap next to the
# compile, so every shard builds its own; check 88's PREPARE probe is a
# property of the tree, not of a shard, so only shard 1 runs it.
SHARD="${TALOS_IT_SHARD:-1/1}"
SHARD_I="${SHARD%%/*}"
SHARD_N="${SHARD##*/}"
if ! [[ "$SHARD_I" =~ ^[0-9]+$ && "$SHARD_N" =~ ^[0-9]+$ ]] || [ "$SHARD_I" -lt 1 ] || [ "$SHARD_I" -gt "$SHARD_N" ]; then
    echo "✗ TALOS_IT_SHARD must be i/n with 1 <= i <= n (got '$SHARD')" >&2
    exit 1
fi

# ── The work list ───────────────────────────────────────────────────────────
# Test BINARIES are discovered, not listed: scripts/ci_test_targets.py reads
# each tests/*.rs and classifies it (controller `mod common;` → ctrl,
# `mod test_helpers;` → tc, `// ci-runner: integration-serial` → ctrl-serial,
# `// ci-store: <store>` → store). Adding a test file is the whole
# registration; there is no array here for parallel PRs to collide on.
# The `lib:` items are library-test FILTERS (unit tests inside src/ that need
# a live broker or Redis), which a directory walk cannot see — they stay
# literal and change rarely.
WORK=()
while IFS=$'\t' read -r crate bin store; do
    [ -n "$crate" ] && WORK+=("store|${crate}|${bin}|${store}")
done < <(python3 scripts/ci_test_targets.py list store)
WORK+=(
    "lib|talos-envelope-seal|--lib|RFC 0010 P3 claim protocol [nats + redis]"
    "lib|talos-workflow-engine-nats|--lib full_claim_loop|RFC 0010 P3 full dispatch→claim loop [nats]"
    "lib|talos-rpc-subscribers|--lib kernel_two_replica|signed-RPC queue group [nats + nats-perm]"
    "lib|talos-totp-2fa|--lib redis_lockout_tests|2FA cross-instance lockout [redis]"
    "lib|talos-worker-runtime|--lib expose_limit_absence_tests|#661 expose-limit error-as-absence [redis]"
)
for cat in ctrl ctrl-serial tc; do
    while IFS=$'\t' read -r crate bin; do
        [ -n "$crate" ] && WORK+=("${cat}|${crate}|${bin}|")
    done < <(python3 scripts/ci_test_targets.py list "$cat")
done
[ "${#WORK[@]}" -gt 0 ] || { echo "✗ empty work list — discovery is broken" >&2; exit 1; }

if [ "${TALOS_IT_LIST_ONLY:-0}" = "1" ]; then
    for idx in "${!WORK[@]}"; do
        [ $(( idx % SHARD_N + 1 )) -eq "$SHARD_I" ] && printf '%s\n' "${WORK[$idx]}"
    done
    exit 0
fi

echo "▶ shard ${SHARD_I}/${SHARD_N}: $(( (${#WORK[@]} - SHARD_I) / SHARD_N + 1 )) of ${#WORK[@]} work items"

REDIS_PORT="${TALOS_IT_REDIS_PORT:-16399}"
PG_PORT="${TALOS_IT_PG_PORT:-15435}"
NATS_PORT="${TALOS_IT_NATS_PORT:-14222}"
# A SECOND broker running the real compose config (deploy/nats/nats.conf +
# the generated worker permission fragment) with two credentials, for the
# broker-agreement test in talos-workflow-engine-nats. Kept separate from the
# unauthenticated broker above so the existing claim-protocol tests, which
# connect with no credentials, are untouched.
NATS_PERM_PORT="${TALOS_IT_NATS_PERM_PORT:-14223}"
REDIS_NAME="talos-it-redis"
PG_NAME="talos-it-pgvector"
NATS_NAME="talos-it-nats"
NATS_PERM_NAME="talos-it-nats-perm"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PG_USER="postgres"
PG_PASS="test"

# ── Reaping the testcontainer-harness containers ──────────────────────────
#
# The `tc` binaries (scripts/ci_test_targets.py — formerly the TC_TESTS array)
# self-provision their own Postgres through controller/tests/test_helpers,
# which holds the handle in a `static`. Statics are never dropped,
# testcontainers 0.23.3 has no reaper, and
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
    docker rm -f "$REDIS_NAME" "$PG_NAME" "$NATS_NAME" "$NATS_PERM_NAME" >/dev/null 2>&1 || true
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
docker run -d --rm --name "$REDIS_NAME" -p "${REDIS_PORT}:6379" redis:7-alpine@sha256:7aec734b2bb298a1d769fd8729f13b8514a41bf90fcdd1f38ec52267fbaa8ee6 >/dev/null
# `pg_stat_statements` must be PRELOADED at postmaster start, exactly as
# docker-compose.yml does: without it migration 20260908120000 no-ops, the
# talos_ctl template has no extension, and `statement_stats_tests` sees only
# `not_installed`. It is a POSTMASTER GUC, so it can only be set here. (Keep
# this comment ABOVE the command: a `#` line inside a `\` continuation ends it.)
docker run -d --rm --name "$PG_NAME" \
    -e "POSTGRES_USER=${PG_USER}" -e "POSTGRES_PASSWORD=${PG_PASS}" -e POSTGRES_DB=talos \
    -p "${PG_PORT}:5432" pgvector/pgvector:pg17@sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f \
    -c shared_preload_libraries=pg_stat_statements >/dev/null
# NATS for the RFC 0010 P3 (D3b) claim-protocol integration tests (envelope-seal
# responder↔worker handshake + the engine-nats full dispatch→claim→open loop).
# `-js`: the audit-ledger stream-bound test (below) needs JetStream; the claim
# protocol tests do not care either way.
docker run -d --rm --name "$NATS_NAME" -p "${NATS_PORT}:4222" nats:2.10-alpine@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927 -js >/dev/null
# The permissioned broker: the compose nats.conf, byte-for-byte, with the worker
# fragment it includes. Credentials are throwaway literals; what is under test
# is the PERMISSION SET, not the secrets. `-c` only — no JetStream needed here.
docker run -d --rm --name "$NATS_PERM_NAME" -p "${NATS_PERM_PORT}:4222" \
    -v "${REPO_ROOT}/deploy/nats:/etc/nats:ro" \
    -e NATS_USER=it-controller -e NATS_PASSWORD=it-controller-pw \
    -e NATS_WORKER_USER=it-worker -e NATS_WORKER_PASSWORD=it-worker-pw \
    nats:2.10-alpine@sha256:b83efabe3e7def1e0a4a31ec6e078999bb17c80363f881df35edc70fcb6bb927 -c /etc/nats/nats.conf >/dev/null

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
wait_for "NATS-perm (TCP ${NATS_PERM_PORT})" 30 \
    bash -c "printf '' >/dev/tcp/127.0.0.1/${NATS_PERM_PORT}" || exit 1

PG_BASE="postgres://${PG_USER}:${PG_PASS}@127.0.0.1:${PG_PORT}"
MIGRATED_URL="${PG_BASE}/talos"
SELFCONTAINED_URL="${PG_BASE}/talos_sc"
# Dedicated migrated DB for the controller DB-harness binaries (the `ctrl`
# category, formerly the CTRL_TESTS array). They DELETE global tables in
# setup, so they get their own DB to stay isolated from the shared 'talos'
# migrated tests.
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

if [ "$SHARD_I" -eq 1 ]; then
    # Check 88 — every static sqlx statement must PREPARE against the migrated
    # schema. This is the ONLY place it runs with a database: `make lint` leaves
    # the DB leg off (`TALOS_LINT_SQL_PREPARE=1` is opt-in) and, measured
    # 2026-09-12, NOTHING set that variable — no workflow, no runner, no hook — so
    # the gate CLAUDE.md described as "make test-integration runs it against the
    # DB it already builds" had never run anywhere but a developer's shell. The
    # day that was found, #822 had dropped a table one live statement still
    # named, and the probe reported that line on its first run over the tree. The
    # roots mirror `scripts/lint-structural.sh` check 88 (every crate's `src/`
    # except `talos-statement-stats`, whose statements name a relation absent by
    # design). A missing `psql` is a FAILURE, not a skip: asked-for-and-unable-to-
    # run is a green tick over zero statements (checks 64/65).
    echo "▶ check 88: PREPARE every static sqlx statement against 'talos_ctl'…"
    if ! command -v psql >/dev/null 2>&1; then
        echo "✗ psql is not on PATH — check 88 cannot run (install postgresql-client)" >&2
        exit 1
    fi
    SQL_PREPARE_ROOTS=()
    for d in controller worker talos-*; do
        case "$d" in talos-statement-stats) continue ;; esac
        [ -d "$d/src" ] && SQL_PREPARE_ROOTS+=("$d/src")
    done
    python3 scripts/lint-sql-prepare.py --self-test
    python3 scripts/lint-sql-prepare.py "$CTL_URL" "${SQL_PREPARE_ROOTS[@]}"
    # A probe that cannot reach a server must REFUSE, never pass (package BK,
    # 2026-09-15): until then a wrong password, a missing database, a closed port
    # and an unresolvable host all exited 0 with the same "scanned N statements"
    # line as the run above. The run above uses a correct URL, so it cannot see
    # that regression; this one points at a port nothing listens on and requires
    # the harness-failure exit, 2 — not 0 (a pass) and not 1 (a finding).
    set +e
    python3 scripts/lint-sql-prepare.py "postgresql://talos@127.0.0.1:1/talos_ctl" "${SQL_PREPARE_ROOTS[@]}" >/dev/null 2>&1
    unreachable_rc=$?
    set -e
    if [ "$unreachable_rc" -ne 2 ]; then
        echo "✗ check 88's probe exited $unreachable_rc against an unreachable server (want 2)" >&2
        exit 1
    fi
fi

export TALOS_TEST_REDIS_URL="redis://127.0.0.1:${REDIS_PORT}"
export TALOS_TEST_NATS_URL="nats://127.0.0.1:${NATS_PORT}"
export TALOS_TEST_NATS_PERM_URL="nats://127.0.0.1:${NATS_PERM_PORT}"
export TALOS_TEST_NATS_PERM_CONTROLLER_USER=it-controller
export TALOS_TEST_NATS_PERM_CONTROLLER_PASSWORD=it-controller-pw
export TALOS_TEST_NATS_PERM_WORKER_USER=it-worker
export TALOS_TEST_NATS_PERM_WORKER_PASSWORD=it-worker-pw
CTRL_MASTER_KEY="00000000000000000000000000000000000000000000000000000000deadbeef"

rc=0
ran=0
for idx in "${!WORK[@]}"; do
    [ $(( idx % SHARD_N + 1 )) -eq "$SHARD_I" ] || continue
    ran=$((ran + 1))
    IFS='|' read -r kind crate what extra <<< "${WORK[$idx]}"
    echo
    case "$kind" in
        store)
            case "$extra" in
                redis|services) db="" ;;
                migrated)       db="$MIGRATED_URL" ;;
                selfcontained)  db="$SELFCONTAINED_URL" ;;
                *) echo "✗ unknown store '$extra' for ${crate}::${what}" >&2; rc=1; continue ;;
            esac
            echo "▶ ${crate} :: ${what}  [${extra}]"
            TALOS_TEST_DATABASE_URL="$db" cargo test -p "$crate" --test "$what" || rc=1
            ;;
        lib)
            echo "▶ ${crate} ${what}  — ${extra}"
            # shellcheck disable=SC2086  # `what` is a flag plus an optional filter
            cargo test -p "$crate" $what || rc=1
            ;;
        ctrl|ctrl-serial)
            threadflag=()
            [ "$kind" = "ctrl-serial" ] && threadflag=(--test-threads=1)
            echo "▶ controller :: ${what}  [migrated:talos_ctl template → per-test isolated DB]"
            # ${arr[@]+…} guard: bash 3.2 (macOS default) treats an EMPTY array
            # expansion as unbound under `set -u`.
            DATABASE_URL="$CTL_URL" TALOS_MASTER_KEY="$CTRL_MASTER_KEY" \
                cargo test -p controller --test "$what" -- ${threadflag[@]+"${threadflag[@]}"} || rc=1
            ;;
        tc)
            # Self-provisions its own Postgres via testcontainers
            # (controller/tests/test_helpers); ignores DATABASE_URL. One
            # container per binary, several global writes → single-threaded.
            echo "▶ controller :: ${what}  [testcontainers, single-threaded]"
            TALOS_MASTER_KEY="$CTRL_MASTER_KEY" \
                cargo test -p controller --test "$what" -- --test-threads=1 || rc=1
            ;;
    esac
done

echo
echo "▶ shard ${SHARD_I}/${SHARD_N} ran ${ran} of ${#WORK[@]} work items"
if [ "$rc" -eq 0 ]; then
    echo "✓ integration tests passed"
else
    echo "✗ one or more integration tests failed"
fi
exit "$rc"
