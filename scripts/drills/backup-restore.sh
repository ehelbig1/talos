#!/usr/bin/env bash
# Talos backup + restore drill.
#
# "A backup you haven't restored is a hypothesis." This script tests
# the hypothesis end-to-end:
#
#   1. Select the backup artifacts to restore   (newest sidecar dump + vault tar)
#   2. Build the verifiers                      (before anything holds real data)
#   3. Spin up scratch Postgres + Vault         (throwaway net, creds, volumes)
#   4. Restore the Postgres dump into scratch   (pg_restore --exit-on-error)
#   5. Restore the Vault tarball into scratch   (untar into a scratch volume)
#   6. Verify against the restored pair         (verify_restore + verify_phase_b)
#   7. Clean up every scratch container/volume/network
#   8. Emit the Prometheus textfile metric
#
# Exit codes:
#   0  drill passed — backups are restorable
#   1  any step failed — investigate before the next production incident
#
# Usage:
#   ./scripts/drills/backup-restore.sh                 # restore the newest ARTIFACT
#   ./scripts/drills/backup-restore.sh --source live   # dump live now, restore that
#   ./scripts/drills/backup-restore.sh --keep-scratch  # leave scratch up to inspect
#
# See scripts/drills/README.md for scheduling and for what this does NOT cover.

set -euo pipefail

# ══════════════════════════════════════════════════════════════════════════
# 2026-08-03 — what the first-ever run of this script found, and what changed.
#
# Written 2026-05-25, never once executed until 2026-08-03. It PASSED, which
# was the least interesting thing about the run. Every item below is a real
# defect that a passing drill was hiding.
#
#  1. IT NEVER TOUCHED A BACKUP. Step 1 took a FRESH `pg_dump` of the live
#     database and restored that. So the artifact the `postgres-backup` /
#     `vault-backup` sidecars have been writing every day — the thing an
#     actual recovery would reach for — remained, after a green drill, the
#     backup nobody had ever restored. `--source artifact` is now the DEFAULT
#     and `--source live` is the opt-in.
#  2. IT LEAKED THE ENTIRE RESTORED DATABASE. `docker run --rm` + a trap
#     doing `docker rm -f` (no `-v`) left the scratch Postgres's ANONYMOUS
#     data volume behind on every run: 421 MB of real, DEK-encrypted user
#     data, unreferenced, invisible to `docker ps -a`, surviving reboots.
#     Every volume is named and removed explicitly now, `docker rm -fv` is
#     used, and cleanup ASSERTS afterwards that nothing survived.
#  3. `pg_restore` RAN WITHOUT `--exit-on-error`. pg_restore exits 0 after
#     non-fatal errors, so an arbitrary number of failed objects reported as
#     "✓ restore complete". (The backup sidecar's own loop already used
#     `--exit-on-error`; the drill, which exists to be stricter, did not.)
#  4. IT COMPILED THE WORKSPACE WHILE HOLDING REAL DATA. Step 6 was
#     `cargo run`, with `DATABASE_URL` exported — which changes the sqlx
#     macro fingerprint and rebuilds half the workspace. Measured: 17m39s
#     wall for the first run, ~17m of it compiling, with a scratch Postgres
#     full of restored user data listening on a host port the whole time.
#     The verifiers are now built BEFORE any data is staged, with
#     `env -u DATABASE_URL`, and the built binaries are executed directly.
#  5. THE SCRATCH STACK RAN ON LIVE CREDENTIALS. It copied POSTGRES_USER /
#     POSTGRES_PASSWORD out of the live container into the scratch one, so
#     the live database password was also the password on a second, less
#     guarded copy of the same data. Scratch credentials are now generated
#     per run and thrown away.
#  6. IT EMITTED NO METRIC, SILENTLY. The default textfile directory
#     (`/var/lib/node_exporter/textfile_collector`) existed nowhere in this
#     repo and no node_exporter was deployed anywhere, so every run ended in
#     "textfile dir not writable — skipping metric emission" at WARN and
#     `TalosBackupRestoreDrillFailed` could never clear. The default now
#     points at the directory the dev stack's textfile-only node-exporter
#     mounts, the directory is created, and an un-writable one is FATAL
#     unless explicitly waived.
#  7. IT VERIFIED THE WRONG THING. The only check was `verify_phase_b`, which
#     WRITES a new row and reads it back — a test that the restored crypto
#     stack can encrypt something new, not that the restored ciphertext can
#     be read. `verify_restore` (added alongside) decrypts PRE-EXISTING
#     actor_memory and secrets rows, sampled per on-disk format and per DEK,
#     checks the schema version, and reports row counts.
#  8. NO PRODUCTION GUARD. The header said "cron-ready" and the README gave
#     a systemd unit for a k3s host; nothing stopped it from being pointed at
#     a production stack, where it would dump the live database to /tmp.
#  9. A DRILL COULD ABORT AND STILL REPORT SUCCESS. Found while rewriting,
#     not in the original: on macOS's bash 3.2 a `set -u` violation inside a
#     `cmd || die` list stops the script and leaves `$?` at **0**. A cron or
#     systemd job reading only the exit code would have recorded a run that
#     died at step 5 as green. Fixed generally with the `DRILL_COMPLETE`
#     sentinel in cleanup_scratch rather than by chasing the one expansion.
#     Anything that reads a drill's outcome should prefer the METRIC (which
#     only advances on a completed run) over the exit code.
# ══════════════════════════════════════════════════════════════════════════

# ── Config ────────────────────────────────────────────────────────
DRILL_ID="drill-$(date -u +%Y%m%dT%H%M%SZ)"
KEEP_SCRATCH=0
SOURCE_MODE="artifact"

# Where the backup sidecars write. Same default as docker-compose.yml's
# `postgres-backup` / `vault-backup` services.
BACKUP_DIR="${TALOS_DRILL_BACKUP_DIR:-${TALOS_BACKUP_DIR:-$HOME/.talos/backups}}"

# Where the drill publishes its Prometheus metric. This must be a directory
# some collector actually reads: see docker-compose.yml's `node-exporter`
# service, which mounts exactly this path read-only. On a host running a
# system node_exporter, point it at that instead:
#   TALOS_DRILL_TEXTFILE_DIR=/var/lib/node_exporter/textfile_collector
TEXTFILE_DIR="${TALOS_DRILL_TEXTFILE_DIR:-${TALOS_TEXTFILE_DIR:-$HOME/.talos/metrics/textfile_collector}}"
TEXTFILE="$TEXTFILE_DIR/talos_backup_drill.prom"

# Scratch identities. `$$` keeps concurrent runs from colliding; every one of
# these is removed by cleanup_scratch on EVERY exit path.
SCRATCH_PG_NAME="talos-drill-pg-$$"
SCRATCH_VAULT_NAME="talos-drill-vault-$$"
SCRATCH_PG_VOLUME="talos-drill-pgdata-$$"
SCRATCH_VAULT_VOLUME="talos-drill-vault-data-$$"
SCRATCH_VAULT_LOGS="talos-drill-vault-logs-$$"
SCRATCH_NETWORK="talos-drill-net-$$"
SCRATCH_PG_PORT=""   # assigned by docker; see step 3

# Throwaway scratch credentials. NEVER the live ones (see note 5 above):
# the scratch container is a second, less-guarded copy of the same data, and
# sharing the password makes the live database only as safe as the copy.
SCRATCH_PG_USER="drill"
SCRATCH_PG_DB="talos_drill_restore"
SCRATCH_PG_PASSWORD="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"

LIVE_PG_CONTAINER="${TALOS_DRILL_LIVE_PG:-talos-postgres}"
LIVE_VAULT_CONTAINER="${TALOS_DRILL_LIVE_VAULT:-talos-vault}"
LIVE_CONTROLLER="${TALOS_DRILL_LIVE_CONTROLLER:-talos-controller}"
PG_IMAGE="${TALOS_DRILL_PG_IMAGE:-pgvector/pgvector:pg16@sha256:7d400e340efb42f4d8c9c12c6427adb253f726881a9985d2a471bf0eed824dff}"
VAULT_IMAGE="${TALOS_DRILL_VAULT_IMAGE:-hashicorp/vault:1.18@sha256:750bb37c1638fa194ab37053a81618c61bb0491ddec6fccac87c07a8e6cd8166}"

# Parse args.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-scratch) KEEP_SCRATCH=1; shift ;;
        --source) SOURCE_MODE="${2:-}"; shift 2 ;;
        --source=*) SOURCE_MODE="${1#*=}"; shift ;;
        --help|-h) sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done
case "$SOURCE_MODE" in
    artifact|live) ;;
    *) echo "--source must be 'artifact' (default) or 'live', got '$SOURCE_MODE'" >&2; exit 1 ;;
esac

# ── Output helpers. No ansi codes go to the textfile. ─────────────
log()  { printf '\033[1;34m▶ [%s] %s\033[0m\n' "$(date -u +%H:%M:%S)" "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m⚠ %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; emit_metric failure; exit 1; }

# ── Textfile metric for Prometheus scrape. ────────────────────────
# Atomic write via rename. The temp file is created INSIDE the target
# directory so the rename is same-filesystem and therefore actually atomic —
# `mktemp` in $TMPDIR can land on a different device, where `mv` degrades to
# copy+unlink and a collector can read a half-written file.
METRIC_EMITTED=0
emit_metric() {
    local status="$1"; local ts; ts=$(date +%s)
    # `die` emits, then the EXIT trap's incomplete-run check would emit the
    # same failure again. Once is enough and twice reads like two runs.
    (( METRIC_EMITTED == 1 )) && return 0
    METRIC_EMITTED=1
    if [[ ! -d "$TEXTFILE_DIR" ]] || [[ ! -w "$TEXTFILE_DIR" ]]; then
        # Reachable only when metric emission was explicitly waived (the
        # pre-flight makes it fatal otherwise), or when the directory
        # disappeared mid-run.
        warn "textfile dir $TEXTFILE_DIR not writable — metric NOT emitted ($status)"
        return 0
    fi
    local tmp; tmp=$(mktemp "$TEXTFILE_DIR/.talos_backup_drill.XXXXXX")
    {
        echo "# HELP talos_backup_drill_last_run_timestamp_seconds Unix timestamp of the most recent drill attempt."
        echo "# TYPE talos_backup_drill_last_run_timestamp_seconds gauge"
        echo "talos_backup_drill_last_run_timestamp_seconds $ts"
        echo "# HELP talos_backup_drill_last_success_timestamp_seconds Unix timestamp of the most recent SUCCESSFUL drill."
        echo "# TYPE talos_backup_drill_last_success_timestamp_seconds gauge"
        if [[ "$status" == "success" ]]; then
            echo "talos_backup_drill_last_success_timestamp_seconds $ts"
        else
            # Preserve previous success timestamp when available so the
            # alert threshold compares against the last actually-green run.
            local prev="0"
            if [[ -f "$TEXTFILE" ]]; then
                prev=$(grep -E '^talos_backup_drill_last_success_timestamp_seconds ' "$TEXTFILE" \
                    | awk '{print $2}' | head -1)
                [[ -z "$prev" ]] && prev="0"
            fi
            echo "talos_backup_drill_last_success_timestamp_seconds $prev"
        fi
        echo "# HELP talos_backup_drill_last_status Status of the most recent drill (1=success, 0=failure)."
        echo "# TYPE talos_backup_drill_last_status gauge"
        [[ "$status" == "success" ]] && echo "talos_backup_drill_last_status 1" || echo "talos_backup_drill_last_status 0"
    } > "$tmp"
    chmod 644 "$tmp"
    mv "$tmp" "$TEXTFILE"
    ok "emitted metric → $TEXTFILE ($status)"
}

# ── Cleanup. Runs on EVERY exit path: success, failure, and signal. ──
# EXIT alone is not enough. Bash runs the EXIT trap when a trapped signal
# terminates the shell, but an UNTRAPPED SIGINT can kill it first — and this
# script's scratch containers hold real restored user data, so "usually
# cleans up" is not a property worth having. INT/TERM/HUP are trapped
# explicitly and re-raised after cleanup so the exit status still says
# "killed by a signal".
#
# The trap ALSO enforces that the drill ran to the end. Discovered while
# rewriting this script, on macOS's bash 3.2: a `set -u` violation
# (`"${EMPTY_ARRAY[@]}"` is "unbound" there) inside a `cmd || die` list
# aborts the script — and bash reports exit status **0**. Verified in
# isolation: the run stops mid-way, prints the unbound-variable message, and
# `$?` is 0. Anything reading only the exit code (cron, launchd, systemd, a
# CI step) would record a drill that stopped at step 5 as a success. The
# `DRILL_COMPLETE` sentinel closes that generally rather than one bug at a
# time: unless step 7 is reached, the trap forces a non-zero exit and a
# failure metric, whatever aborted the run.
DRILL_COMPLETE=0
CLEANED=0
cleanup_scratch() {
    local code=$?
    (( CLEANED == 1 )) && return
    CLEANED=1
    if (( KEEP_SCRATCH == 1 )) && (( code == 0 )); then
        warn "--keep-scratch: leaving scratch stack UP. It holds REAL restored data."
        warn "  containers: $SCRATCH_PG_NAME $SCRATCH_VAULT_NAME"
        warn "  volumes:    $SCRATCH_PG_VOLUME $SCRATCH_VAULT_VOLUME $SCRATCH_VAULT_LOGS"
        warn "  remove with: docker rm -fv $SCRATCH_PG_NAME $SCRATCH_VAULT_NAME &&"
        warn "               docker volume rm $SCRATCH_PG_VOLUME $SCRATCH_VAULT_VOLUME $SCRATCH_VAULT_LOGS &&"
        warn "               docker network rm $SCRATCH_NETWORK && rm -rf ${WORK_DIR:-<workdir>}"
        return
    fi
    # `-v` is load-bearing: without it the container's ANONYMOUS volumes
    # survive, and for the Postgres image that anonymous volume IS the
    # restored database (421 MB of real user data on the 2026-08-03 run).
    docker rm -fv "$SCRATCH_PG_NAME" "$SCRATCH_VAULT_NAME" >/dev/null 2>&1 || true
    docker volume rm "$SCRATCH_PG_VOLUME" "$SCRATCH_VAULT_VOLUME" "$SCRATCH_VAULT_LOGS" >/dev/null 2>&1 || true
    docker network rm "$SCRATCH_NETWORK" >/dev/null 2>&1 || true
    [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]] && rm -rf "$WORK_DIR"

    # Assert, don't assume. A cleanup that silently failed is how note 2
    # above survived from May to August.
    local leaked=""
    for c in "$SCRATCH_PG_NAME" "$SCRATCH_VAULT_NAME"; do
        docker inspect "$c" >/dev/null 2>&1 && leaked="$leaked container:$c"
    done
    for v in "$SCRATCH_PG_VOLUME" "$SCRATCH_VAULT_VOLUME" "$SCRATCH_VAULT_LOGS"; do
        docker volume inspect "$v" >/dev/null 2>&1 && leaked="$leaked volume:$v"
    done
    [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]] && leaked="$leaked workdir:$WORK_DIR"
    if [[ -n "$leaked" ]]; then
        printf '\033[1;31m✗ CLEANUP INCOMPLETE — remove by hand:%s\033[0m\n' "$leaked" >&2
    fi

    # Did not reach step 7 ⇒ this run is a FAILURE, whatever the shell says
    # and whatever aborted it. Publish that: an abort under `set -e`/`set -u`
    # never reaches `die`, so without this the metric would keep whatever the
    # previous run left behind and `last_run`/`last_status` would describe a
    # run that did not happen.
    if (( DRILL_COMPLETE == 0 )); then
        emit_metric failure
        # Only rewrite the status when the shell is claiming success. On the
        # signal path the caller re-raises the signal itself, so forcing an
        # exit here would replace "killed by SIGINT" with a plain 1.
        if (( code == 0 )) && (( ${IN_SIGNAL:-0} == 0 )); then
            printf '\033[1;31m✗ drill ABORTED before completing (shell reported success) — treating as FAILURE\033[0m\n' >&2
            # `exit` inside an EXIT trap sets the final status and does not
            # re-enter the trap.
            exit 1
        fi
    fi
    # End on a deliberate success so the trap's own status can never become
    # the script's — a trailing `[[ … ]]` that happens to be false here would
    # rewrite a real exit code.
    return 0
}
IN_SIGNAL=0
on_signal() {
    local sig="$1"
    IN_SIGNAL=1
    printf '\033[1;33m⚠ caught %s — tearing down scratch stack\033[0m\n' "$sig" >&2
    cleanup_scratch
    trap - "$sig"
    kill -s "$sig" $$
}
trap cleanup_scratch EXIT
for s in INT TERM HUP; do
    # shellcheck disable=SC2064  # expand $s now, that is the point
    trap "on_signal $s" "$s"
done

# ── 0. Pre-flight ─────────────────────────────────────────────────
log "drill id: $DRILL_ID (source: $SOURCE_MODE)"

command -v docker >/dev/null || die "docker CLI not found"
docker info >/dev/null 2>&1 || die "docker daemon not reachable"

# PRODUCTION GUARD. This script dumps a database to a temp directory and
# stands up a second copy of it. That is a fine thing to do to a dev stack
# and a bad thing to do to production, where the restore rehearsal belongs on
# isolated infrastructure with its own credentials — not on the production
# host, driven by the production docker socket. Refuse rather than trust the
# operator to have read the README.
PROD_SIGNAL=""
for v in RUST_ENV TALOS_ENV NODE_ENV; do
    [[ "${!v:-}" == "production" ]] && PROD_SIGNAL="$PROD_SIGNAL $v(shell)"
done
if docker inspect "$LIVE_CONTROLLER" >/dev/null 2>&1; then
    for v in RUST_ENV TALOS_ENV; do
        cval=$(docker exec "$LIVE_CONTROLLER" printenv "$v" 2>/dev/null || true)
        [[ "$cval" == "production" ]] && PROD_SIGNAL="$PROD_SIGNAL $v($LIVE_CONTROLLER)"
    done
fi
if [[ -n "$PROD_SIGNAL" ]]; then
    if [[ "${TALOS_DRILL_ALLOW_PRODUCTION:-0}" == "1" ]]; then
        warn "production signals present ($PROD_SIGNAL) — proceeding, TALOS_DRILL_ALLOW_PRODUCTION=1"
    else
        die "REFUSING: production environment detected ($PROD_SIGNAL ). Run the restore
   rehearsal on isolated infrastructure. Override with TALOS_DRILL_ALLOW_PRODUCTION=1
   only if you have read scripts/drills/README.md and accept what this does."
    fi
fi

# Never reuse a live name. A collision here would mean the cleanup trap
# deletes something that is not ours.
for n in "$SCRATCH_PG_NAME" "$SCRATCH_VAULT_NAME"; do
    docker inspect "$n" >/dev/null 2>&1 && die "scratch name '$n' already exists — refusing to clobber it"
done
for v in "$SCRATCH_PG_VOLUME" "$SCRATCH_VAULT_VOLUME" "$SCRATCH_VAULT_LOGS"; do
    docker volume inspect "$v" >/dev/null 2>&1 && die "scratch volume '$v' already exists — refusing to clobber it"
done

# Metric emission is a PRECONDITION, not a nice-to-have. A drill that runs
# green and publishes nothing leaves TalosBackupRestoreDrillFailed firing,
# which is indistinguishable from a drill that never ran — the exact state
# this repo was in from 2026-05-25 to 2026-08-03.
if ! mkdir -p "$TEXTFILE_DIR" 2>/dev/null || [[ ! -w "$TEXTFILE_DIR" ]]; then
    if [[ "${TALOS_DRILL_ALLOW_NO_METRIC:-0}" == "1" ]]; then
        warn "textfile dir $TEXTFILE_DIR unusable — continuing without a metric (waived)"
    else
        die "textfile dir '$TEXTFILE_DIR' is not writable.
   The drill's whole outcome is published through it; without it a green run
   cannot clear TalosBackupRestoreDrillFailed. Create it, point
   TALOS_DRILL_TEXTFILE_DIR at your collector's directory, or waive with
   TALOS_DRILL_ALLOW_NO_METRIC=1 (and accept a permanently-firing alert)."
    fi
fi

# WORK_DIR holds a full database dump and the Vault file backend in the
# clear. mktemp gives an unpredictable name with 0700 — a fixed
# /tmp/drill-<timestamp>, which is what this used, is guessable and
# pre-creatable by any local user.
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/talos-drill-XXXXXXXX")"
chmod 700 "$WORK_DIR"

# ── 1. Select the artifacts to restore ────────────────────────────
if [[ "$SOURCE_MODE" == "artifact" ]]; then
    log "[1/7] selecting backup artifacts from $BACKUP_DIR"
    [[ -d "$BACKUP_DIR" ]] || die "backup dir '$BACKUP_DIR' does not exist — is the backup sidecar running?"

    PG_ARTIFACT=$(ls -1t "$BACKUP_DIR"/talos-*.dump 2>/dev/null | head -1 || true)
    [[ -n "$PG_ARTIFACT" ]] || die "no talos-*.dump in $BACKUP_DIR — nothing to restore
   (the postgres-backup sidecar writes these; check 'docker logs talos-postgres-backup')"
    VAULT_ARTIFACT=$(ls -1t "$BACKUP_DIR"/vault/vault-*.tar.gz 2>/dev/null | head -1 || true)
    [[ -n "$VAULT_ARTIFACT" ]] || die "no vault-*.tar.gz in $BACKUP_DIR/vault — nothing to restore"

    # The vault sidecar writes a manifest with a sha256 next to each archive.
    # Checking it here is the only place that number is ever USED.
    if [[ -f "$VAULT_ARTIFACT.manifest" ]]; then
        want=$(grep -E '^sha256=' "$VAULT_ARTIFACT.manifest" | cut -d= -f2)
        got=$(shasum -a 256 "$VAULT_ARTIFACT" 2>/dev/null | awk '{print $1}')
        [[ -z "$got" ]] && got=$(sha256sum "$VAULT_ARTIFACT" | awk '{print $1}')
        [[ "$want" == "$got" ]] || die "vault artifact sha256 mismatch — $VAULT_ARTIFACT is corrupt"
        ok "vault artifact sha256 matches its manifest"
    else
        warn "no manifest beside $VAULT_ARTIFACT — integrity unverified"
    fi

    cp "$PG_ARTIFACT" "$WORK_DIR/pg.dump"
    cp "$VAULT_ARTIFACT" "$WORK_DIR/vault.tgz"
    # Sidecar tarballs are rooted at ./ (the contents of /vault/file); the
    # --source live path below produces vault/file/... instead. Recorded here
    # so step 5 extracts each into the right place.
    VAULT_TAR_ROOT="contents"
    # mtime, portably: BSD `stat -f %m`, GNU `stat -c %Y`. A stale artifact
    # date is the first thing to look at when a drill result is surprising.
    PG_ARTIFACT_MTIME="$(stat -f %m "$PG_ARTIFACT" 2>/dev/null || stat -c %Y "$PG_ARTIFACT" 2>/dev/null || echo '')"
    PG_ARTIFACT_AGE="$([[ -n "$PG_ARTIFACT_MTIME" ]] && date -u -r "$PG_ARTIFACT_MTIME" +%FT%TZ 2>/dev/null || echo '?')"
    ok "postgres artifact: $(basename "$PG_ARTIFACT") ($(wc -c < "$WORK_DIR/pg.dump") bytes, taken $PG_ARTIFACT_AGE)"
    ok "vault artifact:    $(basename "$VAULT_ARTIFACT") ($(wc -c < "$WORK_DIR/vault.tgz") bytes)"
else
    log "[1/7] dumping LIVE postgres + vault (--source live)"
    docker inspect "$LIVE_PG_CONTAINER" >/dev/null 2>&1 || die "live postgres container '$LIVE_PG_CONTAINER' not running"
    docker inspect "$LIVE_VAULT_CONTAINER" >/dev/null 2>&1 || die "live vault container '$LIVE_VAULT_CONTAINER' not running"
    LIVE_PG_USER=$(docker exec "$LIVE_PG_CONTAINER" printenv POSTGRES_USER 2>/dev/null || true)
    LIVE_PG_DB=$(docker exec "$LIVE_PG_CONTAINER" printenv POSTGRES_DB 2>/dev/null || true)
    LIVE_PG_PASSWORD=$(docker exec "$LIVE_PG_CONTAINER" printenv POSTGRES_PASSWORD 2>/dev/null || true)
    [[ -n "$LIVE_PG_USER" && -n "$LIVE_PG_DB" && -n "$LIVE_PG_PASSWORD" ]] \
        || die "could not read POSTGRES_USER/DB/PASSWORD from $LIVE_PG_CONTAINER env"
    docker exec -e PGPASSWORD="$LIVE_PG_PASSWORD" "$LIVE_PG_CONTAINER" \
        pg_dump --username="$LIVE_PG_USER" --dbname="$LIVE_PG_DB" \
            --format=custom --compress=9 --no-owner --no-privileges \
        > "$WORK_DIR/pg.dump" \
        || die "pg_dump failed"
    docker exec "$LIVE_VAULT_CONTAINER" tar -czf - -C / vault/file > "$WORK_DIR/vault.tgz" \
        || die "vault tar failed"
    VAULT_TAR_ROOT="prefixed"
    ok "live pg.dump ($(wc -c < "$WORK_DIR/pg.dump") bytes) + vault.tgz ($(wc -c < "$WORK_DIR/vault.tgz") bytes)"
fi

# ── 2. Build the verifiers BEFORE anything holds real data ────────
# `cargo run` at verify time was the original shape and it is a trap: the
# drill exports DATABASE_URL, which is part of the sqlx macro fingerprint, so
# the "run" recompiles a large part of the workspace — 17 minutes on the
# 2026-08-03 run — with a scratch Postgres full of restored user data
# listening on a loopback port for every second of it. Build first, with
# DATABASE_URL scrubbed, then execute the binaries directly.
log "[2/7] building verifiers (this is the slow step; nothing is staged yet)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"
env -u DATABASE_URL cargo build --quiet --example verify_restore --example verify_phase_b -p controller \
    || die "could not build the verifiers — fix the build before trusting a drill result"
TARGET_DIR="$(env -u DATABASE_URL cargo metadata --no-deps --format-version 1 \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
VERIFY_RESTORE_BIN="$TARGET_DIR/debug/examples/verify_restore"
VERIFY_PHASE_B_BIN="$TARGET_DIR/debug/examples/verify_phase_b"
for b in "$VERIFY_RESTORE_BIN" "$VERIFY_PHASE_B_BIN"; do
    [[ -x "$b" ]] || die "verifier binary missing after build: $b"
done
ok "verifiers built"

# The KEK material must match how the DEKs were wrapped, so it comes from the
# live controller — this is the one live secret the drill needs, it is never
# logged, and it never leaves this process's environment.
docker inspect "$LIVE_CONTROLLER" >/dev/null 2>&1 || die "live controller '$LIVE_CONTROLLER' not running (needed for the KEK)"
TALOS_MASTER_KEY=$(docker exec "$LIVE_CONTROLLER" printenv TALOS_MASTER_KEY 2>/dev/null || echo "")
[[ -n "$TALOS_MASTER_KEY" ]] || die "could not read TALOS_MASTER_KEY from $LIVE_CONTROLLER"
KEK_PROVIDER_LIVE=$(docker exec "$LIVE_CONTROLLER" printenv KEK_PROVIDER 2>/dev/null || echo "vault")

# ── 3. Spin up scratch Postgres ───────────────────────────────────
# A dedicated bridge network: the scratch stack must never be able to reach
# the live one, and vice versa.
log "[3/7] starting scratch postgres (throwaway net + creds + volume)"
docker network create "$SCRATCH_NETWORK" >/dev/null || die "could not create scratch network"
docker volume create "$SCRATCH_PG_VOLUME" >/dev/null || die "could not create scratch pg volume"

# Loopback-only, EPHEMERAL host port. A published port is unavoidable: the
# verifiers run on the host (they are host-arch binaries built from this
# checkout, and a container that could run them would have to compile the
# workspace), and Docker Desktop cannot share a unix socket across the VM
# boundary. So it is bound to 127.0.0.1 — never a LAN interface — on a port
# the kernel picks rather than a fixed, guessable 55432, and it exists only
# for the seconds between restore and verify.
docker run -d \
    --name "$SCRATCH_PG_NAME" \
    --network "$SCRATCH_NETWORK" \
    -e POSTGRES_USER="$SCRATCH_PG_USER" \
    -e POSTGRES_DB="$SCRATCH_PG_DB" \
    -e POSTGRES_PASSWORD="$SCRATCH_PG_PASSWORD" \
    -v "$SCRATCH_PG_VOLUME:/var/lib/postgresql/data" \
    -p "127.0.0.1::5432" \
    "$PG_IMAGE" >/dev/null \
    || die "scratch postgres failed to start"
SCRATCH_PG_PORT="$(docker port "$SCRATCH_PG_NAME" 5432/tcp | head -1 | sed 's/.*://')"
[[ -n "$SCRATCH_PG_PORT" ]] || die "could not resolve the scratch postgres host port"

for i in $(seq 1 60); do
    if docker exec "$SCRATCH_PG_NAME" pg_isready -U "$SCRATCH_PG_USER" >/dev/null 2>&1; then
        ok "scratch postgres ready on 127.0.0.1:$SCRATCH_PG_PORT"
        break
    fi
    sleep 1
    (( i == 60 )) && die "scratch postgres never became ready"
done

# ── 4. Restore the dump into scratch ──────────────────────────────
log "[4/7] restoring dump into scratch postgres"
docker cp "$WORK_DIR/pg.dump" "$SCRATCH_PG_NAME:/tmp/pg.dump" || die "could not copy dump into scratch"
# --exit-on-error is the difference between "restored" and "attempted".
# pg_restore's default is to log an error, carry on, and exit 0 — so without
# this flag any number of failed objects reports as a clean restore. The
# backup sidecar's own verify already used it; the drill did not.
if ! docker exec -e PGPASSWORD="$SCRATCH_PG_PASSWORD" "$SCRATCH_PG_NAME" \
        pg_restore --username="$SCRATCH_PG_USER" --dbname="$SCRATCH_PG_DB" \
            --no-owner --no-privileges --exit-on-error \
            /tmp/pg.dump > "$WORK_DIR/pg_restore.log" 2>&1; then
    warn "pg_restore output (last 30 lines):"
    tail -30 "$WORK_DIR/pg_restore.log" >&2 || true
    die "pg_restore FAILED — this backup is not restorable"
fi
docker exec "$SCRATCH_PG_NAME" rm -f /tmp/pg.dump >/dev/null 2>&1 || true
ok "restore complete with --exit-on-error (no object failed)"

# ── 5. Restore Vault into scratch and unseal it ───────────────────
log "[5/7] restoring vault + unsealing"
docker volume create "$SCRATCH_VAULT_VOLUME" >/dev/null
docker volume create "$SCRATCH_VAULT_LOGS" >/dev/null

# Sidecar artifacts are rooted at the CONTENTS of /vault/file; a --source
# live tarball carries the vault/file/ prefix. Extracting the wrong one
# yields an empty file backend and a vault that "starts" uninitialised —
# which looks like a successful restore right up to the unseal.
if [[ "$VAULT_TAR_ROOT" == "contents" ]]; then
    EXTRACT_CMD='mkdir -p /vault/file && tar -xzf /in/vault.tgz -C /vault/file && ls /vault/file/'
else
    EXTRACT_CMD='tar -xzf /in/vault.tgz -C / && ls /vault/file/'
fi
docker run --rm \
    --network none \
    -v "$SCRATCH_VAULT_VOLUME:/vault/file" \
    -v "$WORK_DIR:/in:ro" \
    --entrypoint sh \
    "$VAULT_IMAGE" \
    -c "$EXTRACT_CMD" \
    >/dev/null || die "vault restore failed"

cat > "$WORK_DIR/vault.hcl" <<EOF
storage "file" { path = "/vault/file" }
listener "tcp" {
    address     = "0.0.0.0:8200"
    tls_disable = 1
}
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
EOF
chmod 644 "$WORK_DIR/vault.hcl"

# No published port. Everything the drill asks of the scratch Vault is done
# with `docker exec`; the host only needs a VAULT_ADDR when KEK_PROVIDER is
# `vault`, and in that case the verifier reaches it over the scratch network
# (see below) rather than through the host.
#
# `VAULT_PORT_ARGS` is expanded with the `${arr[@]+…}` guard because macOS
# ships bash 3.2, where `"${EMPTY[@]}"` under `set -u` is an UNBOUND VARIABLE
# error — which, inside a `cmd || die` list, aborts the script and yields exit
# status 0. That is precisely how the second run of this rewrite "passed"
# while stopping at step 5.
VAULT_PORT_ARGS=()
if [[ "$KEK_PROVIDER_LIVE" == "vault" ]]; then
    VAULT_PORT_ARGS=(-p "127.0.0.1::8200")
fi
docker run -d \
    --name "$SCRATCH_VAULT_NAME" \
    --network "$SCRATCH_NETWORK" \
    --cap-add=IPC_LOCK \
    -v "$SCRATCH_VAULT_VOLUME:/vault/file" \
    -v "$SCRATCH_VAULT_LOGS:/vault/logs" \
    -v "$WORK_DIR/vault.hcl:/vault/config/vault.hcl:ro" \
    ${VAULT_PORT_ARGS[@]+"${VAULT_PORT_ARGS[@]}"} \
    -e VAULT_ADDR=http://127.0.0.1:8200 \
    -e SKIP_CHOWN=true -e SKIP_SETCAP=true \
    "$VAULT_IMAGE" \
    vault server -config=/vault/config/vault.hcl >/dev/null \
    || die "scratch vault failed to start"

for i in $(seq 1 60); do
    # `vault status` exits 2 when sealed — which is exactly the state a
    # freshly restored file backend should be in, so 0 and 2 both mean "the
    # API is up". Any other code means it is not.
    #
    # The `|| rc=$?` is required, not stylistic: `set -e` kills the script on
    # the BARE command, before the next line can capture its status. Written
    # bare, this loop aborted the drill with exit 2 the instant Vault reported
    # "sealed" — the expected state. Caught by running it.
    rc=0
    docker exec "$SCRATCH_VAULT_NAME" vault status >/dev/null 2>&1 || rc=$?
    if (( rc == 0 || rc == 2 )); then ok "scratch vault listening"; break; fi
    sleep 1
    (( i == 60 )) && die "scratch vault never started"
done

docker exec "$SCRATCH_VAULT_NAME" test -f /vault/file/bootstrap.json \
    || die "restored vault has no bootstrap.json — the unseal key is not in this backup"

UNSEAL_KEY=$(docker exec "$SCRATCH_VAULT_NAME" sh -c \
    "awk '/\"unseal_keys_b64\"/{f=1;next} /\]/{f=0} f' /vault/file/bootstrap.json \
        | sed -n 's/.*\"\\([^\"]*\\)\".*/\\1/p' | head -1")
[[ -n "$UNSEAL_KEY" ]] || die "could not parse unseal key from restored bootstrap.json"
docker exec "$SCRATCH_VAULT_NAME" vault operator unseal "$UNSEAL_KEY" >/dev/null \
    || die "scratch vault unseal FAILED — the restored file backend is not usable"

# Unsealing proves the seal-wrapped root key survived. It does not prove the
# secret ENGINES did, so ask for them: a token lookup exercises auth, and
# listing mounts exercises the logical backend the restored `logical/` tree
# holds. Without these, "unsealed" was the entire Vault claim.
VAULT_TOKEN=$(docker exec "$SCRATCH_VAULT_NAME" sh -c \
    "sed -n 's/.*\"root_token\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' /vault/file/bootstrap.json | head -1")
[[ -n "$VAULT_TOKEN" ]] || die "could not parse root token from restored bootstrap.json"
docker exec -e VAULT_TOKEN="$VAULT_TOKEN" "$SCRATCH_VAULT_NAME" vault token lookup >/dev/null 2>&1 \
    || die "restored vault rejected its own root token — auth backend did not survive"
MOUNTS=$(docker exec -e VAULT_TOKEN="$VAULT_TOKEN" "$SCRATCH_VAULT_NAME" \
    vault secrets list -format=json 2>/dev/null | python3 -c \
    'import json,sys; print(" ".join(sorted(json.load(sys.stdin).keys())))' 2>/dev/null || true)
[[ -n "$MOUNTS" ]] || die "restored vault exposes no secret engines — the logical backend is empty"
ok "scratch vault unsealed; token accepted; mounts: $MOUNTS"

if [[ "$KEK_PROVIDER_LIVE" == "vault" ]]; then
    TK="${VAULT_TRANSIT_KEY_NAME:-talos-kek}"
    docker exec -e VAULT_TOKEN="$VAULT_TOKEN" "$SCRATCH_VAULT_NAME" \
        vault read "transit/keys/$TK" >/dev/null 2>&1 \
        || die "restored vault has no transit key '$TK' — every DEK is unwrappable only by luck"
    ok "restored transit key '$TK' present"
    SCRATCH_VAULT_PORT="$(docker port "$SCRATCH_VAULT_NAME" 8200/tcp | head -1 | sed 's/.*://')"
    VAULT_ADDR="http://127.0.0.1:${SCRATCH_VAULT_PORT}"
else
    # Stated plainly rather than implied: with KEK_PROVIDER=env the KEK comes
    # from TALOS_MASTER_KEY and the restored Vault is NOT on the decryption
    # path. The Vault half of this drill still proves the file backend
    # restores, unseals, authenticates and mounts — it does not prove a
    # transit-wrapped DEK can be unwrapped, because this deployment does not
    # wrap them that way.
    VAULT_ADDR="http://127.0.0.1:8200"
    warn "KEK_PROVIDER=$KEK_PROVIDER_LIVE — the restored Vault is not on the KEK path here"
fi

# ── 6. Verify against the restored stack ──────────────────────────
log "[6/7] verifying the restored stack"
DATABASE_URL="postgres://${SCRATCH_PG_USER}:${SCRATCH_PG_PASSWORD}@127.0.0.1:${SCRATCH_PG_PORT}/${SCRATCH_PG_DB}"
EXPECT_MIGRATION="$(ls -1 "$REPO_ROOT"/migrations/*.sql 2>/dev/null | sed 's#.*/##' | cut -d_ -f1 | sort -n | tail -1)"

run_verifier() {
    local bin="$1"; local label="$2"
    DATABASE_URL="$DATABASE_URL" \
    TALOS_MASTER_KEY="$TALOS_MASTER_KEY" \
    KEK_PROVIDER="$KEK_PROVIDER_LIVE" \
    VAULT_ADDR="$VAULT_ADDR" \
    VAULT_TOKEN="$VAULT_TOKEN" \
    VAULT_TRANSIT_KEY_NAME="${VAULT_TRANSIT_KEY_NAME:-talos-kek}" \
    TALOS_DRILL_EXPECT_MIGRATION_VERSION="$EXPECT_MIGRATION" \
        "$bin" || die "$label against the restored stack FAILED — backups not restorable"
    ok "$label passed against the restored stack"
}

# verify_restore first: it reads what the BACKUP contained. verify_phase_b
# then writes, so running it second keeps the read checks off rows this drill
# created itself.
run_verifier "$VERIFY_RESTORE_BIN" "verify_restore"
run_verifier "$VERIFY_PHASE_B_BIN" "verify_phase_b"

# ── 7. Done ───────────────────────────────────────────────────────
log "[7/7] drill passed"
DRILL_COMPLETE=1
emit_metric success

printf '\n\033[1;32m╔══════════════════════════════════════════════════════════════╗\033[0m\n'
printf '\033[1;32m║ Drill %-38s PASSED ║\033[0m\n' "$DRILL_ID"
printf '\033[1;32m╚══════════════════════════════════════════════════════════════╝\033[0m\n'
printf '  Source:          %s\n' "$SOURCE_MODE"
[[ "$SOURCE_MODE" == "artifact" ]] && printf '  Postgres backup: %s\n' "$(basename "${PG_ARTIFACT:-?}")"
[[ "$SOURCE_MODE" == "artifact" ]] && printf '  Vault backup:    %s\n' "$(basename "${VAULT_ARTIFACT:-?}")"
printf '  Schema version:  %s\n' "$EXPECT_MIGRATION"
printf '  Metric:          %s\n' "$TEXTFILE"
printf '  Next drill:      within 7 days (alert fires at 14)\n'
printf '\n'
