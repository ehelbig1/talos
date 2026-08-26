#!/usr/bin/env bash
# Talos backup + restore drill.
#
# "A backup you haven't restored is a hypothesis." This script tests
# the hypothesis end-to-end:
#
#  0b. Obtain the KEK from ESCROW              (NEVER from the live stack)
#   1. Select the backup artifacts to restore   (local sidecar artifacts, or
#                                                --source b2: fetch + age-decrypt
#                                                the OFF-HOST copy)
#   2. Build the verifiers                      (before anything holds real data)
#   3. Spin up scratch Postgres + Vault         (throwaway net, creds, volumes)
#   4. Restore the Postgres dump into scratch   (pg_restore --exit-on-error)
#   5. Restore the Vault tarball into scratch   (untar into a scratch volume)
#   6. Restore Neo4j into scratch + probe it     (counts vs the manifest's own
#                                                neo4j_nodes/neo4j_relationships)
#   7. Verify against the restored stack         (verify_restore + verify_phase_b)
#   8. Clean up every scratch container/volume/network
#   9. Emit the Prometheus textfile metric
#
# THE KEK COMES FROM ESCROW AND ONLY FROM ESCROW. Set exactly one of
# (setting both is refused, not silently resolved by precedence):
#   TALOS_DRILL_ESCROW_KEY_CMD='op read "op://Private/Talos KEK/password"'
#   TALOS_DRILL_ESCROW_KEY_FILE=/Volumes/escrow/talos-master.key
# or run attached to a TTY and paste it at the hidden prompt. There is no
# flag that reads it back off the running controller — see step 0b for why.
# The escrow command is bounded by TALOS_DRILL_ESCROW_TIMEOUT_SECS (default
# 120) so a helper that prompts cannot hang a scheduled run forever.
#
# WHAT THE ESCROW CHECKS DO AND DO NOT ESTABLISH. Step 0b refuses the shapes
# that re-create the deleted live-stack read and the shapes that put the key
# beside the ciphertext. It cannot establish that a source is genuinely
# off-box — see step 0b's "STATED LIMITS".
#
# Exit codes:
#   0  drill passed — backups are restorable
#   1  any step failed — investigate before the next production incident
#
# Usage:
#   ./scripts/drills/backup-restore.sh                 # restore the newest ARTIFACT
#   ./scripts/drills/backup-restore.sh --source b2     # restore the OFF-HOST copy
#   ./scripts/drills/backup-restore.sh --source live   # dump live now, restore that
#   ./scripts/drills/backup-restore.sh --keep-scratch  # leave scratch up to inspect
#
# `--source b2` is the Tier-2 mode and it answers a strictly harder question
# than the default: it fetches from object storage, age-decrypts with the
# ESCROWED passphrase, and only then restores. It needs an age passphrase
# source, set exactly one of (both is refused, same rule as the KEK):
#   TALOS_OFFHOST_AGE_PASSPHRASE_CMD='op read "op://Private/Talos age backup/password"'
#   TALOS_OFFHOST_AGE_PASSPHRASE_FILE=/Volumes/escrow/talos-age.pass
# It FAILS — it does not fall back to the local copy — when the bucket is
# unreachable, when the bucket holds no archive, when the newest archive is
# older than TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS, or when the passphrase is
# wrong. A drill that silently restored the local artifact after failing to
# reach the bucket would certify an off-host copy that does not exist.
#
# EVERY RUN RECORDS WHICH COPY IT RESTORED. The three Prometheus gauges this
# script writes carry a `source` label (`artifact` | `b2` | `live`) as of
# 2026-08-26. Before that they said only "a drill passed", and since the
# LaunchAgent passed no arguments every scheduled run was `artifact` — so a
# green `talos_backup_drill_last_status` read as "the backups are verified"
# while proving strictly less: that a file on the disk we are insuring
# against round-trips. The label is what makes the metric able to say what it
# actually certified. See emit_metric for which series are per-run and which
# are retained per copy.
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
SCRATCH_NEO4J_NAME="talos-drill-neo4j-$$"
SCRATCH_NEO4J_VOLUME="talos-drill-neo4j-data-$$"
SCRATCH_NEO4J_LOGS="talos-drill-neo4j-logs-$$"
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

# THE NEO4J IMAGE MUST MATCH THE ONE THAT WROTE THE STORE, and the tag alone
# does not give you that. The neo4j artifact is a RAW STORE COPY — `databases/`,
# `transactions/`, `dbms/auth.ini` — not a `neo4j-admin database dump`, so the
# server that opens it has to understand that on-disk format. Measured on this
# host 2026-08-26:
#
#   neo4j:5.26-community@sha256:b357872d…  →  image 610dfe7b…  (what talos-neo4j RUNS)
#   neo4j:5.26-community          (bare tag) →  image 846cea23…  (a DIFFERENT build)
#
# `docker images -a` shows the older image now carries the tag `neo4j:<none>`:
# the tag has ALREADY drifted away from the build that wrote every artifact in
# ~/.talos/backups/neo4j. So the digest here is load-bearing, not decoration. It
# is the same digest docker-compose.yml pins for BOTH the `neo4j` service and
# the `neo4j-backup` sidecar — keep the three in lockstep when bumping Neo4j.
#
# It is deliberately NOT read off the live container. Step 0b's whole thesis is
# that the drill has to work when the live host is gone; a drill that asks the
# live stack which image to use cannot run in the disaster it rehearses.
#
# ON MISMATCH the failure is SILENT, which is why step 6's readiness loop is
# not a bare poll. Measured: a Neo4j 5.26 container that cannot start exits with
# code 3 in ~2 s having logged only "Neo4j Server shutdown initiated by request"
# / "Stopped.", with an EMPTY debug.log. Step 6 therefore re-checks
# `.State.Running` on every iteration and dumps both the container log and the
# /logs volume the moment it stops, so a version mismatch is diagnosed in
# seconds instead of read as a 90-second timeout.
NEO4J_IMAGE="${TALOS_DRILL_NEO4J_IMAGE:-neo4j:5.26-community@sha256:b357872da95a164c5243ca8d9060601130717ff43cee3c829402fab46209a412}"

# How far the RESTORED graph may fall short of the count its own manifest
# recorded. See step 6 for the full derivation; the short version is that the
# manifest's cypher probe runs AFTER the tar (sole call site: the manifest
# here-block in scripts/dev-backup/dev-volume-backup-loop.sh), so anything
# committed in the 26-55 s gap between them is in the probe and not in the
# archive.
NEO4J_COUNT_TOLERANCE="${TALOS_DRILL_NEO4J_COUNT_TOLERANCE:-50}"
case "$NEO4J_COUNT_TOLERANCE" in
    ''|*[!0-9]*) echo "TALOS_DRILL_NEO4J_COUNT_TOLERANCE must be a non-negative integer, got '$NEO4J_COUNT_TOLERANCE'" >&2; exit 1 ;;
esac

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
    artifact|live|b2) ;;
    *) echo "--source must be 'artifact' (default), 'b2' or 'live', got '$SOURCE_MODE'" >&2; exit 1 ;;
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
# ── The CLOSED label set for the drill's series. ──────────────────
# `source` is the ONLY label these three gauges carry, and these are the
# only values it may take — the same set the `--source` validation above
# enforces on the WRITE side, restated here because the READ side below
# parses a file that anything on the host could have written. Nine series
# is the hard ceiling (3 names x 3 sources), so this cannot become a
# cardinality bomb and /metrics stays scrapeable.
#
# WHY THE LABEL EXISTS AT ALL. Until 2026-08-26 these gauges said only
# "a drill passed". They could not say WHICH COPY was restored, and the
# scheduled run has always been `artifact` — the dump on the very disk
# the backups insure against. So a green `talos_backup_drill_last_status`
# read as "the backups are verified" while proving strictly less: that a
# local file round-trips. The off-host copy, which is the whole point of
# Tier 2, was uncertified and nothing in the metrics could tell the
# difference. The label is the difference.
DRILL_SOURCES_RE='(artifact|b2|live)'

# ── WHICH KINDS THIS RUN ACTUALLY VERIFIED. ──────────────────────
# A fourth series, on its OWN metric name, added 2026-08-26 with the neo4j leg.
#
# WHY A NEW NAME AND NOT A `kind` LABEL ON THE THREE ABOVE. That was the
# obvious move and it is wrong. The readers of those three were inventoried
# (65 lines / 11 files) before choosing, and four of them break:
#
#   * schedule.sh's awk matches `\{source="[a-z0-9]+"\} ` — a `}` and a space
#     immediately after the source value. It breaks with `kind` in ANY
#     position, and it breaks SILENTLY, printing "no successful drill recorded
#     yet" on a host that has one.
#   * emit_metric's own `prev`/`carried` greps anchor `\{source="` directly
#     after the metric name, and the `grep -vF '{source="…"}'` exclusion needs
#     `source` to be the LAST label. Same silent failure, in the
#     failure-REPORTING path — the exact trap the comment above this one
#     documents, re-armed.
#   * `talos_backup_drill_last_status == 0` would match one series PER KIND.
#     That alert is `category: data-loss`, which alertmanager-route.yaml sends
#     to PagerDuty at repeat_interval 1h — so one failure would become N pages
#     differing only by a label.
#   * the staleness rule's `max without(source)` would RETAIN `kind`, giving
#     one alert per kind and re-opening the per-abandoned-copy permanent red
#     that `without(source)` exists to close.
#
# A separate name touches none of them, and `postgres`/`vault`/`neo4j` are the
# label values talos_offhost_backup_*{kind=…} already uses (see
# talos-offhost-backup/src/key.rs::as_str), so the vocabulary is not new either.
#
# THREE STATES, ALL DISTINGUISHABLE, which is the entire point:
#   1  the kind was restored AND its content assertion passed
#   0  the kind was PRESENT but could NOT be verified (e.g. the manifest says
#      `neo4j_nodes=unknown` because the sidecar's probe could not reach the
#      graph, or there is no manifest at all)
#   (no line)  the kind was NOT PRESENT / not attempted for this source
#
# ABSENCE IS THE HONEST ENCODING OF "not present", and it is deliberate rather
# than an oversight: 0 asserts "present but unverified", which is false for a
# host that has no such artifact. Same argument, same file, as the
# no-line-for-a-never-successful-copy rule on last_success below. Nothing
# alerts on this series — a "neo4j has never been verified" rule would be
# permanently red on a host that legitimately has no graph, the shape #675 and
# #676 each rejected once already.
#
# THIS SERIES IS PER-RUN, NOT PER-COPY. It describes the most recent attempt,
# like last_run and last_status, so only the current source's kinds are written
# and nothing is carried forward. Ceiling: 3 names x 3 sources = 9 series, on
# top of the 9 above.
#
# LAST WRITE WINS, AND EVERY KIND IS RECORDED 0 BEFORE IT IS ATTEMPTED.
# The first cut appended, and only on success — so a leg that DIED left no line
# at all, which is byte-identical to "this host has no such artifact". Two
# different facts with the same encoding is the defect this series exists to
# remove, reintroduced one level in; it showed up the first time the
# deficit-assertion test was driven for real. Now each kind is stamped 0
# ("present, NOT verified") the moment the drill commits to restoring it and
# upgraded to 1 only once every assertion for it has passed, so an abort
# anywhere leaves a 0. No line means, and only means, not present / not
# attempted.
KIND_VERIFIED_LINES=""
record_kind() {
    # $1 = kind (postgres|vault|neo4j), $2 = 1|0
    local line="talos_backup_drill_kind_verified{source=\"$SOURCE_MODE\",kind=\"$1\"} $2"
    local kept=""
    if [[ -n "$KIND_VERIFIED_LINES" ]]; then
        kept=$(printf '%s\n' "$KIND_VERIFIED_LINES" | grep -vF "kind=\"$1\"}" | grep -v '^$' || true)
    fi
    if [[ -n "$kept" ]]; then
        KIND_VERIFIED_LINES="$kept
$line"
    else
        KIND_VERIFIED_LINES="$line"
    fi
}

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
    local sl="{source=\"$SOURCE_MODE\"}"

    # Resolve everything read out of the PREVIOUS file before the temp file
    # exists, and never let any of it fail the shell.
    #
    # This lookup used to live inside the here-block below, unguarded. With
    # `set -e -o pipefail`, an existing $TEXTFILE that does NOT contain a
    # `…_last_success_timestamp_seconds` line makes `grep` exit 1, the pipeline
    # exit 1, and the assignment exit 1 — which killed the shell INSIDE
    # emit_metric. Measured: the failure metric was never written, `die`'s
    # `exit 1` never ran, and the temp file was orphaned in the collector's
    # directory. A fail-open in the failure-REPORTING path is the same defect
    # class as the sentinel it sits next to, so every read is `|| true` plus a
    # default, and every value is re-validated as digits before use.
    #
    # ADDING THE LABEL RE-ARMED THAT EXACT TRAP, which is why the greps below
    # are not the ones they replaced. The old pattern was an ANCHORED,
    # LABEL-FREE prefix — `'^talos_backup_drill_last_success_timestamp_seconds '`
    # with a trailing space — and it stops matching the instant the line
    # becomes `…_seconds{source="artifact"} 123`. It would not have errored;
    # it would have quietly returned nothing, `prev` would have defaulted, and
    # every failed run after the format change would have ERASED the real
    # last-success timestamp. Silent, in the failure-reporting path, one
    # function below the comment warning about it.
    local prev="" legacy="" carried=""
    if [[ -f "$TEXTFILE" ]]; then
        # (a) this source's own last success, in the labelled form.
        prev=$(grep -E "^talos_backup_drill_last_success_timestamp_seconds\{source=\"$SOURCE_MODE\"\} " "$TEXTFILE" 2>/dev/null \
            | awk '{print $2}' | head -1 || true)
        # (b) the LEGACY unlabelled line, written by every run before this
        #     change. Read so the format transition does not throw away a
        #     real proven-restore timestamp.
        legacy=$(grep -E '^talos_backup_drill_last_success_timestamp_seconds [0-9]' "$TEXTFILE" 2>/dev/null \
            | awk '{print $2}' | head -1 || true)
        # (c) every OTHER source's last success, carried forward verbatim.
        #     The regex admits only the closed label set, so a hand-edited or
        #     corrupted file cannot inject a label value this producer would
        #     never write.
        carried=$(grep -E "^talos_backup_drill_last_success_timestamp_seconds\{source=\"$DRILL_SOURCES_RE\"\} [0-9]" "$TEXTFILE" 2>/dev/null \
            | grep -vF "{source=\"$SOURCE_MODE\"}" || true)
    fi
    [[ "$prev"   =~ ^[0-9]+$ ]] || prev=""
    [[ "$legacy" =~ ^[0-9]+$ ]] || legacy=""

    # ATTRIBUTING THE LEGACY LINE. An unlabelled timestamp records a run whose
    # source was not written down, so adopting it is a judgement, not a read —
    # and it is made once, in the one direction the evidence supports: the
    # LaunchAgent has never passed `--source`, so every unattended run this
    # host has ever made was `artifact`. `b2` and `live` only ever happen when
    # an operator types them. Adopting it as `artifact` can therefore only be
    # wrong for a host whose last MANUAL run was `live` — and it is wrong in a
    # bounded way that one subsequent run corrects. Dropping the line instead
    # would fabricate an absence and fire the staleness alert on a host that
    # genuinely had a green drill. A labelled line always wins over it.
    if [[ -n "$legacy" ]]; then
        if [[ "$SOURCE_MODE" == "artifact" ]]; then
            [[ -z "$prev" ]] && prev="$legacy"
        elif ! printf '%s\n' "$carried" | grep -qF '{source="artifact"}'; then
            local adopted="talos_backup_drill_last_success_timestamp_seconds{source=\"artifact\"} $legacy"
            if [[ -n "$carried" ]]; then
                carried="$adopted
$carried"
            else
                carried="$adopted"
            fi
        fi
    fi

    # Sweep temp files orphaned by an earlier aborted emit. node_exporter's
    # textfile collector only reads `*.prom`, so these never corrupted a
    # scrape — but nothing else ever cleans this directory and they accumulate
    # one per aborted run. Swept BEFORE mktemp so the current one is safe.
    rm -f "$TEXTFILE_DIR"/.talos_backup_drill.?????? 2>/dev/null || true

    local tmp; tmp=$(mktemp "$TEXTFILE_DIR/.talos_backup_drill.XXXXXX")
    {
        # WHICH SERIES ARE PER-RUN AND WHICH ARE PER-SOURCE, and why they
        # differ. `last_run` and `last_status` are SINGULAR by name — "the
        # most recent attempt", "the most recent drill" — so exactly one of
        # each is written, labelled with the source that run exercised.
        # Retaining a stale `last_status{source="live"} 0` from an abandoned
        # one-off would manufacture a permanently-firing alert, which is the
        # shape this alert family explicitly rejects.
        #
        # `last_success` is different: "has THIS copy ever been restored" is a
        # durable per-copy fact and it is the question Tier 2 exists to ask,
        # so every source's value is carried forward. It is also required for
        # CORRECTNESS — without it a failed `--source live` run would erase
        # the artifact copy's proven-restore timestamp, which is worse than
        # what this file did before the label existed.
        echo "# HELP talos_backup_drill_last_run_timestamp_seconds Unix timestamp of the most recent drill attempt, labelled with the copy it restored."
        echo "# TYPE talos_backup_drill_last_run_timestamp_seconds gauge"
        echo "talos_backup_drill_last_run_timestamp_seconds$sl $ts"
        echo "# HELP talos_backup_drill_last_success_timestamp_seconds Unix timestamp of the most recent SUCCESSFUL drill, per restored copy."
        echo "# TYPE talos_backup_drill_last_success_timestamp_seconds gauge"
        if [[ "$status" == "success" ]]; then
            echo "talos_backup_drill_last_success_timestamp_seconds$sl $ts"
        elif [[ -n "$prev" ]]; then
            # Preserve previous success timestamp when available so the
            # alert threshold compares against the last actually-green run.
            echo "talos_backup_drill_last_success_timestamp_seconds$sl $prev"
        fi
        # NO LINE AT ALL when this source has failed and has never succeeded.
        # The old code wrote 0 here. With a label that is no longer harmless:
        # `0 < time() - 14d` is true forever, so a first-ever failing `b2`
        # drill on a host whose `artifact` drill is green would fire an alert
        # whose summary — "No successful backup→restore drill in 14+ days" —
        # is FALSE. Absence is the honest encoding of "this copy has never
        # been proven", it is what leg F5 of verify-observability.sh reads to
        # say so, and the all-sources case is still covered by the alert's
        # own absent() arm. Same argument as the deliberate no-absent()-arm
        # carve-out on TalosBackupRestoreDrillLastRunFailed: a gauge with two
        # values and no honest third has no honest pre-seed.
        [[ -n "$carried" ]] && echo "$carried"
        echo "# HELP talos_backup_drill_last_status Status of the most recent drill (1=success, 0=failure), labelled with the copy it restored."
        echo "# TYPE talos_backup_drill_last_status gauge"
        [[ "$status" == "success" ]] && echo "talos_backup_drill_last_status$sl 1" || echo "talos_backup_drill_last_status$sl 0"
        # Per-kind coverage of THIS run. Written even on the failure path: a
        # drill that died at the neo4j leg still verified postgres and vault,
        # and saying so is more useful than saying nothing. Emitted only when
        # at least one kind was reached, so an early abort (before step 1
        # selected anything) writes no lines rather than an empty HELP block.
        if [[ -n "$KIND_VERIFIED_LINES" ]]; then
            echo "# HELP talos_backup_drill_kind_verified Whether the most recent drill restore-verified this artifact kind (1=verified, 0=present but NOT verified). No line at all means the kind was not present / not attempted for that copy."
            echo "# TYPE talos_backup_drill_kind_verified gauge"
            echo "$KIND_VERIFIED_LINES"
        fi
    } > "$tmp"
    chmod 644 "$tmp"
    mv "$tmp" "$TEXTFILE"
    ok "emitted metric → $TEXTFILE ($status, source=$SOURCE_MODE)"
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
# time: unless step 8 is reached, the trap forces a non-zero exit and a
# failure metric, whatever aborted the run.
DRILL_COMPLETE=0
CLEANED=0
cleanup_scratch() {
    local code=$?
    (( CLEANED == 1 )) && return
    CLEANED=1
    # `--keep-scratch` skips the TEARDOWN. It must NOT skip the completion
    # sentinel below: an early `return` here (the original shape) meant a
    # --keep-scratch run that aborted with a bogus exit 0 exited 0 and emitted
    # no failure metric — the precise hole the sentinel exists to close, left
    # open on one opt-in path. Structured as if/else so the sentinel is on the
    # single path out of this function.
    if (( KEEP_SCRATCH == 1 )) && (( code == 0 )); then
        warn "--keep-scratch: leaving scratch stack UP. It holds REAL restored data."
        warn "  containers: $SCRATCH_PG_NAME $SCRATCH_VAULT_NAME $SCRATCH_NEO4J_NAME"
        warn "  volumes:    $SCRATCH_PG_VOLUME $SCRATCH_VAULT_VOLUME $SCRATCH_VAULT_LOGS $SCRATCH_NEO4J_VOLUME $SCRATCH_NEO4J_LOGS"
        warn "  remove with: docker rm -fv $SCRATCH_PG_NAME $SCRATCH_VAULT_NAME $SCRATCH_NEO4J_NAME &&"
        warn "               docker volume rm $SCRATCH_PG_VOLUME $SCRATCH_VAULT_VOLUME $SCRATCH_VAULT_LOGS $SCRATCH_NEO4J_VOLUME $SCRATCH_NEO4J_LOGS &&"
        warn "               docker network rm $SCRATCH_NETWORK && rm -rf ${WORK_DIR:-<workdir>}"
    else
        # `-v` is load-bearing: without it the container's ANONYMOUS volumes
        # survive, and for the Postgres image that anonymous volume IS the
        # restored database (421 MB of real user data on the 2026-08-03 run).
        docker rm -fv "$SCRATCH_PG_NAME" "$SCRATCH_VAULT_NAME" "$SCRATCH_NEO4J_NAME" >/dev/null 2>&1 || true
        docker volume rm "$SCRATCH_PG_VOLUME" "$SCRATCH_VAULT_VOLUME" "$SCRATCH_VAULT_LOGS" \
            "$SCRATCH_NEO4J_VOLUME" "$SCRATCH_NEO4J_LOGS" >/dev/null 2>&1 || true
        docker network rm "$SCRATCH_NETWORK" >/dev/null 2>&1 || true
        [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]] && rm -rf "$WORK_DIR"

        # Assert, don't assume. A cleanup that silently failed is how note 2
        # above survived from May to August.
        local leaked=""
        for c in "$SCRATCH_PG_NAME" "$SCRATCH_VAULT_NAME" "$SCRATCH_NEO4J_NAME"; do
            docker inspect "$c" >/dev/null 2>&1 && leaked="$leaked container:$c"
        done
        for v in "$SCRATCH_PG_VOLUME" "$SCRATCH_VAULT_VOLUME" "$SCRATCH_VAULT_LOGS" \
                 "$SCRATCH_NEO4J_VOLUME" "$SCRATCH_NEO4J_LOGS"; do
            docker volume inspect "$v" >/dev/null 2>&1 && leaked="$leaked volume:$v"
        done
        [[ -n "${WORK_DIR:-}" && -d "${WORK_DIR:-}" ]] && leaked="$leaked workdir:$WORK_DIR"
        if [[ -n "$leaked" ]]; then
            printf '\033[1;31m✗ CLEANUP INCOMPLETE — remove by hand:%s\033[0m\n' "$leaked" >&2
        fi
    fi

    # Did not reach step 8 ⇒ this run is a FAILURE, whatever the shell says
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
for n in "$SCRATCH_PG_NAME" "$SCRATCH_VAULT_NAME" "$SCRATCH_NEO4J_NAME"; do
    docker inspect "$n" >/dev/null 2>&1 && die "scratch name '$n' already exists — refusing to clobber it"
done
for v in "$SCRATCH_PG_VOLUME" "$SCRATCH_VAULT_VOLUME" "$SCRATCH_VAULT_LOGS" \
         "$SCRATCH_NEO4J_VOLUME" "$SCRATCH_NEO4J_LOGS"; do
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

# ── 0b. Obtain the KEK from ESCROW — never from the live host ─────
#
# THIS IS THE POINT OF THE DRILL, and until 2026-08-13 it was inverted.
# The line that stood here was:
#
#     TALOS_MASTER_KEY=$(docker exec "$LIVE_CONTROLLER" printenv TALOS_MASTER_KEY)
#     [[ -n "$TALOS_MASTER_KEY" ]] || die "could not read … from $LIVE_CONTROLLER"
#
# so the drill could only pass while the host it insures was still alive. It
# proved `artifacts + TODAY'S LIVE KEK ⇒ readable`, which is not the claim a
# restore rehearsal is asked for and is trivially true on a healthy host. In
# the disaster it rehearses — the host is gone — the drill could not even
# START, so it had never once tested the property it exists to test. A gate
# that cannot fail for the reason it exists is not a gate.
#
# THE LIVE-CONTAINER READ IS NOT KEPT AS A FALLBACK. Not as a `--live` flag,
# not as a "try escrow, else the container" convenience: a path that can
# quietly succeed the old way leaves the defect in place and makes it look
# fixed. Absent escrow is FATAL, with a message naming what to create.
#
# Three escrow sources, in precedence order. None of them defaults to
# anything inside this repo or inside $BACKUP_DIR — a key stored beside the
# ciphertext it unlocks is not encryption, it is a filename change.
#
#   1. TALOS_DRILL_ESCROW_KEY_CMD  — a command whose STDOUT is the key.
#      The preferred shape, because the key never lands on disk:
#        TALOS_DRILL_ESCROW_KEY_CMD='op read "op://Private/Talos KEK/password"'
#      Its stderr is left attached so a password manager can prompt, and it is
#      bounded by TALOS_DRILL_ESCROW_TIMEOUT_SECS.
#   2. TALOS_DRILL_ESCROW_KEY_FILE — a file containing the key (first line).
#      Rejected if it resolves inside a checkout or the backup directory.
#   3. An interactive prompt, only when stdin is a TTY. `read -rs`: no echo.
#
# Setting BOTH 1 and 2 is refused. The header says "set exactly one of", and a
# silent precedence rule means the operator who set the guarded `_FILE` and the
# unguarded `_CMD` gets the unguarded one without being told.
#
# The value is never printed, never written to a file, never passed on a
# command line (which would put it in `ps`), and never reaches the scratch
# database. It lives in one shell variable — deliberately NOT exported, so it
# reaches only the verifier invocation that names it explicitly (step 6).
#
# A pre-existing `TALOS_MASTER_KEY` in the caller's environment is UNSET here
# and never used. `source .env && make drill` would otherwise sail through on
# the live key while looking like an escrow run, which is the same "quietly
# succeeds the old way" hole as a fallback, just spelled differently.
#
# `TALOS_MASTER_KEY=""` was the first shape of that clear and it is NOT
# equivalent: assignment does not remove the export attribute, so
# `export FOO=live; FOO=""; FOO=escrow` leaves FOO **exported** with the new
# value (measured: `env | grep -c '^FOO='` is 1, and 0 only after `unset`).
# On exactly the `source .env && make drill` path the comment above
# anticipates, that put the ESCROWED key into the environment of every child —
# including the multi-minute `cargo build` in step 2. `TALOS_MASTER_KEY_FILE`
# is unset alongside it: it is inert today only because `read_env_or_file`
# happens to prefer a non-empty env var, i.e. by another crate's precedence
# rather than by anything here.
unset TALOS_MASTER_KEY TALOS_MASTER_KEY_FILE
KEK_SOURCE=""
TALOS_MASTER_KEY=""
ESCROW_ATTEMPTED=""

# Roots a KEK must not live under, one per line. Two of them:
#
#   * the checkout this script is running from, and
#   * the MAIN checkout when this is a git WORKTREE. `${BASH_SOURCE[0]}` and
#     `../..` resolve to the WORKTREE root, whose subtree does not contain the
#     main clone — so running the worktree copy ACCEPTED a key file sitting in
#     the main checkout (a parent directory of it, in this repo's layout).
#     `git rev-parse --git-common-dir` names the shared `.git`, whose parent is
#     the main working tree.
escrow_forbidden_roots() {
    local script_dir root common
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
    root="$(cd "$script_dir/../.." && pwd -P)"
    printf '%s\n' "$root"
    common="$(cd "$script_dir" && git rev-parse --git-common-dir 2>/dev/null || true)"
    if [[ -n "$common" ]]; then
        # `--git-common-dir` may answer relatively; resolve from the script dir.
        (cd "$script_dir" && cd "$common/.." && pwd -P) 2>/dev/null || true
    fi
}

# Portable realpath. `cd "$(dirname f)" && pwd -P` — the obvious one, and what
# this used at first — resolves a symlinked DIRECTORY and not a symlinked FILE.
# Caught by testing the bypass rather than by reading the code: a symlink in
# /tmp pointing at a key file inside the repo was ACCEPTED, and the README had
# already been written claiming "symlinks are resolved before the check". Same
# defect one level up as the drill itself. python3 is already a hard dependency
# of this script (steps 2 and 5); macOS ships no coreutils `realpath`.
escrow_realpath() {
    python3 -c 'import os,sys; print(os.path.realpath(sys.argv[1]))' "$1"
}

# Refuse a path that resolves under a checkout or under $BACKUP_DIR.
# `$2` names what is being checked so the message fits both callers.
assert_escrow_path_contained() {
    local real="$1" what="$2" r backup_real
    while IFS= read -r r; do
        [[ -n "$r" ]] || continue
        case "$real" in
            "$r"|"$r"/*)
                die "$what resolves to '$real', INSIDE a checkout ($r).
   The KEK must not live where the code lives — a checkout, a container image
   layer or a stray \`git add -f\` then carries it. Move it off-box." ;;
        esac
    done < <(escrow_forbidden_roots)
    if [[ -d "$BACKUP_DIR" ]]; then
        backup_real="$(escrow_realpath "$BACKUP_DIR")"
        case "$real" in
            "$backup_real"|"$backup_real"/*)
                die "$what resolves to '$real', INSIDE the backup directory ($backup_real).
   Whoever steals the artifacts then also has the key that unlocks them, which
   makes the encryption decorative. Keep the KEK on a different medium." ;;
        esac
    fi
}

# The `_CMD` shapes that RE-CREATE the deleted live-stack read.
#
# `TALOS_DRILL_ESCROW_KEY_CMD='docker exec talos-controller printenv
# TALOS_MASTER_KEY'` passed every other check in this file and printed
# "KEK obtained from ESCROW … the live stack was never asked" while the live
# stack was the only thing that was asked. The refusal is cheap and closes that
# specific hole; the honest wording in the banner is what stops the transcript
# lying to a future operator about the rest.
assert_escrow_cmd_is_not_the_live_stack() {
    local c="$1"
    if printf '%s' "$c" | grep -Eq 'docker([[:space:]]+[^|;&]*)?[[:space:]]+(exec|inspect)([[:space:]]|$)'; then
        die "TALOS_DRILL_ESCROW_KEY_CMD invokes 'docker exec'/'docker inspect'.
   That is the live-stack read this drill deleted, spelled as an escrow source.
   A drill sourcing the KEK from the running host proves 'artifacts + TODAY'S
   LIVE KEK ⇒ readable', which is trivially true on a healthy host and
   untestable in the disaster it rehearses. Point it at real escrow."
    fi
    if printf '%s' "$c" | grep -Eq 'printenv[[:space:]]+TALOS_MASTER_KEY'; then
        die "TALOS_DRILL_ESCROW_KEY_CMD reads TALOS_MASTER_KEY out of an environment.
   Whatever process that is, it is not escrow: escrow is a copy that survives
   losing this host. See scripts/drills/README.md item 8."
    fi
}

# Cheap containment for `_CMD`, matching what `_FILE` already gets.
# `TALOS_DRILL_ESCROW_KEY_CMD="cat <repo>/.key"` sailed through every check
# while `TALOS_DRILL_ESCROW_KEY_FILE=<repo>/.key` was refused — the guarded
# branch was the one nobody is told to use.
#
# STATED LIMIT: this is a token scan, not a shell parser. It resolves each
# whitespace-separated token that looks like a path AND exists, then applies the
# same containment. A path assembled from a variable, built by the helper
# itself, or reached through a HARD LINK (which `realpath` cannot see through —
# a hard link inside the repo to a file outside it has no symlink to resolve and
# is a genuinely different path) is invisible to it.
assert_escrow_cmd_paths_contained() {
    local c="$1" tok real
    # Word-splitting is the point here.
    # shellcheck disable=SC2086
    for tok in $c; do
        tok="${tok%\"}"; tok="${tok#\"}"
        tok="${tok%\'}"; tok="${tok#\'}"
        [[ "$tok" == */* ]] || continue
        [[ -e "$tok" ]] || continue
        real="$(escrow_realpath "$tok" 2>/dev/null || true)"
        [[ -n "$real" ]] || continue
        assert_escrow_path_contained "$real" "escrow command argument '$tok'"
    done
}

# Run the escrow command under a WATCHDOG and print its stdout.
#
# Nothing bounded this command before, while `schedule.sh` claimed the drill
# "gives up" — it did not, and `grep -n timeout scripts/drills/*.sh` found
# nothing. Under launchd an `op read` that raises a Touch ID prompt waits
# forever, launchd will not start the next weekly run while this one is alive,
# and the drill silently stops running with only the 14-day staleness alert as
# signal.
#
# A watchdog rather than `timeout(1)` because macOS ships no coreutils.
#
# STDERR IS LEFT ATTACHED. The `2>/dev/null` this used to carry contradicted
# the line directly above it and swallowed BOTH a password manager's prompt and
# a failing helper's diagnostic — worst under `make drill-schedule`, where the
# log is the only channel.
#
# STDIN is restored from the terminal when there is one: bash points an
# asynchronous command's stdin at /dev/null when job control is off, which is
# correct for launchd and wrong for an interactive run.
#
# The key is returned through a PIPE, never a temp file — `_CMD` is the
# preferred source precisely because the key does not land on disk, and a
# spool-to-file timeout implementation would have quietly given that up. Only
# the watchdog's verdict touches the filesystem.
#
# THE WATCHDOG MUST KILL THE WHOLE TREE, and the difference is a HANG rather
# than a slow path. `eval "$CMD" &` forks a SUBSHELL, which then forks the real
# command as a GRANDCHILD; that grandchild inherits the capture pipe's write
# end, so TERMing only the direct child leaves `head` waiting for an EOF that
# never comes and the drill blocks forever on the very timeout meant to rescue
# it. Measured while building this: `sleep 300` survived as a PID-1 orphan and
# the run wedged past 45 s with a 3 s limit. The tree is enumerated BEFORE the
# first signal, because a killed intermediate erases the parent links the
# second pass would need.
escrow_descendants() {
    local p="$1" c
    printf '%s\n' "$p"
    for c in $(pgrep -P "$p" 2>/dev/null || true); do
        escrow_descendants "$c"
    done
}
run_escrow_cmd_bounded() {
    local flag="$1" secs="$2" cmd_pid wd_pid
    if [[ -t 0 ]]; then
        eval "$TALOS_DRILL_ESCROW_KEY_CMD" < /dev/tty &
    else
        eval "$TALOS_DRILL_ESCROW_KEY_CMD" < /dev/null &
    fi
    cmd_pid=$!
    (
        sleep "$secs"
        if kill -0 "$cmd_pid" 2>/dev/null; then
            printf 'timeout' > "$flag"
            # `pgrep -P` ships on macOS and on Linux (procps). Where it is
            # missing this degrades to the direct kill — i.e. to the
            # pre-existing "no effective timeout", not to a wrong answer.
            tree="$(escrow_descendants "$cmd_pid")"
            for p in $tree; do kill -TERM "$p" 2>/dev/null || true; done
            sleep 2
            for p in $tree; do kill -KILL "$p" 2>/dev/null || true; done
        fi
    ) >/dev/null 2>&1 &
    wd_pid=$!
    wait "$cmd_pid" 2>/dev/null || true
    kill -TERM "$wd_pid" 2>/dev/null || true
    wait "$wd_pid" 2>/dev/null || true
}

if [[ -n "${TALOS_DRILL_ESCROW_KEY_CMD:-}" && -n "${TALOS_DRILL_ESCROW_KEY_FILE:-}" ]]; then
    die "both TALOS_DRILL_ESCROW_KEY_CMD and TALOS_DRILL_ESCROW_KEY_FILE are set.
   This script says 'set exactly one of'. Resolving it by precedence would
   silently ignore one of them — and the one that loses is the FILE, the branch
   that carries the containment checks. Unset whichever you did not mean."
fi

ESCROW_TIMEOUT_SECS="${TALOS_DRILL_ESCROW_TIMEOUT_SECS:-120}"
case "$ESCROW_TIMEOUT_SECS" in
    ''|*[!0-9]*|0) die "TALOS_DRILL_ESCROW_TIMEOUT_SECS must be a positive integer, got '$ESCROW_TIMEOUT_SECS'" ;;
esac

if [[ -n "${TALOS_DRILL_ESCROW_KEY_CMD:-}" ]]; then
    assert_escrow_cmd_is_not_the_live_stack "$TALOS_DRILL_ESCROW_KEY_CMD"
    assert_escrow_cmd_paths_contained "$TALOS_DRILL_ESCROW_KEY_CMD"
    ESCROW_TIMEOUT_FLAG="$(mktemp "${TMPDIR:-/tmp}/talos-drill-escrow.XXXXXX")"
    # `|| true` so a failing helper produces the empty-key die below (with
    # the actionable message) rather than a bare `set -e` abort.
    TALOS_MASTER_KEY="$(run_escrow_cmd_bounded "$ESCROW_TIMEOUT_FLAG" "$ESCROW_TIMEOUT_SECS" | head -1 || true)"
    ESCROW_TIMED_OUT="$(cat "$ESCROW_TIMEOUT_FLAG" 2>/dev/null || true)"
    rm -f "$ESCROW_TIMEOUT_FLAG"
    KEK_SOURCE="TALOS_DRILL_ESCROW_KEY_CMD"
    if [[ "$ESCROW_TIMED_OUT" == "timeout" ]]; then
        ESCROW_ATTEMPTED="TALOS_DRILL_ESCROW_KEY_CMD did not finish within
   ${ESCROW_TIMEOUT_SECS}s and was killed. A helper that PROMPTS (Touch ID, a
   passphrase) cannot work unattended — under launchd there is no one to answer
   it, and an unbounded wait would stop the weekly drill running at all. Use a
   service-account token, or raise TALOS_DRILL_ESCROW_TIMEOUT_SECS if the
   helper is merely slow."
    else
        ESCROW_ATTEMPTED="TALOS_DRILL_ESCROW_KEY_CMD ran but produced NO OUTPUT (exit status
   is not consulted — only what it printed; its stderr is above). Check it works
   in this shell, and that it writes the key to STDOUT rather than prompting on it."
    fi
elif [[ -n "${TALOS_DRILL_ESCROW_KEY_FILE:-}" ]]; then
    ESCROW_ATTEMPTED="TALOS_DRILL_ESCROW_KEY_FILE was set but its first line is EMPTY."
    ESCROW_FILE="${TALOS_DRILL_ESCROW_KEY_FILE}"
    [[ -r "$ESCROW_FILE" ]] || die "TALOS_DRILL_ESCROW_KEY_FILE='$ESCROW_FILE' is not readable"
    # Resolve symlinks AND relatives before the containment checks, or
    # `../../talos/.env` walks straight past them.
    ESCROW_REAL="$(escrow_realpath "$ESCROW_FILE")" \
        || die "could not resolve TALOS_DRILL_ESCROW_KEY_FILE='$ESCROW_FILE'"
    assert_escrow_path_contained "$ESCROW_REAL" "escrow key file"
    TALOS_MASTER_KEY="$(head -1 "$ESCROW_FILE" || true)"
    KEK_SOURCE="TALOS_DRILL_ESCROW_KEY_FILE ($ESCROW_REAL)"
elif [[ -t 0 ]]; then
    # -s: no echo. The prompt goes to stderr so a redirected stdout keeps
    # only drill output.
    printf 'Escrowed TALOS_MASTER_KEY (input hidden): ' >&2
    read -rs TALOS_MASTER_KEY || true
    printf '\n' >&2
    KEK_SOURCE="interactive prompt"
    ESCROW_ATTEMPTED="Nothing was entered at the prompt."
fi

# Strip a trailing CR so a key escrowed through a Windows-y clipboard or a
# CRLF file does not fail as "wrong key" — the single most confusing possible
# outcome of a correct escrow.
TALOS_MASTER_KEY="${TALOS_MASTER_KEY%$'\r'}"

if [[ -z "$TALOS_MASTER_KEY" ]]; then
    [[ -n "$ESCROW_ATTEMPTED" ]] && warn "$ESCROW_ATTEMPTED"
    die "no escrowed KEK available — REFUSING to read it from the live stack.

   This drill answers ONE question: 'if the host is gone, can the backups be
   read?' Sourcing the key from the running controller answers a different,
   much easier question, so it is not offered here at any flag.

   Supply the escrowed TALOS_MASTER_KEY by ONE of:

     1P / secret manager (preferred — the key never touches disk):
        TALOS_DRILL_ESCROW_KEY_CMD='op read \"op://Private/Talos KEK/password\"' \\
          $0 ${*:-}

     A file on removable or otherwise off-box media:
        TALOS_DRILL_ESCROW_KEY_FILE=/Volumes/escrow/talos-master.key $0 ${*:-}
        (refused if that path is inside this repo or inside $BACKUP_DIR)

     Interactively: run this script attached to a terminal and paste the key
     at the hidden prompt.

   If you cannot produce the key from an off-box source, THAT IS THE DRILL
   RESULT: every byte in $BACKUP_DIR is currently unreadable after a host
   loss. Escrow the KEK first — see scripts/drills/README.md item 8."
fi

# Which provider wrapped the DEKs. This ALSO used to come from the live
# container; same objection, same fix. `env` is the default because it is
# what docker-compose.yml defaults KEK_PROVIDER to, so the common case needs
# no flag — and because being wrong here fails loudly at the first decrypt
# rather than passing.
KEK_PROVIDER_MODE="${TALOS_DRILL_KEK_PROVIDER:-env}"
case "$KEK_PROVIDER_MODE" in
    env|vault) ;;
    *) die "TALOS_DRILL_KEK_PROVIDER must be 'env' or 'vault', got '$KEK_PROVIDER_MODE'" ;;
esac
# Length only. The key itself must never reach a terminal, a log or an issue.
ok "KEK read from $KEK_SOURCE (${#TALOS_MASTER_KEY} chars; provider '$KEK_PROVIDER_MODE')"

# STATED LIMITS OF THE ESCROW CHECKS — here rather than only in the README,
# because the reader who needs them is the one reading a green transcript.
#
# What IS enforced:
#   * the live-container read is deleted, not demoted — no flag restores it;
#   * a `_CMD` naming `docker exec`/`docker inspect` or `printenv
#     TALOS_MASTER_KEY` is refused, so the deleted read cannot be spelled as an
#     escrow source;
#   * a `_FILE`, and any existing path-shaped argument of a `_CMD`, that
#     resolves under a checkout (this one OR the main clone when this is a
#     worktree) or under $BACKUP_DIR is refused, symlinks resolved first;
#   * setting both `_CMD` and `_FILE` is refused rather than silently resolved.
#
# What is NOT, and cannot be, established here:
#   * that the source is genuinely OFF-BOX. `/Volumes/escrow` may be a RAM
#     disk; a 1Password vault may sync to this same laptop; a HARD LINK inside
#     a checkout to a file outside it is a different path with no symlink to
#     resolve, so `realpath` cannot see through it;
#   * that the `_CMD` does not reach the live stack by some spelling this file
#     does not enumerate (a wrapper script, a variable, an API call). The
#     refusals above are a specific hole closed, not a proof of provenance.
# The banner at the end says exactly this, in those words, rather than
# "the live stack was never asked".

# WORK_DIR holds a full database dump and the Vault file backend in the
# clear. mktemp gives an unpredictable name with 0700 — a fixed
# /tmp/drill-<timestamp>, which is what this used, is guessable and
# pre-creatable by any local user.
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/talos-drill-XXXXXXXX")"
chmod 700 "$WORK_DIR"

# Hoisted out of step 2: the `--source b2` branch below needs the repo root
# to build and locate the off-host helper, and step 1 runs first.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# ONE KNOB, TWO SOURCES, ONE VALIDATION — hoisted here on purpose.
#
# `--source artifact` compares it against a file mtime and `--source b2`
# hands it to the off-host helper as TALOS_OFFHOST_MAX_AGE_HOURS, so "stale"
# cannot mean two different things depending on which source you asked for.
# The validation was previously inside the `artifact` branch only, which left
# the b2 path coercing a malformed value to 168 through the helper's
# `.parse().ok().unwrap_or(168)` — a typo'd knob silently becoming the
# default is how a gate stops being the gate you set.
MAX_ARTIFACT_AGE_HOURS="${TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS:-168}"
case "$MAX_ARTIFACT_AGE_HOURS" in
    ''|*[!0-9]*) die "TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS must be a non-negative integer, got '$MAX_ARTIFACT_AGE_HOURS'" ;;
esac

# NEO4J LEG STATE, declared here so `set -u` is safe on every branch and so the
# four states are enumerable in one place. Exactly one of:
#   verified      restored AND the count assertion passed
#   unverifiable  restored (or restorable) but there is nothing to assert against
#   absent        no artifact on this host, and the operator waived it
#   not-attempted this --source cannot reach the neo4j copy (b2 / live) — see D4
# `not-attempted` and `absent` both emit NO kind_verified series; they are kept
# apart because the banner has to say WHICH, and they have different fixes.
NEO4J_STATE="not-attempted"
NEO4J_ARTIFACT=""
NEO4J_ARTIFACT_AGE="?"
NEO4J_MANIFEST_NODES=""
NEO4J_MANIFEST_RELS=""
NEO4J_EXPECTED_PATHS="./databases ./transactions"
NEO4J_RESTORED_NODES=""
NEO4J_RESTORED_RELS=""
NEO4J_DETAIL=""

# ── 1. Select the artifacts to restore ────────────────────────────
if [[ "$SOURCE_MODE" == "artifact" ]]; then
    log "[1/8] selecting backup artifacts from $BACKUP_DIR"
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
    VAULT_ARTIFACT_MTIME="$(stat -f %m "$VAULT_ARTIFACT" 2>/dev/null || stat -c %Y "$VAULT_ARTIFACT" 2>/dev/null || echo '')"
    VAULT_ARTIFACT_AGE="$([[ -n "$VAULT_ARTIFACT_MTIME" ]] && date -u -r "$VAULT_ARTIFACT_MTIME" +%FT%TZ 2>/dev/null || echo '?')"
    ok "postgres artifact: $(basename "$PG_ARTIFACT") ($(wc -c < "$WORK_DIR/pg.dump") bytes, taken $PG_ARTIFACT_AGE)"
    ok "vault artifact:    $(basename "$VAULT_ARTIFACT") ($(wc -c < "$WORK_DIR/vault.tgz") bytes, taken $VAULT_ARTIFACT_AGE)"

    # ARTIFACT AGE IS ASSERTED, NOT MERELY PRINTED.
    #
    # This used to compute the mtime, print it, and stop. So if the
    # `postgres-backup` sidecar died, the drill kept restoring the last good
    # artifact and kept going GREEN for as long as that file survived
    # retention — and `TalosBackupRestoreDrillFailed` could not help, because
    # it measures DRILL recency, not ARTIFACT recency. That is the same shape
    # as the defect this drill exists to catch, one level up: a value computed,
    # displayed, and never compared to anything.
    #
    # The default is 168 h (7 days) against a 24 h sidecar interval and a 14 d
    # retention. Deliberately loose: this is a laptop dev stack whose sidecars
    # only tick while the machine is awake, and the artifact history shows a
    # real two-day gap (2026-08-08/09) from a closed laptop. A 48 h threshold
    # would have false-red on that — an alert that fires during healthy
    # operation is the failure mode this whole area exists to remove. 7 days
    # still fires well before the newest artifact ages out of retention.
    #
    # BOTH artifacts are checked. They are selected INDEPENDENTLY (newest dump,
    # newest vault tarball), so nothing here makes them a matched pair: a fresh
    # dump can be restored beside a Vault backend from days earlier if only one
    # sidecar died. The age gate bounds how far apart they can drift; it does
    # not make them consistent, and a DEK created after the older of the two
    # was taken would be missing. Pairing them properly needs the sidecars to
    # write a joint manifest and is not attempted here.
    #
    # MAX_ARTIFACT_AGE_HOURS is resolved and validated above step 1, because
    # the b2 branch uses the same knob.
    assert_artifact_fresh() {
        local mtime="$1" label="$2" path="$3" age_h now
        if [[ -z "$mtime" ]]; then
            warn "could not read the mtime of $label ($path) — age NOT asserted on this run"
            return 0
        fi
        now="$(date +%s)"
        age_h=$(( (now - mtime) / 3600 ))
        if (( MAX_ARTIFACT_AGE_HOURS == 0 )); then
            warn "$label is ${age_h}h old — age gate DISABLED (TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS=0)"
            return 0
        fi
        if (( age_h > MAX_ARTIFACT_AGE_HOURS )); then
            die "$label is ${age_h}h old (limit ${MAX_ARTIFACT_AGE_HOURS}h): $path
   The newest artifact on disk is stale, which means the sidecar that writes it
   has stopped. Restoring it would go green and certify a backup pipeline that
   is no longer running — the drill measures its OWN recency, nothing measures
   the artifacts'. Check 'docker logs talos-postgres-backup' /
   'docker logs talos-vault-backup'. Raise TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS
   (or set it to 0) only to deliberately drill an ARCHIVED artifact."
        fi
        ok "$label age ${age_h}h (limit ${MAX_ARTIFACT_AGE_HOURS}h)"
    }
    assert_artifact_fresh "$PG_ARTIFACT_MTIME"    "postgres artifact" "$PG_ARTIFACT"
    assert_artifact_fresh "$VAULT_ARTIFACT_MTIME" "vault artifact"    "$VAULT_ARTIFACT"

    # ── The THIRD artifact kind. ──────────────────────────────────
    #
    # ABSENCE IS FATAL BY DEFAULT, and that is the whole design of this leg.
    # A host with no neo4j backups is legitimate — but a silent skip would
    # rebuild, inside the safeguard, the exact hole this leg exists to close:
    # a green run that certified two kinds and reported "PASSED". Making it
    # fatal means "not present" can only be reached by an operator who typed
    # the waiver, never by a sidecar that quietly died. The waiver has two
    # precedents in this same file (TALOS_DRILL_ALLOW_PRODUCTION,
    # TALOS_DRILL_ALLOW_NO_METRIC), so the shape is not new.
    NEO4J_ARTIFACT=$(ls -1t "$BACKUP_DIR"/neo4j/neo4j-*.tar.gz 2>/dev/null | head -1 || true)
    if [[ -z "$NEO4J_ARTIFACT" ]]; then
        if [[ "${TALOS_DRILL_ALLOW_NO_NEO4J:-0}" == "1" ]]; then
            NEO4J_STATE="absent"
            warn "no neo4j-*.tar.gz in $BACKUP_DIR/neo4j — neo4j NOT verified on this run (waived)"
        else
            die "no neo4j-*.tar.gz in $BACKUP_DIR/neo4j — nothing to restore.
   The neo4j-backup sidecar writes these daily (docker-compose.yml § neo4j-backup);
   check 'docker logs talos-neo4j-backup'. If this host genuinely runs no graph,
   set TALOS_DRILL_ALLOW_NO_NEO4J=1 — the run then reports neo4j as NOT VERIFIED
   in the banner and emits NO talos_backup_drill_kind_verified{kind=\"neo4j\"}
   series, rather than passing silently for two kinds out of three."
        fi
    else
        # Integrity FIRST, exactly as the vault leg does. A corrupt archive must
        # fail here, on a cheap sha256 of a ~1.2 MB file, and not 90 seconds
        # later inside a container start that cannot say why it died.
        if [[ -f "$NEO4J_ARTIFACT.manifest" ]]; then
            want=$(grep -E '^sha256=' "$NEO4J_ARTIFACT.manifest" | cut -d= -f2)
            got=$(shasum -a 256 "$NEO4J_ARTIFACT" 2>/dev/null | awk '{print $1}')
            [[ -z "$got" ]] && got=$(sha256sum "$NEO4J_ARTIFACT" | awk '{print $1}')
            [[ -n "$want" && "$want" == "$got" ]] || die "neo4j artifact sha256 mismatch — $NEO4J_ARTIFACT is corrupt
   manifest declares: ${want:-<none>}
   file hashes to:    $got"
            ok "neo4j artifact sha256 matches its manifest"

            # The counts the sidecar recorded at dump time. Anchor on
            # `^neo4j_nodes=`: content_probe calls log() INSIDE the manifest
            # here-block, so every manifest ALSO contains a prose line
            # ("… live graph has 1283 nodes / 1939 relationships") that a
            # looser scan would happily match.
            NEO4J_MANIFEST_NODES=$(grep -E '^neo4j_nodes=' "$NEO4J_ARTIFACT.manifest" | head -1 | cut -d= -f2)
            NEO4J_MANIFEST_RELS=$(grep -E '^neo4j_relationships=' "$NEO4J_ARTIFACT.manifest" | head -1 | cut -d= -f2)
            # `unknown` is a REAL value the sidecar writes when its cypher probe
            # could not reach the graph (the probe is non-fatal there). Blanking
            # it here is what stops it coercing to a pass — see step 6.
            [[ "$NEO4J_MANIFEST_NODES" =~ ^[0-9]+$ ]] || NEO4J_MANIFEST_NODES=""
            [[ "$NEO4J_MANIFEST_RELS"  =~ ^[0-9]+$ ]] || NEO4J_MANIFEST_RELS=""
            # Which top-level paths the sidecar asserted INTO the archive. Read
            # from the manifest rather than hardcoded so it tracks the sidecar's
            # EXPECTED_PATHS; the fallback is that env var's compose default.
            NEO4J_EXPECTED_PATHS=$(grep -E '^expected_paths=' "$NEO4J_ARTIFACT.manifest" | head -1 | cut -d= -f2-)
            [[ -n "$NEO4J_EXPECTED_PATHS" ]] || NEO4J_EXPECTED_PATHS="./databases ./transactions"
        else
            # No manifest ⇒ no sha256 to check AND no counts to assert against.
            # That is precisely "present but unverifiable", and step 6 records it
            # as such rather than restoring it and calling that a pass.
            warn "no manifest beside $NEO4J_ARTIFACT — integrity unverified AND no counts to assert"
        fi
        NEO4J_ARTIFACT_MTIME="$(stat -f %m "$NEO4J_ARTIFACT" 2>/dev/null || stat -c %Y "$NEO4J_ARTIFACT" 2>/dev/null || echo '')"
        NEO4J_ARTIFACT_AGE="$([[ -n "$NEO4J_ARTIFACT_MTIME" ]] && date -u -r "$NEO4J_ARTIFACT_MTIME" +%FT%TZ 2>/dev/null || echo '?')"
        ok "neo4j artifact:    $(basename "$NEO4J_ARTIFACT") ($(wc -c < "$NEO4J_ARTIFACT" | tr -d ' ') bytes, taken $NEO4J_ARTIFACT_AGE)"
        # Same gate, same knob, same reason as the other two: an artifact that
        # stopped being written must not keep going green off the last good file.
        assert_artifact_fresh "$NEO4J_ARTIFACT_MTIME" "neo4j artifact" "$NEO4J_ARTIFACT"
    fi
elif [[ "$SOURCE_MODE" == "b2" ]]; then
    # ── TIER 2: restore the OFF-HOST copy ─────────────────────────
    #
    # WHY THIS MODE EXISTS. `--source artifact` restores a file from the very
    # disk whose loss the backups insure against, so a green run says nothing
    # about surviving that loss. Until this mode existed, the off-host egress
    # could have been shipping corrupt archives, or nothing at all, and every
    # drill would still have passed — the same "re-tests the copy already
    # known to work" defect the 2026-08-03 rewrite found one level in.
    #
    # THERE IS NO FALLBACK TO THE LOCAL COPY, deliberately, and for exactly
    # the reason step 0b keeps no fallback to the live KEK: a path that can
    # quietly succeed the easy way leaves the defect in place while looking
    # fixed. Unreachable bucket, empty bucket, stale archive and wrong
    # passphrase are all FATAL here.
    log "[1/8] fetching backup artifacts from OFF-HOST object storage (--source b2)"

    # The age passphrase is a SECOND fatal secret — losing it makes every
    # uploaded archive unreadable, exactly as losing the KEK does. Same
    # containment rules, reusing the same helpers rather than similar ones.
    if [[ -n "${TALOS_OFFHOST_AGE_PASSPHRASE_CMD:-}" && -n "${TALOS_OFFHOST_AGE_PASSPHRASE_FILE:-}" ]]; then
        die "both TALOS_OFFHOST_AGE_PASSPHRASE_CMD and TALOS_OFFHOST_AGE_PASSPHRASE_FILE are set.
   Set exactly one. Resolving it by precedence would silently ignore one of them
   — and the one that loses is the FILE, the branch that carries the containment
   checks. Unset whichever you did not mean."
    fi
    if [[ -z "${TALOS_OFFHOST_AGE_PASSPHRASE_CMD:-}${TALOS_OFFHOST_AGE_PASSPHRASE_FILE:-}" ]]; then
        die "no age passphrase source configured — the off-host archives cannot be opened.

   This mode answers 'if the host is gone, can the OFF-HOST copy be read?'.
   Supply the escrowed passphrase by ONE of:

     TALOS_OFFHOST_AGE_PASSPHRASE_CMD='op read \"op://Private/Talos age backup/password\"'
     TALOS_OFFHOST_AGE_PASSPHRASE_FILE=/Volumes/escrow/talos-age.pass
       (refused if that path is inside this repo or inside $BACKUP_DIR)

   If you cannot produce it from an off-box source, THAT IS THE DRILL RESULT:
   every archive in the bucket is currently unreadable. See docs/offhost-backup.md."
    fi
    if [[ -n "${TALOS_OFFHOST_AGE_PASSPHRASE_FILE:-}" ]]; then
        [[ -r "$TALOS_OFFHOST_AGE_PASSPHRASE_FILE" ]] \
            || die "TALOS_OFFHOST_AGE_PASSPHRASE_FILE='$TALOS_OFFHOST_AGE_PASSPHRASE_FILE' is not readable"
        AGE_PASS_REAL="$(escrow_realpath "$TALOS_OFFHOST_AGE_PASSPHRASE_FILE")" \
            || die "could not resolve TALOS_OFFHOST_AGE_PASSPHRASE_FILE"
        assert_escrow_path_contained "$AGE_PASS_REAL" "age passphrase file"
    else
        assert_escrow_cmd_paths_contained "$TALOS_OFFHOST_AGE_PASSPHRASE_CMD"
    fi

    # The helper re-applies the same containment in Rust (pure, unit-tested),
    # and fails closed if it cannot determine the roots. Both checkout roots:
    # this one AND the main clone when we are in a worktree.
    TALOS_OFFHOST_CHECKOUT_ROOTS="$(escrow_forbidden_roots | paste -sd: -)"
    export TALOS_OFFHOST_CHECKOUT_ROOTS
    # One knob, two gates — resolved and validated above step 1, so a
    # malformed value dies here instead of being coerced back to 168 inside
    # the helper.
    TALOS_OFFHOST_MAX_AGE_HOURS="$MAX_ARTIFACT_AGE_HOURS"
    export TALOS_OFFHOST_MAX_AGE_HOURS

    OFFHOST_BIN="${TALOS_OFFHOST_BIN:-}"
    if [[ -z "$OFFHOST_BIN" ]]; then
        # `env -u DATABASE_URL` for the same reason as step 2: DATABASE_URL is
        # part of the sqlx macro fingerprint and its presence rebuilds a large
        # part of the workspace.
        (cd "$REPO_ROOT" && env -u DATABASE_URL cargo build --quiet \
            -p talos-offhost-backup --bin talos-offhost-backup) \
            || die "could not build talos-offhost-backup — fix the build before trusting a drill result"
        OFFHOST_TARGET_DIR="$(cd "$REPO_ROOT" && env -u DATABASE_URL cargo metadata --no-deps --format-version 1 \
            | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])')"
        OFFHOST_BIN="$OFFHOST_TARGET_DIR/debug/talos-offhost-backup"
    fi
    [[ -x "$OFFHOST_BIN" ]] || die "off-host helper missing after build: $OFFHOST_BIN"

    # Fetch = list + GET + age-decrypt + AGE-ASSERT, all inside the helper.
    # Its stdout is the object key and nothing else; every diagnostic is on
    # stderr and is visible above.
    PG_OBJECT="$("$OFFHOST_BIN" fetch --kind postgres --dest "$WORK_DIR/pg.dump")" \
        || die "could not fetch + decrypt the off-host POSTGRES archive.
   This is the whole point of --source b2: there is no usable off-host copy of
   the database right now. Check scripts/offhost-backup/upload.sh, its log at
   ~/.talos/logs/offhost-backup.log, and talos_offhost_backup_failures_total."
    VAULT_OBJECT="$("$OFFHOST_BIN" fetch --kind vault --dest "$WORK_DIR/vault.tgz")" \
        || die "could not fetch + decrypt the off-host VAULT archive.
   Without Vault the restored database is ciphertext nobody can read: it holds
   every OAuth token, and the transit key when KEK_PROVIDER=vault."
    # Uploaded artifacts ARE the sidecar tarballs, which are rooted at the
    # CONTENTS of /vault/file — not the vault/file/ prefix a --source live
    # tar carries. Extracting the wrong one yields an empty file backend and
    # a vault that "starts" uninitialised.
    VAULT_TAR_ROOT="contents"
    ok "postgres object: $PG_OBJECT ($(wc -c < "$WORK_DIR/pg.dump") bytes decrypted)"
    ok "vault object:    $VAULT_OBJECT ($(wc -c < "$WORK_DIR/vault.tgz") bytes decrypted)"
    # Age was asserted inside the helper against
    # TALOS_OFFHOST_MAX_AGE_HOURS (set above from the drill's own knob), so a
    # stale bucket has already failed the run by this point rather than being
    # printed and ignored.
    #
    # ...unless the knob is 0, which DISABLES the staleness limit inside the
    # helper. Printing "within 0h" then would be the same defect this line
    # was written to avoid, one report further out: a ✓ asserting a bound
    # nothing checked. The LOCAL branch already warns in that case; same
    # knob, so the same report.
    if (( MAX_ARTIFACT_AGE_HOURS == 0 )); then
        warn "off-host archive staleness gate DISABLED (TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS=0) — age was NOT asserted on this run
   A future-dated key is still refused; only the upper bound is off."
    else
        ok "off-host archives are within ${MAX_ARTIFACT_AGE_HOURS}h"
    fi
else
    log "[1/8] dumping LIVE postgres + vault (--source live)"
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

# Both other kinds are now PRESENT (step 1 hard-fails if either is missing on
# any source). Stamp them 0 — "present, not yet verified" — so that if the drill
# dies in step 4 or step 5 the metric says which kind it died on, instead of
# omitting the line and reading like the artifact was never there.
record_kind postgres 0
record_kind vault 0

# ── 2. Build the verifiers BEFORE anything holds real data ────────
# `cargo run` at verify time was the original shape and it is a trap: the
# drill exports DATABASE_URL, which is part of the sqlx macro fingerprint, so
# the "run" recompiles a large part of the workspace — 17 minutes on the
# 2026-08-03 run — with a scratch Postgres full of restored user data
# listening on a loopback port for every second of it. Build first, with
# DATABASE_URL scrubbed, then execute the binaries directly.
log "[2/8] building verifiers (this is the slow step; nothing is staged yet)"
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

# ── 3. Spin up scratch Postgres ───────────────────────────────────
# A dedicated bridge network: the scratch stack must never be able to reach
# the live one, and vice versa.
log "[3/8] starting scratch postgres (throwaway net + creds + volume)"
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
log "[4/8] restoring dump into scratch postgres"
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
record_kind postgres 1

# ── 5. Restore Vault into scratch and unseal it ───────────────────
log "[5/8] restoring vault + unsealing"
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
if [[ "$KEK_PROVIDER_MODE" == "vault" ]]; then
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
record_kind vault 1

if [[ "$KEK_PROVIDER_MODE" == "vault" ]]; then
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
    warn "KEK_PROVIDER=$KEK_PROVIDER_MODE — the restored Vault is not on the KEK path here"
fi

# ── 6. Restore Neo4j into scratch and probe the RESTORED graph ────
#
# WHY THIS LEG EXISTS. Until 2026-08-26 this script contained ZERO occurrences
# of the string "neo4j" (measured on 037b96d3: 0 in 1421 lines). It knew two
# artifacts, hard-failed if either was missing, and printed an unqualified
# "Drill … PASSED" — so a green run certified TWO of the THREE kinds the host
# backs up, and nothing in its output or its metrics could tell you that. #677
# had just added neo4j to the off-host UPLOADER and said, in the PR, that the
# restore path did not follow. This is that follow.
#
# WHAT IS BEING ASSERTED, AND WHY IT IS NOT EQUALITY.
#
# The manifest carries `neo4j_nodes=` / `neo4j_relationships=` written by the
# sidecar's cypher probe. Those numbers have been sitting in every manifest
# since July with NO reader. The ordering matters and is easy to get backwards:
# `content_probe` is DEFINED near the top of dev-volume-backup-loop.sh but its
# sole CALL SITE is the manifest here-block at the very END of take_backup —
# after `tar -czf`, after the integrity check, after the `.partial` → final
# rename. So the probe reads the LIVE graph *after* the archive's content is
# already fixed. Measured across all 13 manifests on this host: archive stamp →
# probe is 26-55 s (median 32).
#
# That gives a ONE-SIDED relation, because the graph never shrinks. Every
# Cypher write in the workspace lives in exactly one file
# (talos-graph-rag/src/lib.rs) and its node writer is
# `MERGE (n:{label} {actor_id, name})`; there is no production DELETE, no
# DETACH DELETE, and no graph pruning/retention job anywhere. So:
#
#     restored <= manifest        (structural: counts are monotonic)
#     restored >= manifest - TOL  (the actual verification)
#
# The UPPER bound is exact and deliberately has no tolerance. It cannot be
# exceeded while the MERGE-only property holds, so a violation means either the
# manifest does not belong to this archive or that property has expired — both
# worth a red drill. This is #677's own lesson applied to this assertion: the
# condition that would reverse it is named, and dated 2026-08-26.
#
# The LOWER bound does the work. TOL defaults to 50 rather than 0 for a reason
# that is about the ROUTING TABLE, not about statistics: all 13 archives on this
# host restore to EXACTLY their manifest counts (7 of them taken on days the
# graph actually grew, by +37/+16/+28/+1/+30/+39 nodes), so equality would
# usually hold — but `talos_backup_drill_last_status == 0` carries
# `category: data-loss`, and alertmanager-route.yaml sends that category to
# PagerDuty at repeat_interval 1h. A count assertion that is flaky PAGES, and a
# pager that cries wolf trains an operator to ignore red, which is the same
# defect one level up. 50 is more than an entire peak DAY's write volume
# (39 nodes / 64 rels), therefore more than any 55 s window can contain.
#
# AND 50 MASKS NOTHING, because no real failure is that small:
#   * wrong extraction root      → 0 nodes restored, a 1283-node deficit
#   * truncated/corrupt archive  → caught by the sha256 in step 1, then by tar
#   * `transactions/` missing    → store opens at the last checkpoint, which
#                                  CAN be a small deficit — so that one is
#                                  closed STRUCTURALLY below (expected-paths
#                                  assertion on the extracted tree), not by the
#                                  number
#   * store opens but the DB is broken → `SHOW DATABASES` currentStatus check
#
# ISOLATION. `--network none` was the obvious choice and it does not work:
# measured, Neo4j 5.26 refuses to start without a network namespace (exit 3 in
# 2 s, empty debug.log) — confirmed with a 2x2 control against an EMPTY volume,
# so the cause is the namespace and not the restored store. Instead: the same
# per-run bridge the rest of the drill uses, NO published ports at all, and
# every query issued through `docker exec` against a LITERAL
# `bolt://localhost:7687` — the container's own loopback, not an address
# derived from anything.
#
# AND THE ISOLATION IS PROVEN, not asserted. The scratch server runs
# NEO4J_AUTH=none; the live talos-neo4j runs with auth ENABLED and answers an
# anonymous connection with "The client is unauthorized due to authentication
# failure" (verified against the live stack). So an ANONYMOUS query that
# SUCCEEDS cannot have reached the live instance. A useful side effect: this
# leg needs no Neo4j credential at all — there is nothing here to log, leak, or
# bake into a fixture.
if [[ "$SOURCE_MODE" != "artifact" ]]; then
    # b2 and live are out of this leg's reach and MUST NOT read as verified.
    # See the banner and docs/offhost-backup.md — #677 made neo4j uploadable
    # and fetchable, so `--source b2` under-certifies in exactly the way this
    # leg exists to stop being silent about.
    NEO4J_STATE="not-attempted"
    log "[6/8] neo4j: NOT ATTEMPTED for --source $SOURCE_MODE"
    warn "neo4j is restored only by --source artifact; this run certifies 2 of 3 kinds"
elif [[ "$NEO4J_STATE" == "absent" ]]; then
    log "[6/8] neo4j: NOT PRESENT on this host (waived with TALOS_DRILL_ALLOW_NO_NEO4J=1)"
else
    log "[6/8] restoring neo4j into scratch and probing the RESTORED graph"
    # Present ⇒ stamped 0 up front; only the successful path below upgrades it.
    record_kind neo4j 0
    docker volume create "$SCRATCH_NEO4J_VOLUME" >/dev/null || die "could not create scratch neo4j volume"
    docker volume create "$SCRATCH_NEO4J_LOGS"   >/dev/null || die "could not create scratch neo4j log volume"

    cp "$NEO4J_ARTIFACT" "$WORK_DIR/neo4j.tgz" || die "could not stage the neo4j artifact"
    # The sidecar tars `-C "$SRC_DIR" .`, so members are root-relative
    # (./databases, ./transactions, ./dbms, ./server_id) and the extraction
    # root is /data itself. Getting this wrong is the highest-probability bug
    # in the whole leg and it fails LOUDLY rather than subtly: Neo4j would come
    # up on an empty store and answer 0, which the count assertion rejects by a
    # factor of ~25 over the tolerance.
    docker run --rm \
        --network "$SCRATCH_NETWORK" \
        -v "$SCRATCH_NEO4J_VOLUME:/data" \
        -v "$WORK_DIR:/in:ro" \
        --entrypoint sh \
        "$NEO4J_IMAGE" \
        -c 'tar -xzf /in/neo4j.tgz -C /data' \
        >/dev/null || die "neo4j extract FAILED — $NEO4J_ARTIFACT is not a readable tar.gz"

    # EXPECTED PATHS, ASSERTED ON THE EXTRACTED TREE. The sidecar checks these
    # against the archive LISTING when it writes; this checks them against what
    # actually landed on disk. It is what closes the "transactions/ went
    # missing" case — a store without its transaction logs opens cleanly at the
    # last checkpoint and loses only the txns since, which is exactly the size
    # of deficit a 50-node tolerance would swallow.
    for p in $NEO4J_EXPECTED_PATHS; do
        docker run --rm --network "$SCRATCH_NETWORK" -v "$SCRATCH_NEO4J_VOLUME:/data" \
            --entrypoint sh "$NEO4J_IMAGE" -c "test -e '/data/${p#./}'" \
            || die "restored neo4j store is missing '$p' (the manifest's expected_paths).
   A store without ./transactions opens at its last checkpoint and silently
   drops every transaction since — a deficit small enough to pass a count
   tolerance, which is why it is checked structurally here."
    done
    ok "restored neo4j store has every expected path: $NEO4J_EXPECTED_PATHS"

    # NEO4J_AUTH=none is the isolation discriminator described above, AND it
    # keeps every credential out of this script. The restored dbms/auth.ini is
    # left untouched on disk; the config setting simply makes it irrelevant.
    docker run -d \
        --name "$SCRATCH_NEO4J_NAME" \
        --network "$SCRATCH_NETWORK" \
        -v "$SCRATCH_NEO4J_VOLUME:/data" \
        -v "$SCRATCH_NEO4J_LOGS:/logs" \
        -e NEO4J_AUTH=none \
        -e NEO4J_server_memory_heap_initial__size=256m \
        -e NEO4J_server_memory_heap_max__size=512m \
        "$NEO4J_IMAGE" >/dev/null \
        || die "scratch neo4j failed to start"

    # THE READINESS LOOP RE-CHECKS LIVENESS EVERY ITERATION. A bare poll would
    # turn the version-mismatch case — the single most likely reason a raw
    # store copy will not open — into a 90-second timeout whose message names
    # the wrong cause. Measured: a Neo4j that cannot start exits in ~2 s with
    # code 3 and an EMPTY debug.log, so the container log and the /logs volume
    # are both dumped the moment `.State.Running` goes false. This is also what
    # makes the negative test fail AT the failure rather than at a deadline.
    neo4j_ready=0
    for i in $(seq 1 90); do
        if [[ "$(docker inspect -f '{{.State.Running}}' "$SCRATCH_NEO4J_NAME" 2>/dev/null)" != "true" ]]; then
            warn "scratch neo4j container log:"
            docker logs --tail 40 "$SCRATCH_NEO4J_NAME" 2>&1 | tail -40 >&2 || true
            warn "scratch neo4j /logs/neo4j.log:"
            docker run --rm -v "$SCRATCH_NEO4J_LOGS:/logs" --entrypoint sh "$NEO4J_IMAGE" \
                -c 'tail -40 /logs/neo4j.log 2>/dev/null; tail -40 /logs/debug.log 2>/dev/null' >&2 || true
            die "scratch neo4j EXITED after ${i}s (code $(docker inspect -f '{{.State.ExitCode}}' "$SCRATCH_NEO4J_NAME" 2>/dev/null)).
   The store is a RAW COPY, so the commonest cause is an image that does not
   match the one that wrote it — this drill pins
   ${NEO4J_IMAGE}
   and docker-compose.yml must pin the same digest for both the neo4j service
   and the neo4j-backup sidecar. Override with TALOS_DRILL_NEO4J_IMAGE."
        fi
        if docker exec "$SCRATCH_NEO4J_NAME" cypher-shell -a bolt://localhost:7687 \
                --format plain "RETURN 1;" >/dev/null 2>&1; then
            neo4j_ready=1
            ok "scratch neo4j accepted an ANONYMOUS query after ${i}s"
            ok "  ⇒ this is NOT the live graph: talos-neo4j runs with auth enabled and refuses anonymous connections"
            break
        fi
        sleep 1
    done
    (( neo4j_ready == 1 )) || die "scratch neo4j never became queryable within 90s — see 'docker logs $SCRATCH_NEO4J_NAME'"

    # A SERVER THAT ANSWERS `RETURN 1` IS NOT A DATABASE THAT RECOVERED.
    # Neo4j will happily serve the system database while the `neo4j` database
    # sits in `failed` after a botched recovery, so ask it directly rather than
    # inferring liveness from the fact that something replied.
    NEO4J_DB_STATUS=$(docker exec "$SCRATCH_NEO4J_NAME" cypher-shell -a bolt://localhost:7687 \
        --format plain "SHOW DATABASES YIELD name, currentStatus WHERE name = 'neo4j' RETURN currentStatus;" \
        2>/dev/null | tail -1 | tr -d '"' | tr -d ' ' || true)
    [[ "$NEO4J_DB_STATUS" == "online" ]] \
        || die "restored neo4j database is '${NEO4J_DB_STATUS:-<unreadable>}', not 'online' — transaction recovery did not complete"
    ok "restored neo4j database is online (transaction recovery completed)"

    NEO4J_RESTORED_NODES=$(docker exec "$SCRATCH_NEO4J_NAME" cypher-shell -a bolt://localhost:7687 \
        --format plain "MATCH (n) RETURN count(n);" 2>/dev/null | tail -1 | tr -d ' ' || true)
    NEO4J_RESTORED_RELS=$(docker exec "$SCRATCH_NEO4J_NAME" cypher-shell -a bolt://localhost:7687 \
        --format plain "MATCH ()-[r]->() RETURN count(r);" 2>/dev/null | tail -1 | tr -d ' ' || true)
    [[ "$NEO4J_RESTORED_NODES" =~ ^[0-9]+$ ]] \
        || die "could not read a node count from the restored graph (got '${NEO4J_RESTORED_NODES:-<empty>}')"
    [[ "$NEO4J_RESTORED_RELS" =~ ^[0-9]+$ ]] \
        || die "could not read a relationship count from the restored graph (got '${NEO4J_RESTORED_RELS:-<empty>}')"

    # BOTH counts, not just nodes. The sidecar's probe runs the node query and
    # the relationship query SEPARATELY and prints
    # `neo4j_relationships=${rels:-unknown}` on the branch where the NODE query
    # succeeded — so `neo4j_nodes=1283` beside `neo4j_relationships=unknown` is
    # a manifest this host can really produce. Guarding on nodes alone reached
    # `assert_neo4j_count relationships 1939 ""`, and bash coerces the empty
    # string to 0 inside `(( ))` — so it evaluated `1939 > 0` and died with
    # "restored neo4j relationships (1939) EXCEEDS the manifest's ()". A false
    # RED on a shape the producer emits by design, and one that PAGES
    # (last_status=0 carries category: data-loss). Found by auditing this leg
    # against the standing question "can it pass without having verified
    # anything"; the exact failure mode was then MEASURED, not predicted — the
    # first guess written here was "arithmetic syntax error", which bash does
    # not do for an empty operand.
    if [[ -z "$NEO4J_MANIFEST_NODES" || -z "$NEO4J_MANIFEST_RELS" ]]; then
        # `neo4j_nodes=unknown`, or no manifest at all. THE RESTORE STILL RAN
        # and still proved something real — the archive opens, the store is a
        # valid Neo4j store, the database recovers to `online` — but there is
        # no recorded truth to compare the content against, so this is NOT a
        # verification and must not be reported as one. It is recorded as
        # kind_verified=0 ("present but NOT verified"), which is a different
        # value from 1 and a different thing from no line at all.
        NEO4J_STATE="unverifiable"
        NEO4J_DETAIL="restored $NEO4J_RESTORED_NODES nodes / $NEO4J_RESTORED_RELS rels; manifest nodes=${NEO4J_MANIFEST_NODES:-unknown} rels=${NEO4J_MANIFEST_RELS:-unknown}"
        record_kind neo4j 0
        warn "neo4j manifest has no usable node AND relationship count (the sidecar writes"
        warn "  'unknown' for whichever query could not reach the graph; both are required"
        warn "  because a half-known manifest verifies half a graph). The store restored"
        warn "  and the database came up"
        warn "  online with $NEO4J_RESTORED_NODES nodes / $NEO4J_RESTORED_RELS relationships,"
        warn "  but NOTHING was verified against it — this is 'present but unverifiable',"
        warn "  not a pass. Fix the sidecar's probe (docker logs talos-neo4j-backup) so the"
        warn "  NEXT artifact carries a count."
    else
        assert_neo4j_count() {
            local label="$1" restored="$2" expected="$3"
            if (( restored > expected )); then
                die "restored neo4j $label ($restored) EXCEEDS the manifest's ($expected).
   That is supposed to be impossible: the graph is MERGE-only with no production
   DELETE path, so an archive can never hold MORE than the probe taken after it.
   Either this manifest does not belong to this archive, or the MERGE-only
   property has expired (measured 2026-08-26; re-derive with
   grep -rn --include='*.rs' 'DETACH DELETE' talos-graph-rag/src)."
            fi
            local deficit=$(( expected - restored ))
            if (( deficit > NEO4J_COUNT_TOLERANCE )); then
                die "restored neo4j $label ($restored) is $deficit short of the manifest's ($expected),
   over the ${NEO4J_COUNT_TOLERANCE} tolerance. THIS BACKUP DID NOT RESTORE ITS CONTENT.
   A deficit this size is not the 26-55 s probe-after-tar window: check that the
   archive contains ./databases AND ./transactions, and compare
   '$NEO4J_ARTIFACT' against its .manifest. Raise
   TALOS_DRILL_NEO4J_COUNT_TOLERANCE only if you can show the graph legitimately
   grew that much inside one backup's probe window."
            fi
            ok "neo4j $label: restored $restored vs manifest $expected (deficit $deficit, tolerance $NEO4J_COUNT_TOLERANCE)"
        }
        assert_neo4j_count "nodes"         "$NEO4J_RESTORED_NODES" "$NEO4J_MANIFEST_NODES"
        assert_neo4j_count "relationships" "$NEO4J_RESTORED_RELS"  "$NEO4J_MANIFEST_RELS"
        NEO4J_STATE="verified"
        NEO4J_DETAIL="restored $NEO4J_RESTORED_NODES/$NEO4J_RESTORED_RELS vs manifest $NEO4J_MANIFEST_NODES/$NEO4J_MANIFEST_RELS"
        record_kind neo4j 1
    fi
fi

# ── 7. Verify against the restored stack ──────────────────────────
log "[7/8] verifying the restored stack"
DATABASE_URL="postgres://${SCRATCH_PG_USER}:${SCRATCH_PG_PASSWORD}@127.0.0.1:${SCRATCH_PG_PORT}/${SCRATCH_PG_DB}"
# EVERY migration version this checkout ships, not just the newest. The
# verifier used to be handed only the newest and required equality, which
# false-reds on a good backup: an artifact taken before a migration landed
# cannot contain it, and migrations land most weeks. See verify_restore.rs.
MIGRATION_VERSIONS="$(ls -1 "$REPO_ROOT"/migrations/*.sql 2>/dev/null \
    | sed 's#.*/##' | cut -d_ -f1 | sort -n | paste -sd, -)"
EXPECT_MIGRATION="${MIGRATION_VERSIONS##*,}"

run_verifier() {
    local bin="$1"; local label="$2"
    DATABASE_URL="$DATABASE_URL" \
    TALOS_MASTER_KEY="$TALOS_MASTER_KEY" \
    KEK_PROVIDER="$KEK_PROVIDER_MODE" \
    VAULT_ADDR="$VAULT_ADDR" \
    VAULT_TOKEN="$VAULT_TOKEN" \
    VAULT_TRANSIT_KEY_NAME="${VAULT_TRANSIT_KEY_NAME:-talos-kek}" \
    TALOS_DRILL_MIGRATION_VERSIONS="$MIGRATION_VERSIONS" \
        "$bin" || die "$label against the restored stack FAILED — backups not restorable"
    ok "$label passed against the restored stack"
}

# verify_restore first: it reads what the BACKUP contained. verify_phase_b
# then writes, so running it second keeps the read checks off rows this drill
# created itself.
run_verifier "$VERIFY_RESTORE_BIN" "verify_restore"
run_verifier "$VERIFY_PHASE_B_BIN" "verify_phase_b"

# ── 8. Done ───────────────────────────────────────────────────────
log "[8/8] drill passed"
DRILL_COMPLETE=1
emit_metric success

# THE HEADLINE CARRIES THE COVERAGE, because the headline is the only part of
# this that gets read on a good day. A green "PASSED" box with a "Neo4j: NOT
# VERIFIED" line four rows below it is the same shape as the defect this whole
# leg exists to remove — a green signal certifying less than it appears to. So
# the count of kinds actually verified goes IN the box, and the box turns amber
# the moment it is not 3 of 3. Denominator is 3 because that is how many
# artifact kinds this platform backs up (talos-offhost-backup/src/key.rs's
# ArtifactKind), NOT how many this run attempted: a host that legitimately has
# no graph still reads 2/3, and the line below says why. Reporting "2/2" for
# that host would be exactly the aggregation that hides the shortfall.
BANNER_KINDS_OK=0
if [[ -n "$KIND_VERIFIED_LINES" ]]; then
    BANNER_KINDS_OK=$(printf '%s\n' "$KIND_VERIFIED_LINES" | grep -c '} 1$' || true)
fi
BANNER_COLOUR='1;32'
(( BANNER_KINDS_OK < 3 )) && BANNER_COLOUR='1;33'
printf '\n\033[%sm╔══════════════════════════════════════════════════════════════╗\033[0m\n' "$BANNER_COLOUR"
# ASCII only inside the padded field: printf's %-60s pads by BYTES, and an
# em dash is 3 bytes to 1 display column, which knocks the box border out of
# alignment by 2. The border characters themselves are literals, so they are
# unaffected.
printf '\033[%sm║ %-60s ║\033[0m\n' "$BANNER_COLOUR" \
    "Drill $DRILL_ID PASSED - $BANNER_KINDS_OK/3 kinds verified"
printf '\033[%sm╚══════════════════════════════════════════════════════════════╝\033[0m\n' "$BANNER_COLOUR"
printf '  Source:          %s\n' "$SOURCE_MODE"
[[ "$SOURCE_MODE" == "artifact" ]] && printf '  Postgres backup: %s\n' "$(basename "${PG_ARTIFACT:-?}")"
[[ "$SOURCE_MODE" == "artifact" ]] && printf '  Vault backup:    %s\n' "$(basename "${VAULT_ARTIFACT:-?}")"
# THE THIRD KIND, ALWAYS NAMED. The banner is where an operator decides whether
# to stop reading, so the state that used to be invisible is printed here rather
# than only in the caveat block: "verified", "not present" and "present but
# unverifiable" are three different lines, and none of them is silence.
case "$NEO4J_STATE" in
    verified)
        printf '  Neo4j backup:    %s\n' "$(basename "${NEO4J_ARTIFACT:-?}")"
        printf '  Neo4j content:   VERIFIED — %s\n' "$NEO4J_DETAIL" ;;
    unverifiable)
        printf '  Neo4j backup:    %s\n' "$(basename "${NEO4J_ARTIFACT:-?}")"
        printf '  Neo4j content:   NOT VERIFIED (present but unverifiable) — %s\n' "$NEO4J_DETAIL" ;;
    absent)
        printf '  Neo4j content:   NOT VERIFIED — no artifact on this host (TALOS_DRILL_ALLOW_NO_NEO4J=1)\n' ;;
    *)
        printf '  Neo4j content:   NOT VERIFIED — not attempted for --source %s\n' "$SOURCE_MODE" ;;
esac
[[ "$SOURCE_MODE" == "b2" ]] && printf '  Postgres object: %s\n' "${PG_OBJECT:-?}"
[[ "$SOURCE_MODE" == "b2" ]] && printf '  Vault object:    %s\n' "${VAULT_OBJECT:-?}"
# The RESTORED schema version is reported by verify_restore (which is the only
# thing that has read it); this line is the checkout's, labelled as such so the
# two are never confused.
printf '  Checkout schema: %s (newest migration in this working tree)\n' "$EXPECT_MIGRATION"
# The KEK line states the SOURCE THAT WAS CONFIGURED, not a verdict about it.
# It used to read "(ESCROW — the live stack was never asked)" unconditionally,
# which is a claim this script cannot check:
# `TALOS_DRILL_ESCROW_KEY_CMD='docker exec talos-controller printenv
# TALOS_MASTER_KEY'` printed exactly that line while the live stack was the
# only thing asked. That specific spelling is now REFUSED (step 0b), but the
# general claim is still unverifiable, so it is not made.
printf '  KEK source:      %s\n' "$KEK_SOURCE"
printf '                   (as configured; provenance is NOT verified — see step 0b STATED LIMITS)\n'
printf '  Metric:          %s\n' "$TEXTFILE"
# WHICH COPY THE METRIC NOW CLAIMS. Printed next to the file path because the
# whole point of the label is that a reader of the gauge can tell what was
# certified; a summary that omitted it would be the same gap one report out.
printf '                   (all three gauges labelled source="%s")\n' "$SOURCE_MODE"
printf '  Next drill:      within 7 days (alert fires at 14)\n'

# WHAT A PASS NOW MEANS, AND WHAT IT STILL DOES NOT. Printed inside the banner
# on purpose: a caveat forty lines above the result is a caveat nobody reads,
# and this arc exists because verifications quietly proved less than they
# implied.
#
# As of 2026-08-13 the KEK comes from ESCROW, never from the live controller,
# and its absence is fatal. So the claim has been upgraded from
#
#     artifacts + TODAY'S LIVE KEK  ⇒  readable        (untestable in a disaster)
# to
#     artifacts + ESCROWED KEK      ⇒  readable        (what recovery actually is)
#
# The remaining gap is now a CIPHERTEXT-LOCATION one, not a key one: the
# artifacts themselves still live only on this host's filesystem. Losing the
# disk loses them, escrowed key or not. That is Tier 2 and it is an open
# operator decision (encrypted off-host replication vs. object storage with an
# append-only credential) — see docker-compose.yml's `postgres-backup` comment
# and scripts/drills/README.md § What this drill doesn't cover, item 8.
printf '\n'
printf '\033[1;33m  ⚠ WHAT THIS DOES NOT PROVE\033[0m\n'
printf '\033[1;33m    KEK provenance: the live-container read is deleted and the shapes that\033[0m\n'
printf '\033[1;33m      re-create it are refused, but nothing here can show the configured\033[0m\n'
printf '\033[1;33m      source is genuinely off-box (a RAM disk, a vault synced to this same\033[0m\n'
printf '\033[1;33m      laptop, or a hard link past the containment check all read as escrow).\033[0m\n'
if [[ "$SOURCE_MODE" == "b2" ]]; then
    printf '\033[1;33m    Artifact location: this run READ FROM OBJECT STORAGE, so the claim is\033[0m\n'
    printf '\033[1;33m      the strong one: escrowed KEK + escrowed age passphrase + the OFF-HOST\033[0m\n'
    printf '\033[1;33m      copy are readable on a clean stack. Losing this disk does not lose it.\033[0m\n'
    printf '\033[1;33m      STILL NOT proven: that the bucket cannot be emptied. Delete/overwrite\033[0m\n'
    printf '\033[1;33m      refusal is the PROVIDER'"'"'s job and is checked separately by\033[0m\n'
    printf '\033[1;33m      `scripts/offhost-backup/upload.sh probe-append-only`, not by this drill.\033[0m\n'
    printf '\033[1;33m      Nor that the age passphrase source is genuinely off-box — same limit,\033[0m\n'
    printf '\033[1;33m      same reasons, as the KEK provenance bullet above.\033[0m\n'
else
    printf '\033[1;33m    Artifact location: this run read the LOCAL copy, on the very disk the\033[0m\n'
    printf '\033[1;33m      backups insure against losing.\033[0m\n'
    printf '\033[1;33m      Proven: escrowed KEK + these artifacts are readable on a clean stack.\033[0m\n'
    printf '\033[1;33m      NOT proven: that anything survives losing this disk. Run\033[0m\n'
    printf '\033[1;33m      `make drill ARGS="--source b2"` for that — it is a strictly harder\033[0m\n'
    printf '\033[1;33m      question and it is the one a recovery actually asks.\033[0m\n'
fi
if [[ "$KEK_PROVIDER_MODE" != "vault" ]]; then
    printf '\033[1;33m    KEK_PROVIDER=%s: the restored Vault is NOT on the decryption path here.\033[0m\n' "$KEK_PROVIDER_MODE"
    printf '\033[1;33m      Its file backend restored, unsealed, authenticated and mounted —\033[0m\n'
    printf '\033[1;33m      but no transit-wrapped DEK was unwrapped, because this deployment\033[0m\n'
    printf '\033[1;33m      does not wrap them that way.\033[0m\n'
fi
printf '\033[1;33m    Column families: only actor_memory, secrets and ml_examples ciphertext\033[0m\n'
printf '\033[1;33m      was decrypted and content-checked. workflow_executions output, module\033[0m\n'
printf '\033[1;33m      payloads, TOTP/webhook secrets and integration_state were not.\033[0m\n'
# WHAT THE NEO4J COUNTS DO AND DO NOT PROVE. Said plainly, because a count is a
# weak content check and a banner that implied otherwise would be this arc's
# own defect: 1,283 nodes of the right shape and 1,283 nodes of garbage both
# count 1,283.
if [[ "$NEO4J_STATE" == "verified" ]]; then
    printf '\033[1;33m    Neo4j content: the CARDINALITY of the restored graph matches the count\033[0m\n'
    printf '\033[1;33m      the sidecar recorded, and its labels/relationship types are readable.\033[0m\n'
    printf '\033[1;33m      NOT proven: that any individual node holds the right PROPERTIES. Nothing\033[0m\n'
    printf '\033[1;33m      here compares a node to a known value — the manifest records only two\033[0m\n'
    printf '\033[1;33m      integers, so two integers is the strongest claim available from it.\033[0m\n'
else
    printf '\033[1;33m    Neo4j: NOT verified on this run (%s). This drill certified 2 of the 3\033[0m\n' "$NEO4J_STATE"
    printf '\033[1;33m      artifact kinds this host backs up. See the Neo4j line above.\033[0m\n'
fi
printf '\n'
