#!/usr/bin/env bash
# Talos backup + restore drill.
#
# "A backup you haven't restored is a hypothesis." This script tests
# the hypothesis end-to-end:
#
#   1. Dump live Postgres                     (via docker exec pg_dump)
#   2. Tar-gz live Vault data PVC             (via docker exec tar)
#   3. Spin up scratch Postgres + Vault       (temporary containers)
#   4. Restore Postgres dump into scratch     (pg_restore)
#   5. Restore Vault tarball into scratch     (untar into volume)
#   6. Run verify_phase_b against the scratch stack
#   7. Clean up scratch containers
#   8. Emit success/failure textfile metric for Prometheus scrape
#
# Exit codes:
#   0  drill passed — backups are restorable
#   1  any step failed — investigate before the next production incident
#
# Usage:
#   ./scripts/drills/backup-restore.sh              # default: docker-compose target
#   ./scripts/drills/backup-restore.sh --keep-scratch   # leave scratch running for inspection
#
# Cron-ready. Weekly cadence recommended:
#   0 3 * * 1  /opt/talos/scripts/drills/backup-restore.sh >> /var/log/talos/drill.log 2>&1

set -euo pipefail

# ── Config ────────────────────────────────────────────────────────
DRILL_ID="drill-$(date -u +%Y%m%dT%H%M%SZ)"
WORK_DIR="${TALOS_DRILL_WORKDIR:-/tmp/$DRILL_ID}"
KEEP_SCRATCH=0
TEXTFILE_DIR="${TALOS_DRILL_TEXTFILE_DIR:-/var/lib/node_exporter/textfile_collector}"
TEXTFILE="$TEXTFILE_DIR/talos_backup_drill.prom"

# Scratch port offsets — chosen to not collide with the live stack.
SCRATCH_PG_PORT="${TALOS_DRILL_PG_PORT:-55432}"
SCRATCH_VAULT_PORT="${TALOS_DRILL_VAULT_PORT:-58200}"
SCRATCH_PG_NAME="talos-drill-pg-$$"
SCRATCH_VAULT_NAME="talos-drill-vault-$$"
SCRATCH_VOLUME="talos-drill-vault-data-$$"

LIVE_PG_CONTAINER="${TALOS_DRILL_LIVE_PG:-talos-postgres}"
LIVE_VAULT_CONTAINER="${TALOS_DRILL_LIVE_VAULT:-talos-vault}"
PG_IMAGE="${TALOS_DRILL_PG_IMAGE:-pgvector/pgvector:pg16@sha256:7d400e340efb42f4d8c9c12c6427adb253f726881a9985d2a471bf0eed824dff}"
VAULT_IMAGE="${TALOS_DRILL_VAULT_IMAGE:-hashicorp/vault:1.18@sha256:750bb37c1638fa194ab37053a81618c61bb0491ddec6fccac87c07a8e6cd8166}"

# Parse args.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep-scratch) KEEP_SCRATCH=1; shift ;;
        --help|-h) sed -n '1,/^$/p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown flag: $1" >&2; exit 1 ;;
    esac
done

# ── Output helpers. No ansi codes go to the textfile. ─────────────
log()  { printf '\033[1;34m▶ [%s] %s\033[0m\n' "$(date -u +%H:%M:%S)" "$*"; }
ok()   { printf '\033[1;32m✓ %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m⚠ %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; emit_metric failure; exit 1; }

# ── Textfile metric for Prometheus scrape. ────────────────────────
# Atomic write via rename — node_exporter reads partial files as-is otherwise.
emit_metric() {
    local status="$1"; local ts; ts=$(date +%s)
    local tmp; tmp=$(mktemp)
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
    if [[ -d "$TEXTFILE_DIR" ]] && [[ -w "$TEXTFILE_DIR" ]]; then
        mv "$tmp" "$TEXTFILE"
        ok "emitted metric → $TEXTFILE ($status)"
    else
        rm -f "$tmp"
        warn "textfile dir $TEXTFILE_DIR not writable — skipping metric emission"
    fi
}

# Ensure we don't leak scratch containers/volumes on unexpected exit.
cleanup_scratch() {
    local code=$?
    if (( KEEP_SCRATCH == 1 )) && (( code == 0 )); then
        warn "--keep-scratch set; leaving $SCRATCH_PG_NAME $SCRATCH_VAULT_NAME up"
        return
    fi
    [[ -n "${SCRATCH_PG_NAME:-}" ]] && docker rm -f "$SCRATCH_PG_NAME" >/dev/null 2>&1 || true
    [[ -n "${SCRATCH_VAULT_NAME:-}" ]] && docker rm -f "$SCRATCH_VAULT_NAME" >/dev/null 2>&1 || true
    [[ -n "${SCRATCH_VOLUME:-}" ]] && docker volume rm "$SCRATCH_VOLUME" >/dev/null 2>&1 || true
    if [[ -d "$WORK_DIR" ]]; then
        rm -rf "$WORK_DIR"
    fi
}
trap cleanup_scratch EXIT

# ── 0. Pre-flight ─────────────────────────────────────────────────
log "drill id: $DRILL_ID"
mkdir -p "$WORK_DIR"
chmod 700 "$WORK_DIR"

command -v docker >/dev/null || die "docker CLI not found"
docker info >/dev/null 2>&1 || die "docker daemon not reachable"
docker inspect "$LIVE_PG_CONTAINER" >/dev/null 2>&1 || die "live postgres container '$LIVE_PG_CONTAINER' not running"
docker inspect "$LIVE_VAULT_CONTAINER" >/dev/null 2>&1 || die "live vault container '$LIVE_VAULT_CONTAINER' not running"

# Pull the live Postgres credentials out of env. Never log them.
PG_USER=$(docker exec "$LIVE_PG_CONTAINER" printenv POSTGRES_USER 2>/dev/null || true)
PG_DB=$(docker exec "$LIVE_PG_CONTAINER" printenv POSTGRES_DB 2>/dev/null || true)
PG_PASSWORD=$(docker exec "$LIVE_PG_CONTAINER" printenv POSTGRES_PASSWORD 2>/dev/null || true)
[[ -n "$PG_USER" && -n "$PG_DB" && -n "$PG_PASSWORD" ]] \
    || die "could not read POSTGRES_USER/DB/PASSWORD from $LIVE_PG_CONTAINER env"

# ── 1. Dump Postgres ──────────────────────────────────────────────
log "[1/7] dumping postgres (db=$PG_DB)"
docker exec -e PGPASSWORD="$PG_PASSWORD" "$LIVE_PG_CONTAINER" \
    pg_dump --username="$PG_USER" --dbname="$PG_DB" \
        --format=custom --compress=9 --no-owner --no-privileges \
    > "$WORK_DIR/pg.dump" \
    || die "pg_dump failed"
ok "pg.dump written ($(wc -c < "$WORK_DIR/pg.dump") bytes)"

# ── 2. Tar Vault data ─────────────────────────────────────────────
log "[2/7] snapshotting vault /vault/file"
docker exec "$LIVE_VAULT_CONTAINER" tar -czf - -C / vault/file \
    > "$WORK_DIR/vault.tgz" \
    || die "vault tar failed"
ok "vault.tgz written ($(wc -c < "$WORK_DIR/vault.tgz") bytes)"

# ── 3. Spin up scratch Postgres ───────────────────────────────────
log "[3/7] starting scratch postgres on :$SCRATCH_PG_PORT"
docker run -d --rm \
    --name "$SCRATCH_PG_NAME" \
    -e POSTGRES_USER="$PG_USER" \
    -e POSTGRES_DB="$PG_DB" \
    -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    -p "127.0.0.1:$SCRATCH_PG_PORT:5432" \
    "$PG_IMAGE" >/dev/null \
    || die "scratch postgres failed to start"

# Wait for scratch to become ready.
for i in $(seq 1 30); do
    if docker exec "$SCRATCH_PG_NAME" pg_isready -U "$PG_USER" >/dev/null 2>&1; then
        ok "scratch postgres ready"
        break
    fi
    sleep 1
    (( i == 30 )) && die "scratch postgres never became ready"
done

# ── 4. Restore Postgres dump into scratch ─────────────────────────
log "[4/7] restoring dump into scratch postgres"
# Copy the dump into the container then pg_restore — avoids streaming across docker exec stdin
# (which truncates on binary content in some docker versions).
docker cp "$WORK_DIR/pg.dump" "$SCRATCH_PG_NAME:/tmp/pg.dump"
docker exec -e PGPASSWORD="$PG_PASSWORD" "$SCRATCH_PG_NAME" \
    pg_restore --username="$PG_USER" --dbname="$PG_DB" \
        --no-owner --no-privileges \
        /tmp/pg.dump \
    || die "pg_restore failed"
ok "restore complete"

# Spot-check a key table loaded.
ROW_COUNT=$(docker exec -e PGPASSWORD="$PG_PASSWORD" "$SCRATCH_PG_NAME" \
    psql -tA -U "$PG_USER" -d "$PG_DB" \
    -c "SELECT COUNT(*) FROM encryption_keys WHERE active = true;")
[[ "$ROW_COUNT" =~ ^[0-9]+$ ]] || die "scratch postgres query for encryption_keys failed"
ok "encryption_keys rows in scratch: $ROW_COUNT"

# ── 5. Spin up scratch Vault from tarball ─────────────────────────
log "[5/7] starting scratch vault on :$SCRATCH_VAULT_PORT"
docker volume create "$SCRATCH_VOLUME" >/dev/null

# Extract the tarball into the volume. The tarball's root path is
# `vault/file/...` (from step 2), so we strip that when restoring into
# /vault/file inside the new volume.
docker run --rm \
    -v "$SCRATCH_VOLUME:/vault/file" \
    -v "$WORK_DIR:/in:ro" \
    --entrypoint sh \
    "$VAULT_IMAGE" \
    -c 'tar -xzf /in/vault.tgz -C / && ls /vault/file/' \
    >/dev/null || die "vault restore failed"

# Need a vault.hcl config — use a minimal one for the scratch instance.
cat > "$WORK_DIR/vault.hcl" <<EOF
storage "file" { path = "/vault/file" }
listener "tcp" {
    address     = "0.0.0.0:8200"
    tls_disable = 1
}
disable_mlock = true
api_addr = "http://127.0.0.1:8200"
EOF

docker run -d --rm \
    --name "$SCRATCH_VAULT_NAME" \
    --cap-add=IPC_LOCK \
    -v "$SCRATCH_VOLUME:/vault/file" \
    -v "$WORK_DIR/vault.hcl:/vault/config/vault.hcl:ro" \
    -p "127.0.0.1:$SCRATCH_VAULT_PORT:8200" \
    -e VAULT_ADDR=http://127.0.0.1:8200 \
    -e SKIP_CHOWN=true -e SKIP_SETCAP=true \
    "$VAULT_IMAGE" \
    vault server -config=/vault/config/vault.hcl >/dev/null \
    || die "scratch vault failed to start"

# Wait for Vault API (starts listening even while sealed).
for i in $(seq 1 30); do
    if docker exec "$SCRATCH_VAULT_NAME" vault status >/dev/null 2>&1 || [[ $? -eq 2 ]]; then
        ok "scratch vault listening"
        break
    fi
    sleep 1
    (( i == 30 )) && die "scratch vault never started"
done

# Unseal using the key from the restored bootstrap.json.
if docker exec "$SCRATCH_VAULT_NAME" test -f /vault/file/bootstrap.json; then
    UNSEAL_KEY=$(docker exec "$SCRATCH_VAULT_NAME" sh -c \
        "awk '/\"unseal_keys_b64\"/{f=1;next} /\]/{f=0} f' /vault/file/bootstrap.json \
            | sed -n 's/.*\"\\([^\"]*\\)\".*/\\1/p' | head -1")
    [[ -n "$UNSEAL_KEY" ]] || die "could not parse unseal key from restored bootstrap.json"
    docker exec "$SCRATCH_VAULT_NAME" vault operator unseal "$UNSEAL_KEY" >/dev/null \
        || die "scratch vault unseal failed"
    ok "scratch vault unsealed"
else
    die "restored vault missing bootstrap.json — unseal key lost"
fi

# ── 6. Run verify_phase_b against the scratch stack ───────────────
log "[6/7] running verify_phase_b against scratch postgres + vault"

# Resolve the live controller's TALOS_MASTER_KEY so the verifier can
# exercise env-legacy fallback if the scratch Vault is reachable.
LIVE_CONTROLLER="${TALOS_DRILL_LIVE_CONTROLLER:-talos-controller}"
TALOS_MASTER_KEY=$(docker exec "$LIVE_CONTROLLER" printenv TALOS_MASTER_KEY 2>/dev/null || echo "")
[[ -n "$TALOS_MASTER_KEY" ]] || die "could not read TALOS_MASTER_KEY from live controller"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Same KEK_PROVIDER as live — it must match how the DEKs were wrapped.
KEK_PROVIDER_LIVE=$(docker exec "$LIVE_CONTROLLER" printenv KEK_PROVIDER 2>/dev/null || echo "vault")

# Build up the verify env.
DATABASE_URL="postgres://${PG_USER}:${PG_PASSWORD}@127.0.0.1:${SCRATCH_PG_PORT}/${PG_DB}"
VAULT_ADDR="http://127.0.0.1:${SCRATCH_VAULT_PORT}"
VAULT_TOKEN=$(docker exec "$SCRATCH_VAULT_NAME" sh -c \
    "sed -n 's/.*\"root_token\"[[:space:]]*:[[:space:]]*\"\\([^\"]*\\)\".*/\\1/p' /vault/file/bootstrap.json | head -1")
[[ -n "$VAULT_TOKEN" ]] || die "could not parse root token from restored bootstrap.json"

# Verify the scratch vault is reachable before running the expensive verifier.
if ! VAULT_TOKEN="$VAULT_TOKEN" VAULT_ADDR="$VAULT_ADDR" \
        docker run --rm --network host "$VAULT_IMAGE" \
            vault token lookup >/dev/null 2>&1; then
    warn "scratch vault token lookup failed; proceeding anyway — verifier will catch real issues"
fi

cd "$REPO_ROOT"
DATABASE_URL="$DATABASE_URL" \
TALOS_MASTER_KEY="$TALOS_MASTER_KEY" \
KEK_PROVIDER="$KEK_PROVIDER_LIVE" \
VAULT_ADDR="$VAULT_ADDR" \
VAULT_TOKEN="$VAULT_TOKEN" \
VAULT_TRANSIT_KEY_NAME="${VAULT_TRANSIT_KEY_NAME:-talos-kek}" \
    cargo run --quiet --example verify_phase_b -p controller \
    || die "verify_phase_b against restored stack FAILED — backups not restorable"
ok "verify_phase_b passed against restored stack"

# ── 7. Done ───────────────────────────────────────────────────────
log "[7/7] drill passed"
emit_metric success

printf '\n\033[1;32m╔══════════════════════════════════════════════════════════════╗\033[0m\n'
printf '\033[1;32m║ Drill %-30s  PASSED  ║\033[0m\n' "$DRILL_ID"
printf '\033[1;32m╚══════════════════════════════════════════════════════════════╝\033[0m\n'
printf '  Postgres dump:   %s bytes\n' "$(wc -c < "$WORK_DIR/pg.dump" 2>/dev/null || echo '(cleaned up)')"
printf '  Vault tarball:   %s bytes\n' "$(wc -c < "$WORK_DIR/vault.tgz" 2>/dev/null || echo '(cleaned up)')"
printf '  encryption_keys: %s active rows\n' "$ROW_COUNT"
printf '  Next drill:      run in 7 days (or sooner if infra changes)\n'
printf '\n'
