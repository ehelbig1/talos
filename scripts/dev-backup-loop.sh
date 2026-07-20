#!/bin/bash
# Local-dev Postgres backup loop — runs inside the `postgres-backup`
# compose sidecar (see docker-compose.yml).
#
# Why this exists: the dev database holds the ONLY copy of data that is
# not reproducible from git — human severity corrections, the ML gold
# slice, ops-alert triage history, actor memory. Code re-clones; labels
# don't. Dumps land on the HOST filesystem (bind mount), deliberately
# NOT in a docker volume or MinIO: on a single machine those share the
# same failure domain as the database volume (`docker volume rm`,
# `make clean`, compose down -v), while a host directory survives all
# docker-level wipes and rides the user's machine backups (Time
# Machine) off-box for free.
#
# Wake-aware cadence: instead of a fixed nightly hour (which a sleeping
# laptop misses indefinitely), each hourly tick backs up whenever the
# newest dump is older than BACKUP_INTERVAL_HOURS. A laptop opened
# after a week immediately takes a fresh backup.
#
# Every dump is RESTORE-VERIFIED into a scratch database (pg_restore +
# a corrections-count sanity probe) before it counts — a backup you
# haven't restored is a hypothesis (deploy/k3s/README.md says the same
# for prod). Failures log loudly at ERROR for `docker logs`.
set -euo pipefail

PGHOST="${PGHOST:-postgres}"
PGUSER="${PGUSER:-talos}"
PGDATABASE="${PGDATABASE:-talos}"
BACKUP_DIR="${BACKUP_DIR:-/backups}"
BACKUP_INTERVAL_HOURS="${BACKUP_INTERVAL_HOURS:-24}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
VERIFY_DB="talos_backup_verify"

log() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$*"; }

newest_dump_age_hours() {
    local newest
    newest=$(ls -1t "$BACKUP_DIR"/talos-*.dump 2>/dev/null | head -1 || true)
    [ -z "$newest" ] && { echo 999999; return; }
    echo $(( ($(date +%s) - $(stat -c %Y "$newest")) / 3600 ))
}

take_backup() {
    local stamp file tmp
    stamp=$(date -u +%Y%m%d-%H%M%S)
    file="$BACKUP_DIR/talos-$stamp.dump"
    tmp="$file.partial"
    log "backup: dumping $PGDATABASE -> $file"
    pg_dump -h "$PGHOST" -U "$PGUSER" -d "$PGDATABASE" \
        --format=custom --compress=9 --file="$tmp"
    mv "$tmp" "$file"
    log "backup: wrote $(du -h "$file" | cut -f1) $file"

    # ── Restore verification into a scratch DB ─────────────────────
    log "verify: restoring into $VERIFY_DB"
    dropdb -h "$PGHOST" -U "$PGUSER" --if-exists "$VERIFY_DB"
    createdb -h "$PGHOST" -U "$PGUSER" "$VERIFY_DB"
    # --no-owner: role names inside the dump may not exist verbatim.
    # Extensions (vector) exist cluster-wide on the pgvector image.
    if ! pg_restore -h "$PGHOST" -U "$PGUSER" -d "$VERIFY_DB" \
            --no-owner --exit-on-error "$file" >/dev/null 2>&1; then
        log "ERROR verify: pg_restore FAILED for $file — backup unusable, keeping previous dumps"
        dropdb -h "$PGHOST" -U "$PGUSER" --if-exists "$VERIFY_DB"
        rm -f "$file"
        return 1
    fi
    local corrections
    corrections=$(psql -h "$PGHOST" -U "$PGUSER" -d "$VERIFY_DB" -t -A -c \
        "SELECT count(*) FROM ml_examples WHERE source = 'correction';" 2>/dev/null || echo "-1")
    dropdb -h "$PGHOST" -U "$PGUSER" --if-exists "$VERIFY_DB"
    if [ "$corrections" -lt 0 ] 2>/dev/null; then
        log "ERROR verify: sanity probe failed (ml_examples unreadable) for $file"
        rm -f "$file"
        return 1
    fi
    log "verify: OK — $corrections corrections present in restored copy"

    # ── Retention ──────────────────────────────────────────────────
    find "$BACKUP_DIR" -name 'talos-*.dump' -mtime +"$RETENTION_DAYS" -delete
    find "$BACKUP_DIR" -name 'talos-*.dump.partial' -mmin +120 -delete
    log "backup: retention pruned to ${RETENTION_DAYS}d ($(ls -1 "$BACKUP_DIR"/talos-*.dump 2>/dev/null | wc -l) dumps kept)"
}

log "postgres-backup sidecar started (interval ${BACKUP_INTERVAL_HOURS}h, retention ${RETENTION_DAYS}d, dir $BACKUP_DIR)"
mkdir -p "$BACKUP_DIR"
while true; do
    age=$(newest_dump_age_hours)
    if [ "$age" -ge "$BACKUP_INTERVAL_HOURS" ]; then
        take_backup || log "ERROR backup cycle failed — will retry next tick"
    fi
    sleep 3600
done
