#!/bin/bash
# Local-dev volume backup loop — the non-Postgres half of the dev-stack
# backup story. Runs inside the `vault-backup` and `neo4j-backup` compose
# sidecars (see docker-compose.yml). Sibling of scripts/dev-backup-loop.sh
# (Postgres); this script covers the two stateful stores whose data is NOT
# reproducible from git and NOT reachable with a clean logical dump tool:
#
#   • Vault  (BACKUP_TARGET=vault) — the file-storage KEK backend. Holds
#     the per-org DEKs and every OAuth token. Losing it makes ALL encrypted
#     rows (secrets, actor memory, TOTP, module payloads, exec output)
#     permanently unreadable — the single worst dev-stack failure mode, far
#     worse than losing Postgres (whose ciphertext would survive but be
#     undecryptable). There is no "reconstruct" path: gone means gone.
#
#   • Neo4j  (BACKUP_TARGET=neo4j) — graph-RAG entity data. Valuable but
#     RECONSTRUCTIBLE via the graph_backfill tool from actor_memory, so this
#     is a convenience safety net, not a last-line-of-defense artifact.
#
# Redis is deliberately NOT backed up: it is cache-only for the dev stack
# (embedding LRU, OCI module cache, semantic cache, rate-limit buckets, LLM
# key cache). Everything in it is either regenerated on demand or a mirror
# of Postgres state. A Redis backup would only add noise.
#
# ── Why a volume TAR and not a logical dump ────────────────────────────
# Neither store offers a safe live logical dump on this stack:
#   • Vault file backend: there is no "consistent snapshot" API for the file
#     storage backend (raft has `operator raft snapshot`; file does not).
#     The supported dev/prod path is a filesystem copy of /vault/file (see
#     deploy/k3s/README.md, which tars /vault/file the same way). We copy it
#     opaquely — the tar is NEVER extracted or inspected here, so no secret
#     material is ever read or logged. See the "integrity, not restore" note
#     below.
#   • Neo4j Community 5.x: `neo4j-admin database dump` requires the database
#     to be STOPPED (offline). We will not stop the live graph on a backup
#     schedule. `neo4j-admin database backup` (online) is Enterprise-only.
#     APOC cypher export exists in the image but streaming it cleanly through
#     cypher-shell is fragile (plain-format escaping mangles embedded
#     newlines/quotes) and file-export needs extra config. A volume tar of
#     /data is the pragmatic, robust dev choice; graph_backfill covers the
#     rare tear.
#
# ── Copy-while-live consistency: read-stability retry ──────────────────
# A tar of a live store can tear (files change mid-copy). We can't quiesce
# either service on a schedule, so we take a best-effort-consistent copy: we
# hash a listing of the source tree (path + size + mtime) BEFORE and AFTER
# the tar. If the signature changed, the tree moved under us → discard and
# retry, up to STABILITY_RETRIES. A stable signature across the copy window
# means nothing observable changed while we read. This shrinks — does not
# eliminate — the tear window; documented honestly as such.
#
# ── Verification level (HONEST scope) ──────────────────────────────────
# Unlike the Postgres sidecar (which pg_restores every dump into a scratch
# DB before it counts — a real restore-verify), these targets get
# INTEGRITY verification, NOT restore verification:
#   • Vault: `tar -tzf` (archive is well-formed + fully readable) + all
#     EXPECTED_PATHS present at the archive root + a manifest (file count,
#     uncompressed bytes, archive bytes, sha256 of the archive). We do NOT
#     unseal a scratch Vault and load the DEKs — that would require the
#     unseal key + a throwaway Vault and defeats the "never touch secret
#     material" rule. Restore procedure is documented in docs/dev-backup.md;
#     the real proof of DEK usability is: compose down, restore the volume,
#     compose up, controller /health green (it decrypts a DEK on boot).
#   • Neo4j: same tar integrity + expected-paths + manifest, PLUS a live
#     cypher-shell node/relationship count recorded in the manifest as a
#     reference/liveness datum. Community Edition hosts exactly ONE database
#     (+ system) and cannot create a scratch DB, so a true restore-verify is
#     impossible here; the count is a sanity signal, not a content diff.
#
# ── Same-dir, per-target subdirs ───────────────────────────────────────
# Backups land under the SAME host backup dir as Postgres
# (${TALOS_BACKUP_DIR:-~/.talos/backups}), in a per-target subdir
# (/backups/vault, /backups/neo4j) so Time Machine / host backups ride along
# off-box for free — the whole reason the Postgres sidecar writes to a host
# bind mount and not a docker volume. (Postgres itself writes to the backup
# root for backward compatibility with existing dumps.)
#
# Wake-aware cadence, .partial atomicity, loud ERROR logs, and retention
# pruning all mirror scripts/dev-backup-loop.sh.
set -euo pipefail

BACKUP_TARGET="${BACKUP_TARGET:?BACKUP_TARGET required (vault|neo4j)}"
SRC_DIR="${SRC_DIR:?SRC_DIR required (read-only mount of the source volume)}"
BACKUP_ROOT="${BACKUP_DIR:-/backups}"
BACKUP_DIR="$BACKUP_ROOT/$BACKUP_TARGET"
EXPECTED_PATHS="${EXPECTED_PATHS:-}"
BACKUP_INTERVAL_HOURS="${BACKUP_INTERVAL_HOURS:-24}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"
STABILITY_RETRIES="${STABILITY_RETRIES:-4}"

log() { printf '%s [%s-backup] %s\n' "$(date -u +%FT%TZ)" "$BACKUP_TARGET" "$*"; }

newest_backup_age_hours() {
    local newest
    newest=$(ls -1t "$BACKUP_DIR/$BACKUP_TARGET"-*.tar.gz 2>/dev/null | head -1 || true)
    [ -z "$newest" ] && { echo 999999; return; }
    echo $(( ($(date +%s) - $(stat -c %Y "$newest")) / 3600 ))
}

# Signature of the source tree: sorted path + size + mtime, hashed. Used
# only to DETECT change across the copy window — never records file NAMES to
# disk or logs (the sha256 is opaque). GNU find -printf is present in both
# the pgvector (Debian) and neo4j (Debian) sidecar images.
tree_signature() {
    find "$SRC_DIR" -printf '%P\t%s\t%T@\n' 2>/dev/null | LC_ALL=C sort | sha256sum | cut -d' ' -f1
}

# Optional per-target liveness probe. Only neo4j has one: a live node/rel
# count via cypher-shell, recorded in the manifest. Never fatal — the tar is
# a valid snapshot of whatever is on disk regardless of what the count says.
# Echoes manifest lines on stdout (empty for targets with no probe).
content_probe() {
    case "$BACKUP_TARGET" in
        neo4j)
            local nodes rels
            nodes=$(cypher-shell -a "${NEO4J_URI:-bolt://neo4j:7687}" \
                -u "${NEO4J_USER:-neo4j}" -p "${NEO4J_PASSWORD:-}" --format plain \
                "MATCH (n) RETURN count(n);" 2>/dev/null | tail -1 || true)
            rels=$(cypher-shell -a "${NEO4J_URI:-bolt://neo4j:7687}" \
                -u "${NEO4J_USER:-neo4j}" -p "${NEO4J_PASSWORD:-}" --format plain \
                "MATCH ()-[r]->() RETURN count(r);" 2>/dev/null | tail -1 || true)
            if [ -z "$nodes" ] || ! [ "$nodes" -ge 0 ] 2>/dev/null; then
                # WARN, not ERROR: an unreachable graph doesn't invalidate a
                # disk-level tar. Record unknown and move on.
                log "WARNING content probe: live node count unavailable (graph unreachable?)"
                printf 'neo4j_nodes=unknown\nneo4j_relationships=unknown\n'
            else
                log "content probe: live graph has $nodes nodes / ${rels:-unknown} relationships"
                printf 'neo4j_nodes=%s\nneo4j_relationships=%s\n' "$nodes" "${rels:-unknown}"
            fi
            ;;
        *) : ;;  # no probe for this target
    esac
}

take_backup() {
    local stamp file tmp sig_before sig_after attempt ok
    stamp=$(date -u +%Y%m%d-%H%M%S)
    file="$BACKUP_DIR/$BACKUP_TARGET-$stamp.tar.gz"
    tmp="$file.partial"

    # ── Read-stability retry loop ──────────────────────────────────────
    ok=0
    for attempt in $(seq 1 "$STABILITY_RETRIES"); do
        sig_before=$(tree_signature)
        log "backup: tarring $SRC_DIR -> $file (attempt $attempt/$STABILITY_RETRIES)"
        # -C into the source so archive members are root-relative (./core,
        # ./databases, ...). The tar is OPAQUE: we never list or extract its
        # members' contents; only metadata (count/bytes/sha) is recorded.
        if ! tar -czf "$tmp" -C "$SRC_DIR" . 2>/dev/null; then
            log "WARNING backup: tar exited non-zero on attempt $attempt (tree changing?), retrying"
            rm -f "$tmp"
            continue
        fi
        sig_after=$(tree_signature)
        if [ "$sig_before" = "$sig_after" ]; then
            ok=1
            break
        fi
        log "WARNING backup: source tree changed during copy (attempt $attempt), retrying"
        rm -f "$tmp"
    done
    if [ "$ok" -ne 1 ]; then
        log "ERROR backup: source never stabilized after $STABILITY_RETRIES attempts — no consistent snapshot, keeping previous backups"
        rm -f "$tmp"
        return 1
    fi

    # ── Integrity verification (tar is fully readable) ─────────────────
    local listing
    if ! listing=$(tar -tzf "$tmp" 2>/dev/null); then
        log "ERROR verify: archive is unreadable (tar -tzf failed) for $tmp — discarding"
        rm -f "$tmp"
        return 1
    fi

    # ── Expected top-level paths present ───────────────────────────────
    local p
    for p in $EXPECTED_PATHS; do
        # Members appear as "./core", "./core/...", etc. Match the dir entry
        # or anything under it so a trailing-slash variance doesn't miss.
        if ! printf '%s\n' "$listing" | grep -q -e "^${p}\$" -e "^${p}/"; then
            log "ERROR verify: expected path '$p' MISSING from archive $tmp — backup looks truncated/wrong, discarding"
            rm -f "$tmp"
            return 1
        fi
    done

    # Promote .partial -> final only after integrity + expected-paths pass.
    mv "$tmp" "$file"
    log "verify: OK — archive well-formed, all expected paths present ($(du -h "$file" | cut -f1))"

    # ── Manifest (metadata only — never secret material) ───────────────
    local file_count uncompressed_bytes archive_bytes sha
    file_count=$(find "$SRC_DIR" -type f 2>/dev/null | wc -l | tr -d ' ')
    uncompressed_bytes=$(du -sb "$SRC_DIR" 2>/dev/null | cut -f1)
    archive_bytes=$(stat -c %s "$file")
    sha=$(sha256sum "$file" | cut -d' ' -f1)
    {
        printf 'target=%s\n' "$BACKUP_TARGET"
        printf 'archive=%s\n' "$(basename "$file")"
        printf 'created_utc=%s\n' "$(date -u +%FT%TZ)"
        printf 'source=%s\n' "$SRC_DIR"
        printf 'file_count=%s\n' "$file_count"
        printf 'uncompressed_bytes=%s\n' "$uncompressed_bytes"
        printf 'archive_bytes=%s\n' "$archive_bytes"
        printf 'sha256=%s\n' "$sha"
        printf 'expected_paths=%s\n' "$EXPECTED_PATHS"
        printf 'verification=integrity+manifest (NOT restore-verified; see docs/dev-backup.md)\n'
        content_probe
    } > "$file.manifest"
    log "manifest: $file_count files, $uncompressed_bytes bytes uncompressed, sha256 $sha"

    # ── Retention ──────────────────────────────────────────────────────
    find "$BACKUP_DIR" -name "$BACKUP_TARGET-*.tar.gz" -mtime +"$RETENTION_DAYS" -delete
    find "$BACKUP_DIR" -name "$BACKUP_TARGET-*.tar.gz.partial" -mmin +120 -delete
    # Drop orphaned manifests whose archive was pruned.
    local m
    for m in "$BACKUP_DIR/$BACKUP_TARGET"-*.tar.gz.manifest; do
        [ -e "$m" ] || continue
        [ -e "${m%.manifest}" ] || rm -f "$m"
    done
    log "backup: retention pruned to ${RETENTION_DAYS}d ($(ls -1 "$BACKUP_DIR/$BACKUP_TARGET"-*.tar.gz 2>/dev/null | wc -l | tr -d ' ') archives kept)"
}

log "sidecar started (interval ${BACKUP_INTERVAL_HOURS}h, retention ${RETENTION_DAYS}d, src $SRC_DIR, dir $BACKUP_DIR)"
mkdir -p "$BACKUP_DIR"
while true; do
    age=$(newest_backup_age_hours)
    if [ "$age" -ge "$BACKUP_INTERVAL_HOURS" ]; then
        take_backup || log "ERROR backup cycle failed — will retry next tick"
    fi
    sleep 3600
done
