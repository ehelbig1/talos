# Dev-stack backups (full-stack)

The local dev stack keeps the only copy of data that is **not reproducible
from git**. Three compose sidecars back up the three stateful stores to the
**host** filesystem (a bind mount, not a docker volume — so it survives
`docker volume rm`, `make clean`, and `compose down -v`, and rides Time
Machine / host backups off-box for free).

All three land under one host dir — `${TALOS_BACKUP_DIR:-~/.talos/backups}` —
in per-target subdirs:

```
~/.talos/backups/
├── talos-<stamp>.dump              # Postgres (root, for back-compat)
├── vault/
│   ├── vault-<stamp>.tar.gz
│   └── vault-<stamp>.tar.gz.manifest
└── neo4j/
    ├── neo4j-<stamp>.tar.gz
    └── neo4j-<stamp>.tar.gz.manifest
```

Shared behavior across all three (see `scripts/dev-backup/dev-backup-loop.sh` and
`scripts/dev-backup/dev-volume-backup-loop.sh`): **wake-aware cadence** (each hourly
tick backs up only when the newest artifact is older than
`BACKUP_INTERVAL_HOURS`, default 24 — a laptop opened after a week backs up
immediately instead of missing a fixed nightly hour), **`.partial`
atomicity** (a half-written artifact is never promoted to a real name),
**loud `ERROR` logs** on failure (visible in `docker logs`), and
**retention pruning** (`BACKUP_RETENTION_DAYS`, default 14).

## What's backed up, and how hard

| Target | Why it matters | Method | Verification |
|---|---|---|---|
| **Postgres** | Human corrections + ML gold slice + ops-alert history + actor memory. Code re-clones; labels don't. | `pg_dump --format=custom` | **Restore-verified**: `pg_restore` into a scratch DB + a corrections-count probe before the dump counts. |
| **Vault** | Per-org DEKs + every OAuth token. Losing it makes **all** encrypted rows permanently unreadable — the single worst failure mode. **No reconstruct path.** | Opaque `tar` of the `/vault/file` volume, read-only mount, read-stability retry. | **Integrity + manifest** (see below). NOT restore-verified. |
| **Neo4j** | Graph-RAG entity data. Partly reconstructible via `graph_backfill` — but measured 2026-08-26, **6 of 16 `(actor_id, source_key)` pairs (191 nodes, 14.9 %) have no surviving `actor_memory` row to rebuild from**, so treat it as real data. | Opaque `tar` of the `/data` volume, read-only mount, read-stability retry. | **Integrity + manifest + live count** per cycle, **and restore-verified by `scripts/drills/backup-restore.sh`** as of 2026-08-26 (scratch container, counts vs the manifest). |
| **Redis** | — | **Not backed up.** Cache-only (embedding LRU, OCI/semantic cache, rate-limit buckets, LLM-key cache) — regenerated on demand or mirrors Postgres. | n/a |

### Why the volume-tar approach for Vault and Neo4j

Neither store has a safe *live logical dump*:

- **Vault file backend** has no consistent-snapshot API (that's a raft-storage
  feature). The supported copy path — used by prod too, see
  `deploy/k3s/README.md` — is a filesystem copy of `/vault/file`.
- **Neo4j Community 5.x** `neo4j-admin database dump` requires the DB to be
  **stopped**; online backup is Enterprise-only. We will not stop the live
  graph on a schedule.

So both do an **opaque tar** of the read-only-mounted volume. "Opaque" is a
security property: the sidecar never extracts or inspects archive members,
so **no secret material is ever read or logged**. The Vault volume is mounted
**read-only** and the sidecar holds **no Vault token / unseal key** — a
volume-level copy needs none, and the worst case is a torn opaque tar.

### Copy-while-live consistency: read-stability retry

A tar of a live store can tear. Since we can't quiesce the service, the
sidecar hashes a listing of the source tree (path + size + mtime) **before**
and **after** the tar; if the signature changed, the tree moved under us, so
it discards and retries (up to `STABILITY_RETRIES`, default 4). This
**shrinks — does not eliminate — the tear window**. For Neo4j the residual
tear risk is backstopped by `graph_backfill`; for Vault the risk is low
(the file backend writes are small and infrequent) and a fresh backup is
taken on the next tick.

### Verification levels — read this honestly

- **Postgres is the only target that is truly restore-verified.** Every dump
  is `pg_restore`d into a scratch DB and probed before it counts.
- **Vault and Neo4j get integrity verification per CYCLE, not restore
  verification.** (Neo4j is separately restore-verified by the weekly drill —
  see below.) Each cycle checks the archive is well-formed and fully readable
  (`tar -tzf`), that all expected top-level paths are present (`./core
  ./sys ./logical` for Vault; `./databases ./transactions` for Neo4j), and
  writes a `*.manifest` next to the archive (file count, uncompressed bytes,
  archive bytes, **sha256 of the archive**). Neo4j additionally records a
  live `cypher-shell` node/relationship count as a liveness/sanity datum.

  Why not a real restore-verify *in the sidecar*? Vault would need the unseal
  key + a throwaway Vault and would defeat the "never touch secret material"
  rule. Neo4j Community hosts exactly one database (+ `system`) and cannot
  create a scratch DB to restore into — but it *can* be restored into a
  throwaway CONTAINER, which is what the drill does rather than the sidecar.

- **`scripts/drills/backup-restore.sh` restore-verifies all three** as of
  2026-08-26 (`--source artifact`). For Neo4j it extracts the newest archive
  into a scratch volume, starts a digest-pinned `neo4j:5.26-community` on it,
  waits for the `neo4j` database to reach `online` (transaction recovery),
  and compares the restored node/relationship counts to this manifest's
  `neo4j_nodes=` / `neo4j_relationships=` — the first reader those numbers
  have ever had. It publishes
  `talos_backup_drill_kind_verified{source,kind}` so a green drill says which
  kinds it covered. `--source b2` still fetches Postgres + Vault only.

## Restore procedures

### Postgres

```bash
# Into a fresh scratch DB (adjust host/port to your stack):
createdb -h 127.0.0.1 -p 5433 -U talos talos_restore
pg_restore -h 127.0.0.1 -p 5433 -U talos -d talos_restore --no-owner \
    ~/.talos/backups/talos-<stamp>.dump
```

### Vault (the DEK-usability drill — do this once for real)

```bash
# 1. Verify the archive first (never restore an unverified tar):
sha256sum -c <<<"$(grep sha256 ~/.talos/backups/vault/vault-<stamp>.tar.gz.manifest \
    | cut -d= -f2)  ~/.talos/backups/vault/vault-<stamp>.tar.gz"
tar -tzf ~/.talos/backups/vault/vault-<stamp>.tar.gz >/dev/null && echo "archive OK"

# 2. Stop the stack and wipe the Vault volume:
docker compose down
docker volume rm talos_vault_data

# 3. Recreate the volume and restore the file backend into it:
docker volume create talos_vault_data
docker run --rm -v talos_vault_data:/vault/file \
    -v ~/.talos/backups/vault:/restore:ro \
    --entrypoint /bin/sh hashicorp/vault:1.18 -c \
    'tar -xzf /restore/vault-<stamp>.tar.gz -C /vault/file'

# 4. Bring the stack up. vault-init unseals from the restored bootstrap.json,
#    and the controller decrypts a DEK on boot:
docker compose up -d
curl -fsS http://localhost:8080/health   # green ⇒ DEKs are usable ⇒ restore proven
```

The final `/health` (controller boots, resolves the KEK from Vault, decrypts
a DEK) is what actually proves the Vault backup is good — the per-cycle
integrity check only proves the archive is well-formed.

### Neo4j

`make drill` already exercises this path weekly against a throwaway
container, so the procedure below is the one you run to restore the LIVE
graph, not the one that proves the archive works.

Graph data is *partly* reconstructible via `graph_backfill` — but ~15 % of
the current graph has no `actor_memory` row left to rebuild from, so
restoring the tar is usually the right move rather than the fallback:

```bash
docker compose stop neo4j
docker volume rm talos_neo4j_data && docker volume create talos_neo4j_data
docker run --rm -v talos_neo4j_data:/data \
    -v ~/.talos/backups/neo4j:/restore:ro \
    --entrypoint /bin/sh neo4j:5.26-community -c \
    'tar -xzf /restore/neo4j-<stamp>.tar.gz -C /data'
docker compose up -d neo4j
# Sanity: the live count should roughly match the manifest's neo4j_nodes.
```

Restore across a different Neo4j minor version is not guaranteed (store
format can change); if it fails, restore an empty volume and re-run
`graph_backfill`. **Use the digest, not the bare tag** — measured on the dev
host 2026-08-26, `neo4j:5.26-community` had already drifted to a different
image than the running container, and the store is a raw copy, so the tag
alone does not give you the server that wrote it. The drill pins the digest
for exactly this reason (`TALOS_DRILL_NEO4J_IMAGE`).

## Tuning

All knobs are compose env with sensible defaults:

- `TALOS_BACKUP_DIR` — host backup dir (default `~/.talos/backups`).
- `BACKUP_INTERVAL_HOURS` — cadence (default 24).
- `BACKUP_RETENTION_DAYS` — retention (default 14).

Watch a sidecar: `docker logs -f talos-vault-backup` /
`docker logs -f talos-neo4j-backup` / `docker logs -f talos-postgres-backup`.
