# Talos operational drills

A backup you haven't restored is a hypothesis. The scripts in this
directory test that hypothesis on a schedule, so you find out the
backup is broken during a Monday-morning drill rather than during an
incident.

## Drills

### `backup-restore.sh` — end-to-end Postgres + Vault restore

What it does:

1. Dumps the live Postgres (`pg_dump --format=custom`).
2. Tars `/vault/file` from the live Vault container.
3. Spins up a scratch Postgres container on a non-colliding port.
4. Spins up a scratch Vault container with a fresh volume, restores
   the tarball, and unseals using the restored `bootstrap.json`.
5. Runs `cargo run --example verify_phase_b -p controller` against
   the restored pair — the same verifier we use in development to
   confirm Phase B encryption works end-to-end.
6. Emits Prometheus textfile metrics for the
   `TalosBackupRestoreDrillFailed` alert.
7. Cleans up the scratch containers (unless `--keep-scratch`).

Exit code:
- `0` — restore works, verify passes, backups are actually restorable.
- `1` — any step failed; investigate before the next production
  incident. The alert at
  [`deploy/observability/alerts.yaml`](../../deploy/observability/alerts.yaml)
  will fire within 14 days of the last successful drill.

#### Running manually

```bash
./scripts/drills/backup-restore.sh
```

Tunables (all env vars):

| Var | Default | What it does |
|---|---|---|
| `TALOS_DRILL_WORKDIR` | `/tmp/drill-<ts>` | Where to stage the dump + tarball. Auto-cleaned on success. |
| `TALOS_DRILL_PG_PORT` | `55432` | Host port for scratch Postgres. |
| `TALOS_DRILL_VAULT_PORT` | `58200` | Host port for scratch Vault. |
| `TALOS_DRILL_LIVE_PG` | `talos-postgres` | Name of the live Postgres container. |
| `TALOS_DRILL_LIVE_VAULT` | `talos-vault` | Name of the live Vault container. |
| `TALOS_DRILL_LIVE_CONTROLLER` | `talos-controller` | Name of the live controller container (used to resolve `TALOS_MASTER_KEY`). |
| `TALOS_DRILL_PG_IMAGE` | digest-pinned pgvector:pg16 | Scratch Postgres image. |
| `TALOS_DRILL_VAULT_IMAGE` | digest-pinned hashicorp/vault:1.18 | Scratch Vault image. |
| `TALOS_DRILL_TEXTFILE_DIR` | `/var/lib/node_exporter/textfile_collector` | Where to write drill metrics. Absent dir = metric emission skipped with warning. |

Flags:

- `--keep-scratch` — leave scratch containers running after success so
  you can `psql`/`vault` into them manually. Useful when you want to
  explore restored data.

#### Scheduling

Weekly at 3am Monday local time is a reasonable cadence — quiet enough
to avoid competing with business-hours traffic, frequent enough that
`TalosBackupRestoreDrillFailed` (triggered at 14 days since last green
run) gives two missed-run cycles before paging.

**systemd timer** (preferred for single-node k3s Phase 1):

```ini
# /etc/systemd/system/talos-drill.service
[Unit]
Description=Talos backup-restore drill
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
User=root
WorkingDirectory=/opt/talos
ExecStart=/opt/talos/scripts/drills/backup-restore.sh
Environment=TALOS_DRILL_TEXTFILE_DIR=/var/lib/node_exporter/textfile_collector
```

```ini
# /etc/systemd/system/talos-drill.timer
[Unit]
Description=Weekly Talos backup-restore drill

[Timer]
OnCalendar=Mon 03:00
Persistent=true
RandomizedDelaySec=15min

[Install]
WantedBy=timers.target
```

```bash
systemctl enable --now talos-drill.timer
systemctl list-timers talos-drill.timer
journalctl -u talos-drill.service --since "last week"
```

**cron** (acceptable if you prefer):

```cron
0 3 * * 1 /opt/talos/scripts/drills/backup-restore.sh >> /var/log/talos/drill.log 2>&1
```

**Kubernetes CronJob** (for Phase 2): the script talks directly to the
docker daemon, which K8s pods can't do by default. Port it to
`kubectl exec` + in-cluster scratch Job patterns. Left as a follow-up
when Phase 2 onboards — file an RFC before reaching for it.

### Wiring the Prometheus textfile metric

`backup-restore.sh` writes `talos_backup_drill.prom` with three series:

- `talos_backup_drill_last_run_timestamp_seconds` — every run (success
  or failure).
- `talos_backup_drill_last_success_timestamp_seconds` — only green runs.
  Preserves previous value on failure so the alert compares to the
  last actually-green run, not the most recent failed run.
- `talos_backup_drill_last_status` — `1` on success, `0` on failure.

To scrape:

1. Run `node_exporter` on the drill host with
   `--collector.textfile.directory=/var/lib/node_exporter/textfile_collector`.
2. Scrape node_exporter's `/metrics` from Prometheus.
3. The alert in `deploy/observability/alerts.yaml`
   (`TalosBackupRestoreDrillFailed`) compares
   `talos_backup_drill_last_success_timestamp_seconds` against
   `time() - 14*86400`.

If you don't have node_exporter yet, that's the quickest Grafana-Cloud-
compatible exporter to add — it also gives you host metrics (disk,
network, load average) you'll want soon anyway.

## What this drill doesn't cover

Honest list so future-you doesn't develop false confidence:

1. **Neo4j graph data.** The drill tests Postgres + Vault. If your
   actor memory is used primarily for graph-RAG, add a `neo4j-admin
   database dump` + restore step.
2. **MinIO object storage.** Audit logs and artifacts live there.
   Not in scope today because the blast radius of a MinIO loss is
   smaller than DEK loss — but worth adding.
3. **Cross-region failover.** We test that a backup taken from live
   data is restorable *on the same host*. We don't test that data
   survives a host loss. For Phase 2 enterprise SaaS, run the drill
   against a separately-hosted scratch environment.
4. **The backup's own integrity over time.** A freshly-taken backup
   restored five minutes later doesn't prove a 6-month-old backup
   still works. Rotate drill artifacts: occasionally restore from a
   month-old pg_dump + Vault tarball from the archive, not the
   live dump.

## Related

- Alerts that fire when the drill hasn't run: `deploy/observability/alerts.yaml` → `TalosBackupRestoreDrillFailed`.
- The verifier the drill runs end-to-end:
  `controller/examples/verify_phase_b.rs`.
- Memory on why this matters: `memory/vault_persistence_fix.md` —
  the 2026-04-24 incident that motivated the drill.
