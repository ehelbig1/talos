# Talos operational drills

A backup you haven't restored is a hypothesis. The scripts in this
directory test that hypothesis on a schedule, so you find out the
backup is broken during a Monday-morning drill rather than during an
incident.

## Drills

### `backup-restore.sh` — end-to-end Postgres + Vault restore

What it does:

1. Selects the **newest backup artifacts** written by the
   `postgres-backup` / `vault-backup` compose sidecars, and checks the
   Vault archive against the `sha256` in its own manifest.
2. Builds the two verifier binaries — **before** anything holds real
   data, so the slow step is not the one with a database full of
   restored user rows sitting on a loopback port.
3. Spins up a scratch Postgres on a throwaway network, with throwaway
   credentials and a named (removable) volume, on an ephemeral
   loopback-only port.
4. `pg_restore --exit-on-error` into it.
5. Spins up a scratch Vault, restores the tarball into a fresh volume,
   unseals with the restored `bootstrap.json`, then checks that the
   root token is accepted and that secret engines are mounted.
6. Runs `verify_restore` (schema version, table counts, and decryption
   of **pre-existing** `actor_memory` + `secrets` rows sampled per
   on-disk format and per DEK) followed by `verify_phase_b` (a fresh
   write/read round-trip).
7. Removes every scratch container, volume and network — and asserts
   afterwards that none survived.
8. Emits the Prometheus textfile metric.

Exit code:
- `0` — restore works, verify passes, backups are actually restorable.
- `1` — any step failed; investigate before the next production
  incident. The alert at
  [`deploy/observability/alerts.yaml`](../../deploy/observability/alerts.yaml)
  will fire within 14 days of the last successful drill.

**Prefer the metric over the exit code.** macOS ships bash 3.2, where a
`set -u` violation inside a `cmd || die` list aborts the script and
still reports exit **0** — measured, not theorised. The script now
carries a completion sentinel that turns any such abort into a
non-zero exit *and* a failure metric, but the metric is the signal
that only ever advances on a run that reached the end, so that is what
`TalosBackupRestoreDrillFailed` reads and what
`make drill-schedule-status` reports.

**Runtime.** Steps 3–7 take about 20 seconds. Step 2 (building the
verifiers) dominates, and in a **git worktree** it currently rebuilds
`talos-mcp-handlers` on *every* invocation — ~16 minutes — because that
crate's `build.rs` declares `rerun-if-changed=../.git/HEAD` and
`../.git/index`, and in a worktree `.git` is a *file*, so neither path
resolves and cargo re-runs the script (which re-stamps `BUILD_TIME`)
every time. In a normal clone the build is a no-op after the first run.
That is a build-system issue, not a drill one, but budget for it when
scheduling.

#### Running manually

```bash
make drill                      # restore the newest ARTIFACT (default)
make drill ARGS="--source live" # dump the live stack now and restore that
```

`--source artifact` is the default on purpose. Until 2026-08-03 this
script only ever took a **fresh** `pg_dump` and restored that, which
tests `pg_dump`/`pg_restore` but leaves the dumps the sidecars have
been writing every night still un-restored — the backup nobody has
ever restored. `--source live` keeps that older behaviour for the case
where you want to prove the *current* database is dumpable.

Tunables (all env vars):

| Var | Default | What it does |
|---|---|---|
| `TALOS_DRILL_BACKUP_DIR` | `$TALOS_BACKUP_DIR` or `~/.talos/backups` | Where the sidecars write. `--source artifact` restores the newest file here. |
| `TALOS_DRILL_TEXTFILE_DIR` | `~/.talos/metrics/textfile_collector` | Where to write the drill metric. Must be a directory a collector reads. **Not writable ⇒ the drill fails**, unless `TALOS_DRILL_ALLOW_NO_METRIC=1`. |
| `TALOS_DRILL_LIVE_PG` | `talos-postgres` | Live Postgres container (`--source live` only). |
| `TALOS_DRILL_LIVE_VAULT` | `talos-vault` | Live Vault container (`--source live` only). |
| `TALOS_DRILL_LIVE_CONTROLLER` | `talos-controller` | Live controller — the KEK (`TALOS_MASTER_KEY`) and `KEK_PROVIDER` are read from it. |
| `TALOS_DRILL_PG_IMAGE` | digest-pinned pgvector:pg16 | Scratch Postgres image. |
| `TALOS_DRILL_VAULT_IMAGE` | digest-pinned hashicorp/vault:1.18 | Scratch Vault image. |
| `TALOS_DRILL_ALLOW_PRODUCTION` | unset | Required to run when a production environment is detected. Don't. |
| `TALOS_DRILL_ALLOW_NO_METRIC` | unset | Waive the "metric must be publishable" precondition. Accepts a permanently-firing alert. |

Flags:

- `--source artifact|live` — what to restore (default `artifact`).
- `--keep-scratch` — leave the scratch stack up after a *successful*
  run so you can `psql`/`vault` into it. It holds **real restored
  data**; the script prints the exact teardown commands.

#### Safety properties

These are the invariants, not aspirations — check them if you change
the script.

- **Scratch is isolated.** Its own bridge network (never
  `talos-network`), its own randomly generated Postgres password (never
  the live one), its own named volumes. The only host exposure is a
  kernel-assigned Postgres port bound to `127.0.0.1`, which exists
  because the verifiers are host-arch binaries and Docker Desktop
  cannot share a unix socket across the VM boundary. Vault publishes no
  port at all unless `KEK_PROVIDER=vault`.
- **Cleanup runs on every exit path** — success, failure, and
  `INT`/`TERM`/`HUP`, which are trapped explicitly rather than being
  left to the `EXIT` trap. `docker rm -fv` is used: without `-v` the
  Postgres image's *anonymous* data volume survives, and that volume is
  the restored database (421 MB of real user data leaked this way on
  the 2026-08-03 run, before it was fixed). Cleanup then re-inspects
  and shouts if anything survived.
- **It refuses to run against production.** `RUST_ENV`/`TALOS_ENV`/
  `NODE_ENV` in the shell, and `RUST_ENV`/`TALOS_ENV` inside the live
  controller, are all checked.
- **Nothing decrypted is ever printed.** The verifiers report counts
  and byte lengths only. Staged dumps live in a `mktemp -d` 0700
  directory that is removed on exit.

#### Scheduling

Weekly. `TalosBackupRestoreDrillFailed` fires when the last green run is
14 days old, so a weekly cadence gives exactly two missed runs of slack:
one skipped week (closed laptop, stack down) does not page, but the
alert still means something. **Do not stretch this to fortnightly** — a
cadence equal to the alert window guarantees the alert fires on ordinary
jitter, and an alert that fires during healthy operation is the failure
mode this whole area exists to remove.

**macOS / the docker-compose dev stack** — a launchd agent:

```bash
make drill-schedule         # install + load (Sunday 03:00 local)
make drill-schedule-status  # is it scheduled, and when did it last pass?
make drill-unschedule
```

`StartCalendarInterval` runs missed jobs once the machine wakes, which
is what makes a weekly cadence workable on a laptop — the same
wake-aware property the backup sidecars get from their hourly tick.
Installing it is a deliberate act (it writes to
`~/Library/LaunchAgents`), so it is a target rather than something
`make up` does behind your back.

A compose sidecar was considered and rejected: the drill creates and
destroys containers, so a containerised version needs
`/var/run/docker.sock`, and mounting the docker socket into a
long-lived `restart: unless-stopped` service to gain a weekly tick is
root-on-the-host in exchange for a cron entry.

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

**This unit will refuse to run on a production host** — the drill checks
`RUST_ENV`/`TALOS_ENV` in its own environment *and* inside the live
controller container, and exits 1 if either says `production`. That is
deliberate: the drill dumps the live database to a temp directory and
stands a second copy of it up on the same host, which is a rehearsal
you want on isolated infrastructure, not on the machine you are trying
to protect. `TALOS_DRILL_ALLOW_PRODUCTION=1` overrides it if you have
read the safety properties above and accept them.

**cron** (acceptable if you prefer):

```cron
0 3 * * 1 /opt/talos/scripts/drills/backup-restore.sh >> /var/log/talos/drill.log 2>&1
```

**Kubernetes CronJob** (for Phase 2): the script talks directly to the
docker daemon, which K8s pods can't do by default. Port it to
`kubectl exec` + in-cluster scratch Job patterns. Left as a follow-up
when Phase 2 onboards — file an RFC before reaching for it.

### Wiring the metric into Prometheus

`backup-restore.sh` writes `talos_backup_drill.prom` with three series:

- `talos_backup_drill_last_run_timestamp_seconds` — every run (success
  or failure).
- `talos_backup_drill_last_success_timestamp_seconds` — only green runs.
  Preserves previous value on failure so the alert compares to the
  last actually-green run, not the most recent failed run.
- `talos_backup_drill_last_status` — `1` on success, `0` on failure.

**Until 2026-08-03 there was no collector for any of them.** The script
wrote to `/var/lib/node_exporter/textfile_collector`, a path that
existed nowhere in this repo, and no `node_exporter` was deployed
anywhere — zero matches in `docker-compose.yml` or
`observability/prometheus/prometheus.yml`. It degraded *silently*
("textfile dir not writable — skipping metric emission"), so
`TalosBackupRestoreDrillFailed` was permanently red **by
construction**: a perfect drill run could not clear it. That is now
fixed for the dev stack, and the script fails loudly rather than
skipping when it cannot publish.

#### Which deployments can clear this alert

| Deployment | Can it clear? | How |
|---|---|---|
| `docker-compose` dev stack | **Yes** | `docker-compose.yml` runs `node-exporter` with `--collector.disable-defaults --collector.textfile`, mounting `~/.talos/metrics/textfile_collector` read-only; the `node-exporter` job in `observability/prometheus/prometheus.yml` scrapes it. `make drill` clears the alert. |
| VM / bare metal running the stack | **Yes** | Install a system `node_exporter` with `--collector.textfile.directory=/var/lib/node_exporter/textfile_collector`, set `TALOS_DRILL_TEXTFILE_DIR` to match, scrape it, and schedule the drill (systemd timer above). |
| `docker-compose.observability.yml` | **No** | That stack defines no `node-exporter` service (and cannot reach Talos at all — see its header). The job is red there, like `talos-controller`. |
| Kubernetes / the Helm chart | **No, not yet** | The drill drives the docker socket directly, which a pod does not have. Nothing publishes the series in-cluster, so the alert fires permanently. This is *accurate* — nobody has verified those backups — but it is not actionable in-cluster today. Either accept it as a standing "restore is unverified here" marker, or drop the rule from your `PrometheusRule` and track the gap elsewhere. Porting the drill to a CronJob (`kubectl exec` + an in-cluster scratch Job) is the open follow-up; file an RFC before reaching for it. |

The alert itself is in `deploy/helm/talos/files/alerts.yaml` (symlinked
as `deploy/observability/alerts.yaml`) and compares
`talos_backup_drill_last_success_timestamp_seconds` against
`time() - 14*86400`, with an `absent()` arm so a series that was never
published fires rather than silently matching nothing.

There is deliberately **no separate alert on the collector itself**.
The `absent()` arm already covers it: if node-exporter stops, its
scrape fails, the series disappears, and `TalosBackupRestoreDrillFailed`
fires an hour later. "The drill's result is not visible" and "the drill
has not run" are the same operational fact and want one alert, not two.

The transitions are unit-tested against the real expression in
`observability/alerts_chart_test.yml` (`promtool test rules`), because
`for: 1h` makes them impossible to demonstrate on a live stack inside a
review — and "the alert is clearable" is exactly the kind of claim this
repo has learned not to take on trust.

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
4. **Old artifacts.** `--source artifact` restores the **newest**
   dump, so a green run proves last night's backup is good. It does
   not prove a six-month-old one is. Occasionally point
   `--source artifact` at an archived directory instead.
5. **Everything in Postgres beyond the sampled rows.** `verify_restore`
   decrypts a sample per on-disk format and per DEK, not every row: it
   catches "this DEK/format is unreadable", not "row 4,821 is
   individually corrupt". Restore *completeness* is covered separately
   by `pg_restore --exit-on-error`, which fails the drill if any object
   failed to load.
6. **Transit-wrapped KEKs, when the deployment doesn't use them.** With
   `KEK_PROVIDER=env` (the dev-stack default) the KEK is
   `TALOS_MASTER_KEY` and the restored Vault is not on the decryption
   path at all. The Vault half still proves the file backend restores,
   unseals, authenticates and mounts its engines — but "the restored
   Vault can unwrap a DEK" is only proven when `KEK_PROVIDER=vault`, in
   which case the drill additionally checks the transit key is present.
   The drill prints which of these two it did.
7. **In-cluster backups.** The chart's CronJob + PVC path is untested by
   this script; see the deployment table above.

## Related

- Alerts that fire when the drill hasn't run: `deploy/observability/alerts.yaml` → `TalosBackupRestoreDrillFailed`.
- The verifiers the drill runs end-to-end:
  `controller/examples/verify_restore.rs` (reads what the backup
  contained) and `controller/examples/verify_phase_b.rs` (writes a
  fresh round-trip).
- The collector that carries the drill's metric: the `node-exporter`
  service in `docker-compose.yml` and the job of the same name in
  `observability/prometheus/prometheus.yml`.
- Memory on why this matters: `memory/vault_persistence_fix.md` —
  the 2026-04-24 incident that motivated the drill.
