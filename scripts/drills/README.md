# Talos operational drills

A backup you haven't restored is a hypothesis. The scripts in this
directory test that hypothesis on a schedule, so you find out the
backup is broken during a Monday-morning drill rather than during an
incident.

## Drills

### `backup-restore.sh` — end-to-end Postgres + Vault restore

What it does:

0b. Obtains the KEK from **escrow** — never from the live stack — under a
   bounded timeout, refusing the shapes that would re-create the deleted
   live-container read. Before the verifier build, so a missing escrow
   fails in seconds rather than after a six-minute compile.
1. Selects the **newest backup artifacts** written by the
   `postgres-backup` / `vault-backup` compose sidecars, checks the
   Vault archive against the `sha256` in its own manifest, and **asserts
   both artifacts are younger than
   `TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS`** (default 168 h) so a dead
   backup sidecar fails the drill instead of leaving it green on the
   last good file.
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
6. Runs `verify_restore` (schema version, table row counts, and
   decryption of **pre-existing** `actor_memory` + `secrets` rows)
   followed by `verify_phase_b` (a fresh write/read round-trip).
   Sampling is per distinct `(format, DEK)` on **both** tables —
   `(value_format, value_key_id)` for `actor_memory` and
   `(encryption_format_version, encryption_key_id)` for `secrets` — so
   every on-disk AEAD format and every DEK actually in use is exercised
   at least once. (`secrets` grouped by format *alone* until review:
   with per-ORG v4 DEKs that touched whichever org sorted first and a
   second org's secrets-only DEK went unexercised.) **Expired rows are
   excluded from both samples**, because `recall_exact` and
   `get_secret` refuse them by design — sampling them made an intact
   backup report "a sampled row vanished on read" / "DECRYPT FAILED".
   Row counts are **reported, not compared** against any baseline; only
   `encryption_keys` and `actors` are asserted non-empty. The schema
   check requires the restored `_sqlx_migrations` max version to be a
   migration point this checkout ships — *not* equality with the newest,
   which false-red on every good artifact taken before the last
   migration landed.
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
still reports exit **0** — measured, not theorised. **The exit-0 half
needs an `EXIT` trap installed**, which this script always has: without
one the same violation exits **1**, so an isolated reproduction that
omits the trap will "disprove" the bug. Measured both ways on bash
3.2.57 (arm64-apple-darwin25): no trap → `$?` is 1; `trap … EXIT`
installed → the trap sees `$?` as 0 and the shell exits 0. The script now
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
# The KEK comes from ESCROW. Pick one:
TALOS_DRILL_ESCROW_KEY_CMD='op read "op://Private/Talos KEK/password"' make drill
TALOS_DRILL_ESCROW_KEY_FILE=/Volumes/escrow/talos-master.key       make drill
make drill                      # no escrow var set → hidden prompt (TTY only)

make drill ARGS="--source live" # dump the live stack now and restore that

# TIER 2 — the strictly harder question. Fetch from object storage,
# age-decrypt with the ESCROWED passphrase, restore that. Needs BOTH
# escrowed secrets: the KEK (above) and the age passphrase.
TALOS_DRILL_ESCROW_KEY_CMD='op read "op://Private/Talos KEK/password"' \
TALOS_OFFHOST_AGE_PASSPHRASE_CMD='op read "op://Private/Talos age backup/password"' \
  make drill ARGS="--source b2"
```

**There is no way to run this drill from the live stack's key.** That was
the shape until 2026-08-13 and it made the drill unable to fail for the
reason it exists — see "What this drill doesn't cover" item 8. With no
escrow source the drill dies before it stages anything, and the message
names what to create. If you cannot produce the key from an off-box
source, *that is the drill result*: the artifacts are currently
unreadable after a host loss.

`--source artifact` is the default on purpose. Until 2026-08-03 this
script only ever took a **fresh** `pg_dump` and restored that, which
tests `pg_dump`/`pg_restore` but leaves the dumps the sidecars have
been writing every night still un-restored — the backup nobody has
ever restored. `--source live` keeps that older behaviour for the case
where you want to prove the *current* database is dumpable.

`--source b2` is the mode that tests the copy which survives losing the
disk. The other two read from the very filesystem the backups insure
against, so however green they are they cannot answer "is there an
off-host copy, and is it readable?". It fetches, `age`-decrypts, asserts
the object's age, and restores — and it **fails rather than falling back**
when the bucket is unreachable, empty, stale, or the passphrase is wrong.
Setting up the destination is `docs/offhost-backup.md`; until that is
done this mode fails, which is the accurate answer.

Tunables (all env vars):

| Var | Default | What it does |
|---|---|---|
| `TALOS_DRILL_BACKUP_DIR` | `$TALOS_BACKUP_DIR` or `~/.talos/backups` | Where the sidecars write. `--source artifact` restores the newest file here. |
| `TALOS_DRILL_TEXTFILE_DIR` | `~/.talos/metrics/textfile_collector` | Where to write the drill metric. Must be a directory a collector reads. **Not writable ⇒ the drill fails**, unless `TALOS_DRILL_ALLOW_NO_METRIC=1`. |
| `TALOS_DRILL_LIVE_PG` | `talos-postgres` | Live Postgres container (`--source live` only). |
| `TALOS_DRILL_LIVE_VAULT` | `talos-vault` | Live Vault container (`--source live` only). |
| `TALOS_DRILL_LIVE_CONTROLLER` | `talos-controller` | Live controller. Used **only** for the production-environment guard. The KEK is no longer read from it — see below. |
| `TALOS_DRILL_ESCROW_KEY_CMD` | unset | Command whose stdout is the escrowed `TALOS_MASTER_KEY`. Preferred: the key never lands on disk (it is captured through a pipe, never spooled to a file). Its stderr really does stay attached — it carried a `2>/dev/null` until 2026-08-13, which contradicted the line above it and swallowed both a password-manager prompt and a failing helper's diagnostic. Refused if it names `docker exec`/`docker inspect`/`printenv TALOS_MASTER_KEY`, or if a path-shaped argument resolves inside a checkout or `$BACKUP_DIR`. Setting this **and** `_FILE` is refused. |
| `TALOS_DRILL_ESCROW_KEY_FILE` | unset | File whose first line is the escrowed `TALOS_MASTER_KEY`. **Refused if it resolves inside a checkout (this one *or* the main clone when you are in a worktree) or inside `$TALOS_DRILL_BACKUP_DIR`** — a key stored beside the ciphertext it unlocks is not encryption. Symlinks are resolved before the check; hard links are not, and cannot be. Setting this **and** `_CMD` is refused rather than resolved by precedence. |
| `TALOS_DRILL_ESCROW_TIMEOUT_SECS` | `120` | Wall-clock bound on `_CMD`. On expiry the whole process tree is killed and the drill fails naming this knob. Without it a helper that prompts (Touch ID) hangs forever under launchd, which also stops launchd starting the *next* weekly run — the drill silently stops running with only the 14-day alert as signal. |
| `TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS` | `168` | Maximum age of the newest Postgres dump **and** the newest Vault archive. Older ⇒ the drill fails. Without this the age was computed, printed, and never compared, so a sidecar that died left the drill green for as long as its last artifact survived retention. `0` disables (use only to drill an archived artifact deliberately). Default is deliberately loose: the sidecars tick only while the laptop is awake, and a real two-day gap exists in the artifact history. |
| `TALOS_DRILL_KEK_PROVIDER` | `env` | Which provider wrapped the DEKs. Was read from the live container; now stated, because in a real recovery there is no live container. Matches `docker-compose.yml`'s `KEK_PROVIDER` default. Being wrong fails loudly at the first decrypt. |
| `TALOS_DRILL_ALLOW_NO_CIPHERTEXT` | unset | Read by `verify_restore`, not the script. Waives the "something, anywhere, must have decrypted" floor. Only correct for a genuinely fresh deployment, and it means the run certifies nothing about readability. |
| `TALOS_DRILL_PG_IMAGE` | digest-pinned pgvector:pg16 | Scratch Postgres image. **Must be ≥ the major version the dump came from.** The compose stack is pg16 so the default matches; the Helm chart deploys `pgvector/pgvector:pg17`, and a pg17 dump will not restore into pg16. On a pg17 deployment set this to a pg17 image. The failure is loud (`pg_restore` aborts under `--exit-on-error`), not silent. |
| `TALOS_DRILL_VAULT_IMAGE` | digest-pinned hashicorp/vault:1.18 | Scratch Vault image. |
| `TALOS_DRILL_ALLOW_PRODUCTION` | unset | Required to run when a production environment is detected. Don't. |
| `TALOS_DRILL_ALLOW_NO_METRIC` | unset | Waive the "metric must be publishable" precondition. Accepts a permanently-firing alert. |
| `TALOS_OFFHOST_AGE_PASSPHRASE_CMD` | unset | **`--source b2` only.** Command whose stdout is the escrowed `age` passphrase. Same containment as the KEK's `_CMD`: a path-shaped argument resolving inside a checkout or `$BACKUP_DIR` is refused, and setting this **and** `_FILE` is refused rather than resolved by precedence. Bounded by `TALOS_OFFHOST_ESCROW_TIMEOUT_SECS` (default 120), whose expiry kills the whole process group. |
| `TALOS_OFFHOST_AGE_PASSPHRASE_FILE` | unset | **`--source b2` only.** File whose first line is the escrowed `age` passphrase. Refused if it resolves inside a checkout (this one *or* the main clone from a worktree) or inside `$BACKUP_DIR`. Symlinks resolved first; hard links are not, and cannot be. |
| `TALOS_OFFHOST_B2_BUCKET` / `_ENDPOINT` / `_REGION` | unset | **`--source b2` only.** The destination. All three or none — a bucket with no endpoint would silently address real AWS S3. |
| `TALOS_OFFHOST_BIN` | unset | Path to a prebuilt `talos-offhost-backup`. Skips the `cargo build` in step 1. |

Flags:

- `--source artifact|b2|live` — what to restore (default `artifact`).
  `b2` reads the off-host copy; see `docs/offhost-backup.md`.
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
- **Cleanup runs on every exit path a shell can observe** — success,
  failure, and `INT`/`TERM`/`HUP`, which are trapped explicitly rather
  than being left to the `EXIT` trap. `docker rm -fv` is used: without
  `-v` the Postgres image's *anonymous* data volume survives, and that
  volume is the restored database (421 MB of real user data leaked this
  way on the 2026-08-03 run, before it was fixed). Cleanup then
  re-inspects and shouts if anything survived.
- **…but "every exit path" is not a property any trap has.** Stated
  rather than left implied, because that phrasing is how a limit becomes
  a false assurance:
  - **`SIGKILL`, an OOM kill, and a host crash / power loss are
    untrappable.** A drill killed with `kill -9` leaves its scratch
    containers, volumes and network behind — holding restored user data.
    There is no in-process fix. Recovery:
    `docker rm -fv $(docker ps -aq --filter name=talos-drill-)` then
    `docker volume rm $(docker volume ls -q --filter name=talos-drill-)`.
  - **A trapped signal arriving during a long foreground step is
    deferred** until that step returns — bash's own semantics. `Ctrl-C`
    during the multi-minute step 2 build does not tear down immediately;
    it tears down when `cargo` exits.
  - **The `INT` trap is inert if the drill is started as a BACKGROUND
    job from a non-interactive shell** (`… backup-restore.sh &`,
    `nohup … &`, a CI step that backgrounds it). POSIX has the shell set
    `SIGINT`/`SIGQUIT` to *ignored* in an asynchronous child, and a
    signal ignored on entry **cannot be trapped** — so `trap 'on_signal
    INT' INT` silently does nothing and the drill runs straight through
    a `kill -INT`. Measured both ways: backgrounded → the trap never
    fires; started with a default `SIGINT` disposition (which is what a
    terminal `Ctrl-C` and launchd both give it) → it fires, tears down,
    and re-raises so the exit status is still "killed by signal 2".
    `TERM` and `HUP` are unaffected in either case, so **send `TERM`,
    not `INT`, to a backgrounded drill.**
  - **`--keep-scratch` leaves a full restored database up on purpose.**
    That is the flag's job, but the containers hold real user data until
    you remove them by hand, using the command the script prints.
- **It refuses to run against production.** `RUST_ENV`/`TALOS_ENV`/
  `NODE_ENV` in the shell, and `RUST_ENV`/`TALOS_ENV` inside the live
  controller, are all checked.
- **Nothing decrypted is ever printed.** The verifiers report counts
  and byte lengths only. Staged dumps live in a `mktemp -d` 0700
  directory that is removed on exit.
- **The master key never leaves process memory.** It is read from the
  escrow source into a shell variable and exported only into the
  verifier child's environment. It is never echoed (the interactive
  prompt uses `read -rs`), never written to a file, never passed as a
  command-line argument (which would put it in `ps`), and never reaches
  the scratch database. The drill prints its LENGTH, so a truncated or
  empty escrow read is diagnosable without exposing the value.
  - A caller's pre-existing `TALOS_MASTER_KEY` is **`unset`**, not
    assigned `""`. Assignment does not remove the export attribute —
    `export FOO=live; FOO=""; FOO=escrow` leaves `FOO` **exported** with
    the new value (measured). The `""` form therefore put the *escrowed*
    key into the environment of every child on exactly the
    `source .env && make drill` path this rule exists for, including the
    multi-minute `cargo build` in step 2. `TALOS_MASTER_KEY_FILE` is
    unset alongside it: it was inert only because `read_env_or_file`
    happens to prefer a non-empty env var, i.e. by another crate's
    precedence rather than by anything the drill does.
- **The drill certifies a real decrypt, not an exit code.** Before
  2026-08-13 `verify_restore`'s memory arm counted `Ok(Some(_))` and
  nothing more. It now inspects the plaintext and fails when a family had
  rows eligible for decryption and read none of them back.
  - The *reason* first given for tightening it was wrong and is worth
    not repeating: it said a row with no ciphertext decodes to JSON
    `null`, so `null` had to be rejected. In the restored schema
    `actor_memory.value_enc` and `value_key_id` are `NOT NULL` and the
    legacy plaintext `value` column is dropped, so **no real row can
    reach that path** — a successful decrypt is itself the readability
    proof. The tightening was right; the justification was not, and
    acting on it made `null`/`[]`/`{}` fatal, which would have red-ed an
    intact backup carrying an ordinary "nothing today" payload.

#### Scheduling

Weekly. `TalosBackupRestoreDrillFailed` fires when the last green run is
14 days old, so a weekly cadence tolerates exactly **one** missed run:
one skipped week (closed laptop, stack down) does not page, the second
consecutive miss does. Note the margin on that single miss is thin — the
14-day threshold lands on the recovery run's own scheduled time, and only
the alert's `for: 1h` absorbs the gap, so a run deferred more than an
hour past its slot (a laptop woken late) pages anyway. **Do not stretch
this to fortnightly** — a
cadence equal to the alert window guarantees the alert fires on ordinary
jitter, and an alert that fires during healthy operation is the failure
mode this whole area exists to remove.

**An unattended drill needs an unattended escrow source.** Since the KEK
comes from escrow and only from escrow, a scheduled run has no TTY for the
hidden prompt, so `TALOS_DRILL_ESCROW_KEY_CMD` (or `_FILE`) must be in the
job's own environment. `make drill-schedule` propagates whichever is set in
*your* shell at install time into the plist — the **command or the path,
never the key**: a plist is `chmod 600` but it is still a plaintext file on
the same disk as the ciphertext, which is the arrangement the escrow rule
exists to prevent.

The command must be genuinely non-interactive at 03:00 on a Sunday. `op
read` with a service-account token qualifies; `op read` that raises a
Touch ID prompt does not. Installing with no escrow source at all is
allowed and the installer says so loudly — the resulting permanently-red
`TalosBackupRestoreDrillFailed` is *true* (you cannot presently prove
recoverability unattended), but a permanently-red alert trains you to
ignore red. Wire the escrow or unschedule; do not leave it half-way.

**macOS / the docker-compose dev stack** — a launchd agent:

```bash
# Propagates TALOS_DRILL_ESCROW_KEY_CMD / _FILE into the plist if set.
TALOS_DRILL_ESCROW_KEY_CMD='op read "op://Private/Talos KEK/password"' \
  make drill-schedule       # install + load (Sunday 03:00 local)
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
# The escrowed KEK. A COMMAND, never the key itself — a unit file under
# /etc/systemd/system is world-readable by default and sits on the same host
# as the artifacts. Point it at whatever your secret manager exposes.
Environment=TALOS_DRILL_ESCROW_KEY_CMD=/opt/talos/bin/fetch-escrowed-kek
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

1. **Neo4j graph data.** The drill tests Postgres + Vault only. This is
   not a hypothetical gap: the `neo4j-backup` compose sidecar has been
   writing `~/.talos/backups/neo4j/neo4j-*.tar.gz` daily since July, and
   those artifacts get tar-integrity + expected-paths verification and
   nothing else — they are, today, exactly the "backup nobody has ever
   restored" that this drill was rewritten to eliminate for Postgres and
   Vault. Community Edition can't host a scratch database, so a restore
   drill means standing up a throwaway Neo4j on the tarball and counting
   nodes/relationships against the manifest. Mitigating factor, not an
   excuse: the graph is reconstructible from `actor_memory` via
   `graph_backfill`.
2. **MinIO object storage.** Audit logs and artifacts live there.
   Not in scope today because the blast radius of a MinIO loss is
   smaller than DEK loss — but worth adding.
3. **Cross-region failover.** We test that a backup taken from live
   data is restorable *on the same host*. We don't test that data
   survives a host loss. For Phase 2 enterprise SaaS, run the drill
   against a separately-hosted scratch environment.
4. **Artifact freshness — one direction now closed, one still open.**
   `--source artifact` restores the **newest** dump, so a green run
   proves last night's backup is good and says nothing about a
   six-month-old one; point `--source artifact` at an archived
   directory occasionally. That direction is still uncovered.
   The other one — the dangerous one — is closed as of 2026-08-13.
   The drill used to *print* the artifact's mtime and never compare it,
   so if the `postgres-backup` sidecar died the drill kept restoring the
   last good artifact and kept going green for as long as that file
   survived retention: a value computed, displayed and never asserted,
   which is the same shape as the defect the drill itself exists to
   catch, one level up. Both artifacts are now age-gated by
   `TALOS_DRILL_MAX_ARTIFACT_AGE_HOURS` (default 168 h) and an over-age
   artifact **fails** the run. `TalosBackupRestoreDrillFailed` still
   measures drill recency, not artifact recency — the age gate is what
   converts a stale artifact into a failed drill, which the alert then
   sees.

   **Still unclosed, and worth knowing:** the newest dump and the newest
   Vault archive are selected **independently**, so nothing makes them a
   matched pair. If only one sidecar dies, a fresh dump can be restored
   beside a Vault backend from days earlier; a DEK created after the
   older of the two was taken would simply be missing. The age gate
   bounds how far apart they can drift, it does not make them
   consistent. Pairing them properly needs the sidecars to write a joint
   manifest.
5. **Everything in Postgres beyond the sampled rows, and every encrypted
   column family other than three.** `verify_restore` decrypts a sample,
   not every row: it catches "this DEK/format is unreadable", not "row
   4,821 is individually corrupt". It touches `actor_memory`, `secrets`
   and `ml_examples` — `workflow_executions` output, module payloads,
   TOTP secrets, webhook secrets and `integration_state` all carry their
   own `*_format` / `*_key_id` columns and are never decrypt-verified, so
   a format or DEK used *only* by one of those is unexercised. Restore
   *completeness* (as opposed to readability) is covered separately by
   `pg_restore --exit-on-error`, which fails the drill if any object
   failed to load.

   Since 2026-08-13 the verifier fails when a family had eligible rows
   and read none of them back, or when nothing anywhere decrypted, and it
   inspects the decrypted PLAINTEXT rather than only "a row came back".
   Where the plaintext is *trivial* (JSON `null`, `""`, `[]`, `{}`) the
   line is drawn per family, by what the writer makes meaningful:
   for `actor_memory` it is **reported, not failed** — `__memory_write__`
   defaults `value` to JSON `null` and `[]` is a legitimate "nothing
   today" payload, so failing on one would red an intact backup — while
   for `secrets` and `ml_examples` an empty plaintext **is** a failure,
   because nothing writes an empty OAuth token or a contentless training
   datum. A decrypt that errors, or a row that vanishes on read, is fatal
   everywhere.

   The stated hole in the anti-vacuity rule: a family with **zero**
   eligible rows is skipped, not failed — and that applies to **every**
   family, `secrets` and `actor_memory` exactly as much as `ml_examples`,
   not just the ML one this used to name. Making it fatal would false-red
   every deployment that legitimately has no ML datasets. So a restore
   that silently moved no rows for a family is caught by
   `pg_restore --exit-on-error` and the printed row counts, not by the
   decrypt check.
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
8. **~~The KEK itself~~ — CLOSED 2026-08-13. The artifacts' LOCATION is
   what remains open.** This item used to read: *"the drill reads
   `TALOS_MASTER_KEY` out of the running controller container and refuses
   to start without it, so a green run proves 'these artifacts + today's
   live KEK ⇒ readable data', which is not the same claim as 'these
   artifacts ⇒ readable data' … the drill structurally cannot tell you
   whether you have escrowed the key."*

   That was the single worst thing about this drill, because it meant the
   drill could only pass while the host it insures was still alive — it
   had never once tested the property it exists to test, and it went green
   every time. The KEK is now sourced from **escrow only**
   (`TALOS_DRILL_ESCROW_KEY_CMD`, `TALOS_DRILL_ESCROW_KEY_FILE`, or an
   interactive hidden prompt), the live-container read is **deleted rather
   than demoted** — there is no flag that restores it — and its absence is
   fatal with a message naming what to create. See step 0b of the script.

   The claim a green run now supports is
   *"these artifacts + the escrowed KEK ⇒ readable data"*, which is what a
   recovery actually consists of.

   **Tier 2 — getting the ciphertext off this host — now has a path, and
   the drill can test it.** `--source b2` fetches from object storage,
   `age`-decrypts with an ESCROWED passphrase, and only then restores;
   it FAILS rather than falling back to the local copy when the bucket is
   unreachable, holds nothing, holds only a stale archive, or the
   passphrase is wrong. That mode answers the strictly harder question a
   real recovery asks. See `docs/offhost-backup.md`.

   **The default `--source artifact` still does not.** It restores a file
   from the very disk whose loss the backups insure against, so a green
   run there says nothing about surviving that loss — the banner now says
   so explicitly and points at `--source b2`. Run the b2 mode at least as
   often as you would trust the claim.

   At the time of writing the bucket itself **does not exist yet**: the
   five operator prerequisites in `docs/offhost-backup.md` § Operator
   setup need a Backblaze account and cannot be done from this repo, so
   `--source b2` currently fails on this machine and that failure is the
   accurate answer. The dumps still live only on the host filesystem;
   `docker-compose.yml` used to claim they "ride Time Machine off-box"
   while `tmutil destinationinfo` answers "No destinations configured"
   (that comment is now corrected).

   Three limits of the b2 mode, stated rather than implied:
   * It restores the **newest** off-host archive. A corrupt object from
     three months ago would go unnoticed — the same "newest only" hole
     item 4 above describes for local artifacts.
   * It proves the archives are READABLE. It does not prove they are
     UNDELETABLE: refusing delete and overwrite is the provider's job and
     is checked separately by
     `scripts/offhost-backup/upload.sh probe-append-only`, which attempts
     both and expects both to be refused.
   * The age passphrase gets the same containment checks as the KEK
     (not inside a checkout, not inside `$BACKUP_DIR`, symlinks resolved,
     both-set refused) and therefore the same stated limits: nothing here
     can tell that the source is genuinely off-box.

   Limits of the fix, stated rather than implied — and note the first
   two bullets used to contradict each other, one claiming provenance is
   enforced and the next admitting it is not audited. Only the second was
   ever true:
   * **The drill does NOT establish the key's PROVENANCE.** It refuses
     specific shapes; it cannot verify a source. What is actually
     enforced: the live-container read is deleted (no flag restores it);
     a `_CMD` naming `docker exec` / `docker inspect` or `printenv
     TALOS_MASTER_KEY` is refused; a `_FILE`, and any existing
     path-shaped argument of a `_CMD`, that resolves inside a checkout
     (this one *or* the main clone when you are in a worktree) or inside
     `$BACKUP_DIR` is refused, symlinks resolved first; setting both
     `_CMD` and `_FILE` is refused rather than silently resolved by
     precedence. Until 2026-08-13 the banner printed "(ESCROW — the live
     stack was never asked)" unconditionally, so
     `TALOS_DRILL_ESCROW_KEY_CMD='docker exec talos-controller printenv
     TALOS_MASTER_KEY'` passed every check and printed exactly that while
     the live stack was the only thing asked. That spelling is now
     refused; the general claim is unverifiable and is no longer made.
   * **An escrow source is not audited for being genuinely off-box.** It
     cannot tell that `/Volumes/escrow` is a RAM disk, that your `op`
     vault syncs to this same laptop, or that a **hard link** inside a
     checkout points at a file outside it — a hard link is a genuinely
     different path with no symlink to resolve, so `realpath` cannot see
     through it. The `_CMD` scan is a token scan, not a shell parser: a
     path built from a variable, or assembled inside the helper, is
     invisible to it.
   * **`verify_restore` enforces none of this.** Running `cargo run
     --example verify_restore` by hand with a key copied out of a
     container proves exactly what it always did. The gate is in the
     shell script, one layer up, on purpose.

## Related

- Alerts that fire when the drill hasn't run: `deploy/observability/alerts.yaml` → `TalosBackupRestoreDrillFailed`.
- Alerts that fire when the OFF-HOST copy stops advancing:
  the same file → `TalosOffhostBackupUploadFailing` (a classified failure
  inside a 6 h window) and `TalosOffhostBackupStale` (no successful upload
  in 7+ days). Both are gated on `talos_offhost_backup_enabled == 1`, so a
  deployment that does not use off-host egress stays quiet — which means
  the "configured but never scheduled" case is caught by THIS drill's
  `--source b2` leg and not by those alerts. See `docs/offhost-backup.md`
  § What goes wrong.
- The off-host egress itself: `docs/offhost-backup.md`,
  `scripts/offhost-backup/`, `talos-offhost-backup/`.
- The verifiers the drill runs end-to-end:
  `controller/examples/verify_restore.rs` (reads what the backup
  contained) and `controller/examples/verify_phase_b.rs` (writes a
  fresh round-trip).
- The collector that carries the drill's metric: the `node-exporter`
  service in `docker-compose.yml` and the job of the same name in
  `observability/prometheus/prometheus.yml`.
- Memory on why this matters: `memory/vault_persistence_fix.md` —
  the 2026-04-24 incident that motivated the drill.
