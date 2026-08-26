# Off-host backup egress (Tier 2)

**Status: the code is landed and testable; the bucket is not created yet.**
Everything in "Operator setup" below needs the operator's Backblaze account
and cannot be done from this repo. Until it is done, `talos_offhost_backup_*`
reports `enabled 0`, nothing is uploaded, and `make drill ARGS="--source b2"`
fails — correctly, because there is no off-host copy.

## Why

Tier 1 closed on 2026-08-13: the master KEK is escrowed in 1Password, so the
restore drill's claim became *"these artifacts + the escrowed KEK ⇒ readable
data"*. The half that stayed open is **where the artifacts live** —
`~/.talos/backups` on one laptop SSD, replicated nowhere. `tmutil
destinationinfo` answers "No destinations configured".

Losing that disk loses:

| | rows | replaceable? |
|---|---|---|
| `module_executions` input payloads | 22,360 | no |
| `workflow_executions` outputs | 7,122 | no |
| **`ml_examples` + `ml_disagreements`** | **1,544 + 384** | **no — a month of human labelling** |
| `actor_memory` | 22 | no |
| `secrets` | 14 | yes (re-issue) |

Code re-clones. Labels do not.

## What was built

| Piece | Path |
|---|---|
| Pure logic (object keys, `aws` argv, retention arithmetic, failure classification, metric rendering, passphrase containment, age round-trip) | `talos-offhost-backup/src/` |
| CLI (`upload`, `fetch`, `plan`, `probe-append-only`) | `talos-offhost-backup/src/main.rs` |
| Host wrapper + launchd scheduler | `scripts/offhost-backup/{upload.sh,schedule.sh}` |
| Restore-from-B2 drill mode | `scripts/drills/backup-restore.sh --source b2` |
| Alerts | `deploy/helm/talos/files/alerts.yaml` → `TalosOffhostBackupUploadFailing`, `TalosOffhostBackupStale` |
| Promtool tests for both, both directions | `observability/alerts_chart_test.yml` |

Design decisions, made rather than left implicit:

* **Backblaze B2 via the S3-compatible API.** The provider is a
  `--endpoint-url` and a region; swapping to S3/R2/MinIO changes two strings.
* **`age` with a passphrase**, client-side, before anything leaves the host.
  A `pg_dump --format=custom` carries plaintext workflow names, module source
  and `graph_json` **alongside** the DEK-encrypted columns, so an unencrypted
  push publishes all of that to a third party. There is no flag to skip it.
* **The `age` *library*, not the `age` CLI.** Not a preference — the CLI reads
  its passphrase from `/dev/tty` and fails with `ENOTTY` on a pipe, so an
  unattended encrypt is impossible through it. **The output is a standard age
  v1 file**: `age -d archive.age`, typing the escrowed passphrase, opens it by
  hand with no Rust toolchain involved. That property is pinned by a unit test
  (`output_is_a_standard_age_v1_file`) because recovery must not depend on
  this workspace compiling.
* **Postgres, Vault and Neo4j are all uploaded.** Neo4j was excluded until
  2026-08-26 because the graph was "reconstructible from `actor_memory` via
  `graph_backfill`". That justification was measured against both live stores
  and had decayed: of the graph's 16 distinct (`actor_id`, `source_key`)
  pairs, **6 — 191 of 1,283 nodes — no longer have a row to rebuild from**,
  and 90 of those never did (`reflection_synthesis` is a sentinel written by
  the reflection loop, not an `actor_memory` key, so no backfill can emit it).
  Nodes also accumulate over every value a mutable `latest` key has held while
  `actor_memory` keeps only the current one, so even the recoverable remainder
  would come back as a *different* graph. Cost is 1.2 MB/day against ~240 MB
  for the Postgres dump. **No second secret**: it rides the same `age`
  passphrase. Full derivation: `ArtifactKind`'s doc comment in
  `talos-offhost-backup/src/key.rs`.
* **Uploading Neo4j is not the same as restoring it.** `make drill
  ARGS="--source b2"` fetches and restores `--kind postgres` and `--kind
  vault` only; it does **not** touch the neo4j archive. `fetch --kind neo4j`
  works and proves the object is present and decryptable, but nothing
  automated proves the tarball is a loadable Neo4j store. See
  [What none of this proves](#what-none-of-this-proves) below.
* **First upload = "newest onward", not a backfill.** `upload` sends only the
  newest local artifact of each kind, *including the one already on disk*, so
  enabling this puts a real archive off-host within minutes rather than
  waiting for the sidecar's next tick. A `pg_dump` is cumulative, so the
  newest dump already contains every `ml_examples` row ever written — the
  older local dumps are point-in-time convenience, not additional data.
  `upload --backfill` is the explicit one-time opt-in that pushes the whole
  retained history if point-in-time recovery inside the retention window
  matters to you.

## "Append-only" is three things, and only some of them are code

A credential that can `PutObject` **can overwrite an existing key** — same
name, new bytes, history gone. No delete call required. So:

| Property | Enforced by | Strength |
|---|---|---|
| Object keys are unique, timestamped, non-reusable | **code** (`talos-offhost-backup/src/key.rs`, unit-tested) | a *guard*: two distinct artifacts cannot collide |
| An existing key is never re-PUT | **code** (listing + `head-object` pre-flight) | a *guard*: TOCTOU-racy, defeated by any concurrent or hostile writer |
| The credential physically cannot delete or overwrite | **your B2 application key** (no `deleteFiles`) | a **control** — and `probe-append-only` is how you verify it rather than assume it |
| Old versions survive a hostile overwrite | **your bucket lifecycle / object-lock rule, set with the MASTER key** | a **control** |

The first two live in this repo and are conveniences. **The last two are the
actual controls and neither of them lives here.** Do not read the unique-key
derivation as append-only enforcement; it is not.

Conditional writes (`If-None-Match: *`) would turn the second row into a real
control, but B2's S3 compatibility layer does not document support for them.
Shipping a dependency on an unverified provider behaviour would be a claim,
not a control, so it is deliberately not used.

## Residual risk, stated plainly

**The upload credential lives on the host it protects. It is compromised if
the host is compromised.** There is no way around that for an unattended push.

What the design buys is that an attacker holding it can only **add** objects:
they cannot delete yesterday's archive and they cannot overwrite it. They
*can* upload garbage — a thousand junk objects, or a valid-looking archive of
nothing — and they can run up your egress bill. Recoverability survives
because the real archives are still there under their own distinct keys and
the retention rule you set with the master key keeps them there. **Retention
plus distinct keys is the whole of that guarantee.**

One specific shape of that, because "upload garbage" is vague and this one is
concrete, and it is **closed** rather than accepted: `fetch` picks the archive
with the **highest key stamp**, and an age in the future saturates to 0 hours
rather than going negative. A **future-dated** object therefore shadows the
real newest one *and reads as 0 h old forever*.

This is not merely poisoning. The upload credential also holds `readFiles` —
the drill needs it — so anyone holding it can `GET` today's real archive and
`PUT` those exact bytes back under a future-dated key. That object decrypts,
`pg_restore --exit-on-error` succeeds and both verifiers pass: **the drill
would report success while restoring a replay**, with the freshness gate
permanently disabled for that kind because the age never leaves 0. No attacker
is required either — the stamp comes from the sidecar's filename, so one
upload from a host with a skewed clock does the same by accident.

An earlier version of this document called it "poisoning, not data loss, and
the drill fails loudly on it". That was only true for a *junk* object, which is
not the only shape.

The stated dichotomy — reject future keys, or accept false-reds on clock skew —
was false: a **bounded tolerance** closes it with neither cost. `fetch` refuses
any archive stamped more than `MAX_FUTURE_SKEW_HOURS` (24 h) ahead of the local
clock, which is far wider than any clock error that survives on a networked
host and far narrower than any useful replay window. Ordinary drift is still
accepted and still reads as fresh. When a future-dated key IS present, `fetch`
fails with a message naming the skew, and the escape hatch is
`fetch --key <object-key>` to name a known-good archive explicitly.

**What that costs, stated rather than implied.** A planted future key makes
`make drill ARGS="--source b2"` fail until the object is gone, and the host
credential cannot delete it — that is the whole design. Clearing it needs your
**master** Backblaze credential. That is the right trade: the alternative is a
drill that keeps going green on a replay. Until it is cleared, `fetch --key`
still proves a named archive is readable; only the automated drill is blocked.
Check the host's clock first — an accidental skew is by far the likelier cause
than an attacker, and it leaves exactly the same object behind.

Object keys deliberately carry nothing sensitive: a bucket listing is
metadata, and whoever can list learns every key name. A key is
`talos/v1/<kind>/<YYYY>/<MM>/<stamp>-<kind>.age` — the artifact family and
when it was taken, both already implied by the bucket existing. No user id, no
hostname, no local path, no secret path.

## The `age` passphrase is a SECOND fatal secret

**Lose it and every archive in the bucket is unreadable forever, exactly as if
the KEK had been lost.** It is not a lesser secret because it is newer.

Escrow rules — the same ones #639 gave the KEK, not similar ones:

* **A distinct 1Password entry from the KEK**, cross-referenced both ways.
  Two secrets in one entry is one secret with two values, and a recovery that
  finds the entry deleted loses both.
* **Record which archives it opens**, by object-key date range. A rotated
  passphrase opens the OLD archives and not the new ones, and the reverse —
  the same trap the KEK entry carries. `talos/v1/**` keys are dated, so
  "opens everything from 2026-08-17 onward" is a writable, checkable note.
* **The source must not resolve inside a checkout or inside `$BACKUP_DIR`**,
  symlinks resolved first. A key stored beside the ciphertext it opens is not
  encryption, it is a filename change. Enforced in
  `talos-offhost-backup/src/passphrase.rs` (pure, unit-tested) and again in
  `scripts/drills/backup-restore.sh`.
* **Setting both `_CMD` and `_FILE` is refused**, not resolved by precedence —
  the branch that would lose is the `_FILE` one, which carries the checks.

Stated limits, because a containment check described as a guarantee is worse
than none: this cannot tell that `/Volumes/escrow` is a RAM disk, that your
1Password vault syncs to this same laptop, or that a **hard link** inside a
checkout points at a file outside it (a hard link is a genuinely different
path with no symlink to resolve). The `_CMD` scan is a token scan, not a shell
parser. These are specific holes closed, not a proof of provenance.

Never log, echo or persist the passphrase or the B2 secret. The B2 key **id**
may be logged and is, so you can tell *which* credential is failing; the
secret never appears in argv, in the launchd plist, or in an error message.

## Operator setup

Five steps, all of which need your Backblaze and 1Password accounts.

### 1. Create the bucket

Private. Any region. Note the region code (e.g. `us-west-004`) and the
matching S3 endpoint (`https://s3.us-west-004.backblazeb2.com`).

### 2. Create the application key — scoped, and WITHOUT delete

Scope it **to that bucket only**, with:

```
listBuckets, listFiles, readFiles, writeFiles
```

and **not** `deleteFiles`. This is the control that makes the host credential
additive-only.

### 3. Set the retention rule with the MASTER key, not this one

In the bucket's lifecycle settings, choose "Keep prior versions for N days"
(90 is a reasonable start) — **using your master application key**. If the
host credential could set its own lifecycle, a compromised host could shorten
retention to a day and then overwrite everything.

### 4. Generate and escrow the age passphrase

A long random passphrase (`head -c 32 /dev/urandom | base64` is fine). Put it
in a **new** 1Password entry, distinct from the KEK entry, cross-referenced
from both. In the entry's notes, record: *"opens `talos/v1/**` archives from
`<today>` onward"*.

### 5. Put the credentials where the scripts read them — not in the repo, not in `$BACKUP_DIR`

```bash
# ~/.talos/offhost.env  (chmod 600, outside the repo and outside $BACKUP_DIR)
export TALOS_OFFHOST_B2_BUCKET=talos-offhost
export TALOS_OFFHOST_B2_ENDPOINT=https://s3.us-west-004.backblazeb2.com
export TALOS_OFFHOST_B2_REGION=us-west-004
export AWS_ACCESS_KEY_ID=<the application key id>          # loggable
export AWS_SECRET_ACCESS_KEY=<the application key secret>  # never logged, never in the plist
export TALOS_OFFHOST_AGE_PASSPHRASE_CMD='op read "op://Private/Talos age backup/password"'
```

For the *scheduled* run, `AWS_SECRET_ACCESS_KEY` is deliberately **not**
copied into the launchd plist — a plist is `chmod 600` but it is still a
plaintext file on the same disk as the ciphertext. Use a `chmod 600`
`~/.aws/credentials` profile and export `AWS_PROFILE` instead.

## Bring-up, in order

```bash
source ~/.talos/offhost.env

# 0. What would be sent, without touching the network at all.
scripts/offhost-backup/upload.sh plan --offline

# 1. PROVE APPEND-ONLY BEFORE TRUSTING IT. Attempts an overwrite and a
#    delete with the upload credential; both must be REFUSED BY THE
#    PROVIDER (a 403). Anything else — no network, no `aws`, an
#    unconfigured bucket — exits non-zero as "NOT PROVEN", because an
#    attempt that never reached B2 is evidence of nothing and scoring it
#    as a refusal would make this command answer YES exactly when it
#    could not ask the question. Leaves one un-deletable probe object
#    behind under talos/v1/_probe/ — that object is the evidence, and it
#    cannot be cleaned up (that would need the delete it just proved
#    absent).
scripts/offhost-backup/upload.sh probe-append-only

# 2. First real upload: newest postgres dump + newest vault and neo4j tarballs.
scripts/offhost-backup/upload.sh

# 3. PROVE IT IS RESTORABLE FROM THE BUCKET. Fetch → age-decrypt →
#    pg_restore → decrypt real rows with the ESCROWED KEK.
make drill ARGS="--source b2"

# 4. Schedule the daily push.
make offhost-schedule
make offhost-status
```

Step 3 is the one that matters. Steps 0-2 prove the pipe works; step 3 proves
the thing on the other end is a backup.

### Optional one-time backfill

```bash
scripts/offhost-backup/upload.sh --backfill
```

Pushes every retained local artifact the bucket lacks (as of 2026-08-26:
13 dumps, 13 vault tarballs, 13 neo4j tarballs). Only worth the egress if you want point-in-time
recovery to a specific day inside the retention window; the newest dump alone
already contains all the data.

## What goes wrong, and what tells you

| Symptom | Signal |
|---|---|
| B2 key rotated / revoked | `TalosOffhostBackupUploadFailing` with `reason="auth"` |
| Bucket or passphrase not configured | `reason="config"` |
| Laptop closed / no network on **two** nights | `reason="network"` — one offline night is deliberately NOT an alert (the threshold is "at least two failures in 50 h"), because a daily job that alerts on every unrouted night trains you to ignore it |
| Upload silently stopped for a week | `TalosOffhostBackupStale` |
| Uploader was never scheduled at all | **Neither alert.** See below. |
| Bucket holds nothing, or only stale archives | `make drill ARGS="--source b2"` FAILS → `TalosBackupRestoreDrillLastRunFailed`, naming the `b2` copy |
| Off-host copy has never been restored at all | **No alert, deliberately.** `make drill-schedule-status` and leg F of `make observability-verify` both say so; a rule for it could never clear on a host that cannot run `--source b2` yet |
| Wrong age passphrase | the drill's b2 leg fails with `reason="encrypt"` and says the download succeeded, so it is the key and not the network |

**The gap, stated rather than implied.** Both new alerts are gated on
`talos_offhost_backup_enabled == 1`, which only exists once the uploader has
run at least once. If you configure the bucket and never schedule the
uploader, no `.prom` file is ever written and **neither alert can fire** — the
detector silenced by a version of its own condition. That case is caught one
layer out, by the drill: `--source b2` fails when the bucket holds no archive.
The gating is deliberate — an `absent()` arm would fire permanently on every
deployment that does not use B2, and a permanently-red alert trains operators
to ignore red. The drill is the gate for "no off-host copy at all"; the alerts
are the gate for "the off-host copy stopped advancing". Neither substitutes
for the other.

## Testing it without credentials

Everything except the live run is exercisable offline:

```bash
cargo test -p talos-offhost-backup
```

covers object-key construction (including that keys leak nothing and never
collide), the `aws` argv for all five verbs, failure classification, the
metric pre-seeding and carry-forward, the passphrase containment rules, and
the full `age` encrypt→decrypt round trip including wrong-passphrase,
truncated-archive and flipped-byte cases.

The `aws` binary itself is a seam: `TALOS_OFFHOST_AWS_BIN` points at any
executable, and the binary's own tests use a stub script to drive pagination,
auth failure, missing-tool and garbage-listing paths with no network. That is
the same reasoning as `cosign_verify_argv` in `talos-worker-runtime` — the
security-critical command construction is unit-tested without invoking the
tool.

The alerts are driven in both directions through `promtool`:

```bash
docker run --rm -v "$PWD:/repo:ro" --entrypoint promtool \
  prom/prometheus:v2.48.0 test rules /repo/observability/alerts_chart_test.yml
```

## What none of this proves

* **That the Neo4j archive is restorable.** This is the newest and largest gap,
  and it is stated first because it is the shape this whole arc keeps finding.
  As of 2026-08-26 `scripts/drills/backup-restore.sh` knows exactly two
  artifacts, `PG_ARTIFACT` and `VAULT_ARTIFACT`. `--kind neo4j` uploads and
  fetches — so the object's presence, freshness and decryptability ARE proven
  by `fetch` — but no automated step has ever loaded one back into a Neo4j
  server. What a real restore leg would need, in order:
  1. a scratch `neo4j:5.26-community` container with an empty data volume;
  2. `tar -xzf` the archive into it (the tarball is a raw store-file copy of
     `/neo4j-data` — `databases/`, `transactions/`, `dbms/auth.ini` — **not**
     a `neo4j-admin database dump`, so there is no load command; the restore
     is "stop, replace the directory, start");
  3. start the server and let it recover `transactions/`;
  4. a **content** probe, not an exit code: `MATCH (n) RETURN count(n)` and
     `MATCH ()-[r]->() RETURN count(r)` compared against the `neo4j_nodes=` /
     `neo4j_relationships=` lines the sidecar already writes into the local
     `.tar.gz.manifest`. A `pg_restore`-shaped "it exited 0" check would
     certify an empty database.
  Not built here on purpose — it is a drill change, not a key change, and
  bundling it would have hidden that the two are separable.
* That the bucket cannot be emptied by someone who steals your **master**
  Backblaze credential. Nothing here defends against that.
* That the age passphrase source is genuinely off-box (see the stated limits
  above).
* That an archive older than the newest one is still readable. The drill
  restores the **newest** off-host archive; a corrupt object from three months
  ago would go unnoticed. Fetch an older one by hand occasionally:

  ```bash
  source ~/.talos/offhost.env
  aws s3api list-objects-v2 --endpoint-url "$TALOS_OFFHOST_B2_ENDPOINT" \
      --bucket "$TALOS_OFFHOST_B2_BUCKET" --prefix talos/v1/postgres/ \
      --query 'Contents[].Key' --output text | tr '\t' '\n'
  scripts/offhost-backup/upload.sh fetch --kind postgres \
      --key talos/v1/postgres/2026/06/20260601T101757Z-postgres.age \
      --dest /tmp/old.dump
  ```

  A named object is exempt from the **staleness** limit (you asked for that
  object, so its age is not a claim about the pipeline) but not from the
  future-stamp refusal. This is also the way past a future-dated key that is
  shadowing the real newest archive. `--source b2` itself always takes the
  newest and has no `--key`; driving the whole drill from an arbitrary key is
  not wired up.
* That B2 itself is durable. That is their claim, not a measurement of ours.
