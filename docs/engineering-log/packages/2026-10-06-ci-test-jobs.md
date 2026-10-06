# The test jobs that set CI's wall time (2026-10-06)

## Measured

After the disk step was removed (2026-10-05) a full `quality.yml` run still
took 15.6 minutes (run 37403154166), set by one job:

| job | minutes |
|---|---:|
| integration 3/3 | 15.2 |
| unit / lib | 12.7 |
| integration 2/3 | 11.9 |
| integration 1/3 | 10.8 |

From that run's three shard logs, per work item: 182 items, 33.9 minutes in
all; median 4.8 s, and 15 items of 30 s or more are 17.1 minutes — half.
Items are dealt round-robin, so which shard gets the slow ones is chance:
their test items ran 9.4 / 10.7 / 13.9 minutes.

For the 138 controller binaries (each its own `cargo test --test <name>`):
**7.0 minutes between an item's start and its first test — 3.0 s each, one
after another — against 10.1 minutes running tests.**

The unit job ran the library tests (6.8 minutes), then the DB-free `tests/`
binaries (4.4) and the doctests (0.8): two builds back to back.

## Changed

* `scripts/test-integration.sh` builds a shard's controller test binaries in
  ONE `cargo test --no-run` call before the per-item loop, so cargo builds
  them side by side. The loop is unchanged: each item still runs through its
  own `cargo test`, so a compile error or a test failure is attributed where
  it was. A failed combined build is a warning, not the verdict.
* `quality.yml` runs four integration shards, not three.
* The unit job is two jobs side by side: `Rust tests (unit / lib)` and
  `Rust tests (DB-free binaries + doctests)`. The second restores the first's
  dependency cache and never saves it. The gate needs both.
* CLAUDE.md's sentence on `quality.yml` no longer names the shard count
  (`docs/ci.md` does), so the next change of count is not a CLAUDE.md edit.

## First measurement, and what it changed

This package's first commit made the three changes above and dealt the work
round-robin, as before. Its run (37461915856): **15.6 → 12.4 minutes**.

| job | before | first commit |
|---|---:|---:|
| unit / lib | 12.7 | 6.5 |
| DB-free binaries + doctests | (in the unit job) | 7.7 |
| integration shards | 10.8 / 11.9 / 15.2 | 9.3 / 7.7 / 12.1 / 6.6 |

The combined build took 2.0–3.0 minutes per shard and the test items fell
from 33.9 minutes to 19.2 (the builds no longer inside them). But one shard
was again the whole wall time, and the per-item figures say why: ten items
are 8.8 of the 19.2 minutes, and round-robin put five of them on shard 3 —
7.6 minutes of tests against 4.7, 3.8 and 3.0.

**So the work is now dealt by measured duration** — the thing this record's
first version listed as deliberately not done, on the argument that a fourth
shard bought the same for less. It did not: four round-robin shards left a
5.5-minute spread. `scripts/ci_shard.py select` deals longest-first greedy
from `scripts/ci-test-weights.tsv` (40 items of 5 s or more; an item not
listed weighs 3 s, so a new test file still needs no CI edit, and a deleted
test's entry is ignored). Replayed against that run's own per-item times,
four shards come to 4.7 / 4.9 / 4.8 / 4.8 minutes of tests, where
round-robin gave 4.7 / 3.8 / 7.6 / 3.0. `ci_shard.py weights --run <id>`
rebuilds the table from a run's shard logs.

The deal is computed from the list and the table alone, so every shard
computes the same one; `scripts/tests/ci-shard-test.sh` (supply-chain job)
checks that 2, 3, 4, 5 and 7 shards each partition the real list exactly. The
selection is captured, not streamed: a failed deal stops the shard, where a
streamed one would have run nothing and passed.

## Second measurement: the deal alone did not shorten the run

The dealt shards' first run (37464963912): **12.3 minutes — no better than
round-robin's 12.4.** Shards 11.9 / 9.4 / 8.8 / 7.8; their tests ran
7.1 / 5.3 / 4.2 / 4.5 minutes, not the 4.8 each the replay predicted. Three
separate things, read from the logs:

1. **An intermittent 60-second stall, and it had been recorded as weight.**
   `actor_clone_parity_tests` and `approval_policy_trigger_refusal_tests`
   took 61 and 62 s in the first run and 2 and 3 s in the second;
   `create_workflow_node_controls_tests` and `enqueue_drain_tests` took 1 s
   and then 61. In each case cargo reported the binary fresh in under a
   second and every test in it sat for a minute from its first line, then
   passed. Different binaries each run, two per run, on shards at random.
   The one-run table had listed two of them as minute-long tests.
   The cause is NOT known. Nothing on the client side waits 60 s; the one
   arithmetic match is the harness's clone retry (10 retries, Postgres
   waiting 5 s inside each) — which would mean something holds a session on
   the template database, and that is a hypothesis.
2. **Compile-heavy `--lib` items vary by a minute between runs**
   (`expose_limit_absence_tests` 71 → 119 s, `kernel_two_replica` 36 → 59 s);
   both fell on shard 1.
3. **The DB-free job took 12.0 minutes, not 7.7:** it alone landed on a newer
   runner image (20261004 against 20260927), whose toolchain environment
   gives `rust-cache` a different key, found no cache and compiled every
   dependency. GitHub's rollout, and it ends when main saves a cache on the
   new image — but that job never saves one, so it depends on the unit job
   having run on the same image.

Changed in response:

* `ci_shard.py weights` takes several `--run`s and keeps each item's
  **fastest** time: a stall or a slow runner only adds. The table is rebuilt
  from both runs — 182 items, 16.3 minutes, 37 listed; the four stalled
  binaries are no longer in it.
* Each shard's Postgres logs statements of 3 s or more, lock waits and every
  session, and the shard ends by printing the slow statements, any refusal
  to clone the template, and sessions of 3 s or more on the template. The
  next stall names its own cause; until then the stall is unexplained and
  costs about two minutes a run.

## Deliberately not done

* **Running binaries in parallel inside a shard.** The `tc` binaries are
  single-threaded by design (several global writes), and the controller
  binaries each clone the template database.
* **A lint that the weights table is fresh.** A stale table only costs
  balance, never correctness; `docs/ci.md` says when to refresh it.
* **A fix for the stall.** Not without its cause.

## Not yet known

Whether the deal shortens the run once the stall is out of the table: one
run, with two stalls and a cold job in it, says nothing either way.
`make test-integration` locally (one shard) now builds all 155 controller
binaries in one call first; that was not timed here.
