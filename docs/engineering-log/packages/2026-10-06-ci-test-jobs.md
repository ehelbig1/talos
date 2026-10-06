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

## Deliberately not done

* **Running binaries in parallel inside a shard.** The `tc` binaries are
  single-threaded by design (several global writes), and the controller
  binaries each clone the template database.
* **A lint that the weights table is fresh.** A stale table only costs
  balance, never correctness; `docs/ci.md` says when to refresh it.

## Not yet known

The dealt shards have not run in CI: about 9 minutes of wall time is expected
(4.8 of tests + 2–3 of build + setup), from 12.4. `make test-integration`
locally (one shard) now builds all 155 controller binaries in one call first;
that was not timed here.
