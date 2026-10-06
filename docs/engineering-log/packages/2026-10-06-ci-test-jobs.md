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

## Deliberately not done

* **Balancing shards by measured duration.** It needs a checked-in table of
  per-test weights and a tool to refresh it; a new or renamed test would fall
  back to a default. A fourth shard buys about the same wall time with a
  one-line change, and "adding a test file needs no CI edit" stays true.
* **Running binaries in parallel inside a shard.** The `tc` binaries are
  single-threaded by design (several global writes), and the controller
  binaries each clone the template database.

## Not yet known

The effect is this PR's own run: expected about 10–11 minutes of wall time.
`make test-integration` locally (one shard) now builds all 155 controller
binaries in one call first; that was not timed here.
