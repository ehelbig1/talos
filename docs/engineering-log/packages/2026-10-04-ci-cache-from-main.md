# CI compiled every dependency from nothing on every pull request

2026-10-04

Found while measuring where a pull request's 23 minutes of CI go.

## Measured

Four successful pull-request runs of `quality.yml`: wall time 20.6 to 24.6
minutes. The critical path is "Rust tests (unit / lib)" at 22.8 minutes on
average, then the three integration shards at about 19 each, clippy at 10.

The first run of a new pull request logs "No cache found" in the unit job
and in the integration shards. The repository's caches at the time:

* 9 caches, 11.8 GB, against a 10 GB limit;
* every one on a `refs/pull/N/merge` ref (two pull requests' worth);
* none on `refs/heads/main`, although the nightly run on main had succeeded
  that morning.

## Why

GitHub scopes a cache to the ref that saved it. A pull request reads caches
from its own ref and from its base branch. Every job saved on every run, so:

1. a cache saved by pull request A was unreadable by pull request B;
2. each pull request wrote about 6.4 GB (unit 2.2, integration 1.7, clippy
   1.0, catalog 0.8, sqlx 0.7), so two of them exceeded the limit and
   evicted the rest — including the caches the nightly run had saved on
   main, which are the only ones another pull request could have read.

The cache was doing work only for a second push to the same pull request.

## The fix

One workflow value, `CACHE_SAVE`, true only when the run's ref is
`refs/heads/main`; all five `Swatinem/rust-cache` steps carry `save-if` with
it (the integration shards keep "shard 1 only" as well). Pull-request and
merge-queue runs restore and save nothing.

Side effect worth having: a pull request can no longer write a cache that
any other run restores.

## Not measured, and when it will be

**The saving is not measured.** History has no clean comparison: the only
pull requests with two successful runs were documentation and frontend
changes, whose Rust jobs were skipped. The first pull request opened after
main holds a cache is the measurement — the unit job's and the shards'
durations against the 22.8 and 19 minutes above.

What the cache can save is the dependency build. This workspace's own 148
crates are rebuilt on every run regardless (`rust-cache` does not keep
workspace crates, and cargo would rebuild them after a fresh checkout
anyway), so the saving is some fraction of each job, not all of it.

## Considered and not done here

* **Splitting the unit job** into its two halves (library tests 10.9
  minutes, DB-free integration binaries 9.7) so they run side by side. It
  would shorten the critical path whatever the cache does. Left for its own
  change, after this one is measured, so the two effects can be told apart.
* **A fourth integration shard.** Same reason.
* **A lint** that every cache step carries `save-if`. Population: five steps
  in one file. The workflow states the rule where the value is defined.
* **Deleting the existing pull-request caches.** They are the least recently
  used and are evicted first as main's are written.

## To seed main's cache after this merges

`gh workflow run quality.yml --ref main`, or wait for the nightly run at
07:00 UTC. Until one of those has run, pull requests still start cold.

## Measured, 2026-10-05

Main was seeded with `gh workflow run quality.yml --ref main` (five Rust
caches, 6.4 GB together). The next pull request to run every job restored
them. Minutes per job:

| Job | Cold, pull requests before | Cold, the seeding run | Warm, first pull request after |
|---|---|---|---|
| Unit / lib | 22.8 (average) | 18.6 | 11.4 |
| Integration shard 1 / 2 / 3 | about 19 each | 19.7 / 14.5 / 16.7 | 12.3 / 14.3 / 12.5 |
| Clippy | about 10 | 8.6 | 4.6 |
| sqlx offline cache | — | 8.3 | 5.3 |
| Catalog templates | — | 5.5 | 2.4 |

Inside the unit job: library tests 10.9 → 4.6, DB-free integration binaries
9.7 → 3.2. The slowest job of a full run went from about 23 minutes to 14.3.

**A second warm run, the same day, read differently.** Unit job 14.8
(library tests 6.7, DB-free binaries 4.4), shards 12.5 / 13.5 / 13.4, clippy
4.2. So the warm unit job is 11.4 to 14.8 on two readings, and the sentence
first written here — that it is shorter than every integration shard — held
for one run of two. The slowest job of a full run was 14.3 and then 14.8.

**Splitting the unit job is still not worth doing, for a narrower reason.**
Warm, the unit job and the shards are level. Splitting it would leave the
shards as the limit at 12 to 14 minutes, so a run would finish at most about
a minute sooner, and two jobs would each pay the setup the one pays now.

**A fourth integration shard is left unmeasured.** A warm shard spends 10.4
of its 12.3 minutes inside `make test-integration`. How that divides between
building the test binaries (which a fourth shard would not shorten much) and
running them (which it would) has not been read.

