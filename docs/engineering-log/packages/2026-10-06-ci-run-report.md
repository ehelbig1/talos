# One command for what a CI run cost (2026-10-06)

## Why

Every CI change of 2026-10-05/06 (#1109, #1111–#1115) was measured with a
script written on the spot: find the run, wait, pull each job's minutes,
its runner image, its cache line, each shard's log. It was written about
eight times, differently each time, and once it took "the branch's newest
run" for the run of a commit pushed after the pull request had merged — no
run existed for that commit, and the earlier commit's figures were reported
as its measurement.

## Changed

`scripts/ci-run-report.py --pr N | --sha C | --run ID [--wait]`. It finds
the run by commit and says so when there is none. It prints each job's
minutes, runner image, cache state and long steps; each integration shard's
combined build, test minutes, slow controller binaries and Postgres wait
summary; and what stands out. Each "stands out" rule is a cause actually
found that day:

* a job on a different runner image from the rest (its `rust-cache` key
  differs — the DB-free job at 12.0 minutes instead of 7.7);
* a job that found no build cache (the unit job on main, 12.2 instead of 8);
* shard test minutes more than two apart (a stale weights table);
* a `DROP DATABASE` of 3 s or more in a shard's Postgres report (the
  login-timeout stall);
* a job cancelled before it started (GitHub had no runner).

Run against #1113's run it reports the three stalled shards; against the
commit pushed after #1112 merged it reports that no run exists (exit 2).

`--self-test` checks the log readers against made-up log text (supply-chain
job). The shard reader is `scripts/ci_shard.py`'s, not a second one.

## Not done

A `make` target: the Makefile is in the list that makes a change run every
CI job, and the command is one line.
