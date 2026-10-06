# CI frees the runner's disk without waiting for it (2026-10-05)

## Measured

Twelve full `quality.yml` runs: wall time 13.7–21.6 minutes, set by four jobs
that run side by side (medians: unit 14.7, integration shards 12.2 / 13.9 /
14.2). In six passing runs each of those four spent a median of 1.5–2.1
minutes on "Free runner disk space" before compiling anything, and the step
is erratic: in run 37385168807 it took 1m57s in one job and 6m12s in another.
It deletes six toolchains the image ships, one after another, in the
foreground. It left 108 GB free of 145 GB.

## Changed

`scripts/ci-free-disk.sh` replaces the four copies of that step (unit,
integration, sqlx-cache, clippy), and each of those jobs now ends with
`df -h /` (`if: always()`).

**It deletes nothing unless less than 40 GB is free.** The first version of
this package deleted in the background every time; its own run (37388069851)
supplied the figure that was missing: `df` first and last in each job showed
86 GB free of 145 GB at the start, and 59–62 GB in use at the end with the
~22 GB of toolchains gone — a test job adds about 25 GB. So on these runners
the deletion buys nothing. In that run the step took 0 s, the unit job went
14.7 → 10.6 minutes, clippy 5.6 → 3.1 and sqlx 5.1 → 3.3, but all three
integration shards' `make test-integration` ran slower than their medians
(+0.5 to +1.8 minutes) — one run, so not separable from variance, and
consistent with a 22 GB delete competing for the disk. Not deleting removes
the question.

The step stays as a guard for a smaller runner: GitHub promises far less disk
than it gives today. Below the threshold it renames each directory beside
itself — instant, never across a filesystem — and deletes the renamed copies
in the background with its output closed. The rename is what makes that safe:
a later step sees what it saw before (the paths are gone), and one that
recreates a path — `setup-node` rebuilds the tool cache — writes a new
directory, not the one being removed. An unreadable free-space figure counts
as short. `scripts/tests/ci-free-disk-test.sh` covers both sides of the
threshold on made-up directories (also under `/bin/bash` 3.2 and Linux).

## Not decided here

* **Measured and declined:** `shellcheck` as a lint gate — 13 findings at
  warning level across 62 scripts, none in the drill script, so it would have
  caught neither drill defect of 2026-10-05; and a lint for BSD-only shell
  idioms — 4 lines, 3 of them in macOS-only scripts.
* **Next, not in this package:** the unit job runs two builds in sequence
  and the integration shards are uneven (9.0 / 10.9 / 12.5 minutes of
  `make test-integration`); the slowest shard now sets the run's wall time.
