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
integration, sqlx-cache, clippy). It renames each directory beside itself —
instant, never across a filesystem — and deletes the renamed copies in the
background with its output closed, so the step returns at once.

The rename is what makes the background delete safe: a later step sees what
it saw before (the paths are gone), and one that recreates a path —
`setup-node` in the integration job rebuilds the tool cache — writes a new
directory, not the one being removed. `scripts/tests/ci-free-disk-test.sh`
covers that on made-up directories (also under `/bin/bash` 3.2 and Linux).

Each of the four jobs now ends with `df -h /` (`if: always()`).

## Not decided here

* **Whether to delete at all.** 108 GB free after deleting suggests the jobs
  may fit without it, but nothing recorded what a job uses at its end. The
  new last step records it; read a week of them before removing the step.
* **Measured and declined:** `shellcheck` as a lint gate — 13 findings at
  warning level across 62 scripts, none in the drill script, so it would have
  caught neither drill defect of 2026-10-05; and a lint for BSD-only shell
  idioms — 4 lines, 3 of them in macOS-only scripts.
* **Next, not in this package:** the unit job runs two builds in sequence
  (6.7 + 4.4 minutes) and the integration shards are uneven (9.0 / 10.9 /
  12.5); both are larger than this change and need their own measurement.
