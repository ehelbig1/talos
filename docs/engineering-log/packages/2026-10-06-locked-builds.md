# Builds use the committed lockfile or fail (2026-10-06)

## Measured

No cargo command in `quality.yml`, in the scripts it calls, or in the
controller and worker Dockerfiles passed `--locked` (0 uses). Without it,
cargo treats a lockfile that disagrees with a manifest as something to
repair: it resolves the missing entries to the newest matching releases and
builds. A manifest committed without its `Cargo.lock` change would have
passed CI and built an image on versions chosen at build time, reviewed by
nobody and different from run to run. The lockfile was in sync on main when
this was written; nothing enforced it.

The same reading of the workflow found that the lint job runs
`scripts/lint-structural.sh` directly, not `make lint`. `check-rust-pins.py`
(added the same day) was wired into the Makefile only, so CI ran its
self-test and never the check.

## Changed

* The lint job, which every pull request runs, starts with
  `cargo update --workspace --locked`. It re-resolves only the workspace's
  own entries and fails if the lockfile would change. Measured locally: 0.5 s
  and exit 0 on a clean tree; exit 101 with "cannot update the lock file …
  because --locked was passed" after adding one dependency line to a
  manifest.
* `cargo build --locked` in `controller/Dockerfile` and `worker/Dockerfile`.
  Both copy the whole build context, lockfile included, and neither edits a
  manifest before building.
* The lint job runs `python3 scripts/check-rust-pins.py`.
* `docs/ci.md` says what to do when the lockfile step fails, and that a
  check added to `make lint` needs its own step in the lint job.

## Decided

* **One step, not a flag on every command.** With the lockfile proven
  current at the start of the run, every later cargo command in every job
  uses it unchanged. Adding `--locked` to each `cargo nextest`, `cargo test`,
  `cargo clippy` and script would be a dozen edits that a new command could
  forget.
* **The image builds carry the flag themselves**, because CI does not build
  them: a deploy from a checkout whose lockfile lags fails at the build
  instead of shipping.

## Not verified here

The image builds were not run. `cargo metadata --locked` passes on this
tree, which is the same resolution the Dockerfile's `cargo build --locked`
performs; the first `make up` after this merges is the real check.
