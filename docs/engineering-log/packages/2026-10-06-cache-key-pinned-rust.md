# The build cache no longer depends on the runner image's own Rust (2026-10-06)

## Measured

Three slow jobs in one day, each on a job that found no build cache and
compiled every dependency:

| run | job | minutes | usual |
|---|---|---:|---:|
| 37464963912 | DB-free binaries + doctests | 12.0 | 7.7 |
| main, 0bace895 | unit / lib | 12.2 | 8 |
| 37476202275 | integration 4/4 | ~14 | 9 |

In each, that job was on runner image `20261004.327.1` while the rest of the
run was on `20260927.320.1`. The pinned toolchain was the same on both
(`rustc 1.96.1 (31fca3adb 2026-06-26)`). The cache keys were not
(`…-1dca7fac-…` against `…-82cad1ee-…`), and the action's own log says why:
its "Rust Versions" list had three entries — the pinned 1.96.1 twice, and the
image's preinstalled `stable`: **1.98.1 on the older image, 1.99.0 on the
newer**. `Swatinem/rust-cache` (v2.9.1, `getRustVersions`) runs
`rustup toolchain list` and hashes every toolchain it finds.

So every image that bumps its preinstalled Rust invalidates every cache, and
while two images are in service jobs flip between a hit and a full compile.

## Changed

`scripts/ci-only-pinned-rust.sh` removes every installed toolchain except
`RUST_TOOLCHAIN`, and runs in each of the six cached jobs between "Install
Rust toolchain" and the cache step. It refuses to remove anything if the
pinned toolchain is not installed. `scripts/tests/ci-only-pinned-rust-test.sh`
drives it with a fake `rustup`.

`scripts/ci-run-report.py` no longer calls a different runner image a cause
on its own; it mentions the image only for a job that also missed its cache —
which, after this change, would mean the key depends on the image again.

## Verified on its own run (37480261228)

Nine cached jobs, five on image `20261004.327.1` and four on
`20260927.320.1`:

* each removed `stable-x86_64-unknown-linux-gnu`, in 0–3 seconds;
* each one's "Rust Versions" was `1.96.1 31fca3ad` and nothing else;
* **the four integration shards — two on each image — computed one key**
  (`v0-rust-quality-integration-Linux-x64-e6de0650-8ed95a7d`), and the unit
  and DB-free jobs one key between them.

Every job missed, as expected: the key changed once and a pull request
never saves a cache. That run took 15.2 minutes.

## Not yet seen

A cache HIT on the new key from either image: it needs a run that starts
after main's run for this change has saved the caches.

## Considered and not done

`add-rust-environment-hash-key: false` with a hand-built `key:`. It drops the
action's hashing of `Cargo.lock`, `rust-toolchain` and `.cargo/config.toml`
along with the toolchain list, and those would have to be rebuilt by hand in
six places.
