# Two runtime advisories the gate did not show, and one it stopped showing (2026-10-06)

## Found by switching Dependabot alerts on

GitHub listed six advisories against the lockfiles the hour alerts went on.
Three were handled by Dependabot's own pull requests (`shell-quote`, `cmov`,
`serde_with`). For two it tried and failed, and `cargo deny` had reported
neither:

| advisory | crate | installed | patched | scope |
|---|---|---|---|---|
| GHSA-8ffr-xgwf-xj56 (high) — uncontrolled recursion in the unknown-key skip path | `aws-smithy-json` | 0.61.9 and 0.62.5 | 0.62.7 | runtime |
| GHSA-rhfx-m35p-ff5j (low) — `IterMut` invalidates an internal pointer | `lru` | 0.12.5 | 0.16.3 | runtime |

Both came from one crate: `aws-sdk-s3` 1.119.0 (December 2025), used by the
controller and `talos-audit-ledger` for object storage. `cargo update -p
aws-sdk-s3` alone changes nothing — the newer SDK needs newer `aws-smithy-*`
crates, and a single-package update does not move them — which is why
Dependabot's two jobs failed.

(The sixth, `tokio-tar` GHSA-j5gw-2vrg-8fgx, has no patched release and is
reached only through `testcontainers`, a dev-dependency of `controller`. Not
changed here.)

## Changed

* `Cargo.lock`: the 22 `aws-*` crates named by exact version and updated
  together — `aws-sdk-s3` 1.119.0 → 1.152.0, `aws-config` 1.8.16 → 1.12.0,
  `aws-smithy-json` → 0.63.1 (both affected copies gone), `lru` 0.12.5 gone.
  The newer SDK also drops a set of old duplicates it used to pull in
  (`http` 0.2, `http-body` 0.4, `p256` 0.11, `ecdsa` 0.14, `elliptic-curve`
  0.12, …): 245 lines added, 401 removed.
  `cargo update … --recursive` was tried first and not used: it moved every
  shared dependency as well (612 added, 884 removed).
* `talos-audit-ledger` declares `lru = "0.18"` (was `"0.16"`): its one use,
  `LruCache<Uuid, SdkTracerProvider>`, now shares the patched copy the SDK
  brings in. No third copy.
* `event-listener` 5.4.1 → 5.4.2 (RUSTSEC-2026-0221, unsound; via `sqlx`).
* `deny.toml`: `unsound = "all"`.

## Why `unsound = "all"`

With our own `lru` declaration on a patched release, `cargo deny` reported
the existing RUSTSEC-2026-0253 exception as matching nothing — although
`async-graphql` 7.2.1 still links lru 0.16.4, which that advisory covers.
cargo-deny's default reports an unsoundness advisory only for the
workspace's DIRECT dependencies. So fixing our own declaration made the gate
go quiet about a crate that is still in the binary.

With `"all"` the affected copy stays reported and excepted, with its
reachability argument (the keys are `String`/`Uuid`; the trigger is a key
whose `Drop` panics) rewritten for the one path left. Widening the scope
surfaced exactly one more advisory, `event-listener`, a patch release away.

## Checked

`cargo check -p controller -p talos-audit-ledger --all-targets`;
`cargo deny check` (advisories, bans, licenses, sources ok; no unmatched
exception); `talos-audit-ledger`'s unit tests; `make lint`. The object-store
paths themselves are exercised by CI's integration shards
(`audit_ledger_stream_bounds` and the S3 host functions), not here.

## Not checked

The 33 minor releases of `aws-sdk-s3` between 1.119 and 1.152 were not read.
The running stack talks to MinIO; nothing was run against it from here.
