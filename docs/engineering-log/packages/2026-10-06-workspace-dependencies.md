# A shared dependency's version is declared once, in the workspace table (2026-10-06)

Operator question: "are all dependencies declared following workspace best
practices?" Measured answer that day: no. This is the largest of the gaps.

## Measured (before)

153 workspace crates; 1,246 third-party dependency declarations. The
`[workspace.dependencies]` table listed 8 crates, and 497 declarations
inherited from it. 58 more dependencies were declared by two or more crates
each, crate by crate: `sqlx` in 76 manifests, `reqwest` in 29, `async-nats`
in 25. Even the 8 in the table were not inherited everywhere (`tokio`: 64
crates wrote `"1"`, 15 inherited). 14 dependencies were written with more
than one requirement for the same locked version (`uuid`: `1`, `1.11`,
`1.20`).

## Changed

* `[workspace.dependencies]` lists all 66 dependencies that two or more
  crates use. Each version is the most specific requirement any crate had
  written, so no crate's minimum is lowered.
* 711 declarations in 137 manifests now read `name.workspace = true` or
  `{ workspace = true, features = [...] }`. Each crate keeps exactly the
  features it listed.
* Nine entries say `default-features = false`, because at least one user
  needs the defaults off; the crates that had them on now list `"default"`
  (`rand` in 23 crates, `tracing-subscriber` in 8, `redis` in 2,
  `oci-distribution` in 1). Inheritance can add features, never remove them.
  For `tokio` and `tokio-util` the flag is dropped: their `default` feature
  set is empty, so it did nothing.
* One crate keeps its own line, marked: `talos-evaluation` is on
  `thiserror` 1 where the workspace is on 2.
* The integration scaffold's manifest template inherits too, so a generated
  integration is in line from its first commit.
* `scripts/check-workspace-deps.py`, in `make lint`: a dependency two crates
  share must be in the table and inherited; anything in the table must be
  inherited wherever it is declared; no entry may be unused. Run against
  main as it was, it reports 210 findings.

## Verified: nothing that is built changes

* `Cargo.lock` is byte-identical to main's.
* The resolved package set and every package's enabled features, for the
  `controller`, `worker` and `talos-offhost-backup` binaries on both Linux
  targets and for the whole workspace with dev edges: 0 differences (807,
  443, 129 and 910 packages).
* `cargo check --workspace --all-targets` passes. The scaffold self-test
  generates, lints and tests a crate from the new template.

What does change: a crate built ALONE (`cargo build -p one-crate`) now also
gets the features the four older table entries carry (`chrono/serde`,
`serde/derive`, `tokio/{sync,rt,macros}`, `uuid/{v4,serde}`) where it used to
write the bare version. That can only add features, and every real build
already had them through another crate.

## Two checks that read manifests had to learn the new spelling

`grep '^sqlparser[[:space:]]*='` (the structural check that keeps the SQL
parser in three crates) does not match `sqlparser.workspace = true`. Left
alone it would have kept passing while a fourth crate added the parser. It
now matches both spellings and skips the root manifest, whose entry declares
a version and parses nothing; with `sqlparser.workspace = true` added to a
fourth crate it fails, as it must. Check 51 (no engine dependency in
repository crates) got the same widening, though its dependency is a path
and was not moved.

Found by `make lint` failing on the root manifest — the silent half was
found by reading the pattern, not by a failure.

## Not done

* **Internal `path` dependencies** (980 declarations) are not in the table.
  A path is not a version to keep in step, and the churn is three times
  this change's.
* **Dependencies only one crate uses** (38) stay in that crate.
* **`talos-evaluation` to `thiserror` 2.** It would change the lockfile, and
  this change's proof is that the lockfile does not move.
* 12 crates still do not inherit the shared package fields, and 7 do not
  inherit the workspace lint table.
