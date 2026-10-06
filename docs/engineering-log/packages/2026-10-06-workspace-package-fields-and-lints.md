# Every crate inherits the shared package fields and lint table, or says why not (2026-10-06)

The last of the gaps from the operator's question about workspace best
practices (`2026-10-06-workspace-dependencies.md` is the largest).

## Measured (before)

13 of 153 workspace crates did not inherit `[workspace.package]` or
`[workspace.lints]`:

* **Six wrote the package fields out by hand** — `controller`, `worker`,
  `talos-worker-runtime`, `talos-memory`, `talos-secrets`, `talos-dlp`. All
  six therefore declared NO minimum Rust version, while the workspace says
  1.99.
* **One had no `[lints]` table at all**: `talos-google-health`, generated
  from the integration scaffold, whose manifest template had none. So the
  workspace's `unsafe_code = "deny"` did not apply to it, and would not have
  applied to any integration generated later.
* **Six do not inherit by decision**: the five engine crates (written to be
  published on their own, with their own version, minimum Rust and a
  stricter lint table) and `talos_sdk_macros` (shipped into the controller
  image as a standalone crate with no workspace above it).

## Changed

* The six inherit `version`, `edition`, `rust-version`, `license` and
  `publish`. `controller` keeps its own `version` (`1.0.0-r306`, its release
  number), marked. `Cargo.lock` is unchanged.
* `talos-google-health` has `[lints] workspace = true`; it is clean under
  it. The scaffold's template has it too.
* `talos_sdk_macros` cannot inherit the lint table, so its `lib.rs` now
  says `#![forbid(unsafe_code)]` itself. It contained none.
* The six deliberate exceptions carry a marker and a reason in their
  manifests.
* `scripts/check-workspace-package.py`, in `make lint`: each of the five
  fields inherits and `[lints]` is `workspace = true`, unless the manifest
  says why not — `# not-inherited: <reason>` for one field,
  `# package-not-inherited: <reason>` for all five,
  `# lints-not-inherited: <reason>` for the lint table. A marker with no
  reason is refused. Run against main as it was: 67 findings in 13 crates.

## A reader of the controller's version line

`scripts/release.sh` reads `controller/Cargo.toml`'s `version = "…"` with
`sed -E 's/version = "(.+)"/\1/'`, which keeps anything after the closing
quote. The marker was first written as a trailing comment on that line; the
release pre-flight would then have compared `1.0.0-r306  # not-inherited: …`
with the version asked for and refused every release. Found by listing what
reads the manifest before pushing (the lesson of the previous package), not
by a failure. The marker is on the line above, the guard accepts it there,
and the script's pattern now takes only the quoted value.

## Verified

The whole unit suite and the DB-free test binaries were run through
`make test-unit` and `make test-dbfree` before the push; clippy
`-D warnings` on the eight crates whose manifests or sources changed;
the scaffold self-test generates and builds a crate from the new template.

## Not done

* **The engine crates' fields.** Their `rust-version = "1.88"` is a claim
  nothing tests (the workspace builds with 1.99 only). Whether they are
  still meant to be published separately is the operator's decision; until
  then their manifests are left as their authors wrote them.
