# One manifest parser and one writer for shared catalog rows

2026-10-03 — step 1 of the two-lane module plan (operator decision: the
registry carries SHARED modules; a user's own modules are compiled on the
platform; modules are operator-and-agent authored).

## Why

Two code paths write the shared row of a catalog template: the disk seed
(`controller::bootstrap::services::seed_templates`) and the registry sync
(`talos_registry::sync`). Each parsed `talos.json` and wrote the row itself.
They had drifted: the registry sync wrote neither `allowed_methods` nor
`capability_world` nor `dependencies` nor `max_fuel`. A row it created kept
those columns' defaults — no verb allowed (since 2026-09-24 an empty list
denies every verb), `minimal-node`, 2,000,000 — so no HTTP template synced
from a registry could make a request. It also keyed on the display name, so a
renamed template minted a second row.

Latent: no deployment runs in registry mode (0 rows with an `oci_url` on the
reference deployment; the publish workflow has no runs).

## What changed

* `reconcile::CatalogManifest::parse(manifest)` — the one reading of a
  manifest: name, category, description, config schema, hosts, verbs,
  secrets, approval list, capability world, dependencies, fuel limit. It
  validates the grants and the world and returns a `ManifestRefusal`
  otherwise.
* `reconcile::CatalogSource` — `Disk { source_code }` or
  `Registry { oci_url }`. `upsert_catalog_template_by_slug` takes it and
  writes `oci_url` on both of its paths: a disk row clears it, a registry
  row sets it and leaves any stored source alone. A registry row never asks
  for a compile.
* The seed and the sync both call `parse` then `upsert`. Neither builds a
  row by hand; `sync.rs` has no statement of its own.
* `talos_compilation::manifest_dependencies` — the free form of
  `CatalogTemplate::dependencies`, for a manifest that did not come from a
  directory; `catalog.rs` stays the only reader of the key (check 68).

## Behaviour changes, stated

* **A manifest with no `capability_world` is refused by both writers.** The
  disk seed used to default it to `automation-node`, the widest world. All
  79 shipped manifests declare one, so no shipped row changes.
* A `capability_world` no module can be compiled for is refused.
* The registry sync is keyed on the slug (rename-safe), writes the four
  columns it left out, and defaults a missing category to `General` and a
  missing config schema to `{}`, as the disk seed does (it used `Custom`
  and a typed empty object; every shipped manifest declares both).
* A disk seed clears a row's `oci_url`. Dispatch prefers `oci_url` whenever
  it is set, so a deployment switched back from registry mode would
  otherwise keep dispatching to a registry it no longer syncs.

## Decisions

* **`talos-registry` now depends on `talos-compilation`**, for two pure
  readers of a manifest (`recommended_max_fuel`, `manifest_dependencies`).
  Acyclic; the worker links neither crate. Moving the fuel-budget
  arithmetic to a leaf crate instead was weighed and declined: about 550
  lines with their tests, for two function calls.
* **The manifest's world is taken as declared.** A world narrower than the
  component's imports fails to instantiate; a wider one grants nothing the
  component does not import. What a module may reach is its hosts and
  secrets, which come from the same signed manifest as before.

## Stated limits

* Not run against a real registry: the sync's network half (discovery,
  cosign verification, the config pull) is unchanged and untested here. The
  parser and the writer are driven directly.
* In registry mode `install_module_from_catalog` still compiles a private
  copy from the template directory baked into the image.

## Tests

* Parser: a whole manifest; what is left out; each refusal; an unreadable
  fuel recommendation; **every shipped manifest is accepted** (79).
* Database (`catalog_one_writer_tests`): the same manifest through either
  source stores the same value in all ten manifest-decided columns, and
  they are the manifest's values; a row follows the source that wrote it
  last; a renamed registry template keeps its row.
* Pins: the seed and the sync each parse once and write through the shared
  writer; the sync has no `INSERT` of its own.
