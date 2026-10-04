# Three decisions about the two module lanes

2026-10-04. Operator decisions; each had been left open by an earlier
package with a recommendation, and the operator took the recommendation in
all three.

## 1. No boot gate requiring a registry in production

The two-lane plan's second step was "make the registry the required source
for shared modules in production". It was not built, and will not be.

* The templates baked into the controller image are already provenanced: the
  image is cosign-signed by the publish workflow and deployed by digest.
* The chart's default is production with no registry, and the installer's
  first-deploy path seeds from the image. A gate there would be satisfied by
  an acknowledgement the installer sets for every deployment.
* The boundary that matters is whether a deployment builds code from source,
  and the compile switch enforces it: with `TALOS_MODULE_COMPILATION=false`
  the boot validator already requires `TALOS_REGISTRY_URL`.

Rejected alternative: a `security_audit` finding for "production, no
registry". Not added: it would be a permanent warning on a supported,
provenanced configuration.

## 2. A copy keeps the registry reference it was installed with

`install_module_from_catalog` on a registry deployment stores the reference
its catalog row holds at that moment, which is a tag.

* A republish under the SAME tag reaches the copy at the next pull, with the
  copy's grants unchanged. The artifact is signed by the publish workflow and
  its digest is verified at every pull, and a copy's grants can only be
  narrower than the template's own.
* A NEW version is a new tag. The sync rewrites the shared row; existing
  copies stay on the old tag until they are reinstalled.

Rejected alternative: pin each copy to a digest. It would make a copy
immutable until reinstalled, at the cost of the sync recording digests and of
every security fix under an existing tag needing a reinstall of every copy —
the staleness the disk lane already has (five of eight copies were found
behind on 2026-09-29).

**What changed with this decision.** `get_catalog_status` reported every
copy on a registry deployment as `unknown` ("the catalog row carries no
source"). For a copy that references an artifact that was wrong: its code IS
its reference, and the catalog row has one to compare it with.
`list_catalog_copy_drift` now reads both references
(`CatalogCopyRow::artifact_matches`), and such a copy is `current` when they
are the same and the manifest fields match, and `behind` otherwise, with
`artifact` in `differs_in` when the catalog has moved to a new tag. `unknown`
remains for the one pairing with nothing to compare: a copy compiled here
against a catalog row that has no source.

## 3. Hot update of a reference copy is refused

A reference copy holds no code. Dispatch sends its reference, so compiled
bytes written onto the row would report success and change nothing it runs.

Rejected alternative: detach — compile the supplied source onto the row and
drop the reference. It would leave a module that carries a catalog entry's
name and slug and runs something else. Running different code is a new
module (`compile_custom_sandbox`) and a node swap, and the refusal says so.

## Tests

Unit: `catalog_copy_state_tests::a_registry_copy_is_compared_by_its_reference`
(same reference, moved reference, stale schema, the compiled-copy case that
stays `unknown`). Database:
`registry_catalog_install_tests::a_reference_copy_is_current_until_the_catalog_moves_to_a_new_artifact`
drives install, a sync that moves the shared row to a new tag, and a
reinstall, through the real writer and the real tool.

Latent on a deployment with no registry configured.
