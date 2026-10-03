# A catalog row a registry provides is a module that can run

2026-10-03

Follow-up to the two-lane plan for modules. Found while building the compile
switch: in registry mode the surfaces that list and resolve modules treated
every module the registry provides as not compiled.

## The defect

In registry mode a shared catalog row holds no compiled bytes. It names a
signed artifact (`oci_url`) that the worker pulls, verifies and runs.
Dispatch was built for that: `ModuleRegistry::get_module` returns such a row
with empty bytes and its reference, and the engine sends the reference as the
job's module URI.

Four statements asked a narrower question — "does this row hold bytes?":

| Reader | What it decided |
|---|---|
| `ModuleRegistry::list_template_metadata_for_user` (two statements) | the `is_compiled` flag on every template listing |
| `WorkflowRepository::list_scaffolding_templates` | which modules `create_workflow_from_description` may offer the planner |
| `WorkflowRepository::find_compiled_template_by_name` | whether a workflow pattern's module "exists" |

So on a registry deployment the planner would be offered nothing from the
catalog and a pattern naming a catalog module would report it missing, while
the same module ran fine when a workflow dispatched it.

Each now reads "compiled bytes on the row, OR a registry reference". A row
with neither still reads as unrunnable; that row is what the flag is for, and
the tests keep it on the far side.

## In-process runs

`test_module`, module replay and the GraphQL `testModule` mutation run a
stored module inside the controller. Given a registry row they handed the
runtime its empty `wasm_bytes`, which fails with a parse error that says
nothing about the cause. The controller has no path that fetches and verifies
a registry artifact, and should not grow one beside the worker's.
`WasmModule::in_process_bytes()` returns the bytes or the typed
`RegistryArtifactOnly` refusal, and all three surfaces ask it first and say
why.

## Also corrected

The registry sync's refusal to run without an explicit Sigstore policy in
production said "disk-seeded templates remain the source of truth meanwhile".
The disk seed is skipped whenever a registry URL is set, so that was false:
the controller serves whatever an earlier sync left in the database. The
message now says so.

## Tests

`controller/tests/registry_row_runnable_tests.rs`, against rows written by
the real catalog writer: both listing statements, the planner's listing and
name resolution each count the registry row and not the bare one; the registry
row loads for dispatch and is refused in-process; a pin that every in-process
run of a stored module asks for its bytes first (population: three). With the
registry arm removed from the four statements, the two listing tests fail.

## Deliberately not changed

* `get_module_export_info`'s `is_compiled` (it decides how an EXPORT bundle
  classifies a module, and a registry module has no source to put in one).
* The stale-name fallback in `get_module_for_execution` (it finds a rebuilt
  copy of a user's own module by name; a registry row is not rebuilt).
* `find_node_template_by_name_and_user`, `find_compiled_sandbox_template`,
  the pinned-module status and the cache and storage statistics: each is about
  bytes this platform compiled.

## Not done here

Listing the catalog and installing a private copy still read the template
directory baked into the image, and installing compiles. Both are the next
change.

Latent on this fleet: no registry is configured and there are no registry
rows. Nothing here was exercised against a live registry.
