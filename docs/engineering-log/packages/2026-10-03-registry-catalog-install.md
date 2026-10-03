# Listing and installing catalog modules from the registry's rows

2026-10-03

Second follow-up to the two-lane plan for modules. With this a registry-mode
deployment, including one with compiling turned off, can list its catalog and
give a user their own copy of a catalog module.

## The defect

In registry mode the catalog is the shared rows the registry sync writes, each
naming a signed artifact. Two surfaces ignored them and read the template
directory baked into the controller image instead:

* `list_module_catalog` listed the image's templates, which the deployment
  does not offer (the disk seed is skipped in registry mode) and which may be
  behind the registry.
* `install_module_from_catalog` read the image's template and COMPILED it. The
  copy ran code the registry never published, and on a deployment with
  compiling off the install was refused, so a user could not get a copy with
  narrower secret grants at all.

## What a copy is now

`install_module_from_catalog` first asks whether the key names a shared
catalog row that carries a registry reference
(`ModuleRepository::find_shared_registry_entry`, slug or display name, slug
wins). If it does, the copy references the same artifact: it stores the row's
`oci_url`, no bytes and no source, with the installer's grants. Nothing is
compiled. If it does not, the image's template is read and compiled exactly as
before. A lookup that fails is refused; it does not fall through to the image.

The choice is made from the row, not from the environment, so the handler has
one path and the tests need no environment.

Everything between resolving the entry and writing the copy is unchanged and
shared: the role gate on the capability world, the rule that a caller may
only narrow the template's secret grant, the carrying of an installed copy's
grants across a reinstall, the dry run, the fuel precedence. The registry row
is read in the shape a template's `talos.json` has (`registry_entry_manifest`)
so that code cannot tell the sources apart. The fuel limit offered is the one
the catalog writer resolved from the published manifest.

**One writer for both kinds of copy.**
`ModuleRepository::install_catalog_copy` takes an `InstalledArtifact`
(`Compiled { bytes, hash, source, dependencies }` or `Registry { oci_url }`)
and the upsert sets `oci_url` and the bytes together, so a reinstall that
changes which kind a copy is leaves nothing of the other. The audit record
gains `oci_url`. `install_catalog_module_to_modules` remains as the compiled
spelling of it.

## What follows from a copy that holds no code

* **Hot update is refused**, before any compile
  (`refuse_registry_reference`). Dispatch sends the reference, so compiled
  bytes written onto the row would report success and change nothing it runs.
  The refusal names the tools that do apply (host, method and secret grants;
  per-node `max_fuel`) and how to run different code.
* **An in-process run is refused** (from the previous change:
  `WasmModule::in_process_bytes`).
* **A pinned copy reads as present.** `list_user_pinned_modules` counted only
  bytes, so `restore_pinned_modules` would have tried to rebuild a reference
  copy from an image template.

## The listing

`list_module_catalog` reads the shared registry rows when a registry is
configured, in the same item shape and order, and refuses rather than report
an empty catalog when the read fails. `get_catalog_status` says what each
surface reads in each mode.

## Tests

`controller/tests/registry_catalog_install_tests.rs`, through the real MCP
dispatch with the compile service turned off, against rows written by the real
catalog writer: a copy references the artifact with narrowed grants, the
row's fuel limit and an audit record; the display name resolves and an unknown
key does not; hot update and `test_module` are refused and the pinned copy
reads as present; a reinstall that changes the kind of copy replaces the other
kind in both directions; the registry catalog is the rows that name an
artifact.

A tenancy test, mutation-proved: one user's reference copy also names an
artifact and carries that user's grants, and is never read as a catalog entry
(removing `user_id IS NULL` from the lookup fails it).

Unit tests for the manifest shape, the ordering and the status wording.

## Decisions taken here, for the operator to overrule

1. **A copy references the artifact by the same reference its catalog row
   holds**, which is a tag. A republish under that tag changes what the copy
   runs without a reinstall, while its grants stay as they were approved. This
   follows the existing GraphQL path that creates a module from a registry
   template. Pinning a copy to a digest would make a copy immutable until it
   is reinstalled; it needs the sync to record the digest, and was not done.
2. **Hot update of a reference copy is refused, not turned into a detach.**
   Detaching (compile the supplied source, drop the reference) is a
   reasonable alternative; refusing leaves no row whose code silently differs
   from the catalog entry it is named after.

## Not done

* `restore_pinned_modules` and the catalog drift report still read the
  image's templates for compiled copies. A reference copy needs neither.
* A deployment switched from registry mode back to disk mode keeps registry
  rows for templates the image does not ship; an install of one still makes a
  reference copy. That is what the row says it is.
* Nothing here was exercised against a live registry. None exists.
