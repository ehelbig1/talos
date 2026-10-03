# A per-deployment switch that turns module compilation off

2026-10-03

Step 3 of the two-lane plan for modules: shared modules come from the
registry, the operator's own modules are compiled on the platform. This step
lets a deployment choose to have no compile lane at all.

## What it is

`TALOS_MODULE_COMPILATION=false` makes a deployment registry-only. The
controller then never runs a toolchain over module source: no compile, no
lint, no source analysis, in any language, from any surface. Default is on,
and a deployment that does not set the variable behaves exactly as before.

## Where it is enforced

* **One chokepoint.** A sandbox child can only be spawned with a
  `&CompileSlot` (`SandboxCommand::run`), and the service obtains a slot in
  one place, `CompilationService::acquire_slot`. That method refuses with the
  typed `CompilationDisabled` error before it touches the semaphore. So a
  compile path added later that forgets the switch still cannot start a
  toolchain. Before this change slot acquisition was a free function with six
  callers, each mapping its error to its own "queue full" sentence.
* **Up-front check on every public entry point** (`compile_to_wasm_with_config`,
  `compile_to_wasm_with_language_and_world`, `compile_js_to_wasm`,
  `compile_python_to_wasm`, `lint_code`, `analyze_code`), so a refused request
  creates no workspace, emits no progress event and returns no static-lint
  answer on its way to the slot.
* **The switch is a property of the service instance**, read once in
  `CompilationService::new` from `talos_config::module_compilation_enabled()`.
  `with_compilation_enabled` exists so a test can drive the real entry points
  with it off and without touching the process environment.

## An unreadable value does not mean "on"

`talos_config::bool_env` folds an unrecognised value into "unset" and warns,
which is right for a tuning flag. This switch turns a capability off, so
`TALOS_MODULE_COMPILATION=disabled` must not leave compiling on.
`talos_config::module_compilation()` returns `Err(raw)` for a value that is
not a boolean token; the boot validator refuses to start on it, and
`module_compilation_enabled()` reads it as off for any process that does not
run the validator. The token vocabulary is unchanged and still has one home
(`parse_bool_env`, which `bool_env` now calls).

## Compiling off requires a registry

The templates baked into the controller image are source, and the boot seed
compiles them. With compiling off and no registry nothing could run, and every
catalog row would sit without bytes behind a controller that looks healthy.
`ConfigValidator` refuses to start in that combination, the chart refuses to
render it, and compose documents it. With a registry configured the disk seed
is already skipped, so no boot path compiles.

`TALOS_REGISTRY_URL` had three readers with two different empty-value rules
(the seed and the sync filtered an empty string, `get_catalog_status` also
trimmed). There is now one, `talos_config::registry_url()`, which trims and
treats empty as unset.

## What a caller is told

A compile-service `Err` used to be answered with "Compilation service error —
see server logs" at five MCP sites, and with other generic sentences at the
rest, because the error can carry host paths and the toolchain's stderr. A
refusal the operator chose is different: it is safe to say and the caller
cannot act without it. `talos_compilation::caller_facing_service_error(&e)`
returns the policy sentence for `CompilationDisabled` and the generic sentence
for anything else, and the generic sentence now lives only there. The two
services with typed errors (`HotUpdateError`, `InlineCompileError`) gained a
`CompilationDisabled` variant; the GraphQL compile mutation and source-analysis
query map it too. `import_workflow` reports it per module.

`get_catalog_status` and `get_platform_info` report the switch
(`module_compilation: {enabled, note}`).

## Tests

* `talos-compilation::compile_switch_tests`: every public entry point refuses
  with the typed error, creates no workspace and emits no event; the slot
  itself is refused; the refusal survives `anyhow` context; a source pin that
  the service obtains a slot in exactly one place, after the switch is checked.
* Mutations, both killed: removing the check in `acquire_slot` fails the slot
  test and the pin; removing the up-front check in `lint_code` fails the
  entry-point test (the static-lint pre-pass answers without a slot).
* `talos-config`: the switch does not fold an unreadable value into the
  default; an empty registry URL is unset.
* `talos-config-validator`: compiling off requires a registry and a readable
  switch.
* `talos-mcp-handlers::compile_refusal_pins`: no handler spells the generic
  sentence itself; the two typed services say the policy verbatim; both status
  reports state the switch.
* Chart, rendered by hand: default renders no variable; `false` with no
  registry fails the render with the reason; `false`, `0` and a misspelling
  with a registry render the value verbatim (the misspelling then fails the
  controller's boot validator).

## Not done here, and why it matters

A registry-only deployment can run the shared catalog modules the registry
sync provides. Three things the registry lane still gets wrong were found
while reading for this change and are NOT fixed by it:

1. `install_module_from_catalog` builds a private copy by compiling the
   template baked into the image, in registry mode too. With compiling off it
   is refused, so a registry-only deployment cannot give a user a copy with
   narrower secret grants or its own hosts.
2. Five readers derive `is_compiled` from `wasm_bytes` alone. A registry row
   has an `oci_url` and no bytes, so it reads as not compiled:
   `create_workflow_from_description` would offer no catalog modules and
   `list_templates` would mark every one unbuilt. The missing-bytes gauge
   already uses the right predicate (bytes or `oci_url`).
3. `list_module_catalog` reads the directory baked into the image, not the
   catalog the registry provided.

These are one piece of work: make a registry row a first-class module for
install, listing and planning. Until it lands, turning the switch off is
correct and safe but leaves those three surfaces short.

Also unchanged: the registry sync's message when the Sigstore policy is not
explicit in production says disk-seeded templates remain the source of truth,
but the disk seed is skipped whenever a registry URL is set, so that
deployment has no catalog. Recorded, not changed.

Nothing in this change was exercised against a live registry; none exists yet
(the template publish workflow has not been run).
