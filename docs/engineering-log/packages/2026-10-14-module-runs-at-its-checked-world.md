# A module runs at the world that was checked, never a wider one (2026-10-14)

Security review 2026-10-14, findings **G-1** (High), **G-17** and **G-22**
(Low). Package 2 of the review's remediation. Stacked on package 1.

## The defect, as verified

Every gate on a module's capability world — the agent role
(`require_agent_role_permits_world`), the actor ceiling (`ceiling_permits`),
the dispatch-time ceiling — read a world the CALLER chose: the
`capability_world` argument, or the row label written from it. What ran was
the binary's own world, and three links let the two differ:

1. **Compile.** `wrap_rust_code_with_talos_module` returns a body untouched
   when it already carries `#[talos_module]` / `#[talos_node]` /
   `wit_bindgen::generate!`, and `compile_to_wasm_with_language_and_world`
   ignored `world_override` for Rust. The binary was reconciled against the
   SOURCE's declaration — i.e. against itself.
2. **Record.** `compile_custom_sandbox`, `InlineCompileService` and
   `HotUpdateService` wrote the argument's label to `modules.capability_world`;
   `import_workflow` wrote the bundle's claimed label.
3. **Run.** The worker linked the hint when one came, and the binary's
   inspected world when none did. The pipeline step, the four module-bound
   push paths (webhook router ×2, Gmail, Google Calendar, Google Cloud) and
   every in-process rehearsal (`run_sandbox`, scratch sessions,
   `test_module`, module replay, GraphQL `testModule`) sent none.
   `validate_capability_level` had no production caller.

So an agent whose role or actor ceiling allowed `minimal-node` could compile
a body declaring `automation-node`, have it labelled `minimal`, and run it as
automation in-process or through any hint-less dispatch.

## Decided

- **Compile for a world.** `CompilationService::compile_rust_for_world`
  (and the Rust arm of `compile_to_wasm_with_language_and_world`, which now
  honours `world_override`) holds the compile to the required world: every
  world the source declares must be it (`required_world_declaration` —
  checked before any workspace is made; ALL declarations, so a decoy ahead
  of the real macro does not pass), and the binary is reconciled against it.
  `compile_to_wasm_with_config` keeps the source-declared reference for
  surfaces that checked no world (templates, catalog, imports).
- **Record the binary's world.** `talos_compilation::world_to_record(requested,
  &result)` returns the binary's world (the inspection for Rust; the
  authoritative build world for JS/Python) and refuses one that is unknown or
  not within `requested`. `compile_custom_sandbox`, the inline-compile
  service, hot update and catalog install record through it; `import_workflow`
  records `res.capability_world` (it checked no world, so it records the
  truth rather than the bundle's claim).
- **Run at the hint.** `talos_wit_inspector::link_world(hint, inspection)` is
  the one decision the worker makes before it instantiates: with a hint, the
  binary is inspected and refused if wider (`capability-world-exceeded`, an
  audit-target WARN); with an uninspectable binary, the hint (its linker
  resolves only the hint's imports); with no hint, the inspection (legacy).
  Every production dispatch now sends the module row's world:
  `ModuleExecutionInfo.capability_world` carries it to the push paths; the
  pipeline step sets it from the artifact; each rehearsal passes the world
  its own gate checked (`sandbox::checked_world_hint`).
- **G-17.** `install_module_from_catalog` reads the world through
  `CatalogManifest::parse` (`catalog_install_world`), which refuses a
  manifest with no world or a non-compilable one. The `automation-node`
  default is gone. All 87 manifests in `module-templates/` declare one.
- **G-22.** `target_cache::resolve_for` returns no cache for the nil user;
  such a compile runs cold.

## One home

- Compile-time world rule: `talos_compilation::required_world_declaration`.
- Record rule: `talos_compilation::world_to_record`.
- Link rule: `talos_wit_inspector::link_world`.
- Lint check 99 (`scripts/lint-world-hint.py`): a `JobRequest` /
  `DispatchJob` literal with `capability_world: None` outside tests carries
  `// no-world-hint: <reason>`.

## Measured

- Check 99: 7 hits on `main` @ 59b1081a — the six hint-less dispatch sites
  above and the `DispatchJob` Default impl; 1 after (the Default, marked);
  0 false positives.
- Manifests: 87 of 87 `talos.json` files declare `capability_world`, so the
  G-17 refusal changes no shipped template.

## Mutation proof (authorization gates)

| Gate | Mutation | Test | Verdict |
|---|---|---|---|
| source world vs required | comparison disabled (`&& false`) | `compile_for_world_tests::{a_body_declaring_a_wider_world…, a_decoy_declaration…, the_compile_entry_refuses…}` | FAIL / PASS restored |
| router honours override for Rust | Rust arm passes `None` | `the_compile_entry_refuses_a_body_naming_another_world_before_any_build` | FAIL / PASS restored |
| record within request | `ceiling_permits` against `automation-node` | `the_recorded_world_is_the_binarys_never_wider_than_the_request` | FAIL / PASS restored |
| worker link gate | validation skipped | inspector `a_binary_wider_than_its_hint_is_refused`; worker `capability_world_hint_tests::a_binary_wider_than_its_dispatched_world_is_refused` | FAIL / PASS restored |
| push path sends the hint | Gmail dispatch back to `capability_world: None` | lint check 99 | FAIL / PASS restored |
| G-17 never defaulted | default to `automation-node` restored | `catalog_install_world_tests::*` | FAIL / PASS restored |
| G-22 nil user uncached | nil check removed | `the_nil_user_gets_no_shared_cache` | FAIL / PASS restored |

The worker fixtures are real components built from WAT with the world's
metadata embedded; the secrets-node fixture imports `talos:core/secrets`
(the encoder does not embed the world NAME, so a fixture without a live
import of the world's interface is read as the narrower world).

## Deliberately NOT done

- The chain path's wire step (`PipelineStep`) has no world field, so the
  worker's chain executor still inspects each step. Chain dispatch is
  disabled in every production entry point (G-15); whether the chain path is
  given a signed world/dry-run/actor or deleted is package 15's decision. The
  `DispatchJob` carries the step's world so an adapter that can send it does.
- `JobRequest.capability_world` is not HMAC-bound. Stripping it on the wire
  needs the fleet key (finding B-2, package 5a); with it stripped the worker
  falls back to the inspection, which is the pre-fix behaviour, not worse.
- The scratch-session handler keeps its own inline `#[talos_module]` wrapper
  (a second home for wrapping). The compile-for-world rule makes its world
  enforced regardless; folding the wrapper into the shared one was not needed
  to close the defect.
- The catalog install's secret grant still unions `requires_secrets` with
  `allowed_secrets` (the review's "one key for the grant"). Moving to the
  parser's `requires_secrets`-only reading changes one shipped template
  (`constitutional-refinement` grants `["*"]` under `allowed_secrets` only)
  and would break it; that is a manifest change plus package 11's wildcard
  rule, recorded there.

## Stated limits

- A hint with an uninspectable binary links at the hint; the hint's linker is
  then the only bound (it resolves only the hint's imports).
- Inspection now runs on every hinted job too: one `wasmparser` pass over the
  binary's sections, the same pass the hint-less and chain paths already
  made per job.
