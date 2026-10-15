# One gate for everything that compiles or grants, and a gold label is a class (2026-10-15)

Security review 2026-10-15 (round 2), findings **A2-1**, **A2-2**, **G2-1**,
**I2-1** (Medium), **A2-3** (Low), **I2-5** (Info), and the carried-over
**C-8** (operator decision D2-D). Package R4 of the round-2 remediation.

## The defects, as verified

- **A2-1.** The bearer `*`-grant rule lived in `sandbox.rs`'s private
  `refuse_bearer_grant`, called by `compile_custom_sandbox` and `run_sandbox`,
  and in the repository's `set_module_permission_recorded`, reached only by
  the three `update_module_allowed_*`. `add_node_to_workflow`'s inline compile
  (`InlineCompileService::compile_and_persist`) wrote `allowed_secrets`
  verbatim and gave a network world `allowed_hosts = ["*"]` by default
  (`resolve_default_allowed_hosts`); `create_workflow_from_spec` refused `*`
  hosts and wrote `allowed_secrets` unchecked.
- **A2-2.** `add_node_to_workflow`'s inline path called no
  `require_world_permitted`: only the workflow's bound actor's ceiling applied,
  and an actor-less workflow has none.
- **G2-1.** `import_workflow` compiled a bundle module with
  `compile_to_wasm_with_config` at whatever the source declared, and asked
  neither the role nor the user ceiling.
- **A2-3.** `update_module_secrets` accepted `svc/*` from a bearer; the
  marketplace install already refused `/*` from another publisher.
- **I2-1.** A `human_confirmed` distill item became a gold `correction` row
  after trim and length checks only; the operator path
  (`ml_resolve_disagreement`) refuses a label outside the dataset's classes.
- **I2-5.** A tap and an operator correction were indistinguishable at rest.

## Partly refuted: the bare-prefix half of A2-3

The review asks that a bearer also be refused "any bare-prefix entry" (`svc`).
`vault_path_permitted` treats EVERY entry as a prefix — an exact path `a/b`
also permits `a/b/c` — so a "bare prefix" and an exact path cannot be told
apart by their text, and a bare OAuth namespace (`oauth/gmail`) beside a
`vault://` reference in node config is the platform's documented grant for
every OAuth module (`vault_path_prefetched`'s doc). Refusing it would end MCP
authoring of OAuth modules. What a bearer may not write is the WILDCARD forms:
`*` and the explicit `<prefix>/*` glob. The per-path rule (only a path a
secret is stored at) stays the one recorded as not built
(`2026-10-14-loosening-needs-a-second-factor.md`).

## Decided

- **One grant rule: `talos_capability_world::refuse_wildcard_grant(authority,
  secrets, hosts)`** — for a caller that may not loosen, no `*` in either list
  and no `<prefix>/*` in `allowed_secrets` (`secret_grant_list_has_wildcard`).
  `refuse_bearer_grant` (sandbox), the repository write and the inline-compile
  service all ask it. The marketplace install keeps its own G-24 rule (`/*`
  refused only from another publisher).
- **The inline-compile service holds the grant, before it compiles.**
  `InlineCompileInput` carries `authority`; `compile_checked` — which both
  callers reach — resolves the grant (`resolve_grant`) and refuses
  (`InlineCompileError::GrantRefused`, `-32003`). Both MCP callers pass
  `BearerCredential`; `CreateFromSpecRequest` carries it too, so the service
  is not told who is asking by assumption.
- **No every-host default for a bearer.** `resolve_default_allowed_hosts`
  takes the authority; a network world with no explicit list is
  `HOSTS_MUST_BE_NAMED` for a bearer. A second-factor session still receives
  `["*"]`.
- **`create_workflow_from_spec` refuses a `*` or `<prefix>/*` secret** in the
  spec, the twin of its existing `*` host rule (authority-free: a spec grants
  by name).
- **The world gate on both remaining compile surfaces.**
  `add_node_to_workflow` calls `require_world_permitted` as soon as the inline
  path is chosen. `import_workflow` now follows the CLAUDE.md rule for a
  surface that gates a world: the module's label is the bundle's
  `capability_world`, else the source's first declared world
  (`talos_compilation::source_declared_world`), else `minimal-node`; that label
  is held to the role and user ceiling BEFORE the compile, the compile is
  `compile_rust_for_world(label)`, and the row records
  `world_to_record(label, &res)`. A refusal stops the import before that
  module's row. Until then the import recorded the truth (G-1) but asked
  nobody (G-3 b).
- **A tapped label is a class (I2-1, operator decision D2-C — recommended
  option built).** `process_distill` loads the dataset's vocabulary in its
  resolve transaction (`DatasetService::label_vocabulary`, the source
  `correction.rs` uses) and drops each `human_confirmed` item whose label is
  not in it (`keep_known_human_labels`, the operator path's
  `label_in_vocabulary` — an EMPTY vocabulary accepts anything, so the first
  label of a new dataset lands). Counted and logged with the model and a
  count, never the label text. Model labels are not checked: their
  disagreement flow catches them.
- **A tap says so at rest (I2-5).** `AppendExample.origin`, rendered as
  `label_json.origin = "tap"` (`dataset::TAP_ORIGIN`) for a human-confirmed
  distill item; `None` otherwise, an operator correction included. A key in
  the JSON: no migration, no reader change.
- **C-8 (operator decision D2-D) — the narrow option, as built by A-2 + A2-1:**
  a second-factor session may write `allowed_secrets = ["*"]`; no bearer
  credential may, on any writer. The full option — refuse `*` secrets for
  every authority at the repository write — is the operator's to take; it
  would end the one remaining way to give a module every stored secret.
  `security_audit` reporting the count of modules holding `{*}` was not built
  in this package (stated below).

## Every production compile / grant site, enumerated

`scripts/lint-compile-gate.py` (check 106) enumerates the calls of
`compile_and_persist`, `compile_checked`, `compile_to_wasm_with_config`,
`compile_to_wasm_with_language_and_world`, `compile_rust_for_world`,
`compile_catalog_template`, `update_module_allowed_secrets` and
`update_module_allowed_hosts` outside `talos-compilation` and outside test
items, and requires a world gate (`require_world_permitted` /
`require_grant_edit_permitted`) and a grant gate (`refuse_wildcard_grant` /
`refuse_bearer_grant`) in the calling function, or a
`// compile-gate-elsewhere: <where>` marker. 17 sites:

| Site | World gate | Grant gate |
|---|---|---|
| `compile_custom_sandbox`, `run_sandbox` (sandbox.rs) | in the function | in the function (`refuse_bearer_grant`) |
| `compile_template` (sandbox.rs), `createModuleFromTemplate` (GraphQL) | in the function / the mutation's ceiling check | marker: the template's own grants |
| `update_module_secrets` / `_hosts` (sandbox.rs) | `require_grant_edit_permitted` | marker: the repository write (`refuse_wildcard_grant`) |
| `add_node_to_workflow` (workflows.rs) | in the function (new, A2-2) | marker: `compile_checked` → `resolve_grant` (new, A2-1) |
| `import_workflow` (workflows.rs) | in the function, before the compile (new, G2-1) | marker: no grant written |
| `create_workflow_from_spec` → `compile_checked` (spec.rs) | marker: the handler's per-world gate | marker: `resolve_grant` |
| inline-compile service internals ×2 | marker: each caller | marker: `resolve_grant` |
| `run_scratch_session` (advanced.rs) | marker: `validate_scratch_world` | marker: no module grant |
| `install_module_from_catalog` (modules.rs) | in the function | marker: the manifest's grants |
| `restore_pinned_modules` (modules.rs) | in the function (**new — found by this enumeration**: it compiled with no role or ceiling check) | marker: bytes only |
| hot update service | marker: the handler's gate | marker: no grant change |
| controller CLI publish, boot catalog seed | marker: no user | marker: the manifest's grants |

## Tests

- `talos-capability-world`: `wildcard_grant_tests::a_bearer_writes_no_wildcard_grant`.
- `talos-workflow-creation-helpers`: the `resolve_default_allowed_hosts` tests,
  including `…_only_for_a_session`.
- `talos-ml`: `distill::tests::a_tapped_label_outside_the_vocabulary_is_dropped`.
- `controller/tests/module_grant_bearer_tests.rs`:
  `an_inline_node_takes_no_wildcard_grant_from_a_bearer` (`*` secret, `svc/*`
  secret, `*` host, and an http world with no hosts — all refused, no module
  row, no graph change; and a spec with a `*` secret),
  `an_inline_node_is_compiled_within_the_users_ceiling` (ceiling and role),
  `an_imported_module_is_compiled_within_the_users_ceiling` (the bundle's
  world and a source's declared world, both above the ceiling; a role below;
  no module row, no workflow), `a_bearer_writes_no_secret_glob`
  (`update_module_secrets` and the repository; a second-factor session writes
  it; a bare namespace is written).
- `controller/tests/ml_human_confirmed_label_tests.rs`: a tap naming a
  phantom class is dropped while a tap naming a class lands; a tap's
  `label_json.origin` is `"tap"`, a model's has none.
- `lint-compile-gate.py --self-test`.

## Mutation proof

Each against `controller/tests/module_grant_bearer_tests.rs` (whole binary)
or `ml_human_confirmed_label_tests.rs`, restored and re-run green after.

| Gate | Mutation | Test(s) that failed | Verdict |
|---|---|---|---|
| grant rule in the inline service | `refuse_wildcard_grant` call removed from `resolve_grant` | `an_inline_node_takes_no_wildcard_grant_from_a_bearer` | FAIL / PASS restored |
| no every-host default for a bearer | `resolve_default_allowed_hosts` ignores the authority | `an_inline_node_takes_no_wildcard_grant_from_a_bearer` | FAIL / PASS restored |
| `add_node_to_workflow` world gate | the gate asked of `minimal-node` instead of the node's world | `an_inline_node_is_compiled_within_the_users_ceiling` | FAIL / PASS restored |
| `import_workflow` world gate | the gate asked of `minimal-node` instead of the label | `an_imported_module_is_compiled_within_the_users_ceiling` | FAIL / PASS restored |
| `<prefix>/*` is a wildcard | `secret_grant_list_has_wildcard` matches `*` only | `a_bearer_writes_no_secret_glob`, `an_inline_node_takes_no_wildcard_grant_from_a_bearer` | FAIL ×2 / PASS restored |
| spec secrets twin | the spec's `allowed_secrets` refusal disabled | `an_inline_node_takes_no_wildcard_grant_from_a_bearer` | FAIL / PASS restored |
| tapped label is a class | `keep_known_human_labels` keeps every item | `a_human_label_is_gold_only_from_a_run_an_action_link_started` | FAIL / PASS restored |
| check 106 | its `restore_pinned_modules` and `add_node` gates removed would be named (self-test covers a missing world gate, a missing grant gate, both, a nested `fn`, a site after a test module) | `lint-compile-gate.py --self-test` | — |

`restore_pinned_modules`' new world gate is NOT mutation-proven: the handler
reads catalog templates from the fixed path `/app/module-templates`, so a test
cannot reach the gate (every test install stops at "no catalog template
matches"). Stated, not hidden.

## Deliberately NOT done

- The bare-prefix refusal (above).
- A `security_audit` count of modules holding `allowed_secrets = {*}` (C-8's
  exposure report): left for the operator's D2-D answer, which decides whether
  the count is a standing report or a migration's worklist.
- No backfill of `label_json.origin` on existing correction rows: which of
  them were taps is not recorded anywhere.

## Stated limits

- Check 106 is textual: a gate's result is not checked, and a marker's reason
  is not verified.
- `import_workflow` with a bundle whose source declares a world different from
  the bundle's stated one is refused by `compile_rust_for_world`
  (world-mismatch), where until now it was compiled and recorded wide.
