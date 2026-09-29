# 2026-09-29 — installed catalog copies drift silently

**Found live** while fixing the fuel ledger. The seeder refreshes the SYSTEM
catalog row (`modules.user_id IS NULL`, `kind = 'catalog'`); a user's
installed copy is a separate row that workflows reference by id, and nothing
refreshes it. Measured on the reference fleet: 5 of 8 installed copies had
drifted. Two were live: the user's LLM Inference (14 non-archived workflows)
and Hybrid Classify (Alerts) (1) were missing the 2026-09-10 prompt-injection
hardening (`<agent_memory>` described as authoritative; no closing-tag
neutralisation). Both were reinstalled on 2026-09-29 with operator approval.
Three GCP copies are behind with no workflow using them. Nothing reported any
of it.

The seeder does try to refresh user copies (`REFRESH_CATALOG_WASM_BY_SLUG_SQL`,
a compare-and-set on `content_hash`), but that hash is SHA-256 of the compiled
WASM and every compile yields different bytes, so it effectively never
matches, and it would not refresh `source_code` or grants if it did.

**Decided.**
- **Report, don't auto-refresh.** Refreshing a copy changes what live
  workflows run; that is the operator's call. The report says what is behind
  and what a reinstall does. The reinstall keeps the copy's grants since
  package `2026-09-29-reinstall-keeps-grants` (#989), which is why this ships
  after it.
- **Source is the comparison.** A copy stores the template text verbatim, so
  `source_code` equality is exact; `content_hash` cannot be used (above).
- **Five states, one classifier** (`talos_module_repository::CatalogCopyState`):
  `current`, `behind`, `detached` (edited in place with `hot_update_module`,
  so a difference is deliberate), `unknown` (the catalog row has no source:
  OCI mode, where the registry sync writes `source_code = ''`) and
  `not_in_catalog`. An unknown comparison is never reported as current; a
  copy hot-updated back to the catalog text is current.
- **One read**, `ModuleRepository::list_catalog_copy_drift`: the user's copies,
  each beside its catalog row matched by `catalog_slug`, else by `name` for
  copies installed before the slug existed, plus the count of the user's
  workflows that are not retired (`talos_workflow_liveness::not_retired_sql`)
  and use the copy. Measured 2.3 ms on the reference fleet.
- **Two surfaces.** `get_catalog_status` gains `installed_copies` (a count per
  state, every copy with its state and live-workflow count, most urgent
  first) and a tip naming the behind copies, used ones first, and what a
  reinstall keeps. `session_start` gains a compact `catalog_drift` field,
  because nobody asks `get_catalog_status` a question they do not know to
  ask. Both render `null` when the read fails, never an empty list.

**Proof.** Unit tests: every classifier state and its precedence; the
rendering's counts and urgency order; the tip fires only when something is
behind, names used copies first and does not treat a deliberate edit as a
finding; the session summary. A database test on a real clone drives the
production read over one copy per state (including a slug-less legacy copy
matched by name, an OCI-style catalog row with no source, and an orphan) and
checks the workflow count excludes archived workflows and other users'
workflows. Run live, read-only, the same query reproduces the 2026-09-29
measurement exactly.

**Stated limits.**
- **OCI mode reports `unknown`.** A copy there records no installed-from
  digest, so drift cannot be determined; recording one is a schema change for
  a mode this fleet does not run.
- **Only copies written by `install_module_from_catalog`** (`kind = 'catalog'`)
  are covered. `compile_template`, GraphQL `createModuleFromTemplate` and
  marketplace installs write `kind = 'sandbox'` rows with no slug and no
  recorded template, so they cannot be traced to a catalog entry.
- The live-workflow count matches the module id textually in `graph_json`,
  the same rule `find_referenced_modules_in_workflows` uses; its cost scales
  with copies × the user's workflows.
- No metric and no alert: drift is per user and the fix is an operator
  action, so the report is the surface.
