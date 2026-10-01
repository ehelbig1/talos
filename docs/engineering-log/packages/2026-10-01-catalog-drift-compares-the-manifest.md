# 2026-10-01 — the installed-copy drift report compares everything a reinstall copies

**Defect.** `get_catalog_status → installed_copies` (and `session_start`'s
`catalog_drift`) classified a copy by comparing its SOURCE with the catalog
row's. A reinstall also copies the catalog row's `config_schema`,
`capability_world` and `requires_approval_for`. A template change that touched
only its schema therefore left the copy reading `current`.

**Observed.** After #1017 documented two LLM Inference config keys (schema
only, source unchanged), the installed copy — used by 16 nodes — read
`current` while its stored schema lacked both keys. A reinstall fixed it.

**Fix.**
* `list_catalog_copy_drift` also compares `config_schema` (jsonb, so key order
  is not a difference), `capability_world` and `requires_approval_for`.
* `CatalogCopyState::of`: `Current` needs the source AND those three to match.
  `Detached` stays a statement about the source: an edited copy whose source
  differs is the user's change; a copy whose source matches and whose schema
  is stale is `Behind`, because a reinstall is what refreshes it.
* Each copy reports `differs_in` — the columns a reinstall would change.

**Not compared, deliberately.** `allowed_hosts` / `allowed_methods` /
`allowed_secrets` and `max_fuel`: a reinstall carries the copy's own, so a
difference there is an operator's narrowing, not staleness.

**Measured.** Live, read-only: 5 installed copies, all match on all four
columns; the statement takes 1.9 ms. No other writer of a copy's
`config_schema` exists (the install is the only one), so a difference cannot
be a deliberate edit.

**Guards.** `catalog_copy_state_tests` (repository), a handler test, and
`controller/tests/catalog_copy_drift_tests::a_copy_with_the_same_source_and_a_stale_schema_is_behind`
on a real database (the statement is built with `format!`, which check 88
cannot see) — with a control that the same schema in a different key order is
not a difference.

**Stated limit.** In OCI mode the catalog row carries no source and the state
stays `unknown`; the manifest is not compared there either.
