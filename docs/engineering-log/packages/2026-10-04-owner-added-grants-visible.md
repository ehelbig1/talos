# The owner-added record is visible where the grants are read

2026-10-04. Completes `2026-10-04-reinstall-keeps-owner-added-grants.md` on
the read side. No write path and no part of the reinstall rule changed.

## The gap

`modules.owner_added_hosts / _methods / _secrets` decide which of a copy's
grants a catalog reinstall keeps. The record was visible in two places only:
the reply of the three `update_module_*` tools, and a reinstall's
`grants_kept_as_owner_added` — that is, while writing it and after acting on
it. Nothing let an owner LOOK at a module and see it.

That matters most for a copy granted before the record existed: it holds
grants beyond its template and an EMPTY record, so its next reinstall drops
them. Measured on the reference fleet on 2026-10-04, before the two were
corrected by hand (that measurement is not repeated here): both such copies had
`allowed_hosts` and `allowed_secrets` set and all three record columns empty.

## Decided

* **`get_module_info` shows the record.** Three lists —
  `owner_added_hosts`, `owner_added_methods`, `owner_added_secrets` — and a
  one-sentence legend, `owner_added_note`. Named after the columns, so a
  reader who greps one finds the other.
* **Always present.** An empty list is an answer ("nothing in this grant is
  recorded as yours, so all of it narrows with the template"), and it is the
  answer that describes the copies at risk. A shared catalog row reads empty
  too: nothing writes a record on one.
* **Shown as stored.** The reinstall rule keeps an entry only when the record
  names it AND the grant list still holds it. The reply does not intersect
  the two; the legend states the condition. Filtering in the reader would be
  a second statement of the rule, and would hide a stale record instead of
  showing it.
* **No new query, no new scope.** `get_wasm_module_info` selects three more
  columns under its existing predicate (`id = $1 AND (user_id = $2 OR user_id
  IS NULL)`). The columns are `NOT NULL`, and a failed decode is an error, not
  an empty record: "nothing recorded" is a claim a reader acts on.

One home: `owner_added_report` + `OWNER_ADDED_NOTE` in
`talos-mcp-handlers/src/modules.rs`; `WasmModuleInfo::owner_added` in
`talos-module-repository`.

## Deliberately NOT done: `grants_a_reinstall_would_drop` in `get_catalog_status`

The second half of the request was one derived signal per installed copy in
the `installed_copies` drift report: the entries a plain reinstall would not
carry, computed by the one rule (`grants_for_install`). It was stopped, not
approximated.

`grants_for_install` takes the template's grant as its input, and "the
template's grant as the install derives it" is not a function. It is a run of
`let` bindings inside `handle_install_module_from_catalog`:

* which entry the key names — a shared registry row, else the template baked
  into the image (`InstallSource`), resolved inline;
* the capability world — the manifest's, else the `#[talos_module(world =
  …)]` attribute in the template SOURCE, else `automation-node`;
* hosts — the manifest's `allowed_hosts` when it is an array, else
  `default_allowed_hosts_for_world(world)`;
* verbs — the manifest's `allowed_methods`;
* secrets — `requires_secrets ∪ allowed_secrets`;

interleaved with the caller's arguments and the role gate. The drift report
cannot call it. The two ways to get the value anyway are both ruled out:

* **Copy those bindings into the drift report.** A second derivation of "the
  template's grant" — the thing the previous package rejected by name.
* **Read the shared catalog row's grant columns**, which the drift query
  already joins. That row and the handler disagree (a manifest with no
  `allowed_hosts` is `[]` in the row and `["*"]` by world default in the
  handler; secrets are `requires_secrets` in one and the union in the other),
  so the signal would report drops a reinstall does not make, and miss ones
  it does.

**The smallest refactor that unblocks it** (not done here: it edits the
install handler, a write path):

1. Extract the template-only bindings into one pure function, e.g.
   `template_grant(manifest, source) -> { capability_world, hosts, methods,
   secrets }`, called by the install handler before it applies the caller's
   arguments.
2. Extract the source resolution (`find_shared_registry_entry`, else
   `resolve_catalog_template_dir` + `CatalogTemplate::load`) into one function
   returning `InstallSource`.
3. Give `list_catalog_copy_drift` the copy's three grant lists and three
   record lists (same statement, same `user_id` predicate).
4. In the report, per copy: `grants_for_install(Some(&stored), g.hosts,
   g.methods.clone(), g.secrets, false, false, &g.methods).not_carried`.

Three things that refactor has to settle, found while reading for it:

* **N+1.** `find_shared_registry_entry` reads one key per call; over every
  installed copy that is one query per copy. It needs a batched form.
* **The disk read is not cheap or always possible.** The world can come from
  the template's source text, so the template file is read too; and the
  report must say "not computed" for a copy whose template cannot be read,
  never an empty list (an empty list reads as "a reinstall drops nothing").
* **Which row a reinstall lands on.** The install finds the installed copy by
  display name (the caller's `display_name`, else the manifest's, else the
  key). A copy installed under its own `display_name` is reached only by a
  reinstall that passes that name again; the drift report maps a copy to its
  template by `catalog_slug`. "A plain reinstall" has to be defined as
  "by slug, with this copy's name".

Until then the per-copy answer exists, from the one rule, without writing:
`install_module_from_catalog` with `dry_run: true` returns `grants_not_carried`
and `grants_kept_as_owner_added`. The `get_module_info` description now says
so. `get_catalog_status` and its description are unchanged.

## Tests

* `talos-mcp-handlers`, `owner_added_report_tests` (3): each list under its
  own key; nothing recorded is three empty lists, not missing fields; the
  legend states both halves, names the three tools, and is one sentence.
* `controller/tests/owner_added_grants_tests.rs` (2 added, real database,
  through the real tool):
  `module_info_shows_which_grants_the_owner_added` — the repository read
  equals what the writers stored; the reply carries the lists and the legend;
  an inherited verb is in the grant and not in the record; another user gets
  neither the module nor its record.
  `nothing_recorded_reads_as_three_empty_lists` — a copy with grants and no
  record, and a shared catalog row.

One mutation, because the tests exist to cover the handler's call site:
removing the `owner_added_report` merge from the handler fails both database
tests; restored, 5 of 5 pass. No security gate changed, so no others were run.

## Stated limits

* The reply's JSON keys are sorted (this build of `serde_json` does not
  preserve insertion order), so the three lists and the legend appear
  together under `owner_added_*`, not interleaved with `allowed_*`. In the
  handler source they sit with the grants.
* `get_module_info` has a second branch (`get_node_template_info_for_user`)
  that was not given the fields. It reads the same table under the same
  predicate as the first, so it answers only if a row appears between the two
  reads; it does not report `allowed_methods` either.
* The record can be stale (other writers of the grant columns do not maintain
  it — the previous package's limit). A stale entry is shown as stored; the
  legend's "for as long as the grant list still holds it" is what covers it.
* `list_modules`, the GraphQL module types and the frontend do not show the
  record.

## Not verified

* Not run against a live controller: no `get_module_info` call was made on
  the reference fleet, and the two legacy copies named above were not
  re-read.
* The claim that the fallback branch is unreachable is from reading the two
  queries, not from a test.
