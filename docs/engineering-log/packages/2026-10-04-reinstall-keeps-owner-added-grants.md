# A reinstall keeps what the owner added

2026-10-04. Revises one stated limit of `2026-09-29-reinstall-keeps-grants.md`
on a new fact; the rest of that package stands.

## The gap, live

The 2026-09-29 rule: on a reinstall, a copy's stored grant is kept only
within the new template's grant. Its stated limit: "a deliberate operator
WIDENING beyond the template is dropped on reinstall and reported, not kept."

Since 2026-10-03 the catalog has templates that install with NO host and NO
secret on purpose (`json-api-reader`, `notify-*`, `control-*`): the owner
grants the one host and the one token. For those, every entry is beyond the
template, so every reinstall wiped the copy back to reaching nothing.
Measured 2026-10-04: reinstalling `control-home-assistant` to pick up a fix
dropped its host and its token grant; the reply said so, and both had to be
put back by hand. A workflow using the copy would have failed until someone
did.

## Decided (operator, 2026-10-04)

Remember which grants the owner added, and carry those across a reinstall.
What a copy inherited from its template still narrows with the template.

## What changed

* **Three columns** on `modules`: `owner_added_hosts`, `owner_added_methods`,
  `owner_added_secrets` (migration `20261004160000`).
* **The one permission writer records them.**
  `set_module_permission_recorded` locks the row, computes the record with
  `owner_added_after`, and writes the list and its record in ONE statement.
  The `admin_event_log` record and the tool's reply both carry
  `owner_added`.
* **The one install rule keeps them.** In `grants_for_install`, an entry the
  template bound drops is kept when the copy's record names it, and reported
  under `grants_kept_as_owner_added`. The record is written back beside the
  lists by `install_catalog_copy`.

## The rule, exactly

An entry of a grant list is the owner's when the owner put it there with an
`update_module_*` tool (or passed it as an extra verb to an install) and the
INHERITED part of the list at that moment did not already grant it. The
inherited part is the previous list without the owner's own entries.

* Narrowing inside what the template granted is not an addition. A copy
  pinned from `oauth/gmail/*` to one account's path still loses that path
  if the template stops granting gmail tokens — the 2026-09-29 guarantee.
* The owner's own wide entry does not vouch for a narrower one that
  replaces it: the narrower one is recorded.
* An entry stays the owner's until an update removes it from the list.

"Did not already grant it" uses the three matchers the bound already uses
(`carry_host_grant`, `carry_method_grant`, `vault_path_permitted`), passed
to the repository as a function so that crate gains no matcher of its own.

## What a reinstall can and cannot do now

* It can keep an entry the copy holds, the template does not grant, and the
  record names.
* It cannot ADD anything. Only entries that came out of the stored list are
  candidates, so a stale or wrong record grants nothing; and the install
  writer refuses a record that names an entry outside the list it is
  written with.
* The owner could already write any host or path into a copy with
  `update_module_*`; this keeps what they wrote, and widens nothing they
  did not.

## Considered and rejected

* **Compare against the template when the owner writes.** The shared
  catalog row and the install handler derive "the template's grant"
  differently (a manifest with no `allowed_hosts` is `[]` in the row and
  `["*"]` by world default in the handler; secrets are `requires_secrets`
  in one and `requires_secrets ∪ allowed_secrets` in the other). A second
  derivation is a second rule. The previous list is local, locked, and
  needs no lookup.
* **Backfill existing copies.** Which of a copy's entries the owner added
  was never recorded. Inferring it (for example "the template grants
  nothing, so everything is the owner's") would mark an entry a template
  later removed as the owner's. No backfill: an existing widening is dropped
  once more on its next reinstall, reported, and recorded when the owner
  sets it again.

## Tests

* `talos-module-repository`: `owner_added_after`, 5 cases.
* `talos-mcp-handlers`: the live case; inherited entries still narrow; a
  record naming an entry the copy does not hold grants nothing; passed verbs
  are recorded and kept; the three "beyond" functions.
* `controller/tests/owner_added_grants_tests.rs` (real database): recorded
  with the grant, in the audit record, untouched by another user, kept
  across a reinstall, removed with the entry; an inherited entry is never
  recorded; a record outside its list is refused.
* `privilege_audit_record_tests`: through the real tool, the reply and the
  audit record carry `owner_added`.

Mutations, each killed and restored:

| Mutation | Test that failed |
|---|---|
| every dropped entry is kept | `an_inherited_entry_still_narrows_with_the_template` (+3) |
| the record adds entries the copy did not hold | `a_record_naming_an_entry_the_copy_does_not_hold_grants_nothing` |
| the record may name entries outside the new list | `the_record_is_always_within_the_new_list` (+2) |
| the owner's own entries vouch for new ones | `the_owners_own_wide_entry_does_not_vouch_for_a_narrower_one` |
| the install writer accepts a record outside its list | `a_record_that_names_an_entry_outside_its_list_is_refused` |

## Stated limits

* Existing copies have no record. Re-applying the SAME list records nothing
  (every entry is already held); the owner clears the list and sets it
  again, or sets it after the next reinstall has dropped it.
* Other writers of the grant columns (`hot_update_module`,
  `compile_custom_sandbox`) do not maintain the record. A record that has
  gone stale is harmless by the rule above, and is corrected by the next
  `update_module_*` or install.
* Read-then-write on a reinstall is still not atomic (2026-09-29's limit).
