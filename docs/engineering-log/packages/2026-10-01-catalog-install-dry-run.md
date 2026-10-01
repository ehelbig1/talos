# 2026-10-01 — `install_module_from_catalog` can preview what it would store

**Gap.** A reinstall keeps the installed copy's grants "bounded by the new
template's grant", and drops whatever the template no longer grants. Which
grants that would be was only known from the response — after the module that
live workflows use had been replaced. On 2026-10-01 the copy behind 14 nodes
was reinstalled twice on the strength of reading the handler's source.

**Change.** `dry_run: true` returns after the grant decision and before the
compile, the write and the audit record. The reply says what would be stored
(`would_install`), the installed copy's current grants (`current`, `null` on
a first install), whether the three lists differ as sets (`grants_changed`,
`null` on a first install), and what would not be carried
(`grants_not_carried`, `secrets_not_granted`).

**Decisions.**
* **Built from the same value the install writes.** The report takes the
  `InstallGrants` that `grants_for_install` returned, so a preview cannot
  disagree with the install that follows it.
* **Code is not compared.** Whether the copy is behind the catalog is already
  answered by `get_catalog_status → installed_copies` (and by
  `session_start`'s `catalog_drift`); the note says so.
* **No compile in a dry run**, so it answers in milliseconds and takes no
  compile slot.

**Withdrawn from the pain-point list, on reading the code.** "Nothing prompts
when an installed copy is behind": `session_start` has carried a
`catalog_drift` block since the drift report landed (2026-09-29). It was not
seen in the session that raised it because that session's MCP connection was
down. A "reinstall every behind copy" action was considered and not built: a
reinstall replaces code live workflows run, and each one should be a deliberate
call.

**Guards.** `install_dry_run_tests` (a reinstall that drops a secret, an
unchanged reinstall compared as sets, a first install). A source pin in
`install_grants_pin.rs`: the dry-run branch sits after the grant decision and
returns before the compile and the write.

**Stated limit.** The handler branch is pinned textually, not driven (the
handler needs the catalog compiler).
