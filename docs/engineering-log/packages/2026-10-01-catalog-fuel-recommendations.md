# 2026-10-01 — an install says what fuel limit the copy carries, and why

**Context.** A catalog template may declare `recommended_fuel`; a first
install writes that limit. A REINSTALL keeps the copy's own limit unless the
caller passes `fuel_budget` (so an operator's tuning survives — the
2026-07-17 fix).

**Measured on the reference deployment.**
- `Gmail: List Messages` declared no `recommended_fuel`, so a fresh install
  took the generic baseline (~2.2 M). One page at its documented maximum of
  25 messages needs about 2.3 M (1,754,755 fuel for 19 messages, ~92 K each).
- The installed `LLM Inference` copy carries 1,404,000; its template
  recommends 9,900,000. A reinstall kept 1,404,000 and said nothing.
- Every node using either copy sets its own `max_fuel` to get past the module
  limit: 11 of 11 and 18 of 18. The module limit had stopped meaning anything,
  and `test_module` (which enforces it) could not rehearse them.
- 8 of 75 templates declare `recommended_fuel`.

**Change.**
- `gmail-list-messages` declares `recommended_fuel` (25 items × 8 KB × 3 →
  5.85 M). A catalog test pins a template's recommendation to twice its
  measured per-item cost at its documented maximum page.
- `install_fuel_report` (pure): the reply and the dry run carry a `fuel`
  block — `max_fuel`, `source` (`template` | `fuel_budget` | `kept`),
  `template_max_fuel`, and a `note` when a kept limit is below what the
  template now recommends, saying how to adopt it.
- The limit reported by a real install is read back from the write
  (`CatalogInstallResult::max_fuel`), since the value offered is not always
  the value stored. `StoredModuleGrants` carries the stored limit for the dry
  run.

**Deliberately not changed.**
- The keep-on-reinstall rule. Taking `max(kept, recommended)` would also
  raise a limit an operator lowered on purpose; the note leaves the choice
  with them.
- The other 66 templates without a recommendation: none is measured here.
  The calendar template is sized in its own package.
- The system catalog rows' own limits, which nothing executes under.

**Follow-up on the reference deployment (operator's call).** Reinstall
`LLM Inference` and `Gmail: List Messages` with `fuel_budget` set to the
templates' recommendations; the nodes' own overrides then become optional.

**Tests.** Unit: the fuel report (first install, kept above/below, explicit),
the dry-run report carrying it, the tool description. Catalog: the Gmail
template's recommendation covers its maximum page. Database
(`catalog_install_audit_tests`): a reinstall keeps the limit, the result
reports the stored value, an explicit budget moves it up and down.
