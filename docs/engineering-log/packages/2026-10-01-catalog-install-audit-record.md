# 2026-10-01 — a catalog install is recorded, in the install's own transaction

**Defect.** `install_module_from_catalog` replaces a module's code and can
replace its capability world and all three grant lists, and it wrote nothing
to `admin_event_log`. The 2026-09-19 privilege-audit package (CT) made the
three permission setters, `hot_update_module`'s world change and the inline
compile record in their own transactions; the install path was the one
module-grant writer it did not reach. Observed 2026-10-01: a reinstall of
`LLM Inference` (the module behind 14 live nodes) left no row. `admin_event_log`
held 10 `module_allowed_methods_updated` and 3 `module_allowed_secrets_updated`
rows and no install row of any kind.

**Why it matters.** A reinstall keeps the installed copy's grants unless the
caller passes new ones, and a caller-passed `allowed_secrets: ["*"]` means the
template's whole grant. So a module's secret grant could be widened, used and
narrowed again through this tool with no durable trace.

**Fix.** `ModuleRepository::install_catalog_module_to_modules` (one caller:
the MCP handler) now runs in a transaction: it locks the row it is about to
overwrite, performs the same upsert, and inserts one record through
`talos_admin_event_log::insert_on_conn` before commit.
* `module_installed_from_catalog` — a first install: slug, capability world,
  the three grant lists, content hash.
* `module_reinstalled_from_catalog` — the same plus every value it replaced
  (`previous_<field>`), and `code_changed` / `grants_changed`. The summary
  names a capability-world change in words.

The record is built by the pure `catalog_install_record`.

**Decisions.**
* **Every install is recorded, including one that changes nothing.** Installs
  are operator acts with one caller, so the volume is a handful of rows, and
  "an install ran and changed nothing" is itself the answer to "did the
  redeploy reach this module".
* **An install that cannot be recorded does not happen** (CS's rule for every
  privilege change).
* **Grant lists are stored as written**, as the three permission setters
  already store them. A vault path can contain an account address
  (`oauth/gmail/<user>/<address>/…`); the table is read per tenant and its
  writer applies DLP redaction to credential-shaped values, not to paths.
  Stated, not changed.

**Not changed.** `hot_update_module` still records only a capability-world
change, not a plain code change. The system catalog seeding at boot (which
writes `user_id IS NULL` rows through a different function) records nothing.

**Guards.** `controller/tests/catalog_install_audit_tests` (database): a first
install, a widening reinstall and an identical reinstall each write exactly
one row with the right previous values; with `admin_event_log` unavailable a
reinstall leaves code and grants untouched and a first install leaves no row.
Both tests fail on the unfixed repository code. Two unit tests on
`catalog_install_record` (a world change is named and is not a grant change;
each grant list and a missing hash count as changes).

**Stated limits.** The handler's call into the repository function is not
driven by a test (it needs a compile); the record lives inside the function
it has always called, and that function has no other caller.
