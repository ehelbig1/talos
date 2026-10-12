# 2026-10-12 — the integration scaffold has a Google flavour

**Why.** A write scope for Google Calendar had to be a connection of its own
(`2026-10-11-google-calendar-write-connection.md`). `scripts/new-integration.py`
wrote a generic crate — its own client id and secret, an account id taken as
the provider gives it, three endpoints to fill in — which was then replaced
by hand with a copy of `talos-google-health`, because none of that is the
Google shape. The checklist it left listed the generic shared edits and not
the Google ones, two of which fail quietly when missed.

**Decided.**
- **`--google`**, a second template set under
  `scripts/integration-scaffold/google/`, generated from
  `talos-google-calendar-write` (the newest Google connection) by name
  substitution, with the scope-specific parts made a placeholder:
  `REQUIRED_SCOPE`, refused-without (`ConnectRefusal::NoRequiredScope`,
  shown as `scope_not_granted`), and a test, `the_scope_was_filled_in`, that
  fails until the scope is real. The crate has the shared Google client, the
  shared account-key derivation, `account_email`, and the row written before
  the tokens with the compensating hide.
- **Its `SCAFFOLD.md` lists the Google-specific shared edits**:
  `GOOGLE_SHARED_CLIENT_PROVIDERS` and `GOOGLE_REVOKE_PROVIDERS` and the
  `active_google_connections` arm in `talos-oauth` (missing the first, the
  token is never refreshed; missing the arm, the connection cannot be placed
  on an account and WITHHOLDS the revoke of every other Google disconnect),
  the shared-grant test, the redirect URI on the shared client, the registry
  entry with `account_email_column`, and one configuration variable instead
  of three.
- **A flavour is a template directory and its placeholder test** (`FLAVOURS`).
  A template the flavour does not have falls back to the generic one (the
  controller shim). The generic flavour's output is unchanged.
- **The self-test builds both flavours** (clippy `-D warnings`, the unit
  tests, and that the placeholder test FAILS on an unedited scaffold), so a
  change to `talos-oauth` that breaks the Google shape is found in CI.

**Measured and not done.**
- **A format check in the self-test.** Tried: it fails on the GENERIC
  flavour too, because where rustfmt wraps a line depends on the names
  substituted into it. The Google checklist's first item is `cargo fmt -p`.
- **Formatting the crate at generation.** It would change what the generic
  flavour writes; left for whoever wants it.
- **Editing the shared files.** As for the generic flavour, they are listed
  and not edited: those edits need a reader.

**Not done, by instruction.** The "scoped connection" kind in the provider
registry (same client, a named scope set, its own vault namespace), which
would make a new scope set a registry entry and a migration, is written up
as a proposal only.

**Tests.** `make test-integration-scaffold`: both flavours generated, built
and tested, and each placeholder test fails on the unedited crate.

**Not verified, stated.** No real integration was generated and carried
through its checklist with this flavour, so the checklist is the last Google
connection's list of files read back, not a list proved complete by use. The
template is a copy at a point in time: a later fix to
`talos-google-calendar-write` is not carried into it by anything.
