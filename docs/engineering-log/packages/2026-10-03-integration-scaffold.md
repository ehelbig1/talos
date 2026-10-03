# A scaffold for new OAuth integrations

2026-10-03

## Why

Google Health and the Plaid connection each took several changes across the
same places: a crate, a table, two handlers, the provider registry, the
GraphQL enum, routes, service wiring, configuration in three files, the
refresh and revoke lists, a lint's crate list. `docs/adding-an-integration.md`
describes all of it; nothing wrote any of it.

## What it is

`scripts/new-integration.py <id> "<Display Name>"` writes:

* the crate `talos-<id>` — service, redacting `Debug`, the `OAuthIntegration`
  impl (code exchange through the hardened client and the capped body read,
  account lookup, row first then tokens, the hide-on-failure compensation),
  the connect and callback handlers, and unit tests;
* a migration for `<id>_integrations`;
* the controller re-export shim;
* one line in the workspace member list;
* `SCAFFOLD.md` in the crate: every remaining edit, as a checklist.

Templates live in `scripts/integration-scaffold/`.

## Decisions

* **Shared files are listed, not edited.** The registry entry, the GraphQL
  enum and its arms, the routes, the service wiring, the refresh and revoke
  lists and the configuration rows are each a few lines in a file many things
  read. An anchor-based edit there is the kind that silently lands in the
  wrong place; a checklist with the exact lines is slower and cannot.
* **The scaffold is built in CI.** `--self-test` generates a throwaway crate,
  runs clippy `-D warnings` and its unit tests, and removes it, restoring
  `Cargo.toml` and `Cargo.lock` byte for byte. It runs as a step of the clippy
  job (every dependency of the probe is already built there) and as
  `make test-integration-scaffold`. A change to the scaffold alone counts as a
  Rust change (`scripts/ci-changed-areas.sh`). A template nothing builds rots
  with the first change to a crate it uses.
* **Not a template crate in the workspace.** A compiling example crate would
  carry SQL for a table that does not exist, which structural check 88 (every
  static statement must PREPARE) rightly refuses.
* **One generated test is meant to fail**: `the_provider_endpoints_were_filled_in`
  fails while the endpoints are the scaffold's placeholders. The self-test
  skips it and separately asserts that it fails, so the guard cannot be
  quietly removed from the template.
* **The account id is checked before it keys a credential.** The provider's
  account id becomes a vault-path segment; one that is empty, long, or holds
  a `/` is refused (`provider_key_for`).
* **The id and display name are validated** (kebab-case id; a display name
  with no quote, brace, backslash or `--`), because both are written into
  Rust string literals and SQL comments. An id that is already a crate, a
  provider or a migration is refused.
* **Generic OAuth, not Google-specific.** A Google integration on the shared
  client has extra rules (shared client, account-id derivation, revoke only
  for the account's last connection); the guide's step 7 covers them and the
  scaffold does not attempt them.

## Measured

* The self-test passes: the generated crate is clippy-clean, its five unit
  tests pass, and the placeholder test fails as designed.
* One real generation (`acme-crm`), by hand: its migration applied to a clone
  of the migrated schema and both of the crate's SQL statements PREPAREd
  against it. Everything it wrote was then removed.

## Stated limits

* The scaffold covers the connect flow. A push-notification integration
  (watch channels, webhooks) is `docs/integration-pattern.md` and is not
  generated.
* The migration and the crate's SQL are checked against the schema once, by
  hand, not by the self-test (which has no database).
* `SCAFFOLD.md` is prose: nothing verifies that the checklist is complete, or
  that a person finished it. Lints 49, 89 and 97 catch three of its items.
