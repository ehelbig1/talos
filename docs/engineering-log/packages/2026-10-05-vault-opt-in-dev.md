# Vault is opt-in in the dev compose stack (2026-10-05)

## Measured on the running dev stack

- The controller runs with `KEK_PROVIDER=env` (this file's default; `.env`
  does not set it).
- Both rows of `encryption_keys` are not Vault-wrapped (no `vault:v1:`
  prefix).
- The only code that reads `VAULT_ADDR` / `VAULT_TOKEN` is the Vault KEK
  provider (`talos-secrets-manager/src/vault_kek_provider.rs`) and examples.
  `vault://` paths in workflows name Talos's own secret store in Postgres.
- Prometheus in the dev stack does not scrape Vault.

So `vault`, `vault-init` and `vault-backup` were started by every `make up`
and did nothing.

## Changed

- The three services carry `profiles: ["vault"]`.
- The controller's `depends_on: vault-init` is `required: false`: with the
  profile off the controller starts without it; with it on, the wait applies
  as before.
- To use Vault: `KEK_PROVIDER=vault` and `COMPOSE_PROFILES=vault` in `.env`.

Checked with `docker compose config` against a real `.env`: 22 services
before, 19 by default after, and all three Vault services return with
`COMPOSE_PROFILES=vault`.

## Not changed

- The Helm chart (production) still defaults to Vault; this file is the dev
  stack only.
- The Vault code, its tests and the `vault_data` volume stay. Deleting the
  code is a separate decision, after a period of not missing it.
