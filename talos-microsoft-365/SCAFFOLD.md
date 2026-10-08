# Microsoft 365 integration — what is left

`scripts/new-integration.py` wrote this crate, its migration and the
controller shim. This file lists what it did not do. Delete it when the list
is done. The full guide is `docs/adding-an-integration.md`; `talos-google-health`
is the smallest finished example of every step below.

## In this crate

- [x] `src/lib.rs`: every `SCAFFOLD:` comment — the three endpoints, the
      scopes, what makes the provider issue a refresh token, and the fields
      of its account endpoint. `the_provider_endpoints_were_filled_in` fails
      until the endpoints are real.
- [x] Read `migrations/20261008183735_microsoft_365_integrations.sql` and keep or change the columns before it
      is applied anywhere. An applied migration is never edited.

## Wiring in the controller

- [x] `controller/Cargo.toml`: `talos-microsoft-365 = { path = "../talos-microsoft-365" }`.
- [x] `controller/src/main.rs`: `mod microsoft_365;` and a
      `microsoft_365_service: std::sync::Arc<microsoft_365::Microsoft365Service>` field
      beside `google_health_service`.
- [x] `controller/src/bootstrap/services.rs`: build it the way
      `google_health_service` is built
      (`Microsoft365Service::new(db_pool.clone()).with_credentials_service(oauth_credential_service.clone())`).
- [x] `controller/src/bootstrap/router.rs`: two routes, copied from the
      `google_health_*_route` pair —
      `/api/microsoft-365/connect` behind `rest_auth_middleware` + `rest_cookie_csrf_gate`,
      and `/api/microsoft-365/callback` with NO session auth (rate-limited only),
      then merge both.

## Token refresh and revoke (a provider missing from either fails quietly)

- [x] `talos-oauth/src/credentials.rs`: add `"microsoft_365"` to the refresh
      `match provider` (token URL, client id, client secret), and to revoke if
      the provider has a revoke endpoint. Left out of refresh, the connection
      works for one token lifetime and then stops.

## Settings page

- [x] `talos-integrations/src/provider_config.rs`: a `PROVIDERS` entry
      (`id: "microsoft-365"`, `graphql_enum: "MICROSOFT_365"`,
      `db_table: "microsoft_365_integrations"`,
      `account_identifier_column: "COALESCE(t.account_label, 'Microsoft 365')"`,
      `extra_where: "AND t.is_active = true"`,
      `provider_key_column: "provider_key"`,
      `credential_provider: "microsoft_365"`,
      `env_vars: &["MICROSOFT_365_CLIENT_ID", "MICROSOFT_365_CLIENT_SECRET"]`,
      `redirect_path: "/api/microsoft-365/callback"`).
      `list_connections` and the generic disconnect work from this entry.
- [x] `talos-api/src/schema/types.rs`: a `Microsoft365` variant on
      `IntegrationService`, with its arms in `platform/queries.rs`
      (`"MICROSOFT_365" => IntegrationService::Microsoft365`) and
      `platform/mutations.rs`.
- [x] `cd frontend && npm run codegen` and commit `schema.graphql` and
      `src/generated/*`.

## Configuration (lints 89 and 97 fail until these exist)

- [x] `docs/configuration-reference.md`: a row for
      `MICROSOFT_365_CLIENT_ID` / `MICROSOFT_365_CLIENT_SECRET` / `MICROSOFT_365_REDIRECT_URI`.
- [x] `docker-compose.yml` controller `environment:` and the chart's
      controller deployment: the same three, empty by default.

## Lints and tests

- [ ] `scripts/lint-structural.sh`, check 49: add `talos-microsoft-365/src` to the
      integration crate list.
- [x] A controller DB test of the connect flow against a loopback provider,
      modelled on `controller/tests/google_health_connect_tests.rs`: tokens
      stored under the user who started the flow, a URL minted in one browser
      refused in another, reconnect updates the row.
- [ ] `make lint` and the crate's tests pass.
- [x] A setup page (`docs/microsoft-365-setup.md`): where to create the OAuth client
      and which redirect URI to register.
