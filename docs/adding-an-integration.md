# Adding an integration

The single authoritative guide for adding a third-party integration (Slack,
GitHub, Jira, a new OAuth provider, a push-notification source, …) to Talos so
it follows every hardening practice **by construction**. If you follow this and
the lint checks pass, your integration is tenant-isolated, credential-safe,
SSRF-safe, and OOM-bounded without you having to re-derive any of it.

> This folds together the older `OAUTH_SETUP.md`, `GMAIL_INTEGRATION.md`, and the
> push-notification `integration-pattern.md` (still the deep reference for the
> 10-file watch/webhook shape). Read `integration-pattern.md` *in addition* to
> this only if your integration receives push notifications.

## TL;DR — the toolkit (never hand-roll these)

| Concern | Use | Never |
|---|---|---|
| HTTP client to a fixed provider host | `talos_http_utils::trusted_client::{build_integration_client, hardened_client_builder}` | raw `reqwest::Client::builder()` (lint 49) |
| HTTP client to a **user-supplied** URL | `talos_http_utils::outbound::build_outbound_webhook_client*` (+ `check_outbound_url_no_ssrf`) | anything without the SSRF resolver (lint 40) |
| Reading a response body | `talos_http_body::read_json_capped` / `read_error_text_capped` | bare `.json()/.text()/.bytes().await` (lint 31) |
| OAuth authorize + callback | `talos_oauth::OAuthIntegration` + `authorization_url` / `handle_oauth_callback` (or the `begin_oauth_authorization` / `consume_oauth_state` primitives) | re-implementing PKCE / CSRF state / `used=true` consume |
| Storing / resolving OAuth tokens | `talos_oauth::OAuthCredentialService` (path `oauth/<provider>/<user_id>/<key>`) | inline `INSERT`s or a bespoke token table |
| Per-user watch / cursor state | `talos_integration_state` (keyed `(integration_name, user_id, key)`) | a bespoke, un-scoped table |
| Inbound webhook token lookup | `WHERE token_hash = sha256_hex(provided)` + constant-time compare | `WHERE token = $1` raw equality (lint 41) |
| Secret-holding struct | hand-written `Debug` that redacts | `#[derive(Debug)]` over a token (lint 37) |

## Non-negotiable rules

1. **Tenancy — resolve credentials scoped to the *requesting/owning* user.**
   The credential a workflow uses MUST be resolved with the execution's
   `user_id`, never by a provider-side identifier alone (workspace/team/cloud/
   installation id). This is the class of bug fixed in the `github_app` provider
   (PR #374): the installation was looked up by GitHub owner login with no
   `user_id` filter, so any user could mint a token against another user's
   install. OAuth creds avoid this because they live at
   `oauth/<provider>/<user_id>/…` and `SecretsManager::get_secrets_by_paths` gates
   on `owner_user_id = $requesting_user` (fail-closed when there's no user). If
   you add a provider-side lookup table, its credential lookup **must** carry
   `AND user_id = $requesting_user` and fail closed.

2. **Callback identity comes from the state token, never the session cookie.**
   The OAuth callback recovers `user_id` from `oauth_state_tokens` (set at
   authorize time), because an attacker who completes consent on *their* account
   can hand a victim the callback URL. `consume_oauth_state` does this for you —
   use it. State consume MUST be atomic single-use
   (`UPDATE … used=true … WHERE used=false … RETURNING`).

3. **Inbound push/webhook requests must be authenticated before any DB work,**
   and mapped to the owning user via the *owned trigger/channel row* or a
   verified token — not via request-supplied identifiers. (GCal: HMAC
   `X-Goog-Channel-Token`; Gmail: Google-signed Pub/Sub JWT; generic webhooks:
   HMAC signing secret or constant-time `verification_token`.)

4. **Never log a token, refresh token, or PII.** For gmail/gcal the OAuth
   `provider_key` IS the user's email — redact it
   (`talos_oauth::refresh_task::redact_provider_key_for_log`). Give any
   secret-holding struct a hand-written `Debug` that prints `[REDACTED]`.

5. **Cap every response body** through `talos_http_body` (a misbehaving/MITM'd
   host can otherwise OOM the controller), and **cap every collection / paginated
   loop** (`take(N)`, a max-pages counter — no unbounded `loop { next_cursor }`).

## Adding an OAuth integration — step by step

1. **New crate** `talos-<provider>` (workspace member). Depend on `talos-oauth`,
   `talos-http-utils`, `talos-http-body`, `sqlx`, `uuid`, `anyhow`, `async-trait`.

2. **Service struct** holding `db_pool`, the `client_id/secret/redirect_uri`
   (read from env with `.filter(|v| !v.is_empty())` — empty-env class), and an
   `OAuthCredentialService`.

3. **Implement `OAuthIntegration`** (this is the whole flow):

   ```rust
   #[async_trait::async_trait]
   impl talos_oauth::OAuthIntegration for MyService {
       type Connected = MyIntegration;

       fn provider(&self) -> &'static str { "myprovider" }

       fn authorize_request(&self) -> anyhow::Result<talos_oauth::AuthorizeRequest<'static>> {
           Ok(talos_oauth::AuthorizeRequest {
               provider: "myprovider",
               auth_url: "https://provider.example/oauth/authorize",
               token_url: "https://provider.example/oauth/token",
               client_id: self.client_id.clone().ok_or_else(|| anyhow::anyhow!("MYPROVIDER_CLIENT_ID not set"))?,
               client_secret: self.client_secret.clone().ok_or_else(|| anyhow::anyhow!("MYPROVIDER_CLIENT_SECRET not set"))?,
               redirect_uri: self.redirect_uri.clone().ok_or_else(|| anyhow::anyhow!("MYPROVIDER_REDIRECT_URI not set"))?,
               scopes: &["read:thing", "offline_access"],
               extra_params: &[("access_type", "offline")],
           })
       }

       async fn complete_callback(
           &self,
           pool: &sqlx::PgPool,
           code: &str,
           consumed: talos_oauth::ConsumedOAuthState, // user_id + pkce_verifier, already validated
       ) -> anyhow::Result<MyIntegration> {
           // 1. Exchange `code` (+ consumed.pkce_verifier) at the token URL, using
           //    the shared hardened client + capped read:
           let client = talos_http_utils::trusted_client::build_integration_client(
               std::time::Duration::from_secs(15));
           let resp = client.post("https://provider.example/oauth/token")
               .form(&[/* grant_type, code, client_id/secret, redirect_uri, code_verifier */])
               .send().await?;
           let tokens: TokenResponse = talos_http_body::read_json_capped(resp).await?;

           // 2. Derive the provider key (email / team / site) if needed (another
           //    capped GET), then STORE against consumed.user_id — the tenancy anchor:
           self.credentials_service.store_credentials(
               consumed.user_id, "myprovider", &provider_key,
               &tokens.access_token, tokens.refresh_token.as_deref(),
               talos_oauth::oauth_expires_at(tokens.expires_in), &granted_scope,
           ).await?;

           // 3. Upsert your integration row (user_id, provider_key, …) and return it.
       }
   }
   ```

4. **Public API delegates to the drivers** (keeps the security-critical ordering
   — consume-before-exchange — impossible to skip):

   ```rust
   pub async fn get_authorization_url(&self, user_id: Uuid) -> Result<(String, String)> {
       talos_oauth::authorization_url(&self.db_pool, self, user_id).await
   }
   pub async fn handle_callback(&self, code: String, state: String) -> Result<MyIntegration> {
       talos_oauth::handle_oauth_callback(&self.db_pool, self, &code, &state).await
   }
   ```

   **`talos-slack` is the canonical reference implementation** — copy its shape.

5. **Wire the two HTTP handlers** (authorize redirect + callback) in `talos-api`
   / `talos-mcp-handlers`, gated by the usual auth (`require_2fa`, scope). The
   callback handler just calls `handle_callback`.

6. **Add the provider hostname to the LLM/host allow/deny lists only if
   relevant**, and register the crate in the workspace `Cargo.toml`.

That's it — token refresh (`OAuthCredentialService` + the background sweep),
user-scoped resolution (`vault://oauth/<provider>/<user_id>/<key>` in a module's
`allowed_secrets`), encryption at rest, and DLP are all handled by the shared
layers.

## Adding a push-notification integration

On top of the OAuth flow above, a watch/webhook integration (like gmail/gcal)
follows the 10-file shape in **`docs/integration-pattern.md`** — read it before
coding. Key extra rules:

- Store watch/channel/cursor state in `talos_integration_state` (per-user scoped
  automatically). **It is not encrypted at rest today** — keep real secrets out
  of it (tokens belong in the vault; make callback auth a *stateless* HMAC).
- Authenticate every inbound notification (§rule 3) before touching the DB, and
  resolve the owning user from the verified token / owned channel row.
- Reuse `talos_integration_helpers::{RenewalFailure, looks_like_oauth_failure}`
  for the renewal path.

## Final checklist

- [ ] Every HTTP client via `trusted_client` (fixed host) or `outbound` (user URL) — **lint 49/40**
- [ ] Every response body via `talos_http_body::read_json_capped` / `read_error_text_capped` — **lint 31**
- [ ] OAuth via `OAuthIntegration` + drivers (or `begin`/`consume` primitives) — no hand-rolled PKCE/CSRF/consume
- [ ] Credentials stored via `OAuthCredentialService` against the **state-bound `user_id`**
- [ ] Any provider-side credential lookup filters `AND user_id = $requesting_user` and fails closed — **tenancy**
- [ ] Inbound requests authenticated (HMAC/JWT/`token_hash`) before DB work — **lint 41**
- [ ] No token / refresh-token / email logged; secret structs have a redacting `Debug` — **lint 37**
- [ ] Collections + paginated loops are bounded; DB lookups indexed, no N+1
- [ ] `make lint` (structural + clippy) and the new integration's tests pass
