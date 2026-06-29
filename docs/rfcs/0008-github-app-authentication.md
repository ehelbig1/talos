# RFC 0008 — GitHub App authentication (Phase B of native GitHub integration)

**Status:** Draft
**Author:** Claude (paired with Evan)
**Date:** 2026-06-27
**Follows:** [RFC 0007](0007-native-github-integration.md) (Phase A — event-typed webhook triggers, shipped)

## TL;DR

Phase A made inbound GitHub webhooks first-class (signature verify + replay/dedup
already existed; we added server-side event-type filtering + `__webhook__`
metadata). The remaining gap is **outbound auth**: the `github-pr-reviewer` /
`github-analyzer` modules call the GitHub API with a long-lived **Personal Access
Token (PAT)** stored as a secret. PATs are coarse-grained, manually rotated, and
tied to a human account.

Phase B replaces them with a **GitHub App**: short-lived (1-hour), per-repo-scoped,
**auto-rotating installation access tokens** minted from the App's private key,
plus a click-to-connect install flow. The PAT path keeps working as a fallback
during migration.

**Why a separate RFC (not just "add a provider"):** GitHub App auth is **not** the
OAuth authorization-code + refresh-token flow that Talos's centralized OAuth
refresh (`talos-oauth`) implements. Installation tokens are minted from an App
JWT (RS256-signed with the App private key) and are **not refreshable** — you
re-mint them. That breaks the core assumption of `refresh_oauth_token_if_needed`
and needs its own renewal arm. The shape is different enough to design before
coding.

## Context

**What exists today:**

- **Inbound (Phase A, shipped #337–#341):** `talos-webhooks` verifies GitHub's
  `X-Hub-Signature-256`, dedups on `X-GitHub-Delivery`, filters by event type
  (`event_filter`), and surfaces `__webhook__ = {event, delivery, action}` to the
  workflow.
- **Outbound:** `module-templates/github-pr-reviewer` + `github-analyzer` call
  `api.github.com` with a PAT supplied as a module secret. No App, no scoped
  tokens, no connect-UX.
- **OAuth infrastructure (reuse where it fits):**
  - `talos-oauth/src/credentials.rs` — `OAuthCredentialService` (tokens live in
    `integration_credentials`, never in the provider's own table) +
    `refresh_oauth_token_if_needed` (per-provider OAuth refresh-token exchange).
  - `talos-oauth/src/refresh_task.rs` — `proactive_token_refresh_task`, polls
    `integration_credentials` every ~5 min, renews tokens expiring within ~10 min.
  - `talos-integrations/src/provider_config.rs` — the `PROVIDERS` registry the
    frontend auto-discovers (`/api/integrations/providers`).
  - Gold-standard providers to mirror: `talos-atlassian` (PKCE, metadata-only
    table), `talos-gmail` (dual-write), `talos-google-calendar`.
  - Vault path convention: `oauth/{provider}/{user_id}/{provider_key}/access_token`.
  - Renewal-failure classification: `talos_integration_helpers::RenewalFailure` +
    `looks_like_oauth_failure` (see `docs/integration-pattern.md`).
- There is **no `talos-github` crate** yet.

**Why PATs are insufficient:** long-lived (no forced expiry), coarse (user-scoped,
usually all of a user's repos), manually rotated, and bound to a person — when
they leave or rotate the token, every workflow breaks. A compromised PAT is a
broad, durable credential.

**The GitHub App token model (the crux):** two distinct credentials.

1. **App JWT** — a short-lived (≤10 min) JWT **RS256-signed with the App's private
   key**, `iss = App ID`. Identifies the App itself. Used *only* to mint
   installation tokens.
2. **Installation access token** — `POST /app/installations/{installation_id}/access_tokens`
   (authorized by the App JWT) returns a token that expires in **1 hour**, scoped
   to that installation's repositories + permissions. **It is not refreshable via
   an OAuth `refresh_token` grant** — when it expires you mint a new App JWT and
   request a fresh installation token.

(GitHub Apps *also* support a user-to-server OAuth flow — authorization code +
refresh token — for acting *as* the connecting user. That's the flow
`talos-oauth` already models, but it's **not** what webhook-triggered automation
wants. See Non-goals.)

## Decisions

**D1. Use server-to-server installation tokens, not user-to-server OAuth.**
Webhook-triggered automation runs with no interactive user in the loop, so the
installation token (acting as the App, scoped to the installation) is the correct
credential. User-to-server OAuth is deferred (D-NG1).

**D2. App config is a platform/operator secret; installation state is per-connection
metadata.** The App **private key + App ID + webhook secret** are a *single*
operator-provided config (one self-hosted Talos operator registers one GitHub
App), stored in the platform secret namespace via `SecretsManager` (encrypted at
rest; per-org DEK v4 where an org is resolvable, else global v3). Per connection
we persist only **metadata** — `installation_id`, the GitHub account/org, granted
permissions + repo selection — mirroring the Atlassian "metadata-only table"
pattern. **No private key or token columns in the provider table.**

**D3. Installation tokens are minted + cached, renewed by a NEW arm — not the OAuth
refresh path.** A new minter (in a `talos-github` crate) produces: App JWT (RS256)
→ installation token. Cache the installation token with its 1-hour expiry in
`integration_credentials` (keyed by `installation_id`). Extend
`proactive_token_refresh_task` to recognize `provider = "github_app"` and call the
minter **instead of** `refresh_oauth_token_if_needed` (which does an OAuth
refresh-token exchange GitHub App installations don't have). Reuse the task's
scheduling + `RenewalFailure` / `looks_like_oauth_failure` classification; branch
only the actual mint call.

**D4. Webhook delivery via the App-level webhook, not per-repo registration.** A
GitHub App has **one** configured webhook URL; GitHub auto-delivers events for
*every* installation to it. So "connect" = install the App — **no per-repo
`POST /repos/{}/hooks` calls**, no per-repo webhook state to manage. The App
webhook secret is **App-level** (one HMAC secret for all deliveries). Reconcile
with Phase A: the App secret verifies the delivery (the existing
`X-Hub-Signature-256` path already does HMAC-SHA256 over the raw body — it just
reads the secret from a different place); routing to a specific workflow is by
installation/repo rather than per-trigger `signing_secret`.
*Alternative — repository webhooks via API per repo:* rejected — more API calls,
more renewal-sensitive state, and GitHub recommends App webhooks for App
integrations. (Keep per-repo as an escape hatch only if a use case demands
repo-granular routing.)

**D5. Click-to-connect = the App install flow (not authorization-code OAuth).**
Redirect the user to `https://github.com/apps/{app_slug}/installations/new`;
GitHub handles repo selection and redirects back to a callback with
`installation_id` + `setup_action`. Persist the installation metadata (D2).
Follow `docs/integration-pattern.md`'s file shape where it maps, but note the
install flow differs from the PKCE authorization-code flow the gold-standard
providers use — there is no `code`→token exchange; the `installation_id` is the
durable handle and tokens are minted on demand (D3).

**D6. Migration is additive: PAT keeps working, App is opt-in then default.** The
GitHub modules resolve a token at run time: **prefer** an App installation token
for the repo's owner when an installation is connected; **fall back** to the
existing PAT secret otherwise. No flag-day; an operator with no App configured is
unaffected.

**D7. Installation tokens obey the existing secret + host + tier gates.** The
minted token is a secret: vault-stored, never logged (presence only), DLP-redacted
in any persisted output, and it reaches the worker only through the standard
AES-256-GCM `encrypted_secrets` envelope / `vault://` header resolution — never as
plaintext on the wire. Outbound calls stay gated by `allowed_hosts`
(`api.github.com`) and the actor's `max_llm_tier` path (GitHub is not an LLM host,
so no tier-1 deny, but the dispatch path is unchanged).

## Migration plan

Each phase independently shippable; PAT path intact throughout.

- **B1. `talos-github` crate — token minting.** App JWT (RS256) + installation-token
  mint + 1-hour cache. JWT signing is pure given (private key, App ID, clock), so
  it's unit-tested without network (inject the clock; assert header/claims/`exp`).
  *Rollback:* crate unused until B3 wires it.
- **B2. Connect flow + provider registry + installation table.** Migration:
  `github_app_installations (user_id/org, installation_id UNIQUE, account_login,
  permissions JSONB, repo_selection, is_active, created/updated)` — **no token
  columns**. Add a `PROVIDERS` entry; add the install-redirect + callback handlers.
  *Rollback:* table is additive; routes behind the registry entry.
- **B3. Token cache + rotation.** ✅ Shipped as `talos_github::InstallationTokenCache`
  (feature `client`): in-memory, single-flight, on-demand re-mint within 5 min of
  expiry (see open-question 4). No `proactive_token_refresh_task` branch /
  `integration_credentials` row needed — the token never touches the DB.
  *Rollback:* the cache is only constructed where a configured App exists.
- **B4. Module token resolution (App-first, PAT-fallback).**
  - *B4-core (shipped):* `talos_github_connect::GithubTokenResolver` composes the
    installation registry (B2a) + the mint cache (B3): `token_for_owner(owner)` →
    `Ok(Some(token))` if an active installation exists, `Ok(None)` if not /
    App-disabled (→ caller falls back to PAT), `Err` only if minting fails for an
    existing installation. Opt-in is **explicit** via a secret-path scheme:
    `github_app:<owner>` (parsed by `parse_github_app_secret_path`, charset-guarded)
    selects the App token; any other path stays a PAT/vault secret. No module-code
    change — the operator just sets the module's `GITHUB_TOKEN_SECRET` config to
    `github_app:<owner>`.
  - *B4-wiring (remaining):* call the resolver from the controller's per-module
    secret prefetch (`build_encrypted_secrets`) — for each requested secret path
    matching the scheme, resolve + inject the minted token under that key (falling
    back to the existing PAT resolution on `Ok(None)`). Touches the
    security-critical secret-prefetch path → best validated against a live
    workflow run. *Rollback:* default to PAT if no installation resolves.
- **B5. App-level webhook secret verification.** The verifier
  (`talos_github::verify_app_webhook_signature`) is shipped: the same Phase-A
  `X-Hub-Signature-256` scheme — `HMAC-SHA256(secret, raw_body)`, constant-time —
  pointed at `GithubAppConfig::webhook_secret`, fail-closed, unit-tested. **Remaining
  (B5-wiring):** an App-webhook RECEIVER endpoint that calls it and routes the
  verified delivery to a workflow by installation/repo. That routing is a new
  App-event-driven trigger surface (bigger than auth) — likely its own follow-up.
  Per-trigger `signing_secret` webhooks (Phase A) are unaffected. *Rollback:* the
  verifier is unused until a receiver calls it.

## Non-goals

- **(D-NG1) User-to-server OAuth** (acting *as* the connecting GitHub user, with a
  user refresh token). Separate future work if "attribute the action to the user"
  semantics are needed; installation tokens act as the App.
- **GitHub Enterprise Server (self-hosted GHES)** — different API base URL +
  host-allowlist entries. Note as a follow-up; Phase B targets github.com.
- **Retiring PATs.** They remain the documented fallback (D6); deprecation is a
  later decision once App coverage is proven.
- Any change to Phase A's inbound filter/replay/dedup (already shipped + correct).

## Open questions

1. **Platform-global vs per-org App.** Assumption: one operator-registered App per
   Talos deployment; installations are per connecting GitHub account/org. Confirm
   this fits the multi-tenant model (vs. each org bringing its own App ID/key —
   more config, stronger isolation).
2. **Where exactly App config lives.** ✅ **Resolved (talos-github `GithubAppConfig`):**
   the App credentials are PLATFORM-level (one operator App per deployment), so
   they're provisioned the same way as the other platform credentials (master DEK,
   LLM keys, Vault token) — the **bootstrap / k8s Secret surfaced as env vars**,
   NOT the per-user `SecretsManager` vault (which is for user/module secrets).
   Vars: `GITHUB_APP_ID` (presence = enabled), `GITHUB_APP_SLUG` (non-secret),
   `GITHUB_APP_PRIVATE_KEY` (PEM, secret), `GITHUB_APP_WEBHOOK_SECRET` (secret).
   Secrets are held in `Zeroizing` + redacted from `Debug`; blank = unset;
   half-configured fails loudly at load. The k8s Secret is the at-rest store
   (encrypted in etcd, RBAC'd, helm-managed, auto-bounced on rotation per
   MCP-1231). Helm/deploy wiring for these vars is part of B2b.
3. **RS256 dependency.** ✅ **Resolved (B1):** signing uses `ring` (constant-time,
   Marvin-resistant) — see RFC §D3 + the RUSTSEC-2023-0071 note in `deny.toml`.
   Controller-side only; the worker never holds the App key (credential-free-worker
   invariant preserved).
4. **Token cache scope.** ✅ **Resolved (B3 — `InstallationTokenCache`):** the
   **dedicated short-TTL cache** branch, in-memory rather than
   `integration_credentials`. Rationale: the installation token is a secret, so
   keeping it only in a `Zeroizing` in-memory cell (never written to the DB)
   shrinks the secret-exposure surface — and the App private key can always
   re-mint, so nothing durable is worth persisting. Rotation is **on-demand**:
   the cache re-mints once a token is within `REFRESH_MARGIN_SECS` (5 min) of
   expiry, so no separate proactive-refresh task / `proactive_token_refresh_task`
   branch is needed. The "must not thunder" requirement is met by **single-flight
   per installation** (a per-installation async lock → exactly one mint under a
   concurrent burst). Multi-replica controllers mint independently (≤ replica
   count mints/hour per installation) — well within GitHub's limits.

## Success criteria

- A connected repository fires Talos workflows with **no PAT** anywhere in the
  path.
- Installation tokens **auto-rotate hourly** with zero manual operator action;
  a forced clock-advance test shows a fresh token minted before expiry.
- **Revoking the App installation on GitHub immediately stops access** (next mint
  fails closed; cached token expires within the hour).
- The worker never holds the App private key; minting + token resolution are
  controller-side only (credential-free-worker invariant preserved).
- PAT-configured deployments are byte-for-byte unaffected until they opt in.

## See also

- [RFC 0007](0007-native-github-integration.md) — Phase A (inbound, shipped).
- `docs/integration-pattern.md` — the 10-file push-notification shape +
  `RenewalFailure` / `looks_like_oauth_failure`.
- `memory/oauth_provider_guide.md` (session memory) — the Atlassian gold-standard
  OAuth pattern (note: the *install* flow here differs — no code→token exchange).
- `talos-oauth/src/{credentials.rs,refresh_task.rs}`, `talos-integrations/src/provider_config.rs`.
- `module-templates/github-pr-reviewer`, `module-templates/github-analyzer` — the
  PAT consumers B4 migrates.
