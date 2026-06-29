# GitHub App setup & testing

How to register a GitHub App and wire it into Talos for the connect/install flow
(RFC 0008, Phase B). Covers a local/dev test App and the production deployment.

> **Status of Phase B (what a test App actually exercises today).**
> Wired end-to-end: the **connect/install flow** — `GET /api/github/connect`
> (returns the install URL) → operator installs the App → GitHub redirects to
> `GET /api/github/setup` → Talos mints an App JWT, fetches the installation
> metadata, and stores it in `github_app_installations`. The App-JWT minting,
> the 1-hour installation-token cache (`InstallationTokenCache`), and the webhook
> signature verifier (`verify_app_webhook_signature`) are implemented + unit
> tested. **Not yet wired:** the GitHub *modules* don't consume installation
> tokens yet (B4), there's no App-webhook *receiver* endpoint yet (B5-wiring),
> and there's no frontend "Connect GitHub" button yet. So today you can validate
> credentials + the connect flow; outbound module auth and inbound App webhooks
> are follow-ups.

---

## 1. Register the App

GitHub → **Settings → Developer settings → GitHub Apps → New GitHub App**.

| Field | Value |
|---|---|
| **GitHub App name** | globally unique, e.g. `talos-test-<you>` |
| **Homepage URL** | anything (e.g. `https://example.com`) |
| **Setup URL** | `https://<your-host>/api/github/setup` (dev: `http://localhost:8000/api/github/setup`) |
| **Redirect on update** | ✅ enabled |
| **Webhook → Active** | ❌ **disabled for now** — the App-webhook receiver isn't built yet (B5-wiring). Enable it later. |
| **Webhook secret** | set a random string anyway (used once B5-wiring lands; Talos reads it as `GITHUB_APP_WEBHOOK_SECRET`) |
| **Repository permissions** | start minimal, e.g. **Contents: Read-only**, **Pull requests: Read-only** |
| **Where can this be installed?** | "Only on this account" for a test App |

Create it, then from the App's settings page collect:

- **App ID** — numeric, near the top.
- **App slug** — the last path segment of the App's public page URL,
  `https://github.com/apps/<slug>`.
- **Private key** — "Generate a private key" downloads a `.pem` (PKCS#1, i.e.
  `-----BEGIN RSA PRIVATE KEY-----`; Talos also accepts PKCS#8).

> **Localhost is fine for dev.** The Setup URL is hit by the *browser* (your
> browser can reach localhost), and Talos's calls to `api.github.com` go
> *outbound* (work from anywhere). Only the inbound **webhook** would need a
> public URL / tunnel — and that path is off for now.

## 2. Install it & find the installation id

On the App page → **Install App** → choose a repository. GitHub lands you at
`https://github.com/settings/installations/<ID>` (org installs:
`https://github.com/organizations/<org>/settings/installations/<ID>`). Note
**`<ID>`** — the installation id.

## 3. Validate the credentials against real GitHub (no controller needed)

The `app_smoke` example runs the real `talos-github` code path
(`GithubAppConfig::from_env` → App JWT mint → `get_installation` →
`mint_installation_token`) against `api.github.com`. Run it first — if it passes,
the App is registered correctly and the cryptographic/API core works.

```bash
# bash — $(cat ...) preserves the PEM's newlines
GITHUB_APP_ID=<app-id> \
GITHUB_APP_SLUG=<slug> \
GITHUB_APP_WEBHOOK_SECRET=placeholder \
GITHUB_APP_PRIVATE_KEY="$(cat ~/Downloads/<your-app>.private-key.pem)" \
cargo run -p talos-github --features client --example app_smoke -- <INSTALLATION_ID>
```

Expected:

```
✓ config loaded: app_id=…, slug=…
✓ get_installation: account=… type=… repo_selection=…
  granted permissions: {…}
✓ mint_installation_token: minted (… chars), expires_at=…
✅ All live GitHub App checks passed.
```

(The example never prints token bytes — only presence, length, and expiry.)

## 4. Configuration (env vars)

Talos reads the App config from the environment (platform-level, like the master
DEK / LLM keys — see RFC 0008 D2). All four are required to enable the feature;
**`GITHUB_APP_ID` blank = feature disabled**. A half-config (id set, another
field missing/blank, or an unparseable key) makes the controller **fail to boot**
— by design, so a broken config is loud, not silent.

| Env var | Secret? | Purpose |
|---|---|---|
| `GITHUB_APP_ID` | no | JWT `iss`; presence enables the feature |
| `GITHUB_APP_SLUG` | no | builds the install-redirect URL |
| `GITHUB_APP_PRIVATE_KEY` | **yes** | RS256 signing key (PEM, PKCS#1 or PKCS#8) |
| `GITHUB_APP_WEBHOOK_SECRET` | **yes** | App webhook HMAC secret (used by B5-wiring) |

### Dev (`make up-dev`)

Add to `.env` (the controller picks these up). The PEM is multi-line — keep the
real newlines inside the quotes:

```dotenv
GITHUB_APP_ID=123456
GITHUB_APP_SLUG=talos-test-you
GITHUB_APP_WEBHOOK_SECRET=<the-webhook-secret>
GITHUB_APP_PRIVATE_KEY="-----BEGIN RSA PRIVATE KEY-----
MIIE...
...
-----END RSA PRIVATE KEY-----"
```

> ⚠️ **Rebuild the controller image before testing.** The dev image can be stale
> versus `main`, and the connect routes only exist post-#350. On boot, a
> correctly-configured controller logs `GitHub App connect flow enabled (RFC 0008)`.

### Production (Helm)

The four keys live in the controller bootstrap Secret (`bootstrapSecret.data` in
`values.yaml`; injected via the controller `$secretKeys` list). Set them to real
values; leaving `GITHUB_APP_ID` blank keeps the feature off. The k8s Secret is
the at-rest store (encrypted in etcd, RBAC'd, helm-managed). See
`deploy/helm/talos/values.yaml`.

## 5. Test the connect flow (controller running)

The initiate endpoint requires an authenticated session.

```bash
# 1) initiate — returns the install URL
curl -s -b <session-cookie> https://<host>/api/github/connect
# → {"success":true,"install_url":"https://github.com/apps/<slug>/installations/new?state=…"}
```

Open the `install_url` in the browser → install/confirm → GitHub redirects to
`/api/github/setup` → you should land on the frontend at
`…/settings?github_connected=<account>#integrations`.

Confirm persistence:

```bash
# dev (in-cluster Postgres)
docker exec talos-postgres psql -U talos -d talos -c \
  "SELECT installation_id, account_login, account_type, repository_selection, is_active \
   FROM github_app_installations;"
```

## 6. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `/api/github/connect` → 503 "not configured" | `GITHUB_APP_ID` blank, or controller not rebuilt since #350 |
| Controller won't boot, logs "GitHub App is half-configured" | one of the four vars set, another missing/blank |
| Controller won't boot, "invalid GitHub App private key" | PEM mangled (lost newlines) — re-paste with `"$(cat key.pem)"` |
| `app_smoke` / callback: `get_installation … HTTP 401` | wrong App ID, or key doesn't match the App |
| `app_smoke` / callback: `HTTP 404` | wrong installation id, or the App was uninstalled |
| Callback redirects with `?github_error=install_failed` | server-side error — check the controller logs (full error is logged; the redirect carries only a generic code by design) |

## See also

- [`docs/rfcs/0008-github-app-authentication.md`](rfcs/0008-github-app-authentication.md) — the design.
- `talos-github/examples/app_smoke.rs` — the live credential check (§3).
- [`docs/OAUTH_SETUP.md`](OAUTH_SETUP.md) — the OAuth provider flow (distinct from the App install flow).
