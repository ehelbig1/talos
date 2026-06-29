//! Live smoke test for a GitHub App's credentials (RFC 0008).
//!
//! Validates the real talos-github code path against `api.github.com` WITHOUT
//! needing the controller deployed: config load → App JWT mint (ring) →
//! `get_installation` → `mint_installation_token`.
//!
//! Setup:
//!   1. Register a GitHub App, download its private key, install it on a repo.
//!   2. Find the installation id at
//!      `https://github.com/settings/installations/<ID>` (org installs:
//!      `https://github.com/organizations/<org>/settings/installations/<ID>`).
//!   3. Run (bash — `$(cat ...)` preserves the PEM newlines):
//!
//!      GITHUB_APP_ID=123456 \
//!      GITHUB_APP_SLUG=my-test-app \
//!      GITHUB_APP_WEBHOOK_SECRET=anything-nonblank \
//!      GITHUB_APP_PRIVATE_KEY="$(cat ~/Downloads/my-test-app.private-key.pem)" \
//!      cargo run -p talos-github --features client --example app_smoke -- <INSTALLATION_ID>
//!
//! No token bytes are ever printed — only presence, length, and expiry.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let installation_id: i64 = std::env::args()
        .nth(1)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "usage: app_smoke <installation_id> (see the module docs for where to find it)"
            )
        })?
        .parse()
        .map_err(|_| anyhow::anyhow!("installation_id must be an integer"))?;

    // Config load — exercises GithubAppConfig::from_env + the PEM parse +
    // the empty-env / half-config guards.
    let cfg = talos_github::GithubAppConfig::from_env()
        .map_err(|e| anyhow::anyhow!("GitHub App config invalid: {e}"))?
        .ok_or_else(|| anyhow::anyhow!("GITHUB_APP_ID is unset/blank — App not configured"))?;
    println!(
        "✓ config loaded: app_id={}, slug={}",
        cfg.app_id, cfg.app_slug
    );

    // Build the live client (parses the key into a ring signing key).
    let client = cfg
        .client()
        .map_err(|e| anyhow::anyhow!("build client: {e}"))?;
    let now = chrono::Utc::now().timestamp();

    // get_installation — proves the App JWT is accepted by GitHub + the parse.
    let info = client
        .get_installation(installation_id, now)
        .await
        .map_err(|e| anyhow::anyhow!("get_installation failed: {e:#}"))?;
    println!(
        "✓ get_installation: account={} type={:?} repo_selection={:?}",
        info.account_login, info.account_type, info.repository_selection
    );
    println!("  granted permissions: {}", info.permissions);

    // mint_installation_token — proves the full App JWT → installation-token chain.
    let token = client
        .mint_installation_token(installation_id, now)
        .await
        .map_err(|e| anyhow::anyhow!("mint_installation_token failed: {e:#}"))?;
    // NEVER print token bytes — presence/length/expiry only.
    println!(
        "✓ mint_installation_token: minted ({} chars), expires_at={}",
        token.token.len(),
        token.expires_at
    );

    println!("\n✅ All live GitHub App checks passed.");
    Ok(())
}
