//! Static registry of OAuth integration providers.
//!
//! Adding a new provider requires:
//!   1. Add an entry to the `PROVIDERS` array below (including db_table, etc.)
//!   2. Create `controller/src/{provider}/` with integration service + handlers
//!   3. Register routes in `main.rs`
//!   4. Add a migration for the provider's integration table
//!   5. Add the GraphQL `IntegrationService` enum variant in types.rs
//!
//! The frontend discovers providers dynamically from `/api/integrations/providers`
//! — no frontend changes needed for display, icon, or OAuth host allowlisting.

use serde::Serialize;

/// Static metadata for an OAuth integration provider.
/// This struct is returned by the `/api/integrations/providers` REST endpoint
/// so the frontend can render integration cards without hardcoding.
#[derive(Debug, Clone, Serialize)]
pub struct IntegrationProviderConfig {
    /// Internal identifier (e.g. "gmail", "slack", "atlassian").
    /// Used as the REST API path segment: `/api/{id}/connect`.
    pub id: &'static str,

    /// Human-readable display name (e.g. "Gmail", "Slack", "Jira (Atlassian)").
    pub display_name: &'static str,

    /// Short description for the integration card.
    pub description: &'static str,

    /// Lucide icon name for the frontend (e.g. "Mail", "MessageSquare", "LayoutGrid").
    pub icon: &'static str,

    /// Brand color hex for the card accent (e.g. "#EA4335" for Gmail red).
    pub color: &'static str,

    /// GraphQL enum value returned by serviceIntegrations query.
    /// Must match the async-graphql `IntegrationService` enum variant serialization.
    pub graphql_enum: &'static str,

    /// OAuth authorization server hostnames the frontend should allow redirects to.
    /// Used by the frontend's `validateOAuthUrl` function.
    pub oauth_hosts: &'static [&'static str],

    /// Environment variable names for client credentials.
    /// The provider is considered "configured" when ALL of these are set.
    pub env_vars: &'static [&'static str],

    /// Default redirect URI path (appended to BASE_URL).
    pub redirect_path: &'static str,

    /// Database table name (e.g. "atlassian_integrations").
    pub db_table: &'static str,

    /// Column expression to use as `account_identifier` in the serviceIntegrations query.
    pub account_identifier_column: &'static str,

    /// Optional SQL JOIN clause for providers that need it (e.g. Google Calendar joins oauth_accounts).
    pub account_identifier_join: Option<&'static str>,

    /// Additional WHERE clause fragment (e.g. "AND is_active = true" for Atlassian soft-delete).
    pub extra_where: &'static str,

    /// Whether disconnect uses soft-delete (UPDATE is_active=false) vs hard-delete (DELETE).
    pub disconnect_is_soft_delete: bool,

    /// Column on `db_table` that holds the vault provider_key for this row — the
    /// value that keys the unified `integration_credentials` / vault entries
    /// (e.g. gmail's `email_address`, gcal's `oauth_account_id`, gcp's
    /// `provider_key`). The generic disconnect `RETURNING`s this so it can
    /// revoke + clean up the OAuth token, not just hide the row.
    pub provider_key_column: &'static str,

    /// Base OAuth provider string for vault-path resolution / revoke (the
    /// namespace segment `store_credentials` used: `"gmail"`, `"slack"`,
    /// `"atlassian"`, `"google_calendar"`, `"google_cloud"`). For a tiered
    /// provider (see `tier_column`) this is the DEFAULT; the row's tier value
    /// overrides it.
    pub credential_provider: &'static str,

    /// For providers whose OAuth provider string depends on a per-row
    /// discriminator column (GCP: one row per consent tier, each stored under a
    /// distinct provider namespace), the name of that column (`"tier"`). The
    /// generic disconnect `RETURNING`s it and maps the value to the tier's
    /// provider string so the RIGHT namespace is revoked. `None` for
    /// single-namespace providers.
    pub tier_column: Option<&'static str>,
}

impl IntegrationProviderConfig {
    /// Returns true if all required environment variables are set (non-empty).
    pub fn is_configured(&self) -> bool {
        self.env_vars
            .iter()
            .all(|var| std::env::var(var).ok().filter(|v| !v.is_empty()).is_some())
    }
}

/// All registered OAuth providers.
/// The frontend reads this list from `/api/integrations/providers` to render
/// integration cards dynamically — adding a provider here is sufficient for
/// frontend discovery (no frontend code changes needed).
/// Resolve the OAuth provider string whose vault namespace should be revoked
/// when a disconnected row is torn down. For a single-namespace provider it's
/// the config's `credential_provider`. For a tiered provider (GCP) the row's
/// `tier` value selects the namespace, derived as `<base>` / `<base>_write` /
/// `<base>_full` — matching `talos_google_cloud::GcpTier::provider_str`
/// (the canonical source; pinned by `gcp_tier_provider_strings` test).
///
/// Returns `None` for a tiered provider with an unknown/missing tier — fail
/// closed rather than revoke the wrong namespace (the row is still hidden; the
/// token just isn't auto-revoked). Mirrors the dedicated GCP disconnect's
/// unknown-tier handling.
pub fn revoke_provider_for(
    config: &IntegrationProviderConfig,
    tier: Option<&str>,
) -> Option<String> {
    match (config.tier_column, tier) {
        (None, _) => Some(config.credential_provider.to_string()),
        (Some(_), Some("read")) => Some(config.credential_provider.to_string()),
        (Some(_), Some("write")) => Some(format!("{}_write", config.credential_provider)),
        (Some(_), Some("full")) => Some(format!("{}_full", config.credential_provider)),
        (Some(_), _) => None,
    }
}

pub static PROVIDERS: &[IntegrationProviderConfig] = &[
    IntegrationProviderConfig {
        id: "google-calendar",
        display_name: "Google Calendar",
        description: "Sync events and schedules",
        icon: "Calendar",
        color: "#4285F4",
        graphql_enum: "GOOGLE_CALENDAR",
        oauth_hosts: &["accounts.google.com"],
        env_vars: &["GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET"],
        redirect_path: "/auth/oauth/google/callback",
        db_table: "google_calendar_integrations",
        // PR #440 decoupled Google Calendar from the SSO-login `oauth_accounts`
        // table (dropped the FK) and moved the connected-account label to the
        // `account_email` column, written by the dedicated connect callback.
        // So: prefer `g.account_email`, LEFT JOIN (not INNER) `oauth_accounts`
        // so decoupled rows — whose synthetic `oauth_account_id` has no
        // matching login-identity row — still surface, and fall back to
        // `o.email` for legacy SSO-piggyback rows. The trailing literal
        // guarantees a non-NULL identifier (the row struct's `identifier` is
        // non-nullable — a NULL would fail the whole UNION-ALL query and hide
        // EVERY provider's integrations). Pre-fix the INNER JOIN matched zero
        // rows for the new flow, so a connected calendar showed no account.
        account_identifier_column: "COALESCE(g.account_email, o.email, 'Google Calendar')",
        account_identifier_join: Some("LEFT JOIN oauth_accounts o ON g.oauth_account_id = o.id"),
        // Hide soft-disconnected integrations (the dedicated GCal disconnect
        // flow sets is_active = false).
        extra_where: "AND g.is_active = true",
        disconnect_is_soft_delete: false,
        provider_key_column: "oauth_account_id",
        credential_provider: "google_calendar",
        tier_column: None,
    },
    IntegrationProviderConfig {
        id: "gmail",
        display_name: "Gmail",
        description: "Send and process emails",
        icon: "Mail",
        color: "#EA4335",
        graphql_enum: "GMAIL",
        oauth_hosts: &["accounts.google.com"],
        env_vars: &["GMAIL_CLIENT_ID", "GMAIL_CLIENT_SECRET"],
        redirect_path: "/api/gmail/callback",
        db_table: "gmail_integrations",
        account_identifier_column: "email_address",
        account_identifier_join: None,
        extra_where: "",
        disconnect_is_soft_delete: false,
        provider_key_column: "email_address",
        credential_provider: "gmail",
        tier_column: None,
    },
    IntegrationProviderConfig {
        id: "slack",
        display_name: "Slack",
        description: "Automate channel messages",
        icon: "MessageSquare",
        color: "#4A154B",
        graphql_enum: "SLACK",
        oauth_hosts: &["slack.com", "oauth.slack.com", "app.slack.com"],
        env_vars: &["SLACK_CLIENT_ID", "SLACK_CLIENT_SECRET"],
        redirect_path: "/api/slack/callback",
        db_table: "slack_integrations",
        account_identifier_column: "team_name",
        account_identifier_join: None,
        extra_where: "",
        disconnect_is_soft_delete: false,
        provider_key_column: "team_id",
        credential_provider: "slack",
        tier_column: None,
    },
    IntegrationProviderConfig {
        id: "atlassian",
        display_name: "Jira (Atlassian)",
        description: "Track issues and projects",
        icon: "LayoutGrid",
        color: "#0052CC",
        graphql_enum: "JIRA",
        oauth_hosts: &["auth.atlassian.com"],
        env_vars: &["ATLASSIAN_CLIENT_ID", "ATLASSIAN_CLIENT_SECRET"],
        redirect_path: "/api/atlassian/callback",
        db_table: "atlassian_integrations",
        account_identifier_column: "COALESCE(display_name, site_url)",
        account_identifier_join: None,
        extra_where: "AND is_active = true",
        disconnect_is_soft_delete: true,
        provider_key_column: "cloud_id",
        credential_provider: "atlassian",
        tier_column: None,
    },
    IntegrationProviderConfig {
        id: "gcp",
        display_name: "Google Cloud",
        description: "List projects and receive Cloud Monitoring alerts",
        icon: "Cloud",
        color: "#4285F4",
        graphql_enum: "GOOGLE_CLOUD",
        oauth_hosts: &["accounts.google.com"],
        env_vars: &["GOOGLE_CLOUD_CLIENT_ID", "GOOGLE_CLOUD_CLIENT_SECRET"],
        redirect_path: "/api/gcp/callback",
        db_table: "google_cloud_integrations",
        // store.rs aliases the table `t` when there is no join, so the
        // identifier + extra_where fragments reference `t.*` (NOT `g.*`,
        // which is the alias only used for join-carrying providers like gcal).
        // Phase C: the same account can hold a read row AND a write
        // (provisioning) row — suffix the write tier so the generic
        // integrations card distinguishes the two consents.
        account_identifier_column: "COALESCE(t.account_email, 'Google Cloud') || \
             CASE WHEN t.tier = 'write' THEN ' (provisioning)' ELSE '' END",
        account_identifier_join: None,
        extra_where: "AND t.is_active = true",
        disconnect_is_soft_delete: true,
        provider_key_column: "provider_key",
        // Base namespace; the row's `tier` overrides it to
        // google_cloud / google_cloud_write / google_cloud_full.
        credential_provider: "google_cloud",
        tier_column: Some("tier"),
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression guard for the "Google Calendar shows no connected account"
    /// bug: PR #440 dropped the `google_calendar_integrations → oauth_accounts`
    /// FK and moved the label to `account_email`, but the serviceIntegrations
    /// query still INNER-JOINed `oauth_accounts` on the now-synthetic
    /// `oauth_account_id`, matching zero rows. The config must (a) prefer
    /// `account_email`, (b) LEFT JOIN so decoupled rows survive, and (c) never
    /// yield a NULL identifier (non-nullable row field → a NULL fails the whole
    /// UNION-ALL and hides every provider).
    #[test]
    fn google_calendar_surfaces_decoupled_rows() {
        let gcal = PROVIDERS
            .iter()
            .find(|p| p.id == "google-calendar")
            .expect("google-calendar provider must exist");

        assert!(
            gcal.account_identifier_column.contains("account_email"),
            "must prefer the decoupled account_email column, got: {}",
            gcal.account_identifier_column
        );
        let join = gcal
            .account_identifier_join
            .expect("gcal still LEFT JOINs oauth_accounts for legacy SSO rows");
        assert!(
            join.trim_start().to_uppercase().starts_with("LEFT JOIN"),
            "join must be a LEFT JOIN so decoupled rows without an oauth_accounts \
             match still appear, got: {join}"
        );
        assert!(
            gcal.account_identifier_column
                .to_uppercase()
                .contains("COALESCE"),
            "identifier must be COALESCE-guarded so it is never NULL (non-nullable \
             row field), got: {}",
            gcal.account_identifier_column
        );
    }

    /// Every provider must declare the two fields the generic disconnect needs
    /// to revoke a token (a missing/empty value would silently skip revocation
    /// — the very bug this registry data fixes).
    #[test]
    fn all_providers_declare_revoke_metadata() {
        for p in PROVIDERS {
            assert!(
                !p.provider_key_column.is_empty(),
                "{} missing provider_key_column",
                p.id
            );
            assert!(
                !p.credential_provider.is_empty(),
                "{} missing credential_provider",
                p.id
            );
        }
    }

    /// GCP tier → OAuth provider string must match
    /// `talos_google_cloud::GcpTier::provider_str` exactly (read→google_cloud,
    /// write→google_cloud_write, full→google_cloud_full). Drift here would
    /// revoke the wrong vault namespace on a tiered disconnect and strand the
    /// token — the same drift class as the Phase D refresh/revoke lockstep.
    #[test]
    fn gcp_tier_provider_strings() {
        let gcp = PROVIDERS
            .iter()
            .find(|p| p.id == "gcp")
            .expect("gcp provider must exist");
        assert_eq!(gcp.tier_column, Some("tier"));
        assert_eq!(
            revoke_provider_for(gcp, Some("read")).as_deref(),
            Some("google_cloud")
        );
        assert_eq!(
            revoke_provider_for(gcp, Some("write")).as_deref(),
            Some("google_cloud_write")
        );
        assert_eq!(
            revoke_provider_for(gcp, Some("full")).as_deref(),
            Some("google_cloud_full")
        );
        // Unknown / missing tier → fail closed (don't revoke a guessed namespace).
        assert_eq!(revoke_provider_for(gcp, Some("bogus")), None);
        assert_eq!(revoke_provider_for(gcp, None), None);
    }

    /// Single-namespace providers use their base credential_provider verbatim,
    /// regardless of any (irrelevant) tier value.
    #[test]
    fn non_tiered_providers_use_base_provider() {
        for (id, expected) in [
            ("gmail", "gmail"),
            ("slack", "slack"),
            ("atlassian", "atlassian"),
            ("google-calendar", "google_calendar"),
        ] {
            let p = PROVIDERS.iter().find(|p| p.id == id).unwrap();
            assert_eq!(p.tier_column, None, "{id} should not be tiered");
            assert_eq!(
                revoke_provider_for(p, None).as_deref(),
                Some(expected),
                "{id} base provider"
            );
        }
    }
}
