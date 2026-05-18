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
        account_identifier_column: "o.email",
        account_identifier_join: Some("JOIN oauth_accounts o ON g.oauth_account_id = o.id"),
        extra_where: "",
        disconnect_is_soft_delete: false,
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
    },
];
