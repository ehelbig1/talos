use std::fmt;

/// Capability vocabulary for API keys. Stored on `api_keys.scopes` as
/// a `text[]` of the lowercase string forms.
///
/// Service code (`ApiKeyService`) handles persistence. This enum
/// exists so type-aware callers can match on capability without
/// re-stringifying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApiKeyScope {
    /// Read-only access to workflows
    WorkflowsRead,
    /// Full access to workflows
    WorkflowsWrite,
    /// Read-only access to secrets
    SecretsRead,
    /// Full access to secrets
    SecretsWrite,
    /// Access to webhooks
    WebhooksAccess,
    /// Full admin access
    Admin,
}

impl ApiKeyScope {
    /// Every recognized scope, in stable display order. Single source
    /// of truth for callers that need to enumerate the scope set
    /// (API documentation, validation warn messages, JSON-Schema
    /// `enum` values). Order matches the historic ordering of the
    /// `from_string` arms below so test fixtures stay stable.
    ///
    /// MCP-847 (2026-05-14): canonical list extracted so the API docs
    /// surface (talos-api-docs) and the parser-warn message
    /// (talos-api-keys::parse_api_key_scope_logged) can render from
    /// one source instead of hand-listing. Pre-fix the docs listed
    /// FIVE phantom scopes ("modules:read", "modules:write",
    /// "executions:read", "executions:write", "webhooks:read",
    /// "webhooks:write") that this enum doesn't recognise — operators
    /// following the docs would create API keys with all-unknown
    /// scopes (silently dropped by `parse_api_key_scope_logged`),
    /// land with zero effective permissions, and see "Insufficient
    /// API key permissions" on every request with no clue why.
    pub const ALL: &'static [ApiKeyScope] = &[
        ApiKeyScope::Admin,
        ApiKeyScope::WorkflowsRead,
        ApiKeyScope::WorkflowsWrite,
        ApiKeyScope::SecretsRead,
        ApiKeyScope::SecretsWrite,
        ApiKeyScope::WebhooksAccess,
    ];

    /// Comma-separated list of the recognized scope strings.
    /// Used by `parse_api_key_scope_logged` for its warn message.
    pub fn scopes_csv() -> String {
        Self::ALL
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Parse from the canonical `:`-separated string form. Unknown
    /// strings return `None`; the caller decides whether to log.
    pub fn from_string(s: &str) -> Option<Self> {
        match s {
            "workflows:read" => Some(ApiKeyScope::WorkflowsRead),
            "workflows:write" => Some(ApiKeyScope::WorkflowsWrite),
            "secrets:read" => Some(ApiKeyScope::SecretsRead),
            "secrets:write" => Some(ApiKeyScope::SecretsWrite),
            "webhooks:access" => Some(ApiKeyScope::WebhooksAccess),
            "admin" => Some(ApiKeyScope::Admin),
            _ => None,
        }
    }
}

impl fmt::Display for ApiKeyScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ApiKeyScope::WorkflowsRead => "workflows:read",
            ApiKeyScope::WorkflowsWrite => "workflows:write",
            ApiKeyScope::SecretsRead => "secrets:read",
            ApiKeyScope::SecretsWrite => "secrets:write",
            ApiKeyScope::WebhooksAccess => "webhooks:access",
            ApiKeyScope::Admin => "admin",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_known_scopes() {
        for scope in [
            ApiKeyScope::WorkflowsRead,
            ApiKeyScope::WorkflowsWrite,
            ApiKeyScope::SecretsRead,
            ApiKeyScope::SecretsWrite,
            ApiKeyScope::WebhooksAccess,
            ApiKeyScope::Admin,
        ] {
            let s = scope.to_string();
            assert_eq!(ApiKeyScope::from_string(&s), Some(scope));
        }
    }

    #[test]
    fn unknown_scope_is_none() {
        assert!(ApiKeyScope::from_string("nope").is_none());
    }
}
