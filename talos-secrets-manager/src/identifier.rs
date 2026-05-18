//! Typed identifiers for secret lookup. Replaces the implicit
//! split between operator-facing `name` lookups and runtime-facing
//! `key_path` lookups that previously left every name-keyed
//! handler making its own ad-hoc query.
//!
//! See r306 (2026-05-05) for the reconciliation rationale.

use thiserror::Error;
use uuid::Uuid;

/// How a caller refers to a single secret.
///
/// * `Name { name, namespace }` — operator-facing path. Matches
///   what humans typed into `set_secret(name=…)`. Resolves through
///   `SecretsManager::resolve_to_id`, which fails closed with
///   `SecretResolveError::Ambiguous` when more than one row
///   matches (e.g. duplicate names in the same namespace).
///   `namespace = None` searches across all namespaces the user
///   owns; supply `Some(ns)` to scope.
/// * `KeyPath { key_path, namespace }` — runtime-facing path used
///   by `vault://…` substitution. Always namespace-scoped because
///   the on-disk unique constraint is `(namespace, key_path,
///   created_by)`.
/// * `Id(Uuid)` — direct lookup; no ambiguity possible.
///
/// All variants are `created_by`-scoped at the resolver — cross-
/// tenant resolution is impossible regardless of variant.
#[derive(Debug, Clone, Copy)]
pub enum SecretIdentifier<'a> {
    Name {
        name: &'a str,
        namespace: Option<&'a str>,
    },
    KeyPath {
        key_path: &'a str,
        namespace: &'a str,
    },
    Id(Uuid),
}

impl<'a> SecretIdentifier<'a> {
    /// Convenience: by-name without namespace scope (matches the
    /// pre-r306 behaviour of `delete_secret(name)` and friends
    /// when the caller didn't pass a namespace).
    pub fn name(name: &'a str) -> Self {
        Self::Name {
            name,
            namespace: None,
        }
    }

    /// Convenience: by-name scoped to namespace.
    pub fn name_in(name: &'a str, namespace: &'a str) -> Self {
        Self::Name {
            name,
            namespace: Some(namespace),
        }
    }

    /// Convenience: by-key_path within a namespace.
    pub fn key_path(key_path: &'a str, namespace: &'a str) -> Self {
        Self::KeyPath {
            key_path,
            namespace,
        }
    }
}

/// Errors returned by [`crate::SecretsManager::resolve_to_id`].
///
/// Pre-r306 every name-keyed handler did its own SQL and silently
/// picked one row when a `(name, namespace)` lookup matched more
/// than one. That's a real footgun for operators who accidentally
/// create two secrets with the same display name — `delete_secret`
/// would mutate one of N without telling them which. The new
/// resolver fails closed with `Ambiguous` and surfaces the matching
/// IDs so the caller can either pick one explicitly via
/// `SecretIdentifier::Id`, or use the more-specific
/// `SecretIdentifier::KeyPath`.
#[derive(Debug, Error)]
pub enum SecretResolveError {
    /// No row matched the identifier within the user's scope. Maps
    /// to a tool-level "Secret not found or access denied" — the
    /// distinction between "missing" and "owned by someone else"
    /// is deliberately collapsed to avoid leaking existence to
    /// non-owners.
    #[error("Secret not found or access denied")]
    NotFound,

    /// More than one row matched. Returns the matching IDs so the
    /// caller can disambiguate. Operators should either pick a
    /// specific `id` or look up by `key_path` (which is
    /// per-tenant unique). Surfacing IDs is safe — they are
    /// non-secret values already exposed elsewhere in the API.
    #[error("Multiple secrets matched the identifier ({matches:?}); specify key_path or id to disambiguate")]
    Ambiguous { matches: Vec<Uuid> },

    /// Required-path repository call returned an error. Logged at
    /// `error!` by the resolver; callers receive the generic
    /// mapped message.
    #[error("internal error: {0}")]
    Internal(#[from] anyhow::Error),
}

impl SecretResolveError {
    /// Stable JSON-RPC error code for protocol wrappers. Pairs
    /// with `user_facing_message()` for the tool-response shape.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            // NotFound + Ambiguous are caller-fixable; Internal is
            // server-side. All map to -32000 (the existing tool
            // error code) — InvalidArg in JSON-RPC reserves for
            // structural issues like missing required fields,
            // which the handler validates before reaching here.
            Self::NotFound | Self::Ambiguous { .. } | Self::Internal(_) => -32000,
        }
    }

    /// Caller-facing message. NotFound + Ambiguous pass through
    /// (already redacted by design); Internal collapses to a
    /// generic string so SQL / schema details don't leak.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::NotFound | Self::Ambiguous { .. } => self.to_string(),
            Self::Internal(_) => "Internal error".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_codes_are_stable() {
        assert_eq!(SecretResolveError::NotFound.jsonrpc_code(), -32000);
        assert_eq!(
            SecretResolveError::Ambiguous {
                matches: vec![Uuid::nil()]
            }
            .jsonrpc_code(),
            -32000
        );
        assert_eq!(
            SecretResolveError::Internal(anyhow::anyhow!("boom")).jsonrpc_code(),
            -32000,
        );
    }

    #[test]
    fn internal_user_message_does_not_leak_detail() {
        let err = SecretResolveError::Internal(anyhow::anyhow!(
            "ERROR: column \"created_by_v2\" of relation \"secrets\" does not exist"
        ));
        assert_eq!(err.user_facing_message(), "Internal error");
    }

    #[test]
    fn not_found_message_is_generic() {
        assert_eq!(
            SecretResolveError::NotFound.user_facing_message(),
            "Secret not found or access denied"
        );
    }

    #[test]
    fn ambiguous_message_includes_match_count_hint() {
        let err = SecretResolveError::Ambiguous {
            matches: vec![Uuid::nil(), Uuid::nil()],
        };
        let m = err.user_facing_message();
        assert!(m.contains("Multiple"), "msg: {}", m);
        assert!(m.contains("disambiguate"), "msg: {}", m);
    }

    #[test]
    fn name_constructors_set_namespace_correctly() {
        match SecretIdentifier::name("foo") {
            SecretIdentifier::Name { name, namespace } => {
                assert_eq!(name, "foo");
                assert_eq!(namespace, None);
            }
            _ => panic!("expected Name variant"),
        }
        match SecretIdentifier::name_in("foo", "default") {
            SecretIdentifier::Name { name, namespace } => {
                assert_eq!(name, "foo");
                assert_eq!(namespace, Some("default"));
            }
            _ => panic!("expected Name variant"),
        }
    }

    #[test]
    fn key_path_constructor_pins_namespace() {
        match SecretIdentifier::key_path("anthropic/api_key", "default") {
            SecretIdentifier::KeyPath { key_path, namespace } => {
                assert_eq!(key_path, "anthropic/api_key");
                assert_eq!(namespace, "default");
            }
            _ => panic!("expected KeyPath variant"),
        }
    }
}
