//! Pure predicates for the one-shot reactive OAuth credential repair.
//!
//! Kept as free functions with no I/O so the two decisions that gate the
//! repair — *is this credential one Talos can refresh?* and *does this failure
//! read as the provider rejecting it?* — are unit-testable without a
//! dispatcher, a resolver, a database, or a provider.
//!
//! # Why a reactive path exists at all
//!
//! The predictive refresh (`SecretsResolver::refresh_vault_paths`, run
//! immediately before every dispatch that carries a `vault://` path) asks
//! "is the RECORDED expiry near?". That is bookkeeping about our own row, not
//! evidence about what the provider will accept. Two observed shapes slip
//! straight past it:
//!
//! 1. the predictive refresh fired but its token-endpoint call failed
//!    transiently — the outcome is logged as a WARN and the OLD token is
//!    dispatched anyway;
//! 2. the provider invalidated the access token before its stated
//!    `expires_in`, so the recorded expiry is comfortably in the future and
//!    the predictive check correctly answers "still valid".
//!
//! Both end as a 401 from the provider at execution time, and neither is
//! reachable by any improvement to an expiry-based predicate. Only the error
//! itself is evidence.

/// The vault-path prefix that marks a secret as an OAuth credential this
/// platform holds a refresh token for.
const OAUTH_PATH_PREFIX: &str = "oauth/";

/// Select the refreshable OAuth credentials from a node's resolved vault paths.
///
/// This is the **narrow** gate on the reactive repair, and it is deliberately
/// structural rather than heuristic: a path under `oauth/` is one this
/// platform minted through the OAuth flow and holds a refresh token for, so a
/// rejection of it is a statement about OUR credential. A 401 from an
/// arbitrary user-supplied host authenticated by a static API key is not —
/// there is nothing to refresh, retrying achieves nothing, and widening the
/// repair to cover it would be a retry on an unbounded population of
/// caller-controlled endpoints.
///
/// Returns an empty vec when the node holds no OAuth credential, which the
/// caller treats as "no repair is possible here" and skips every subsequent
/// step, including the snapshot the repair would need.
pub(crate) fn refreshable_oauth_paths(vault_paths: &[String]) -> Vec<String> {
    vault_paths
        .iter()
        .filter(|p| p.starts_with(OAUTH_PATH_PREFIX))
        .cloned()
        .collect()
}

/// Does this dispatch failure read as *the provider rejected our credential*?
///
/// Only ever consulted for a node that already passed
/// [`refreshable_oauth_paths`], so this predicate does not have to be
/// conservative about unrelated hosts — it only has to separate an
/// authentication rejection from every other way an OAuth-bearing node can
/// fail (fuel exhaustion, a timeout, a 500 from the provider, a module bug).
///
/// The strings it must catch are heterogeneous because each integration module
/// writes its own message; these are the forms observed live:
///
/// ```text
/// Gmail 401: access_token invalid or expired. Call refresh_oauth_token …
/// GET https://gmail.googleapis.com/gmail/v1/users/me/drafts -> HTTP 401: {…}
/// Calendar returned 401
/// calendar API 401: {…}
/// list labels -> 401
/// ```
///
/// **403 is deliberately NOT matched.** A 403 means the credential
/// authenticated and was then denied — a missing or revoked SCOPE, a
/// permission the grant never had. A fresh access token carries exactly the
/// same scopes, so refreshing cannot fix it; retrying would burn a
/// token-endpoint round trip and fail identically. Same reasoning for 429 and
/// every 5xx: real, retryable in other ways, not credential staleness.
pub(crate) fn looks_like_credential_rejection(error_message: &str) -> bool {
    let lower = error_message.to_ascii_lowercase();

    // Textual forms that are unambiguous on their own.
    const AUTH_PHRASES: &[&str] = &[
        "unauthorized",
        "access_token invalid",
        "invalid authentication credentials",
        "invalid_token",
        "token expired",
        "expired token",
        "invalid credentials",
    ];
    if AUTH_PHRASES.iter().any(|p| lower.contains(p)) {
        return true;
    }

    contains_status_401(&lower)
}

/// `true` when `haystack` contains `401` as a standalone number.
///
/// A bare `contains("401")` would match inside a fuel count, a byte offset, a
/// port, or a version string — all of which appear in module error text. The
/// digit/`.` guards on both sides keep `401` from matching `14012`, `4010`, or
/// `1.401`, while still matching every real form: `HTTP 401:`, `-> 401`,
/// `returned 401`, `401 Unauthorized`, `"code": 401,`.
fn contains_status_401(haystack: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut from = 0usize;
    while let Some(rel) = haystack[from..].find("401") {
        let start = from + rel;
        let end = start + 3;
        let before_ok = start == 0 || !matches!(bytes[start - 1], b'0'..=b'9' | b'.');
        let after_ok = end >= bytes.len() || !matches!(bytes[end], b'0'..=b'9' | b'.');
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn selects_only_oauth_paths() {
        let paths = owned(&[
            "oauth/gmail/00000000-0000-0000-0000-000000000000/a@b.com/access_token",
            "anthropic/api_key",
            "oauth/google_calendar/00000000-0000-0000-0000-000000000000/cal/access_token",
            "myservice/webhook_token",
        ]);
        let picked = refreshable_oauth_paths(&paths);
        assert_eq!(picked.len(), 2, "only the two oauth/ paths are refreshable");
        assert!(picked.iter().all(|p| p.starts_with("oauth/")));
    }

    #[test]
    fn a_node_with_no_oauth_credential_offers_nothing_to_repair() {
        // The structural gate: a static-API-key node can never enter the
        // reactive path, however its 401 is worded.
        let paths = owned(&["stripe/secret_key", "github/pat"]);
        assert!(refreshable_oauth_paths(&paths).is_empty());
    }

    #[test]
    fn matches_every_live_observed_401_form() {
        // Verbatim from `workflow_executions.error_message` on this
        // deployment — the whole population of OAuth 401s ever recorded.
        for msg in [
            "execution failure: Component returned error: Gmail 401: access_token invalid or expired. Call refresh_oauth_token to force a refresh.",
            "execution failure: Component returned error: GET https://gmail.googleapis.com/gmail/v1/users/me/drafts?maxResults=25 -> HTTP 401: {\"error\":{\"code\":401,\"message\":\"Request had invalid authentication credentials.\"}}",
            "execution failure: Component returned error: Calendar returned 401",
            "execution failure: Component returned error: calendar API 401: {\"error\":{\"code\":401}}",
            "execution failure: Component returned error: list labels -> 401",
        ] {
            assert!(
                looks_like_credential_rejection(msg),
                "should have matched: {msg}"
            );
        }
    }

    #[test]
    fn does_not_match_a_403_scope_failure() {
        // A refresh returns the SAME scopes, so a scope denial is not
        // repairable and must not consume a retry.
        assert!(!looks_like_credential_rejection(
            "Component returned error: HTTP 403: {\"error\":{\"code\":403,\"message\":\"Request had insufficient authentication scopes.\"}}"
        ));
    }

    #[test]
    fn does_not_match_unrelated_failures() {
        for msg in [
            "Job failed: fuel exhausted after 6000000 units",
            "node 'fetch' failed: Job timed out after 120s",
            "Component returned error: HTTP 500: upstream unavailable",
            "Component returned error: HTTP 429: rate limit exceeded",
            "Component returned error: networkerror: connection reset",
        ] {
            assert!(
                !looks_like_credential_rejection(msg),
                "should NOT have matched: {msg}"
            );
        }
    }

    #[test]
    fn digit_neighbours_do_not_fake_a_401() {
        // The reason `contains("401")` is not good enough: all of these are
        // realistic strings in module error text.
        for msg in [
            "fuel exhausted: used 14012345 of 14012345",
            "byte offset 4010 out of range",
            "connect to 10.0.0.1:4011 refused",
            "module version 1.401.0 is unsupported",
            "read 8401200 bytes",
        ] {
            assert!(
                !looks_like_credential_rejection(msg),
                "digit-adjacent 401 must not match: {msg}"
            );
        }
    }

    #[test]
    fn matches_a_401_at_the_very_end_and_start() {
        assert!(looks_like_credential_rejection("list labels -> 401"));
        assert!(looks_like_credential_rejection("401 Unauthorized"));
    }

    #[test]
    fn matches_word_forms_without_a_status_code() {
        assert!(looks_like_credential_rejection(
            "Atlassian: Unauthorized; token expired"
        ));
        assert!(looks_like_credential_rejection(
            "provider said invalid_token"
        ));
    }
}
