//! The WEAK marker: "this module's last call to the outside world was an HTTP
//! call that failed host-side, and then it returned an error".
//!
//! # Why a second marker
//!
//! `[reason_class=<token>]` is stamped only when the module's own error text
//! carries the WIT discriminant the class explains (`networkerror`, …). That
//! bound is deliberate: both classifiers check their transient bucket BEFORE
//! `auth_failure`, so a class stamped onto unrelated text would turn
//! `401 Unauthorized` into a retried failure. But it leaves a module that
//! says nothing useful — `Err("failed")` after a DNS failure — classified
//! `unknown`: not retried, and shown to the operator as "unclassified".
//! Five catalog templates were fixed by hand on 2026-10-12 to keep the word;
//! a module outside the catalog still drops it.
//!
//! This marker carries the same fact with a WEAKER claim, and two bounds keep
//! it from reintroducing the mis-attribution:
//!
//! 1. **The worker emits it only when nothing else followed the failed call.**
//!    A module that swallowed a failed fetch, then read memory or called a
//!    model, and then failed, gets no marker: the failure is not the last
//!    thing it did. (Logging and the pure helpers do not count.)
//! 2. **A classifier consults it LAST**, after every rule it already had. A
//!    message that says `401`, `fuel exhausted` or `forbiddenhost` classifies
//!    exactly as it did. Only a message nothing else recognises is upgraded.
//!
//! # Why the vocabulary is its own
//!
//! The words here are chosen to match NO rule in any of the substring
//! classifiers that read failure text (`talos_retry_intelligence`, the
//! ops-alert self-monitor, the failure-analysis service, the worker's own
//! transient gate). Writing the class token itself (`timeout`, `secret-lookup`)
//! would have those classifiers read the MARKER as prose: `timeout` matches
//! the timeout rule, which runs before `auth_failure`. `inert_to_prose_rules`
//! in each consumer pins this.
//!
//! No host is carried. A hostname is free text, and `sql.example.test` or
//! `timeout-service.example.test` in a failure message is exactly what those
//! substring rules cannot tell from a cause.

use crate::Family;

/// The text every weak marker starts with, after its `[`.
pub const KEY: &str = "after_host_failure=";

/// What kind of host-side HTTP failure preceded the module's error.
///
/// Coarser than [`Family`] on purpose: it answers "should this be tried
/// again, and what would an operator call it", not "which gate".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AfterHostFailure {
    /// The call did not get an answer: DNS, TLS, connect, send, or a broken
    /// response stream. Worth trying again.
    Unreachable,
    /// The call's deadline elapsed. Worth trying again.
    Late,
    /// A policy refused the call: allowlist, SSRF, tier, write ceiling,
    /// method, capability world, a budget, a size cap. The same refusal
    /// awaits a retry.
    Denied,
    /// The per-host circuit breaker was open.
    BreakerOpen,
    /// The URL was unusable. An authoring error.
    BadUrl,
    /// A `vault://` header could not be resolved.
    Credential,
}

impl AfterHostFailure {
    /// Every kind, for tests that must cover the vocabulary.
    pub const ALL: [Self; 6] = [
        Self::Unreachable,
        Self::Late,
        Self::Denied,
        Self::BreakerOpen,
        Self::BadUrl,
        Self::Credential,
    ];

    /// The word in the marker. Lowercase, and matched by no prose rule.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unreachable => "unreachable",
            Self::Late => "late",
            Self::Denied => "denied",
            Self::BreakerOpen => "breaker",
            Self::BadUrl => "badurl",
            Self::Credential => "credential",
        }
    }

    /// The kind a latched class belongs to, or `None` for one the weak marker
    /// does not speak for.
    ///
    /// `Cancelled` has none: an abandoned call is not a cause. The local-LLM
    /// timeout classes are [`Family::Timeout`] and would map to `Late`; the
    /// worker excludes them before asking (their retry rules are their own).
    #[must_use]
    pub const fn from_family(family: Family) -> Option<Self> {
        Some(match family {
            Family::Transport => Self::Unreachable,
            Family::Timeout => Self::Late,
            Family::CircuitOpen => Self::BreakerOpen,
            Family::MalformedUrl => Self::BadUrl,
            Family::SecretLookup => Self::Credential,
            Family::ResponseCap
            | Family::RequestCap
            | Family::InsecureScheme
            | Family::CapabilityWorld
            | Family::HostAllowlist
            | Family::PrivateAddress
            | Family::ActorEgressTier
            | Family::WriteCeiling
            | Family::MethodAllowlist
            | Family::EgressBudget
            | Family::GraphqlIntrospection => Self::Denied,
            Family::Cancelled => return None,
        })
    }

    /// Whether a failure of this kind is worth trying again.
    #[must_use]
    pub const fn is_transient(self) -> bool {
        matches!(self, Self::Unreachable | Self::Late)
    }
}

/// The rendered marker, e.g. `[after_host_failure=unreachable]`.
#[must_use]
pub fn marker(kind: AfterHostFailure) -> String {
    format!("[{KEY}{}]", kind.as_str())
}

/// The weak marker in a failure message, if it carries one this build knows.
///
/// `lower` MUST already be lowercased and length-capped by the caller, as for
/// [`crate::token`]; a message longer than the cap hides its marker and
/// classifies as it did before.
#[must_use]
pub fn parse(lower: &str) -> Option<AfterHostFailure> {
    let start = lower.find(KEY)? + KEY.len();
    let rest = &lower[start..];
    let word = &rest[..rest.find(']').unwrap_or(rest.len())];
    AfterHostFailure::ALL
        .into_iter()
        .find(|kind| kind.as_str() == word)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_marker_reads_back_as_the_kind_it_was_written_for() {
        for kind in AfterHostFailure::ALL {
            let message = format!("component returned error: failed {}", marker(kind));
            assert_eq!(parse(&message), Some(kind));
        }
        assert_eq!(parse("component returned error: failed"), None);
        assert_eq!(parse("failed [after_host_failure=]"), None);
        assert_eq!(parse("failed [after_host_failure=something-newer]"), None);
    }

    #[test]
    fn every_class_token_has_a_kind_or_is_cancellation() {
        for token in crate::ALL {
            let family = crate::family(token).expect("every token has a family");
            match AfterHostFailure::from_family(family) {
                Some(_) => {}
                None => assert_eq!(family, Family::Cancelled, "{token} has no kind"),
            }
        }
    }

    #[test]
    fn only_a_call_that_got_no_answer_is_worth_trying_again() {
        let transient: Vec<AfterHostFailure> = AfterHostFailure::ALL
            .into_iter()
            .filter(|k| k.is_transient())
            .collect();
        assert_eq!(
            transient,
            [AfterHostFailure::Unreachable, AfterHostFailure::Late]
        );
        // A refusal by the allowlist is the case that must never be retried.
        assert_eq!(
            AfterHostFailure::from_family(Family::HostAllowlist),
            Some(AfterHostFailure::Denied)
        );
        assert!(!AfterHostFailure::Denied.is_transient());
    }

    /// The marker's own words must not be the strong marker's, or a reader of
    /// one would find the other.
    #[test]
    fn the_weak_marker_is_not_readable_as_the_strong_one() {
        for kind in AfterHostFailure::ALL {
            let text = marker(kind);
            assert_eq!(crate::token(&text), None, "{text}");
            assert!(!crate::ALL.contains(&kind.as_str()), "{}", kind.as_str());
        }
    }
}
