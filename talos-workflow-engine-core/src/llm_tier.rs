//! LLM data-egress tier — privacy ceiling that gates which LLM
//! providers a job may reach.
//!
//! **Tier 1** = local-only (Ollama). Payloads stay on-host; nothing
//! leaves the system. Suitable for actors processing private data
//! (medical, financial, relationship context) where third-party
//! retention is unacceptable.
//!
//! **Tier 2** = external providers (Anthropic / `OpenAI` / Gemini).
//! Payloads leave the system. DLP scrubbing is best-effort; treat as
//! "anything sent here is potentially seen by the provider".
//!
//! Per-actor ceiling (`actors.max_llm_tier` in the controller schema)
//! gates which tier a job dispatched on behalf of that actor may
//! reach. Default `Tier2` (no restriction) for backward compatibility;
//! operators flip sensitive actors to `Tier1`.
//!
//! Lives in core (rather than job-protocol) because the engine's
//! `DispatchJob` data model carries it through the dispatcher
//! pipeline, and core is below job-protocol in the dependency graph.
//! The wire-format and provider classification helpers live in
//! job-protocol where they belong (alongside `LLM_PROVIDER_VAULT_PATHS`).

use serde::{Deserialize, Serialize};

/// Pluggable LLM data-egress ceiling for a `DispatchJob`.
///
/// `#[non_exhaustive]` so adding a new tier (e.g. an enterprise-only
/// regional ceiling) in a minor bump doesn't break downstream
/// exhaustive-match consumers.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum LlmTier {
    /// Local-only providers (Ollama). Payloads MUST NOT leave the host.
    Tier1,
    /// External providers permitted (Anthropic / `OpenAI` / Gemini).
    #[default]
    Tier2,
}

impl LlmTier {
    /// Wire-format string used in the `JobRequest` signing payload and
    /// in the `actors.max_llm_tier` database column. Stable — never
    /// reorder or rename without coordinating a controller+worker
    /// restart.
    pub fn as_signing_str(self) -> &'static str {
        match self {
            LlmTier::Tier1 => "tier1",
            LlmTier::Tier2 => "tier2",
        }
    }

    /// Parse from the database-canonical string. Unknown / mistyped
    /// values fall back to `Tier1` (the fail-closed posture: a guest
    /// processing a row with an unrecognised `actors.max_llm_tier`
    /// value gets the most-restrictive ceiling, not the least).
    ///
    /// Pre-r306 the fallback was `Tier2` ("refusing every LLM call on a
    /// typo would be worse than reverting to current behavior"). That
    /// argument is incorrect: Tier1 still permits LLM calls via local
    /// Ollama — it does not "refuse every LLM call", only external
    /// providers. The previous fallback fail-opened on column drift /
    /// migration bugs / manual operator typos in the database.
    ///
    /// Note: `apply_actor_to_engine` already fail-closes to Tier1 on
    /// "actor not found" and on DB errors. This fix closes the
    /// remaining gap: an actor row that exists but has a malformed
    /// `max_llm_tier` value (e.g. `tier3`, `null`, or a stale value
    /// from a future migration).
    ///
    /// Recognised tokens are `"tier1"` and `"tier2"`; everything else
    /// (including the empty string) lands in `Tier1`.
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "tier2" => LlmTier::Tier2,
            // All other values — including "tier1" (canonical),
            // unrecognised tokens, and empty strings — get Tier1.
            // The explicit "tier1" arm is folded into the wildcard
            // for fail-closed correctness: even a future column-name
            // typo cannot accidentally upgrade an actor to Tier2.
            _ => LlmTier::Tier1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::LlmTier;

    #[test]
    fn canonical_strings_round_trip() {
        assert_eq!(LlmTier::from_db_str("tier1"), LlmTier::Tier1);
        assert_eq!(LlmTier::from_db_str("tier2"), LlmTier::Tier2);
        assert_eq!(LlmTier::Tier1.as_signing_str(), "tier1");
        assert_eq!(LlmTier::Tier2.as_signing_str(), "tier2");
    }

    #[test]
    fn unknown_db_value_fails_closed_to_tier1() {
        // SECURITY: any garbage / drift / migration-bug value in
        // `actors.max_llm_tier` MUST land on Tier1 (local-only),
        // not Tier2 (external providers). Pre-r306 the fallback
        // was Tier2 which fail-OPENED — a column typo could leak
        // private actor data to api.openai.com.
        assert_eq!(LlmTier::from_db_str("tier3"), LlmTier::Tier1);
        assert_eq!(LlmTier::from_db_str("TIER1"), LlmTier::Tier1); // case-sensitive
        assert_eq!(LlmTier::from_db_str(""), LlmTier::Tier1);
        assert_eq!(LlmTier::from_db_str("null"), LlmTier::Tier1);
        assert_eq!(LlmTier::from_db_str("local"), LlmTier::Tier1);
        // Any future tier added to the enum must explicitly opt into
        // being parsed — bare addition to the enum is not enough.
    }

    #[test]
    fn from_db_str_is_case_sensitive_by_design() {
        // The wire format is documented as lowercase. We don't accept
        // mixed case so a controller writing the wrong case (e.g. via
        // an admin tool's input form) lands in Tier1 — the operator
        // sees the restrictive behaviour and fixes the input, rather
        // than silently getting Tier2 behaviour that was never
        // intentionally configured.
        assert_eq!(LlmTier::from_db_str("Tier1"), LlmTier::Tier1);
        assert_eq!(LlmTier::from_db_str("Tier2"), LlmTier::Tier1);
        assert_eq!(LlmTier::from_db_str("TIER2"), LlmTier::Tier1);
    }
}
