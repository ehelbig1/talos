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
    /// values fall back to `Tier2` (the safer default for backward
    /// compatibility — refusing every LLM call on a typo would be
    /// worse than reverting to current behavior).
    pub fn from_db_str(s: &str) -> Self {
        match s {
            "tier1" => LlmTier::Tier1,
            _ => LlmTier::Tier2,
        }
    }
}
