/// Per-actor LLM data-egress ceiling.
///
/// `Tier1` = local Ollama only; data must not leave the host.
/// `Tier2` = external providers allowed.
///
/// **Implemented clients vs. classified providers.** `talos-llm` today ships
/// exactly two clients: Anthropic (`api.anthropic.com`, Tier 2) and Ollama
/// (local, Tier 1). OpenAI and Gemini are *classified* — their hostnames are in
/// `job_protocol::EXTERNAL_LLM_HOSTS` and their vault paths in
/// `LLM_PROVIDER_VAULT_PATHS` so the Tier-1 egress gate already denies them —
/// but no completion client exists for them yet. The classification is
/// deliberate defensive completeness (a future OpenAI/Gemini client inherits a
/// working deny-list on day one), not a claim that those providers are usable.
///
/// Mirrors the wire-protocol enum in `talos_workflow_job_protocol::LlmTier`
/// so request-layer code can take this type directly without depending
/// on the protocol crate; conversion lives at the controller boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmTier {
    /// External providers allowed. Only the Anthropic client is implemented
    /// today; OpenAI/Gemini are deny-list-classified but not yet callable
    /// (see the type-level doc).
    Tier2,
    /// Local Ollama only — data must not leave the host.
    Tier1,
}

impl LlmTier {
    /// Parse the canonical lowercase string form (`"tier1"` / `"tier2"`).
    pub fn from_arg(s: &str) -> Result<Self, String> {
        match s {
            "tier2" => Ok(Self::Tier2),
            "tier1" => Ok(Self::Tier1),
            other => Err(format!(
                "llm_tier must be 'tier1' or 'tier2' (got '{}')",
                talos_text_util::bounded_preview(other, 64)
            )),
        }
    }

    /// String form, suitable for DB storage and external APIs.
    pub fn as_str(&self) -> &'static str {
        match self {
            LlmTier::Tier1 => "tier1",
            LlmTier::Tier2 => "tier2",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for tier in [LlmTier::Tier1, LlmTier::Tier2] {
            assert_eq!(LlmTier::from_arg(tier.as_str()).unwrap(), tier);
        }
    }

    #[test]
    fn unknown_rejected() {
        assert!(LlmTier::from_arg("tier3").is_err());
    }
}
