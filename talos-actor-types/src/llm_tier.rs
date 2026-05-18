/// Per-actor LLM data-egress ceiling.
///
/// `Tier1` = local Ollama only; data must not leave the host.
/// `Tier2` = external providers (Anthropic / OpenAI / Gemini) allowed.
///
/// Mirrors the wire-protocol enum in `talos_workflow_job_protocol::LlmTier`
/// so request-layer code can take this type directly without depending
/// on the protocol crate; conversion lives at the controller boundary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmTier {
    /// External providers allowed (Anthropic / OpenAI / Gemini).
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
