//! Typed errors for [`crate::EvaluationService`], following the canonical
//! cross-protocol service pattern (stable `jsonrpc_code()` + a
//! `user_facing_message()` that collapses internal detail so the protocol
//! response never leaks schema/query internals).

use thiserror::Error;

#[derive(Debug, Error)]
pub enum EvaluationError {
    /// Caller supplied something invalid (no tasks, too many, bad wait).
    #[error("{0}")]
    InvalidArgument(String),

    /// The actor is tier-1 (local-only) but no local Ollama judge is wired,
    /// so its outputs cannot be judged without risking external egress. Fail
    /// closed — never judge a tier-1 actor's content on an external provider.
    #[error("cannot evaluate tier-1 actor: no local judge available (wire Ollama to judge tier-1 outputs locally)")]
    TierSkip,

    /// A trigger/dispatch of one arm failed. Message is pre-sanitised.
    #[error("{0}")]
    Orchestration(String),

    /// The judge LLM call failed for every attempt.
    #[error("judge model call failed")]
    Judge,

    /// Internal error (DB, decrypt, serialization). Collapsed on the wire.
    #[error("internal evaluation error")]
    Internal(#[from] anyhow::Error),
}

impl EvaluationError {
    /// Stable JSON-RPC error code mapping (mirrors `OrchestrationError`).
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::InvalidArgument(_) => -32602,
            Self::TierSkip => -32004,
            Self::Orchestration(_) => -32000,
            Self::Judge => -32000,
            Self::Internal(_) => -32000,
        }
    }

    /// Operator-safe message. `Internal` collapses to a generic string so a DB
    /// or crypto error never leaks details onto the protocol surface.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::Internal(_) => "internal evaluation error".to_string(),
            other => other.to_string(),
        }
    }
}
