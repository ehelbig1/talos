//! Closed label sets for the embedding-provider instrument:
//! `talos_embedding_requests_total{outcome}` and
//! `talos_embedding_gate_total{outcome}`.
//!
//! The values are the wire spellings `talos_memory::embedding` reports;
//! `talos-memory` cannot be a dependency of this crate, so the two lists meet
//! in a test there (`embedding::observer_tests`).

/// What one call to the embedding provider came to. One per call that
/// reached the provider — a cache hit, or a caller that shared another
/// caller's in-flight request, is not a provider call and is not counted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmbeddingOutcome {
    /// A vector of the configured dimensions came back.
    Ok,
    /// The provider answered and the answer cannot be used: a 4xx, or a
    /// vector of the wrong dimensions. Not retried.
    Rejected,
    /// No usable answer after the retry: timeout, transport error, 5xx or a
    /// malformed body. The caller falls back to keyword search, or stores a
    /// row without an embedding.
    Unavailable,
}

impl EmbeddingOutcome {
    /// Every value, in the order they are pre-seeded.
    pub const ALL: &'static [Self] = &[Self::Ok, Self::Rejected, Self::Unavailable];

    /// The label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Rejected => "rejected",
            Self::Unavailable => "unavailable",
        }
    }
}

/// How a provider call passed the in-flight gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EmbeddingGateOutcome {
    /// It held a slot for the whole call.
    Acquired,
    /// No slot came free within the wait bound; the call went ahead without
    /// one. A load signal: the queue did not drain.
    WaitExpired,
    /// The gate does not apply: it is disabled, or the provider is external.
    /// A steady state, not a load signal.
    Ungated,
}

impl EmbeddingGateOutcome {
    /// Every value, in the order they are pre-seeded.
    pub const ALL: &'static [Self] = &[Self::Acquired, Self::WaitExpired, Self::Ungated];

    /// The label value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Acquired => "acquired",
            Self::WaitExpired => "wait_expired",
            Self::Ungated => "ungated",
        }
    }
}
