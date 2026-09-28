//! Closed label sets for the controller's local-inference series:
//! `talos_local_llm_fleet_admission_total{outcome}` (the fleet-wide queue,
//! RFC 0014 P3b; the worker's twin is `wasm_llm_fleet_admission_total`) and
//! `talos_local_llm_timeouts_total{kind}` (which progress deadline cut an
//! exchange, RFC 0014 P4a; the worker's twin is `wasm_llm_timeouts_total`).
//!
//! Both are DUPLICATED from `talos_local_inference` (`FleetOutcome`,
//! `StallKind`) rather than imported: importing would pull redis and reqwest into this
//! crate. The controller maps one to the other with an exhaustive match, and a
//! test there pins the label strings equal (the `RPC_WRITE_CEILING_SUBJECTS`
//! precedent).

/// What happened when a call asked the fleet queue for a slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalLlmFleetOutcome {
    Leased,
    WaitExpired,
    Unavailable,
    LeaseLost,
}

impl LocalLlmFleetOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Leased,
        Self::WaitExpired,
        Self::Unavailable,
        Self::LeaseLost,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Leased => "leased",
            Self::WaitExpired => "wait_expired",
            Self::Unavailable => "unavailable",
            Self::LeaseLost => "lease_lost",
        }
    }
}

/// Which progress deadline cut a local LLM exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalLlmTimeoutKind {
    FirstByte,
    Idle,
    Ceiling,
}

impl LocalLlmTimeoutKind {
    pub const ALL: &'static [Self] = &[Self::FirstByte, Self::Idle, Self::Ceiling];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FirstByte => "first_byte",
            Self::Idle => "idle",
            Self::Ceiling => "ceiling",
        }
    }
}
