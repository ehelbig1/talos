//! Closed label set for `talos_local_llm_fleet_admission_total{outcome}` —
//! the controller's view of the fleet-wide local-inference queue (RFC 0014
//! P3b). The worker exports the same outcomes as
//! `wasm_llm_fleet_admission_total`.
//!
//! The outcomes are DUPLICATED from `talos_local_inference::fleet::FleetOutcome`
//! rather than imported: importing would pull redis and reqwest into this
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
