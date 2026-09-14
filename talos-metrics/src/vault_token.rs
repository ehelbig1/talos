//! Closed label sets for the Vault KEK-token renewal instruments —
//! `talos_vault_token_renewals_total{outcome}` and
//! `talos_vault_token_ttl_seconds{lifetime}`.
//!
//! Why they exist (2026-09-14): with `KEK_PROVIDER=vault` (the chart default)
//! every DEK wrap and unwrap is a transit call authenticated by ONE token, and
//! nothing in the workspace ever renewed it. The chart's vault-init Job mints
//! that token with `-period=768h` under a comment saying it "auto-renews every
//! 32d as long as the controller is calling Vault". Vault does not renew a
//! token because it is used — measured on the dev Vault: a 45 s periodic
//! token used for `transit/encrypt` every 10 s counted down 45 → 5 and the
//! next encrypt returned 403. So an installer-built cluster lost its KEK path
//! 32 days after install, with no series anywhere counting down to it.
//!
//! Both label sets are ENUMS so the compiler closes them. The counter's three
//! outcomes are seeded at 0 by [`crate::seed_vault_token_renewals_on`], called
//! by the renewal loop when — and only when — a Vault KEK provider is
//! running: on an `env`-KEK deployment nothing can increment them, and a
//! seeded series nothing can move is check 58's defect. The gauge is NOT
//! seeded: it is a reading, not a count, and a seeded 0 would say "expires
//! now".

/// Outcome of one `auth/token/renew-self` attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultTokenRenewalOutcome {
    /// Vault extended the token by the full requested increment.
    Renewed,
    /// Vault answered, but granted LESS than the full increment (or reported
    /// the token no longer renewable): the token has reached its maximum TTL
    /// and WILL expire. `TalosVaultTokenCapped` reads this.
    Capped,
    /// The renewal did not succeed (transport error, non-2xx, malformed
    /// body). `TalosVaultTokenRenewalFailing` reads this.
    Failed,
}

impl VaultTokenRenewalOutcome {
    pub const ALL: &'static [Self] = &[Self::Renewed, Self::Capped, Self::Failed];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Renewed => "renewed",
            Self::Capped => "capped",
            Self::Failed => "failed",
        }
    }
}

/// What the token's own `lookup-self` says about how it can live.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VaultTokenLifetimeLabel {
    /// Renewable, periodic, no explicit max TTL: renewal extends it forever.
    Periodic,
    /// Renewable but bounded by a maximum TTL: renewal extends it until then.
    RenewableBounded,
    /// Finite TTL and not renewable: expires no matter what.
    Expiring,
    /// No TTL at all (e.g. a root token): nothing to renew.
    NonExpiring,
}

impl VaultTokenLifetimeLabel {
    pub const ALL: &'static [Self] = &[
        Self::Periodic,
        Self::RenewableBounded,
        Self::Expiring,
        Self::NonExpiring,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Periodic => "periodic",
            Self::RenewableBounded => "renewable_bounded",
            Self::Expiring => "expiring",
            Self::NonExpiring => "non_expiring",
        }
    }
}
