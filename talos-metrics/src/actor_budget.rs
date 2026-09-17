//! Closed label sets for `talos_actor_budget_refusals_total{cap,mode}` — the
//! counter that says an actor budget refused a workflow start.
//!
//! Package CD (2026-09-17): a budget refusal was only a returned error string,
//! and `on_budget_exceeded = 'alert'` raised no alert — it refused exactly as
//! `block` did. Every refusal now moves this series, and `alert` also raises an
//! ops alert (`talos_actor_budget_refusal`).
//!
//! Every value is an ENUM so the label set is closed by the compiler, and all
//! 15 `(cap, mode)` pairs are pre-seeded at 0: any cap can be set under any mode.
//! No alert: a refusal is the budget working.

/// Which cap refused the start. `as_str` is the `kind` string the atomic
/// backstop reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetCap {
    PerMinute,
    PerHour,
    Total,
    FuelPerHour,
    LlmTokensPerDay,
}

impl BudgetCap {
    pub const ALL: &'static [Self] = &[
        Self::PerMinute,
        Self::PerHour,
        Self::Total,
        Self::FuelPerHour,
        Self::LlmTokensPerDay,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PerMinute => "per_minute",
            Self::PerHour => "per_hour",
            Self::Total => "total",
            Self::FuelPerHour => "fuel_per_hour",
            Self::LlmTokensPerDay => "llm_tokens_per_day",
        }
    }
}

/// `actor_budget_policies.on_budget_exceeded`. The column's CHECK admits
/// exactly these three.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BudgetMode {
    Suspend,
    Alert,
    Block,
}

impl BudgetMode {
    pub const ALL: &'static [Self] = &[Self::Suspend, Self::Alert, Self::Block];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Suspend => "suspend",
            Self::Alert => "alert",
            Self::Block => "block",
        }
    }
    /// Parse the stored column value. `None` for anything else — the CHECK
    /// makes that unreachable, and a caller must not guess a mode.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "suspend" => Some(Self::Suspend),
            "alert" => Some(Self::Alert),
            "block" => Some(Self::Block),
            _ => None,
        }
    }
}
