//! Label sets for the RustSec advisory-database age series (2026-09-22).
//!
//! `check_advisory_db_age` (talos-compilation) warns at 30 days and, in
//! production, REFUSES every Rust compile and `cargo audit` once the baked
//! `/opt/talos-advisory-db` is older than `TALOS_ADVISORY_DB_MAX_AGE_DAYS`
//! (default 90). Until this module existed that age was computed only when
//! somebody compiled — the reference controller's copy was 75 days old on
//! 2026-09-22 and nothing counted down to the day the gate would start
//! refusing. Same shape as the Vault KEK token before package BA: a
//! deterministic cliff with no series in front of it.
//!
//! Both label sets are closed at compile time. `copy` names WHICH baked copy
//! was sampled: the controller and the builder image each bake their own,
//! the gate stats the controller's, and in container mode `cargo audit`
//! reads the builder's (measured 2026-09-22: 2026-07-09 vs 2026-07-07). Only
//! the controller's copy is sampled today; the label is what lets a
//! builder-side sampler join without renaming the series.

/// Which baked copy of the advisory database a sample describes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdvisoryDbCopy {
    /// The copy baked into the controller image — the one the compile gate
    /// `check_advisory_db_age` consults.
    Controller,
}

impl AdvisoryDbCopy {
    pub const ALL: &'static [Self] = &[Self::Controller];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Controller => "controller",
        }
    }
}

/// Outcome of one age sample.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdvisoryDbSampleOutcome {
    /// The age was read; `talos_advisory_db_age_days` was set from it.
    Measured,
    /// The database could not be dated (missing, unreadable, or dated in
    /// the future). The age gauge is NOT touched — its last reading, if any,
    /// stands — so this counter is what says the reading is stale.
    /// `TalosAdvisoryDbUnreadable` reads it.
    Unreadable,
}

impl AdvisoryDbSampleOutcome {
    pub const ALL: &'static [Self] = &[Self::Measured, Self::Unreadable];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::Unreadable => "unreadable",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_sets_are_closed_and_distinct() {
        let copies: Vec<&str> = AdvisoryDbCopy::ALL.iter().map(|c| c.as_str()).collect();
        assert_eq!(copies, ["controller"]);
        let outcomes: Vec<&str> = AdvisoryDbSampleOutcome::ALL
            .iter()
            .map(|o| o.as_str())
            .collect();
        assert_eq!(outcomes, ["measured", "unreadable"]);
    }
}
