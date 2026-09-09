//! What an outcome means to an OPERATOR — the ONE class notion, shared by
//! every instrument on this platform.
//!
//! # Why one type and not one per surface
//!
//! #787 built this partition for the signed-RPC data plane
//! (`talos_rpc_subscribers`); package 35 needed the same question answered of
//! the MCP `tools/call` surface. The per-surface OUTCOME vocabularies are
//! legitimately different — `talos.memory.op` can answer `not_promoted` and
//! `tools/call` cannot — but "is the platform declining, or failing?" is ONE
//! question and an operator asks it of both. Two enums with the same three
//! spellings is two places for `served|declined|finding` to drift; one type
//! with one `as_str` cannot. That is why this moved out of `rpc.rs` and lost
//! its `Rpc` prefix rather than being copied.

/// What an outcome means to an OPERATOR, which is a different question from
/// what it means to the caller.
///
/// This is the ONE home the `talos_rpc` log level rests on, the `class` label
/// on [`crate::TalosMetrics::rpc_calls_total`], and therefore the one home a
/// future alert selector rests on too. Modelled on
/// `talos_task_supervision::TaskExit::is_finding` (#780): the question is not
/// "did the platform fail" but "should someone look at this".
///
/// Before this existed the partition was binary — `outcome == "ok"` was
/// `debug!` and EVERYTHING else was `warn!` — so a designed pre-promotion
/// state produced 53% of the controller's entire WARN volume, hourly,
/// forever. That is check 69's harm: a level that fires forever on a healthy
/// fleet trains operators to ignore that level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum OutcomeClass {
    /// The call was answered. High volume, routine, uninteresting on its own.
    Served,
    /// The platform answered CORRECTLY by declining: a policy refusal, a
    /// designed lifecycle state, a configured cap, or a caller error the
    /// caller was told about. A healthy fleet produces these and no operator
    /// action follows from one of them.
    Declined,
    /// Someone should look: either the platform could not serve the call, or
    /// the call should not have arrived in the shape it did.
    Finding,
}

impl OutcomeClass {
    /// The one predicate. Named for #780's precedent so the two read alike.
    #[must_use]
    pub const fn is_finding(self) -> bool {
        matches!(self, Self::Finding)
    }

    /// The `class` label value.
    ///
    /// Three compile-time values, and `class` is a pure function of `outcome`,
    /// so this label adds NO series: every `(subject, outcome)` has exactly
    /// one class.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Served => "served",
            Self::Declined => "declined",
            Self::Finding => "finding",
        }
    }

    /// Every variant, for the tests and for anything that must enumerate the
    /// partition.
    pub const ALL: &'static [Self] = &[Self::Served, Self::Declined, Self::Finding];
}
