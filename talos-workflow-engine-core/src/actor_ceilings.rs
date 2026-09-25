//! The per-actor ceilings that travel on every signed job, as ONE value.
//!
//! # Why one struct (2026-09-25)
//!
//! `actors.http_verb_ceiling` (package EL, 2026-09-24) was the fourth ceiling
//! axis, and it was carried on the top-level trigger path and DROPPED on the
//! two paths that copy ceilings from one place to another by listing the axes
//! by hand:
//!
//! * **sub-workflow binding.** `apply_subworkflow_binding` stamped tier, write
//!   ceiling and egress and never the verb override, and the resolver always
//!   answered `None` for it because the repository query never read the
//!   column. A child bound to a `readonly` actor therefore inherited the
//!   PARENT's `Some(Write)` override — POST-shaped egress for an actor whose
//!   operator had said "no writes" — and the DB-error fail-closed binding kept
//!   it too.
//! * **actor clone.** The clone copied `max_llm_tier`, `egress_scope` and
//!   `max_write_ceiling` and not the verb override, so a clone of a
//!   `write` + `http_verb_ceiling = readonly` actor (one that may keep notes
//!   but must not POST) came out able to POST.
//!
//! Both are the same defect: an axis list written out at a copy site, where a
//! new axis compiles cleanly by being absent. The answer is structural — the
//! four axes are one type, every consumer that COPIES them destructures it
//! exhaustively (no `..`), and adding a fifth axis is a compile error at each
//! place it would otherwise be silently dropped.
//!
//! # What is deliberately NOT a member
//!
//! `max_capability_world` is also a per-actor ceiling, but it does not travel
//! on the job and it carries its own exemption rule (the user's DEFAULT actor
//! is ceiling-exempt, `None`), so it is stamped separately by
//! `apply_actor_to_engine` and gated at dispatch. Folding it in here would
//! give one of the five axes a meaning (`None` = exempt) that none of the
//! other four has.

use crate::{effective_write_ceiling, CeilingAxis, EgressScope, LlmTier, WriteCeiling};

/// The four per-actor ceilings a job is signed with.
///
/// Construct with a struct literal (every field, no `..Default::default()` —
/// there is deliberately no `Default`, because the permissive value of every
/// axis is the wrong one to fall into) and consume by exhaustive destructure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActorCeilings {
    /// `actors.max_llm_tier` — the data-egress ceiling for LLM providers.
    pub max_llm_tier: LlmTier,
    /// `actors.max_write_ceiling` — the data-mutation ceiling.
    pub max_write_ceiling: WriteCeiling,
    /// `actors.http_verb_ceiling` — override for the VERB-INFERRED half of the
    /// write ceiling. `None` inherits `max_write_ceiling`.
    pub http_verb_ceiling: Option<WriteCeiling>,
    /// `actors.egress_scope` — blanket public-egress override. `None` is the
    /// tier-derived default.
    pub egress_scope: Option<EgressScope>,
}

impl ActorCeilings {
    /// The most restrictive value on every axis — what a binding that could
    /// not be READ must run at.
    ///
    /// `http_verb_ceiling` is an EXPLICIT `Some(ReadOnly)`, not `None`: `None`
    /// would be restrictive only because the ceiling beside it is, a
    /// coincidence that stops holding the moment either line is edited.
    /// Likewise `egress_scope` is an explicit `Some(Local)`.
    pub const FAIL_CLOSED: Self = Self {
        max_llm_tier: LlmTier::Tier1,
        max_write_ceiling: WriteCeiling::ReadOnly,
        http_verb_ceiling: Some(WriteCeiling::ReadOnly),
        egress_scope: Some(EgressScope::Local),
    };

    /// The ceiling the three verb-inferring gates actually apply.
    #[must_use]
    pub fn effective_http_verb(self) -> WriteCeiling {
        effective_write_ceiling(
            CeilingAxis::VerbInferred,
            self.max_write_ceiling,
            self.http_verb_ceiling,
        )
    }

    /// The scope the worker's blanket public-egress gate actually applies.
    #[must_use]
    pub fn effective_egress(self) -> EgressScope {
        EgressScope::effective(self.egress_scope, self.max_llm_tier)
    }

    /// Compose a parent's ceilings with a sub-workflow actor's RAW ceilings
    /// for a child engine: the more restrictive of the two on EVERY axis. The
    /// result can only ever be narrower than either side.
    ///
    /// Two axes are `Option`s whose `None` means "derive from a sibling axis",
    /// and both are resolved to their EFFECTIVE value on each side before they
    /// are compared, then stamped EXPLICITLY:
    ///
    /// * `egress_scope`: a child air-gapped only by its tier default (egress
    ///   NULL on a `tier1` actor) must not be widened by a parent's explicit
    ///   `Public`.
    /// * `http_verb_ceiling`: a child whose override is NULL inherits ITS OWN
    ///   `max_write_ceiling`, not the parent's override. Comparing the raw
    ///   `Option`s — the rule this replaces, `narrow_verb_inference_override`
    ///   — read the child's `None` as "no opinion" and let a parent's
    ///   `Some(Write)` through to a `readonly` child.
    ///
    /// Destructures both sides exhaustively: a fifth axis is a compile error
    /// here until its narrowing rule is written.
    #[must_use]
    pub fn narrowed_for_child(self, child: Self) -> Self {
        let Self {
            max_llm_tier: parent_tier,
            max_write_ceiling: parent_write,
            http_verb_ceiling: _,
            egress_scope: _,
        } = self;
        let Self {
            max_llm_tier: child_tier,
            max_write_ceiling: child_write,
            http_verb_ceiling: _,
            egress_scope: _,
        } = child;
        Self {
            max_llm_tier: parent_tier.most_restrictive(child_tier),
            max_write_ceiling: parent_write.most_restrictive(child_write),
            http_verb_ceiling: Some(
                self.effective_http_verb()
                    .most_restrictive(child.effective_http_verb()),
            ),
            egress_scope: EgressScope::narrow(
                Some(self.effective_egress()),
                Some(child.effective_egress()),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::ActorCeilings;
    use crate::{EgressScope, LlmTier, WriteCeiling};
    use WriteCeiling::{ReadOnly, Write};

    fn c(write: WriteCeiling, verb: Option<WriteCeiling>) -> ActorCeilings {
        ActorCeilings {
            max_llm_tier: LlmTier::Tier2,
            max_write_ceiling: write,
            http_verb_ceiling: verb,
            egress_scope: None,
        }
    }

    /// The defect this type closes: a parent's explicit `Write` override must
    /// not reach a child whose own ceiling is `readonly` and whose override is
    /// NULL — the child's effective verb ceiling is its own `readonly`.
    #[test]
    fn a_parent_override_does_not_widen_a_readonly_child() {
        let parent = c(Write, Some(Write));
        let child = c(ReadOnly, None);
        let got = parent.narrowed_for_child(child);
        assert_eq!(got.http_verb_ceiling, Some(ReadOnly));
        assert_eq!(got.effective_http_verb(), ReadOnly);
        // Also with a readonly parent ceiling whose override grants POST.
        let parent = c(ReadOnly, Some(Write));
        assert_eq!(
            parent.narrowed_for_child(child).effective_http_verb(),
            ReadOnly
        );
    }

    /// A child's explicit override is honoured even when it is looser than its
    /// own data ceiling — narrowing works on EFFECTIVE values, it does not
    /// erase a grant the child's operator made — and never loosens the parent.
    #[test]
    fn a_child_override_narrows_on_effective_values() {
        // Both grant POST via the override; the child keeps it.
        let got = c(Write, Some(Write)).narrowed_for_child(c(ReadOnly, Some(Write)));
        assert_eq!(got.effective_http_verb(), Write);
        assert_eq!(
            got.max_write_ceiling, ReadOnly,
            "the data ceiling still narrows"
        );
        // Parent refuses POST (readonly, no override); a child grant cannot
        // widen it.
        let got = c(ReadOnly, None).narrowed_for_child(c(Write, Some(Write)));
        assert_eq!(got.effective_http_verb(), ReadOnly);
        // A child override that TIGHTENS wins over a permissive parent.
        let got = c(Write, None).narrowed_for_child(c(Write, Some(ReadOnly)));
        assert_eq!(got.effective_http_verb(), ReadOnly);
        // Control: both fully permissive stays permissive.
        let got = c(Write, None).narrowed_for_child(c(Write, None));
        assert_eq!(got.effective_http_verb(), Write);
    }

    /// The narrowed verb axis is stamped EXPLICITLY, never left to inherit.
    #[test]
    fn the_narrowed_verb_axis_is_explicit() {
        for (pw, pv, cw, cv) in [
            (Write, None, Write, None),
            (ReadOnly, None, ReadOnly, None),
            (Write, Some(ReadOnly), Write, None),
        ] {
            assert!(c(pw, pv)
                .narrowed_for_child(c(cw, cv))
                .http_verb_ceiling
                .is_some());
        }
    }

    /// Egress narrows on effective scopes: a tier1 child air-gapped only by
    /// its tier default stays local under a public parent.
    #[test]
    fn egress_narrows_on_effective_scope() {
        let parent = ActorCeilings {
            max_llm_tier: LlmTier::Tier2,
            max_write_ceiling: Write,
            http_verb_ceiling: None,
            egress_scope: Some(EgressScope::Public),
        };
        let child = ActorCeilings {
            max_llm_tier: LlmTier::Tier1,
            max_write_ceiling: Write,
            http_verb_ceiling: None,
            egress_scope: None,
        };
        let got = parent.narrowed_for_child(child);
        assert_eq!(got.egress_scope, Some(EgressScope::Local));
        assert_eq!(got.max_llm_tier, LlmTier::Tier1);
    }

    /// Every axis of the fail-closed value is the restrictive one, explicitly.
    #[test]
    fn fail_closed_is_restrictive_on_every_axis_explicitly() {
        let ActorCeilings {
            max_llm_tier,
            max_write_ceiling,
            http_verb_ceiling,
            egress_scope,
        } = ActorCeilings::FAIL_CLOSED;
        assert_eq!(max_llm_tier, LlmTier::Tier1);
        assert_eq!(max_write_ceiling, ReadOnly);
        assert_eq!(http_verb_ceiling, Some(ReadOnly));
        assert_eq!(egress_scope, Some(EgressScope::Local));
        // And narrowing anything against it stays fail-closed.
        let wide = ActorCeilings {
            max_llm_tier: LlmTier::Tier2,
            max_write_ceiling: Write,
            http_verb_ceiling: Some(Write),
            egress_scope: Some(EgressScope::Public),
        };
        assert_eq!(
            wide.narrowed_for_child(ActorCeilings::FAIL_CLOSED),
            ActorCeilings::FAIL_CLOSED
        );
        assert_eq!(
            ActorCeilings::FAIL_CLOSED.narrowed_for_child(wide),
            ActorCeilings::FAIL_CLOSED
        );
    }
}
