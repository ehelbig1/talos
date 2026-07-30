//! The ML entries for the operator's decision inbox.
//!
//! Before this module the autonomy cockpit's `needs_me` panel totalled pending
//! approvals + ops-alert corrections + autonomous failures and carried NO ML
//! entry at all, while the evaluator's `ml_lifecycle_policy_satisfied` audit
//! event — the one signal that says "a model cleared its gate and is waiting
//! for you" — had ZERO consumers repo-wide. A model could sit clear of its
//! policy indefinitely and nothing would say so.
//!
//! Two states are surfaced, and they are different facts:
//!
//! * **[`PendingKind::PolicySatisfiedAwaitingHuman`]** — a stored verdict says
//!   the gate is clear, `auto_advance` is off, and a next lifecycle state
//!   exists. The platform has deliberately stopped here.
//! * **[`PendingKind::VerdictStale`] / [`PendingKind::NeverEvaluated`]** — the
//!   evidence has moved past the last stored verdict (or there has never been
//!   one). This is a claim about the DECISION being unmade, not about the
//!   model being good or bad.
//!
//! # What this module will not say
//!
//! It never recommends a promotion. A satisfied policy means the configured
//! gates are met on the judged version; it does not establish that the version
//! is better than the one production serves, and the confidence intervals on a
//! small gold slice routinely straddle the band boundaries. Every item states
//! what is known and names the decision — the decision stays the operator's.
//!
//! # Bounds and tenancy
//!
//! One statement, `LIMIT`-capped, scoped by `m.user_id = $1` like every other
//! reader in this crate. At most ONE item per model (the states are ordered by
//! precedence, not concatenated), so the panel cannot grow with version count.

use anyhow::{Context, Result};
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Ceiling on models inspected — and therefore on items emitted, since a model
/// contributes at most one. Sized like the digest's sibling panels
/// (`list_pending_approvals_for_user(25)`).
pub const MAX_PENDING_ML_DECISIONS: i64 = 10;

/// Why a model is on the list. Each variant is a distinct fact; none of them
/// is a quality judgment about the model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingKind {
    /// A stored verdict says the gate is clear and `auto_advance` is off.
    PolicySatisfiedAwaitingHuman,
    /// A verdict exists but examples were banked after it.
    VerdictStale,
    /// No version of this model has ever carried a policy verdict.
    NeverEvaluated,
}

impl PendingKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PolicySatisfiedAwaitingHuman => "policy_satisfied_awaiting_human",
            Self::VerdictStale => "verdict_stale",
            Self::NeverEvaluated => "never_evaluated",
        }
    }
}

/// One decision the platform has parked and cannot make for itself.
#[derive(Debug, Clone)]
pub struct PendingMlDecision {
    pub model: String,
    pub lifecycle_state: String,
    pub kind: PendingKind,
    /// The version the stored verdict judged (`None` when never evaluated).
    pub verdict_version: Option<i32>,
    /// When that verdict's version row was written, RFC 3339. Carried from
    /// `trained_at`; never a read-time clock.
    pub verdict_measured_at: Option<String>,
    /// The stored `satisfied` flag, when it was a real bool.
    pub verdict_satisfied: Option<bool>,
    /// `evaluate_policy`'s own blocking reasons, VERBATIM. Empty when the
    /// verdict was satisfied or carried no usable `unmet` array.
    pub unmet: Vec<String>,
    /// The newest recorded version, judged or not.
    pub latest_version: Option<i32>,
    /// Labeled examples banked after the verdict — or, when there is no
    /// verdict, banked at all.
    pub examples_since_verdict: i64,
    pub auto_advance: bool,
    /// The one state a satisfied policy would advance to, when there is one.
    pub next_state: Option<String>,
}

impl PendingMlDecision {
    /// The concrete thing the operator can do, naming the model, the version
    /// and the numbers the platform already has.
    #[must_use]
    pub fn next_action(&self) -> String {
        let model = &self.model;
        match self.kind {
            PendingKind::NeverEvaluated => format!(
                "no version of '{model}' has ever had its lifecycle policy evaluated, and \
                 {} labeled examples are banked. Run ml_eval_model to judge the gate now; the \
                 scheduled evaluator will otherwise judge it on its next visit.",
                self.examples_since_verdict
            ),
            PendingKind::VerdictStale => {
                let v = self
                    .verdict_version
                    .map_or_else(|| "?".to_string(), |v| v.to_string());
                let when = self
                    .verdict_measured_at
                    .as_deref()
                    .unwrap_or("unknown date");
                let blamed = if self.unmet.is_empty() {
                    String::new()
                } else {
                    format!(" That verdict blamed: {}.", self.unmet.join("; "))
                };
                format!(
                    "the newest stored policy verdict for '{model}' is version {v} ({when}) and \
                     {} labeled examples have been banked since.{blamed} Nothing has re-judged \
                     it, so whether those gates are still unmet is UNKNOWN. Run ml_eval_model to \
                     judge the current data.",
                    self.examples_since_verdict
                )
            }
            PendingKind::PolicySatisfiedAwaitingHuman => {
                let v = self
                    .verdict_version
                    .map_or_else(|| "?".to_string(), |v| v.to_string());
                let next = self.next_state.as_deref().unwrap_or("the next state");
                format!(
                    "'{model}''s lifecycle policy is SATISFIED on version {v} and auto_advance is \
                     off, so the platform stopped here on purpose. Advancing {} -> {next} is what \
                     changes what production serves; promoting a version alone does not. A \
                     cleared gate is not evidence that version {v} beats the version serving \
                     today — compare the gold intervals first. The decision is yours.",
                    self.lifecycle_state
                )
            }
        }
    }

    /// Why the item is on the list at all — including what its PERSISTENCE
    /// across digests would mean.
    #[must_use]
    pub fn why_listed(&self) -> &'static str {
        match self.kind {
            PendingKind::PolicySatisfiedAwaitingHuman => {
                "the scheduled evaluator records a satisfied policy and stops when auto_advance \
                 is false. Nothing else surfaces that, so this item is the only place the parked \
                 decision appears."
            }
            PendingKind::VerdictStale | PendingKind::NeverEvaluated => {
                "a working scheduled evaluator re-judges a model within one \
                 ML_POLICY_EVAL_MIN_INTERVAL_SECS window of the dataset changing. A model that \
                 stays on this list across digests therefore means the evaluator is not reaching \
                 it — which is the failure this item exists to make visible (2026-07-30: one \
                 model sat five days and 161 examples past its last verdict, unnoticed)."
            }
        }
    }
}

/// Read the parked ML decisions for one user.
///
/// One statement. The three LATERALs are `LIMIT 1` / indexed-count lookups per
/// model, and the model set is itself capped — no N+1 is added to the digest
/// path. `fast_primary` models are excluded: the scheduled evaluator governs
/// them by drift alone and never re-judges the policy, so a stale verdict
/// there is by design, not a parked decision.
pub async fn pending_ml_decisions(
    pool: &PgPool,
    user_id: Uuid,
    limit: i64,
) -> Result<Vec<PendingMlDecision>> {
    let rows = sqlx::query(
        "SELECT m.name, m.lifecycle_state, \
                COALESCE((m.policy_json->>'auto_advance')::boolean, false) AS auto_advance, \
                pv.version AS verdict_version, pv.trained_at AS verdict_trained_at, \
                pv.metrics_json -> 'policy_decision' AS policy_decision, \
                lv.version AS latest_version, \
                COALESCE(ex.n, 0) AS examples_since_verdict \
         FROM ml_models m \
         LEFT JOIN LATERAL ( \
             SELECT version, trained_at, metrics_json FROM ml_model_versions \
             WHERE model_id = m.id AND jsonb_exists(metrics_json, 'policy_decision') \
             ORDER BY version DESC LIMIT 1 \
         ) pv ON TRUE \
         LEFT JOIN LATERAL ( \
             SELECT version FROM ml_model_versions \
             WHERE model_id = m.id ORDER BY version DESC LIMIT 1 \
         ) lv ON TRUE \
         LEFT JOIN LATERAL ( \
             SELECT COUNT(*)::bigint AS n FROM ml_examples e \
             WHERE e.dataset_id = m.dataset_id \
               AND (pv.trained_at IS NULL OR e.created_at > pv.trained_at) \
         ) ex ON TRUE \
         WHERE m.user_id = $1 AND m.policy_json <> '{}'::jsonb \
           AND m.lifecycle_state <> 'fast_primary' \
         ORDER BY m.name LIMIT $2",
    )
    .bind(user_id)
    .bind(limit.clamp(1, MAX_PENDING_ML_DECISIONS))
    .fetch_all(pool)
    .await
    .context("scan parked ml policy decisions")?;

    let mut out = Vec::new();
    for r in rows {
        let lifecycle_state: String = r.try_get("lifecycle_state")?;
        let decision: Option<serde_json::Value> = r.try_get("policy_decision")?;
        let verdict_trained_at: Option<chrono::DateTime<chrono::Utc>> =
            r.try_get("verdict_trained_at")?;
        let candidate = classify_pending(
            r.try_get("name")?,
            lifecycle_state,
            r.try_get("auto_advance")?,
            r.try_get("verdict_version")?,
            verdict_trained_at.map(|t| t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)),
            decision.as_ref(),
            r.try_get("latest_version")?,
            r.try_get("examples_since_verdict")?,
        );
        if let Some(item) = candidate {
            out.push(item);
        }
    }
    Ok(out)
}

/// The precedence rule, pure so it is testable without a database.
///
/// At most ONE item per model. Staleness OUTRANKS a satisfied verdict on
/// purpose: a satisfied-but-stale verdict describes evidence that no longer
/// exists, and prompting a lifecycle advance on it would be exactly the
/// over-reading this whole surface is being fixed for.
#[allow(clippy::too_many_arguments)]
pub fn classify_pending(
    model: String,
    lifecycle_state: String,
    auto_advance: bool,
    verdict_version: Option<i32>,
    verdict_measured_at: Option<String>,
    decision: Option<&serde_json::Value>,
    latest_version: Option<i32>,
    examples_since_verdict: i64,
) -> Option<PendingMlDecision> {
    let decision = decision.filter(|d| d.is_object());
    let verdict_satisfied = decision
        .and_then(|d| d.get("satisfied"))
        .and_then(serde_json::Value::as_bool);
    let unmet: Vec<String> = decision
        .and_then(|d| d.get("unmet"))
        .and_then(serde_json::Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default();
    let next_state = crate::lifecycle::LifecycleState::parse(&lifecycle_state)
        .and_then(|s| s.next())
        .map(|s| s.as_str().to_string());

    let kind = if decision.is_none() {
        // Never judged. Only actionable once there is something to judge.
        if examples_since_verdict > 0 {
            PendingKind::NeverEvaluated
        } else {
            return None;
        }
    } else if examples_since_verdict > 0 {
        PendingKind::VerdictStale
    } else if verdict_satisfied == Some(true) && !auto_advance && next_state.is_some() {
        PendingKind::PolicySatisfiedAwaitingHuman
    } else {
        // A fresh UNSATISFIED verdict is the system working as designed, and a
        // fresh satisfied one under auto_advance is the evaluator's job on its
        // next tick. Neither needs the operator.
        return None;
    };

    Some(PendingMlDecision {
        model,
        lifecycle_state,
        kind,
        verdict_version,
        verdict_measured_at,
        verdict_satisfied,
        unmet,
        latest_version,
        examples_since_verdict,
        auto_advance,
        next_state,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn classify(
        state: &str,
        auto_advance: bool,
        decision: Option<serde_json::Value>,
        examples_since: i64,
    ) -> Option<PendingMlDecision> {
        classify_pending(
            "inbox-classifier-personal".into(),
            state.into(),
            auto_advance,
            decision.as_ref().map(|_| 31),
            decision
                .as_ref()
                .map(|_| "2026-07-25T09:30:00.000Z".to_string()),
            decision.as_ref(),
            Some(44),
            examples_since,
        )
    }

    /// The measured live state: `auto_advance` on, verdict from v31 blaming a
    /// class count that has since been cleared, 161 examples banked after it.
    /// The blocking reasons must reach the operator VERBATIM — "keep
    /// correcting" is strictly less useful than the number the platform has.
    #[test]
    fn the_live_state_lists_a_stale_verdict_with_its_reasons_verbatim() {
        let unmet = "min_corrections_per_class: 'follow_up' has 1 < 3";
        let d = json!({
            "satisfied": false,
            "unmet": [unmet, "accuracy_at_coverage: no threshold reaches 0.95"],
        });
        let item = classify("shadow", true, Some(d), 161).expect("listed");
        assert_eq!(item.kind, PendingKind::VerdictStale);
        assert_eq!(item.unmet[0], unmet);
        let action = item.next_action();
        assert!(action.contains("version 31"), "{action}");
        assert!(action.contains("2026-07-25"), "{action}");
        assert!(action.contains("161 labeled examples"), "{action}");
        assert!(
            action.contains(unmet),
            "reasons must survive verbatim: {action}"
        );
        assert!(
            action.contains("UNKNOWN"),
            "the item must not claim the gates are still unmet: {action}"
        );
        // …and it must not tell the operator to promote anything.
        assert!(!action.to_ascii_lowercase().contains("ml_promote_model"));
        assert!(item.why_listed().contains("evaluator is not reaching it"));
    }

    /// A satisfied-but-STALE verdict is listed as stale, not as a cleared
    /// gate: prompting an advance on evidence that has since changed is the
    /// over-reading this surface exists to prevent.
    #[test]
    fn staleness_outranks_a_satisfied_verdict() {
        let d = json!({ "satisfied": true, "unmet": [] });
        let item = classify("shadow", false, Some(d), 12).expect("listed");
        assert_eq!(item.kind, PendingKind::VerdictStale);
        assert_eq!(item.verdict_satisfied, Some(true));
    }

    /// D4(a): fresh, satisfied, auto_advance off → the parked decision.
    #[test]
    fn a_fresh_satisfied_verdict_with_auto_advance_off_is_the_parked_decision() {
        let d = json!({ "satisfied": true, "unmet": [] });
        let item = classify("shadow", false, Some(d), 0).expect("listed");
        assert_eq!(item.kind, PendingKind::PolicySatisfiedAwaitingHuman);
        assert_eq!(item.next_state.as_deref(), Some("hybrid"));
        let action = item.next_action();
        assert!(action.contains("shadow -> hybrid"), "{action}");
        assert!(
            action.contains("promoting a version alone does not"),
            "{action}"
        );
        assert!(
            action.contains("not evidence that version 31 beats"),
            "a cleared gate is not a comparison: {action}"
        );
        assert!(action.contains("The decision is yours."), "{action}");
    }

    /// The quiet states produce NOTHING — the panel must not grow with every
    /// healthy model.
    #[test]
    fn healthy_and_working_as_designed_states_are_not_listed() {
        // Fresh satisfied verdict with auto_advance ON: the evaluator's job.
        assert!(classify(
            "shadow",
            true,
            Some(json!({ "satisfied": true, "unmet": [] })),
            0
        )
        .is_none());
        // Fresh UNSATISFIED verdict: the gate is doing its job.
        assert!(classify(
            "shadow",
            false,
            Some(json!({ "satisfied": false, "unmet": ["min_examples: 10 < 50"] })),
            0
        )
        .is_none());
        // Never evaluated AND no examples: nothing to judge.
        assert!(classify("shadow", false, None, 0).is_none());
    }

    /// A model with no stored verdict but banked evidence is the 30-of-44
    /// case, and it must not be reported as an unsatisfied gate.
    #[test]
    fn an_unjudged_model_with_evidence_says_never_evaluated() {
        let item = classify("shadow", false, None, 161).expect("listed");
        assert_eq!(item.kind, PendingKind::NeverEvaluated);
        assert_eq!(item.verdict_satisfied, None);
        assert!(item.unmet.is_empty());
        let action = item.next_action();
        assert!(action.contains("has ever had its lifecycle policy evaluated"));
        assert!(action.contains("161 labeled examples"));
    }

    /// A satisfied policy at the end of the ladder has nowhere to advance, so
    /// there is no decision to park.
    #[test]
    fn a_terminal_state_parks_no_advance_decision() {
        // `hybrid` has a next state; `fast_primary` is filtered out in SQL,
        // but the classifier must agree if it is ever reached.
        assert_eq!(
            classify(
                "hybrid",
                false,
                Some(json!({ "satisfied": true, "unmet": [] })),
                0
            )
            .map(|i| i.kind),
            Some(PendingKind::PolicySatisfiedAwaitingHuman)
        );
        assert!(classify(
            "fast_primary",
            false,
            Some(json!({ "satisfied": true, "unmet": [] })),
            0
        )
        .is_none());
    }

    /// A malformed stored decision is NOT a verdict: it must fall through to
    /// the "never evaluated" reading rather than being read as unsatisfied.
    #[test]
    fn a_malformed_decision_is_not_read_as_a_verdict() {
        let item = classify("shadow", false, Some(json!("satisfied")), 5).expect("listed");
        assert_eq!(item.kind, PendingKind::NeverEvaluated);
        assert_eq!(item.verdict_satisfied, None);
        // An object with no `satisfied` key IS a stored decision, just an
        // uninformative one — it cannot become the "satisfied" item.
        let item = classify("shadow", false, Some(json!({})), 0);
        assert!(item.is_none(), "an unreadable verdict parks no decision");
    }
}
