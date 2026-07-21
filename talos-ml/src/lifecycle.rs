//! RFC 0011 P2d — the managed distillation lifecycle.
//!
//! The state machine on `ml_models` (`lifecycle_state` + `policy_json`)
//! that turns the hybrid LLM→small-model pattern declarative:
//!
//! ```text
//! llm_only ──> shadow ──> hybrid ──> fast_primary
//! ```
//!
//! Design gates (task #31 / review-hardened):
//! - **CAS transitions**: every state change is compare-and-swap on the
//!   current state AND owner-scoped, so two evaluators (or an evaluator
//!   racing a manual command) can't double-apply; the caller audit-logs
//!   the change.
//! - **Fail-safe direction**: forward moves advance ONE step at a time
//!   and only when the policy is satisfied on present data; backward
//!   moves (demotes) of any distance are always structurally legal —
//!   missing data may block a promote, never a demote.
//! - **Typed policy**: `PolicyJson` is `deny_unknown_fields` — a typo'd
//!   policy key fails loudly at write time instead of silently
//!   never-enforcing.
//! - **Local-LLM pin**: the fallback/baseline provider in
//!   `config_json` must be a LOCAL provider unless the model explicitly
//!   opts into `allow_external_llm: true` (the RFC's dataset-derived-
//!   LLM-call locality guard — eval and fallback both feed DECRYPTED
//!   example content to an LLM with no owning actor, so `max_llm_tier`
//!   never applies).
//! - **Bounded storage**: disagreements are capped per model
//!   (oldest-first prune inside the insert), shadow stats are a fixed
//!   set of per-band counters.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use sqlx::PgConnection;
use talos_secrets_manager::Zeroizing;
use uuid::Uuid;

use crate::eval::EvalReport;

/// Ceiling on stored PENDING+resolved divergences per model. The digest
/// consumes well under this; the cap exists so a noisy model can't grow
/// the table unboundedly between digests.
pub const MAX_DISAGREEMENTS_PER_MODEL: i64 = 500;

/// Providers considered local (no data egress). Mirrors the tier-1
/// posture: dataset-derived content may only reach these without the
/// explicit `allow_external_llm` opt-in.
pub const LOCAL_LLM_PROVIDERS: &[&str] = &["ollama"];

// ────────────────────────────────────────────────────────────────────
// State machine
// ────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LifecycleState {
    LlmOnly,
    Shadow,
    Hybrid,
    FastPrimary,
}

impl LifecycleState {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::LlmOnly => "llm_only",
            Self::Shadow => "shadow",
            Self::Hybrid => "hybrid",
            Self::FastPrimary => "fast_primary",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "llm_only" => Some(Self::LlmOnly),
            "shadow" => Some(Self::Shadow),
            "hybrid" => Some(Self::Hybrid),
            "fast_primary" => Some(Self::FastPrimary),
            _ => None,
        }
    }

    fn rank(&self) -> u8 {
        match self {
            Self::LlmOnly => 0,
            Self::Shadow => 1,
            Self::Hybrid => 2,
            Self::FastPrimary => 3,
        }
    }

    /// The single next state a policy-satisfied promote may advance to.
    pub fn next(&self) -> Option<Self> {
        match self {
            Self::LlmOnly => Some(Self::Shadow),
            Self::Shadow => Some(Self::Hybrid),
            Self::Hybrid => Some(Self::FastPrimary),
            Self::FastPrimary => None,
        }
    }
}

/// Structural transition legality: promotes advance exactly one step;
/// demotes may drop any distance (fail-safe — an uncertain drift signal
/// must always be able to fall all the way back to llm_only).
pub fn can_transition(from: LifecycleState, to: LifecycleState) -> bool {
    if to.rank() < from.rank() {
        return true;
    }
    from.next() == Some(to)
}

// ────────────────────────────────────────────────────────────────────
// Policy
// ────────────────────────────────────────────────────────────────────

/// `ml_models.policy_json`, typed. `deny_unknown_fields` so a typo'd
/// key ("min_exmaples") is a loud write-time error, not a silently
/// never-enforced gate.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyJson {
    /// Minimum labeled examples in the dataset before any advance.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_examples: Option<i64>,
    /// Minimum human corrections PER CLASS before any advance — the
    /// human-in-the-loop enforcement knob.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_corrections_per_class: Option<i64>,
    /// Fast-path accuracy measured above the confidence threshold, with
    /// the coverage it retains.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accuracy_at_coverage: Option<AccuracyAtCoverage>,
    /// Per-class recall floors (e.g. `{"follow_up": 0.9}`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recall_floors: Option<BTreeMap<String, f64>>,
    /// When false (default), the evaluator reports a satisfied policy
    /// but leaves the promote button to a human.
    #[serde(default)]
    pub auto_advance: bool,
    /// Shadow/hybrid drift guard: when the rolling fast-vs-LLM
    /// agreement (band-weighted, from ml_shadow_stats) drops below this,
    /// the evaluator auto-DEMOTES one step. Fail-safe: applies only when
    /// enough shadow traffic exists to judge (see `min_shadow_total`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub demote_below_agreement: Option<f64>,
    /// Minimum shadow observations before `demote_below_agreement` is
    /// judged (default 50) — never demote on a handful of samples.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_shadow_total: Option<i64>,
    /// Corrections-as-training (2026-07-19): per-sample training
    /// emphasis for `source='correction'` rows (LR sample weight, knn
    /// vote multiplier). Default 3.0; validated 1.0..=10.0.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correction_weight: Option<f64>,
    /// Fraction of corrections held out as the GOLD eval slice
    /// (deterministic per-class hash split). Default 0.3; 0.1..=0.5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gold_fraction: Option<f64>,
    /// Global floor on the gold slice size (topped up deterministically;
    /// bounded by leave-one-in-train). Default 8; 0..=100.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_gold: Option<i64>,
    /// Active learning (R3): width of the gray band ABOVE the serving
    /// confidence threshold. A Gated prediction with confidence in
    /// [threshold, threshold + gray_band) is SERVED but also routed to
    /// the review queue (kind='low_confidence') — the most informative
    /// examples for human labeling. 0.0 disables. Default 0.1; 0.0..=0.3.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gray_band: Option<f64>,
    /// Daily cap on gray-band review rows per model (routing stops for
    /// the day once reached — serving is unaffected). Default 20; 1..=200.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gray_band_daily_cap: Option<i64>,
}

/// Gray-band defaults — accessors below apply them so an empty policy
/// still routes a bounded trickle of barely-served predictions to review.
pub const DEFAULT_GRAY_BAND: f64 = 0.1;
pub const DEFAULT_GRAY_BAND_DAILY_CAP: i64 = 20;

/// Resolve the corrections config for the model that owns `dataset_id`
/// (defaults when no model / empty or unparseable policy). Manual eval
/// paths call this so their voting/weighting scheme matches what the
/// lifecycle promotion path will use — divergent schemes would
/// mis-calibrate the confidence thresholds recorded in metrics_json.
pub async fn corrections_cfg_for_dataset(
    conn: &mut sqlx::PgConnection,
    dataset_id: uuid::Uuid,
) -> crate::eval::CorrectionsCfg {
    let policy: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT policy_json FROM ml_models WHERE dataset_id = $1 LIMIT 1")
            .bind(dataset_id)
            .fetch_optional(&mut *conn)
            .await
            .ok()
            .flatten();
    policy
        .and_then(|p| PolicyJson::parse(&p).ok())
        .map(|p| p.corrections_cfg())
        .unwrap_or_default()
}

impl PolicyJson {
    /// Resolved [`crate::eval::CorrectionsCfg`] with policy overrides
    /// applied over the defaults — the ONE place eval/serve read these
    /// knobs so the voting scheme can't drift between them.
    #[must_use]
    pub fn corrections_cfg(&self) -> crate::eval::CorrectionsCfg {
        let d = crate::eval::CorrectionsCfg::default();
        crate::eval::CorrectionsCfg {
            weight: self.correction_weight.map_or(d.weight, |w| w as f32),
            gold_fraction: self.gold_fraction.unwrap_or(d.gold_fraction),
            min_gold: self.min_gold.map_or(d.min_gold, |g| g as usize),
        }
    }

    /// Parse the stored policy, failing loudly on unknown fields or
    /// wrong types — the write path (ml_set_policy) calls this before
    /// persisting, and the evaluator calls it before judging.
    pub fn parse(value: &serde_json::Value) -> Result<Self, String> {
        serde_json::from_value(value.clone()).map_err(|e| format!("invalid policy_json: {e}"))
    }

    /// Range-check the numeric knobs (serde can't express these).
    pub fn validate(&self) -> Result<(), String> {
        if let Some(n) = self.min_examples {
            if n < 0 {
                return Err("min_examples must be >= 0".into());
            }
        }
        if let Some(n) = self.min_corrections_per_class {
            if n < 0 {
                return Err("min_corrections_per_class must be >= 0".into());
            }
        }
        if let Some(w) = self.correction_weight {
            if !(1.0..=10.0).contains(&w) || !w.is_finite() {
                return Err("correction_weight must be within 1.0..=10.0".into());
            }
        }
        if let Some(f) = self.gold_fraction {
            if !(0.1..=0.5).contains(&f) || !f.is_finite() {
                return Err("gold_fraction must be within 0.1..=0.5".into());
            }
        }
        if let Some(g) = self.min_gold {
            if !(0..=100).contains(&g) {
                return Err("min_gold must be within 0..=100".into());
            }
        }
        if let Some(ac) = &self.accuracy_at_coverage {
            if !(0.0..=1.0).contains(&ac.min_accuracy) || !(0.0..=1.0).contains(&ac.min_coverage) {
                return Err("accuracy_at_coverage bounds must be within [0, 1]".into());
            }
        }
        if let Some(floors) = &self.recall_floors {
            if floors.values().any(|f| !(0.0..=1.0).contains(f)) {
                return Err("recall_floors must be within [0, 1]".into());
            }
        }
        if let Some(a) = self.demote_below_agreement {
            if !(0.0..=1.0).contains(&a) {
                return Err("demote_below_agreement must be within [0, 1]".into());
            }
        }
        if let Some(n) = self.min_shadow_total {
            if n < 1 {
                return Err("min_shadow_total must be >= 1".into());
            }
        }
        if let Some(b) = self.gray_band {
            if !(0.0..=0.3).contains(&b) || !b.is_finite() {
                return Err("gray_band must be within 0.0..=0.3".into());
            }
        }
        if let Some(c) = self.gray_band_daily_cap {
            if !(1..=200).contains(&c) {
                return Err("gray_band_daily_cap must be within 1..=200".into());
            }
        }
        Ok(())
    }

    /// Effective gray-band width (default applied).
    #[must_use]
    pub fn gray_band(&self) -> f64 {
        self.gray_band.unwrap_or(DEFAULT_GRAY_BAND)
    }

    /// Effective gray-band daily cap (default applied).
    #[must_use]
    pub fn gray_band_daily_cap(&self) -> i64 {
        self.gray_band_daily_cap
            .unwrap_or(DEFAULT_GRAY_BAND_DAILY_CAP)
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccuracyAtCoverage {
    pub min_accuracy: f64,
    pub min_coverage: f64,
}

/// Everything the pure policy judgment needs, gathered by the caller.
pub struct PolicyInputs<'a> {
    pub report: &'a EvalReport,
    /// Labeled-example total in the dataset.
    pub total_examples: i64,
    /// `source='correction'` counts per class.
    pub corrections_per_class: &'a BTreeMap<String, i64>,
    /// Every class present in the dataset (the per-class correction
    /// minimum applies to ALL of these, not just corrected ones).
    pub dataset_classes: &'a [String],
}

#[derive(Debug)]
pub struct PolicyDecision {
    pub satisfied: bool,
    /// Human-readable reasons for every UNMET gate (empty = satisfied).
    pub unmet: Vec<String>,
}

/// Pure policy judgment — fail-safe: any gate that cannot be evaluated
/// on present data (empty coverage curve, class missing from the
/// report) counts as UNMET. Never promotes on missing data.
pub fn evaluate_policy(policy: &PolicyJson, inputs: &PolicyInputs<'_>) -> PolicyDecision {
    let mut unmet = Vec::new();

    if let Some(min) = policy.min_examples {
        if inputs.total_examples < min {
            unmet.push(format!("min_examples: {} < {min}", inputs.total_examples));
        }
    }

    if let Some(min) = policy.min_corrections_per_class {
        if inputs.dataset_classes.is_empty() {
            unmet.push("min_corrections_per_class: dataset has no classes yet".into());
        }
        for class in inputs.dataset_classes {
            let have = inputs
                .corrections_per_class
                .get(class)
                .copied()
                .unwrap_or(0);
            if have < min {
                unmet.push(format!(
                    "min_corrections_per_class: '{class}' has {have} < {min}"
                ));
            }
        }
    }

    if let Some(ac) = &policy.accuracy_at_coverage {
        // Satisfied when SOME threshold point retains the required
        // coverage at the required accuracy.
        let hit = inputs.report.coverage_curve.iter().any(|p| {
            p.coverage >= ac.min_coverage
                && p.accuracy.map(|a| a >= ac.min_accuracy).unwrap_or(false)
        });
        if !hit {
            unmet.push(format!(
                "accuracy_at_coverage: no threshold reaches accuracy {} at coverage {} \
                 (curve has {} points)",
                ac.min_accuracy,
                ac.min_coverage,
                inputs.report.coverage_curve.len()
            ));
        }
    }

    if let Some(floors) = &policy.recall_floors {
        for (class, floor) in floors {
            match inputs.report.per_class.get(class) {
                Some(m) if m.recall >= *floor => {}
                Some(m) => unmet.push(format!(
                    "recall_floors: '{class}' recall {:.3} < {floor}",
                    m.recall
                )),
                None => unmet.push(format!("recall_floors: '{class}' absent from eval report")),
            }
        }
    }

    PolicyDecision {
        satisfied: unmet.is_empty(),
        unmet,
    }
}

// ────────────────────────────────────────────────────────────────────
// Local-LLM pin (config validation)
// ────────────────────────────────────────────────────────────────────

/// RFC 0011 locality guard: the model's fallback/baseline LLM feeds
/// DECRYPTED dataset content to a provider, and those legs run with no
/// owning actor (so `max_llm_tier` never applies). The provider must be
/// LOCAL unless `allow_external_llm: true` is explicit on the config.
///
/// SCOPE (honest, verified 2026-07-13): this gates config WRITES only —
/// no serving-time consumer re-checks it today. talos-ml itself makes no
/// LLM calls (no dataset-derived LLM invocation exists server-side), and
/// the NODE's fallback leg resolves its provider from the node config's
/// PROVIDER key, gated at runtime by the ACTOR's `max_llm_tier`, not by
/// this flag. `provision_classifier` therefore returns a
/// `locality_warning` when `allow_external_llm: false` is paired with a
/// non-tier1 actor — the flag is advisory until the actor tier backs it.
/// If a server-side dataset-derived LLM leg is ever added, it MUST call
/// this before the invocation, restoring the defense-in-depth intent.
pub fn validate_llm_locality(config_json: &serde_json::Value) -> Result<(), String> {
    let allow_external = config_json
        .get("allow_external_llm")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    if allow_external {
        return Ok(());
    }
    for key in ["fallback", "baseline"] {
        if let Some(provider) = config_json
            .get(key)
            .and_then(|f| f.get("provider"))
            .and_then(|p| p.as_str())
        {
            if !LOCAL_LLM_PROVIDERS.contains(&provider) {
                return Err(format!(
                    "config.{key}.provider '{provider}' is external; dataset-derived \
                     LLM calls are locality-pinned — set allow_external_llm: true \
                     explicitly to override (audit-logged)"
                ));
            }
        }
    }
    Ok(())
}

// ────────────────────────────────────────────────────────────────────
// DB service — transitions, shadow accounting, disagreements
// ────────────────────────────────────────────────────────────────────

fn disagreement_aad(model_id: Uuid, id: Uuid) -> Vec<u8> {
    format!("ml_disagreement:{model_id}:{id}").into_bytes()
}

/// Band index for a confidence in tenths, matching the eval
/// coverage-curve thresholds. Abstentions map to band 0.
pub fn confidence_band(confidence: Option<f32>) -> i16 {
    match confidence {
        None => 0,
        Some(c) => (c.clamp(0.0, 1.0) * 10.0).floor() as i16,
    }
}

/// How many PAST shadow eras to retain alongside the current one.
/// Each era is at most 11 counter rows (bands 0..=10), so retention is
/// a display/debug affordance, not a storage concern — the bump prunes
/// anything older so the table stays bounded per model regardless of
/// transition count.
const RETAINED_SHADOW_EPOCHS: i32 = 4;

/// Rotate the model's shadow-agreement window: bump `shadow_epoch` and
/// prune eras past the retention depth. Free function (not a
/// `LifecycleService` method) because BOTH era-change paths call it —
/// `LifecycleService::transition` and `ModelRegistry::promote_version`
/// — plus the operator's manual window reset. Returns the new epoch.
///
/// Callers run this inside the same transaction as the era change so a
/// rollback can't leave the window rotated without the transition (or
/// vice versa). Double-bumps within one tx (auto-advance promotes AND
/// transitions) are harmless: each bump is a distinct empty era and the
/// prune keeps the retention invariant.
pub async fn bump_shadow_epoch(conn: &mut PgConnection, model_id: Uuid) -> Result<i32> {
    let new_epoch: i32 = sqlx::query_scalar(
        "UPDATE ml_models SET shadow_epoch = shadow_epoch + 1, updated_at = NOW() \
         WHERE id = $1 RETURNING shadow_epoch",
    )
    .bind(model_id)
    .fetch_one(&mut *conn)
    .await
    .context("bump shadow epoch")?;
    sqlx::query("DELETE FROM ml_shadow_stats WHERE model_id = $1 AND epoch < $2")
        .bind(model_id)
        .bind(new_epoch - RETAINED_SHADOW_EPOCHS)
        .execute(&mut *conn)
        .await
        .context("prune retired shadow epochs")?;
    Ok(new_epoch)
}

/// The model's current shadow era — display context for the agreement
/// number ("era 3, 41 observations" reads very differently from a
/// lifetime aggregate).
pub async fn shadow_epoch(conn: &mut PgConnection, model_id: Uuid) -> Result<i32> {
    sqlx::query_scalar("SELECT shadow_epoch FROM ml_models WHERE id = $1")
        .bind(model_id)
        .fetch_one(&mut *conn)
        .await
        .context("read shadow epoch")
}

pub struct LifecycleService {
    secrets: std::sync::Arc<talos_secrets_manager::SecretsManager>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct PendingDisagreement {
    pub id: Uuid,
    pub example_key: Option<String>,
    pub features_text: String,
    pub fast_label: Option<String>,
    pub fast_confidence: Option<f32>,
    pub llm_label: String,
    pub kind: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl LifecycleService {
    pub fn new(secrets: std::sync::Arc<talos_secrets_manager::SecretsManager>) -> Self {
        Self { secrets }
    }

    /// CAS state transition, owner-scoped. Returns `true` when the swap
    /// applied; `false` means the row wasn't in `from` (someone else
    /// moved it first) or isn't the caller's — callers treat both as a
    /// clean lost-race no-op and re-read. The caller is responsible for
    /// audit-logging + notifying on `true`.
    pub async fn transition(
        &self,
        conn: &mut PgConnection,
        model_id: Uuid,
        user_id: Uuid,
        from: LifecycleState,
        to: LifecycleState,
    ) -> Result<bool> {
        if !can_transition(from, to) {
            anyhow::bail!(
                "illegal lifecycle transition {} -> {}",
                from.as_str(),
                to.as_str()
            );
        }
        let res = sqlx::query(
            "UPDATE ml_models SET lifecycle_state = $1, updated_at = NOW() \
             WHERE id = $2 AND user_id = $3 AND lifecycle_state = $4",
        )
        .bind(to.as_str())
        .bind(model_id)
        .bind(user_id)
        .bind(from.as_str())
        .execute(&mut *conn)
        .await
        .context("lifecycle CAS transition")?;
        if res.rows_affected() != 1 {
            return Ok(false);
        }
        // Every era change rotates the shadow-agreement window: the
        // drift guard must judge the NEW state on fresh observations,
        // not on history accumulated under a different state/teacher
        // (the advance→demote ping-pong this prevents is documented on
        // migration 20260714170000).
        bump_shadow_epoch(&mut *conn, model_id).await?;
        Ok(true)
    }

    /// Record one shadow observation: the fast path predicted (or
    /// abstained) alongside the LLM. Upsert-increment — concurrent hook
    /// fires never race a read-modify-write.
    pub async fn record_shadow_outcome(
        &self,
        conn: &mut PgConnection,
        model_id: Uuid,
        user_id: Uuid,
        org_id: Option<Uuid>,
        confidence: Option<f32>,
        agreed: bool,
    ) -> Result<()> {
        // INSERT..SELECT stamps the model's CURRENT shadow_epoch in the
        // same statement — one round trip, and an outcome can never land
        // in a stale era even if a transition commits between a read and
        // a write. A concurrently-deleted model inserts zero rows.
        sqlx::query(
            "INSERT INTO ml_shadow_stats \
                 (model_id, user_id, org_id, band, epoch, agree_count, total_count, updated_at) \
             SELECT $1, $2, $3, $4, m.shadow_epoch, $5, 1, NOW() \
             FROM ml_models m WHERE m.id = $1 \
             ON CONFLICT (model_id, epoch, band) DO UPDATE SET \
                 agree_count = ml_shadow_stats.agree_count + EXCLUDED.agree_count, \
                 total_count = ml_shadow_stats.total_count + 1, \
                 updated_at = NOW()",
        )
        .bind(model_id)
        .bind(user_id)
        .bind(org_id)
        .bind(confidence_band(confidence))
        .bind(if agreed { 1i64 } else { 0i64 })
        .execute(&mut *conn)
        .await
        .context("record shadow outcome")?;
        Ok(())
    }

    /// Rolling agreement across bands AT OR ABOVE `min_band`, plus the
    /// total observation count — the drift-guard input. Returns None
    /// when no observations exist (fail-safe: no data, no judgment).
    ///
    /// Scoped to the model's CURRENT shadow epoch: observations from
    /// before the last transition / promotion / window reset don't
    /// count. This is what makes the drift guard's demote decision read
    /// only evidence about the current model-state-teacher combination
    /// (see migration 20260714170000 for the ping-pong this prevents).
    /// Use [`Self::shadow_agreement_lifetime`] for the all-history view.
    pub async fn shadow_agreement(
        &self,
        conn: &mut PgConnection,
        model_id: Uuid,
        min_band: i16,
    ) -> Result<Option<(f64, i64)>> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT COALESCE(SUM(s.agree_count), 0)::bigint, \
                    COALESCE(SUM(s.total_count), 0)::bigint \
             FROM ml_shadow_stats s \
             JOIN ml_models m ON m.id = s.model_id AND s.epoch = m.shadow_epoch \
             WHERE s.model_id = $1 AND s.band >= $2",
        )
        .bind(model_id)
        .bind(min_band)
        .fetch_optional(&mut *conn)
        .await
        .context("read shadow agreement")?;
        Ok(
            row.and_then(|(agree, total)| {
                (total > 0).then(|| (agree as f64 / total as f64, total))
            }),
        )
    }

    /// All-history sibling of [`Self::shadow_agreement`] — sums every
    /// retained epoch. Display/context only; never feed this to the
    /// drift guard (stale eras would re-poison the demote decision).
    pub async fn shadow_agreement_lifetime(
        &self,
        conn: &mut PgConnection,
        model_id: Uuid,
        min_band: i16,
    ) -> Result<Option<(f64, i64)>> {
        let row: Option<(i64, i64)> = sqlx::query_as(
            "SELECT COALESCE(SUM(agree_count), 0)::bigint, COALESCE(SUM(total_count), 0)::bigint \
             FROM ml_shadow_stats WHERE model_id = $1 AND band >= $2",
        )
        .bind(model_id)
        .bind(min_band)
        .fetch_optional(&mut *conn)
        .await
        .context("read lifetime shadow agreement")?;
        Ok(
            row.and_then(|(agree, total)| {
                (total > 0).then(|| (agree as f64 / total as f64, total))
            }),
        )
    }

    /// Store one reviewable divergence (encrypted features), pruning
    /// oldest rows past the per-model cap inside the same call so the
    /// table stays bounded without a sweeper.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_disagreement(
        &self,
        conn: &mut PgConnection,
        model_id: Uuid,
        user_id: Uuid,
        org_id: Option<Uuid>,
        example_key: Option<&str>,
        features_text: &str,
        fast: Option<(&str, f32)>,
        llm_label: &str,
        kind: &str,
    ) -> Result<Uuid> {
        let id = Uuid::new_v4();
        let aad = disagreement_aad(model_id, id);
        let (key_id, ciphertext, format) = self
            .secrets
            .encrypt_value_aad_v4_or_global(features_text, org_id, &aad)
            .await
            .context("encrypt disagreement features")?;
        sqlx::query(
            "INSERT INTO ml_disagreements \
                 (id, model_id, user_id, org_id, example_key, features_enc, \
                  features_key_id, features_format, fast_label, fast_confidence, \
                  llm_label, kind) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(id)
        .bind(model_id)
        .bind(user_id)
        .bind(org_id)
        .bind(example_key)
        .bind(&ciphertext)
        .bind(key_id)
        .bind(format)
        .bind(fast.map(|(l, _)| l.to_string()))
        .bind(fast.map(|(_, c)| c))
        .bind(llm_label)
        .bind(kind)
        .execute(&mut *conn)
        .await
        .context("insert disagreement")?;

        // Bounded storage: prune oldest beyond the cap (id-keyed delete
        // via the (model_id, created_at DESC) index).
        sqlx::query(
            "DELETE FROM ml_disagreements WHERE id IN ( \
                 SELECT id FROM ml_disagreements WHERE model_id = $1 \
                 ORDER BY created_at DESC, id OFFSET $2)",
        )
        .bind(model_id)
        .bind(MAX_DISAGREEMENTS_PER_MODEL)
        .execute(&mut *conn)
        .await
        .context("prune disagreements past cap")?;
        Ok(id)
    }

    /// Pending divergences for the digest, decrypted, OWNER-scoped
    /// (the digest never crosses tenants).
    pub async fn pending_disagreements(
        &self,
        conn: &mut PgConnection,
        model_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PendingDisagreement>> {
        let limit = limit.clamp(1, 100);
        let rows: Vec<(
            Uuid,
            Option<String>,
            Vec<u8>,
            Uuid,
            i16,
            Option<String>,
            Option<f32>,
            String,
            String,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT id, example_key, features_enc, features_key_id, features_format, \
                    fast_label, fast_confidence, llm_label, kind, created_at \
             FROM ml_disagreements \
             WHERE model_id = $1 AND user_id = $2 AND status = 'pending' \
             ORDER BY created_at DESC, id LIMIT $3",
        )
        .bind(model_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .context("list pending disagreements")?;

        let mut out = Vec::with_capacity(rows.len());
        for (
            id,
            example_key,
            enc,
            key_id,
            format,
            fast_label,
            fast_confidence,
            llm_label,
            kind,
            created_at,
        ) in rows
        {
            let aad = disagreement_aad(model_id, id);
            let text: Zeroizing<String> = self
                .secrets
                .decrypt_versioned(key_id, &enc, &aad, format)
                .await
                .with_context(|| format!("decrypt disagreement {id}"))?;
            out.push(PendingDisagreement {
                id,
                example_key,
                features_text: text.to_string(),
                fast_label,
                fast_confidence,
                llm_label,
                kind,
                created_at,
            });
        }
        Ok(out)
    }

    /// Fetch ONE pending disagreement decrypted, owner-scoped — the
    /// resolve path's input (correction append + status flip).
    pub async fn get_disagreement(
        &self,
        conn: &mut PgConnection,
        id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<(Uuid, PendingDisagreement)>> {
        let row: Option<(
            Uuid,
            Option<String>,
            Vec<u8>,
            Uuid,
            i16,
            Option<String>,
            Option<f32>,
            String,
            String,
            chrono::DateTime<chrono::Utc>,
        )> = sqlx::query_as(
            "SELECT model_id, example_key, features_enc, features_key_id, features_format, \
                    fast_label, fast_confidence, llm_label, kind, created_at \
             FROM ml_disagreements \
             WHERE id = $1 AND user_id = $2 AND status = 'pending'",
        )
        .bind(id)
        .bind(user_id)
        .fetch_optional(&mut *conn)
        .await
        .context("fetch disagreement")?;
        let Some((
            model_id,
            example_key,
            enc,
            key_id,
            format,
            fast_label,
            fast_confidence,
            llm_label,
            kind,
            created_at,
        )) = row
        else {
            return Ok(None);
        };
        let aad = disagreement_aad(model_id, id);
        let text: Zeroizing<String> = self
            .secrets
            .decrypt_versioned(key_id, &enc, &aad, format)
            .await
            .with_context(|| format!("decrypt disagreement {id}"))?;
        Ok(Some((
            model_id,
            PendingDisagreement {
                id,
                example_key,
                features_text: text.to_string(),
                fast_label,
                fast_confidence,
                llm_label,
                kind,
                created_at,
            },
        )))
    }

    /// One-tap digest verdict: mark resolved (a correction was
    /// appended by the caller) or dismissed. Owner-scoped.
    pub async fn set_disagreement_status(
        &self,
        conn: &mut PgConnection,
        id: Uuid,
        user_id: Uuid,
        status: &str,
    ) -> Result<bool> {
        if !matches!(status, "resolved" | "dismissed") {
            anyhow::bail!("invalid disagreement status");
        }
        let res = sqlx::query(
            "UPDATE ml_disagreements SET status = $1 \
             WHERE id = $2 AND user_id = $3 AND status = 'pending'",
        )
        .bind(status)
        .bind(id)
        .bind(user_id)
        .execute(&mut *conn)
        .await
        .context("set disagreement status")?;
        Ok(res.rows_affected() == 1)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eval::{ClassMetrics, CoveragePoint};

    fn report(per_class: &[(&str, f64)], curve: &[(f64, f64, Option<f64>)]) -> EvalReport {
        EvalReport {
            accuracy: 0.9,
            total: 100,
            abstained: 0,
            per_class: per_class
                .iter()
                .map(|(c, r)| {
                    (
                        c.to_string(),
                        ClassMetrics {
                            precision: 0.9,
                            recall: *r,
                            f1: 0.9,
                            support: 10,
                        },
                    )
                })
                .collect(),
            coverage_curve: curve
                .iter()
                .map(|(t, cov, acc)| CoveragePoint {
                    threshold: *t,
                    coverage: *cov,
                    accuracy: *acc,
                })
                .collect(),
            gold: None,
        }
    }

    #[test]
    fn transitions_promote_one_step_demote_any() {
        use LifecycleState::*;
        assert!(can_transition(LlmOnly, Shadow));
        assert!(can_transition(Shadow, Hybrid));
        assert!(can_transition(Hybrid, FastPrimary));
        // No skipping forward.
        assert!(!can_transition(LlmOnly, Hybrid));
        assert!(!can_transition(Shadow, FastPrimary));
        // Demotes of any distance are legal (fail-safe).
        assert!(can_transition(FastPrimary, LlmOnly));
        assert!(can_transition(Hybrid, Shadow));
        assert!(can_transition(FastPrimary, Hybrid));
        // Self-transition is not a transition.
        assert!(!can_transition(Shadow, Shadow));
    }

    #[test]
    fn policy_rejects_unknown_fields_and_bad_ranges() {
        let bad = serde_json::json!({"min_exmaples": 10});
        assert!(PolicyJson::parse(&bad).is_err());
        let out_of_range = PolicyJson {
            demote_below_agreement: Some(1.5),
            ..Default::default()
        };
        assert!(out_of_range.validate().is_err());
        let ok = PolicyJson::parse(&serde_json::json!({
            "min_examples": 500,
            "min_corrections_per_class": 3,
            "accuracy_at_coverage": {"min_accuracy": 0.958, "min_coverage": 0.8},
            "recall_floors": {"follow_up": 0.9},
            "auto_advance": false
        }))
        .unwrap();
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn policy_fails_safe_on_missing_data() {
        let policy = PolicyJson::parse(&serde_json::json!({
            "accuracy_at_coverage": {"min_accuracy": 0.95, "min_coverage": 0.8},
            "recall_floors": {"follow_up": 0.9}
        }))
        .unwrap();
        // Empty curve + class absent from the report → both gates UNMET.
        let r = report(&[("archive", 0.99)], &[]);
        let classes = vec!["archive".to_string()];
        let corrections = BTreeMap::new();
        let d = evaluate_policy(
            &policy,
            &PolicyInputs {
                report: &r,
                total_examples: 1000,
                corrections_per_class: &corrections,
                dataset_classes: &classes,
            },
        );
        assert!(!d.satisfied);
        assert_eq!(d.unmet.len(), 2);
    }

    #[test]
    fn policy_satisfied_end_to_end() {
        let policy = PolicyJson::parse(&serde_json::json!({
            "min_examples": 500,
            "min_corrections_per_class": 2,
            "accuracy_at_coverage": {"min_accuracy": 0.95, "min_coverage": 0.8},
            "recall_floors": {"follow_up": 0.6}
        }))
        .unwrap();
        let r = report(
            &[("archive", 0.99), ("follow_up", 0.64)],
            &[(0.6, 0.9, Some(0.969)), (0.7, 0.82, Some(1.0))],
        );
        let classes = vec!["archive".to_string(), "follow_up".to_string()];
        let corrections: BTreeMap<String, i64> =
            [("archive".to_string(), 5), ("follow_up".to_string(), 2)]
                .into_iter()
                .collect();
        let d = evaluate_policy(
            &policy,
            &PolicyInputs {
                report: &r,
                total_examples: 721,
                corrections_per_class: &corrections,
                dataset_classes: &classes,
            },
        );
        assert!(d.satisfied, "unmet: {:?}", d.unmet);

        // One missing correction flips it, with a targeted reason.
        let short: BTreeMap<String, i64> = [("archive".to_string(), 5)].into_iter().collect();
        let d = evaluate_policy(
            &policy,
            &PolicyInputs {
                report: &r,
                total_examples: 721,
                corrections_per_class: &short,
                dataset_classes: &classes,
            },
        );
        assert!(!d.satisfied);
        assert!(d.unmet[0].contains("follow_up"));
    }

    #[test]
    fn llm_locality_pin() {
        // Local fallback: fine.
        assert!(validate_llm_locality(
            &serde_json::json!({"fallback": {"provider": "ollama", "model": "qwen3.6"}})
        )
        .is_ok());
        // External without opt-in: refused.
        assert!(
            validate_llm_locality(&serde_json::json!({"fallback": {"provider": "anthropic"}}))
                .is_err()
        );
        // Baseline leg is guarded too.
        assert!(
            validate_llm_locality(&serde_json::json!({"baseline": {"provider": "openai"}}))
                .is_err()
        );
        // Explicit opt-in permits (audit-logging is the caller's job).
        assert!(validate_llm_locality(&serde_json::json!({
            "fallback": {"provider": "anthropic"},
            "allow_external_llm": true
        }))
        .is_ok());
        // No LLM legs configured: nothing to pin.
        assert!(validate_llm_locality(&serde_json::json!({"k": 5})).is_ok());
    }

    #[test]
    fn gray_band_knob_validation_and_defaults() {
        // Defaults via accessors when unset.
        let p = PolicyJson::default();
        assert_eq!(p.gray_band(), DEFAULT_GRAY_BAND);
        assert_eq!(p.gray_band_daily_cap(), DEFAULT_GRAY_BAND_DAILY_CAP);
        // In-range values accepted, including 0.0 (disable) and bounds.
        for (band, cap) in [(0.0, 1), (0.3, 200), (0.05, 20)] {
            let p = PolicyJson {
                gray_band: Some(band),
                gray_band_daily_cap: Some(cap),
                ..Default::default()
            };
            assert!(p.validate().is_ok(), "band={band} cap={cap}");
            assert_eq!(p.gray_band(), band);
            assert_eq!(p.gray_band_daily_cap(), cap);
        }
        // Out-of-range rejected.
        for band in [-0.01, 0.31, f64::NAN] {
            let p = PolicyJson {
                gray_band: Some(band),
                ..Default::default()
            };
            assert!(p.validate().is_err(), "band={band} must be rejected");
        }
        for cap in [0, -1, 201] {
            let p = PolicyJson {
                gray_band_daily_cap: Some(cap),
                ..Default::default()
            };
            assert!(p.validate().is_err(), "cap={cap} must be rejected");
        }
        // Unknown-field strictness still holds with the new keys present.
        let ok = PolicyJson::parse(&serde_json::json!({
            "gray_band": 0.15,
            "gray_band_daily_cap": 50
        }))
        .unwrap();
        assert!(ok.validate().is_ok());
    }

    #[test]
    fn confidence_bands() {
        assert_eq!(confidence_band(None), 0);
        assert_eq!(confidence_band(Some(0.0)), 0);
        assert_eq!(confidence_band(Some(0.55)), 5);
        assert_eq!(confidence_band(Some(0.99)), 9);
        assert_eq!(confidence_band(Some(1.0)), 10);
        assert_eq!(confidence_band(Some(7.5)), 10); // clamped
    }
}
