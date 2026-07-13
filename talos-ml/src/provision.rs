//! RFC 0011 — one-call classifier provisioning (the Smart Classifier front
//! door).
//!
//! Collapses the eight-step manual setup (create dataset → create model →
//! set policy → …) into ONE owner-scoped, idempotent transaction. A caller
//! (the MCP tool, the GraphQL mutation, or the editor's provision-on-save)
//! hands a name + label set + the workflow's actor; this creates the
//! dataset + model (born `llm_only`) + a safe default policy under the
//! caller's tenancy and returns the model name to stamp into the node.
//!
//! The classifier "starts as an LLM and distills into a fast model over
//! time" is emergent, not built here: a fresh model is `llm_only`, so the
//! gated serving path abstains and the workflow's LLM does the work; the
//! `__ml_distill__` protocol feeds the dataset; the scheduled evaluator
//! promotes once the policy clears. Provisioning only lays the substrate.
//!
//! Same cross-protocol shape as [`crate::correction::resolve_disagreement`]:
//! a typed input/outcome/error, one internally-managed tenant tx, mapped by
//! each protocol surface.

use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

use crate::dataset::DatasetService;
use crate::lifecycle::{validate_llm_locality, PolicyJson};
use crate::registry::ModelRegistry;

/// Label-set caps (defensive — labels become dataset classes + policy keys).
const MAX_LABELS: usize = 64;
const MAX_LABEL_LEN: usize = 64;
const MAX_NAME_LEN: usize = 128;

/// Tier-1 local defaults for the LLM fallback leg (data stays on host).
const DEFAULT_PROVIDER: &str = "ollama";
const DEFAULT_MODEL: &str = "qwen3.6:latest";
const DEFAULT_K: i64 = 7;
const DEFAULT_CONFIDENCE_THRESHOLD: f64 = 0.6;

pub struct ProvisionInput {
    /// Base name — used for both the dataset and the model (per-user unique).
    pub name: String,
    /// The label set the model predicts — ≥2 distinct labels.
    pub labels: Vec<String>,
    /// The workflow's bound actor. REQUIRED: it owns tenancy (must belong to
    /// the caller) and becomes the disagreement-digest delivery target, so
    /// both serving and distillation resolve the same principal.
    pub actor_id: Uuid,
    /// LLM fallback leg; defaults to Tier-1 local (`ollama`/`qwen3.6`).
    pub fallback_provider: Option<String>,
    pub fallback_model: Option<String>,
    /// Opt-in for a non-`ollama` (external, Tier-2) fallback provider. When
    /// false, a non-local provider is rejected before any write.
    pub allow_external_llm: bool,
    /// kNN neighborhood + serving confidence gate (sane defaults).
    pub k: Option<i64>,
    pub confidence_threshold: Option<f64>,
    /// Dataset growth cap (rows before oldest-eviction).
    pub max_examples: Option<i64>,
    /// Advanced escape hatch: a full policy override (validated). `None` →
    /// the safe default (auto-advance OFF) derived from the label set.
    pub policy_override: Option<serde_json::Value>,
}

#[derive(Debug)]
pub struct ProvisionOutcome {
    pub model_name: String,
    pub model_id: Uuid,
    pub dataset_id: Uuid,
    pub lifecycle_state: String,
    /// True when a model of this name already existed and was reused
    /// (idempotent re-add), rather than freshly created.
    pub already_existed: bool,
    /// Set when the classifier's local-only intent (`allow_external_llm:
    /// false`) is not backed by the runtime gate that actually enforces
    /// egress: the bound actor's `max_llm_tier`. The model-config flag gates
    /// WRITES (this call); at serving time the node's PROVIDER + the actor
    /// tier decide egress, so a tier-2 actor leaves the contract advisory.
    /// Surfaced verbatim by both protocol surfaces so the caller can act
    /// (set the actor's tier ceiling to tier1).
    pub locality_warning: Option<String>,
}

#[derive(Debug)]
pub enum ProvisionError {
    /// Bad label set / name / policy / non-local provider without opt-in.
    InvalidInput(String),
    /// The actor doesn't belong to the caller (cross-tenant binding).
    InvalidActor,
    Internal(anyhow::Error),
}

/// Provision (or idempotently reuse) a classifier: dataset + model + policy,
/// owner-scoped. `user_id` is the SIGNED caller; `input.actor_id` is the
/// workflow's actor and must belong to `user_id`.
pub async fn provision_classifier(
    pool: &PgPool,
    dataset: &DatasetService,
    input: ProvisionInput,
    user_id: Uuid,
) -> Result<ProvisionOutcome, ProvisionError> {
    // ---- Validate everything BEFORE any write (cheap, fail fast) ----
    let name = input.name.trim().to_string();
    if name.is_empty()
        || name.len() > MAX_NAME_LEN
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(ProvisionError::InvalidInput(
            "name must be 1–128 chars of [A-Za-z0-9._-]".into(),
        ));
    }

    // Dedupe + validate labels, preserving first-seen order.
    let mut seen = std::collections::HashSet::new();
    let mut labels: Vec<String> = Vec::new();
    for raw in &input.labels {
        let l = raw.trim().to_string();
        if l.is_empty() || l.len() > MAX_LABEL_LEN || l.chars().any(|c| c.is_control()) {
            return Err(ProvisionError::InvalidInput(format!(
                "invalid label '{raw}' (non-empty, ≤{MAX_LABEL_LEN} chars, no control chars)"
            )));
        }
        if seen.insert(l.clone()) {
            labels.push(l);
        }
    }
    if labels.len() < 2 {
        return Err(ProvisionError::InvalidInput(
            "a classifier needs at least 2 distinct labels".into(),
        ));
    }
    if labels.len() > MAX_LABELS {
        return Err(ProvisionError::InvalidInput(format!(
            "too many labels (max {MAX_LABELS})"
        )));
    }

    let provider = input
        .fallback_provider
        .as_deref()
        .unwrap_or(DEFAULT_PROVIDER)
        .to_string();
    let model = input
        .fallback_model
        .as_deref()
        .unwrap_or(DEFAULT_MODEL)
        .to_string();
    let k = input.k.unwrap_or(DEFAULT_K).clamp(1, 50);
    let threshold = input
        .confidence_threshold
        .unwrap_or(DEFAULT_CONFIDENCE_THRESHOLD)
        .clamp(0.0, 1.0);

    // Model config: serving knobs + the (owner-validated) digest actor.
    // `labels` is recorded so idempotent re-adds can detect an incompatible
    // label set instead of silently reusing a model trained on other classes.
    let config = json!({
        "k": k,
        "confidence_threshold": threshold,
        "fallback": { "provider": provider, "model": model },
        "allow_external_llm": input.allow_external_llm,
        "digest": { "actor_id": input.actor_id.to_string() },
        "labels": labels,
    });
    // Data-egress gate: a non-local fallback requires explicit opt-in.
    validate_llm_locality(&config).map_err(ProvisionError::InvalidInput)?;

    // Effective policy: caller override or the safe default. Either way it
    // is parsed + range-validated before it can be written.
    let policy = input
        .policy_override
        .unwrap_or_else(|| default_policy(&labels));
    PolicyJson::parse(&policy)
        .and_then(|p| p.validate())
        .map_err(ProvisionError::InvalidInput)?;

    // ---- One owner-scoped tx: actor check → idempotency → create ----
    let mut tx = talos_db::begin_tenant_read_scoped(
        pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .map_err(|e| ProvisionError::Internal(anyhow::anyhow!("open provision tx: {e}")))?;

    // Tenancy: the actor MUST belong to the caller — it is the digest target
    // and the distill/serve principal. Fail closed at WRITE time (don't rely
    // only on the delivery-time skip). Ownership failures and not-found are
    // deliberately indistinguishable (InvalidActor — no enumeration); the
    // STATUS refusal is separate and specific, because the caller provably
    // owns the actor. Mirrors the setWorkflowActorId mutations, which refuse
    // archived/terminated actors ("reactivate it first").
    let actor_row: Option<(Uuid, String, String)> =
        sqlx::query_as("SELECT user_id, status, max_llm_tier FROM actors WHERE id = $1")
            .bind(input.actor_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| ProvisionError::Internal(e.into()))?;
    let (actor_status, actor_tier) = match actor_row {
        Some((owner, status, tier)) if owner == user_id => (status, tier),
        _ => return Err(ProvisionError::InvalidActor),
    };
    if actor_status == "archived" || actor_status == "terminated" {
        return Err(ProvisionError::InvalidInput(format!(
            "actor is {actor_status} — reactivate it (or pick an active actor) before binding \
             it as the classifier's digest target"
        )));
    }
    // The local-only contract is enforced at runtime by the ACTOR tier, not
    // by this config flag (the flag gates writes). Tell the caller when the
    // two disagree instead of letting the contract be silently advisory.
    let locality_warning = (!input.allow_external_llm && actor_tier != "tier1").then(|| {
        format!(
            "allow_external_llm is false but actor {} has max_llm_tier '{}' — the local-only \
             intent is only enforced at runtime by a tier1 ceiling \
             (set_actor_llm_tier_ceiling); with a {} actor, a workflow edit that switches the \
             node's PROVIDER to an external one WILL egress data",
            input.actor_id, actor_tier, actor_tier
        )
    });

    // Idempotent re-add: a model of this name already exists → reuse it
    // verbatim (never clobber a model a human may have tuned or advanced) —
    // but only when the request is COMPATIBLE with what exists. Silently
    // returning a model with a different label set or digest actor poisons
    // the dataset (new-label rows distilled into the old class space) and
    // routes digests to an actor the caller didn't name.
    if let Some(existing) = ModelRegistry::resolve_by_name(&mut tx, &name, user_id)
        .await
        .map_err(ProvisionError::Internal)?
    {
        let Some(dataset_id) = existing.dataset_id else {
            return Err(ProvisionError::InvalidInput(
                "a model of this name exists but has no dataset — pick a different name".into(),
            ));
        };
        if let Some(existing_actor) = existing.config_json["digest"]["actor_id"].as_str() {
            if existing_actor != input.actor_id.to_string() {
                return Err(ProvisionError::InvalidInput(format!(
                    "model '{name}' already exists bound to a different actor — re-use it with \
                     that actor, or pick a different name"
                )));
            }
        }
        // Pre-remediation models don't record labels in config; skip the
        // check for those rather than refusing every legacy reuse.
        if let Some(existing_labels) = existing.config_json["labels"].as_array() {
            let existing_set: std::collections::HashSet<&str> =
                existing_labels.iter().filter_map(|v| v.as_str()).collect();
            let requested_set: std::collections::HashSet<&str> =
                labels.iter().map(String::as_str).collect();
            if existing_set != requested_set {
                return Err(ProvisionError::InvalidInput(format!(
                    "model '{name}' already exists with a different label set — matching \
                     labels are required to re-use it, or pick a different name"
                )));
            }
        }
        return Ok(ProvisionOutcome {
            model_name: existing.name,
            model_id: existing.model_id,
            dataset_id,
            lifecycle_state: existing.lifecycle_state,
            already_existed: true,
            locality_warning,
        });
    }

    // A same-name DATASET without a model (created earlier via
    // ml_create_dataset) would fail create_dataset's unique index with an
    // opaque Internal error on every retry — catch it here with an
    // actionable message instead.
    let dataset_collision: Option<Uuid> = sqlx::query_scalar(
        "SELECT id FROM ml_datasets WHERE user_id = $1 AND name = $2 AND org_id IS NULL",
    )
    .bind(user_id)
    .bind(&name)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| ProvisionError::Internal(e.into()))?;
    if dataset_collision.is_some() {
        return Err(ProvisionError::InvalidInput(format!(
            "a dataset named '{name}' already exists (without a model) — pick a different \
             name, or attach a model to it with ml_create_model"
        )));
    }

    // Create dataset → model (born llm_only) → policy, all in this tx.
    // A non-positive growth cap is a caller error, not a request for
    // "no cap" — reject it like every other invalid input.
    if input.max_examples.is_some_and(|cap| cap <= 0) {
        return Err(ProvisionError::InvalidInput(
            "max_examples must be positive (omit it for the default growth behavior)".into(),
        ));
    }
    let schema_json = match input.max_examples {
        Some(cap) => json!({ "max_examples": cap }),
        None => json!({}),
    };
    let dataset_id = dataset
        .create_dataset(
            &mut tx,
            user_id,
            None,
            &name,
            "classification",
            &schema_json,
        )
        .await
        .map_err(ProvisionError::Internal)?;

    let model_id = ModelRegistry::create_model(
        &mut tx,
        user_id,
        None,
        &name,
        "classification",
        Some(dataset_id),
        &config,
    )
    .await
    .map_err(ProvisionError::Internal)?;

    ModelRegistry::set_policy(&mut tx, model_id, user_id, &policy)
        .await
        .map_err(ProvisionError::Internal)?;

    tx.commit()
        .await
        .map_err(|e| ProvisionError::Internal(e.into()))?;

    tracing::info!(
        target: "talos_ml",
        %model_id,
        %dataset_id,
        labels = labels.len(),
        "classifier provisioned (llm_only; distills as it runs)"
    );

    Ok(ProvisionOutcome {
        model_name: name,
        model_id,
        dataset_id,
        lifecycle_state: "llm_only".to_string(),
        already_existed: false,
        locality_warning,
    })
}

/// The safe default promotion policy for a fresh classifier. `auto_advance`
/// is OFF — the evaluator will report "ready" but leave the promote to a
/// human (the one non-negotiable safety property of a one-click classifier).
/// Recall floors (not F1) gate the imbalanced-class case, seeded per label.
fn default_policy(labels: &[String]) -> serde_json::Value {
    let recall_floors: serde_json::Map<String, serde_json::Value> =
        labels.iter().map(|l| (l.clone(), json!(0.70))).collect();
    json!({
        "min_examples": 200,
        "min_corrections_per_class": 2,
        "accuracy_at_coverage": { "min_accuracy": 0.90, "min_coverage": 0.70 },
        "recall_floors": recall_floors,
        "demote_below_agreement": 0.80,
        "min_shadow_total": 50,
        "auto_advance": false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy_is_safe_and_valid() {
        let p = default_policy(&["a".into(), "b".into()]);
        // auto_advance MUST be off by default.
        assert_eq!(p["auto_advance"], serde_json::Value::Bool(false));
        // Recall floors seeded per label.
        assert!(p["recall_floors"]["a"].is_number());
        assert!(p["recall_floors"]["b"].is_number());
        // And it parses + validates through the real policy type.
        assert!(PolicyJson::parse(&p).and_then(|x| x.validate()).is_ok());
    }
}
