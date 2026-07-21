//! RFC 0011 P1b — ML lifecycle MCP surface (datasets, models, eval).
//!
//! Thin handlers per the architectural mandate: parse → validate →
//! service → format. All SQL lives in `talos-ml`; every DB call runs on
//! a per-user tenant-scoped transaction (sets `app.current_user_id`, so
//! the fail-closed ml_* RLS policies enforce), and handlers ALSO verify
//! dataset/model ownership app-level — defense in depth for deploys
//! without `TALOS_RLS_SET_ROLE`.
//!
//! P1 scope is personal (org_id NULL); org-shared datasets/models arrive
//! with the GraphQL surface. Batch guidance: `ml_append_examples` caps
//! at 200 examples/call — the embedding round-trips run BEFORE the
//! write transaction opens (prepare-outside-tx), so even a slow local
//! embedder never holds a connection.

use super::types::JsonRpcResponse;
use super::utils::{mcp_error, mcp_text};
use super::McpState;
use serde_json::Value;
use std::sync::Arc;
use talos_ml::{AppendExample, DatasetService, ExampleSource, ModelRegistry};
use uuid::Uuid;

const MAX_EXAMPLES_PER_CALL: usize = 200;
// Single source of truth in talos-ml so the MCP predict/eval paths and
// the RPC serving path can never diverge on the default neighborhood
// (review finding 2026-07-11: a local 5-vs-7 split meant the promotion
// gate certified a different model than the one being served).
use talos_ml::serve::DEFAULT_KNN_K;

pub fn tool_schemas() -> Vec<Value> {
    vec![
        serde_json::json!({
            "name": "ml_create_dataset",
            "description": "Create a labeled-example dataset (RFC 0011). Datasets back trainable models: LLM-bootstrap labels in, fast local backends out. Features are encrypted at rest; embeddings are computed with the LOCAL embedding model only.",
            "inputSchema": { "type": "object", "properties": {
                "name": { "type": "string", "description": "Unique per user (e.g. 'inbox-personal')" },
                "task_type": { "type": "string", "enum": ["classification", "regression", "forecasting", "ranking"], "description": "P1 backends support classification" },
                "schema_json": { "type": "object", "description": "Optional feature-shape documentation + policies (e.g. {\"max_examples\": 50000})" }
            }, "required": ["name", "task_type"] }
        }),
        serde_json::json!({
            "name": "ml_append_examples",
            "description": "Append (upsert) labeled examples to a dataset. Rows with the same example_key REPLACE earlier ones — corrections beat bootstrap labels. Max 200 per call; embedding happens before the write transaction opens.",
            "inputSchema": { "type": "object", "properties": {
                "dataset_id": { "type": "string" },
                "examples": { "type": "array", "items": { "type": "object", "properties": {
                    "features_text": { "type": "string", "description": "The text that is encrypted AND embedded. Do NOT include the label." },
                    "label": { "type": "string" },
                    "source": { "type": "string", "enum": ["llm_bootstrap", "correction", "llm_fallback", "llm_production", "import", "synthetic"] },
                    "example_key": { "type": "string", "description": "Dedupe key (e.g. gmail message id)" }
                }, "required": ["features_text", "label", "source"] } }
            }, "required": ["dataset_id", "examples"] }
        }),
        serde_json::json!({
            "name": "ml_dataset_stats",
            "description": "Counts for a dataset: total, per-label, per-source, embedded, holdout, unlabeled.",
            "inputSchema": { "type": "object", "properties": {
                "dataset_id": { "type": "string" }
            }, "required": ["dataset_id"] }
        }),
        serde_json::json!({
            "name": "ml_sample_examples",
            "description": "Decrypt up to N random examples per label for human spot-checking (the review step of the bootstrap→review→train→deploy loop).",
            "inputSchema": { "type": "object", "properties": {
                "dataset_id": { "type": "string" },
                "per_label": { "type": "integer", "description": "1-25, default 5" }
            }, "required": ["dataset_id"] }
        }),
        serde_json::json!({
            "name": "ml_create_model",
            "description": "Register a model over a dataset. The model NAME is what workflows reference; versions are created by eval/train runs and promoted explicitly.",
            "inputSchema": { "type": "object", "properties": {
                "name": { "type": "string" },
                "task_type": { "type": "string", "enum": ["classification", "regression", "forecasting", "ranking"] },
                "dataset_id": { "type": "string" },
                "config_json": { "type": "object", "description": "Backend knobs, e.g. {\"k\": 7, \"confidence_threshold\": 0.6}" }
            }, "required": ["name", "task_type", "dataset_id"] }
        }),
        serde_json::json!({
            "name": "ml_eval_model",
            "description": "Run the knn-pgvector backend over a fresh stratified holdout (advisory-locked so concurrent evals can't corrupt each other) and record the metrics as a NEW model version. Judge the coverage_curve (fast-path accuracy@threshold; production falls back to the LLM below it) and the gold subreport (human-corrected truth) — overall accuracy is teacher-agreement only.",
            "inputSchema": { "type": "object", "properties": {
                "model_id": { "type": "string" },
                "k": { "type": "integer", "description": "Neighbors to vote (default 7)" },
                "holdout_fraction": { "type": "number", "description": "0.05-0.5, default 0.2" }
            }, "required": ["model_id"] }
        }),
        serde_json::json!({
            "name": "ml_promote_model",
            "description": "Promote a version to production: predict() serves it from now on; the previously promoted version is retired.",
            "inputSchema": { "type": "object", "properties": {
                "model_id": { "type": "string" },
                "version_id": { "type": "string" }
            }, "required": ["model_id", "version_id"] }
        }),
        serde_json::json!({
            "name": "ml_list_models",
            "description": "List registered models with their promoted-version summary (backend + metrics).",
            "inputSchema": { "type": "object", "properties": {} }
        }),
        serde_json::json!({
            "name": "ml_get_model_card",
            "description": "Full model card: config, dataset stats, and every version's backend/metrics/status — the provenance record for 'why did the model say X'.",
            "inputSchema": { "type": "object", "properties": {
                "model_name": { "type": "string" }
            }, "required": ["model_name"] }
        }),
        serde_json::json!({
            "name": "ml_predict",
            "description": "Run one prediction through a model's PROMOTED version (P1: knn-pgvector). Returns {label, confidence, backend} or abstains — use it to sanity-check a model before wiring it into a workflow.",
            "inputSchema": { "type": "object", "properties": {
                "model_name": { "type": "string" },
                "text": { "type": "string" }
            }, "required": ["model_name", "text"] }
        }),
        serde_json::json!({
            "name": "ml_set_policy",
            "description": "Set a model's lifecycle transition policy (RFC 0011 P2d). Typed + strict: unknown keys are rejected. Keys: min_examples, min_corrections_per_class, accuracy_at_coverage {min_accuracy, min_coverage}, recall_floors {class: floor}, auto_advance (default false — evaluator reports but a human promotes), demote_below_agreement, min_shadow_total. The scheduled evaluator re-judges on every dataset change.",
            "inputSchema": { "type": "object", "properties": {
                "model_id": { "type": "string" },
                "policy": { "type": "object", "description": "The policy document; {} clears it (evaluator skips the model)" }
            }, "required": ["model_id", "policy"] }
        }),
        serde_json::json!({
            "name": "ml_set_lifecycle",
            "description": "Manually move a model's lifecycle state (llm_only → shadow → hybrid → fast_primary). Promotes advance ONE step; demotes may drop any distance (every switch is one command to reverse). Audit-logged.",
            "inputSchema": { "type": "object", "properties": {
                "model_id": { "type": "string" },
                "state": { "type": "string", "enum": ["llm_only", "shadow", "hybrid", "fast_primary"] }
            }, "required": ["model_id", "state"] }
        }),
        serde_json::json!({
            "name": "ml_disagreements",
            "description": "Pending fast-vs-LLM divergences and low-confidence samples for a model (decrypted, owner-only) — the disagreement digest feed. Review each with ml_resolve_disagreement.",
            "inputSchema": { "type": "object", "properties": {
                "model_name": { "type": "string" },
                "limit": { "type": "integer", "description": "1-100, default 20" }
            }, "required": ["model_name"] }
        }),
        serde_json::json!({
            "name": "ml_resolve_disagreement",
            "description": "One-tap digest verdict. With correct_label: appends a human CORRECTION example (gold truth, replaces the production row via example_key) and marks the disagreement resolved. Without: marks it dismissed.",
            "inputSchema": { "type": "object", "properties": {
                "disagreement_id": { "type": "string" },
                "correct_label": { "type": "string", "description": "The human-verified label; omit to dismiss" }
            }, "required": ["disagreement_id"] }
        }),
        serde_json::json!({
            "name": "ml_provision_classifier",
            "description": "One-call classifier setup: creates the dataset + model (born llm_only) + a safe default promotion policy (auto_advance OFF — a human promotes) under the given actor's tenancy, and returns the model_name to wire into a Smart Classifier / Model_Predict node. Idempotent: an existing model of the same name is reused. The classifier starts as pure-LLM and distills into a fast model as the workflow runs.",
            "inputSchema": { "type": "object", "properties": {
                "name": { "type": "string", "description": "Classifier name (per-user unique; [A-Za-z0-9._-])" },
                "labels": { "type": "array", "items": {"type": "string"}, "description": "The label set — 2+ distinct classes" },
                "actor_id": { "type": "string", "description": "The workflow's bound actor (must be yours); owns tenancy + digest delivery" },
                "fallback_provider": { "type": "string", "description": "LLM fallback provider (default ollama, Tier-1 local)" },
                "fallback_model": { "type": "string", "description": "LLM fallback model (default qwen3.6:latest)" },
                "allow_external_llm": { "type": "boolean", "description": "Opt-in for a non-local (Tier-2) fallback provider; default false" },
                "k": { "type": "integer", "description": "kNN neighborhood (default 7)" },
                "confidence_threshold": { "type": "number", "description": "Serving confidence gate 0-1 (default 0.6)" },
                "max_examples": { "type": "integer", "description": "Dataset growth cap" },
                "policy": { "type": "object", "description": "Advanced: full policy override; omit for the safe default" }
            }, "required": ["name", "labels", "actor_id"] }
        }),
        serde_json::json!({
            "name": "ml_teacher_audit",
            "description": "Run the LLM TEACHER over a model's GOLD slice (its source='correction' rows — human truth) and report teacher-vs-human accuracy + per-class breakdown. Quantifies teacher-label noise, the accuracy CEILING of the distilled model. Uses the SAME prompt/few-shot contract as the production classify leg; local (ollama) teachers only. ASYNC: returns {status:'started', gold_rows} immediately (config errors still return synchronously) and runs the ≤100-call loop in the background — POLL ml_get_model_card and read teacher_audit (status: running→complete/failed) for progress and the result. A second start while one is running is refused.",
            "inputSchema": { "type": "object", "properties": {
                "model_id": { "type": "string" },
                "limit": { "type": "integer", "description": "Gold rows to audit, 1-100 (default 100); each row is one local LLM call" },
                "system_prompt": { "type": "string", "description": "The classifier node's SYSTEM_PROMPT, for exact prompt parity; omit to audit with the bare label instruction" }
            }, "required": ["model_id"] }
        }),
        serde_json::json!({
            "name": "ml_reset_shadow_window",
            "description": "Rotate a model's shadow-agreement window (new epoch): the drift guard and the card's `shadow` block start counting fresh observations, and history moves to the lifetime aggregate. Use after changing the TEACHER without promoting a version (new fallback model/prompt, correction-loop improvements) — transitions and promotions rotate the window automatically. Audit-logged.",
            "inputSchema": { "type": "object", "properties": {
                "model_name": { "type": "string", "description": "The model whose window to rotate (must be yours)" }
            }, "required": ["model_name"] }
        }),
        serde_json::json!({
            "name": "ml_delete_model",
            "description": "Delete a registered model (versions/shadow-stats/disagreements cascade) and optionally its dataset (+examples). Refuses when any of YOUR workflows reference the model by name (remove/repoint those nodes first) or, with delete_dataset, when other models still train on the dataset. The cleanup path for test/demo classifiers.",
            "inputSchema": { "type": "object", "properties": {
                "model_name": { "type": "string", "description": "The model to delete (must be yours)" },
                "delete_dataset": { "type": "boolean", "description": "Also delete the model's dataset and all its examples; default false" }
            }, "required": ["model_name"] }
        }),
    ]
}

pub async fn dispatch(
    tool_name: &str,
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    agent: Arc<super::auth::AgentIdentity>,
) -> Option<JsonRpcResponse> {
    if !tool_name.starts_with("ml_") {
        return None;
    }
    let Some(user_id) = agent.user_id else {
        return Some(mcp_error(
            req_id,
            -32000,
            "ML lifecycle tools require a user-bound agent identity",
        ));
    };
    match tool_name {
        "ml_create_dataset" => Some(handle_create_dataset(req_id, args, state, user_id).await),
        "ml_append_examples" => Some(handle_append_examples(req_id, args, state, user_id).await),
        "ml_dataset_stats" => Some(handle_dataset_stats(req_id, args, state, user_id).await),
        "ml_sample_examples" => Some(handle_sample_examples(req_id, args, state, user_id).await),
        "ml_create_model" => Some(handle_create_model(req_id, args, state, user_id).await),
        "ml_eval_model" => Some(handle_eval_model(req_id, args, state, user_id).await),
        "ml_promote_model" => Some(handle_promote_model(req_id, args, state, user_id).await),
        "ml_list_models" => Some(handle_list_models(req_id, state, user_id).await),
        "ml_get_model_card" => Some(handle_get_model_card(req_id, args, state, user_id).await),
        "ml_predict" => Some(handle_predict(req_id, args, state, user_id).await),
        "ml_set_policy" => Some(handle_set_policy(req_id, args, state, user_id).await),
        "ml_set_lifecycle" => Some(handle_set_lifecycle(req_id, args, state, user_id).await),
        "ml_disagreements" => Some(handle_disagreements(req_id, args, state, user_id).await),
        "ml_resolve_disagreement" => {
            Some(handle_resolve_disagreement(req_id, args, state, user_id).await)
        }
        "ml_provision_classifier" => {
            Some(handle_provision_classifier(req_id, args, state, user_id).await)
        }
        "ml_teacher_audit" => Some(handle_teacher_audit(req_id, args, state, user_id).await),
        "ml_reset_shadow_window" => {
            Some(handle_reset_shadow_window(req_id, args, state, user_id).await)
        }
        "ml_delete_model" => Some(handle_delete_model(req_id, args, state, user_id).await),
        _ => None,
    }
}

fn dataset_service(state: &McpState) -> DatasetService {
    DatasetService::new(state.secrets_manager.clone())
}

/// Per-user tenant-scoped tx: sets `app.current_user_id` so the ml_*
/// RLS policies (read union + write pins) enforce.
async fn user_tx(
    state: &McpState,
    user_id: Uuid,
) -> anyhow::Result<sqlx::Transaction<'_, sqlx::Postgres>> {
    talos_db::begin_tenant_read_scoped(
        &state.db_pool,
        &talos_tenancy::TenantReadScope::new(user_id, Vec::new()),
    )
    .await
    .map_err(|e| anyhow::anyhow!("open user-scoped tx: {e}"))
}

fn parse_uuid(args: &Value, key: &str) -> Result<Uuid, String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| format!("Missing required parameter: {key}"))
        .and_then(|s| Uuid::parse_str(s).map_err(|_| format!("{key} must be a UUID")))
}

fn parse_source(s: &str) -> Result<ExampleSource, String> {
    match s {
        "llm_bootstrap" => Ok(ExampleSource::LlmBootstrap),
        "correction" => Ok(ExampleSource::Correction),
        "llm_fallback" => Ok(ExampleSource::LlmFallback),
        "llm_production" => Ok(ExampleSource::LlmProduction),
        "import" => Ok(ExampleSource::Import),
        "synthetic" => Ok(ExampleSource::Synthetic),
        other => Err(format!(
            "invalid source '{other}' (expected llm_bootstrap|correction|llm_fallback|llm_production|import|synthetic)"
        )),
    }
}

/// Internal errors collapse to a generic message (never leak schema /
/// query detail through the protocol); the full error is logged.
fn internal(req_id: Option<Value>, context: &str, e: &anyhow::Error) -> JsonRpcResponse {
    tracing::error!(target: "talos_ml", error = %e, "{context} failed");
    mcp_error(
        req_id,
        -32000,
        &format!("{context} failed (see server logs)"),
    )
}

/// Ownership gate: the dataset's tenancy row must name the caller.
/// Defense in depth alongside RLS (which only enforces under
/// TALOS_RLS_SET_ROLE).
async fn require_dataset_owner(
    svc: &DatasetService,
    conn: &mut sqlx::PgConnection,
    dataset_id: Uuid,
    user_id: Uuid,
) -> Result<talos_ml::DatasetTenancy, String> {
    match svc.dataset_tenancy(conn, dataset_id).await {
        Ok(t) if t.user_id == user_id => Ok(t),
        // Single message for not-found AND foreign rows so the surface
        // can't enumerate other tenants' dataset ids.
        _ => Err("Dataset not found".to_string()),
    }
}

async fn handle_create_dataset(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: name");
    };
    let Some(task_type) = args.get("task_type").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: task_type");
    };
    let schema_json = args
        .get("schema_json")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let svc = dataset_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "create_dataset", &e),
    };
    let created = svc
        .create_dataset(&mut tx, user_id, None, name, task_type, &schema_json)
        .await;
    match created {
        Ok(id) => match tx.commit().await {
            Ok(()) => mcp_text(
                req_id,
                &serde_json::json!({ "dataset_id": id.to_string(), "name": name }).to_string(),
            ),
            Err(e) => internal(req_id, "create_dataset commit", &e.into()),
        },
        Err(e) => internal(req_id, "create_dataset", &e),
    }
}

async fn handle_append_examples(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let dataset_id = match parse_uuid(args, "dataset_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let Some(raw) = args.get("examples").and_then(|v| v.as_array()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: examples");
    };
    if raw.is_empty() || raw.len() > MAX_EXAMPLES_PER_CALL {
        return mcp_error(
            req_id,
            -32602,
            &format!("examples must contain 1-{MAX_EXAMPLES_PER_CALL} items"),
        );
    }
    let mut examples = Vec::with_capacity(raw.len());
    for (i, ex) in raw.iter().enumerate() {
        let get = |k: &str| ex.get(k).and_then(|v| v.as_str());
        let (Some(text), Some(label), Some(source)) =
            (get("features_text"), get("label"), get("source"))
        else {
            return mcp_error(
                req_id,
                -32602,
                &format!("examples[{i}] needs features_text, label, source"),
            );
        };
        let source = match parse_source(source) {
            Ok(s) => s,
            Err(m) => return mcp_error(req_id, -32602, &format!("examples[{i}]: {m}")),
        };
        examples.push(AppendExample {
            features_text: text.to_string(),
            label: label.to_string(),
            source,
            example_key: get("example_key").map(str::to_string),
        });
    }
    let svc = dataset_service(state);
    // Short tx #1: ownership + tenancy. Then embed/encrypt with NO
    // connection held. Then short tx #2: batched insert.
    let tenancy = {
        let mut tx = match user_tx(state, user_id).await {
            Ok(tx) => tx,
            Err(e) => return internal(req_id, "append_examples", &e),
        };
        match require_dataset_owner(&svc, &mut tx, dataset_id, user_id).await {
            Ok(t) => t,
            Err(m) => return mcp_error(req_id, -32000, &m),
        }
    };
    let prepared = match svc.prepare_examples(dataset_id, tenancy, examples).await {
        Ok(p) => p,
        Err(e) => return internal(req_id, "append_examples prepare", &e),
    };
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "append_examples", &e),
    };
    match svc
        .insert_prepared(&mut tx, dataset_id, tenancy, prepared)
        .await
    {
        Ok(stored) => match tx.commit().await {
            Ok(()) => mcp_text(
                req_id,
                &serde_json::json!({ "dataset_id": dataset_id.to_string(), "stored": stored })
                    .to_string(),
            ),
            Err(e) => internal(req_id, "append_examples commit", &e.into()),
        },
        Err(e) => internal(req_id, "append_examples insert", &e),
    }
}

async fn handle_dataset_stats(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let dataset_id = match parse_uuid(args, "dataset_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let svc = dataset_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "dataset_stats", &e),
    };
    if let Err(m) = require_dataset_owner(&svc, &mut tx, dataset_id, user_id).await {
        return mcp_error(req_id, -32000, &m);
    }
    match svc.stats(&mut tx, dataset_id).await {
        Ok(stats) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&stats).unwrap_or_default(),
        ),
        Err(e) => internal(req_id, "dataset_stats", &e),
    }
}

async fn handle_sample_examples(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let dataset_id = match parse_uuid(args, "dataset_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let per_label = args
        .get("per_label")
        .and_then(|v| v.as_i64())
        .unwrap_or(5)
        .clamp(1, 25);
    let svc = dataset_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "sample_examples", &e),
    };
    if let Err(m) = require_dataset_owner(&svc, &mut tx, dataset_id, user_id).await {
        return mcp_error(req_id, -32000, &m);
    }
    match svc.sample_examples(&mut tx, dataset_id, per_label).await {
        Ok(samples) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&samples).unwrap_or_default(),
        ),
        Err(e) => internal(req_id, "sample_examples", &e),
    }
}

async fn handle_create_model(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: name");
    };
    let Some(task_type) = args.get("task_type").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: task_type");
    };
    let dataset_id = match parse_uuid(args, "dataset_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let config_json = args
        .get("config_json")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let svc = dataset_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "create_model", &e),
    };
    // The model's dataset must be the caller's own.
    if let Err(m) = require_dataset_owner(&svc, &mut tx, dataset_id, user_id).await {
        return mcp_error(req_id, -32000, &m);
    }
    let created = ModelRegistry::create_model(
        &mut tx,
        user_id,
        None,
        name,
        task_type,
        Some(dataset_id),
        &config_json,
    )
    .await;
    match created {
        Ok(id) => match tx.commit().await {
            Ok(()) => mcp_text(
                req_id,
                &serde_json::json!({ "model_id": id.to_string(), "name": name }).to_string(),
            ),
            Err(e) => internal(req_id, "create_model commit", &e.into()),
        },
        Err(e) => internal(req_id, "create_model", &e),
    }
}

async fn handle_eval_model(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let model_id = match parse_uuid(args, "model_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let holdout_fraction = args
        .get("holdout_fraction")
        .and_then(|v| v.as_f64())
        .unwrap_or(0.2);
    let svc = dataset_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "eval_model", &e),
    };
    // Resolve model + its dataset; ownership gate rides on the dataset.
    let Ok(Some(models)) = ModelRegistry::resolve_by_id(&mut tx, model_id, user_id).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
    // Effective k: explicit arg > the MODEL's configured k > default. Using
    // the model's own k (like the scheduled evaluator does) keeps the eval
    // from certifying a different neighborhood than production serves.
    let k = args
        .get("k")
        .and_then(|v| v.as_i64())
        .or_else(|| models.config_json.get("k").and_then(|v| v.as_i64()))
        .unwrap_or(DEFAULT_KNN_K)
        .clamp(1, 50);
    let Some(dataset_id) = models.dataset_id else {
        return mcp_error(
            req_id,
            -32000,
            "Model has no dataset (cannot eval a lazy backend)",
        );
    };
    if let Err(m) = require_dataset_owner(&svc, &mut tx, dataset_id, user_id).await {
        return mcp_error(req_id, -32000, &m);
    }
    // Split + score + record inside ONE tx: the advisory lock taken by
    // run_knn_eval holds until commit, so a concurrent eval can't thrash
    // this run's holdout mid-scoring.
    // Split ONCE, evaluate EVERY backend on it (knn + linear), and record
    // the highest-macro-F1 winner as a version — all inside ONE tx (the
    // advisory lock the selector takes holds until commit, so a concurrent
    // eval can't thrash this run's split mid-scoring).
    // Same corrections scheme as the lifecycle promotion path — manual
    // and scheduled evals must not calibrate thresholds under different
    // voting/weighting rules.
    let corrections_cfg = talos_ml::corrections_cfg_for_dataset(&mut tx, dataset_id).await;
    let candidates = match talos_ml::run_backend_selection_eval(
        &svc,
        &mut tx,
        dataset_id,
        k,
        holdout_fraction,
        talos_ml::FitOpts::default(),
        corrections_cfg,
    )
    .await
    {
        Ok(c) if !c.is_empty() => c,
        Ok(_) => return mcp_error(req_id, -32000, "eval produced no backend candidates"),
        Err(e) => return internal(req_id, "eval_model", &e),
    };
    // Winner is first (selector sorts best-first). Clone what outlives the
    // borrow so the version record + response can both reference it.
    let winner_backend = candidates[0].backend;
    let report = candidates[0].report.clone();
    let artifact = candidates[0].artifact.clone();
    let params = candidates[0].params.clone();
    let comparison: Vec<Value> = candidates
        .iter()
        .map(|c| {
            serde_json::json!({
                "backend": c.backend,
                "macro_recall": c.macro_recall,
                "macro_f1": c.macro_f1,
            })
        })
        .collect();

    let mut metrics = serde_json::json!({
        "backend": winner_backend,
        "holdout_fraction": holdout_fraction,
        "report": report,
        "selected_backend": winner_backend,
        "backend_comparison": comparison.clone(),
    });
    // Fold in the winner's backend-specific hyperparameters (voting/k for
    // knn, epochs/l2/balanced for linear) so the card records exactly what
    // produced the artifact.
    if let (Some(obj), Some(p)) = (metrics.as_object_mut(), params.as_object()) {
        for (kk, vv) in p {
            obj.insert(kk.clone(), vv.clone());
        }
    }
    let version = match ModelRegistry::create_version(
        &mut tx,
        model_id,
        user_id,
        None,
        winner_backend,
        artifact.as_deref(),
        &metrics,
    )
    .await
    {
        Ok(v) => v,
        Err(e) => return internal(req_id, "eval_model record version", &e),
    };
    match tx.commit().await {
        Ok(()) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "model_id": model_id.to_string(),
                "version_id": version.id.to_string(),
                "version": version.version,
                "selected_backend": winner_backend,
                "backend_comparison": comparison,
                "report": metrics.get("report"),
                "next_step": "the eval scored every backend on one holdout and picked the highest macro-recall (balanced accuracy, aligned with the policy's per-class recall floors); judge report.coverage_curve + report.gold, then ml_promote_model when the policy clears",
            }))
            .unwrap_or_default(),
        ),
        Err(e) => internal(req_id, "eval_model commit", &e.into()),
    }
}

async fn handle_promote_model(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let model_id = match parse_uuid(args, "model_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let version_id = match parse_uuid(args, "version_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let svc = dataset_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "promote_model", &e),
    };
    let Ok(Some(model)) = ModelRegistry::resolve_by_id(&mut tx, model_id, user_id).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
    if let Some(dataset_id) = model.dataset_id {
        if let Err(m) = require_dataset_owner(&svc, &mut tx, dataset_id, user_id).await {
            return mcp_error(req_id, -32000, &m);
        }
    }
    match ModelRegistry::promote_version(&mut tx, model_id, version_id).await {
        Ok(()) => match tx.commit().await {
            Ok(()) => {
                // P2c serving cache: drop the resolved entry so the RPC
                // path serves the newly promoted version immediately
                // (same-process; the 15 s TTL bounds other replicas).
                talos_ml::serve::invalidate_serving_cache(user_id, &model.name);
                mcp_text(
                    req_id,
                    &serde_json::json!({
                        "model_id": model_id.to_string(),
                        "promoted_version_id": version_id.to_string(),
                    })
                    .to_string(),
                )
            }
            Err(e) => internal(req_id, "promote_model commit", &e.into()),
        },
        Err(e) => internal(req_id, "promote_model", &e),
    }
}

async fn handle_list_models(
    req_id: Option<Value>,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "list_models", &e),
    };
    match ModelRegistry::list_models(&mut tx, user_id).await {
        Ok(models) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({ "models": models }))
                .unwrap_or_default(),
        ),
        Err(e) => internal(req_id, "list_models", &e),
    }
}

async fn handle_get_model_card(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let Some(name) = args.get("model_name").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: model_name");
    };
    let svc = dataset_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "get_model_card", &e),
    };
    let Ok(Some(model)) = ModelRegistry::resolve_by_name(&mut tx, name, user_id).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
    let versions = match ModelRegistry::list_versions(&mut tx, model.model_id).await {
        Ok(v) => v,
        Err(e) => return internal(req_id, "get_model_card", &e),
    };
    let dataset_stats = match model.dataset_id {
        Some(did) => match require_dataset_owner(&svc, &mut tx, did, user_id).await {
            Ok(_) => svc.stats(&mut tx, did).await.ok(),
            Err(_) => None,
        },
        None => None,
    };
    // P2d lifecycle visibility: state + shadow agreement + pending-review
    // count ride on the card so "why did the model say X" and "is it safe
    // to advance" read from one place. Agreement is CURRENT-ERA (what the
    // drift guard judges); the lifetime aggregate rides alongside for
    // context, clearly labeled so nobody feeds it back into a decision.
    let lsvc = lifecycle_service(state);
    let epoch = talos_ml::shadow_epoch(&mut tx, model.model_id).await.ok();
    let shadow = lsvc
        .shadow_agreement(&mut tx, model.model_id, 0)
        .await
        .ok()
        .flatten()
        .map(|(agreement, total)| {
            serde_json::json!({"agreement": agreement, "observations": total, "epoch": epoch})
        });
    let shadow_lifetime = lsvc
        .shadow_agreement_lifetime(&mut tx, model.model_id, 0)
        .await
        .ok()
        .flatten()
        .map(
            |(agreement, total)| serde_json::json!({"agreement": agreement, "observations": total}),
        );
    let pending_disagreements = lsvc
        .pending_disagreements(&mut tx, model.model_id, user_id, 1)
        .await
        .map(|v| !v.is_empty())
        .unwrap_or(false);
    // Latest teacher-vs-gold audit (null until ml_teacher_audit runs).
    let teacher_audit = talos_ml::stored_teacher_audit(&mut tx, model.model_id, user_id)
        .await
        .ok()
        .flatten();
    let card = serde_json::json!({
        "model_id": model.model_id.to_string(),
        "name": name,
        "lifecycle_state": model.lifecycle_state,
        "shadow": shadow,
        "shadow_lifetime": shadow_lifetime,
        "has_pending_disagreements": pending_disagreements,
        "teacher_audit": teacher_audit,
        "dataset_id": model.dataset_id.map(|d| d.to_string()),
        "config_json": model.config_json,
        "policy_json": model.policy_json,
        "promoted_version": model.promoted_version,
        "versions": versions,
        "dataset_stats": dataset_stats,
    });
    mcp_text(
        req_id,
        &serde_json::to_string_pretty(&card).unwrap_or_default(),
    )
}

async fn handle_predict(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let Some(name) = args.get("model_name").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: model_name");
    };
    let Some(text) = args.get("text").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: text");
    };
    let svc = dataset_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "predict", &e),
    };
    // Route through the shared serving path (ServingMode::Raw = predict
    // unconditionally, backend-agnostic) so this sanity check reflects
    // EXACTLY what production serving returns for whichever backend is
    // promoted — knn OR linear.
    let inputs = [text.to_string()];
    match talos_ml::serve_predict_batch(
        &svc,
        &mut tx,
        user_id,
        name,
        &inputs,
        talos_ml::ServingMode::Raw,
    )
    .await
    {
        Ok(reply) => match reply.predictions.into_iter().next().flatten() {
            Some(p) => mcp_text(
                req_id,
                &serde_json::to_string_pretty(&serde_json::json!({
                    "model": name,
                    "version": reply.model_version,
                    "backend": reply.backend,
                    "prediction": { "label": p.label, "confidence": p.confidence },
                }))
                .unwrap_or_default(),
            ),
            None => mcp_text(
                req_id,
                &serde_json::json!({
                    "model": name,
                    "abstained": true,
                    "note": "degenerate neighborhood, below-threshold vote, or embedding unavailable — production callers fall back to the LLM here",
                })
                .to_string(),
            ),
        },
        Err(talos_ml::ServeError::NotFound) => mcp_error(req_id, -32000, "Model not found"),
        Err(talos_ml::ServeError::NotPromoted) => mcp_error(
            req_id,
            -32000,
            "Model has no promoted version — run ml_eval_model + ml_promote_model first",
        ),
        Err(talos_ml::ServeError::NotAvailable) => mcp_error(
            req_id,
            -32000,
            "Model's backend or dataset is not available for serving",
        ),
        Err(talos_ml::ServeError::Internal(e)) => internal(req_id, "predict", &e),
    }
}

// ────────────────────────────────────────────────────────────────────
// RFC 0011 P2d — lifecycle governance handlers
// ────────────────────────────────────────────────────────────────────

fn lifecycle_service(state: &McpState) -> talos_ml::LifecycleService {
    talos_ml::LifecycleService::new(state.secrets_manager.clone())
}

/// Set (or clear, with `{}`) a model's transition policy. Typed +
/// strict (`deny_unknown_fields` + range checks) so a typo can never
/// silently disable a governance gate; the model's config is ALSO
/// re-checked against the LLM-locality pin so a policy write can't
/// coexist with an unguarded external fallback.
async fn handle_set_policy(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let model_id = match parse_uuid(args, "model_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let Some(policy_raw) = args.get("policy") else {
        return mcp_error(req_id, -32602, "Missing required parameter: policy");
    };
    let policy = match talos_ml::PolicyJson::parse(policy_raw) {
        Ok(p) => p,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    if let Err(m) = policy.validate() {
        return mcp_error(req_id, -32602, &m);
    }
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "set_policy", &e),
    };
    let Ok(Some(model)) = ModelRegistry::resolve_by_id(&mut tx, model_id, user_id).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
    // Locality pin (RFC guard): auto_advance may route production
    // traffic; refuse a policy on a config whose fallback/baseline LLM
    // is external without the explicit opt-in.
    if let Err(m) = talos_ml::validate_llm_locality(&model.config_json) {
        return mcp_error(req_id, -32000, &m);
    }
    match ModelRegistry::set_policy(&mut tx, model_id, user_id, policy_raw).await {
        Ok(true) => match tx.commit().await {
            Ok(()) => {
                let _ = state
                    .actor_repo
                    .insert_admin_event_log(
                        user_id,
                        "ml_policy_set",
                        "ml_model",
                        Some(model_id),
                        &format!(
                            "Model '{}' lifecycle policy set (auto_advance={})",
                            model.name, policy.auto_advance
                        ),
                        Some(policy_raw),
                    )
                    .await;
                mcp_text(
                    req_id,
                    &serde_json::json!({
                        "model_id": model_id.to_string(),
                        "policy": policy_raw,
                        "auto_advance": policy.auto_advance,
                    })
                    .to_string(),
                )
            }
            Err(e) => internal(req_id, "set_policy commit", &e.into()),
        },
        Ok(false) => mcp_error(req_id, -32000, "Model not found"),
        Err(e) => internal(req_id, "set_policy", &e),
    }
}

/// Manual lifecycle transition — CAS from the CURRENT state, one step
/// forward or any distance back, audit-logged.
async fn handle_set_lifecycle(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let model_id = match parse_uuid(args, "model_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let Some(to) = args
        .get("state")
        .and_then(|v| v.as_str())
        .and_then(talos_ml::LifecycleState::parse)
    else {
        return mcp_error(
            req_id,
            -32602,
            "state must be one of llm_only|shadow|hybrid|fast_primary",
        );
    };
    let svc = lifecycle_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "set_lifecycle", &e),
    };
    let Ok(Some(model)) = ModelRegistry::resolve_by_id(&mut tx, model_id, user_id).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
    let Some(from) = talos_ml::LifecycleState::parse(&model.lifecycle_state) else {
        return internal(
            req_id,
            "set_lifecycle",
            &anyhow::anyhow!("unrecognized stored lifecycle state"),
        );
    };
    if from == to {
        return mcp_text(
            req_id,
            &serde_json::json!({"model_id": model_id.to_string(), "state": to.as_str(), "changed": false})
                .to_string(),
        );
    }
    if !talos_ml::can_transition(from, to) {
        return mcp_error(
            req_id,
            -32000,
            &format!(
                "Illegal transition {} -> {}: promotes advance one step at a time; demotes may drop any distance",
                from.as_str(),
                to.as_str()
            ),
        );
    }
    match svc.transition(&mut tx, model_id, user_id, from, to).await {
        Ok(true) => match tx.commit().await {
            Ok(()) => {
                talos_ml::invalidate_serving_cache(user_id, &model.name);
                let _ = state
                    .actor_repo
                    .insert_admin_event_log(
                        user_id,
                        "ml_lifecycle_set",
                        "ml_model",
                        Some(model_id),
                        &format!(
                            "Model '{}' lifecycle manually moved {} -> {}",
                            model.name,
                            from.as_str(),
                            to.as_str()
                        ),
                        None,
                    )
                    .await;
                mcp_text(
                    req_id,
                    &serde_json::json!({
                        "model_id": model_id.to_string(),
                        "from": from.as_str(),
                        "to": to.as_str(),
                        "changed": true,
                    })
                    .to_string(),
                )
            }
            Err(e) => internal(req_id, "set_lifecycle commit", &e.into()),
        },
        // CAS miss: someone (the evaluator) moved it first.
        Ok(false) => mcp_error(
            req_id,
            -32000,
            "State changed concurrently — re-read the model card and retry",
        ),
        Err(e) => internal(req_id, "set_lifecycle", &e),
    }
}

/// Teacher-vs-gold audit: parse → build the local-LLM transport closure →
/// `talos_ml::start_teacher_audit` (which owns the prompt contract, tenancy
/// gates, locality pin, and background execution) → format. The audit runs
/// in the background; this returns as soon as the config is validated and
/// the loop is spawned. Poll `ml_get_model_card` for the result.
async fn handle_teacher_audit(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let model_id = match parse_uuid(args, "model_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let limit = args
        .get("limit")
        .and_then(|v| v.as_i64())
        .unwrap_or(talos_ml::teacher_audit::MAX_AUDIT_ROWS)
        .clamp(1, talos_ml::teacher_audit::MAX_AUDIT_ROWS);
    // Owned so it can move into the Send + 'static classify closure / task.
    let system_prompt = args
        .get("system_prompt")
        .and_then(|v| v.as_str())
        .map(str::to_string);
    let Some(ollama) = state.ollama_client.clone() else {
        return mcp_error(
            req_id,
            -32000,
            "Local LLM (ollama) is not configured — the teacher audit runs locally only",
        );
    };
    let svc = dataset_service(state);
    // Send + 'static: captures only an Arc<OllamaClient>, so it detaches
    // cleanly onto the spawned audit task.
    // `complete_structured` = the Smart Classifier template's LLM options
    // (think:false, format:"json", temp 0.1). Reasoning teachers (qwen3.6)
    // otherwise burn the whole response budget thinking without emitting
    // the {"label": ...} object — measured 23/100 unparseable replies on
    // the 2026-07-21 audit; reasoning-off also ~3x'd the inbox A/B.
    let classify = move |r: talos_ml::TeacherRequest| {
        let ollama = ollama.clone();
        async move {
            ollama
                .complete_structured(
                    &r.llm_model,
                    &r.system_prompt,
                    &r.user_content,
                    r.max_tokens,
                )
                .await
        }
    };
    match talos_ml::start_teacher_audit(
        &state.db_pool,
        &svc,
        user_id,
        model_id,
        limit,
        system_prompt,
        classify,
    )
    .await
    {
        Ok(started) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "status": "started",
                "model_id": model_id.to_string(),
                "gold_rows": started.gold_rows,
                "poll": "ml_get_model_card",
                "next_step": "the audit runs in the background (≤100 local LLM calls) — poll ml_get_model_card and read teacher_audit.status (running → complete/failed); on complete, review mismatches (real disagreements only) and parse_failed, improve the node's SYSTEM_PROMPT or add corrections, then re-audit",
            }))
            .unwrap_or_default(),
        ),
        Err(talos_ml::TeacherAuditError::NotFound) => mcp_error(req_id, -32000, "Model not found"),
        Err(talos_ml::TeacherAuditError::NoDataset) => {
            mcp_error(req_id, -32000, "Model has no dataset to audit against")
        }
        Err(talos_ml::TeacherAuditError::InvalidConfig(m)) => mcp_error(req_id, -32000, &m),
        Err(talos_ml::TeacherAuditError::AlreadyRunning) => mcp_error(
            req_id,
            -32000,
            "A teacher audit is already running for this model — poll ml_get_model_card for progress",
        ),
        Err(talos_ml::TeacherAuditError::Internal(e)) => internal(req_id, "teacher_audit", &e),
    }
}

/// Manual shadow-window rotation — for teacher-only changes (new
/// fallback model/prompt, correction-loop improvements) that don't run
/// through the automatic rotation on transition/promotion. Owner-only,
/// audit-logged. The bump itself discards nothing: history moves to the
/// lifetime aggregate and prunes past the retention depth.
async fn handle_reset_shadow_window(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let Some(name) = args.get("model_name").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: model_name");
    };
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "reset_shadow_window", &e),
    };
    // resolve_by_name is user-scoped — the tenancy gate; a foreign model
    // is indistinguishable from an absent one.
    let Ok(Some(model)) = ModelRegistry::resolve_by_name(&mut tx, name, user_id).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
    let new_epoch = match talos_ml::bump_shadow_epoch(&mut tx, model.model_id).await {
        Ok(e) => e,
        Err(e) => return internal(req_id, "reset_shadow_window", &e),
    };
    match tx.commit().await {
        Ok(()) => {
            let _ = state
                .actor_repo
                .insert_admin_event_log(
                    user_id,
                    "ml_shadow_window_reset",
                    "ml_model",
                    Some(model.model_id),
                    &format!(
                        "Model '{}' shadow-agreement window manually rotated to epoch {new_epoch}",
                        model.name
                    ),
                    None,
                )
                .await;
            mcp_text(
                req_id,
                &serde_json::json!({
                    "model_id": model.model_id.to_string(),
                    "shadow_epoch": new_epoch,
                    "note": "drift guard and card `shadow` now count fresh observations; history is in `shadow_lifetime`",
                })
                .to_string(),
            )
        }
        Err(e) => internal(req_id, "reset_shadow_window commit", &e.into()),
    }
}

/// The digest feed: pending fast-vs-LLM divergences, decrypted,
/// owner-only.
async fn handle_disagreements(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let Some(name) = args.get("model_name").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: model_name");
    };
    let limit = args.get("limit").and_then(|v| v.as_i64()).unwrap_or(20);
    let svc = lifecycle_service(state);
    let mut tx = match user_tx(state, user_id).await {
        Ok(tx) => tx,
        Err(e) => return internal(req_id, "disagreements", &e),
    };
    let Ok(Some(model)) = ModelRegistry::resolve_by_name(&mut tx, name, user_id).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
    match svc
        .pending_disagreements(&mut tx, model.model_id, user_id, limit)
        .await
    {
        Ok(items) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "model_id": model.model_id.to_string(),
                "lifecycle_state": model.lifecycle_state,
                "pending": items,
                "next_step": "for each: ml_resolve_disagreement with correct_label (appends a gold correction) or without (dismiss)",
            }))
            .unwrap_or_default(),
        ),
        Err(e) => internal(req_id, "disagreements", &e),
    }
}

/// One-tap digest verdict. With `correct_label`, the SYSTEM stamps a
/// `source='correction'` example from the disagreement's own stored
/// features + example_key (the trusted correction-provenance path: the
/// caller supplies only the label; features/key come from the recorded
/// production traffic), then marks the row resolved. Without it, the
/// row is dismissed.
async fn handle_resolve_disagreement(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let id = match parse_uuid(args, "disagreement_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let correct_label = args.get("correct_label").and_then(|v| v.as_str());
    let lsvc = lifecycle_service(state);
    let dsvc = dataset_service(state);

    // The full two-tx, prepare-outside-tx, owner-scoped flow lives in
    // `talos_ml::resolve_disagreement` — the ONE implementation shared with
    // the GraphQL resolver so the tenancy invariants can't drift between
    // the two surfaces. This handler only parses input + maps the outcome.
    match talos_ml::resolve_disagreement(&state.db_pool, &lsvc, &dsvc, id, user_id, correct_label)
        .await
    {
        Ok(outcome) => mcp_text(
            req_id,
            &serde_json::json!({
                "disagreement_id": id.to_string(),
                "status": outcome.status,
                "correction_appended": outcome.correction_appended,
            })
            .to_string(),
        ),
        Err(talos_ml::ResolveError::NotFound) => {
            mcp_error(req_id, -32000, "Disagreement not found or already handled")
        }
        Err(talos_ml::ResolveError::NoDataset) => {
            mcp_error(req_id, -32000, "Model has no dataset to correct into")
        }
        Err(talos_ml::ResolveError::Internal(e)) => internal(req_id, "resolve_disagreement", &e),
    }
}

/// One-call classifier provisioning — the Smart Classifier front door.
/// Composes dataset + model + safe-default policy in one owner-scoped tx via
/// the shared `talos_ml::provision_classifier` (the same service the GraphQL
/// mutation calls). This handler only parses input + maps the outcome.
async fn handle_provision_classifier(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let Some(name) = args.get("name").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: name");
    };
    let labels: Vec<String> = args
        .get("labels")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    if labels.is_empty() {
        return mcp_error(
            req_id,
            -32602,
            "Missing required parameter: labels (2+ distinct)",
        );
    }
    let actor_id = match parse_uuid(args, "actor_id") {
        Ok(v) => v,
        Err(m) => return mcp_error(req_id, -32602, &m),
    };
    let input = talos_ml::ProvisionInput {
        name: name.to_string(),
        labels,
        actor_id,
        fallback_provider: args
            .get("fallback_provider")
            .and_then(|v| v.as_str())
            .map(String::from),
        fallback_model: args
            .get("fallback_model")
            .and_then(|v| v.as_str())
            .map(String::from),
        allow_external_llm: args
            .get("allow_external_llm")
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        k: args.get("k").and_then(|v| v.as_i64()),
        confidence_threshold: args.get("confidence_threshold").and_then(|v| v.as_f64()),
        max_examples: args.get("max_examples").and_then(|v| v.as_i64()),
        policy_override: args.get("policy").cloned(),
    };
    let dsvc = dataset_service(state);
    match talos_ml::provision_classifier(&state.db_pool, &dsvc, input, user_id).await {
        Ok(o) => mcp_text(
            req_id,
            &serde_json::json!({
                "model_name": o.model_name,
                "model_id": o.model_id.to_string(),
                "dataset_id": o.dataset_id.to_string(),
                "lifecycle_state": o.lifecycle_state,
                "already_existed": o.already_existed,
                "locality_warning": o.locality_warning,
                "next_step": "wire model_name into a classifier node on an actor-bound workflow; it serves via the LLM until it distills enough data and you promote it in the Models page",
            })
            .to_string(),
        ),
        Err(talos_ml::ProvisionError::InvalidInput(m)) => mcp_error(req_id, -32602, &m),
        Err(talos_ml::ProvisionError::InvalidActor) => {
            mcp_error(req_id, -32000, "actor not found or not owned by you")
        }
        Err(talos_ml::ProvisionError::Internal(e)) => internal(req_id, "provision_classifier", &e),
    }
}

async fn handle_delete_model(
    req_id: Option<Value>,
    args: &Value,
    state: &McpState,
    user_id: Uuid,
) -> JsonRpcResponse {
    let Some(model_name) = args.get("model_name").and_then(|v| v.as_str()) else {
        return mcp_error(req_id, -32602, "Missing required parameter: model_name");
    };
    let delete_dataset = args
        .get("delete_dataset")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    match talos_ml::delete_model(&state.db_pool, model_name, delete_dataset, user_id).await {
        Ok(o) => mcp_text(
            req_id,
            &serde_json::json!({
                "model_name": model_name,
                "model_id": o.model_id.to_string(),
                "model_deleted": o.model_deleted,
                "dataset_id": o.dataset_id.map(|d| d.to_string()),
                "dataset_deleted": o.dataset_deleted,
            })
            .to_string(),
        ),
        Err(talos_ml::DeleteError::NotFound) => {
            mcp_error(req_id, -32000, "model not found or not owned by you")
        }
        Err(talos_ml::DeleteError::ReferencedByWorkflows(n)) => mcp_error(
            req_id,
            -32602,
            &format!(
                "{n} of your workflow(s) reference this model by name — remove or repoint \
                 those nodes (search_workflows for the model name), then retry"
            ),
        ),
        Err(talos_ml::DeleteError::DatasetShared(siblings)) => mcp_error(
            req_id,
            -32602,
            &format!(
                "dataset is still used by other model(s): {} — delete those first or omit \
                 delete_dataset",
                siblings.join(", ")
            ),
        ),
        Err(talos_ml::DeleteError::Internal(e)) => internal(req_id, "delete_model", &e),
    }
}
