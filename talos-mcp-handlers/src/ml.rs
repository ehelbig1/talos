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
const DEFAULT_KNN_K: i64 = 7;

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
                    "source": { "type": "string", "enum": ["llm_bootstrap", "correction", "llm_fallback", "import", "synthetic"] },
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
            "description": "Run the knn-pgvector backend over a fresh stratified holdout (advisory-locked so concurrent evals can't corrupt each other) and record the metrics as a NEW model version. Compare the report's accuracy against your LLM baseline before promoting.",
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
        "import" => Ok(ExampleSource::Import),
        "synthetic" => Ok(ExampleSource::Synthetic),
        other => Err(format!(
            "invalid source '{other}' (expected llm_bootstrap|correction|llm_fallback|import|synthetic)"
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
    let k = args
        .get("k")
        .and_then(|v| v.as_i64())
        .unwrap_or(DEFAULT_KNN_K)
        .clamp(1, 50);
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
    let Ok(Some(models)) = ModelRegistry::resolve_by_id(&mut tx, model_id).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
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
    let report = match talos_ml::run_knn_eval(&svc, &mut tx, dataset_id, k, holdout_fraction).await
    {
        Ok(r) => r,
        Err(e) => return internal(req_id, "eval_model", &e),
    };
    let metrics = serde_json::json!({
        "backend": "knn-pgvector",
        "k": k,
        "holdout_fraction": holdout_fraction,
        "report": report,
    });
    let version = match ModelRegistry::create_version(
        &mut tx,
        model_id,
        user_id,
        None,
        "knn-pgvector",
        None,
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
                "report": report,
                "next_step": "compare report.accuracy against your LLM baseline; ml_promote_model if it clears the gate",
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
    let Ok(Some(model)) = ModelRegistry::resolve_by_id(&mut tx, model_id).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
    if let Some(dataset_id) = model.dataset_id {
        if let Err(m) = require_dataset_owner(&svc, &mut tx, dataset_id, user_id).await {
            return mcp_error(req_id, -32000, &m);
        }
    }
    match ModelRegistry::promote_version(&mut tx, model_id, version_id).await {
        Ok(()) => match tx.commit().await {
            Ok(()) => mcp_text(
                req_id,
                &serde_json::json!({
                    "model_id": model_id.to_string(),
                    "promoted_version_id": version_id.to_string(),
                })
                .to_string(),
            ),
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
    match ModelRegistry::list_models(&mut tx).await {
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
    let Ok(Some(model)) = ModelRegistry::resolve_by_name(&mut tx, name).await else {
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
    let card = serde_json::json!({
        "model_id": model.model_id.to_string(),
        "name": name,
        "dataset_id": model.dataset_id.map(|d| d.to_string()),
        "config_json": model.config_json,
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
    let Ok(Some(model)) = ModelRegistry::resolve_by_name(&mut tx, name).await else {
        return mcp_error(req_id, -32000, "Model not found");
    };
    let Some(promoted) = &model.promoted_version else {
        return mcp_error(
            req_id,
            -32000,
            "Model has no promoted version — run ml_eval_model + ml_promote_model first",
        );
    };
    if promoted.backend != "knn-pgvector" {
        return mcp_error(
            req_id,
            -32000,
            &format!(
                "backend '{}' is not servable in P1 (knn-pgvector only)",
                promoted.backend
            ),
        );
    }
    // Loud, distinct failure for a dataset-less lazy backend (the RFC's
    // deletion-lifecycle contract), never a silent abstain.
    let Some(dataset_id) = model.dataset_id else {
        return mcp_error(
            req_id,
            -32000,
            "Model's dataset is gone — knn backend not available",
        );
    };
    if let Err(m) = require_dataset_owner(&svc, &mut tx, dataset_id, user_id).await {
        return mcp_error(req_id, -32000, &m);
    }
    let k = model
        .config_json
        .get("k")
        .and_then(|v| v.as_i64())
        .unwrap_or(DEFAULT_KNN_K)
        .clamp(1, 50);
    match svc.knn_predict_text(&mut tx, dataset_id, text, k).await {
        Ok(Some(pred)) => mcp_text(
            req_id,
            &serde_json::to_string_pretty(&serde_json::json!({
                "model": name,
                "version": promoted.version,
                "backend": "knn-pgvector",
                "prediction": pred,
            }))
            .unwrap_or_default(),
        ),
        Ok(None) => mcp_text(
            req_id,
            &serde_json::json!({
                "model": name,
                "abstained": true,
                "note": "empty/degenerate neighborhood or embedding unavailable — production callers fall back to the LLM here",
            })
            .to_string(),
        ),
        Err(e) => internal(req_id, "predict", &e),
    }
}
