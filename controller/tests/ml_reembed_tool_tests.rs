//! `ml_reembed_dataset` end to end, through the tool, against a real database
//! and a stand-in local embedding provider (2026-10-01).
//!
//! `ml_reembed_tests` drives the pass itself with a supplied embedder. This
//! binary drives what that cannot see: the tool's dry-run default, its
//! ownership gate, the production embedder call, and the `admin_event_log`
//! record written on the pass's own transaction.
//!
//! ONE test in this binary: the embedding client reads its configuration
//! once per process.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use uuid::Uuid;

const DIMS: usize = 1024;
const MODEL: &str = "mock-embedder";

/// A local OpenAI-compatible embedder: the vector depends only on the text.
async fn start_embedder(calls: Arc<AtomicUsize>) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/v1/embeddings", listener.local_addr().unwrap());
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let calls = calls.clone();
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 8192];
                let body_start = loop {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let head = String::from_utf8_lossy(&buf[..body_start]).to_ascii_lowercase();
                let want: usize = head
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .unwrap_or(0);
                while buf.len() < body_start + want {
                    let Ok(n) = sock.read(&mut chunk).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                calls.fetch_add(1, Ordering::SeqCst);
                let request: Value = serde_json::from_slice(&buf[body_start..]).unwrap_or_default();
                let text = request["input"].as_str().unwrap_or_default();
                let seed = text.bytes().fold(7u32, |acc, b| {
                    acc.wrapping_mul(31).wrapping_add(u32::from(b))
                });
                let vector: Vec<f32> = (0..DIMS)
                    .map(|i| ((seed.wrapping_add(i as u32) % 1000) as f32) / 1000.0)
                    .collect();
                let body = json!({ "data": [{ "embedding": vector }] }).to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = sock.write_all(response.as_bytes()).await;
                let _ = sock.shutdown().await;
            });
        }
    });
    url
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true)",
    )
    .bind(id)
    .bind(format!("{id}@ml-reembed-tool.test"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn call(
    state: &controller::mcp::McpState,
    user: Uuid,
    tool: &str,
    args: Value,
) -> controller::mcp::types::JsonRpcResponse {
    controller::mcp::ml::dispatch(tool, Some(json!(1)), &args, state, agent(user))
        .await
        .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

/// `(rows with no vector, rows on another model, rows on the active model)`.
async fn row_states(pool: &sqlx::PgPool, ds: Uuid) -> (i64, i64, i64) {
    sqlx::query_as(
        "SELECT COUNT(*) FILTER (WHERE embedding IS NULL), \
                COUNT(*) FILTER (WHERE embedding IS NOT NULL AND embedding_model IS DISTINCT FROM $2), \
                COUNT(*) FILTER (WHERE embedding IS NOT NULL AND embedding_model = $2) \
           FROM ml_examples WHERE dataset_id = $1",
    )
    .bind(ds)
    .bind(MODEL)
    .fetch_one(pool)
    .await
    .expect("row states")
}

async fn reembed_events(pool: &sqlx::PgPool, ds: Uuid) -> Vec<(Option<Uuid>, Value)> {
    sqlx::query_as(
        "SELECT user_id, details FROM admin_event_log \
         WHERE event_type = 'ml_dataset_reembedded' AND resource_id = $1 ORDER BY created_at",
    )
    .bind(ds)
    .fetch_all(pool)
    .await
    .expect("read admin events")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_tool_surveys_by_default_and_re_embeds_only_for_the_owner() {
    let calls = Arc::new(AtomicUsize::new(0));
    let url = start_embedder(calls.clone()).await;
    // Before the first embedding call of the process.
    std::env::set_var("EMBEDDING_API_URL", &url);
    std::env::set_var("EMBEDDING_MODEL", MODEL);
    std::env::set_var("EMBEDDING_DIMENSIONS", DIMS.to_string());
    std::env::remove_var("EMBEDDING_API_KEY");
    std::env::remove_var("OPENAI_API_KEY");

    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    // The harness builds the secrets manager without a data key; the append
    // below encrypts features, so it needs one.
    state
        .secrets_manager
        .initialize()
        .await
        .expect("initialize secrets manager");

    let created = text_json(
        &call(
            &state,
            owner,
            "ml_create_dataset",
            json!({"name": "reembed-tool", "task_type": "classification"}),
        )
        .await,
    );
    let ds = Uuid::parse_str(created["dataset_id"].as_str().expect("dataset_id")).unwrap();
    let examples: Vec<Value> = ["none", "other", "current"]
        .iter()
        .map(|k| json!({"features_text": format!("text {k}"), "label": "archive", "source": "llm_production", "example_key": k}))
        .collect();
    let appended = call(
        &state,
        owner,
        "ml_append_examples",
        json!({"dataset_id": ds.to_string(), "examples": examples}),
    )
    .await;
    assert_eq!(
        appended
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(Value::as_bool),
        None,
        "append failed: {appended:?}"
    );
    assert_eq!(
        row_states(&pool, ds).await,
        (0, 0, 3),
        "the append embedded every row"
    );

    // One row loses its vector, one is left on another model.
    let ids: Vec<Uuid> =
        sqlx::query_scalar("SELECT id FROM ml_examples WHERE dataset_id = $1 ORDER BY id")
            .bind(ds)
            .fetch_all(&pool)
            .await
            .unwrap();
    sqlx::query("UPDATE ml_examples SET embedding = NULL, embedding_model = NULL WHERE id = $1")
        .bind(ids[0])
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("UPDATE ml_examples SET embedding_model = 'model-old' WHERE id = $1")
        .bind(ids[1])
        .execute(&pool)
        .await
        .unwrap();
    assert_eq!(row_states(&pool, ds).await, (1, 1, 1));
    // The append left these texts in the client's 5-minute cache; drop it so
    // the provider calls below are the re-embed's own.
    talos_memory::embedding::clear_cache();
    let calls_before = calls.load(Ordering::SeqCst);

    // Default: a dry run. It counts, embeds nothing, writes nothing.
    let dry = text_json(
        &call(
            &state,
            owner,
            "ml_reembed_dataset",
            json!({"dataset_id": ds.to_string()}),
        )
        .await,
    );
    assert_eq!(dry["dry_run"], true, "{dry}");
    assert_eq!(dry["active_embedding_model"], MODEL);
    assert_eq!(
        dry["rows"],
        json!({"total": 3, "without_embedding": 1, "other_model": 1, "active_model": 1})
    );
    assert!(dry["pass"].is_null());
    assert_eq!(row_states(&pool, ds).await, (1, 1, 1));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        calls_before,
        "a dry run calls no embedder"
    );
    assert!(reembed_events(&pool, ds).await.is_empty());

    // Someone else's dataset is "not found", and nothing happens.
    let refused = call(
        &state,
        stranger,
        "ml_reembed_dataset",
        json!({"dataset_id": ds.to_string(), "apply": true}),
    )
    .await;
    let message = error_message(&refused);
    assert!(message.to_lowercase().contains("not found"), "{message}");
    assert_eq!(row_states(&pool, ds).await, (1, 1, 1));
    assert_eq!(calls.load(Ordering::SeqCst), calls_before);

    // An unreadable scope is an error, not a default.
    let bad = call(
        &state,
        owner,
        "ml_reembed_dataset",
        json!({"dataset_id": ds.to_string(), "scope": "everything", "apply": true}),
    )
    .await;
    assert!(error_message(&bad).contains("scope must be"), "{bad:?}");
    assert_eq!(row_states(&pool, ds).await, (1, 1, 1));

    // The owner applies: both stale rows are re-embedded, and it is recorded.
    let applied = text_json(
        &call(
            &state,
            owner,
            "ml_reembed_dataset",
            json!({"dataset_id": ds.to_string(), "apply": true}),
        )
        .await,
    );
    assert_eq!(applied["dry_run"], false, "{applied}");
    assert_eq!(applied["pass"]["re_embedded"], 2);
    assert_eq!(applied["pass"]["failed"], 0);
    assert_eq!(applied["pass"]["done"], true);
    assert_eq!(
        applied["rows"],
        json!({"total": 3, "without_embedding": 0, "other_model": 0, "active_model": 3})
    );
    assert_eq!(row_states(&pool, ds).await, (0, 0, 3));
    assert_eq!(
        calls.load(Ordering::SeqCst),
        calls_before + 2,
        "one embedder call per stale row"
    );
    let events = reembed_events(&pool, ds).await;
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, Some(owner));
    assert_eq!(events[0].1["re_embedded"], 2);
    assert_eq!(events[0].1["scope"], "stale");

    // A full pass over an already-consistent dataset rewrites nothing and
    // records nothing.
    let all = text_json(
        &call(
            &state,
            owner,
            "ml_reembed_dataset",
            json!({"dataset_id": ds.to_string(), "scope": "all", "apply": true}),
        )
        .await,
    );
    assert_eq!(all["pass"]["processed"], 3, "{all}");
    assert_eq!(all["pass"]["re_embedded"], 0);
    assert_eq!(all["pass"]["unchanged"], 3);
    assert_eq!(reembed_events(&pool, ds).await.len(), 1);
}
