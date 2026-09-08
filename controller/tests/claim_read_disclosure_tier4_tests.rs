//! The next tier of the read inventory's CLAIM sites — nine of the ten
//! repaired on 2026-09-08, driven through the REAL production surface.
//!
//! `docs/swallowed-reads-inventory.md`, re-measured on this tree before any
//! edit, carried **46** unrepaired `claim` sites: reads whose default becomes a
//! count, a list, a verdict or a "not found" a caller acts on. This binary
//! covers the ten ranked highest by BLAST RADIUS — a decision above a count an
//! operator pages on, above a list that feeds a next step, above a label — and
//! it makes each read fail deterministically by removing the relation it names
//! (package 22's mechanism: a statement that cannot run is the cheapest
//! reproducible database failure there is).
//!
//! Every test carries its CONTROL in the same run, because "the tool answered
//! unusually" is not evidence unless the healthy shape is pinned beside it: the
//! contract is that a healthy response stays byte-identical and only a degraded
//! one changes. Where the pre-fix path ALSO refused — `get_agent_card` on an
//! absent actor, `suggest_actor_for_task` for a user with none — the control is
//! the half that matters, because "the tool refused" proves nothing when the
//! pre-fix path refused too, just with the wrong diagnosis.
//!
//! # What this binary does NOT cover, stated rather than implied
//!
//! * `talos-api`'s `me` 2FA read is covered by a GraphQL execution below, but
//!   NOT by a relation drop: `AuthService::get_user` projects `totp_enabled`
//!   from the same `users` row, so dropping the table or the column breaks the
//!   read ABOVE the one under test and the resolver refuses for the wrong
//!   reason. The failure is injected as a POOL that cannot connect, which is
//!   the shape this defect actually takes in production.
//! * `handle_bulk_tag_workflows`'s SECOND read
//!   (`count_owned_workflows_in_set`) cannot be isolated at all: it queries the
//!   same `workflows` relation as the write above it, so any drop refuses at
//!   the write. Only the write half is driven here; the breakdown's `null`
//!   rendering is a pure consequence of `Readings::record` and is not pinned.
//! * `handle_list_module_catalog`'s disk walk has no relation to drop — it is
//!   `std::fs::read_dir` over a baked image directory, and in a test
//!   environment the handler takes its `else` stub branch entirely. Its fix
//!   (a failure that is no longer MEMOIZED) is argued at the site and pinned by
//!   a source assertion at the bottom of this file, which is weaker than a
//!   round trip and is said so.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::Value;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("p31-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_actor(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user_id)
        .bind(format!("p31-actor-{}", id.simple()))
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

async fn seed_workflow(pool: &sqlx::PgPool, user_id: Uuid, actor_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows \
             (id, user_id, actor_id, name, module_uri, graph_json, status, is_enabled, capabilities) \
         VALUES ($1, $2, $3, $4, 'test:p31', \
                 '{\"nodes\":[{\"id\":\"n1\",\"type\":\"module\",\"data\":{\"label\":\"first\"}}],\"edges\":[]}', \
                 'active', true, ARRAY['p31-cap'])",
    )
    .bind(id)
    .bind(user_id)
    .bind(actor_id)
    .bind(format!("p31-wf-{}", id.simple()))
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_execution(pool: &sqlx::PgPool, wf_id: Uuid, user_id: Uuid, actor_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, actor_id, status, started_at, completed_at) \
         VALUES ($1, $2, $3, $4, 'completed', NOW() - INTERVAL '1 hour', NOW())",
    )
    .bind(id)
    .bind(wf_id)
    .bind(user_id)
    .bind(actor_id)
    .execute(pool)
    .await
    .expect("seed execution");
    id
}

/// `minutes_ago` is load-bearing rather than cosmetic: the waterfall renderer
/// divides by the run's total span, and a node whose start equals that span
/// makes `bar_len.clamp(1, chart_width - bar_start)` take `min > max`. A
/// fixture with coincident timestamps therefore panics the handler on the
/// CONTROL path — see AGENT_NOTES for the pre-existing defect that is, which
/// this package records rather than fixes.
async fn seed_event(
    pool: &sqlx::PgPool,
    exec_id: Uuid,
    event_type: &str,
    node: Uuid,
    minutes_ago: i32,
) {
    sqlx::query(
        "INSERT INTO execution_events \
             (id, execution_id, event_type, node_id, status, created_at) \
         VALUES ($1, $2, $3, $4, 'Completed', NOW() - ($5::int * INTERVAL '1 minute'))",
    )
    .bind(Uuid::new_v4())
    .bind(exec_id)
    .bind(event_type)
    .bind(node)
    .bind(minutes_ago)
    .execute(pool)
    .await
    .expect("seed execution event");
}

fn not_measured(body: &Value) -> Vec<String> {
    body.pointer("/measurement/not_measured")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str())
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

async fn drop_relation(pool: &sqlx::PgPool, relation: &str) {
    sqlx::query(&format!("DROP TABLE IF EXISTS {relation} CASCADE"))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("drop {relation}: {e}"));
}

/// The text body of an `mcp_text` response, for the two handlers that render a
/// plain-text report rather than JSON.
fn text_body(resp: &controller::mcp::types::JsonRpcResponse) -> String {
    serde_json::to_value(resp)
        .ok()
        .and_then(|v| {
            v.pointer("/result/content/0/text")
                .and_then(|t| t.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default()
}

// ───────────────────────────────────────────────────────────────────────────
// 1. `bulk_tag_workflows` — a failed WRITE is not "they were already tagged".
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unwritable_tag_is_not_a_workflow_that_already_carried_it() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let wf_id = seed_workflow(&pool, user_id, Some(actor_id)).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({
        "workflow_ids": [wf_id.to_string()],
        "tag": "p31tag",
    });

    // CONTROL: the healthy path tags exactly one workflow and reports it.
    let ok = controller::mcp::search::dispatch(
        "bulk_tag_workflows",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("bulk_tag_workflows is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy.get("tagged_count").and_then(Value::as_u64),
        Some(1),
        "control: one workflow must actually be tagged: {healthy}"
    );
    assert!(
        healthy.get("measurement").is_none(),
        "a healthy response carries no disclosure: {healthy}"
    );

    drop_relation(&pool, "workflows").await;

    let degraded = controller::mcp::search::dispatch(
        "bulk_tag_workflows",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("bulk_tag_workflows is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("NO workflow was tagged"),
        "an unwritable tag must REFUSE. Pre-fix this rendered \
         tagged_count: 0 with already_tagged_count equal to the owned count, \
         i.e. 'they already had it'. Got: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 2 + 3. `get_agent_card` — an unreadable actor is not an absent one, and a
//        card whose capabilities could not be read must not be shareable.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_actor_is_not_an_actor_that_does_not_exist() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({
        "actor_id": actor_id.to_string(),
        "base_url": "https://p31.example.com",
    });

    // CONTROL A: a real actor renders a card.
    let ok = controller::mcp::platform::dispatch(
        "get_agent_card",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_agent_card is dispatched");
    let healthy = text_json(&ok);
    assert!(
        healthy.pointer("/agent_card/actor_id").is_some(),
        "control: a real actor must render a card: {healthy}"
    );

    // CONTROL B: a genuinely absent actor keeps the pre-fix wording, so the
    // fix cannot pass by refusing everything.
    let absent = controller::mcp::platform::dispatch(
        "get_agent_card",
        Some(serde_json::json!(2)),
        &serde_json::json!({
            "actor_id": Uuid::new_v4().to_string(),
            "base_url": "https://p31.example.com",
        }),
        &state,
        agent(user_id),
    )
    .await
    .expect("get_agent_card is dispatched");
    assert!(
        error_message(&absent).contains("Actor not found or access denied"),
        "control: an actor that really is absent must keep its wording: {}",
        error_message(&absent)
    );

    drop_relation(&pool, "actors").await;

    let degraded = controller::mcp::platform::dispatch(
        "get_agent_card",
        Some(serde_json::json!(3)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_agent_card is dispatched");
    let msg = error_message(&degraded);
    assert!(
        !msg.contains("Actor not found or access denied"),
        "an unreadable actor must NOT be reported as absent or unowned — both \
         clauses of that sentence are false while the database is the broken \
         thing. Got: {msg}"
    );
}

#[tokio::test]
async fn an_unreadable_workflow_list_makes_the_agent_card_unshareable() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    seed_workflow(&pool, user_id, Some(actor_id)).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({
        "actor_id": actor_id.to_string(),
        "base_url": "https://p31.example.com",
    });

    // CONTROL: a real published workflow makes a shareable card with no
    // disclosure at all.
    let ok = controller::mcp::platform::dispatch(
        "get_agent_card",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_agent_card is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy.get("shareable").and_then(Value::as_bool),
        Some(true),
        "control: a measured card is shareable: {healthy}"
    );
    assert!(
        healthy
            .pointer("/agent_card/available_workflows")
            .and_then(Value::as_array)
            .is_some_and(|a| !a.is_empty()),
        "control: the workflow must appear on the card: {healthy}"
    );
    assert!(healthy.get("measurement").is_none());

    // `workflows` alone: the ACTOR read above it still answers, so this
    // isolates the capability list.
    drop_relation(&pool, "workflows").await;

    let degraded = controller::mcp::platform::dispatch(
        "get_agent_card",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_agent_card is dispatched");
    let body = text_json(&degraded);
    assert_eq!(
        body.get("shareable").and_then(Value::as_bool),
        Some(false),
        "a card whose capability list could not be read MUST NOT be shareable \
         — pre-fix it shipped `shareable: true` advertising an agent that can \
         do nothing: {body}"
    );
    assert!(
        body.pointer("/agent_card/available_workflows")
            .is_some_and(Value::is_null),
        "the list must be null, NEVER []: {body}"
    );
    assert!(
        not_measured(&body).contains(&"available_workflows".to_string()),
        "and the failure must be named: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 4. `get_execution_comparison_report` — a DB error is not a set of bad ids.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_execution_batch_is_not_a_set_of_wrong_ids() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let wf_id = seed_workflow(&pool, user_id, Some(actor_id)).await;
    let a = seed_execution(&pool, wf_id, user_id, actor_id).await;
    let b = seed_execution(&pool, wf_id, user_id, actor_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({
        "execution_ids": [a.to_string(), b.to_string()],
    });

    // CONTROL: two real executions compare, and an id that really is absent is
    // still reported as not-found — so the fix cannot pass by refusing on any
    // missing row.
    let ok = controller::mcp::executions::dispatch(
        "get_execution_comparison_report",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_comparison_report is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy
            .pointer("/summary/total_compared")
            .and_then(Value::as_u64),
        Some(2),
        "control: both executions must compare: {healthy}"
    );

    let bogus = Uuid::new_v4();
    let mixed = controller::mcp::executions::dispatch(
        "get_execution_comparison_report",
        Some(serde_json::json!(2)),
        &serde_json::json!({ "execution_ids": [a.to_string(), bogus.to_string()] }),
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_comparison_report is dispatched");
    let mixed_body = text_json(&mixed);
    assert!(
        mixed_body
            .pointer("/summary/not_found_ids")
            .and_then(Value::as_array)
            .is_some_and(|a| a.len() == 1),
        "control: a genuinely absent id must still be reported as not found: {mixed_body}"
    );

    drop_relation(&pool, "workflow_executions").await;

    let degraded = controller::mcp::executions::dispatch(
        "get_execution_comparison_report",
        Some(serde_json::json!(3)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_comparison_report is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("NOT a statement that these ids are missing or not yours"),
        "an unreadable batch must refuse, not report every id as \
         not-found-or-unowned. Got: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 5. `get_node_io` — an unreadable graph must not answer about another node.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_graph_does_not_answer_about_a_different_node() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let wf_id = seed_workflow(&pool, user_id, Some(actor_id)).await;
    let exec_id = seed_execution(&pool, wf_id, user_id, actor_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({
        "execution_id": exec_id.to_string(),
        "node_id": "first",
    });

    // CONTROL: with the graph readable the tool answers (null I/O here is a
    // measured answer — no input event was recorded — and that is exactly the
    // answer the degraded path must NOT be able to produce).
    let ok = controller::mcp::executions::dispatch(
        "get_node_io",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_node_io is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy.get("node_id").and_then(Value::as_str),
        Some("first"),
        "control: the tool must answer while the graph is readable: {healthy}"
    );

    // NOT `DROP TABLE workflows` — measured: that also breaks the EXECUTION
    // lookup above this read, so the handler refuses with
    // "Execution not found or access denied" and the test passes on BOTH
    // trees, proving nothing about the graph read. (It did, until the mutation
    // said so.) Dropping the one COLUMN the graph read names leaves every
    // other statement in this handler answering.
    sqlx::query("ALTER TABLE workflows DROP COLUMN graph_json")
        .execute(&pool)
        .await
        .expect("drop graph_json column");

    let degraded = controller::mcp::executions::dispatch(
        "get_node_io",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_node_io is dispatched");
    let msg = error_message(&degraded);
    assert_eq!(
        msg,
        "Database error",
        "an unreadable graph must refuse AS a database error — not resolve the \
         label against an empty map and render null I/O for a DIFFERENT node's \
         uuid, and not refuse for some other reason either: {}",
        serde_json::to_string(&degraded).unwrap_or_default()
    );
    assert!(
        text_json(&degraded).get("node_id").is_none(),
        "and it must not render a body at all: {}",
        serde_json::to_string(&degraded).unwrap_or_default()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 6 + 7. `get_execution_timeline` / `get_execution_waterfall` — an unread
//        event sequence is not an execution that did nothing.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unread_event_sequence_is_disclosed_in_the_timeline() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let wf_id = seed_workflow(&pool, user_id, Some(actor_id)).await;
    let exec_id = seed_execution(&pool, wf_id, user_id, actor_id).await;
    let node = Uuid::new_v4();
    seed_event(&pool, exec_id, "node_started", node, 50).await;
    seed_event(&pool, exec_id, "node_completed", node, 20).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "execution_id": exec_id.to_string() });

    let ok = controller::mcp::executions::dispatch(
        "get_execution_timeline",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_timeline is dispatched");
    let healthy = text_body(&ok);
    assert!(
        healthy.contains("node_started"),
        "control: the seeded events must appear: {healthy}"
    );
    assert!(
        !healthy.contains("NOT MEASURED"),
        "a healthy timeline carries no disclosure: {healthy}"
    );

    drop_relation(&pool, "execution_events").await;

    let degraded = controller::mcp::executions::dispatch(
        "get_execution_timeline",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_timeline is dispatched");
    let body = text_body(&degraded);
    assert!(
        body.contains("NOT MEASURED"),
        "an unread event sequence must say so — an empty `Event Sequence` on a \
         tool called 'timeline' reads as 'nothing happened': {body}"
    );
}

#[tokio::test]
async fn an_unread_event_sequence_is_disclosed_in_the_waterfall() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let wf_id = seed_workflow(&pool, user_id, Some(actor_id)).await;
    let exec_id = seed_execution(&pool, wf_id, user_id, actor_id).await;
    let node = Uuid::new_v4();
    seed_event(&pool, exec_id, "node_started", node, 50).await;
    seed_event(&pool, exec_id, "node_completed", node, 20).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "execution_id": exec_id.to_string() });

    let ok = controller::mcp::executions::dispatch(
        "get_execution_waterfall",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_waterfall is dispatched");
    let healthy = text_body(&ok);
    assert!(
        !healthy.contains("NOT MEASURED"),
        "a healthy waterfall carries no disclosure: {healthy}"
    );

    drop_relation(&pool, "execution_events").await;

    let degraded = controller::mcp::executions::dispatch(
        "get_execution_waterfall",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_waterfall is dispatched");
    let body = text_body(&degraded);
    assert!(
        body.contains("NOT MEASURED"),
        "pre-fix this rendered the literal 'No node timing data available for \
         this execution.' — a determinate negative about a run whose events \
         nobody read: {body}"
    );
    assert!(
        !body.contains("No node timing data available for this execution."),
        "and it must not ALSO carry the pre-fix sentence: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 8. `suggest_actor_for_task` — an unreadable listing is not an instruction
//    to create actors the caller may already have.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_actor_listing_is_not_an_instruction_to_create_one() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    seed_actor(&pool, user_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "task": "summarise the inbox" });

    // CONTROL A: with an actor present the tool answers.
    let ok = controller::mcp::actor::dispatch(
        "suggest_actor_for_task",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("suggest_actor_for_task is dispatched");
    let healthy = text_json(&ok);
    assert!(
        healthy.get("suggestions").is_some(),
        "control: the tool must answer while actors are readable: {healthy}"
    );

    // CONTROL B: a user who genuinely has no actors keeps the pre-fix note, so
    // the fix cannot pass by refusing whenever the list is empty.
    let empty_user = seed_user(&pool).await;
    let empty = controller::mcp::actor::dispatch(
        "suggest_actor_for_task",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(empty_user),
    )
    .await
    .expect("suggest_actor_for_task is dispatched");
    let empty_body = text_json(&empty);
    assert!(
        empty_body
            .get("note")
            .and_then(Value::as_str)
            .is_some_and(|n| n.contains("No active actors found")),
        "control: a real zero must keep its wording: {empty_body}"
    );

    drop_relation(&pool, "actors").await;

    let degraded = controller::mcp::actor::dispatch(
        "suggest_actor_for_task",
        Some(serde_json::json!(3)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("suggest_actor_for_task is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("NOT an instruction to create one"),
        "an unreadable listing must refuse. Pre-fix it answered \
         'No active actors found. Create actors with create_actor first.' — a \
         DIRECTIVE, not merely a wrong count. Got: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 9. `compress_actor_context` — a failed retirement must roll back, not commit
//    the replacements and report `status: "compressed"`.
// ───────────────────────────────────────────────────────────────────────────

/// Register the actor-memory crypto hook. Process-global `OnceLock`, so AT
/// MOST ONE test per binary may call it — this is that test, and it is the
/// only one here that writes `actor_memory`.
async fn register_crypto(pool: &sqlx::PgPool) {
    let sm = std::sync::Arc::new(
        controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"),
    );
    sm.initialize().await.expect("initialize secrets");
    talos_memory::register_memory_crypto_hook(std::sync::Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm),
    ));
}

async fn count_memories(pool: &sqlx::PgPool, actor: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM actor_memory WHERE actor_id = $1")
        .bind(actor)
        .fetch_one(pool)
        .await
        .expect("count actor_memory")
}

#[tokio::test]
async fn a_failed_key_retirement_rolls_back_rather_than_reporting_compressed() {
    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let state = mcp_state(pool.clone()).await;

    for i in 0..3 {
        talos_memory::persist_memory(
            &pool,
            actor_id,
            &format!("p31/key-{i}"),
            &serde_json::json!({ "text": format!("entry {i} with a little body text") }),
            "episodic",
            Some(720.0),
        )
        .await
        .expect("seed actor memory");
    }
    assert_eq!(count_memories(&pool, actor_id).await, 3, "three seeded");

    let args = serde_json::json!({
        "actor_id": actor_id.to_string(),
        "archive_keys": ["p31/key-0", "p31/key-1"],
        "replacement_entries": [{
            "key": "p31/condensed",
            "value": { "text": "the condensed replacement" },
            "memory_type": "episodic",
        }],
    });

    // CONTROL: the healthy path retires the two archive keys and writes the
    // replacement, so the count moves 3 -> 2 (3 - 2 retired + 1 written).
    let ok = controller::mcp::actor::dispatch(
        "compress_actor_context",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("compress_actor_context is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy.get("keys_retired").and_then(Value::as_u64),
        Some(2),
        "control: both archive keys must actually be retired: {healthy}"
    );
    assert_eq!(
        count_memories(&pool, actor_id).await,
        2,
        "control: 3 - 2 + 1"
    );

    // DEGRADED. The failing statement and the write it must not outlive share
    // ONE relation (`actor_memory`), so no relation drop can separate them —
    // dropping the table refuses at the replacement write instead. The failure
    // is injected exactly where it occurs: a BEFORE DELETE trigger, so the
    // measure-and-forget CTE's DELETE raises while the replacement INSERT
    // above it succeeds. That is the state the pre-fix code COMMITTED.
    sqlx::query(
        "CREATE FUNCTION p31_block_delete() RETURNS trigger AS $$          BEGIN RAISE EXCEPTION 'p31: retirement blocked'; END; $$ LANGUAGE plpgsql",
    )
    .execute(&pool)
    .await
    .expect("create trigger fn");
    sqlx::query(
        "CREATE TRIGGER p31_no_delete BEFORE DELETE ON actor_memory          FOR EACH ROW EXECUTE FUNCTION p31_block_delete()",
    )
    .execute(&pool)
    .await
    .expect("create trigger");

    let before = count_memories(&pool, actor_id).await;
    let degraded = controller::mcp::actor::dispatch(
        "compress_actor_context",
        Some(serde_json::json!(2)),
        &serde_json::json!({
            "actor_id": actor_id.to_string(),
            "archive_keys": ["p31/key-2"],
            "replacement_entries": [{
                "key": "p31/condensed-2",
                "value": { "text": "a second replacement that must not survive" },
                "memory_type": "episodic",
            }],
        }),
        &state,
        agent(user_id),
    )
    .await
    .expect("compress_actor_context is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("this actor's memory is unchanged"),
        "a failed retirement must REFUSE. Pre-fix it defaulted to (0, 0) and          fell through to tx.commit(), answering status=compressed with          keys_retired=0. Got: {msg}"
    );

    // Asserted on ROWS, not on the reply: a refusal that arrives after the
    // write is not a rollback, and the whole defect was a COMMIT.
    assert_eq!(
        count_memories(&pool, actor_id).await,
        before,
        "the replacement must NOT have been committed without the retirement —          that committed state is memory GROWING under a response claiming it          shrank"
    );
    let orphan: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM actor_memory WHERE actor_id = $1 AND key = 'p31/condensed-2'",
    )
    .bind(actor_id)
    .fetch_one(&pool)
    .await
    .expect("count orphan replacement");
    assert_eq!(orphan, 0, "the replacement row must have been rolled back");
}

// ───────────────────────────────────────────────────────────────────────────
// 10. `me` — one unreadable column must not report "no 2FA, and verified".
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_two_factor_state_is_not_a_user_without_two_factor() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let secrets = std::sync::Arc::new(
        controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"),
    );
    let auth = std::sync::Arc::new(
        talos_auth::AuthService::new(
            pool.clone(),
            "p31-test-secret-value-long-enough".to_string(),
            10,
            None,
        )
        .expect("auth service"),
    );

    let query = "{ me { id twoFactorEnabled isTwoFactorVerified } }";

    // CONTROL: a healthy TOTP pool answers, and the seeded user has no 2FA.
    let healthy_totp = std::sync::Arc::new(talos_totp_2fa::TotpService::new(
        pool.clone(),
        None,
        secrets.clone(),
    ));
    let schema = async_graphql::Schema::build(
        talos_api::schema::QueryRoot::default(),
        talos_api::schema::MutationRoot::default(),
        talos_api::schema::SubscriptionRoot,
    )
    .data(auth.clone())
    .data(healthy_totp)
    .data(user_id)
    .finish();
    let ok = schema.execute(query).await;
    assert!(
        ok.errors.is_empty(),
        "control: a readable 2FA state must answer: {:?}",
        ok.errors
    );
    let ok_json = ok.data.into_json().expect("json");
    assert_eq!(
        ok_json
            .pointer("/me/twoFactorEnabled")
            .and_then(Value::as_bool),
        Some(false),
        "control: the seeded user has no 2FA: {ok_json}"
    );

    // DEGRADED: the 2FA read cannot be isolated by dropping `users` —
    // `AuthService::get_user` projects `totp_enabled` from the same row and
    // would refuse first — so the failure is injected where it really occurs,
    // in the pool. A lazily-connected pool naming a database that does not
    // exist fails on first use, deterministically and without a timeout.
    let broken = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy(
            "postgres://talos:p31-not-a-password@127.0.0.1:5433/talos_agent31_no_such_database",
        )
        .expect("lazy pool");
    let broken_totp = std::sync::Arc::new(talos_totp_2fa::TotpService::new(broken, None, secrets));
    let schema = async_graphql::Schema::build(
        talos_api::schema::QueryRoot::default(),
        talos_api::schema::MutationRoot::default(),
        talos_api::schema::SubscriptionRoot,
    )
    .data(auth)
    .data(broken_totp)
    .data(user_id)
    .finish();
    let degraded = schema.execute(query).await;
    assert!(
        !degraded.errors.is_empty(),
        "an unreadable 2FA state must REFUSE. Pre-fix it answered \
         twoFactorEnabled=false AND isTwoFactorVerified=true — one unreadable \
         column flipping both security-gating booleans to their permissive \
         reading. Got: {:?}",
        degraded.data
    );
}

// ───────────────────────────────────────────────────────────────────────────
// The catalog walk: a source pin, and it is weaker than a round trip.
// ───────────────────────────────────────────────────────────────────────────

/// `handle_list_module_catalog`'s disk walk has no relation to drop and, in a
/// test environment, no `/app/module-templates` to make unreadable — the
/// handler takes its stub branch. What this pins is the property that made the
/// defect PERMANENT rather than transient: the failure must not be memoized in
/// the process-wide `OnceCell`. `get_or_try_init` leaves the cell uninitialised
/// on `Err`; `get_or_init` could not.
#[test]
fn a_failed_catalog_walk_is_not_cached() {
    let src = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .join("talos-mcp-handlers/src/modules.rs"),
    )
    .expect("read modules.rs");

    assert!(
        src.contains("CATALOG_CACHE\n            .get_or_try_init("),
        "the catalog walk must use `get_or_try_init`, so a failed walk leaves \
         the cell UNINITIALISED and the next call retries. With `get_or_init` \
         plus a default, one panicked blocking task made every later call in \
         the pod's lifetime report an empty catalog."
    );
    assert!(
        src.contains("std::fs::read_dir(&catalog_dir_owned).map_err("),
        "and the inner io::Error must PROPAGATE rather than yielding an empty \
         `items` — an EACCES on the baked template directory produced the same \
         cached empty catalog through `if let Ok(read_dir) = …`"
    );
}
