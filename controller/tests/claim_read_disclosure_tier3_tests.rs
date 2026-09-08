//! The five highest-ranked CLAIM sites the read inventory still carried.
//!
//! `docs/swallowed-reads-inventory.md` (package 23, rebuilt and re-measured by
//! #776) closes with 52 unrepaired `claim` sites — reads whose default becomes
//! a count, a list or a verdict that a caller acts on. This binary drives the
//! five it ranks highest through the REAL MCP dispatch over a real `McpState`,
//! with each read made to fail deterministically by removing the relation it
//! names (package 22's mechanism: a statement that cannot run is the cheapest
//! reproducible database failure there is).
//!
//! The sites, and what the default USED to say:
//!
//!  1. `get_workflow_audit_trail` — two `.unwrap_or_default()` history reads,
//!     on a tool NAMED for auditability. A failed version read removed every
//!     `version_published` event ("never published"); a failed execution read
//!     removed every `execution_triggered` event ("never ran"); and `count` /
//!     `event_count` reported the shortened list as the total. The execution
//!     half has form: `list_executions_for_audit` carries a comment recording
//!     that this same swallow once hid a query naming a column that does not
//!     exist, so the trail returned ZERO execution events for every workflow
//!     on the platform. The QUERY was fixed in May 2026; the SWALLOW was left.
//!  2. `get_execution_lineage` — a failed ROOT lookup substituted the
//!     execution's own id, the tree query then matched `id = $1` and came back
//!     NON-empty, so the degraded-tree flag stayed false and the response
//!     rendered the standalone-run claim `lineage_note` exists to remove.
//!  3. `watch_execution` — `events: [], events_count: 0` on a failed read,
//!     beside a `current_status` that WAS measured, on the tool an operator
//!     polls during an incident.
//!  4. `list_module_catalog` — a failed visibility read made every entry read
//!     `needs_install`, and with `installed_only: true` the whole listing
//!     rendered as `[]`.
//!  5. `ml_get_model_card` — `has_pending_disagreements: false`, i.e. "no human
//!     corrections are waiting", immediately before a promotion decision.
//!
//! Every test carries its CONTROL in the same run, because "the tool returned
//! something unusual" is not evidence unless the healthy shape is pinned
//! beside it: the whole contract is that a healthy response stays
//! byte-identical (`Readings::attach` adds nothing when nothing failed) and
//! only a degraded one changes.
//!
//! The database is a per-test `CREATE DATABASE … TEMPLATE` clone
//! (`common::isolated_db_pool`), so dropping a relation here cannot reach any
//! other test or the developer's stack.

#[path = "common/mod.rs"]
mod common;
// The real `McpState` + response helpers, one home (2026-09-08).
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
    .bind(format!("p29-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, status, is_enabled) \
         VALUES ($1, $2, 'p29-trail', 'test:p29', '{\"nodes\":[],\"edges\":[]}', 'active', true)",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

/// `workflow_executions.actor_id` is NOT NULL and the BEFORE-INSERT trigger
/// only stamps a DEFAULT actor when the user has one, so a seed that omits it
/// dies on the constraint — and a control that dies on a constraint is a test
/// that proves nothing (CLAUDE.md records exactly this trap from the
/// archived-dispatch work).
async fn seed_actor(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(id)
        .bind(user_id)
        .bind(format!("p29-actor-{}", id.simple()))
        .execute(pool)
        .await
        .expect("seed actor");
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

async fn seed_version(pool: &sqlx::PgPool, wf_id: Uuid, user_id: Uuid) {
    sqlx::query(
        "INSERT INTO workflow_versions \
             (id, workflow_id, published_by, version_number, graph_json, is_active, published_at) \
         VALUES ($1, $2, $3, 1, '{\"nodes\":[],\"edges\":[]}'::jsonb, true, NOW())",
    )
    .bind(Uuid::new_v4())
    .bind(wf_id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed workflow version");
}

/// Every `event_type` present in an audit-trail response, in order.
fn event_types(body: &Value) -> Vec<String> {
    body.get("events")
        .and_then(|e| e.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|e| e.get("event_type").and_then(|t| t.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
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

// ───────────────────────────────────────────────────────────────────────────
// 1. `get_workflow_audit_trail` — a missing class of event is not an absence
//    of that class of event.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_version_history_is_not_a_workflow_that_was_never_published() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id).await;
    let actor_id = seed_actor(&pool, user_id).await;
    seed_version(&pool, wf_id, user_id).await;
    seed_execution(&pool, wf_id, user_id, actor_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "workflow_id": wf_id.to_string() });

    // CONTROL: a healthy trail carries BOTH classes of event and NO disclosure
    // — `Readings::attach` is a no-op when nothing failed, which is what keeps
    // the healthy response byte-identical to the pre-fix one.
    let ok = controller::mcp::analytics::dispatch(
        "get_workflow_audit_trail",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_workflow_audit_trail is dispatched");
    let healthy = text_json(&ok);
    let kinds = event_types(&healthy);
    assert!(
        kinds.iter().any(|k| k == "version_published"),
        "control must see the published version: {healthy}"
    );
    assert!(
        kinds.iter().any(|k| k == "execution_triggered"),
        "control must see the execution: {healthy}"
    );
    assert!(
        healthy.get("measurement").is_none(),
        "a healthy trail must carry no disclosure at all: {healthy}"
    );
    assert!(
        healthy.get("events_incomplete").is_none(),
        "a healthy trail must not be flagged partial: {healthy}"
    );

    // The version-history read now cannot run.
    sqlx::query("DROP TABLE workflow_versions CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the version read names");

    let degraded = controller::mcp::analytics::dispatch(
        "get_workflow_audit_trail",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_workflow_audit_trail is dispatched");
    let body = text_json(&degraded);
    let kinds = event_types(&body);
    assert!(
        !kinds.iter().any(|k| k == "version_published"),
        "the version events genuinely cannot be read: {body}"
    );
    // …and the response says so, by name, rather than reading as a workflow
    // that was never published.
    assert!(
        not_measured(&body).contains(&"events.version_published".to_string()),
        "the failed history must be named: {body}"
    );
    assert!(
        not_measured(&body).contains(&"event_count".to_string()),
        "a short count is the same defect as a short list: {body}"
    );
    let flag = body
        .get("events_incomplete")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        flag.contains("NOT evidence that it never happened"),
        "the trail must refuse the absence reading in words: {body}"
    );
    // The execution half was NOT affected — a per-read disclosure, not a
    // whole-report one.
    assert!(
        kinds.iter().any(|k| k == "execution_triggered"),
        "the other history still reads: {body}"
    );
    assert!(
        !not_measured(&body).contains(&"events.execution_triggered".to_string()),
        "a read that answered must not be disclosed as failed: {body}"
    );
}

#[tokio::test]
async fn an_unreadable_execution_history_is_not_a_workflow_that_never_ran() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id).await;
    let actor_id = seed_actor(&pool, user_id).await;
    seed_version(&pool, wf_id, user_id).await;
    seed_execution(&pool, wf_id, user_id, actor_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "workflow_id": wf_id.to_string() });

    // CONTROL, in the same run: the execution event is really there.
    let ok = controller::mcp::analytics::dispatch(
        "get_workflow_audit_trail",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("dispatched");
    let healthy = text_json(&ok);
    assert!(
        event_types(&healthy)
            .iter()
            .any(|k| k == "execution_triggered"),
        "control: {healthy}"
    );
    let healthy_count = healthy.get("event_count").and_then(|v| v.as_u64());
    assert_eq!(healthy_count, Some(event_types(&healthy).len() as u64));

    // `list_executions_for_audit` selects `provenance->>'trigger_type'`; drop
    // the column and the statement cannot run. Deliberately a COLUMN and not
    // the table: it leaves the workflow row (and therefore the ownership
    // check above this read) untouched, so the failure is isolated to the one
    // read under test.
    sqlx::query("ALTER TABLE workflow_executions DROP COLUMN provenance CASCADE")
        .execute(&pool)
        .await
        .expect("drop the column the execution read names");

    let degraded = controller::mcp::analytics::dispatch(
        "get_workflow_audit_trail",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("dispatched");
    let body = text_json(&degraded);
    assert!(
        !event_types(&body)
            .iter()
            .any(|k| k == "execution_triggered"),
        "the execution events genuinely cannot be read: {body}"
    );
    assert!(
        not_measured(&body).contains(&"events.execution_triggered".to_string()),
        "the failed history must be named: {body}"
    );
    assert!(
        body.get("events_incomplete").is_some(),
        "a partial trail must say it is partial: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 2. `get_execution_lineage` — an unreadable ROOT is not a root of one.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unreadable_lineage_root_is_not_rendered_as_the_execution_itself() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let exec_id = seed_execution(&pool, wf_id, user_id, actor_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "execution_id": exec_id.to_string() });

    // CONTROL: a genuinely standalone execution IS its own root, and that must
    // still be sayable.
    let ok = controller::mcp::executions::dispatch(
        "get_execution_lineage",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_lineage is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy.get("root_execution_id").and_then(|v| v.as_str()),
        Some(exec_id.to_string().as_str()),
        "control: a readable root renders the id: {healthy}"
    );
    assert!(
        !healthy
            .get("note")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .contains("ROOT could not be read"),
        "control must not claim a failure: {healthy}"
    );

    // The lineage columns are gone: `get_execution_lineage_root` cannot run.
    // `lookup_execution_base` reads none of them, so the anchor still
    // resolves and the handler reaches the root lookup — which is exactly the
    // shape the defect needed.
    sqlx::query("ALTER TABLE workflow_executions DROP COLUMN root_execution_id CASCADE")
        .execute(&pool)
        .await
        .expect("drop the lineage root column");

    let degraded = controller::mcp::executions::dispatch(
        "get_execution_lineage",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_lineage is dispatched");
    let body = text_json(&degraded);
    assert!(
        body.get("root_execution_id")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "an unreadable root must be null, never the anchor's own id: {body}"
    );
    let note = body
        .get("note")
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(note.contains("ROOT could not be read"), "{note}");
    assert!(
        !note.contains("no parent or child EXECUTION rows"),
        "the pre-fix determinate negative must be gone: {note}"
    );
    assert!(
        note.contains("NOT a standalone run"),
        "the note must refuse the standalone reading explicitly: {note}"
    );
    // Dropping the column breaks BOTH lineage reads, so this run also
    // exercises the combined arm. The narrower shape the defect actually took
    // in production — root read fails, tree read SUCCEEDS because it matches
    // `id = $1` — is not separable by relation (both statements name the same
    // two columns of the same two tables), so it is pinned by
    // `executions::lineage_note_tests::an_unreadable_root_never_claims_the_execution_has_no_parent`
    // instead. Stated rather than implied: this binary covers the wiring, the
    // unit test covers the arm.
    assert!(note.contains("tree read failed as well"), "{note}");
}

// ───────────────────────────────────────────────────────────────────────────
// 3. `watch_execution` — no events is not no progress.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn watch_execution_nulls_the_event_list_it_could_not_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id).await;
    let actor_id = seed_actor(&pool, user_id).await;
    let exec_id = seed_execution(&pool, wf_id, user_id, actor_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "execution_id": exec_id.to_string() });

    // CONTROL: an execution that genuinely emitted no events still reports a
    // measured zero, with no disclosure block.
    let ok = controller::mcp::executions::dispatch(
        "watch_execution",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("watch_execution is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy.get("events_count").and_then(|v| v.as_u64()),
        Some(0),
        "a real zero must stay sayable: {healthy}"
    );
    assert!(
        healthy.get("events").and_then(|v| v.as_array()).is_some(),
        "a healthy poll returns a list: {healthy}"
    );
    assert!(
        healthy.get("measurement").is_none(),
        "a healthy poll carries no disclosure: {healthy}"
    );

    sqlx::query("DROP TABLE execution_events CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the events read names");

    let degraded = controller::mcp::executions::dispatch(
        "watch_execution",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("watch_execution is dispatched");
    let body = text_json(&degraded);
    assert!(
        body.get("events_count")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "a poller reads 0 as 'no progress'; it must be null: {body}"
    );
    assert!(
        body.get("events").map(|v| v.is_null()).unwrap_or(false),
        "an empty list is a claim: {body}"
    );
    assert!(
        not_measured(&body).contains(&"events".to_string()),
        "the failed read must be named: {body}"
    );
    // The half that WAS measured is untouched — this is a per-field
    // disclosure, not a refusal.
    assert_eq!(
        body.get("current_status").and_then(|v| v.as_str()),
        Some("completed"),
        "the status came from the execution row and still stands: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 4. `list_module_catalog` — "needs_install" must not be a database failure.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_module_catalog_refuses_rather_than_telling_you_to_install_everything() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({});

    // CONTROL: the listing works and reports a catalog.
    let ok = controller::mcp::modules::dispatch(
        "list_module_catalog",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("list_module_catalog is dispatched");
    assert!(ok.error.is_none(), "control must succeed: {:?}", ok.error);
    let healthy = text_json(&ok);
    assert!(
        healthy.get("catalog").is_some(),
        "control returns a catalog: {healthy}"
    );

    // `list_visible_module_ids` projects `name`; without it the statement
    // cannot run. A COLUMN rather than the table, so the catalog walk itself
    // is untouched and the failure is isolated to the visibility read.
    sqlx::query("ALTER TABLE modules DROP COLUMN name CASCADE")
        .execute(&pool)
        .await
        .expect("drop the column the visibility read names");

    let degraded = controller::mcp::modules::dispatch(
        "list_module_catalog",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("list_module_catalog is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("NOT a statement that you have installed none of them"),
        "a failed visibility read must refuse, and must refuse the install reading: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 5. `ml_get_model_card` — a promotion clearance must be earned, not defaulted.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_model_card_never_defaults_the_pending_disagreement_verdict_to_false() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let model_name = format!("p29-model-{}", Uuid::new_v4().simple());
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, config_json, lifecycle_state) \
         VALUES ($1, $2, $3, 'classification', '{}'::jsonb, 'shadow')",
    )
    .bind(Uuid::new_v4())
    .bind(user_id)
    .bind(&model_name)
    .execute(&pool)
    .await
    .expect("seed model");

    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "model_name": model_name });

    // CONTROL: a model with no disagreements really does report `false`, and
    // the card carries no disclosure.
    let ok = controller::mcp::ml::dispatch(
        "ml_get_model_card",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("ml_get_model_card is dispatched");
    let healthy = text_json(&ok);
    assert_eq!(
        healthy
            .get("has_pending_disagreements")
            .and_then(|v| v.as_bool()),
        Some(false),
        "a measured 'nothing is waiting' must stay sayable: {healthy}"
    );
    assert!(
        healthy.get("measurement").is_none(),
        "a healthy card carries no disclosure: {healthy}"
    );

    sqlx::query("DROP TABLE ml_disagreements CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the disagreement read names");

    let degraded = controller::mcp::ml::dispatch(
        "ml_get_model_card",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("ml_get_model_card is dispatched");
    let body = text_json(&degraded);
    assert!(
        body.get("has_pending_disagreements")
            .map(|v| v.is_null())
            .unwrap_or(false),
        "`false` here is a promotion clearance; an unreadable check must be null: {body}"
    );
    assert!(
        not_measured(&body).contains(&"has_pending_disagreements".to_string()),
        "the failed check must be named: {body}"
    );
}

/// The card's ENTITY lookup, split in the same change: a registry read that
/// failed is not a model that is absent.
#[tokio::test]
async fn a_model_card_does_not_report_an_unreadable_registry_as_a_missing_model() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;

    // CONTROL: a model that genuinely is not there keeps the exact pre-fix
    // wording, so the not-found answer is not weakened by the split.
    let absent = controller::mcp::ml::dispatch(
        "ml_get_model_card",
        Some(serde_json::json!(1)),
        &serde_json::json!({ "model_name": "p29-no-such-model" }),
        &state,
        agent(user_id),
    )
    .await
    .expect("dispatched");
    assert_eq!(error_message(&absent), "Model not found");

    sqlx::query("ALTER TABLE ml_models DROP COLUMN lifecycle_state CASCADE")
        .execute(&pool)
        .await
        .expect("drop a column the registry read projects");

    let degraded = controller::mcp::ml::dispatch(
        "ml_get_model_card",
        Some(serde_json::json!(2)),
        &serde_json::json!({ "model_name": "p29-no-such-model" }),
        &state,
        agent(user_id),
    )
    .await
    .expect("dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("NOT a statement that the model is absent"),
        "a failed registry read must not read as a deletion: {msg}"
    );
}
