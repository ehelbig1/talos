//! Migration `20260926170000` scrubs decrypted actor memory that releases
//! before #960 persisted in plaintext: `__actor_context__` in
//! `workflow_executions[_archive].input_data`, and the same object inside
//! truncated `node_input` previews in `execution_events.log_message`.
//!
//! The migration's own SQL is replayed against fixtures that reproduce each
//! stored shape, beside a CONTROL for every guard the statements carry: a row
//! without the key, a non-object `input_data` whose `?` would match, a preview
//! that names the key as a string, and a non-preview event. It also pins that
//! a re-run rewrites nothing (`xmin` unchanged), so a later re-application —
//! or an operator running it by hand — cannot churn rows.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

const MIGRATION: &str =
    include_str!("../../migrations/20260926170000_scrub_persisted_actor_context.sql");

const MARKER: &str = r#""__actor_context__":"[scrubbed: decrypted actor memory is not kept in input previews]"...(truncated)"#;

struct Fixture {
    user: Uuid,
    workflow: Uuid,
    actor: Uuid,
}

async fn fixture(pool: &PgPool) -> Fixture {
    let user = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash) VALUES ($1, $2, 'x')")
        .bind(user)
        .bind(format!("scrub-{user}@example.test"))
        .execute(pool)
        .await
        .unwrap();
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, 'scrub-actor')")
        .bind(actor)
        .bind(user)
        .execute(pool)
        .await
        .unwrap();
    let workflow = common::create_test_workflow(pool, user, "scrub-wf").await;
    Fixture {
        user,
        workflow,
        actor,
    }
}

async fn live_execution(pool: &PgPool, f: &Fixture, input: Value) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, actor_id, status, started_at, completed_at, input_data) \
         VALUES ($1, $2, $3, $4, 'completed', NOW() - interval '1 day', NOW() - interval '1 day', $5)",
    )
    .bind(id)
    .bind(f.workflow)
    .bind(f.user)
    .bind(f.actor)
    .bind(input)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn archived_execution(pool: &PgPool, f: &Fixture, input: Value) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions_archive \
             (id, workflow_id, user_id, actor_id, status, started_at, completed_at, archived_at, input_data) \
         VALUES ($1, $2, $3, $4, 'completed', NOW() - interval '40 days', NOW() - interval '40 days', NOW(), $5)",
    )
    .bind(id)
    .bind(f.workflow)
    .bind(f.user)
    .bind(f.actor)
    .bind(input)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn event(pool: &PgPool, execution: Uuid, event_type: &str, message: &str) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO execution_events (execution_id, event_type, status, log_message) \
         VALUES ($1, $2, 'Input', $3) RETURNING id",
    )
    .bind(execution)
    .bind(event_type)
    .bind(message)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn input_of(pool: &PgPool, table: &str, id: Uuid) -> (Value, String) {
    sqlx::query_as(&format!(
        "SELECT input_data, xmin::text FROM {table} WHERE id = $1"
    ))
    .bind(id)
    .fetch_one(pool)
    .await
    .unwrap()
}

async fn message_of(pool: &PgPool, id: Uuid) -> (String, String) {
    sqlx::query_as("SELECT log_message, xmin::text FROM execution_events WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

fn actor_context() -> Value {
    json!({
        "actor_id": "a",
        "memories": [{"key": "daily_brief/latest", "value": "private — note"}]
    })
}

#[tokio::test]
async fn the_scrub_removes_decrypted_actor_memory_and_nothing_else() {
    let (pool, _db) = common::isolated_db_pool().await;
    let f = fixture(&pool).await;

    // input_data: the key is removed, every other key survives verbatim.
    let keyed_input = json!({
        "SELF": "x",
        "__actor_context__": actor_context(),
        "__accumulated__": {"fetch": {"count": 0}},
        "payload": {"q": "ünïcode"}
    });
    let mut expected_input = keyed_input.clone();
    expected_input
        .as_object_mut()
        .unwrap()
        .remove("__actor_context__");
    let live_keyed = live_execution(&pool, &f, keyed_input.clone()).await;
    let archived_keyed = archived_execution(&pool, &f, keyed_input).await;

    // Controls: no key; and a non-object whose `?` WOULD match (`?` tests a
    // top-level string element of an array), which `-` would then rewrite.
    let live_plain = live_execution(&pool, &f, json!({"SELF": "x"})).await;
    let archived_array = archived_execution(&pool, &f, json!(["__actor_context__", "other"])).await;

    // Previews: truncated text. A multi-byte character before the key proves
    // the cut counts characters, not bytes.
    let prefix = r#"{"MAX":1,"NOTE":"café — ok","__accumulated__":{"a":1},"#;
    let keyed_preview = format!(
        "{prefix}\"__actor_context__\":{{\"actor_id\":\"a\",\"memories\":[{{\"key\":\"k\",\"value\":\"secret\"}}...(truncated)"
    );
    let preview = event(&pool, live_keyed, "node_input", &keyed_preview).await;
    // Controls: a preview naming the key as a STRING (not the decrypted
    // object), an unkeyed preview, and a non-preview event carrying the text.
    let string_mention = r#"{"hint":"see \"__actor_context__\":\"docs\""}"#;
    let preview_string = event(&pool, live_keyed, "node_input", string_mention).await;
    let preview_plain = event(&pool, live_keyed, "node_input", r#"{"MAX":1}"#).await;
    let other_type = event(&pool, live_keyed, "node_completed", &keyed_preview).await;

    let before_plain = input_of(&pool, "workflow_executions", live_plain).await;
    let before_array = input_of(&pool, "workflow_executions_archive", archived_array).await;
    let before_events = [
        message_of(&pool, preview_string).await,
        message_of(&pool, preview_plain).await,
        message_of(&pool, other_type).await,
    ];

    sqlx::raw_sql(MIGRATION).execute(&pool).await.unwrap();

    assert_eq!(
        input_of(&pool, "workflow_executions", live_keyed).await.0,
        expected_input,
        "live: only __actor_context__ is removed"
    );
    assert_eq!(
        input_of(&pool, "workflow_executions_archive", archived_keyed)
            .await
            .0,
        expected_input,
        "archive: only __actor_context__ is removed"
    );
    assert_eq!(
        message_of(&pool, preview).await.0,
        format!("{prefix}{MARKER}"),
        "preview: cut where the object starts, marker appended"
    );

    // Every control is byte-identical AND unwritten (same xmin).
    assert_eq!(
        input_of(&pool, "workflow_executions", live_plain).await,
        before_plain
    );
    assert_eq!(
        input_of(&pool, "workflow_executions_archive", archived_array).await,
        before_array,
        "a non-object input_data must not be touched"
    );
    let after_events = [
        message_of(&pool, preview_string).await,
        message_of(&pool, preview_plain).await,
        message_of(&pool, other_type).await,
    ];
    assert_eq!(after_events, before_events);

    // Nothing decrypted is left in any of the three columns.
    let remaining: i64 = sqlx::query_scalar(
        "SELECT (SELECT count(*) FROM workflow_executions WHERE input_data ? '__actor_context__') \
              + (SELECT count(*) FROM workflow_executions_archive \
                  WHERE jsonb_typeof(input_data) = 'object' AND input_data ? '__actor_context__') \
              + (SELECT count(*) FROM execution_events \
                  WHERE event_type = 'node_input' AND log_message LIKE '%\"memories\"%')",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(remaining, 0);

    // Idempotent: a re-run matches nothing, so no row gets a new version.
    let scrubbed = (
        input_of(&pool, "workflow_executions", live_keyed).await,
        input_of(&pool, "workflow_executions_archive", archived_keyed).await,
        message_of(&pool, preview).await,
    );
    sqlx::raw_sql(MIGRATION).execute(&pool).await.unwrap();
    assert_eq!(
        (
            input_of(&pool, "workflow_executions", live_keyed).await,
            input_of(&pool, "workflow_executions_archive", archived_keyed).await,
            message_of(&pool, preview).await,
        ),
        scrubbed,
        "a re-run must not rewrite a scrubbed row"
    );
}
