//! Every `query_paginated` run is recorded (security review 2026-10-14, D-5):
//! the caller, the SHA-256 of the statement — never its text — the page and
//! what came of it, in `admin_event_log`. Since 2026-10-15 (D2-4) that
//! includes a statement the gate refused and one that failed.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::sync::Arc;
use talos_advanced_repository::AdminQueryOutcome;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool, user: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@admin-query.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn records(pool: &sqlx::PgPool, user: Uuid) -> Vec<serde_json::Value> {
    sqlx::query_scalar(
        "SELECT details FROM admin_event_log \
         WHERE event_type = 'admin_query_paginated' AND user_id = $1 ORDER BY created_at",
    )
    .bind(user)
    .fetch_all(pool)
    .await
    .expect("the records")
}

#[tokio::test]
async fn a_run_is_recorded_by_the_statements_hash_not_its_text() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = Uuid::new_v4();
    seed_user(&pool, admin).await;
    let repo = talos_advanced_repository::AdvancedRepository::new(pool.clone());
    let statement = "SELECT id FROM workflows WHERE name = 'a literal worth hiding'";
    repo.record_admin_query(admin, statement, 2, AdminQueryOutcome::Returned(7))
        .await
        .expect("record");

    let (user_id, details): (Option<Uuid>, serde_json::Value) = sqlx::query_as(
        "SELECT user_id, details FROM admin_event_log \
         WHERE event_type = 'admin_query_paginated' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .expect("the record");
    assert_eq!(user_id, Some(admin));
    assert_eq!(
        details["statement_sha256"],
        talos_text_util::sha256_hex(statement)
    );
    assert_eq!(details["page"], 2);
    assert_eq!(details["row_count"], 7);
    assert_eq!(details["outcome"], "returned");
    assert!(
        !details.to_string().contains("literal worth hiding"),
        "the statement's text is not stored: {details}"
    );
}

/// Driven through the MCP dispatcher as a platform admin: a statement the
/// gate refuses and a statement that fails each leave one row, by hash
/// (2026-10-15, D2-4). Until then only a statement that returned rows did.
#[tokio::test]
async fn a_refused_or_failed_statement_is_recorded_too() {
    let (pool, _db) = common::isolated_db_pool().await;
    let admin = Uuid::new_v4();
    seed_user(&pool, admin).await;
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(admin)
        .execute(&pool)
        .await
        .unwrap();
    let state = mcp_common::mcp_state(pool.clone()).await;
    let agent = Arc::new(controller::mcp::auth::AgentIdentity {
        agent_id: Uuid::new_v4(),
        name: "admin-query-probe".to_string(),
        role_name: "probe".to_string(),
        allowed_capabilities: vec!["*".to_string()],
        user_id: admin,
    });
    let run = |query: &'static str| {
        let state = &state;
        let agent = agent.clone();
        async move {
            controller::mcp::advanced::dispatch(
                "query_paginated",
                Some(serde_json::json!(1)),
                &serde_json::json!({ "query": query, "page": 3 }),
                state,
                agent,
            )
            .await
            .expect("dispatched")
        }
    };

    let refused = "DELETE FROM workflows WHERE name = 'a literal worth hiding'";
    let said = mcp_common::error_message(&run(refused).await);
    assert!(!said.is_empty(), "the gate refuses a write");
    let failed = "SELECT no_such_column FROM workflows";
    let said = mcp_common::error_message(&run(failed).await);
    assert!(!said.is_empty(), "the statement fails");

    let rows = records(&pool, admin).await;
    assert_eq!(rows.len(), 2, "one row per statement: {rows:?}");
    assert_eq!(rows[0]["outcome"], "refused");
    assert_eq!(
        rows[0]["statement_sha256"],
        talos_text_util::sha256_hex(refused)
    );
    assert_eq!(rows[0]["page"], 3);
    assert!(rows[0]["row_count"].is_null());
    assert_eq!(rows[1]["outcome"], "failed");
    assert_eq!(
        rows[1]["statement_sha256"],
        talos_text_util::sha256_hex(failed)
    );
    assert!(
        !serde_json::json!(rows)
            .to_string()
            .contains("literal worth hiding"),
        "no statement text is stored"
    );

    // A caller who is not a platform admin is refused before the gate and
    // leaves nothing: the record is of admin statements.
    let other = Uuid::new_v4();
    seed_user(&pool, other).await;
    let resp = controller::mcp::advanced::dispatch(
        "query_paginated",
        Some(serde_json::json!(1)),
        &serde_json::json!({ "query": refused }),
        &state,
        Arc::new(controller::mcp::auth::AgentIdentity {
            agent_id: Uuid::new_v4(),
            name: "not-admin".to_string(),
            role_name: "probe".to_string(),
            allowed_capabilities: vec!["*".to_string()],
            user_id: other,
        }),
    )
    .await
    .expect("dispatched");
    assert!(!mcp_common::error_message(&resp).is_empty());
    assert!(records(&pool, other).await.is_empty());
}
