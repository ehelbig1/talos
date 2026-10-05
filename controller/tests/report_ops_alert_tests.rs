//! `report_ops_alert` (2026-10-05) — an operator-side reporter raising and
//! resolving an ops alert for the CALLING user.
//!
//! These drive the REAL MCP dispatch over a real `McpState` against a template
//! clone, and read `ops_alerts` back. They pin what the tool shares with the
//! `__ops_alert__` module envelope (`envelope::apply_entry`): the reserved
//! `talos` namespace is refused before anything is written — including a
//! resolve aimed at a self-monitoring row — and free text is DLP-redacted
//! before it is stored. And they pin what is the tool's own: the row belongs
//! to the caller (another user's resolve cannot touch it) and carries the
//! caller's personal org.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use common::{create_test_user, setup_test_context};
use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use sqlx::PgPool;
use uuid::Uuid;

async fn report(state: &controller::mcp::McpState, user: Uuid, args: Value) -> Value {
    let resp = controller::mcp::ops_alerts::dispatch(
        "report_ops_alert",
        Some(json!(1)),
        &args,
        state,
        agent(user),
    )
    .await
    .expect("report_ops_alert is dispatched");
    text_json(&resp)
}

async fn refused(state: &controller::mcp::McpState, user: Uuid, args: Value) -> String {
    let resp = controller::mcp::ops_alerts::dispatch(
        "report_ops_alert",
        Some(json!(1)),
        &args,
        state,
        agent(user),
    )
    .await
    .expect("report_ops_alert is dispatched");
    error_message(&resp)
}

#[derive(Debug, sqlx::FromRow)]
struct Row {
    user_id: Uuid,
    org_id: Option<Uuid>,
    source: String,
    title: String,
    resource: Option<String>,
    severity: String,
    status: String,
    occurrence_count: i32,
    resolved_source: Option<String>,
    raw: Option<Value>,
}

async fn rows(pool: &PgPool, dedup_key: &str) -> Vec<Row> {
    sqlx::query_as(
        "SELECT user_id, org_id, source, title, resource, severity, status, \
                occurrence_count, resolved_source, raw \
         FROM ops_alerts WHERE dedup_key = $1 ORDER BY user_id",
    )
    .bind(dedup_key)
    .fetch_all(pool)
    .await
    .expect("read ops_alerts")
}

async fn alert_count(pool: &PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM ops_alerts WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count ops_alerts")
}

async fn personal_org(pool: &PgPool, user: Uuid) -> Option<Uuid> {
    sqlx::query_scalar("SELECT id FROM organizations WHERE owner_id = $1 AND is_personal")
        .bind(user)
        .fetch_optional(pool)
        .await
        .expect("read personal org")
}

const KEY: &str = "backup-drill|artifact";

fn raise() -> Value {
    json!({
        "source": "backup-drill",
        "dedup_key": KEY,
        "title": "Backup restore drill failed at [4/8] restore postgres (SSN: 123-45-6789)",
        "severity_hint": "high",
        "resource": "artifact",
        "raw": {"step": "[4/8] restore postgres", "reason": "SSN: 123-45-6789"},
    })
}

fn resolve() -> Value {
    json!({"source": "backup-drill", "dedup_key": KEY, "status_event": "resolved"})
}

#[tokio::test]
async fn a_raise_then_a_resolve_leave_the_expected_row() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "report-ops-alert@example.com").await;
    // Signup provisions the personal org in the GraphQL mutation, not in
    // `create_user`, so the harness user has none until this.
    let org = talos_organizations::OrganizationService::create_personal_org(&pool, user, None)
        .await
        .expect("personal org")
        .id;
    let state = mcp_state(pool.clone()).await;

    let created = report(&state, user, raise()).await;
    assert_eq!(created["result"], "created", "{created}");
    assert_eq!(created["occurrence_count"], 1, "{created}");
    assert!(
        created.get("raw").is_none(),
        "raw is never echoed: {created}"
    );
    assert!(!created.to_string().contains("123-45-6789"), "{created}");

    let r = rows(&pool, KEY).await;
    assert_eq!(r.len(), 1, "{r:?}");
    let row = &r[0];
    assert_eq!(row.user_id, user, "the alert is the caller's");
    assert_eq!(
        row.org_id,
        Some(org),
        "stamped with the caller's personal org"
    );
    assert_eq!(row.source, "backup-drill");
    assert_eq!(row.resource.as_deref(), Some("artifact"));
    assert_eq!(row.severity, "high", "the hint seeds a new alert");
    assert_eq!(row.status, "new");
    assert!(
        !row.title.contains("123-45-6789") && row.title.contains("[REDACTED:SSN]"),
        "title DLP-redacted before it was stored: {}",
        row.title
    );
    let raw = row.raw.as_ref().expect("raw kept").to_string();
    assert!(!raw.contains("123-45-6789"), "raw DLP-redacted: {raw}");

    // The same condition again bumps the one row.
    let bumped = report(&state, user, raise()).await;
    assert_eq!(bumped["result"], "bumped", "{bumped}");
    assert_eq!(bumped["occurrence_count"], 2, "{bumped}");
    assert_eq!(bumped["alert_id"], created["alert_id"]);

    // Resolve, then resolve again: the second has nothing to resolve.
    assert_eq!(report(&state, user, resolve()).await["result"], "resolved");
    let r = rows(&pool, KEY).await;
    assert_eq!(r[0].status, "resolved");
    assert_eq!(r[0].resolved_source.as_deref(), Some("signal"));
    assert_eq!(
        report(&state, user, resolve()).await["result"],
        "no_active_alert"
    );

    // A failure after the resolve reopens the same row.
    let reopened = report(&state, user, raise()).await;
    assert_eq!(reopened["result"], "reopened", "{reopened}");
    assert_eq!(reopened["alert_id"], created["alert_id"]);
    let r = rows(&pool, KEY).await;
    assert_eq!((r.len(), r[0].status.as_str()), (1, "new"));
    assert_eq!(r[0].occurrence_count, 3);
}

#[tokio::test]
async fn the_reserved_namespace_is_refused_and_nothing_is_written() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "report-ops-reserved@example.com").await;
    let state = mcp_state(pool.clone()).await;

    // A platform self-monitoring alert the caller must not be able to touch,
    // written through the trusted repository path.
    let self_key = format!("talos/{}/node/auth", Uuid::new_v4());
    talos_ops_alerts_repository::OpsAlertRepository::new(pool.clone())
        .ingest(
            user,
            None,
            talos_ops_alerts_repository::NewOpsAlert {
                source: "talos".into(),
                external_id: None,
                dedup_key: self_key.clone(),
                title: "workflow failed".into(),
                resource: None,
                severity_raw: None,
                severity_hint: Some("high".into()),
                raw: None,
            },
        )
        .await
        .expect("seed self-monitoring alert");

    for args in [
        // Raise under a reserved dedup key.
        json!({"source": "backup-drill", "dedup_key": "talos/spoof", "title": "spoof"}),
        // Raise under the reserved source.
        json!({"source": "talos", "dedup_key": "spoof", "title": "spoof"}),
        // Bump the existing self-monitoring row.
        json!({"source": "backup-drill", "dedup_key": self_key, "title": "retitled"}),
        // Resolve it — would silence the platform's own alert.
        json!({"source": "backup-drill", "dedup_key": self_key, "status_event": "resolved"}),
    ] {
        let msg = refused(&state, user, args.clone()).await;
        assert!(msg.contains("reserved"), "{args}: {msg}");
    }

    assert_eq!(
        alert_count(&pool, user).await,
        1,
        "only the seeded row exists"
    );
    let r = rows(&pool, &self_key).await;
    assert_eq!(
        (
            r[0].status.as_str(),
            r[0].occurrence_count,
            r[0].title.as_str()
        ),
        ("new", 1, "workflow failed"),
        "the self-monitoring row is untouched"
    );
}

#[tokio::test]
async fn a_resolve_reaches_only_the_callers_own_alert() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let owner = create_test_user(&ctx.auth_service, "report-ops-owner@example.com").await;
    let other = create_test_user(&ctx.auth_service, "report-ops-other@example.com").await;
    let state = mcp_state(pool.clone()).await;

    assert_eq!(report(&state, owner, raise()).await["result"], "created");
    assert_eq!(
        report(&state, other, resolve()).await["result"],
        "no_active_alert",
        "another user's resolve finds nothing of theirs"
    );
    let r = rows(&pool, KEY).await;
    assert_eq!(r.len(), 1, "{r:?}");
    assert_eq!((r[0].user_id, r[0].status.as_str()), (owner, "new"));
    assert_eq!(
        (r[0].org_id, personal_org(&pool, owner).await),
        (None, None),
        "a caller with no personal org writes no org"
    );
    assert_eq!(alert_count(&pool, other).await, 0);
}

#[tokio::test]
async fn invalid_arguments_write_nothing() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "report-ops-invalid@example.com").await;
    let state = mcp_state(pool.clone()).await;
    for (args, needle) in [
        (json!({"source": "backup-drill", "dedup_key": KEY}), "title"),
        (
            json!({"source": "backup-drill", "dedup_key": KEY, "status_event": "closed"}),
            "status_event",
        ),
        (
            json!({"source": "backup-drill", "dedup_key": KEY, "title": "t",
                   "severity_hint": "catastrophic"}),
            "severity_hint",
        ),
    ] {
        let msg = refused(&state, user, args.clone()).await;
        assert!(msg.contains(needle), "{args}: {msg}");
    }
    assert_eq!(alert_count(&pool, user).await, 0);
}
