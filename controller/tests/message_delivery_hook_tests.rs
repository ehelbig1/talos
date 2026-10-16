//! A sent message is recorded by the engine, and the report sets taps
//! against it (2026-10-16).
//!
//! A `notify-*` adapter's output is the only trace of a message having left,
//! and node outputs are encrypted at rest. The engine's node hook reads the
//! adapter's verdict at completion and writes one `message_deliveries` row per
//! real send; `AnalyticsRepository::message_engagement` joins those rows to
//! the action links tapped in the same executions.
//!
//! Driven through the REAL hook (`ControllerNodeHook`) and the real
//! repository, against a migrated Postgres.

mod common;

use serde_json::json;
use talos_engine::node_hook::ControllerNodeHook;
use talos_workflow_engine_core::{NodeCompletionContext, NodeLifecycleHook, WriteCeiling};
use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("sends-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

/// The verdict `notify-ntfy` returns for a two-part list with three actions.
fn verdict() -> serde_json::Value {
    json!({ "provider": "ntfy", "sent": true, "skipped": false, "dry_run": false,
            "status": 200, "parts_total": 2, "parts_sent": 2,
            "actions_sent": 3, "actions_dropped": 0, "one_tap_actions": 2,
            "kept_actions": 1, "link_sent": false, "link_dropped": false, "tag_sent": false })
}

struct Completion<'a> {
    workflow_id: Uuid,
    execution_id: Uuid,
    module_id: Option<Uuid>,
    started_by_kind: Option<&'a str>,
    dry_run: bool,
}

fn complete(hook: &ControllerNodeHook, c: Completion<'_>, output: &serde_json::Value) {
    hook.on_node_completed(
        NodeCompletionContext {
            workflow_id: c.workflow_id,
            execution_id: c.execution_id,
            node_id: Uuid::new_v4(),
            node_label: Some("send"),
            module_id: c.module_id,
            actor_id: None,
            max_write_ceiling: WriteCeiling::Write,
            http_verb_ceiling: None,
            started_by_kind: c.started_by_kind,
            dry_run: c.dry_run,
            wall_time_ms: 1,
        },
        output,
    );
}

#[derive(Debug, PartialEq, Eq, sqlx::FromRow)]
struct Recorded {
    provider: String,
    parts_total: i32,
    parts_sent: i32,
    actions_sent: i32,
    one_tap_actions: i32,
    kept_actions: i32,
    started_by_kind: Option<String>,
}

async fn recorded(pool: &sqlx::PgPool, execution_id: Uuid) -> Vec<Recorded> {
    sqlx::query_as::<_, Recorded>(
        "SELECT provider, parts_total, parts_sent, actions_sent, one_tap_actions, kept_actions, started_by_kind \
         FROM message_deliveries WHERE execution_id = $1",
    )
    .bind(execution_id)
    .fetch_all(pool)
    .await
    .unwrap()
}

#[tokio::test]
async fn a_real_send_is_recorded_with_the_adapters_counts() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let workflow = common::create_test_workflow(&pool, user, "pa-morning").await;
    let hook = ControllerNodeHook::new(pool.clone());
    let execution = Uuid::new_v4();

    complete(
        &hook,
        Completion {
            workflow_id: workflow,
            execution_id: execution,
            module_id: Some(Uuid::new_v4()),
            started_by_kind: Some("schedule"),
            dry_run: false,
        },
        &verdict(),
    );

    common::eventually_default("the send to be recorded", || async {
        !recorded(&pool, execution).await.is_empty()
    })
    .await;
    assert_eq!(
        recorded(&pool, execution).await,
        vec![Recorded {
            provider: "ntfy".into(),
            parts_total: 2,
            parts_sent: 2,
            actions_sent: 3,
            one_tap_actions: 2,
            kept_actions: 1,
            started_by_kind: Some("schedule".into()),
        }]
    );
}

/// `send-html-email` returns the same verdict beside its Gmail ids: one
/// email is one part, its actions the action links in the body.
#[tokio::test]
async fn an_emails_verdict_is_recorded_as_one_part_with_its_links() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let workflow = common::create_test_workflow(&pool, user, "pa-sunday").await;
    let hook = ControllerNodeHook::new(pool.clone());
    let execution = Uuid::new_v4();

    complete(
        &hook,
        Completion {
            workflow_id: workflow,
            execution_id: execution,
            module_id: Some(Uuid::new_v4()),
            started_by_kind: Some("schedule"),
            dry_run: false,
        },
        &json!({ "provider": "gmail", "sent": true, "skipped": false, "dry_run": false,
                 "parts_total": 1, "parts_sent": 1, "actions_sent": 2,
                 "message_id": "made-up", "thread_id": "made-up", "to": "r@example.test", "subject": "Sunday" }),
    );

    common::eventually_default("the email to be recorded", || async {
        !recorded(&pool, execution).await.is_empty()
    })
    .await;
    assert_eq!(
        recorded(&pool, execution).await,
        vec![Recorded {
            provider: "gmail".into(),
            parts_total: 1,
            parts_sent: 1,
            actions_sent: 2,
            one_tap_actions: 0,
            kept_actions: 0,
            started_by_kind: Some("schedule".into()),
        }]
    );
}

#[tokio::test]
async fn nothing_is_recorded_for_a_dry_run_a_stubbed_output_a_system_node_or_another_nodes_output()
{
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let workflow = common::create_test_workflow(&pool, user, "pa-evening").await;
    let hook = ControllerNodeHook::new(pool.clone());

    // The engine's own flag refuses before the output is read: the verdict
    // says a message left, and it did not.
    let dry_run = Uuid::new_v4();
    complete(
        &hook,
        Completion {
            workflow_id: workflow,
            execution_id: dry_run,
            module_id: Some(Uuid::new_v4()),
            started_by_kind: Some("manual"),
            dry_run: true,
        },
        &verdict(),
    );
    // The worker's stamp on a stubbed output is the second refusal.
    let stubbed = Uuid::new_v4();
    let mut stamped = verdict();
    stamped["__dry_run__"] = json!({ "stubbed_calls": 1, "by_surface": { "http": 1 } });
    complete(
        &hook,
        Completion {
            workflow_id: workflow,
            execution_id: stubbed,
            module_id: Some(Uuid::new_v4()),
            started_by_kind: Some("manual"),
            dry_run: false,
        },
        &stamped,
    );
    // A system node sends nothing, whatever its output carries.
    let system = Uuid::new_v4();
    complete(
        &hook,
        Completion {
            workflow_id: workflow,
            execution_id: system,
            module_id: None,
            started_by_kind: Some("schedule"),
            dry_run: false,
        },
        &verdict(),
    );
    // A compose node's output, the output of an email sender's copy from
    // before it returned the verdict (2026-10-16), and a verdict with
    // nothing sent are not sends.
    let others = Uuid::new_v4();
    for output in [
        json!({ "notification": { "body": "Three things today." } }),
        json!({ "sent": true, "message_id": "m1", "thread_id": "t1" }),
        json!({ "provider": "ntfy", "sent": false, "skipped": true, "parts_total": 0, "parts_sent": 0 }),
    ] {
        complete(
            &hook,
            Completion {
                workflow_id: workflow,
                execution_id: others,
                module_id: Some(Uuid::new_v4()),
                started_by_kind: Some("schedule"),
                dry_run: false,
            },
            &output,
        );
    }
    // A verdict outside the contract's bounds is not written.
    let malformed = Uuid::new_v4();
    let mut over = verdict();
    over["parts_sent"] = json!(3);
    complete(
        &hook,
        Completion {
            workflow_id: workflow,
            execution_id: malformed,
            module_id: Some(Uuid::new_v4()),
            started_by_kind: Some("schedule"),
            dry_run: false,
        },
        &over,
    );
    // A run with no workflow row has nothing to attribute a send to.
    let unattributed = Uuid::new_v4();
    complete(
        &hook,
        Completion {
            workflow_id: unattributed,
            execution_id: unattributed,
            module_id: Some(Uuid::new_v4()),
            started_by_kind: Some("manual"),
            dry_run: false,
        },
        &verdict(),
    );

    // A negative control cannot be polled: give the spawned writes time to
    // have landed if they were going to.
    tokio::time::sleep(std::time::Duration::from_millis(400)).await;
    for (execution, what) in [
        (dry_run, "a dry run"),
        (stubbed, "a stubbed output"),
        (system, "a system node"),
        (others, "another node's output"),
        (malformed, "a malformed verdict"),
        (unattributed, "a run with no workflow"),
    ] {
        assert!(
            recorded(&pool, execution).await.is_empty(),
            "{what} was recorded as a send"
        );
    }
}

/// One recorded send. A `ntfy` send carries two actions, one of them one-tap
/// (the shape of the morning message); a `gmail` send carries the actions
/// given and none one-tap (email cannot act in the background).
async fn seed_delivery(
    pool: &sqlx::PgPool,
    workflow: Uuid,
    execution: Uuid,
    provider: &str,
    actions: i32,
    started_by_kind: &str,
    days_ago: i32,
) {
    let one_tap = i32::from(provider == "ntfy" && actions > 0);
    sqlx::query(
        "INSERT INTO message_deliveries (workflow_id, execution_id, node_id, provider, parts_total, parts_sent, \
                                         actions_sent, one_tap_actions, kept_actions, started_by_kind, sent_at) \
         VALUES ($1, $2, $3, $4, 1, 1, $5, $6, 0, $7, NOW() - make_interval(days => $8::int))",
    )
    .bind(workflow)
    .bind(execution)
    .bind(Uuid::new_v4())
    .bind(provider)
    .bind(actions)
    .bind(one_tap)
    .bind(started_by_kind)
    .bind(days_ago)
    .execute(pool)
    .await
    .unwrap();
}

async fn seed_token(pool: &sqlx::PgPool, user: Uuid, target: Uuid, source: Uuid, used: bool) {
    sqlx::query(
        "INSERT INTO workflow_action_tokens \
             (user_id, workflow_id, token_hash, label, source_execution_id, source_node, expires_at, used_at) \
         VALUES ($1, $2, $3, 'Done', $4, 'send', NOW() + interval '1 day', CASE WHEN $5 THEN NOW() ELSE NULL END)",
    )
    .bind(user)
    .bind(target)
    .bind(Uuid::new_v4().to_string())
    .bind(source)
    .bind(used)
    .execute(pool)
    .await
    .unwrap();
}

#[tokio::test]
async fn the_report_sets_taps_against_the_sends_that_carried_them() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let other_user = seed_user(&pool).await;
    let morning = common::create_test_workflow(&pool, user, "pa-morning").await;
    let evening = common::create_test_workflow(&pool, user, "pa-evening").await;
    let target = common::create_test_workflow(&pool, user, "pa-list-done").await;
    let theirs = common::create_test_workflow(&pool, other_user, "their-morning").await;

    // Morning runs: m1 sent a notification AND an email with one link; m2 a
    // notification; m3 an email with no buttons (a plain report: nothing to
    // tap); one rehearsal; one run outside the window. One evening run; one
    // run of another user's.
    let (m1, m2, m3, m_test, m_old, e1, t1) = (
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
    );
    seed_delivery(&pool, morning, m1, "ntfy", 2, "schedule", 1).await;
    seed_delivery(&pool, morning, m1, "gmail", 1, "schedule", 1).await;
    seed_delivery(&pool, morning, m2, "ntfy", 2, "schedule", 3).await;
    seed_delivery(&pool, morning, m3, "gmail", 0, "schedule", 2).await;
    seed_delivery(&pool, morning, m_test, "ntfy", 2, "test", 1).await;
    seed_delivery(&pool, morning, m_old, "ntfy", 2, "schedule", 20).await;
    seed_delivery(&pool, evening, e1, "ntfy", 2, "schedule", 2).await;
    seed_delivery(&pool, theirs, t1, "ntfy", 2, "schedule", 1).await;

    // m1 carried two links, one tapped; m2 one link, tapped; the rehearsal's
    // link was tapped too; a token of another user's names m1 as its source.
    seed_token(&pool, user, target, m1, true).await;
    seed_token(&pool, user, target, m1, false).await;
    seed_token(&pool, user, target, m2, true).await;
    seed_token(&pool, user, target, m_test, true).await;
    seed_token(&pool, user, target, m_old, true).await;
    seed_token(&pool, user, target, e1, false).await;
    seed_token(&pool, other_user, theirs, m1, true).await;

    let repo = talos_analytics_repository::AnalyticsRepository::new(pool.clone());
    let rows = repo.message_engagement(user, 14).await.unwrap();
    let by_name: std::collections::HashMap<&str, _> =
        rows.iter().map(|r| (r.workflow_name.as_str(), r)).collect();
    assert_eq!(by_name.len(), 2, "{rows:?}");
    let morning_row = by_name["pa-morning"];
    assert_eq!(
        (
            morning_row.sends,
            morning_row.parts_sent,
            morning_row.actions_sent,
            morning_row.one_tap_actions,
            morning_row.executions,
            morning_row.executions_with_actions,
            morning_row.executions_tapped,
            morning_row.taps,
        ),
        (4, 4, 5, 2, 3, 2, 2, 2),
        "{morning_row:?}"
    );
    // The same sends by provider; the taps are not split, since m1's links
    // were minted once for both.
    assert_eq!(
        morning_row.providers,
        vec![
            talos_analytics_repository::ProviderSends {
                provider: "gmail".into(),
                sends: 2,
                parts_sent: 2,
                actions_sent: 1,
                one_tap_actions: 0,
            },
            talos_analytics_repository::ProviderSends {
                provider: "ntfy".into(),
                sends: 2,
                parts_sent: 2,
                actions_sent: 4,
                one_tap_actions: 2,
            },
        ],
        "{morning_row:?}"
    );
    let evening_row = by_name["pa-evening"];
    assert_eq!(
        (
            evening_row.sends,
            evening_row.executions_with_actions,
            evening_row.executions_tapped,
            evening_row.taps,
            evening_row.providers.len(),
        ),
        (1, 1, 0, 0, 1),
        "{evening_row:?}"
    );
    // Ordered by sends.
    assert_eq!(rows[0].workflow_name, "pa-morning");

    // The window is the caller's, and the other user sees only their own.
    assert_eq!(
        repo.message_engagement(user, 30).await.unwrap()[0].sends,
        5,
        "a 30-day window takes the send from 20 days ago"
    );
    let their_rows = repo.message_engagement(other_user, 14).await.unwrap();
    assert_eq!(their_rows.len(), 1, "{their_rows:?}");
    assert_eq!(
        (their_rows[0].workflow_name.as_str(), their_rows[0].taps),
        ("their-morning", 0)
    );
}
