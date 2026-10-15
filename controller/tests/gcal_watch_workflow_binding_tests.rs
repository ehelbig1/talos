//! A Google Calendar watch channel that starts a WORKFLOW (2026-10-12).
//!
//! A channel is authenticated by a token signed for one user, so what a push
//! may start is that user's own. The assertions here are on rows:
//!
//! * a workflow is bound only by its owner, to the owner's own channel, and a
//!   refusal changes nothing;
//! * a renewal — which replaces the channel's row — keeps the binding;
//! * a push on a bound channel reaches the trigger service as the channel's
//!   user, a start that is refused is recorded with a reason from a closed
//!   set, and an unbound channel starts nothing;
//! * a binding left pointing at a workflow that is no longer the user's is
//!   refused at the push, by the trigger's own ownership check.
//!
//! A push on a live workflow is driven as far as the execution row the
//! trigger creates for the channel's user; this harness has no dispatch bus,
//! so what a worker then does with it is not. An in-process HTTP server stands
//! in for Google. `common` harness (a template clone per test).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use axum::{extract::State, routing::get, routing::post, Json, Router};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use talos_google_calendar::handlers::{process_webhook_events, BoundWorkflow};
use talos_google_calendar::watch::{bind_channel_workflow, BindWorkflowRefusal};
use talos_google_calendar::watch_channel_service::GcalPushChannelInventory;
use talos_google_calendar::GoogleCalendarService;
use talos_push_channel_inventory::{
    BindWorkflowRefusal as SetRefusal, PushChannelInventory, PushChannelInventorySet,
};
use uuid::Uuid;

const CALENDAR: &str = "primary";
const WEBHOOK: &str = "https://hooks.example.com/api/google-calendar/webhook";

struct FakeGoogle {
    watches: AtomicUsize,
    syncs: AtomicUsize,
}

async fn events_watch(
    State(g): State<Arc<FakeGoogle>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let n = g.watches.fetch_add(1, Ordering::SeqCst) + 1;
    let expiration = (chrono::Utc::now() + chrono::Duration::days(7)).timestamp_millis();
    Json(serde_json::json!({
        "id": body["id"],
        "resourceId": format!("resource-{n}"),
        "resourceUri": "https://www.googleapis.com/calendar/v3/calendars/primary/events",
        "expiration": expiration.to_string(),
    }))
}

/// One changed event per sync, with content a trigger must not carry.
async fn events_list(State(g): State<Arc<FakeGoogle>>) -> Json<serde_json::Value> {
    let n = g.syncs.fetch_add(1, Ordering::SeqCst) + 1;
    Json(serde_json::json!({
        "items": [{
            "id": format!("changedevent{n}"),
            "status": "confirmed",
            "summary": "Performance review",
            "description": "private notes",
        }],
        "nextSyncToken": format!("sync-{n}"),
    }))
}

struct World {
    svc: Arc<GoogleCalendarService>,
    pool: sqlx::Pool<sqlx::Postgres>,
    google: Arc<FakeGoogle>,
    _db: common::TestDb,
}

async fn world() -> World {
    let (pool, db) = common::isolated_db_pool().await;
    let google = Arc::new(FakeGoogle {
        watches: AtomicUsize::new(0),
        syncs: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/calendars/{calendar}/events/watch", post(events_watch))
        .route("/calendars/{calendar}/events", get(events_list))
        .route(
            "/channels/stop",
            post(|| async { axum::http::StatusCode::NO_CONTENT }),
        )
        .with_state(google.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let secrets =
        Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("initialize secrets");
    let svc = GoogleCalendarService::new(pool.clone(), secrets);
    svc.with_api_base_url_for_tests(&base);
    World {
        svc: Arc::new(svc),
        pool,
        google,
        _db: db,
    }
}

/// A user with one connected calendar: (user, integration).
async fn user_with_calendar(w: &World) -> (Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@gcal-workflow-binding.test"))
    .execute(&w.pool)
    .await
    .expect("user");
    let (integration, account) = (Uuid::new_v4(), Uuid::new_v4());
    sqlx::query(
        "INSERT INTO google_calendar_integrations (id, user_id, oauth_account_id, expires_at, scope, is_active) \
         VALUES ($1, $2, $3, now() + interval '1 hour', 'calendar', true)",
    )
    .bind(integration)
    .bind(user)
    .bind(account)
    .execute(&w.pool)
    .await
    .expect("integration");
    let path = format!("oauth/google_calendar/{user}/{account}/access_token");
    controller::secrets::SecretsManager::new(w.pool.clone())
        .expect("secrets manager")
        .upsert_secret(
            &path,
            &path,
            "test-access-token",
            "oauth",
            None,
            user,
            vec![],
            None,
        )
        .await
        .expect("store access token");
    (user, integration)
}

/// The workflow a user's channel names, as the operator inventory reads it
/// (which is also what `list_push_channels` shows).
async fn stored_binding(w: &World, user: Uuid) -> Option<Uuid> {
    let rows = GcalPushChannelInventory::new(w.pool.clone())
        .list_channels(user)
        .await
        .expect("list channels");
    assert_eq!(rows.len(), 1, "one channel for this user");
    rows[0].workflow_id
}

async fn audit(w: &World, user: Uuid, event_type: &str) -> Vec<(bool, Option<String>)> {
    sqlx::query_as(
        "SELECT success, error_message FROM google_calendar_audit_log \
         WHERE user_id = $1 AND event_type = $2 ORDER BY created_at",
    )
    .bind(user)
    .bind(event_type)
    .fetch_all(&w.pool)
    .await
    .expect("audit rows")
}

async fn executions(w: &World, workflow: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflow_executions WHERE workflow_id = $1")
        .bind(workflow)
        .fetch_one(&w.pool)
        .await
        .expect("count executions")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workflow_is_bound_only_by_its_owner_to_the_owners_own_channel() {
    let w = world().await;
    let (alice, alice_cal) = user_with_calendar(&w).await;
    let (bob, bob_cal) = user_with_calendar(&w).await;
    let alice_channel = w
        .svc
        .create_watch_channel(alice_cal, CALENDAR, WEBHOOK, None)
        .await
        .expect("alice's channel");
    let bob_channel = w
        .svc
        .create_watch_channel(bob_cal, CALENDAR, WEBHOOK, None)
        .await
        .expect("bob's channel");
    let alices = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bobs = common::create_test_workflow(&w.pool, bob, "bobs").await;
    assert_eq!(
        alice_channel.workflow_id, None,
        "a new channel starts nothing"
    );

    // Her own workflow, her own channel.
    let bound = bind_channel_workflow(&w.pool, alice, alice_channel.id, Some(alices))
        .await
        .expect("bind");
    assert_eq!(bound.workflow_id, Some(alices));
    assert_eq!(stored_binding(&w, alice).await, Some(alices));
    assert_eq!(audit(&w, alice, "workflow_bound").await.len(), 1);

    // Bob's workflow on her channel: refused, said the way a missing one is,
    // and her binding is what it was.
    assert_eq!(
        bind_channel_workflow(&w.pool, alice, alice_channel.id, Some(bobs))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::WorkflowNotBindable
    );
    assert_eq!(
        bind_channel_workflow(&w.pool, alice, alice_channel.id, Some(Uuid::new_v4()))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::WorkflowNotBindable
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alices));

    // Her workflow on Bob's channel: his channel is not hers to bind, and it
    // is left with no binding. Nor may Bob point his channel at her workflow.
    assert_eq!(
        bind_channel_workflow(&w.pool, alice, bob_channel.id, Some(alices))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::ChannelNotFound
    );
    assert_eq!(
        bind_channel_workflow(&w.pool, bob, bob_channel.id, Some(alices))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::WorkflowNotBindable
    );
    assert_eq!(stored_binding(&w, bob).await, None);
    assert_eq!(
        bind_channel_workflow(&w.pool, alice, Uuid::new_v4(), Some(alices))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::ChannelNotFound
    );

    // Clearing is the owner's too.
    let cleared = bind_channel_workflow(&w.pool, alice, alice_channel.id, None)
        .await
        .expect("clear");
    assert_eq!(cleared.workflow_id, None);
    assert_eq!(stored_binding(&w, alice).await, None);
    assert_eq!(audit(&w, alice, "workflow_unbound").await.len(), 1);
}

/// The owner's own workflow, archived or disabled, is refused: the trigger
/// would refuse every push it started, so the binding would never fire
/// (security review 2026-10-14, F-7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_archived_workflow_cannot_be_bound() {
    let w = world().await;
    let (alice, alice_cal) = user_with_calendar(&w).await;
    let channel = w
        .svc
        .create_watch_channel(alice_cal, CALENDAR, WEBHOOK, None)
        .await
        .expect("channel");
    let archived = common::create_test_workflow(&w.pool, alice, "archived").await;
    let disabled = common::create_test_workflow(&w.pool, alice, "disabled").await;
    sqlx::query("UPDATE workflows SET status = 'archived' WHERE id = $1")
        .bind(archived)
        .execute(&w.pool)
        .await
        .expect("archive");
    sqlx::query("UPDATE workflows SET is_enabled = false WHERE id = $1")
        .bind(disabled)
        .execute(&w.pool)
        .await
        .expect("disable");

    for not_startable in [archived, disabled] {
        assert_eq!(
            bind_channel_workflow(&w.pool, alice, channel.id, Some(not_startable))
                .await
                .unwrap_err(),
            BindWorkflowRefusal::WorkflowNotBindable
        );
    }
    assert_eq!(stored_binding(&w, alice).await, None);
    assert!(audit(&w, alice, "workflow_bound").await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renewal_and_a_second_create_keep_the_binding() {
    let w = world().await;
    let (user, integration) = user_with_calendar(&w).await;
    let channel = w
        .svc
        .create_watch_channel(integration, CALENDAR, WEBHOOK, None)
        .await
        .expect("channel");
    let workflow = common::create_test_workflow(&w.pool, user, "on-change").await;
    bind_channel_workflow(&w.pool, user, channel.id, Some(workflow))
        .await
        .expect("bind");

    // Creating the same calendar's watch again re-points the MODULE binding
    // (to none, here) on the existing row. The workflow binding is not its to
    // change.
    let again = w
        .svc
        .create_watch_channel(integration, CALENDAR, WEBHOOK, None)
        .await
        .expect("second create");
    assert_eq!(again.id, channel.id, "the existing channel is reused");
    assert_eq!(stored_binding(&w, user).await, Some(workflow));

    // A renewal replaces the row: a new id, a new Google channel, the same binding.
    let renewed = w
        .svc
        .renew_watch_channel(user, channel.id)
        .await
        .expect("renew");
    assert_ne!(renewed.id, channel.id);
    assert_ne!(renewed.channel_id, channel.channel_id);
    assert_eq!(renewed.workflow_id, Some(workflow));
    assert_eq!(stored_binding(&w, user).await, Some(workflow));
    assert_eq!(w.google.watches.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_on_a_bound_channel_reaches_the_trigger_as_the_channels_user() {
    let w = world().await;
    let (user, integration) = user_with_calendar(&w).await;
    let channel = w
        .svc
        .create_watch_channel(integration, CALENDAR, WEBHOOK, None)
        .await
        .expect("channel");
    let workflow = common::create_test_workflow(&w.pool, user, "on-change").await;
    let state = mcp_common::mcp_state(w.pool.clone()).await;
    let service = Some(state.execution_orchestration_service.clone());
    let push = |bound: Option<BoundWorkflow>, service| {
        let svc = w.svc.clone();
        async move {
            process_webhook_events(
                svc,
                channel.id,
                integration,
                None,
                user,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                bound,
                service,
            )
            .await
        }
    };
    let bound = || {
        Some(BoundWorkflow {
            workflow_id: workflow,
            calendar_id: CALENDAR.to_string(),
        })
    };

    // Unbound: the changes are synced and nothing is attempted.
    push(None, service.clone()).await.expect("unbound push");
    assert_eq!(w.google.syncs.load(Ordering::SeqCst), 1);
    assert!(audit(&w, user, "workflow_not_started").await.is_empty());

    // Bound, and the workflow is switched off: one audit row with a reason
    // from the closed set, no execution, and the push itself is not an error
    // (Google must not be made to retry what the sync has already consumed).
    sqlx::query("UPDATE workflows SET is_enabled = false WHERE id = $1")
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("switch the workflow off");
    push(bound(), service.clone()).await.expect("bound push");
    let rows = audit(&w, user, "workflow_not_started").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (rows[0].0, rows[0].1.as_deref()),
        (false, Some("workflow_not_live"))
    );
    assert_eq!(executions(&w, workflow).await, 0);

    // Switched on: the trigger takes it, as the channel's user. (This harness
    // has no dispatch bus, so what happens to the execution after it is
    // created is not asserted; that the push produced one, for this user's
    // workflow, is.)
    sqlx::query("UPDATE workflows SET is_enabled = true WHERE id = $1")
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("switch the workflow on");
    push(bound(), service.clone())
        .await
        .expect("bound push, live workflow");
    assert_eq!(executions(&w, workflow).await, 1);
    let owner: Uuid =
        sqlx::query_scalar("SELECT user_id FROM workflow_executions WHERE workflow_id = $1")
            .bind(workflow)
            .fetch_one(&w.pool)
            .await
            .expect("the execution's user");
    assert_eq!(owner, user);
    let not_started_so_far = audit(&w, user, "workflow_not_started").await.len();

    // No trigger service wired: said so, not silently nothing.
    push(bound(), None).await.expect("push with no service");
    let rows = audit(&w, user, "workflow_not_started").await;
    assert_eq!(rows.len(), not_started_so_far + 1);
    assert_eq!(
        rows.last().unwrap().1.as_deref(),
        Some("trigger_service_not_wired")
    );

    // The workflow stops being this user's while the row still names it. The
    // push is the channel user's, so the trigger does not find the workflow:
    // a binding is never what makes a workflow startable.
    let other = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(other)
    .bind(format!("{other}@gcal-workflow-binding.test"))
    .execute(&w.pool)
    .await
    .expect("other user");
    sqlx::query("UPDATE workflows SET user_id = $1 WHERE id = $2")
        .bind(other)
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("move the workflow");
    push(bound(), service).await.expect("push after the move");
    let rows = audit(&w, user, "workflow_not_started").await;
    assert_eq!(rows.len(), not_started_so_far + 2);
    assert_eq!(
        rows.last().unwrap().1.as_deref(),
        Some("workflow_not_found")
    );
    assert_eq!(executions(&w, workflow).await, 1, "no second execution");

    // Nothing an event says reached the audit log.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM google_calendar_audit_log WHERE metadata::text LIKE '%Performance%' \
         OR metadata::text LIKE '%private%' OR coalesce(error_message, '') LIKE '%Performance%'",
    )
    .fetch_one(&w.pool)
    .await
    .expect("scan audit");
    assert_eq!(leaked, 0);
}

/// The path the MCP tool takes: by integration name, through the inventory
/// set. The same ownership rules, and an integration that cannot start a
/// workflow says so.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_inventory_set_binds_by_integration_name_under_the_same_rules() {
    let w = world().await;
    let (alice, alice_cal) = user_with_calendar(&w).await;
    let (bob, _) = user_with_calendar(&w).await;
    let channel = w
        .svc
        .create_watch_channel(alice_cal, CALENDAR, WEBHOOK, None)
        .await
        .expect("channel");
    let alices = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bobs = common::create_test_workflow(&w.pool, bob, "bobs").await;
    let set = PushChannelInventorySet::new(vec![Arc::new(GcalPushChannelInventory::new(
        w.pool.clone(),
    ))]);

    assert_eq!(
        set.bind_workflow("gcal", alice, channel.id, Some(alices))
            .await,
        Ok(())
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alices));
    assert_eq!(
        set.bind_workflow("gcal", alice, channel.id, Some(bobs))
            .await,
        Err(SetRefusal::WorkflowNotBindable)
    );
    assert_eq!(
        set.bind_workflow("gcal", bob, channel.id, Some(bobs)).await,
        Err(SetRefusal::ChannelNotFound),
        "another user cannot bind this channel, even to a workflow of their own"
    );
    assert_eq!(
        set.bind_workflow("gmail", alice, channel.id, Some(alices))
            .await,
        Err(SetRefusal::UnknownIntegration)
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alices));
    assert_eq!(
        set.bind_workflow("gcal", alice, channel.id, None).await,
        Ok(())
    );
    assert_eq!(stored_binding(&w, alice).await, None);
}
