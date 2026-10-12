//! A Gmail watch that starts a WORKFLOW (2026-10-12).
//!
//! A Gmail watch row has been able to name a workflow since the push
//! integration was written, but only a create could set it, nothing asked
//! whose workflow it was until a push arrived, `list_push_channels` reported
//! a bound watch as starting nothing, and the push started the workflow
//! through the route meant for RESUMING a run — which does not ask whether
//! the workflow is switched on. The assertions here are on rows:
//!
//! * a workflow is bound only by its owner, to the owner's own watch, by the
//!   bind function and by a create alike, and a refusal changes nothing;
//! * a renewal — which replaces the watch's row — keeps the binding, and so
//!   does a second create that names no workflow;
//! * a push on a bound watch reaches the trigger service as the watch's user,
//!   a start that is refused is recorded with a reason from a closed set, and
//!   the execution says a Gmail push channel started it;
//! * the inventory (what `list_push_channels` and `set_push_channel_workflow`
//!   use) tells and sets the binding under the same rules.
//!
//! A push on a live workflow is driven as far as the execution row the
//! trigger creates for the watch's user; this harness has no dispatch bus, so
//! what a worker then does with it is not. An in-process HTTP server stands
//! in for Google. `common` harness (a template clone per test).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use axum::{extract::State, routing::post, Json, Router};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use talos_gmail::dispatch::{start_bound_workflow, BoundWorkflowStart};
use talos_gmail::watch::{
    bind_channel_workflow, BindWorkflowRefusal, CreateWatchError, GmailWatchService,
};
use talos_gmail::watch_channel_service::GmailPushChannelInventory;
use talos_gmail::GmailIntegrationService;
use talos_push_channel_inventory::{
    BindWorkflowRefusal as SetRefusal, PushChannelInventory, PushChannelInventorySet,
};
use uuid::Uuid;

const TOPIC: &str = "projects/example/topics/gmail";

struct FakeGoogle {
    watches: AtomicUsize,
}

async fn users_watch(State(g): State<Arc<FakeGoogle>>) -> Json<serde_json::Value> {
    let n = g.watches.fetch_add(1, Ordering::SeqCst) + 1;
    let expiration = (chrono::Utc::now() + chrono::Duration::days(7)).timestamp_millis();
    Json(serde_json::json!({
        "historyId": (1000 + n).to_string(),
        "expiration": expiration.to_string(),
    }))
}

struct World {
    svc: Arc<GmailWatchService>,
    pool: sqlx::Pool<sqlx::Postgres>,
    google: Arc<FakeGoogle>,
    _db: common::TestDb,
}

async fn world() -> World {
    let (pool, db) = common::isolated_db_pool().await;
    let google = Arc::new(FakeGoogle {
        watches: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/users/me/watch", post(users_watch))
        .route(
            "/users/me/stop",
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
    let integrations = Arc::new(
        GmailIntegrationService::new(pool.clone())
            .expect("gmail integrations")
            .with_secrets_manager(secrets),
    );
    let svc = Arc::new(
        GmailWatchService::new(pool.clone(), integrations, TOPIC.to_string(), vec![])
            .with_api_base_url_for_tests(&base),
    );
    World {
        svc,
        pool,
        google,
        _db: db,
    }
}

/// A user with one connected mailbox: (user, integration).
async fn user_with_mailbox(w: &World) -> (Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@gmail-workflow-binding.test"))
    .execute(&w.pool)
    .await
    .expect("user");
    let integration = Uuid::new_v4();
    let mailbox = format!("mailbox-{user}@example.com");
    sqlx::query(
        "INSERT INTO gmail_integrations (id, user_id, email_address, scope, is_active) \
         VALUES ($1, $2, $3, 'gmail.readonly', true)",
    )
    .bind(integration)
    .bind(user)
    .bind(&mailbox)
    .execute(&w.pool)
    .await
    .expect("integration");
    // The access token the watch paths read from the vault. A test value.
    let path = format!("oauth/gmail/{user}/{mailbox}/access_token");
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

/// The workflow a user's watch names, as the operator inventory reads it
/// (which is also what `list_push_channels` shows).
async fn stored_binding(w: &World, user: Uuid) -> Option<Uuid> {
    let rows = GmailPushChannelInventory::new(w.pool.clone())
        .list_channels(user)
        .await
        .expect("list channels");
    assert_eq!(rows.len(), 1, "one watch for this user");
    rows[0].workflow_id
}

async fn watch_rows(w: &World, user: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM integration_state WHERE integration_name = 'gmail' AND user_id = $1",
    )
    .bind(user)
    .fetch_one(&w.pool)
    .await
    .expect("count watch rows")
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
async fn a_workflow_is_bound_only_by_its_owner_to_the_owners_own_watch() {
    let w = world().await;
    let (alice, alice_mail) = user_with_mailbox(&w).await;
    let (bob, bob_mail) = user_with_mailbox(&w).await;
    let alice_watch = w
        .svc
        .create_watch(alice, alice_mail, None, None, None)
        .await
        .expect("alice's watch");
    let bob_watch = w
        .svc
        .create_watch(bob, bob_mail, None, None, None)
        .await
        .expect("bob's watch");
    let alices = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bobs = common::create_test_workflow(&w.pool, bob, "bobs").await;
    assert_eq!(alice_watch.workflow_id, None, "a new watch starts nothing");

    // Her own workflow, her own watch.
    let bound = bind_channel_workflow(&w.pool, alice, alice_watch.id, Some(alices))
        .await
        .expect("bind");
    assert_eq!(bound.workflow_id, Some(alices));
    assert_eq!(stored_binding(&w, alice).await, Some(alices));
    assert_eq!(audit(&w, alice, "workflow_bound").await.len(), 1);

    // Bob's workflow on her watch: refused, said the way a missing one is,
    // and her binding is what it was.
    assert_eq!(
        bind_channel_workflow(&w.pool, alice, alice_watch.id, Some(bobs))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::WorkflowNotBindable
    );
    assert_eq!(
        bind_channel_workflow(&w.pool, alice, alice_watch.id, Some(Uuid::new_v4()))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::WorkflowNotBindable
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alices));

    // Her workflow on Bob's watch: his watch is not hers to bind, and it is
    // left with no binding. Nor may Bob point his watch at her workflow.
    assert_eq!(
        bind_channel_workflow(&w.pool, alice, bob_watch.id, Some(alices))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::ChannelNotFound
    );
    assert_eq!(
        bind_channel_workflow(&w.pool, bob, bob_watch.id, Some(alices))
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
    let cleared = bind_channel_workflow(&w.pool, alice, alice_watch.id, None)
        .await
        .expect("clear");
    assert_eq!(cleared.workflow_id, None);
    assert_eq!(stored_binding(&w, alice).await, None);
    assert_eq!(audit(&w, alice, "workflow_unbound").await.len(), 1);
}

/// A create may name a workflow. Until 2026-10-12 it copied whatever id it
/// was given into the row; the first thing to ask whose workflow it was was a
/// push, so a watch could be created that would never start anything and said
/// nothing about it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_create_binds_only_the_callers_own_workflow() {
    let w = world().await;
    let (alice, alice_mail) = user_with_mailbox(&w).await;
    let (bob, _) = user_with_mailbox(&w).await;
    let alices = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bobs = common::create_test_workflow(&w.pool, bob, "bobs").await;

    // Bob's workflow, and one that does not exist: refused before Google is
    // asked for anything, in the words a missing workflow gets, nothing stored.
    for not_hers in [bobs, Uuid::new_v4()] {
        let refused = w
            .svc
            .create_watch(alice, alice_mail, None, Some(not_hers), None)
            .await
            .unwrap_err();
        assert!(
            matches!(
                refused,
                CreateWatchError::WorkflowBinding(BindWorkflowRefusal::WorkflowNotBindable)
            ),
            "{refused:?}"
        );
        assert_eq!(refused.user_facing_message(), "No such workflow.");
        assert_eq!(refused.status_code(), axum::http::StatusCode::NOT_FOUND);
    }
    assert_eq!(w.google.watches.load(Ordering::SeqCst), 0);
    assert_eq!(watch_rows(&w, alice).await, 0);

    // Her own: created and bound.
    let created = w
        .svc
        .create_watch(alice, alice_mail, None, Some(alices), None)
        .await
        .expect("create with her workflow");
    assert_eq!(created.workflow_id, Some(alices));
    assert_eq!(stored_binding(&w, alice).await, Some(alices));

    // Re-pointing the existing watch at Bob's workflow is refused the same
    // way, and the binding is what it was.
    assert!(matches!(
        w.svc
            .create_watch(alice, alice_mail, None, Some(bobs), None)
            .await
            .unwrap_err(),
        CreateWatchError::WorkflowBinding(BindWorkflowRefusal::WorkflowNotBindable)
    ));
    assert_eq!(stored_binding(&w, alice).await, Some(alices));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renewal_and_a_second_create_keep_the_binding() {
    let w = world().await;
    let (user, integration) = user_with_mailbox(&w).await;
    let watch = w
        .svc
        .create_watch(user, integration, None, None, None)
        .await
        .expect("watch");
    let workflow = common::create_test_workflow(&w.pool, user, "on-mail").await;
    bind_channel_workflow(&w.pool, user, watch.id, Some(workflow))
        .await
        .expect("bind");

    // The settings page re-points a watch's MODULE by creating it again, and
    // sends no workflow. That is not a request to stop starting the workflow.
    let again = w
        .svc
        .create_watch(user, integration, None, None, None)
        .await
        .expect("second create");
    assert_eq!(again.id, watch.id, "the existing watch is reused");
    assert_eq!(again.workflow_id, Some(workflow));
    assert_eq!(stored_binding(&w, user).await, Some(workflow));

    // A create that names another of the user's workflows re-points it.
    let other = common::create_test_workflow(&w.pool, user, "on-mail-2").await;
    let repointed = w
        .svc
        .create_watch(user, integration, None, Some(other), None)
        .await
        .expect("re-point");
    assert_eq!(repointed.workflow_id, Some(other));

    // A renewal replaces the row: a new id, a new registration, the same binding.
    let renewed = w.svc.renew_watch(user, watch.id).await.expect("renew");
    assert_ne!(renewed.id, watch.id);
    assert_eq!(renewed.workflow_id, Some(other));
    assert_eq!(stored_binding(&w, user).await, Some(other));
    assert_eq!(w.google.watches.load(Ordering::SeqCst), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_on_a_bound_watch_reaches_the_trigger_as_the_watchs_user() {
    let w = world().await;
    let (user, integration) = user_with_mailbox(&w).await;
    let workflow = common::create_test_workflow(&w.pool, user, "on-mail").await;
    let row = w
        .svc
        .create_watch(user, integration, None, Some(workflow), None)
        .await
        .expect("watch");
    let state = mcp_common::mcp_state(w.pool.clone()).await;
    let service = state.execution_orchestration_service.clone();
    let ids = ["18c2f3a4b5d6e7f8", "18c2f3a4b5d6e7f9"];

    // The workflow is switched off: one audit row with a reason from the
    // closed set, and no execution. (Until 2026-10-12 this push went through
    // the route that resumes a run, which does not ask.)
    sqlx::query("UPDATE workflows SET is_enabled = false WHERE id = $1")
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("switch the workflow off");
    assert_eq!(
        start_bound_workflow(&w.pool, Some(&service), user, &row, workflow, &ids).await,
        BoundWorkflowStart::NotStarted("workflow_not_live")
    );
    let rows = audit(&w, user, "workflow_not_started").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (rows[0].0, rows[0].1.as_deref()),
        (false, Some("workflow_not_live"))
    );
    assert_eq!(executions(&w, workflow).await, 0);

    // Switched on: the trigger takes it, as the watch's user, and the
    // execution says what started it. This harness's test workflow has an
    // empty graph and there is no dispatch bus, so the trigger creates the
    // execution and then cannot load the graph: that the push produced an
    // execution for this user's workflow is asserted, what a worker would do
    // with it is not, and the load failure is recorded like any other start
    // that did not happen.
    sqlx::query("UPDATE workflows SET is_enabled = true WHERE id = $1")
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("switch the workflow on");
    assert_eq!(
        start_bound_workflow(&w.pool, Some(&service), user, &row, workflow, &ids).await,
        BoundWorkflowStart::NotStarted("trigger_failed")
    );
    assert_eq!(executions(&w, workflow).await, 1);
    let (owner, started_by): (Uuid, serde_json::Value) = sqlx::query_as(
        "SELECT user_id, provenance->'started_by' FROM workflow_executions WHERE workflow_id = $1",
    )
    .bind(workflow)
    .fetch_one(&w.pool)
    .await
    .expect("the execution");
    assert_eq!(owner, user);
    assert_eq!(
        started_by,
        serde_json::json!({ "kind": "push_channel", "integration": "gmail", "id": row.id.to_string() })
    );
    let not_started_so_far = audit(&w, user, "workflow_not_started").await.len();
    assert_eq!(not_started_so_far, 2);

    // No trigger service wired: said so, not silently nothing.
    assert_eq!(
        start_bound_workflow(&w.pool, None, user, &row, workflow, &ids).await,
        BoundWorkflowStart::NotStarted("trigger_service_not_wired")
    );
    assert_eq!(
        audit(&w, user, "workflow_not_started")
            .await
            .last()
            .unwrap()
            .1
            .as_deref(),
        Some("trigger_service_not_wired")
    );

    // The workflow stops being this user's while the row still names it. The
    // push is the watch user's, so the trigger does not find the workflow: a
    // binding is never what makes a workflow startable.
    let other = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(other)
    .bind(format!("{other}@gmail-workflow-binding.test"))
    .execute(&w.pool)
    .await
    .expect("other user");
    sqlx::query("UPDATE workflows SET user_id = $1 WHERE id = $2")
        .bind(other)
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("move the workflow");
    assert_eq!(
        start_bound_workflow(&w.pool, Some(&service), user, &row, workflow, &ids).await,
        BoundWorkflowStart::NotStarted("workflow_not_found")
    );
    assert_eq!(
        audit(&w, user, "workflow_not_started").await.len(),
        not_started_so_far + 2
    );
    assert_eq!(executions(&w, workflow).await, 1, "no second execution");
}

/// The path the MCP tools take: by integration name, through the inventory
/// set. Until 2026-10-12 this inventory reported every Gmail watch as
/// starting no workflow, bound or not, and refused to bind one.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_inventory_tells_and_sets_the_binding_under_the_same_rules() {
    let w = world().await;
    let (alice, alice_mail) = user_with_mailbox(&w).await;
    let (bob, _) = user_with_mailbox(&w).await;
    let alices = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bobs = common::create_test_workflow(&w.pool, bob, "bobs").await;
    // Bound at create, the way a watch could always be: the inventory says so.
    let watch = w
        .svc
        .create_watch(alice, alice_mail, None, Some(alices), None)
        .await
        .expect("watch");
    assert_eq!(stored_binding(&w, alice).await, Some(alices));

    let set = PushChannelInventorySet::new(vec![Arc::new(GmailPushChannelInventory::new(
        w.pool.clone(),
    ))]);
    assert_eq!(
        set.bind_workflow("gmail", alice, watch.id, None).await,
        Ok(())
    );
    assert_eq!(stored_binding(&w, alice).await, None);
    assert_eq!(
        set.bind_workflow("gmail", alice, watch.id, Some(alices))
            .await,
        Ok(())
    );
    assert_eq!(
        set.bind_workflow("gmail", alice, watch.id, Some(bobs))
            .await,
        Err(SetRefusal::WorkflowNotBindable)
    );
    assert_eq!(
        set.bind_workflow("gmail", bob, watch.id, Some(bobs)).await,
        Err(SetRefusal::ChannelNotFound),
        "another user cannot bind this watch, even to a workflow of their own"
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alices));
}
