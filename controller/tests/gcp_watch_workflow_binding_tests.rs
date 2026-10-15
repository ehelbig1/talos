//! A Google Cloud push channel that starts a WORKFLOW (2026-10-12).
//!
//! A channel is authenticated by a push token minted for one user's row, so
//! what a push may start is that user's own. The assertions here are on rows:
//!
//! * a workflow is bound only by its owner, to the owner's own channel, and a
//!   refusal changes nothing;
//! * the push stamp — the one path that rewrites a channel's row — keeps the
//!   binding;
//! * a push on a bound channel reaches the trigger service as the channel's
//!   user, a start that is refused is recorded with a reason from a closed
//!   set, and the execution says a Google Cloud push channel started it;
//! * the inventory (what `list_push_channels` and `set_push_channel_workflow`
//!   use) tells and sets the binding under the same rules.
//!
//! A push on a live workflow is driven as far as the execution row the
//! trigger creates for the channel's user; this harness has no dispatch bus
//! and its test workflow has an empty graph, so what a worker then does with
//! it is not. No Redis either: the claim that lets one delivery of an
//! incident start the workflow is not driven here.
//!
//! An assertion never prints a channel row: it carries the push token.
//! `common` harness (a template clone per test).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use sqlx::{Pool, Postgres};
use std::sync::Arc;
use talos_google_cloud::dispatch::{start_bound_workflow, BoundWorkflowStart, PushedIncident};
use talos_google_cloud::integration::GoogleCloudIntegrationService;
use talos_google_cloud::watch::{bind_channel_workflow, BindWorkflowRefusal, GcpWatchService};
use talos_google_cloud::watch_channel_service::GcpPushChannelInventory;
use talos_push_channel_inventory::{
    BindWorkflowRefusal as SetRefusal, PushChannelInventory, PushChannelInventorySet,
};
use uuid::Uuid;

const SA: &str = "pusher@example-project.iam.gserviceaccount.com";

struct World {
    svc: Arc<GcpWatchService>,
    pool: Pool<Postgres>,
    _db: common::TestDb,
}

async fn world() -> World {
    let (pool, db) = common::isolated_db_pool().await;
    let integrations = Arc::new(
        GoogleCloudIntegrationService::new(pool.clone()).expect("gcp integration service"),
    );
    World {
        svc: Arc::new(GcpWatchService::new(pool.clone(), integrations)),
        pool,
        _db: db,
    }
}

/// A user with one connected Google Cloud account and one push channel on
/// it: (user, channel id).
async fn user_with_channel(w: &World) -> (Uuid, Uuid) {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@gcp-workflow-binding.test"))
    .execute(&w.pool)
    .await
    .expect("user");
    let integration = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO google_cloud_integrations (id, user_id, provider_key, tier, is_active) \
         VALUES ($1, $2, $3, 'read', TRUE)",
    )
    .bind(integration)
    .bind(user)
    .bind(Uuid::new_v4())
    .execute(&w.pool)
    .await
    .expect("integration");
    let channel = w
        .svc
        .create_watch(user, integration, SA.to_string(), None, None)
        .await
        .map(|row| row.id)
        .map_err(|e| e.user_facing_message())
        .expect("channel");
    (user, channel)
}

/// The workflow a user's channel names, as the operator inventory reads it
/// (which is also what `list_push_channels` shows).
async fn stored_binding(w: &World, user: Uuid) -> Option<Uuid> {
    let rows = GcpPushChannelInventory::new(w.pool.clone())
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

/// The refusal of a bind, without the row a success carries.
async fn bind(
    w: &World,
    user: Uuid,
    channel: Uuid,
    workflow: Option<Uuid>,
) -> Result<Option<Uuid>, BindWorkflowRefusal> {
    bind_channel_workflow(&w.pool, user, channel, workflow)
        .await
        .map(|row| row.workflow_id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workflow_is_bound_only_by_its_owner_to_the_owners_own_channel() {
    let w = world().await;
    let (alice, alice_channel) = user_with_channel(&w).await;
    let (bob, bob_channel) = user_with_channel(&w).await;
    let alices = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bobs = common::create_test_workflow(&w.pool, bob, "bobs").await;
    assert_eq!(
        stored_binding(&w, alice).await,
        None,
        "a new channel starts nothing"
    );

    // Her own workflow, her own channel.
    assert_eq!(
        bind(&w, alice, alice_channel, Some(alices)).await,
        Ok(Some(alices))
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alices));
    assert_eq!(audit(&w, alice, "workflow_bound").await.len(), 1);

    // Bob's workflow on her channel: refused, said the way a missing one is,
    // and her binding is what it was.
    assert_eq!(
        bind(&w, alice, alice_channel, Some(bobs)).await,
        Err(BindWorkflowRefusal::WorkflowNotBindable)
    );
    assert_eq!(
        bind(&w, alice, alice_channel, Some(Uuid::new_v4())).await,
        Err(BindWorkflowRefusal::WorkflowNotBindable)
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alices));

    // Her workflow on Bob's channel: his channel is not hers to bind, and it
    // is left with no binding. Nor may Bob point his channel at her workflow.
    assert_eq!(
        bind(&w, alice, bob_channel, Some(alices)).await,
        Err(BindWorkflowRefusal::ChannelNotFound)
    );
    assert_eq!(
        bind(&w, bob, bob_channel, Some(alices)).await,
        Err(BindWorkflowRefusal::WorkflowNotBindable)
    );
    assert_eq!(stored_binding(&w, bob).await, None);
    assert_eq!(
        bind(&w, alice, Uuid::new_v4(), Some(alices)).await,
        Err(BindWorkflowRefusal::ChannelNotFound)
    );

    // Clearing is the owner's too.
    assert_eq!(bind(&w, alice, alice_channel, None).await, Ok(None));
    assert_eq!(stored_binding(&w, alice).await, None);
    assert_eq!(audit(&w, alice, "workflow_unbound").await.len(), 1);
}

/// The owner's own workflow, archived or disabled, is refused: the trigger
/// would refuse every push it started, so the binding would never fire
/// (security review 2026-10-14, F-7).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_archived_workflow_cannot_be_bound() {
    let w = world().await;
    let (alice, channel) = user_with_channel(&w).await;
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
            bind(&w, alice, channel, Some(not_startable)).await,
            Err(BindWorkflowRefusal::WorkflowNotBindable)
        );
    }
    assert_eq!(stored_binding(&w, alice).await, None);
    assert!(audit(&w, alice, "workflow_bound").await.is_empty());
}

/// F-5: a push signed for the wrong service account is a refusal anyone with
/// a Google token can provoke, so it writes at most one audit row a day per
/// channel; a second channel gets its own row.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rejected_push_writes_at_most_one_row_a_day_per_channel() {
    use talos_integration_helpers::audit::{insert_channel_audit_once_per_day, ChannelAuditEvent};
    let w = world().await;
    let (user, channel) = user_with_channel(&w).await;
    let event = || ChannelAuditEvent {
        integration_id: None,
        user_id: user,
        event_type: "gcp_channel_push_rejected",
        target: Some(SA),
        success: false,
        error_message: Some("service account mismatch"),
        metadata: serde_json::json!({}),
    };
    let mut written = Vec::new();
    for _ in 0..5 {
        written.push(
            insert_channel_audit_once_per_day(&w.pool, event(), channel)
                .await
                .expect("insert"),
        );
    }
    assert_eq!(written, [true, false, false, false, false]);
    assert_eq!(audit(&w, user, "gcp_channel_push_rejected").await.len(), 1);
    let other = Uuid::new_v4();
    assert!(insert_channel_audit_once_per_day(&w.pool, event(), other)
        .await
        .expect("insert"));
    assert_eq!(audit(&w, user, "gcp_channel_push_rejected").await.len(), 2);
    // The owner's view reads the row by its channel.
    let tagged: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM google_calendar_audit_log \
         WHERE user_id = $1 AND metadata->>'channel_uuid' = $2 \
           AND event_type = 'gcp_channel_push_rejected'",
    )
    .bind(user)
    .bind(channel.to_string())
    .fetch_one(&w.pool)
    .await
    .expect("count");
    assert_eq!(tagged, 1);
}

/// Nothing replaces a Google Cloud channel's row (there is no renewal). The
/// one path that rewrites it is the stamp a verified push leaves, and a
/// binding that vanished at the first push would fail nothing and start
/// nothing afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_push_stamp_keeps_the_binding_and_the_bind_keeps_the_stamp() {
    let w = world().await;
    let (user, channel) = user_with_channel(&w).await;
    let workflow = common::create_test_workflow(&w.pool, user, "on-incident").await;
    bind(&w, user, channel, Some(workflow)).await.expect("bind");

    w.svc
        .record_push_received(user, channel)
        .await
        .expect("stamp");
    let rows = GcpPushChannelInventory::new(w.pool.clone())
        .list_channels(user)
        .await
        .expect("list");
    assert_eq!(rows[0].workflow_id, Some(workflow));
    let stamped = rows[0].last_event_at.expect("the push was stamped");

    // And the other way: a bind is not a push, so the stamp is what it was.
    bind(&w, user, channel, None).await.expect("clear");
    let rows = GcpPushChannelInventory::new(w.pool.clone())
        .list_channels(user)
        .await
        .expect("list");
    assert_eq!(rows[0].workflow_id, None);
    assert_eq!(rows[0].last_event_at, Some(stamped));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_push_on_a_bound_channel_reaches_the_trigger_as_the_channels_user() {
    let w = world().await;
    let (user, channel) = user_with_channel(&w).await;
    let workflow = common::create_test_workflow(&w.pool, user, "on-incident").await;
    let row = bind_channel_workflow(&w.pool, user, channel, Some(workflow))
        .await
        .map_err(|r| r.user_facing_message())
        .expect("bind");
    let state = mcp_common::mcp_state(w.pool.clone()).await;
    let service = state.execution_orchestration_service.clone();
    let incident = serde_json::json!({
        "incident_id": "0.abc123def456",
        "state": "open",
        "summary": "p99 latency for checkout is above 2s",
    });
    let pushed = PushedIncident {
        incident: &incident,
        incident_id: "0.abc123def456",
        state: "open",
        pubsub_message_id: "9876543210",
    };
    let start = |service| {
        let (pool, row, pushed) = (w.pool.clone(), &row, &pushed);
        async move { start_bound_workflow(&pool, service, None, user, row, workflow, pushed).await }
    };

    // The workflow is switched off: one audit row with a reason from the
    // closed set, and no execution.
    sqlx::query("UPDATE workflows SET is_enabled = false WHERE id = $1")
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("switch the workflow off");
    assert_eq!(
        start(Some(&service)).await,
        BoundWorkflowStart::NotStarted("workflow_not_live")
    );
    let rows = audit(&w, user, "workflow_not_started").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        (rows[0].0, rows[0].1.as_deref()),
        (false, Some("workflow_not_live"))
    );
    assert_eq!(executions(&w, workflow).await, 0);

    // Switched on: the trigger takes it, as the channel's user, and the
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
        start(Some(&service)).await,
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
        serde_json::json!({ "kind": "push_channel", "integration": "google_cloud", "id": channel.to_string() })
    );
    let not_started_so_far = audit(&w, user, "workflow_not_started").await.len();
    assert_eq!(not_started_so_far, 2);

    // No trigger service wired: said so, not silently nothing.
    assert_eq!(
        start(None).await,
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
    // push is the channel user's, so the trigger does not find the workflow:
    // a binding is never what makes a workflow startable.
    let other = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(other)
    .bind(format!("{other}@gcp-workflow-binding.test"))
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
        start(Some(&service)).await,
        BoundWorkflowStart::NotStarted("workflow_not_found")
    );
    assert_eq!(
        audit(&w, user, "workflow_not_started").await.len(),
        not_started_so_far + 2
    );
    assert_eq!(executions(&w, workflow).await, 1, "no second execution");

    // Nothing the incident says, and no push token, reached the audit log.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM google_calendar_audit_log WHERE metadata::text LIKE '%latency%' \
         OR coalesce(error_message, '') LIKE '%latency%' OR metadata::text LIKE '%' || $1 || '%'",
    )
    .bind(&row.push_token)
    .fetch_one(&w.pool)
    .await
    .expect("scan audit");
    assert_eq!(leaked, 0);
}

/// The path the MCP tools take: by integration name, through the inventory
/// set.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_inventory_tells_and_sets_the_binding_under_the_same_rules() {
    let w = world().await;
    let (alice, channel) = user_with_channel(&w).await;
    let (bob, _) = user_with_channel(&w).await;
    let alices = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bobs = common::create_test_workflow(&w.pool, bob, "bobs").await;
    let set =
        PushChannelInventorySet::new(vec![Arc::new(GcpPushChannelInventory::new(w.pool.clone()))]);

    assert_eq!(
        set.bind_workflow("google_cloud", alice, channel, Some(alices))
            .await,
        Ok(())
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alices));
    assert_eq!(
        set.bind_workflow("google_cloud", alice, channel, Some(bobs))
            .await,
        Err(SetRefusal::WorkflowNotBindable)
    );
    assert_eq!(
        set.bind_workflow("google_cloud", bob, channel, Some(bobs))
            .await,
        Err(SetRefusal::ChannelNotFound),
        "another user cannot bind this channel, even to a workflow of their own"
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alices));
    assert_eq!(
        set.bind_workflow("google_cloud", alice, channel, None)
            .await,
        Ok(())
    );
    assert_eq!(stored_binding(&w, alice).await, None);
}
