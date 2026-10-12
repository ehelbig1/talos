//! Creating and stopping a Google Calendar watch channel without the
//! settings page (2026-10-12): the path behind the MCP tools
//! `create_gcal_watch_channel` and `delete_gcal_watch_channel`.
//!
//! The assertions are on rows and on what Google was asked:
//!
//! * a channel is made only on the caller's own connection, and a connection
//!   that is another user's is "no such connection" with Google not asked;
//! * with one connection none need be named; with several, the refusal names
//!   the caller's own and nothing is made;
//! * a calendar that is already watched is handed back as it is — its module
//!   and workflow bindings are what they were, and Google is not asked again;
//! * an address Google cannot deliver to is refused before Google is asked;
//! * a channel is stopped only by its owner, and one that is not there is
//!   said to be not there.
//!
//! An in-process HTTP server stands in for Google. `common` harness (a
//! template clone per test).

mod common;

use axum::{extract::State, routing::post, Json, Router};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use talos_google_calendar::provision::{GcalPushProvisioner, ProvisionError};
use talos_google_calendar::watch::bind_channel_workflow;
use talos_google_calendar::watch_channel_service::GcalPushChannelInventory;
use talos_google_calendar::GoogleCalendarService;
use talos_push_channel_inventory::{
    ProvisionRefusalKind, PushChannelInventory, PushChannelInventorySet, PushChannelRow,
};
use uuid::Uuid;

const WEBHOOK: &str = "https://hooks.example.com/api/google-calendar/webhook";

struct FakeGoogle {
    watches: AtomicUsize,
    stops: AtomicUsize,
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

async fn channels_stop(State(g): State<Arc<FakeGoogle>>) -> axum::http::StatusCode {
    g.stops.fetch_add(1, Ordering::SeqCst);
    axum::http::StatusCode::NO_CONTENT
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
        stops: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/calendars/{calendar}/events/watch", post(events_watch))
        .route("/channels/stop", post(channels_stop))
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
    svc.with_worker_shared_key(vec![7_u8; 32])
        .expect("shared key");
    svc.with_api_base_url_for_tests(&base);
    World {
        svc: Arc::new(svc),
        pool,
        google,
        _db: db,
    }
}

async fn user(w: &World) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@gcal-provision.test"))
    .execute(&w.pool)
    .await
    .expect("user");
    user
}

/// One more connected calendar account for `user`: the integration's id.
async fn connection(w: &World, user: Uuid) -> Uuid {
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
    integration
}

async fn channels(w: &World, user: Uuid) -> Vec<PushChannelRow> {
    GcalPushChannelInventory::new(w.pool.clone())
        .list_channels(user)
        .await
        .expect("list channels")
}

fn asked(w: &World) -> usize {
    w.google.watches.load(Ordering::SeqCst)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_channel_is_made_only_on_the_callers_own_connection() {
    let w = world().await;
    let (alice, bob) = (user(&w).await, user(&w).await);
    let alices = connection(&w, alice).await;

    // Bob names Alice's connection: it is not one of his. Nothing is asked of
    // Google and nobody has a channel.
    assert_eq!(
        w.svc
            .provision_watch_channel_at(bob, Some(alices), None, WEBHOOK)
            .await
            .unwrap_err(),
        ProvisionError::ConnectionNotFound
    );
    // He has none of his own, and says nothing about hers.
    assert_eq!(
        w.svc
            .provision_watch_channel_at(bob, None, None, WEBHOOK)
            .await
            .unwrap_err(),
        ProvisionError::NoConnection
    );
    assert_eq!(asked(&w), 0);
    assert!(channels(&w, alice).await.is_empty());
    assert!(channels(&w, bob).await.is_empty());

    // Alice, naming nothing: her one connection, her primary calendar.
    let (made, created) = w
        .svc
        .provision_watch_channel_at(alice, None, None, WEBHOOK)
        .await
        .expect("alice's channel");
    assert!(created);
    assert_eq!(
        (made.integration_id, made.calendar_id.as_str()),
        (alices, "primary")
    );
    assert_eq!(asked(&w), 1);
    let hers = channels(&w, alice).await;
    assert_eq!(hers.len(), 1);
    assert_eq!(hers[0].channel_id, made.id);
    assert!(channels(&w, bob).await.is_empty());

    // A connection she disconnected is not one to make a channel on.
    let gone = connection(&w, alice).await;
    sqlx::query("UPDATE google_calendar_integrations SET is_active = false WHERE id = $1")
        .bind(gone)
        .execute(&w.pool)
        .await
        .expect("deactivate");
    assert_eq!(
        w.svc
            .provision_watch_channel_at(alice, Some(gone), None, WEBHOOK)
            .await
            .unwrap_err(),
        ProvisionError::ConnectionNotFound
    );
    assert_eq!(asked(&w), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn with_several_connections_one_must_be_named_and_the_refusal_names_only_the_callers() {
    let w = world().await;
    let (alice, bob) = (user(&w).await, user(&w).await);
    let (first, second) = (connection(&w, alice).await, connection(&w, alice).await);
    let bobs = connection(&w, bob).await;

    let refused = w
        .svc
        .provision_watch_channel_at(alice, None, None, WEBHOOK)
        .await
        .unwrap_err();
    let ProvisionError::SeveralConnections(mut named) = refused.clone() else {
        panic!("expected a which-one refusal: {refused:?}");
    };
    named.sort();
    let mut expected = vec![first, second];
    expected.sort();
    assert_eq!(named, expected);
    assert!(!refused.user_facing_message().contains(&bobs.to_string()));
    assert_eq!(asked(&w), 0);

    // Named: that one, and a calendar other than the primary.
    let (made, created) = w
        .svc
        .provision_watch_channel_at(
            alice,
            Some(second),
            Some("family@group.calendar.google.com"),
            WEBHOOK,
        )
        .await
        .expect("named connection");
    assert!(created);
    assert_eq!(
        (made.integration_id, made.calendar_id.as_str()),
        (second, "family@group.calendar.google.com")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_calendar_already_watched_is_handed_back_as_it_is() {
    let w = world().await;
    let alice = user(&w).await;
    let integration = connection(&w, alice).await;
    let module = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world) \
         VALUES ($1, $2, 'on-change', 'sandbox', 'http-node')",
    )
    .bind(module)
    .bind(alice)
    .execute(&w.pool)
    .await
    .expect("module");
    // A channel made the way the module editor makes one, bound to a module,
    // and then bound to a workflow.
    let existing = w
        .svc
        .create_watch_channel(integration, "primary", WEBHOOK, Some(module))
        .await
        .expect("existing channel");
    let workflow = common::create_test_workflow(&w.pool, alice, "on-change").await;
    bind_channel_workflow(&w.pool, alice, existing.id, Some(workflow))
        .await
        .expect("bind");
    assert_eq!(asked(&w), 1);

    let (again, created) = w
        .svc
        .provision_watch_channel_at(alice, None, None, WEBHOOK)
        .await
        .expect("provision an existing channel");
    assert!(!created);
    assert_eq!(again.id, existing.id);
    assert_eq!(asked(&w), 1, "Google was asked to watch the calendar again");
    let rows = channels(&w, alice).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].module_id, rows[0].workflow_id),
        (Some(module), Some(workflow)),
        "an existing channel's bindings were changed by asking for it again"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_google_could_not_use_is_refused_before_google_is_asked() {
    let w = world().await;
    let alice = user(&w).await;
    connection(&w, alice).await;

    for address in [
        "http://hooks.example.com/api/google-calendar/webhook",
        "https://localhost:8000/api/google-calendar/webhook",
        "http://127.0.0.1:8000/api/google-calendar/webhook",
    ] {
        assert_eq!(
            w.svc
                .provision_watch_channel_at(alice, None, None, address)
                .await
                .unwrap_err(),
            ProvisionError::NotDeliverable,
            "{address}"
        );
    }
    for calendar in ["primary/events/watch", "a b", ""] {
        assert_eq!(
            w.svc
                .provision_watch_channel_at(alice, None, Some(calendar), WEBHOOK)
                .await
                .unwrap_err(),
            ProvisionError::InvalidTarget("calendar_id"),
            "{calendar:?}"
        );
    }
    assert_eq!(asked(&w), 0);
    assert!(channels(&w, alice).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_channel_is_stopped_only_by_its_owner() {
    let w = world().await;
    let (alice, bob) = (user(&w).await, user(&w).await);
    connection(&w, alice).await;
    let (made, _) = w
        .svc
        .provision_watch_channel_at(alice, None, None, WEBHOOK)
        .await
        .expect("channel");

    // Bob: no such channel, and hers is still there and still Google's.
    assert_eq!(
        w.svc.remove_watch_channel(bob, made.id).await.unwrap_err(),
        ProvisionError::ChannelNotFound
    );
    assert_eq!(channels(&w, alice).await.len(), 1);
    assert_eq!(w.google.stops.load(Ordering::SeqCst), 0);

    // Alice: stopped at Google and gone here. Again: said to be gone.
    w.svc
        .remove_watch_channel(alice, made.id)
        .await
        .expect("stop");
    assert!(channels(&w, alice).await.is_empty());
    assert_eq!(w.google.stops.load(Ordering::SeqCst), 1);
    assert_eq!(
        w.svc
            .remove_watch_channel(alice, made.id)
            .await
            .unwrap_err(),
        ProvisionError::ChannelNotFound
    );
    assert_eq!(w.google.stops.load(Ordering::SeqCst), 1);
}

/// The path the MCP tools take: by integration name, through the set, with
/// the connection as the caller wrote it and the calendar as the resource.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_set_creates_and_deletes_by_integration_name() {
    let w = world().await;
    let (alice, bob) = (user(&w).await, user(&w).await);
    let integration = connection(&w, alice).await;
    let set = PushChannelInventorySet::new(vec![Arc::new(GcalPushChannelInventory::new(
        w.pool.clone(),
    ))])
    .with_provisioners(vec![Arc::new(
        GcalPushProvisioner::new(w.svc.clone()).with_webhook_url_for_tests(WEBHOOK),
    )]);

    // What is not an id is refused as the caller's mistake, not looked up.
    let not_an_id = set
        .create_channel_on("gcal", alice, Some("my work calendar"), None)
        .await
        .unwrap_err();
    assert_eq!(not_an_id.kind, ProvisionRefusalKind::Refused);
    assert_eq!(not_an_id.message, "Invalid 'integration_id'.");
    assert_eq!(
        set.create_channel_on("gcal", bob, Some(&integration.to_string()), None)
            .await
            .unwrap_err()
            .kind,
        ProvisionRefusalKind::NotFound
    );
    assert_eq!(asked(&w), 0);

    let made = set
        .create_channel_on(
            "gcal",
            alice,
            Some(&integration.to_string()),
            Some("primary"),
        )
        .await
        .expect("create");
    assert!(made.created);
    assert_eq!(
        (made.integration, made.display_name.as_str()),
        ("gcal", "primary")
    );
    assert!(made.expires_at.is_some());
    assert_eq!(channels(&w, alice).await[0].channel_id, made.channel_id);
    // The plain create is the same thing on the primary calendar.
    let same = set
        .create_channel("gcal", alice, None)
        .await
        .expect("again");
    assert_eq!((same.channel_id, same.created), (made.channel_id, false));

    assert_eq!(
        set.delete_channel("gcal", bob, made.channel_id)
            .await
            .unwrap_err()
            .kind,
        ProvisionRefusalKind::NotFound
    );
    assert_eq!(
        set.delete_channel("gcal", alice, made.channel_id).await,
        Ok(())
    );
    assert!(channels(&w, alice).await.is_empty());
}
