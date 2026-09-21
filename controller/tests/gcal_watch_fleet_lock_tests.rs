//! Google Calendar watch create / renew with TWO controller replicas.
//!
//! `events.watch` mints a NEW Google-side channel on every call, so a second
//! call for the same calendar leaves an orphaned channel pushing until it
//! expires. Two `GoogleCalendarService`s on two pools of one database stand
//! in for two replicas; an in-process HTTP server stands in for Google and
//! counts what it is asked to do.
mod common;

use axum::{extract::State, routing::post, Json, Router};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use talos_google_calendar::GoogleCalendarService;
use uuid::Uuid;

const CALENDAR: &str = "primary";
const WEBHOOK: &str = "https://hooks.example.com/api/google-calendar/webhook";

#[derive(Default)]
struct FakeGoogle {
    watches: AtomicUsize,
    stops: AtomicUsize,
}

async fn events_watch(
    State(g): State<Arc<FakeGoogle>>,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    let n = g.watches.fetch_add(1, Ordering::SeqCst) + 1;
    // Long enough that a second, unserialized caller is certainly inside its
    // own "no channel yet" window while this one is still registering.
    tokio::time::sleep(Duration::from_millis(400)).await;
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

async fn fake_google() -> (Arc<FakeGoogle>, String) {
    let state = Arc::new(FakeGoogle::default());
    let app = Router::new()
        .route("/calendars/{calendar}/events/watch", post(events_watch))
        .route("/channels/stop", post(channels_stop))
        .with_state(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (state, base)
}

struct Fleet {
    a: Arc<GoogleCalendarService>,
    b: Arc<GoogleCalendarService>,
    pool: sqlx::Pool<sqlx::Postgres>,
    user: Uuid,
    integration: Uuid,
    google: Arc<FakeGoogle>,
    _db: common::TestDb,
}

async fn replica(pool: sqlx::Pool<sqlx::Postgres>, base: &str) -> Arc<GoogleCalendarService> {
    let secrets =
        Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("initialize secrets");
    let svc = GoogleCalendarService::new(pool, secrets);
    svc.with_worker_shared_key(vec![7_u8; 32])
        .expect("shared key");
    svc.with_api_base_url_for_tests(base);
    Arc::new(svc)
}

async fn fleet() -> Fleet {
    let (pool, db) = common::isolated_db_pool().await;
    let (google, base) = fake_google().await;
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@gcal-fleet-lock.test"))
    .execute(&pool)
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
    .execute(&pool)
    .await
    .expect("integration");

    // A second pool on the same database: the second controller replica.
    let pool_b = sqlx::postgres::PgPoolOptions::new()
        .max_connections(8)
        .connect_with((*pool.connect_options()).clone())
        .await
        .expect("second pool");
    let a = replica(pool.clone(), &base).await;
    let b = replica(pool_b, &base).await;

    // The access token the create path reads from the vault. A test value.
    let path = format!("oauth/google_calendar/{user}/{account}/access_token");
    controller::secrets::SecretsManager::new(pool.clone())
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

    Fleet {
        a,
        b,
        pool,
        user,
        integration,
        google,
        _db: db,
    }
}

async fn channel_rows(f: &Fleet) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM integration_state WHERE integration_name = 'gcal' AND user_id = $1",
    )
    .bind(f.user)
    .fetch_one(&f.pool)
    .await
    .expect("count channel rows")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_replicas_creating_one_calendars_watch_register_with_google_once() {
    let f = fleet().await;
    let (a, b) = (f.a.clone(), f.b.clone());
    let integration = f.integration;
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move {
            a.create_watch_channel(integration, CALENDAR, WEBHOOK, None)
                .await
        }),
        tokio::spawn(async move {
            b.create_watch_channel(integration, CALENDAR, WEBHOOK, None)
                .await
        }),
    );
    let ca = ra.expect("join a").expect("create a");
    let cb = rb.expect("join b").expect("create b");

    assert_eq!(
        f.google.watches.load(Ordering::SeqCst),
        1,
        "Google was asked for two channels"
    );
    assert_eq!(
        ca.channel_id, cb.channel_id,
        "the second replica must reuse the first's channel"
    );
    assert_eq!(channel_rows(&f).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_replicas_renewing_one_channel_replace_it_once() {
    let f = fleet().await;
    let first =
        f.a.create_watch_channel(f.integration, CALENDAR, WEBHOOK, None)
            .await
            .expect("create");
    assert_eq!(f.google.watches.load(Ordering::SeqCst), 1);

    let (a, b, user, id) = (f.a.clone(), f.b.clone(), f.user, first.id);
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move { a.renew_watch_channel(user, id).await }),
        tokio::spawn(async move { b.renew_watch_channel(user, id).await }),
    );
    let na = ra.expect("join a").expect("renew a");
    let nb = rb.expect("join b").expect("renew b");

    assert_eq!(
        f.google.watches.load(Ordering::SeqCst),
        2,
        "one create plus ONE renewal; a third call is an orphaned Google channel"
    );
    assert_eq!(
        f.google.stops.load(Ordering::SeqCst),
        1,
        "the old channel is stopped once"
    );
    assert_eq!(
        na.channel_id, nb.channel_id,
        "the loser is handed the winner's new channel"
    );
    assert_ne!(na.channel_id, first.channel_id);
    assert_eq!(channel_rows(&f).await, 1);
}

/// The stale-row half on its own: ONE replica, two concurrent renewals. The
/// process-local mutex already serialized these, and the second still acted
/// on the row it had read before waiting.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renewal_that_waited_does_not_act_on_the_row_it_read_before_waiting() {
    let f = fleet().await;
    let first =
        f.a.create_watch_channel(f.integration, CALENDAR, WEBHOOK, None)
            .await
            .expect("create");
    let (a1, a2, user, id) = (f.a.clone(), f.a.clone(), f.user, first.id);
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move { a1.renew_watch_channel(user, id).await }),
        tokio::spawn(async move { a2.renew_watch_channel(user, id).await }),
    );
    let n1 = r1.expect("join").expect("renew 1");
    let n2 = r2.expect("join").expect("renew 2");
    assert_eq!(f.google.watches.load(Ordering::SeqCst), 2);
    assert_eq!(n1.channel_id, n2.channel_id);
    assert_eq!(channel_rows(&f).await, 1);

    // A channel that never existed is still "not found", not a reuse.
    let missing = f.a.renew_watch_channel(f.user, Uuid::new_v4()).await;
    assert!(missing.is_err());
}

// ── The lock itself (`CreateLockMap::acquire_fleet`) ───────────────────────

use talos_integration_helpers::state_store::CreateLockMap;

async fn second_pool(pool: &sqlx::Pool<sqlx::Postgres>) -> sqlx::Pool<sqlx::Postgres> {
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(4)
        .connect_with((*pool.connect_options()).clone())
        .await
        .expect("second pool")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_fleet_lock_excludes_another_replica_until_the_guard_drops() {
    let (pool_a, _db) = common::isolated_db_pool().await;
    let pool_b = second_pool(&pool_a).await;
    // Two maps = two processes: their local mutexes know nothing of each other.
    let (map_a, map_b): (CreateLockMap<u8>, CreateLockMap<u8>) =
        (CreateLockMap::new(), CreateLockMap::new());

    let guard = map_a
        .acquire_fleet(&pool_a, 1, "test:one")
        .await
        .expect("a");
    let waiter = tokio::spawn(async move {
        let started = std::time::Instant::now();
        let _g = map_b
            .acquire_fleet(&pool_b, 1, "test:one")
            .await
            .expect("b");
        started.elapsed()
    });
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert!(
        !waiter.is_finished(),
        "the second replica got the lock while the first held it"
    );

    // A different key is not blocked by this one.
    let other = tokio::time::timeout(
        Duration::from_secs(5),
        map_a.acquire_fleet(&pool_a, 2, "test:two"),
    )
    .await
    .expect("an unrelated key must not wait")
    .expect("other key");
    drop(other);

    drop(guard);
    let waited = tokio::time::timeout(Duration::from_secs(10), waiter)
        .await
        .expect("the waiter proceeds once the guard is dropped")
        .expect("join");
    assert!(waited >= Duration::from_millis(500), "waited {waited:?}");
}

#[tokio::test]
async fn an_unreachable_database_is_an_error_not_an_unlocked_create() {
    let dead = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_millis(250))
        .connect_lazy("postgres://127.0.0.1:1/talos_never_connects")
        .expect("lazy pool");
    let map: CreateLockMap<u8> = CreateLockMap::new();
    assert!(map.acquire_fleet(&dead, 1, "test:dead").await.is_err());
    // …and the failed attempt did not leave the local mutex held.
    let again = tokio::time::timeout(Duration::from_secs(2), map.acquire(1)).await;
    assert!(
        again.is_ok(),
        "a failed fleet acquire leaked the process-local lock"
    );
}
