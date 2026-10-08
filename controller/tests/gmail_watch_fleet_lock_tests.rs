//! Gmail watch create / renew with TWO controller replicas.
//!
//! `users.watch` registers the mailbox's push subscription; `users.stop`
//! ends it — every subscription of that mailbox, not one channel. Two
//! `GmailWatchService`s on two pools of one database stand in for two
//! replicas; an in-process HTTP server stands in for Google and counts what
//! it is asked to do.
mod common;

use axum::{extract::State, routing::post, Json, Router};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use talos_gmail::watch::GmailWatchService;
use talos_gmail::GmailIntegrationService;
use uuid::Uuid;

const EMAIL: &str = "fleet-lock@example.com";
const TOPIC: &str = "projects/example/topics/gmail";

struct FakeGoogle {
    watches: AtomicUsize,
    stops: AtomicUsize,
    /// From this `users.watch` call on (1-based; 0 = never), a call does not
    /// answer until the test adds a permit to `release`.
    hold_from_watch: AtomicUsize,
    release: tokio::sync::Semaphore,
}

async fn users_watch(State(g): State<Arc<FakeGoogle>>) -> Json<serde_json::Value> {
    let n = g.watches.fetch_add(1, Ordering::SeqCst) + 1;
    let hold_from = g.hold_from_watch.load(Ordering::SeqCst);
    if hold_from != 0 && n >= hold_from {
        g.release
            .acquire()
            .await
            .expect("the gate is never closed")
            .forget();
    } else {
        // Long enough that a second, unserialized caller is certainly inside
        // its own "no watch yet" window while this one is still registering.
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    let expiration = (chrono::Utc::now() + chrono::Duration::days(7)).timestamp_millis();
    Json(serde_json::json!({
        "historyId": (1000 + n).to_string(),
        "expiration": expiration.to_string(),
    }))
}

async fn users_stop(State(g): State<Arc<FakeGoogle>>) -> axum::http::StatusCode {
    g.stops.fetch_add(1, Ordering::SeqCst);
    axum::http::StatusCode::NO_CONTENT
}

async fn fake_google() -> (Arc<FakeGoogle>, String) {
    let state = Arc::new(FakeGoogle {
        watches: AtomicUsize::new(0),
        stops: AtomicUsize::new(0),
        hold_from_watch: AtomicUsize::new(0),
        release: tokio::sync::Semaphore::new(0),
    });
    let app = Router::new()
        .route("/users/me/watch", post(users_watch))
        .route("/users/me/stop", post(users_stop))
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
    a: Arc<GmailWatchService>,
    b: Arc<GmailWatchService>,
    pool: sqlx::Pool<sqlx::Postgres>,
    user: Uuid,
    integration: Uuid,
    google: Arc<FakeGoogle>,
    _db: common::TestDb,
}

async fn replica(pool: sqlx::Pool<sqlx::Postgres>, base: &str) -> Arc<GmailWatchService> {
    let secrets =
        Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("initialize secrets");
    let integrations = Arc::new(
        GmailIntegrationService::new(pool.clone())
            .expect("gmail integrations")
            .with_secrets_manager(secrets),
    );
    Arc::new(
        GmailWatchService::new(pool, integrations, TOPIC.to_string(), vec![])
            .with_api_base_url_for_tests(base),
    )
}

async fn fleet() -> Fleet {
    let (pool, db) = common::isolated_db_pool().await;
    let (google, base) = fake_google().await;
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@gmail-fleet-lock.test"))
    .execute(&pool)
    .await
    .expect("user");
    let integration = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO gmail_integrations (id, user_id, email_address, scope, is_active) \
         VALUES ($1, $2, $3, 'gmail.readonly', true)",
    )
    .bind(integration)
    .bind(user)
    .bind(EMAIL)
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

    // The access token the watch paths read from the vault. A test value.
    let path = format!("oauth/gmail/{user}/{EMAIL}/access_token");
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

async fn watch_rows(f: &Fleet) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM integration_state WHERE integration_name = 'gmail' AND user_id = $1",
    )
    .bind(f.user)
    .fetch_one(&f.pool)
    .await
    .expect("count watch rows")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_replicas_creating_one_mailboxs_watch_register_with_google_once() {
    let f = fleet().await;
    let (a, b, user, integration) = (f.a.clone(), f.b.clone(), f.user, f.integration);
    let (ra, rb) = tokio::join!(
        tokio::spawn(async move { a.create_watch(user, integration, None, None, None).await }),
        tokio::spawn(async move { b.create_watch(user, integration, None, None, None).await }),
    );
    let wa = ra.expect("join a").expect("create a");
    let wb = rb.expect("join b").expect("create b");

    assert_eq!(
        f.google.watches.load(Ordering::SeqCst),
        1,
        "Google was asked to register the mailbox twice"
    );
    assert_eq!(
        wa.id, wb.id,
        "the second replica must reuse the first's watch"
    );
    assert_eq!(watch_rows(&f).await, 1);
}

/// One replica, two concurrent renewals of one watch. The process-local
/// lock serialized them; the second then acted on the row it had read
/// before waiting: it stopped the mailbox's subscription again and
/// registered another, leaving two rows for one mailbox.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_renewals_of_one_watch_replace_it_once() {
    let f = fleet().await;
    let first =
        f.a.create_watch(f.user, f.integration, None, None, None)
            .await
            .expect("create");
    let (a1, a2, user, id) = (f.a.clone(), f.a.clone(), f.user, first.id);
    let (r1, r2) = tokio::join!(
        tokio::spawn(async move { a1.renew_watch(user, id).await }),
        tokio::spawn(async move { a2.renew_watch(user, id).await }),
    );
    let n1 = r1.expect("join").expect("renew 1");
    let n2 = r2.expect("join").expect("renew 2");

    assert_eq!(n1.id, n2.id, "both renewals must end on the same watch");
    assert_ne!(n1.id, first.id);
    assert_eq!(
        f.google.watches.load(Ordering::SeqCst),
        2,
        "one create plus ONE renewal"
    );
    assert_eq!(f.google.stops.load(Ordering::SeqCst), 1, "stopped once");
    assert_eq!(watch_rows(&f).await, 1);
}

/// A renewal that starts, on the other replica, while one is mid-rotation:
/// the old row deleted, Google's answer held. It must wait and be handed the
/// replacement; later a caller holding the old uuid gets the same row and
/// Google is asked for nothing.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_renewal_that_starts_while_another_is_mid_rotation_is_handed_the_replacement() {
    let f = fleet().await;
    let first =
        f.a.create_watch(f.user, f.integration, None, None, None)
            .await
            .expect("create");

    f.google.hold_from_watch.store(2, Ordering::SeqCst);
    let (a1, user, id) = (f.a.clone(), f.user, first.id);
    let rotating = tokio::spawn(async move { a1.renew_watch(user, id).await });
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    while f.google.watches.load(Ordering::SeqCst) < 2 {
        assert!(
            std::time::Instant::now() < deadline,
            "the first renewal never reached Google"
        );
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(watch_rows(&f).await, 0, "mid-rotation: the old row is gone");

    let (b, user, id) = (f.b.clone(), f.user, first.id);
    let late = tokio::spawn(async move { b.renew_watch(user, id).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !late.is_finished(),
        "a renewal arriving mid-rotation answered before the rotation finished"
    );

    f.google.release.add_permits(1);
    let rotated = rotating.await.expect("join").expect("the first renewal");
    let late = late
        .await
        .expect("join")
        .expect("a renewal arriving mid-rotation is handed the replacement");
    assert_eq!(late.id, rotated.id);
    assert_ne!(rotated.id, first.id);
    assert_eq!(f.google.watches.load(Ordering::SeqCst), 2);
    assert_eq!(f.google.stops.load(Ordering::SeqCst), 1);
    assert_eq!(watch_rows(&f).await, 1);

    let stale =
        f.a.renew_watch(f.user, first.id)
            .await
            .expect("a stale uuid resolves to the row that replaced it");
    assert_eq!(stale.id, rotated.id);
    assert_eq!(f.google.watches.load(Ordering::SeqCst), 2);
    assert_eq!(f.google.stops.load(Ordering::SeqCst), 1);

    assert!(f.a.renew_watch(f.user, Uuid::new_v4()).await.is_err());
}

/// Requests to renew uuids that are not watches hold no lock while they
/// look, so more of them at once than the pool has connections all come
/// back "not found", promptly.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn renewing_ids_that_are_not_watches_does_not_hold_the_pool() {
    let f = fleet().await;
    let started = std::time::Instant::now();
    let tasks: Vec<_> = (0..32)
        .map(|_| {
            let (b, user) = (f.b.clone(), f.user);
            tokio::spawn(async move { b.renew_watch(user, Uuid::new_v4()).await })
        })
        .collect();
    for task in tasks {
        let err = task
            .await
            .expect("join")
            .expect_err("not a watch")
            .to_string();
        assert!(err.contains("not found"), "{err}");
    }
    assert!(
        started.elapsed() < Duration::from_secs(20),
        "32 renewals of nothing took {:?}",
        started.elapsed()
    );
    assert_eq!(f.google.watches.load(Ordering::SeqCst), 0);
}
