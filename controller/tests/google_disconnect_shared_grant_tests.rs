//! A Google disconnect revokes at Google only for the account's LAST
//! connection.
//!
//! Google keeps one grant per (account, OAuth client) and a revoke ends all of
//! it — seen live 2026-10-02: disconnecting Health on an account returned 401
//! on that account's Calendar token two minutes later. These tests drive the
//! real `OAuthCredentialService::revoke_and_cleanup` against a loopback
//! stand-in for Google's revoke endpoint and read what it was sent.
//!
//! Row security is enforced (`talos_app`), as on the reference deployment, so
//! the vault deletes these disconnects rely on run the way they do there.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::post, Router};
use chrono::{Duration, Utc};
use controller::secrets::SecretsManager;
use talos_oauth::OAuthCredentialService;
use uuid::Uuid;

/// Tokens the stand-in revoke endpoint was sent, in order.
type Revoked = Arc<Mutex<Vec<String>>>;

async fn fake_google_revoke() -> (String, Revoked) {
    let seen: Revoked = Arc::default();
    async fn revoke(State(seen): State<Revoked>, body: String) -> axum::http::StatusCode {
        let token = body
            .split('&')
            .filter_map(|p| p.split_once('='))
            .find(|(k, _)| *k == "token")
            .map(|(_, v)| {
                urlencoding::decode(v)
                    .map(|s| s.into_owned())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        seen.lock().unwrap().push(token);
        axum::http::StatusCode::OK
    }
    let app = Router::new()
        .route("/revoke", post(revoke))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/revoke", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (url, seen)
}

struct World {
    pool: sqlx::PgPool,
    creds: OAuthCredentialService,
    revoked: Revoked,
    _db: common::TestDb,
}

async fn world() -> World {
    // Read once per process, before the first scoped transaction.
    std::env::set_var("TALOS_RLS_SET_ROLE", "1");
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = Arc::new(SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("active DEK");
    let (url, revoked) = fake_google_revoke().await;
    let creds =
        OAuthCredentialService::new(pool.clone(), secrets).with_google_revoke_url_for_tests(&url);
    World {
        pool,
        creds,
        revoked,
        _db,
    }
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@shared-grant.test"))
    .execute(pool)
    .await
    .expect("seed user");
    user
}

impl World {
    /// Store a credential whose refresh token is `refresh-<provider>-<key>`.
    async fn connect(&self, user: Uuid, provider: &str, key: &str) {
        self.creds
            .store_credentials(
                user,
                provider,
                key,
                &format!("access-{provider}-{key}"),
                Some(&format!("refresh-{provider}-{key}")),
                Utc::now() + Duration::hours(1),
                "scope",
                vec![],
            )
            .await
            .expect("store credentials");
    }

    /// The integration's own row, which is where a non-Gmail connection's
    /// account address is recorded.
    async fn record_account(&self, user: Uuid, provider: &str, key: Uuid, email: &str) {
        let sql = match provider {
            "google_calendar" => {
                "INSERT INTO google_calendar_integrations (user_id, oauth_account_id, expires_at, scope, account_email) \
                 VALUES ($1, $2, NOW() + interval '1 hour', 'scope', $3)"
            }
            "google_health" => {
                "INSERT INTO google_health_integrations (user_id, provider_key, account_email) VALUES ($1, $2, $3)"
            }
            _ => "INSERT INTO google_cloud_integrations (user_id, provider_key, account_email) VALUES ($1, $2, $3)",
        };
        sqlx::query(sql)
            .bind(user)
            .bind(key)
            .bind(email)
            .execute(&self.pool)
            .await
            .expect("record the integration row");
    }

    async fn disconnect(&self, user: Uuid, provider: &str, key: &str) {
        self.creds
            .revoke_and_cleanup(user, provider, key)
            .await
            .expect("disconnect");
    }

    fn revoked(&self) -> Vec<String> {
        self.revoked.lock().unwrap().clone()
    }

    async fn vault_entries(&self, user: Uuid, provider: &str, key: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path LIKE $1")
            .bind(format!("oauth/{provider}/{user}/{key}/%"))
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
}

/// The live case: Calendar and Health on one Google account. Disconnecting
/// Health sends Google nothing and leaves Calendar's tokens alone; the account's
/// last connection is the one that revokes.
#[tokio::test]
async fn only_the_accounts_last_connection_is_revoked_at_google() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    let account = Uuid::new_v4().to_string();
    w.connect(user, "google_calendar", &account).await;
    w.connect(user, "google_health", &account).await;

    w.disconnect(user, "google_health", &account).await;

    assert!(
        w.revoked().is_empty(),
        "a revoke here would end the Calendar connection too: {:?}",
        w.revoked()
    );
    assert_eq!(
        w.vault_entries(user, "google_health", &account).await,
        0,
        "the disconnected connection's tokens are deleted here"
    );
    assert_eq!(
        w.vault_entries(user, "google_calendar", &account).await,
        2,
        "the other connection's tokens are untouched"
    );

    w.disconnect(user, "google_calendar", &account).await;

    assert_eq!(
        w.revoked(),
        vec![format!("refresh-google_calendar-{account}")],
        "the last connection revokes, with its own refresh token"
    );
    assert_eq!(w.vault_entries(user, "google_calendar", &account).await, 0);
}

/// Gmail is keyed by address, the others by a derived id; the address the
/// integration row records is what relates them.
#[tokio::test]
async fn gmail_and_another_integration_on_one_address_share_the_grant() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    let account = Uuid::new_v4();
    w.connect(user, "gmail", "Person@Example.test").await;
    w.connect(user, "google_calendar", &account.to_string())
        .await;
    w.record_account(user, "google_calendar", account, "person@example.test")
        .await;

    w.disconnect(user, "google_calendar", &account.to_string())
        .await;
    assert!(w.revoked().is_empty(), "Gmail is on the same account");

    w.disconnect(user, "gmail", "Person@Example.test").await;
    assert_eq!(w.revoked(), vec!["refresh-gmail-Person@Example.test"]);
}

/// The control for every withholding case: connections on DIFFERENT Google
/// accounts do not share a grant, so each disconnect revokes.
#[tokio::test]
async fn connections_on_different_accounts_are_each_revoked() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
    w.connect(user, "gmail", "one@example.test").await;
    w.connect(user, "google_calendar", &a.to_string()).await;
    w.record_account(user, "google_calendar", a, "two@example.test")
        .await;
    w.connect(user, "google_health", &b.to_string()).await;
    w.record_account(user, "google_health", b, "three@example.test")
        .await;

    w.disconnect(user, "google_calendar", &a.to_string()).await;
    w.disconnect(user, "google_health", &b.to_string()).await;

    assert_eq!(
        w.revoked(),
        vec![
            format!("refresh-google_calendar-{a}"),
            format!("refresh-google_health-{b}")
        ]
    );
}

/// A connection whose account is not recorded might be on the same account as
/// a Gmail connection, so the revoke is withheld.
#[tokio::test]
async fn a_connection_that_cannot_be_placed_withholds_the_revoke() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    let account = Uuid::new_v4().to_string();
    w.connect(user, "gmail", "one@example.test").await;
    // No integration row, so no recorded address for this one.
    w.connect(user, "google_calendar", &account).await;

    w.disconnect(user, "gmail", "one@example.test").await;

    assert!(w.revoked().is_empty(), "{:?}", w.revoked());
    assert_eq!(w.vault_entries(user, "gmail", "one@example.test").await, 0);
}

/// Another user's connections, and this user's already-disconnected ones, are
/// not siblings.
#[tokio::test]
async fn another_users_and_retired_connections_do_not_withhold_a_revoke() {
    let w = world().await;
    let user = seed_user(&w.pool).await;
    let stranger = seed_user(&w.pool).await;
    let account = Uuid::new_v4().to_string();
    // The stranger is connected to the very same Google account.
    w.connect(stranger, "google_calendar", &account).await;
    // This user's Calendar connection on it was disconnected earlier.
    w.connect(user, "google_calendar", &account).await;
    sqlx::query("UPDATE integration_credentials SET is_active = FALSE WHERE user_id = $1 AND provider = 'google_calendar'")
        .bind(user)
        .execute(&w.pool)
        .await
        .unwrap();
    w.connect(user, "google_health", &account).await;

    w.disconnect(user, "google_health", &account).await;

    assert_eq!(
        w.revoked(),
        vec![format!("refresh-google_health-{account}")],
        "this was the user's last live connection on the account"
    );
    assert_eq!(
        w.vault_entries(stranger, "google_calendar", &account).await,
        2,
        "the stranger's tokens are untouched"
    );
}

/// The three integrations that key a connection by the Google account id must
/// derive it identically: equal keys are how one account is recognised.
#[test]
fn the_account_key_derivations_agree() {
    for id in ["1", "108234567890123456789", "an-account"] {
        assert_eq!(
            talos_google_health::derive_provider_key(id),
            talos_google_cloud::integration::derive_provider_key(id),
            "Health and Cloud derive different keys for Google account {id}"
        );
    }
}
