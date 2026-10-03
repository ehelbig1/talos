//! The Google Health connect, end to end against a real database and a
//! loopback stand-in for Google's token and userinfo endpoints (2026-10-02).
//!
//! What this connection is trusted for: a module holding
//! `vault://oauth/google_health/...` reads a person's sleep and heart rate.
//! So the assertions are on ROWS and on the vault, never on a reply alone:
//!
//! * the tokens land under the user the state was minted for, and nobody
//!   else's list shows the connection;
//! * a URL minted in one browser cannot be completed in another;
//! * a consent that could not be used (no refresh token, every health scope
//!   unticked, a refused exchange) stores NOTHING — no row, no credential;
//! * reconnecting the same Google account updates its row;
//! * the generic disconnect's STORE step hides the row and hands back the key
//!   to revoke, and cannot be used on another user's connection. The revoke
//!   itself (a call to Google) and a token refresh are not driven here.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, HeaderValue};
use axum::{extract::State, routing::get, routing::post, Json, Router};
use controller::oauth::credentials::OAuthCredentialService;
use controller::secrets::SecretsManager;
use serde_json::{json, Value};
use talos_google_health::{derive_provider_key, ConnectRefusal, GoogleHealthService};
use talos_oauth::BrowserBinding;
use uuid::Uuid;

const HEALTH_SCOPES: &str = "openid https://www.googleapis.com/auth/userinfo.email \
    https://www.googleapis.com/auth/googlehealth.sleep.readonly \
    https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly \
    https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly";

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'not-a-real-hash', true)")
        .bind(id)
        .bind(format!("health-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    id
}

/// What the stand-in answers for one authorization code.
#[derive(Clone)]
struct Canned {
    status: u16,
    token: Value,
    account: Value,
}

#[derive(Clone, Default)]
struct Fake {
    /// code → canned answer
    codes: Arc<HashMap<String, Canned>>,
    /// Every token request's form, as received.
    exchanges: Arc<Mutex<Vec<HashMap<String, String>>>>,
}

/// A stand-in for oauth2.googleapis.com/token and the userinfo endpoint.
async fn fake_google(codes: Vec<(&str, Canned)>) -> (String, Fake) {
    let fake = Fake {
        codes: Arc::new(codes.into_iter().map(|(c, a)| (c.to_string(), a)).collect()),
        exchanges: Arc::default(),
    };
    async fn token(State(f): State<Fake>, body: String) -> (axum::http::StatusCode, Json<Value>) {
        let form: HashMap<String, String> = body
            .split('&')
            .filter_map(|p| p.split_once('='))
            .map(|(k, v)| {
                (
                    k.to_string(),
                    urlencoding::decode(v)
                        .map(|s| s.into_owned())
                        .unwrap_or_default(),
                )
            })
            .collect();
        let code = form.get("code").cloned().unwrap_or_default();
        f.exchanges.lock().unwrap().push(form);
        match f.codes.get(&code) {
            Some(c) => (
                axum::http::StatusCode::from_u16(c.status).unwrap(),
                Json(c.token.clone()),
            ),
            None => (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"error": "invalid_grant"})),
            ),
        }
    }
    async fn userinfo(State(f): State<Fake>, headers: HeaderMap) -> Json<Value> {
        let bearer = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim_start_matches("Bearer ").to_string())
            .unwrap_or_default();
        let account = f
            .codes
            .values()
            .find(|c| c.token["access_token"] == bearer.as_str())
            .map(|c| c.account.clone())
            .unwrap_or_else(|| json!({}));
        Json(account)
    }
    let app = Router::new()
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base, fake)
}

fn good(token: &str, account_id: &str, email: &str) -> Canned {
    Canned {
        status: 200,
        token: json!({"access_token": token, "refresh_token": format!("refresh-{token}"), "expires_in": 3599, "scope": HEALTH_SCOPES, "token_type": "Bearer"}),
        account: json!({"id": account_id, "email": email}),
    }
}

struct World {
    pool: sqlx::PgPool,
    creds: Arc<OAuthCredentialService>,
    service: GoogleHealthService,
    fake: Fake,
    _db: common::TestDb,
}

async fn world(codes: Vec<(&str, Canned)>) -> World {
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = Arc::new(SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("active DEK");
    let creds = Arc::new(OAuthCredentialService::new(pool.clone(), secrets));
    let (base, fake) = fake_google(codes).await;
    let service = GoogleHealthService::for_tests(
        pool.clone(),
        Some(("client-id", "client-secret")),
        &format!("{base}/token"),
        &format!("{base}/userinfo"),
    )
    .with_credentials_service(creds.clone());
    World {
        pool,
        creds,
        service,
        fake,
        _db,
    }
}

/// The Cookie header a browser holding `binding` sends back.
fn browser(binding: &BrowserBinding) -> HeaderMap {
    let (_, set_cookie) = binding.set_cookie_pair();
    let pair = set_cookie
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let mut h = HeaderMap::new();
    h.insert(
        axum::http::header::COOKIE,
        HeaderValue::from_str(&pair).unwrap(),
    );
    h
}

/// Start a connect for `user` in a fresh browser; returns the state and that browser.
async fn start(w: &World, user: Uuid) -> (String, HeaderMap, String) {
    let binding = BrowserBinding::fresh();
    let (url, state) = w
        .service
        .get_authorization_url(user, &binding)
        .await
        .expect("authorize url");
    (state, browser(&binding), url)
}

async fn finish(
    w: &World,
    code: &str,
    state: &str,
    browser: &HeaderMap,
) -> anyhow::Result<talos_google_health::GoogleHealthIntegration> {
    w.service
        .handle_callback(
            code.to_string(),
            state.to_string(),
            talos_oauth::presented_connect_binding(browser).as_deref(),
        )
        .await
}

async fn rows(pool: &sqlx::PgPool) -> Vec<(Uuid, Uuid, Option<String>, bool)> {
    sqlx::query_as("SELECT user_id, provider_key, account_email, is_active FROM google_health_integrations ORDER BY created_at")
        .fetch_all(pool)
        .await
        .expect("rows")
}
/// Vault entries under the google_health namespace (the tokens themselves).
async fn vault_entries(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path LIKE 'oauth/google_health/%'")
        .fetch_one(pool)
        .await
        .expect("count")
}
async fn credential_count(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM integration_credentials WHERE provider = 'google_health'",
    )
    .fetch_one(pool)
    .await
    .expect("count")
}

#[tokio::test]
async fn a_connect_stores_the_tokens_under_the_user_who_started_it() {
    let w = world(vec![(
        "code-a",
        good("token-a", "google-account-1", "owner@example.com"),
    )])
    .await;
    let (alice, bob) = (seed_user(&w.pool).await, seed_user(&w.pool).await);

    let (state, cookies, url) = start(&w, alice).await;
    // The consent asks for the read scopes, offline, under the shared client, with PKCE.
    for part in [
        "client_id=client-id",
        "googlehealth.sleep.readonly",
        "access_type=offline",
        "prompt=consent",
        "code_challenge=",
    ] {
        assert!(url.contains(part), "{part} missing from {url}");
    }
    let integration = finish(&w, "code-a", &state, &cookies)
        .await
        .expect("connect");
    let key = derive_provider_key("google-account-1");
    assert_eq!(
        (integration.user_id, integration.provider_key),
        (alice, key)
    );

    // The exchange carried the PKCE verifier and this client.
    let sent = w.fake.exchanges.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    assert!(
        sent[0].get("code_verifier").is_some_and(|v| !v.is_empty()),
        "{:?}",
        sent[0].keys()
    );
    assert_eq!(
        sent[0].get("client_id").map(String::as_str),
        Some("client-id")
    );

    // The row and the tokens belong to Alice, at the google_health vault path.
    assert_eq!(
        rows(&w.pool).await,
        vec![(alice, key, Some("owner@example.com".to_string()), true)]
    );
    assert_eq!(
        w.creds
            .get_valid_access_token(alice, "google_health", &key.to_string())
            .await
            .expect("alice's token"),
        "token-a"
    );
    assert!(
        w.creds
            .get_valid_access_token(bob, "google_health", &key.to_string())
            .await
            .is_err(),
        "bob holds no such token"
    );
    let paths: Vec<String> = sqlx::query_scalar("SELECT key_path FROM secrets WHERE key_path LIKE 'oauth/google_health/%' ORDER BY key_path")
        .fetch_all(&w.pool)
        .await
        .unwrap();
    assert_eq!(
        paths,
        vec![
            format!("oauth/google_health/{alice}/{key}/access_token"),
            format!("oauth/google_health/{alice}/{key}/refresh_token")
        ]
    );

    // The settings list shows it to Alice and not to Bob.
    let mine = talos_integrations::store::list_user_service_integrations(&w.pool, alice)
        .await
        .expect("list");
    assert!(
        mine.iter().any(|r| r.service_tag == "GOOGLE_HEALTH"
            && r.identifier == "owner@example.com"
            && r.id == integration.id),
        "{mine:?}"
    );
    let theirs = talos_integrations::store::list_user_service_integrations(&w.pool, bob)
        .await
        .expect("list");
    assert!(theirs.iter().all(|r| r.service_tag != "GOOGLE_HEALTH"));

    // The same listing with each row's provider key (what `list_connections`
    // builds a vault reference from). The statement is assembled at runtime
    // from the provider registry, so only running it proves every branch
    // names real columns. The key it returns locates the token stored above.
    let mine = talos_integrations::store::list_user_connections(&w.pool, alice)
        .await
        .expect("every provider branch prepares");
    let health: Vec<_> = mine
        .iter()
        .filter(|r| r.provider_id == "google-health")
        .collect();
    assert_eq!(health.len(), 1, "{mine:?}");
    assert_eq!(health[0].id, integration.id);
    assert_eq!(health[0].identifier, "owner@example.com");
    assert_eq!(health[0].tier, None, "not a tiered provider");
    assert_eq!(
        talos_oauth::credentials::access_token_vault_path(
            "google_health",
            alice,
            health[0].provider_key.as_deref().expect("a provider key"),
        ),
        format!("oauth/google_health/{alice}/{key}/access_token"),
        "the listed key names the stored token"
    );
    let theirs = talos_integrations::store::list_user_connections(&w.pool, bob)
        .await
        .expect("list");
    assert!(
        theirs.is_empty(),
        "another user's connections are never listed: {theirs:?}"
    );

    // The state is spent: the same redirect cannot be replayed.
    assert!(finish(&w, "code-a", &state, &cookies).await.is_err());
    assert_eq!(rows(&w.pool).await.len(), 1);
}

#[tokio::test]
async fn a_url_minted_in_one_browser_cannot_be_completed_in_another() {
    let w = world(vec![(
        "code-v",
        good("token-v", "victims-google-account", "victim@example.com"),
    )])
    .await;
    let attacker = seed_user(&w.pool).await;
    // The attacker starts a connect and hands the authorize URL to a victim,
    // who consents. The redirect comes back from the VICTIM's browser, which
    // does not hold the attacker's binding cookie.
    let (state, _attackers_cookies, _) = start(&w, attacker).await;
    let victims_browser = browser(&BrowserBinding::fresh());
    assert!(finish(&w, "code-v", &state, &victims_browser)
        .await
        .is_err());
    // And with no cookie at all.
    let (state, _, _) = start(&w, attacker).await;
    assert!(finish(&w, "code-v", &state, &HeaderMap::new())
        .await
        .is_err());
    // The victim's readings are not now reachable from the attacker's account.
    assert!(rows(&w.pool).await.is_empty());
    assert_eq!(
        (
            credential_count(&w.pool).await,
            vault_entries(&w.pool).await
        ),
        (0, 0)
    );
    assert!(
        w.fake.exchanges.lock().unwrap().is_empty(),
        "the code is not even exchanged"
    );
}

#[tokio::test]
async fn a_consent_that_cannot_be_used_stores_nothing() {
    let mut no_refresh = good("token-1", "acct-1", "a@example.com");
    no_refresh
        .token
        .as_object_mut()
        .unwrap()
        .remove("refresh_token");
    let mut no_health = good("token-2", "acct-2", "b@example.com");
    no_health.token["scope"] = json!("openid https://www.googleapis.com/auth/userinfo.email");
    let refused = Canned {
        status: 400,
        token: json!({"error": "invalid_client"}),
        account: json!({}),
    };
    // An account answer with no id, and one whose id is blank: neither can key a vault path.
    let mut no_account = good("token-4", "", "d@example.com");
    no_account.account = json!({"email": "d@example.com"});
    let blank_account = good("token-5", "  ", "e@example.com");
    let w = world(vec![
        ("no-refresh", no_refresh),
        ("no-health", no_health),
        ("refused", refused),
        ("no-account", no_account),
        ("blank-account", blank_account),
    ])
    .await;
    let user = seed_user(&w.pool).await;

    for code in [
        "no-refresh",
        "no-health",
        "refused",
        "no-account",
        "blank-account",
        "unknown-code",
    ] {
        let (state, cookies, _) = start(&w, user).await;
        let err = finish(&w, code, &state, &cookies).await.expect_err(code);
        if code == "no-health" {
            assert_eq!(
                err.downcast_ref::<ConnectRefusal>(),
                Some(&ConnectRefusal::NoHealthScope),
                "{err:#}"
            );
        }
        assert!(rows(&w.pool).await.is_empty(), "{code} left a row");
        assert_eq!(
            credential_count(&w.pool).await,
            0,
            "{code} left a credential"
        );
        assert_eq!(
            vault_entries(&w.pool).await,
            0,
            "{code} left a token in the vault"
        );
    }
    // CONTROL: the same world accepts a usable consent, so the refusals above
    // are about the consents and not a broken harness.
    let w = world(vec![("ok", good("token-ok", "acct-ok", "ok@example.com"))]).await;
    let user = seed_user(&w.pool).await;
    let (state, cookies, _) = start(&w, user).await;
    finish(&w, "ok", &state, &cookies)
        .await
        .expect("a usable consent connects");
    assert_eq!(
        (
            rows(&w.pool).await.len(),
            credential_count(&w.pool).await,
            vault_entries(&w.pool).await
        ),
        (1, 1, 2)
    );
}

#[tokio::test]
async fn reconnecting_one_account_updates_its_row_and_disconnect_is_the_owners() {
    let w = world(vec![
        ("first", good("token-first", "acct-9", "old@example.com")),
        ("second", good("token-second", "acct-9", "new@example.com")),
    ])
    .await;
    let (alice, bob) = (seed_user(&w.pool).await, seed_user(&w.pool).await);
    let key = derive_provider_key("acct-9");
    for code in ["first", "second"] {
        let (state, cookies, _) = start(&w, alice).await;
        finish(&w, code, &state, &cookies).await.expect(code);
    }
    assert_eq!(
        rows(&w.pool).await,
        vec![(alice, key, Some("new@example.com".to_string()), true)]
    );
    assert_eq!(
        w.creds
            .get_valid_access_token(alice, "google_health", &key.to_string())
            .await
            .unwrap(),
        "token-second"
    );

    let provider = talos_integrations::provider_config::PROVIDERS
        .iter()
        .find(|p| p.id == "google-health")
        .expect("registered");
    let id: Uuid = sqlx::query_scalar("SELECT id FROM google_health_integrations")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    // Another user cannot disconnect it.
    let other = talos_integrations::store::disconnect_user_integration(&w.pool, provider, id, bob)
        .await
        .unwrap();
    assert_eq!((other.rows_affected, other.provider_key), (0, None));
    assert!(rows(&w.pool).await[0].3);
    // The owner can; the row is hidden and the key to revoke comes back.
    let mine = talos_integrations::store::disconnect_user_integration(&w.pool, provider, id, alice)
        .await
        .unwrap();
    assert_eq!(
        (mine.rows_affected, mine.provider_key),
        (1, Some(key.to_string()))
    );
    assert_eq!(
        talos_integrations::provider_config::revoke_provider_for(provider, mine.tier.as_deref())
            .as_deref(),
        Some("google_health")
    );
    assert!(!rows(&w.pool).await[0].3);
    let listed = talos_integrations::store::list_user_service_integrations(&w.pool, alice)
        .await
        .unwrap();
    assert!(listed.iter().all(|r| r.service_tag != "GOOGLE_HEALTH"));
    // Connecting again brings the same row back rather than adding one.
    let (state, cookies, _) = start(&w, alice).await;
    finish(&w, "first", &state, &cookies)
        .await
        .expect("reconnect");
    assert_eq!(
        rows(&w.pool).await,
        vec![(alice, key, Some("old@example.com".to_string()), true)]
    );
}
