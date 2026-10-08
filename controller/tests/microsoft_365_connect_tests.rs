//! The Microsoft 365 connect, end to end against a real database and a
//! loopback stand-in for Microsoft's token endpoint and Graph's `/me`.
//!
//! What this connection is trusted for: a module holding
//! `vault://oauth/microsoft_365/...` reads a person's mailbox and calendar.
//! So the assertions are on ROWS and on the vault, never on a reply alone:
//!
//! * the tokens land under the user the state was minted for, and nobody
//!   else's list shows the connection;
//! * a URL minted in one browser cannot be completed in another;
//! * a consent that could not be used (no refresh token, neither Mail.Read nor
//!   Calendars.Read granted, a refused exchange, no usable account id) stores
//!   NOTHING — no row, no credential;
//! * reconnecting the same account updates its row;
//! * the generic disconnect's STORE step hides the row and hands back the key
//!   to revoke, and cannot be used on another user's connection. A token
//!   refresh is not driven here.
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
use talos_microsoft_365::{ConnectRefusal, Microsoft365Service};
use talos_oauth::BrowserBinding;
use uuid::Uuid;

/// What Microsoft returns for a full consent: short names, plus the OpenID
/// scopes it adds on its own.
const GRANTED: &str = "Calendars.Read Mail.Read User.Read profile openid email";

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'not-a-real-hash', true)")
        .bind(id)
        .bind(format!("m365-{id}@example.com"))
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
    /// Every token request's content type and form, as received.
    exchanges: Arc<Mutex<Vec<(String, HashMap<String, String>)>>>,
}

/// A stand-in for login.microsoftonline.com's token endpoint and Graph's `/me`.
async fn fake_microsoft(codes: Vec<(&str, Canned)>) -> (String, Fake) {
    let fake = Fake {
        codes: Arc::new(codes.into_iter().map(|(c, a)| (c.to_string(), a)).collect()),
        exchanges: Arc::default(),
    };
    async fn token(
        State(f): State<Fake>,
        headers: HeaderMap,
        body: String,
    ) -> (axum::http::StatusCode, Json<Value>) {
        let content_type = headers
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let form: HashMap<String, String> = body
            .split('&')
            .filter_map(|p| p.split_once('='))
            .map(|(k, v)| {
                (
                    k.to_string(),
                    urlencoding::decode(&v.replace('+', " "))
                        .map(|s| s.into_owned())
                        .unwrap_or_default(),
                )
            })
            .collect();
        let code = form.get("code").cloned().unwrap_or_default();
        f.exchanges.lock().unwrap().push((content_type, form));
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
    async fn me(State(f): State<Fake>, headers: HeaderMap) -> Json<Value> {
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
        .route("/me", get(me))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base, fake)
}

fn good(token: &str, account_id: &str, upn: &str) -> Canned {
    Canned {
        status: 200,
        token: json!({"access_token": token, "refresh_token": format!("refresh-{token}"), "expires_in": 3599, "scope": GRANTED, "token_type": "Bearer"}),
        account: json!({"id": account_id, "userPrincipalName": upn, "mail": null}),
    }
}

struct World {
    pool: sqlx::PgPool,
    creds: Arc<OAuthCredentialService>,
    service: Microsoft365Service,
    fake: Fake,
    _db: common::TestDb,
}

async fn world(codes: Vec<(&str, Canned)>) -> World {
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = Arc::new(SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("active DEK");
    let creds = Arc::new(OAuthCredentialService::new(pool.clone(), secrets));
    let (base, fake) = fake_microsoft(codes).await;
    let service = Microsoft365Service::for_tests(
        pool.clone(),
        Some(("client-id", "client-secret")),
        &format!("{base}/token"),
        &format!("{base}/me"),
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

/// Start a connect for `user` in a fresh browser; returns the state, that
/// browser and the authorize URL.
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
) -> anyhow::Result<talos_microsoft_365::Microsoft365Integration> {
    w.service
        .handle_callback(
            code.to_string(),
            state.to_string(),
            talos_oauth::presented_connect_binding(browser).as_deref(),
        )
        .await
}

async fn rows(pool: &sqlx::PgPool) -> Vec<(Uuid, String, Option<String>, bool)> {
    sqlx::query_as("SELECT user_id, provider_key, account_label, is_active FROM microsoft_365_integrations ORDER BY created_at")
        .fetch_all(pool)
        .await
        .expect("rows")
}
/// Vault entries under the microsoft_365 namespace (the tokens themselves).
async fn vault_entries(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path LIKE 'oauth/microsoft_365/%'")
        .fetch_one(pool)
        .await
        .expect("count")
}
async fn credential_count(pool: &sqlx::PgPool) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM integration_credentials WHERE provider = 'microsoft_365'",
    )
    .fetch_one(pool)
    .await
    .expect("count")
}

const OBJECT_ID: &str = "6e4b2f4a-1c3d-4e5f-8a9b-0c1d2e3f4a5b";

#[tokio::test]
async fn a_connect_stores_the_tokens_under_the_user_who_started_it() {
    let w = world(vec![(
        "code-a",
        good("token-a", OBJECT_ID, "owner@contoso.example"),
    )])
    .await;
    let (alice, bob) = (seed_user(&w.pool).await, seed_user(&w.pool).await);

    let (state, cookies, url) = start(&w, alice).await;
    // The consent asks for a refresh token and the read scopes, shows the
    // account picker, and carries PKCE.
    assert!(
        url.starts_with("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?"),
        "{url}"
    );
    for part in [
        "client_id=client-id",
        "offline_access",
        "Mail.Read",
        "Calendars.Read",
        "prompt=select_account",
        "code_challenge=",
    ] {
        assert!(url.contains(part), "{part} missing from {url}");
    }
    let integration = finish(&w, "code-a", &state, &cookies)
        .await
        .expect("connect");
    assert_eq!(
        (integration.user_id, integration.provider_key.as_str()),
        (alice, OBJECT_ID)
    );

    // The exchange was form-encoded (Microsoft refuses a JSON token body) and
    // carried the PKCE verifier and this client.
    let sent = w.fake.exchanges.lock().unwrap().clone();
    assert_eq!(sent.len(), 1);
    let (content_type, form) = &sent[0];
    assert_eq!(content_type, "application/x-www-form-urlencoded");
    assert!(
        form.get("code_verifier").is_some_and(|v| !v.is_empty()),
        "{:?}",
        form.keys()
    );
    assert_eq!(form.get("client_id").map(String::as_str), Some("client-id"));
    assert_eq!(
        form.get("grant_type").map(String::as_str),
        Some("authorization_code")
    );

    // The row and the tokens belong to Alice, at the microsoft_365 vault path.
    assert_eq!(
        rows(&w.pool).await,
        vec![(
            alice,
            OBJECT_ID.to_string(),
            Some("owner@contoso.example".to_string()),
            true
        )]
    );
    assert_eq!(
        w.creds
            .get_valid_access_token(alice, "microsoft_365", OBJECT_ID)
            .await
            .expect("alice's token"),
        "token-a"
    );
    assert!(
        w.creds
            .get_valid_access_token(bob, "microsoft_365", OBJECT_ID)
            .await
            .is_err(),
        "bob holds no such token"
    );
    let paths: Vec<String> = sqlx::query_scalar("SELECT key_path FROM secrets WHERE key_path LIKE 'oauth/microsoft_365/%' ORDER BY key_path")
        .fetch_all(&w.pool)
        .await
        .unwrap();
    assert_eq!(
        paths,
        vec![
            format!("oauth/microsoft_365/{alice}/{OBJECT_ID}/access_token"),
            format!("oauth/microsoft_365/{alice}/{OBJECT_ID}/refresh_token")
        ]
    );

    // The settings list shows it to Alice and not to Bob.
    let mine = talos_integrations::store::list_user_service_integrations(&w.pool, alice)
        .await
        .expect("list");
    assert!(
        mine.iter().any(|r| r.service_tag == "MICROSOFT_365"
            && r.identifier == "owner@contoso.example"
            && r.id == integration.id),
        "{mine:?}"
    );
    let theirs = talos_integrations::store::list_user_service_integrations(&w.pool, bob)
        .await
        .expect("list");
    assert!(theirs.iter().all(|r| r.service_tag != "MICROSOFT_365"));

    // The same listing with each row's provider key (what `list_connections`
    // builds a vault reference from). The statement is assembled at runtime
    // from the provider registry, so only running it proves the new branch
    // names real columns. The key it returns locates the token stored above.
    let mine = talos_integrations::store::list_user_connections(&w.pool, alice)
        .await
        .expect("every provider branch prepares");
    let m365: Vec<_> = mine
        .iter()
        .filter(|r| r.provider_id == "microsoft-365")
        .collect();
    assert_eq!(m365.len(), 1, "{mine:?}");
    assert_eq!(m365[0].id, integration.id);
    assert_eq!(m365[0].identifier, "owner@contoso.example");
    assert_eq!(m365[0].tier, None, "not a tiered provider");
    assert_eq!(
        talos_oauth::credentials::access_token_vault_path(
            "microsoft_365",
            alice,
            m365[0].provider_key.as_deref().expect("a provider key"),
        ),
        format!("oauth/microsoft_365/{alice}/{OBJECT_ID}/access_token"),
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
        good("token-v", OBJECT_ID, "victim@contoso.example"),
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
    // The victim's mailbox is not now reachable from the attacker's account.
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
    let mut no_refresh = good("token-1", "acct-1", "a@contoso.example");
    no_refresh
        .token
        .as_object_mut()
        .unwrap()
        .remove("refresh_token");
    let mut no_reading = good("token-2", "acct-2", "b@contoso.example");
    no_reading.token["scope"] = json!("User.Read profile openid email");
    let refused = Canned {
        status: 400,
        token: json!({"error": "invalid_client", "error_description": "AADSTS7000215"}),
        account: json!({}),
    };
    // An account answer with no id, one whose id is blank, and one whose id
    // would re-root the vault path: none can key a credential.
    let mut no_account = good("token-4", "", "d@contoso.example");
    no_account.account = json!({"userPrincipalName": "d@contoso.example"});
    let blank_account = good("token-5", "  ", "e@contoso.example");
    let rerooting_account = good("token-6", "../other-user", "f@contoso.example");
    let w = world(vec![
        ("no-refresh", no_refresh),
        ("no-reading", no_reading),
        ("refused", refused),
        ("no-account", no_account),
        ("blank-account", blank_account),
        ("rerooting-account", rerooting_account),
    ])
    .await;
    let user = seed_user(&w.pool).await;

    for code in [
        "no-refresh",
        "no-reading",
        "refused",
        "no-account",
        "blank-account",
        "rerooting-account",
        "unknown-code",
    ] {
        let (state, cookies, _) = start(&w, user).await;
        let err = finish(&w, code, &state, &cookies).await.expect_err(code);
        let refusal = err.downcast_ref::<ConnectRefusal>();
        match code {
            "no-refresh" => assert_eq!(refusal, Some(&ConnectRefusal::NoRefreshToken), "{err:#}"),
            "no-reading" => assert_eq!(
                refusal,
                Some(&ConnectRefusal::NoMailOrCalendarScope),
                "{err:#}"
            ),
            _ => assert_eq!(refusal, None, "{code}: {err:#}"),
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
    // are about the consents and not a broken harness. One reading scope is
    // enough, and Microsoft's full resource URIs count.
    let mut calendar_only = good("token-ok", "acct-ok", "ok@contoso.example");
    calendar_only.token["scope"] =
        json!("https://graph.microsoft.com/Calendars.Read https://graph.microsoft.com/User.Read");
    let w = world(vec![("ok", calendar_only)]).await;
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
    // The second consent's account has no sign-in name: the card falls back
    // to its mail address.
    let mut second = good("token-second", OBJECT_ID, "");
    second.account =
        json!({"id": OBJECT_ID, "userPrincipalName": null, "mail": "new@contoso.example"});
    let w = world(vec![
        (
            "first",
            good("token-first", OBJECT_ID, "old@contoso.example"),
        ),
        ("second", second),
    ])
    .await;
    let (alice, bob) = (seed_user(&w.pool).await, seed_user(&w.pool).await);
    for code in ["first", "second"] {
        let (state, cookies, _) = start(&w, alice).await;
        finish(&w, code, &state, &cookies).await.expect(code);
    }
    assert_eq!(
        rows(&w.pool).await,
        vec![(
            alice,
            OBJECT_ID.to_string(),
            Some("new@contoso.example".to_string()),
            true
        )]
    );
    assert_eq!(
        w.creds
            .get_valid_access_token(alice, "microsoft_365", OBJECT_ID)
            .await
            .unwrap(),
        "token-second"
    );

    let provider = talos_integrations::provider_config::PROVIDERS
        .iter()
        .find(|p| p.id == "microsoft-365")
        .expect("registered");
    let id: Uuid = sqlx::query_scalar("SELECT id FROM microsoft_365_integrations")
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
        (1, Some(OBJECT_ID.to_string()))
    );
    assert_eq!(
        talos_integrations::provider_config::revoke_provider_for(provider, mine.tier.as_deref())
            .as_deref(),
        Some("microsoft_365")
    );
    assert!(!rows(&w.pool).await[0].3);
    let listed = talos_integrations::store::list_user_service_integrations(&w.pool, alice)
        .await
        .unwrap();
    assert!(listed.iter().all(|r| r.service_tag != "MICROSOFT_365"));
    // Connecting again brings the same row back rather than adding one.
    let (state, cookies, _) = start(&w, alice).await;
    finish(&w, "first", &state, &cookies)
        .await
        .expect("reconnect");
    assert_eq!(
        rows(&w.pool).await,
        vec![(
            alice,
            OBJECT_ID.to_string(),
            Some("old@contoso.example".to_string()),
            true
        )]
    );
}
