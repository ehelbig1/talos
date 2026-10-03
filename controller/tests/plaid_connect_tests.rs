//! Connecting and disconnecting a bank through Plaid Link, against a loopback
//! stand-in for Plaid and a real database.
//!
//! What must hold: the access token is stored in the vault for the person who
//! connected and never returned; a malformed browser token never reaches
//! Plaid; a connection that cannot be stored is undone AT PLAID (it would
//! otherwise count against the plan's Item limit); a disconnect ends the
//! connection at Plaid and in the vault — and only the owner's.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::{extract::State, routing::post, Json, Router};
use controller::secrets::{SecretRequestor, SecretsManager};
use serde_json::{json, Value};
use talos_plaid::{PlaidClient, PlaidConfig, PlaidEnv};
use talos_plaid_connect::{ConnectRefusal, Institution, PlaidConnectService};
use uuid::Uuid;

/// The stand-in's record of what it was sent: (path, body without the app
/// credentials).
type Calls = Arc<Mutex<Vec<(String, Value)>>>;

#[derive(Clone)]
struct Fake {
    calls: Calls,
    /// public token → (access token, item id)
    items: Arc<HashMap<String, (String, String)>>,
}

async fn fake_plaid(items: Vec<(&str, &str, &str)>) -> (String, Calls) {
    let fake = Fake {
        calls: Arc::default(),
        items: Arc::new(
            items
                .into_iter()
                .map(|(p, a, i)| (p.to_string(), (a.to_string(), i.to_string())))
                .collect(),
        ),
    };
    fn record(f: &Fake, path: &str, mut body: Value) -> Value {
        if let Some(o) = body.as_object_mut() {
            assert!(
                o.remove("client_id").is_some(),
                "{path}: app credentials sent"
            );
            assert!(o.remove("secret").is_some(), "{path}: app credentials sent");
        }
        f.calls
            .lock()
            .unwrap()
            .push((path.to_string(), body.clone()));
        body
    }
    async fn link(State(f): State<Fake>, Json(b): Json<Value>) -> Json<Value> {
        record(&f, "/link/token/create", b);
        Json(json!({"link_token": "link-sandbox-0000", "expiration": "2026-10-03T00:00:00Z"}))
    }
    async fn exchange(
        State(f): State<Fake>,
        Json(b): Json<Value>,
    ) -> (axum::http::StatusCode, Json<Value>) {
        let b = record(&f, "/item/public_token/exchange", b);
        match f.items.get(b["public_token"].as_str().unwrap_or("")) {
            Some((access, item)) => (
                axum::http::StatusCode::OK,
                Json(json!({"access_token": access, "item_id": item})),
            ),
            None => (
                axum::http::StatusCode::BAD_REQUEST,
                Json(json!({"error_type": "INVALID_INPUT", "error_code": "INVALID_PUBLIC_TOKEN"})),
            ),
        }
    }
    async fn accounts(State(f): State<Fake>, Json(b): Json<Value>) -> Json<Value> {
        record(&f, "/accounts/get", b);
        Json(json!({"accounts": [
            {"account_id": "a1", "name": "Checking", "type": "depository", "balances": {}},
            {"account_id": "a2", "name": "Savings", "type": "depository", "balances": {}}
        ]}))
    }
    async fn remove(State(f): State<Fake>, Json(b): Json<Value>) -> Json<Value> {
        record(&f, "/item/remove", b);
        Json(json!({"request_id": "r"}))
    }
    let app = Router::new()
        .route("/link/token/create", post(link))
        .route("/item/public_token/exchange", post(exchange))
        .route("/accounts/get", post(accounts))
        .route("/item/remove", post(remove))
        .with_state(fake.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (base, fake.calls)
}

struct World {
    pool: sqlx::PgPool,
    secrets: Arc<SecretsManager>,
    service: PlaidConnectService,
    calls: Calls,
    _db: common::TestDb,
}

async fn world(items: Vec<(&str, &str, &str)>) -> World {
    let (pool, _db) = common::isolated_db_pool().await;
    let secrets = Arc::new(SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("active DEK");
    let (base, calls) = fake_plaid(items).await;
    let client = PlaidClient::new(PlaidConfig::new(
        "client-id-1".into(),
        "app-secret-1".into(),
        PlaidEnv::Sandbox,
    ))
    .with_base_url_for_tests(&base);
    let service = PlaidConnectService::for_tests(pool.clone(), secrets.clone(), client);
    World {
        pool,
        secrets,
        service,
        calls,
        _db,
    }
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(id)
    .bind(format!("{id}@plaid-connect.test"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

impl World {
    fn paths(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(p, _)| p.clone())
            .collect()
    }
    fn removed_tokens(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|(p, _)| p == "/item/remove")
            .map(|(_, b)| b["access_token"].as_str().unwrap_or("").to_string())
            .collect()
    }
    async fn vault_entries(&self, item: &str) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path = $1")
            .bind(format!("plaid/access_token/{item}"))
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn active_rows(&self, user: Uuid) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM plaid_items WHERE user_id = $1 AND is_active")
            .bind(user)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }
    async fn personal_org(&self, user: Uuid) -> Vec<Uuid> {
        vec![
            talos_organizations::OrganizationService::create_personal_org(&self.pool, user, None)
                .await
                .unwrap()
                .id,
        ]
    }
}

#[tokio::test]
async fn a_connection_stores_the_token_for_its_owner_and_returns_none_of_it() {
    let w = world(vec![("public-sandbox-1", "access-sandbox-1", "item-1")]).await;
    let user = seed_user(&w.pool).await;

    let token = w.service.link_token(user).await.expect("link token");
    assert_eq!(token.as_str(), "link-sandbox-0000");
    let sent = w.calls.lock().unwrap()[0].1.clone();
    assert_eq!(
        sent["user"]["client_user_id"],
        user.to_string(),
        "Plaid's user id is the Talos id"
    );

    let item = w
        .service
        .connect(
            user,
            "public-sandbox-1",
            Institution {
                id: Some("ins_1".into()),
                name: Some("Wells Fargo".into()),
            },
        )
        .await
        .expect("connect");
    assert_eq!(
        (
            item.item_id.as_str(),
            item.institution_name.as_deref(),
            item.accounts
        ),
        ("item-1", Some("Wells Fargo"), Some(2))
    );

    let row: (String, String, bool) = sqlx::query_as(
        "SELECT institution_name, environment, is_active FROM plaid_items WHERE user_id = $1 AND item_id = 'item-1'",
    )
    .bind(user)
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(row, ("Wells Fargo".into(), "sandbox".into(), true));
    let orgs = w.personal_org(user).await;
    let stored = w
        .secrets
        .get_secret(
            "plaid/access_token/item-1",
            SecretRequestor::User(user),
            &orgs,
        )
        .await
        .expect("the owner can read it");
    assert_eq!(stored, "access-sandbox-1");
    let name: String = sqlx::query_scalar("SELECT name FROM secrets WHERE key_path = $1")
        .bind("plaid/access_token/item-1")
        .fetch_one(&w.pool)
        .await
        .unwrap();
    assert_eq!(
        name, "Plaid access token (Wells Fargo)",
        "the entry says which bank it is"
    );
    for path in ["plaid/client_id", "plaid/secret"] {
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM secrets WHERE key_path = $1")
            .bind(path)
            .fetch_one(&w.pool)
            .await
            .unwrap();
        assert_eq!(
            n, 1,
            "{path}: the reader module's app credentials are written too"
        );
    }
}

#[tokio::test]
async fn a_malformed_browser_token_never_reaches_plaid() {
    let w = world(vec![]).await;
    let user = seed_user(&w.pool).await;
    for bad in ["", "not-a-token", "public-abc def", "access-sandbox-1"] {
        assert_eq!(
            w.service
                .connect(user, bad, Institution::default())
                .await
                .err(),
            Some(ConnectRefusal::BadPublicToken),
            "{bad:?}"
        );
    }
    assert!(w.paths().is_empty(), "nothing was sent: {:?}", w.paths());
}

#[tokio::test]
async fn a_token_plaid_refuses_stores_nothing() {
    let w = world(vec![]).await;
    let user = seed_user(&w.pool).await;
    assert_eq!(
        w.service
            .connect(user, "public-sandbox-unknown", Institution::default())
            .await
            .err(),
        Some(ConnectRefusal::Exchange)
    );
    assert_eq!(w.active_rows(user).await, 0);
    assert!(
        w.removed_tokens().is_empty(),
        "no connection was made to undo"
    );
}

/// Plaid made the connection but it cannot be kept here (an item id the vault
/// path refuses): it is undone at Plaid, and nothing is left behind.
#[tokio::test]
async fn a_connection_that_cannot_be_stored_is_undone_at_plaid() {
    let w = world(vec![(
        "public-sandbox-2",
        "access-sandbox-2",
        "bad/../item",
    )])
    .await;
    let user = seed_user(&w.pool).await;
    assert_eq!(
        w.service
            .connect(user, "public-sandbox-2", Institution::default())
            .await
            .err(),
        Some(ConnectRefusal::Store)
    );
    assert_eq!(w.removed_tokens(), vec!["access-sandbox-2"]);
    assert_eq!(w.active_rows(user).await, 0);
}

#[tokio::test]
async fn a_disconnect_ends_the_connection_at_plaid_and_in_the_vault() {
    let w = world(vec![("public-sandbox-3", "access-sandbox-3", "item-3")]).await;
    let user = seed_user(&w.pool).await;
    w.service
        .connect(user, "public-sandbox-3", Institution::default())
        .await
        .expect("connect");
    assert_eq!(w.vault_entries("item-3").await, 1);

    w.service.remove_item(user, "item-3").await.expect("remove");

    assert_eq!(
        w.removed_tokens(),
        vec!["access-sandbox-3"],
        "ended at Plaid with its own token"
    );
    assert_eq!(w.vault_entries("item-3").await, 0, "and deleted here");
}

/// A bank connected in the other Plaid environment (a sandbox bank left over
/// after the switch to production) is not sent to this environment's Plaid,
/// which would refuse the token; it is still deleted here.
#[tokio::test]
async fn a_connection_from_another_environment_is_not_sent_to_plaid() {
    let w = world(vec![("public-sandbox-5", "access-sandbox-5", "item-5")]).await;
    let user = seed_user(&w.pool).await;
    w.service
        .connect(user, "public-sandbox-5", Institution::default())
        .await
        .expect("connect");
    // The row says production; the service is configured for sandbox.
    sqlx::query("UPDATE plaid_items SET environment = 'production' WHERE user_id = $1 AND item_id = 'item-5'")
        .bind(user)
        .execute(&w.pool)
        .await
        .unwrap();

    w.service.remove_item(user, "item-5").await.expect("remove");

    assert!(
        w.removed_tokens().is_empty(),
        "nothing was sent to Plaid: {:?}",
        w.paths()
    );
    assert_eq!(w.vault_entries("item-5").await, 0, "and it is deleted here");
}

/// Another user naming the same item id neither reaches Plaid with the
/// owner's token nor deletes it.
#[tokio::test]
async fn another_user_cannot_end_someone_elses_connection() {
    let w = world(vec![("public-sandbox-4", "access-sandbox-4", "item-4")]).await;
    let owner = seed_user(&w.pool).await;
    let stranger = seed_user(&w.pool).await;
    w.service
        .connect(owner, "public-sandbox-4", Institution::default())
        .await
        .expect("connect");

    let _ = w.service.remove_item(stranger, "item-4").await;

    assert!(
        w.removed_tokens().is_empty(),
        "the owner's token was not used"
    );
    assert_eq!(
        w.vault_entries("item-4").await,
        1,
        "the owner's token is still there"
    );
}
