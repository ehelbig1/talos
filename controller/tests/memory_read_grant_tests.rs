//! A memory read grant reads ONE key of ONE actor's memory, and nothing else
//! (2026-10-13).
//!
//! The narrow credential for handing one document to a session that must not
//! have the rest of the platform. Driven end to end against a real database:
//! the operator tools that make, list and revoke a grant, and the public
//! endpoint a holder reads through, as the router mounts it.
//!
//! What is asserted is the security model: the scope is the row and no
//! request input widens it; the token is stored as a hash; every refusal is
//! one answer; the lifetime, the read limit and revocation hold (the limit
//! under concurrent reads); the actor must still be the minting user's when
//! the grant is read; and only the owner can make or revoke one.
//!
//! One test function writes memory: the actor-memory crypto hook is a
//! process-wide `OnceLock` bound to one test's database, so at most one test
//! in the binary may register it.
//!
//! The binary sets `TALOS_RLS_SET_ROLE` off itself: under `talos_app` a
//! table's policy can hide another user's row before a statement's own
//! ownership predicate is consulted, and it is the predicates these tests
//! are about.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Method, Request, StatusCode};
use axum::routing::get;
use axum::Router;
use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

use controller::mcp::types::JsonRpcResponse;
use controller::mcp::McpState;

const PATH: &str = "/memory-grants/document";

fn leave_row_security_unenforced() {
    std::env::set_var("TALOS_RLS_SET_ROLE", "0");
}

async fn register_crypto(pool: &Pool<Postgres>) {
    let secrets =
        Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"));
    secrets.initialize().await.expect("initialize secrets");
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(secrets),
    ));
}

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'grants')",
    )
    .bind(id)
    .bind(format!("grants-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_actor(pool: &Pool<Postgres>, user: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, status) VALUES ($1, $2, $3, 'active')")
        .bind(id)
        .bind(user)
        .bind(format!("grants-actor-{}", id.simple()))
        .execute(pool)
        .await
        .expect("seed actor");
    id
}

fn refused(resp: &JsonRpcResponse) -> bool {
    resp.error.is_some()
        || resp
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(Value::as_bool)
            == Some(true)
}

async fn tool(state: &Arc<McpState>, user: Uuid, name: &str, args: Value) -> JsonRpcResponse {
    controller::mcp::actor::dispatch(name, Some(json!(1)), &args, state, agent(user))
        .await
        .unwrap_or_else(|| panic!("{name} is dispatched"))
}

/// Make a grant through the tool and return `(grant id, raw token)`.
async fn grant(state: &Arc<McpState>, user: Uuid, args: Value) -> (Uuid, String) {
    let resp = tool(state, user, "create_memory_read_grant", args).await;
    assert!(!refused(&resp), "{resp:?}");
    let reply = text_json(&resp);
    (
        reply["grant_id"]
            .as_str()
            .expect("grant_id")
            .parse()
            .unwrap(),
        reply["token"].as_str().expect("token").to_string(),
    )
}

/// The endpoint as the controller's router mounts it.
fn app(pool: &Pool<Postgres>) -> Router {
    Router::new()
        .route(PATH, get(controller::webhooks::memory_grant_read))
        .layer(Extension(pool.clone()))
}

async fn read(app: &Router, uri: &str, headers: &[(&str, String)]) -> (StatusCode, Value, String) {
    let mut request = Request::builder().method(Method::GET).uri(uri);
    for (name, value) in headers {
        request = request.header(*name, value);
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::empty()).unwrap())
        .await
        .expect("the router answers");
    let status = response.status();
    let cache = response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("a bounded body");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        cache,
    )
}

fn bearer(token: &str) -> Vec<(&'static str, String)> {
    vec![("authorization", format!("Bearer {token}"))]
}

async fn read_with(app: &Router, token: &str) -> (StatusCode, Value) {
    let (status, body, _) = read(app, PATH, &bearer(token)).await;
    (status, body)
}

fn nothing() -> Value {
    json!({ "error": "No document for this grant" })
}

async fn grant_row(pool: &Pool<Postgres>, id: Uuid) -> (String, i32, bool, bool) {
    sqlx::query_as(
        "SELECT token_hash, read_count, last_read_at IS NOT NULL, revoked_at IS NOT NULL \
         FROM memory_read_grants WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("grant row")
}

#[tokio::test]
async fn a_grant_reads_its_one_key_and_nothing_else() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let actor = seed_actor(&pool, owner).await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let app = app(&pool);

    let approved = json!({ "title": "A made-up brief", "body": "Build the thing." });
    talos_memory::persist_memory(&pool, actor, "briefs/approved", &approved, "semantic", None)
        .await
        .expect("store the document");
    talos_memory::persist_memory(
        &pool,
        actor,
        "private/other",
        &json!({ "note": "not for the session" }),
        "semantic",
        None,
    )
    .await
    .expect("store another key");

    // ── Made by its owner; the token is returned once and stored as a hash.
    let args = json!({ "actor_id": actor.to_string(), "key": "briefs/approved",
                       "label": "brief for one build session" });
    let resp = tool(&state, owner, "create_memory_read_grant", args.clone()).await;
    assert!(!refused(&resp), "{resp:?}");
    let made = text_json(&resp);
    let token = made["token"].as_str().expect("token").to_string();
    let id: Uuid = made["grant_id"].as_str().unwrap().parse().unwrap();
    assert_eq!(token.len(), 64);
    assert_eq!(made["key_present"], true);
    assert!(made["read_with"]["url"].as_str().unwrap().ends_with(PATH));
    assert!(!made["read_with"]["url"].as_str().unwrap().contains(&token));
    let (hash, reads, read_at, revoked) = grant_row(&pool, id).await;
    assert_eq!(
        hash,
        talos_text_util::sha256_hex(&token),
        "stored as a hash"
    );
    assert_ne!(hash, token);
    assert_eq!((reads, read_at, revoked), (0, false, false));
    let recorded: (String, Value) = sqlx::query_as(
        "SELECT event_type, details FROM admin_event_log \
         WHERE user_id = $1 AND resource_id = $2 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(owner)
    .bind(actor)
    .fetch_one(&pool)
    .await
    .expect("the mint is recorded");
    assert_eq!(recorded.0, "memory_read_grant_created");
    assert_eq!(
        recorded.1["memory_key"], "briefs/approved",
        "the scope is in the record"
    );
    assert!(!recorded.1.to_string().contains(&token), "the token is not");

    // ── The holder reads the document, and the read is counted.
    let (status, body, cache) = read(&app, PATH, &bearer(&token)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["key"], "briefs/approved");
    assert_eq!(body["value"], approved);
    assert_eq!(cache, "no-store");
    let (_, reads, read_at, _) = grant_row(&pool, id).await;
    assert_eq!((reads, read_at), (1, true));

    // ── Nothing a request sends widens the scope: there is no parameter.
    let (status, body, _) = read(
        &app,
        &format!("{PATH}?key=private/other&actor_id={actor}"),
        &bearer(&token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key"], "briefs/approved");
    assert!(!body.to_string().contains("not for the session"));

    // ── Every request that reads nothing gets ONE answer.
    let other_token = "ab".repeat(32);
    let refusals: Vec<(&str, String, Vec<(&'static str, String)>)> = vec![
        ("no credential", PATH.to_string(), vec![]),
        ("an unknown token", PATH.to_string(), bearer(&other_token)),
        ("a malformed token", PATH.to_string(), bearer("not-a-token")),
        (
            "the token in the URL",
            format!("{PATH}?token={token}"),
            vec![],
        ),
        (
            "the token as a path segment",
            format!("{PATH}/{token}"),
            vec![],
        ),
        (
            "another scheme",
            PATH.to_string(),
            vec![("authorization", format!("Basic {token}"))],
        ),
        (
            "the bare token",
            PATH.to_string(),
            vec![("authorization", token.clone())],
        ),
    ];
    for (what, uri, headers) in &refusals {
        let (status, body, _) = read(&app, uri, headers).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{what}");
        if !uri.starts_with(&format!("{PATH}/")) {
            assert_eq!(body, nothing(), "{what}: the one answer");
        }
    }
    assert_eq!(
        grant_row(&pool, id).await.1,
        2,
        "a refused request is not a read"
    );

    // ── A key with nothing stored: the grant is made, says so, and reads
    //    the same answer as a token that does not exist.
    let (_, empty_token) = {
        let resp = tool(
            &state,
            owner,
            "create_memory_read_grant",
            json!({ "actor_id": actor.to_string(), "key": "briefs/not-written-yet", "label": "early" }),
        )
        .await;
        assert_eq!(text_json(&resp)["key_present"], false);
        let reply = text_json(&resp);
        (
            reply["grant_id"].as_str().unwrap().to_string(),
            reply["token"].as_str().unwrap().to_string(),
        )
    };
    assert_eq!(
        read_with(&app, &empty_token).await,
        (StatusCode::NOT_FOUND, nothing())
    );

    // ── A read limit holds, including when the last read is raced for.
    let mut limited = args.clone();
    limited["max_reads"] = json!(2);
    let (_, two) = grant(&state, owner, limited.clone()).await;
    assert_eq!(read_with(&app, &two).await.0, StatusCode::OK);
    assert_eq!(read_with(&app, &two).await.0, StatusCode::OK);
    assert_eq!(
        read_with(&app, &two).await,
        (StatusCode::NOT_FOUND, nothing())
    );
    limited["max_reads"] = json!(1);
    let (once_id, once) = grant(&state, owner, limited).await;
    let raced = futures::future::join_all((0..8).map(|_| {
        let (app, once) = (app.clone(), once.clone());
        async move { read_with(&app, &once).await.0 }
    }))
    .await;
    assert_eq!(
        raced.iter().filter(|s| **s == StatusCode::OK).count(),
        1,
        "eight reads at once of a one-read grant: {raced:?}"
    );
    assert_eq!(grant_row(&pool, once_id).await.1, 1);

    // ── It expires.
    let (expiring_id, expiring) = grant(&state, owner, args.clone()).await;
    assert_eq!(read_with(&app, &expiring).await.0, StatusCode::OK);
    sqlx::query(
        "UPDATE memory_read_grants SET expires_at = NOW() - interval '1 second' WHERE id = $1",
    )
    .bind(expiring_id)
    .execute(&pool)
    .await
    .unwrap();
    assert_eq!(
        read_with(&app, &expiring).await,
        (StatusCode::NOT_FOUND, nothing())
    );

    // ── Only its owner can revoke it; revoked, it reads nothing.
    let resp = tool(
        &state,
        stranger,
        "revoke_memory_read_grant",
        json!({ "grant_id": id.to_string() }),
    )
    .await;
    assert!(refused(&resp), "a stranger revoked the grant: {resp:?}");
    let unknown = tool(
        &state,
        stranger,
        "revoke_memory_read_grant",
        json!({ "grant_id": Uuid::new_v4().to_string() }),
    )
    .await;
    assert_eq!(
        error_message(&resp),
        error_message(&unknown),
        "one answer for not yours and not there"
    );
    assert_eq!(
        read_with(&app, &token).await.0,
        StatusCode::OK,
        "still live"
    );

    let resp = tool(
        &state,
        owner,
        "revoke_memory_read_grant",
        json!({ "grant_id": id.to_string() }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
    assert!(grant_row(&pool, id).await.3);
    assert_eq!(
        read_with(&app, &token).await,
        (StatusCode::NOT_FOUND, nothing())
    );
    let again = tool(
        &state,
        owner,
        "revoke_memory_read_grant",
        json!({ "grant_id": id.to_string() }),
    )
    .await;
    assert!(refused(&again), "revoking twice is not a second revocation");
    let revocations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM admin_event_log WHERE user_id = $1 AND event_type = 'memory_read_grant_revoked'",
    )
    .bind(owner)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(revocations, 1);

    // ── The listing shows what each grant is and how it was used, and never
    //    a token or a hash.
    let listed = text_json(&tool(&state, owner, "list_memory_read_grants", json!({})).await);
    let states: Vec<&str> = listed["grants"]
        .as_array()
        .unwrap()
        .iter()
        .map(|g| g["state"].as_str().unwrap())
        .collect();
    for state_name in ["live", "revoked", "expired", "used_up"] {
        assert!(states.contains(&state_name), "{state_name} in {states:?}");
    }
    let text = listed.to_string();
    for secret in [&token, &hash, &two, &once] {
        assert!(
            !text.contains(secret.as_str()),
            "the listing shows a token or its hash"
        );
    }
    assert_eq!(
        text_json(&tool(&state, stranger, "list_memory_read_grants", json!({})).await)["count"],
        0
    );

    // ── A grant to a key with nothing stored under it spends no read
    //    (2026-10-14, security review I-8): it answers nothing, the count
    //    stays, and once the key is written the one read is still there.
    let later = json!({ "actor_id": actor.to_string(), "key": "briefs/later",
                        "label": "a brief not yet written", "max_reads": 1 });
    let (later_id, later_token) = grant(&state, owner, later).await;
    for _ in 0..2 {
        assert_eq!(
            read_with(&app, &later_token).await,
            (StatusCode::NOT_FOUND, nothing())
        );
    }
    assert_eq!(grant_row(&pool, later_id).await.1, 0, "no read was spent");
    talos_memory::persist_memory(
        &pool,
        actor,
        "briefs/later",
        &json!({ "title": "Written later" }),
        "semantic",
        None,
    )
    .await
    .expect("write the key");
    assert_eq!(read_with(&app, &later_token).await.0, StatusCode::OK);
    assert_eq!(grant_row(&pool, later_id).await.1, 1);
    assert_eq!(
        read_with(&app, &later_token).await,
        (StatusCode::NOT_FOUND, nothing()),
        "the one read is used"
    );

    // ── A terminated actor's grants answer nothing (I-8).
    let (_, ended) = grant(&state, owner, args.clone()).await;
    assert_eq!(read_with(&app, &ended).await.0, StatusCode::OK);
    sqlx::query("UPDATE actors SET status = 'terminated' WHERE id = $1")
        .bind(actor)
        .execute(&pool)
        .await
        .expect("terminate");
    assert_eq!(
        read_with(&app, &ended).await,
        (StatusCode::NOT_FOUND, nothing())
    );
    sqlx::query("UPDATE actors SET status = 'active' WHERE id = $1")
        .bind(actor)
        .execute(&pool)
        .await
        .expect("restore");

    // ── The actor must still be the minting user's when the grant is read.
    let (_, live) = grant(&state, owner, args.clone()).await;
    assert_eq!(read_with(&app, &live).await.0, StatusCode::OK);
    sqlx::query("UPDATE actors SET user_id = $2 WHERE id = $1")
        .bind(actor)
        .bind(stranger)
        .execute(&pool)
        .await
        .expect("the actor changes hands");
    assert_eq!(
        read_with(&app, &live).await,
        (StatusCode::NOT_FOUND, nothing())
    );
}

#[tokio::test]
async fn only_the_owner_of_an_actor_can_make_a_grant_and_what_is_asked_for_is_bounded() {
    leave_row_security_unenforced();
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let actor = seed_actor(&pool, owner).await;
    let foreign_actor = seed_actor(&pool, stranger).await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    let count = || async {
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM memory_read_grants")
            .fetch_one(&pool)
            .await
            .unwrap()
    };
    let base = |actor_id: Uuid| json!({ "actor_id": actor_id.to_string(), "key": "briefs/approved", "label": "x" });

    // Another user's actor and an actor that does not exist: one answer.
    let foreign = tool(
        &state,
        owner,
        "create_memory_read_grant",
        base(foreign_actor),
    )
    .await;
    let missing = tool(
        &state,
        owner,
        "create_memory_read_grant",
        base(Uuid::new_v4()),
    )
    .await;
    assert!(refused(&foreign) && refused(&missing));
    assert_eq!(error_message(&foreign), error_message(&missing));
    assert_eq!(error_message(&foreign), "Actor not found or not accessible");

    for (what, patch) in [
        ("a lifetime of zero", json!({ "ttl_hours": 0 })),
        ("a lifetime past a week", json!({ "ttl_hours": 169 })),
        (
            "a lifetime that is not a number",
            json!({ "ttl_hours": "long" }),
        ),
        ("no reads", json!({ "max_reads": 0 })),
        ("too many reads", json!({ "max_reads": 1001 })),
        ("an empty label", json!({ "label": "  \n " })),
        ("an empty key", json!({ "key": "   " })),
    ] {
        let mut args = base(actor);
        for (k, v) in patch.as_object().unwrap() {
            args[k] = v.clone();
        }
        let resp = tool(&state, owner, "create_memory_read_grant", args).await;
        assert!(refused(&resp), "{what} was accepted: {resp:?}");
    }
    assert_eq!(count().await, 0, "a refused request made no grant");

    // The longest lifetime asked for is the longest given.
    let resp = tool(&state, owner, "create_memory_read_grant", {
        let mut args = base(actor);
        args["ttl_hours"] = json!(168);
        args
    })
    .await;
    assert!(!refused(&resp), "{resp:?}");
    let hours: f64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM expires_at - created_at) / 3600)::float8 FROM memory_read_grants",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!((167.9..=168.1).contains(&hours), "{hours}");

    // A user holds a bounded number of live grants.
    sqlx::query(
        "INSERT INTO memory_read_grants (user_id, actor_id, memory_key, token_hash, label, expires_at) \
         SELECT $1, $2, 'k', 'seed-' || g, 'seed', NOW() + interval '1 hour' FROM generate_series(1, 49) g",
    )
    .bind(owner)
    .bind(actor)
    .execute(&pool)
    .await
    .expect("seed live grants");
    let resp = tool(&state, owner, "create_memory_read_grant", base(actor)).await;
    assert!(
        refused(&resp),
        "the fifty-first live grant was made: {resp:?}"
    );
    assert!(error_message(&resp).contains("50 live read grants"));
    assert_eq!(count().await, 50);
}
