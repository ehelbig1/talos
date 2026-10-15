//! The tokenless local MCP route answers a caller on this machine and nobody
//! else (2026-10-13).
//!
//! `/mcp/local` has no token: outside production it serves every tool as the
//! first user. Its only condition was the build mode, so anything that put
//! the controller behind another address served it there too. Observed on a
//! development stack with a public tunnel running: a request to the tunnel's
//! address for `/mcp/local` was answered, while `/mcp` on the same address
//! asked for a token.
//!
//! Driven through the route as `create_router` mounts it
//! (`talos_mcp_handlers::local_router`), against a real database: the local
//! caller is served, and each way a request can show it came from somewhere
//! else is answered as if the route were not there.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.
//!
//! One test here sets `RUST_ENV` (to `staging`, then back): it drives the
//! mount decision `talos_mcp_handlers::mount_routes` makes, which reads the
//! variable. It never sets `production`, which other constructors in this
//! binary read at build time; `staging` changes only
//! `browser_hardening_required()`, which nothing else here consults.

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use mcp_common::mcp_state;
use serde_json::{json, Value};
use tower::ServiceExt;

async fn local_app() -> (Router, common::TestDb) {
    let (pool, db) = common::isolated_db_pool().await;
    // The route resolves "the first user"; give it one.
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) \
         VALUES (gen_random_uuid(), 'local-route@example.com', 'x', 'local')",
    )
    .execute(&pool)
    .await
    .expect("seed user");
    let state = mcp_state(pool.clone()).await;
    let app = Router::new().nest(
        "/mcp",
        controller::mcp::local_router(state.clone(), pool).with_state(state),
    );
    (app, db)
}

fn initialize(headers: &[(&str, &str)]) -> Request<Body> {
    let mut request = Request::builder()
        .method(Method::POST)
        .uri("/mcp/local")
        .header("content-type", "application/json");
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request
        .body(Body::from(
            json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {} }).to_string(),
        ))
        .unwrap()
}

async fn answer(app: &Router, request: Request<Body>) -> (StatusCode, Vec<u8>) {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("a bounded body");
    (status, body.to_vec())
}

#[tokio::test]
async fn a_caller_on_this_machine_is_served() {
    let (app, _db) = local_app().await;
    for host in [
        "localhost:8000",
        "127.0.0.1:8000",
        "[::1]:8000",
        "localhost",
        "LOCALHOST:8000",
    ] {
        let (status, body) = answer(&app, initialize(&[("host", host)])).await;
        assert_eq!(status, StatusCode::OK, "Host {host}");
        let reply: Value = serde_json::from_slice(&body).expect("a JSON-RPC reply");
        assert!(
            reply["result"]["serverInfo"].is_object(),
            "Host {host}: {reply}"
        );
    }
    // A page served from this machine may call it (the settings page of the
    // development UI does).
    let (status, _) = answer(
        &app,
        initialize(&[
            ("host", "localhost:8000"),
            ("origin", "http://localhost:3002"),
        ]),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// Each row is a request that did not start on this machine, or that a
/// browser made for a page that was not served from it.
#[tokio::test]
async fn a_request_that_came_from_anywhere_else_finds_no_route() {
    let (app, _db) = local_app().await;
    let elsewhere: &[(&str, &[(&str, &str)])] = &[
        // A tunnel or reverse proxy passes the public name through.
        ("the public name as Host", &[("host", "tunnel.example")]),
        (
            "a public name with a port",
            &[("host", "tunnel.example:443")],
        ),
        // …or rewrites Host and says so in a forwarding header, which the
        // caller cannot remove.
        (
            "X-Forwarded-For behind a rewritten Host",
            &[
                ("host", "localhost:8000"),
                ("x-forwarded-for", "203.0.113.7"),
            ],
        ),
        (
            "X-Forwarded-Host",
            &[
                ("host", "localhost:8000"),
                ("x-forwarded-host", "tunnel.example"),
            ],
        ),
        (
            "X-Forwarded-Proto",
            &[("host", "localhost:8000"), ("x-forwarded-proto", "https")],
        ),
        (
            "X-Real-IP",
            &[("host", "localhost:8000"), ("x-real-ip", "203.0.113.7")],
        ),
        (
            "Forwarded",
            &[("host", "localhost:8000"), ("forwarded", "for=203.0.113.7")],
        ),
        (
            "Via",
            &[("host", "localhost:8000"), ("via", "1.1 proxy.example")],
        ),
        // Another container on the same network.
        ("a service name as Host", &[("host", "controller:8000")]),
        // A name that only looks local.
        ("a look-alike name", &[("host", "localhost.tunnel.example")]),
        (
            "a look-alike address",
            &[("host", "127.0.0.1.tunnel.example")],
        ),
        // A page from another site, in a browser on this machine (including
        // one whose name was re-pointed at 127.0.0.1).
        (
            "a foreign Origin",
            &[
                ("host", "localhost:8000"),
                ("origin", "https://tunnel.example"),
            ],
        ),
        (
            "a null Origin",
            &[("host", "localhost:8000"), ("origin", "null")],
        ),
    ];
    for (what, headers) in elsewhere {
        let (status, body) = answer(&app, initialize(headers)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{what} was served");
        assert!(body.is_empty(), "{what}: the refusal says nothing");
    }
}

#[tokio::test]
async fn the_event_stream_follows_the_same_rule() {
    let (app, _db) = local_app().await;
    let get = |headers: &[(&str, &str)]| {
        let mut request = Request::builder().method(Method::GET).uri("/mcp/local");
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        request.body(Body::empty()).unwrap()
    };
    let response = app
        .clone()
        .oneshot(get(&[("host", "localhost:8000")]))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    for headers in [
        &[("host", "tunnel.example")][..],
        &[
            ("host", "localhost:8000"),
            ("x-forwarded-for", "203.0.113.7"),
        ][..],
    ] {
        let response = app.clone().oneshot(get(headers)).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}

/// A request with no Host at all names no machine; it is not served.
#[tokio::test]
async fn a_request_that_names_no_host_is_not_served() {
    let (app, _db) = local_app().await;
    let (status, _) = answer(&app, initialize(&[])).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

/// The route is MOUNTED only where no browser hardening is required
/// (2026-10-14). Under `RUST_ENV=staging` — what `docker-compose.prod.yml`
/// runs, facing real users — the loopback caller that the gate above serves
/// in development finds no route at all: the gate cannot tell a process on
/// the compose network that sends `Host: localhost` from this machine.
#[tokio::test]
async fn the_route_is_not_mounted_outside_development() {
    let (pool, _db) = common::isolated_db_pool().await;
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) \
         VALUES (gen_random_uuid(), 'local-mount@example.com', 'x', 'local')",
    )
    .execute(&pool)
    .await
    .expect("seed user");
    let state = mcp_state(pool.clone()).await;
    let mounted = |state: controller::mcp::McpState| {
        Router::new().nest("/mcp", controller::mcp::mount_routes(state, pool.clone()))
    };
    let before = std::env::var("RUST_ENV").ok();

    std::env::set_var("RUST_ENV", "development");
    let development = mounted(state.clone());
    std::env::set_var("RUST_ENV", "staging");
    let staging = mounted(state);
    match &before {
        Some(v) => std::env::set_var("RUST_ENV", v),
        None => std::env::remove_var("RUST_ENV"),
    }

    let (status, _) = answer(&development, initialize(&[("host", "localhost:8000")])).await;
    assert_eq!(status, StatusCode::OK, "development mounts the local route");
    let (status, body) = answer(&staging, initialize(&[("host", "localhost:8000")])).await;
    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "RUST_ENV=staging must not mount /mcp/local"
    );
    assert!(body.is_empty(), "the refusal says nothing");
}
