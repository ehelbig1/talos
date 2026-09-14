//! MCP agent-token authentication is the third bearer credential the
//! controller accepts and, until 2026-09-13, the only one whose refusals were
//! counted nowhere and logged nowhere: `mcp_auth_middleware` answered a
//! guessed token with a bare 401 and nothing else happened, while
//! `ApiKeyService::validate_key` and the interactive login both counted and
//! logged theirs. This binary drives the PRODUCTION middleware — mounted on a
//! router the way `mcp_router` mounts it — against real `mcp_agents` rows and
//! reads `talos_mcp_auth_total{outcome}` and
//! `talos_rate_limit_hits_total{type="mcp_auth"}` off the process-global
//! registry as DELTAS.
//!
//! It exists beside the talos-metrics unit test because of check 58's stated
//! wrapper limit: that test proves the recorder moves the series; this one
//! proves every path a request can take through the middleware REACHES the
//! recorder — the middleware funnels its six refusals through one enum and
//! one `match`, and this is what proves the funnel is wired to the paths.
mod common;

use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{header, Request, StatusCode},
    middleware,
    routing::post,
    Router,
};
use common::{create_test_user, setup_test_context};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use std::net::SocketAddr;
use talos_mcp_handlers::auth::mcp_auth_middleware;
use talos_metrics::{ApiKeyValidation, McpAuthOutcome, RateLimitKind, TalosMetrics};
use tower::ServiceExt;
use uuid::Uuid;

/// One `mcp_agents` row behind a fresh role. `token_hash` is bcrypt of
/// `bcrypt_of` and `token_lookup_hash` is SHA-256 of `lookup_of` — the SAME
/// token for an honest row, DIFFERENT for the corrupted-row case that is the
/// only way to reach `invalid_token`.
async fn seed_agent(pool: &PgPool, lookup_of: &str, bcrypt_of: &str, user_id: Option<Uuid>) {
    let role_id = Uuid::new_v4();
    sqlx::query("INSERT INTO agent_roles (id, name, allowed_capabilities) VALUES ($1, $2, $3)")
        .bind(role_id)
        .bind(format!("role-{role_id}"))
        .bind(vec!["minimal"])
        .execute(pool)
        .await
        .expect("insert role");
    let agent_id = Uuid::new_v4();
    // Cost 4 keeps the test fast; the middleware verifies whatever cost the
    // row carries.
    let token_hash = bcrypt::hash(bcrypt_of, 4).expect("bcrypt");
    let lookup = format!("{:x}", Sha256::digest(lookup_of.as_bytes()));
    sqlx::query(
        "INSERT INTO mcp_agents (id, user_id, name, role_id, token_hash, token_lookup_hash, is_active) \
         VALUES ($1, $2, $3, $4, $5, $6, true)",
    )
    .bind(agent_id)
    .bind(user_id)
    .bind(format!("agent-{agent_id}"))
    .bind(role_id)
    .bind(token_hash)
    .bind(lookup)
    .execute(pool)
    .await
    .expect("insert agent");
}

/// The production mount shape: `from_fn_with_state(pool, mcp_auth_middleware)`
/// as a route layer in front of a handler that only answers 200.
fn app(pool: PgPool) -> Router {
    Router::new()
        .route("/mcp", post(|| async { StatusCode::OK }))
        .route_layer(middleware::from_fn_with_state(pool, mcp_auth_middleware))
}

/// One `POST /mcp` from `ip` with an optional bearer. `ConnectInfo` is what
/// `into_make_service_with_connect_info` would have inserted.
async fn call(app: &Router, ip: &str, bearer: Option<&str>) -> StatusCode {
    let mut req = Request::builder()
        .method("POST")
        .uri("/mcp")
        .body(Body::empty())
        .expect("request");
    if let Some(t) = bearer {
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {t}").parse().expect("header value"),
        );
    }
    req.extensions_mut().insert(ConnectInfo(SocketAddr::new(
        ip.parse().expect("ip"),
        40_000,
    )));
    app.clone().oneshot(req).await.expect("response").status()
}

fn snapshot(m: &TalosMetrics) -> HashMap<McpAuthOutcome, f64> {
    McpAuthOutcome::ALL
        .iter()
        .map(|o| (*o, m.mcp_auth_total.with_label_values(&[o.as_str()]).get()))
        .collect()
}

/// The limiter's window cap, read the way the middleware reads it (default
/// 60) so a CI environment that sets `MCP_AUTH_RATE_LIMIT` still passes.
fn window_cap() -> u32 {
    std::env::var("MCP_AUTH_RATE_LIMIT")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(60)
}

/// Every outcome a request can produce, each moving exactly its own series,
/// with the API-key surface's series as the control that the two bearer
/// surfaces are separate. `error` is deliberately NOT driven here — it needs
/// an unreadable agent table under a live pool — and is covered by the unit
/// test in `talos-mcp-handlers` that runs the same function against a pool
/// that can never connect.
#[tokio::test]
async fn every_path_through_the_middleware_moves_its_own_outcome() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    talos_metrics::set_global(TalosMetrics::new().expect("metrics"));
    let m = talos_metrics::global().expect("global metrics installed");
    let count = |o: McpAuthOutcome| m.mcp_auth_total.with_label_values(&[o.as_str()]).get();
    let hits = || {
        m.rate_limit_hits_total
            .with_label_values(&[RateLimitKind::McpAuth.as_str()])
            .get()
    };
    let api_key_total = || {
        ApiKeyValidation::ALL
            .iter()
            .map(|v| {
                m.api_key_validations_total
                    .with_label_values(&[v.as_str()])
                    .get()
            })
            .sum::<f64>()
    };

    // Seeded: every outcome and the limiter kind render before the first
    // request, so the FIRST refusal is a 0 → 1 edge `increase()` can see.
    let rendered = m.render_prometheus().expect("render");
    for o in McpAuthOutcome::ALL {
        assert!(
            rendered.contains(&format!(
                "talos_mcp_auth_total{{outcome=\"{}\"}} ",
                o.as_str()
            )),
            "seeded: {}",
            o.as_str()
        );
    }
    assert!(rendered.contains("talos_rate_limit_hits_total{type=\"mcp_auth\"} "));

    let app = app(pool.clone());
    let user_id = create_test_user(&ctx.auth_service, "mcp-auth-metrics@example.com").await;
    let token = format!("tok-{}", Uuid::new_v4().simple());
    seed_agent(&pool, &token, &token, Some(user_id)).await;
    let before = snapshot(m);
    let hits_before = hits();
    let api_key_before = api_key_total();

    // A guessed token: the caller's bare 401, the operator's guessing signal.
    assert_eq!(
        call(&app, "198.51.100.1", Some("not-the-token")).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        count(McpAuthOutcome::UnknownToken),
        before[&McpAuthOutcome::UnknownToken] + 1.0
    );

    // No credential at all: the same 401, a different series.
    assert_eq!(
        call(&app, "198.51.100.2", None).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        count(McpAuthOutcome::MissingToken),
        before[&McpAuthOutcome::MissingToken] + 1.0
    );

    // The real token, twice: the second is served from the bcrypt cache and
    // is still one admission each.
    assert_eq!(
        call(&app, "198.51.100.3", Some(&token)).await,
        StatusCode::OK
    );
    assert_eq!(
        call(&app, "198.51.100.3", Some(&token)).await,
        StatusCode::OK
    );
    assert_eq!(count(McpAuthOutcome::Ok), before[&McpAuthOutcome::Ok] + 2.0);

    // A row whose two stored hashes disagree: the lookup hash matches the
    // presented token, the bcrypt hash was minted from another — the only
    // shape that reaches `invalid_token`, and it is a data-integrity signal,
    // not a guess.
    let lookup_only = format!("tok-{}", Uuid::new_v4().simple());
    seed_agent(
        &pool,
        &lookup_only,
        "minted-from-a-different-token",
        Some(user_id),
    )
    .await;
    assert_eq!(
        call(&app, "198.51.100.4", Some(&lookup_only)).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        count(McpAuthOutcome::InvalidToken),
        before[&McpAuthOutcome::InvalidToken] + 1.0
    );

    // Authenticated, bound to no user: the 403 `refuse_unscoped_agent` builds.
    let orphan = format!("tok-{}", Uuid::new_v4().simple());
    seed_agent(&pool, &orphan, &orphan, None).await;
    assert_eq!(
        call(&app, "198.51.100.5", Some(&orphan)).await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        count(McpAuthOutcome::UnscopedAgent),
        before[&McpAuthOutcome::UnscopedAgent] + 1.0
    );

    // The limiter: request cap+1 from one IP inside one window. The first
    // `cap` are refused for the (absent) credential, the next one by the
    // limiter — which moves BOTH series it belongs to.
    let cap = window_cap();
    let ip = "198.51.100.9";
    for i in 0..cap {
        assert_eq!(
            call(&app, ip, None).await,
            StatusCode::UNAUTHORIZED,
            "request {i}"
        );
    }
    assert_eq!(call(&app, ip, None).await, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        count(McpAuthOutcome::RateLimited),
        before[&McpAuthOutcome::RateLimited] + 1.0
    );
    assert_eq!(
        hits(),
        hits_before + 1.0,
        "the MCP limiter counts as a rate-limit hit"
    );
    assert_eq!(
        count(McpAuthOutcome::MissingToken),
        before[&McpAuthOutcome::MissingToken] + 1.0 + f64::from(cap),
        "the refusals before the cap were credential refusals, not limiter ones"
    );

    // Controls: nothing here reached the API-key surface's series, and the
    // undriven outcome did not move.
    assert_eq!(
        api_key_total(),
        api_key_before,
        "two bearer surfaces, two series"
    );
    assert_eq!(count(McpAuthOutcome::Error), before[&McpAuthOutcome::Error]);
}
