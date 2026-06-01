//! API Documentation Module
//!
//! Provides comprehensive API documentation including:
//! - GraphQL Schema Definition Language (SDL) export
//! - Interactive GraphQL Playground (security-controlled)
//! - REST endpoint documentation
//! - Example queries and mutations
//! - Rate limit documentation
//!
//! Security:
//! - GraphQL introspection and playground disabled in production
//! - Schema export requires authentication
//! - Rate limits apply to documentation endpoints

use axum::{
    extract::Extension,
    http::{header, StatusCode},
    response::{Html, Json, Response},
    routing::get,
    Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use talos_api::TalosSchema;
use talos_errors::AppError;

/// GraphQL Schema SDL export handler
/// Returns the complete GraphQL schema in SDL format
pub async fn graphql_schema_handler(
    Extension(schema): Extension<TalosSchema>,
) -> Result<Response, AppError> {
    let sdl = schema.sdl();

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/graphql")
        .header(header::CACHE_CONTROL, "public, max-age=3600")
        .body(sdl.into())
        .map_err(|e| AppError::internal(format!("Failed to build response: {}", e)))
}

/// GraphQL Playground HTML source handler
/// Serves the GraphQL Playground IDE for interactive API exploration
/// Disabled in production (RUST_ENV=production)
pub async fn graphql_playground_handler() -> Result<Response, AppError> {
    // Security: Only serve playground in non-production environments
    let is_production = talos_config::is_production();

    if is_production {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body("GraphQL Playground is disabled in production".into())
            .map_err(|e| AppError::internal(format!("Failed to build response: {}", e)));
    }

    // Custom Playground HTML with Talos branding and security headers
    let playground_html = r##"<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Talos API Explorer</title>
    <link rel="stylesheet" href="https://unpkg.com/@graphql-playground-react@1.7.27/build/static/css/index.css" />
    <script src="https://unpkg.com/@graphql-playground-react@1.7.27/build/static/js/middleware.js"></script>
    <link rel="shortcut icon" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='.9em' font-size='90'%3E&#128038;%3C/text%3E%3C/svg%3E" />
    <style>
        body { margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        #root { height: 100vh; width: 100vw; }
        .playground-header { position: fixed; top: 0; left: 0; right: 0; height: 48px; background: #1a1a2e; color: white; display: flex; align-items: center; padding: 0 20px; z-index: 100; font-size: 14px; }
        .playground-header h1 { margin: 0; font-size: 16px; font-weight: 600; }
        .playground-header .badge { margin-left: 12px; padding: 2px 8px; background: #4f46e5; border-radius: 4px; font-size: 11px; text-transform: uppercase; }
    </style>
</head>
<body>
    <div class="playground-header"><h1>&#128038; Talos API Explorer</h1><span class="badge">Development</span></div>
    <div id="root" style="padding-top: 48px;"></div>
    <script>
        window.addEventListener("DOMContentLoaded", function() {
            GraphQLPlayground.init(document.getElementById("root"), {
                endpoint: "/graphql",
                subscriptionEndpoint: window.location.origin.replace("http", "ws") + "/graphql",
                settings: { "editor.cursorShape": "line", "editor.fontSize": 14, "editor.theme": "dark", "request.credentials": "include", "schema.polling.enable": false },
                tabs: [{ name: "Get Templates", query: "query GetTemplates { nodeTemplates { id name description category version inputs outputs } }", variables: {} }]
            });
        });
    </script>
</body>
</html>"##;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/html; charset=utf-8")
        .header(header::CACHE_CONTROL, "no-store, no-cache, must-revalidate")
        .header(header::X_FRAME_OPTIONS, "SAMEORIGIN")
        .header(header::CONTENT_SECURITY_POLICY, "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' unpkg.com; style-src 'self' 'unsafe-inline' unpkg.com; img-src 'self' data:;")
        .body(playground_html.into())
        .map_err(|e| AppError::internal(format!("Failed to build response: {}", e)))
}

/// REST API Endpoint Documentation
#[derive(Debug, Serialize, Deserialize)]
pub struct EndpointDoc {
    pub path: String,
    pub method: String,
    pub description: String,
    pub authentication: String,
    pub scopes: Vec<String>,
    pub rate_limit: String,
    pub example_request: Option<serde_json::Value>,
    pub example_response: Option<serde_json::Value>,
}

/// API Documentation Response
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiDocumentation {
    pub version: String,
    pub description: String,
    pub base_url: String,
    pub graphql: GraphQlDoc,
    pub rest_endpoints: Vec<EndpointDoc>,
    pub rate_limits: RateLimitDoc,
    pub idempotency: IdempotencyDoc,
    pub authentication: AuthDoc,
}

/// GraphQL Documentation
#[derive(Debug, Serialize, Deserialize)]
pub struct GraphQlDoc {
    pub endpoint: String,
    pub playground_url: Option<String>,
    pub schema_url: String,
    pub subscriptions: bool,
    pub introspection: bool,
    pub description: String,
}

/// Rate Limiting Documentation
#[derive(Debug, Serialize, Deserialize)]
pub struct RateLimitDoc {
    pub graphql_per_minute: u32,
    pub webhook_per_minute: u32,
    pub general_per_minute: u32,
    pub burst_allowance: u32,
    pub header_description: String,
}

/// Idempotency Documentation — the opt-in `Idempotency-Key` contract.
#[derive(Debug, Serialize, Deserialize)]
pub struct IdempotencyDoc {
    pub header: String,
    pub applies_to: String,
    pub key_format: String,
    pub behavior: String,
    pub replay_header: String,
}

/// Authentication Documentation
#[derive(Debug, Serialize, Deserialize)]
pub struct AuthDoc {
    pub methods: Vec<String>,
    pub jwt_expiry: String,
    pub api_key_scopes: Vec<ApiKeyScopeDoc>,
    pub mfa_required: bool,
}

/// API Key Scope Documentation
#[derive(Debug, Serialize, Deserialize)]
pub struct ApiKeyScopeDoc {
    pub scope: String,
    pub description: String,
}

/// Generate complete API documentation
pub fn generate_api_documentation() -> ApiDocumentation {
    let is_production = talos_config::is_production();

    // MCP-653: empty-env class. `BASE_URL: ""` previously produced an
    // empty string used to compose every generated endpoint URL in
    // the docs response (`{}/graphql`, etc.). Route through the
    // canonical helper so empty is treated as unset. Same fix shape
    // as MCP-630/631.
    let base_url = talos_config::get_env("BASE_URL", "http://localhost:3000");

    ApiDocumentation {
        version: env!("CARGO_PKG_VERSION").to_string(),
        description: "Talos Workflow Automation Platform API".to_string(),
        base_url: base_url.clone(),
        graphql: GraphQlDoc {
            endpoint: format!("{}/graphql", base_url),
            playground_url: if is_production { None } else { Some(format!("{}/graphql/playground", base_url)) },
            schema_url: format!("{}/graphql/schema", base_url),
            subscriptions: true,
            introspection: !is_production,
            description: "Primary API for all Talos operations. Supports queries, mutations, and real-time subscriptions.".to_string(),
        },
        rest_endpoints: vec![
            EndpointDoc {
                path: "/health".to_string(),
                method: "GET".to_string(),
                description: "Comprehensive health check including database, Redis, and NATS connectivity".to_string(),
                authentication: "None".to_string(),
                scopes: vec![],
                rate_limit: "100/minute".to_string(),
                example_request: None,
                example_response: Some(json!({
                    "status": "healthy",
                    "timestamp": "2024-01-01T00:00:00Z",
                    "services": { "database": "connected", "redis": "connected", "nats": "connected" }
                })),
            },
            EndpointDoc {
                path: "/health/redis".to_string(),
                method: "GET".to_string(),
                description: "Redis-specific health check".to_string(),
                authentication: "None".to_string(),
                scopes: vec![],
                rate_limit: "100/minute".to_string(),
                example_request: None,
                example_response: Some(json!({"status": "healthy", "service": "redis"})),
            },
            EndpointDoc {
                path: "/health/nats".to_string(),
                method: "GET".to_string(),
                description: "NATS-specific health check".to_string(),
                authentication: "None".to_string(),
                scopes: vec![],
                rate_limit: "100/minute".to_string(),
                example_request: None,
                example_response: Some(json!({"status": "healthy", "service": "nats"})),
            },
            // MCP-849 (2026-05-14): correct doc-reality drift on metrics
            // routes. Pre-fix `/metrics` was documented as "Prometheus
            // metrics endpoint" with `# HELP talos_requests_total Total
            // requests` example — that's wrong on two dimensions:
            //   * the controller serves Prometheus-format at
            //     `/metrics/prometheus`, not `/metrics`. Operators
            //     setting up scrape configs against `/metrics` would get
            //     JSON dashboard data that Prometheus can't parse and
            //     fail their scrape silently (no metrics surfaced for
            //     this controller in dashboards) or noisily (parse
            //     errors in scrape logs).
            //   * `/metrics` accepts session/JWT only (no API key path);
            //     pre-fix the `scopes: ["admin"]` claim was misleading
            //     because no API key with `admin` scope would actually
            //     work — operators would create such a key and still
            //     get 401.
            EndpointDoc {
                path: "/metrics".to_string(),
                method: "GET".to_string(),
                description: "Authenticated metrics dashboard (JSON). Served to the operator UI via the /graphql proxy; NOT a Prometheus scrape target.".to_string(),
                authentication: "Session cookie or Bearer JWT. NOT API key.".to_string(),
                scopes: vec![],
                rate_limit: "60/minute".to_string(),
                example_request: None,
                example_response: Some(json!({
                    "uptime_seconds": 12345,
                    "total_requests": 100000,
                    "active_executions": 42
                })),
            },
            EndpointDoc {
                path: "/metrics/prometheus".to_string(),
                method: "GET".to_string(),
                description: "Prometheus scrape endpoint (text format). In-cluster only — Helm chart marks this `no-nginx-route` so it's not externally reachable.".to_string(),
                authentication: "PROMETHEUS_SCRAPE_TOKEN env-bound bearer token (required in production). NOT API key.".to_string(),
                scopes: vec![],
                rate_limit: "60/minute".to_string(),
                example_request: None,
                example_response: Some(json!("# HELP talos_requests_total Total requests\n# TYPE talos_requests_total counter\ntalos_requests_total 12345")),
            },
            // MCP-848 (2026-05-14): four endpoints below previously
            // documented non-existent API key scopes (`webhooks:execute`,
            // `oauth:write`, `modules:read` — none of which ApiKeyScope
            // recognises). Either the docs invented scope names that
            // never shipped, OR these endpoints use a different auth
            // mechanism entirely:
            //   * /webhooks/{webhook_id} — per-webhook HMAC signature
            //     or verification_token (NOT API key scope).
            //   * /auth/oauth/{provider}/login — browser session cookie
            //     (NOT API key scope). The doc path also drifted from
            //     the actual route (`/oauth/{provider}/start` is
            //     fictional; real path is `/auth/oauth/...`).
            //   * /api/registry/* — REGISTRY_PUBLISH_TOKEN bearer auth
            //     (NOT API key scope). Real path is /api/registry/publish
            //     (the modules-read/download paths in the docs are
            //     aspirational and not implemented).
            // The `authentication` field already describes the mechanism;
            // the `scopes` field is for API key scope grants and should
            // be empty when the endpoint doesn't accept API keys.
            EndpointDoc {
                path: "/webhooks/{webhook_id}".to_string(),
                method: "POST".to_string(),
                description: "Trigger a webhook execution".to_string(),
                authentication: "Per-webhook HMAC signature OR verification_token (X-Verification-Token header). NOT API key.".to_string(),
                scopes: vec![],
                rate_limit: "1000/minute".to_string(),
                example_request: Some(json!({ "event": "user.created", "data": { "user_id": "uuid-here" } })),
                example_response: Some(json!({ "execution_id": "uuid-here", "status": "queued" })),
            },
            EndpointDoc {
                path: "/auth/oauth/{provider}/login".to_string(),
                method: "GET".to_string(),
                description: "Initiate OAuth flow for external service integration. Browser-initiated; returns a redirect URL.".to_string(),
                authentication: "Session cookie (browser-initiated). NOT API key.".to_string(),
                scopes: vec![],
                rate_limit: "30/minute".to_string(),
                example_request: None,
                example_response: Some(json!({"authorization_url": "https://oauth-provider.com/authorize?..."})),
            },
            EndpointDoc {
                path: "/api/registry/publish".to_string(),
                method: "POST".to_string(),
                description: "Publish a compiled WASM module to the global catalog (operator-only).".to_string(),
                authentication: "Bearer token: REGISTRY_PUBLISH_TOKEN env-bound. NOT API key.".to_string(),
                scopes: vec![],
                rate_limit: "60/minute".to_string(),
                example_request: None,
                example_response: Some(json!({ "module_id": "uuid", "kind": "catalog" })),
            },
        ],
        // MCP-855 (2026-05-14): correct MCP-850's own drift — values
        // were taken from `RateLimitConfig::api()` in talos-rate-limit
        // which is the TEST helper (env `RATE_LIMIT_API_REQUESTS`,
        // default 300). The PRODUCTION limiter is built in
        // controller/src/main.rs::main at line 1155-1178 reading env
        // `API_RATE_LIMIT` (default 100). Helm chart sets these to
        // `API_RATE_LIMIT: "1000"` / `WEBHOOK_RATE_LIMIT: "500"` /
        // `GLOBAL_RATE_LIMIT: "10000"` — the default Talos deploy
        // serves an order of magnitude more than the unset defaults.
        //
        // Numbers below reflect the CODE DEFAULTS (when env unset)
        // since the doc is a reference for operators who haven't
        // installed via Helm. Burst is `(limit/5).max(10)` for api,
        // `(limit/6).max(5)` for webhook, `(limit/2).max(500)` for
        // global — so the "100 burst" pre-fix value was wrong on
        // both api (20) and global (500) sides.
        //
        // Pre-MCP-850 drift / MCP-850 errata:
        //   * graphql_per_minute: 300 → actual default 100.
        //   * webhook_per_minute: 1000 / fixed to 60 (correct).
        //   * general_per_minute: 100 / fixed to 300 → actual 100.
        //   * burst_allowance: 10 / fixed to 100 → actual ~20 default,
        //     ~200 at Helm deploy.
        // env name `RATE_LIMIT_API_REQUESTS` in MCP-850 header → wrong;
        // production env is `API_RATE_LIMIT`.
        rate_limits: RateLimitDoc {
            graphql_per_minute: 100,
            webhook_per_minute: 60,
            general_per_minute: 100,
            burst_allowance: 20,
            header_description: "Rate limit headers: X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset. Per-IP limits enforced; defaults above are CODE defaults — overridable via API_RATE_LIMIT / WEBHOOK_RATE_LIMIT / GLOBAL_RATE_LIMIT envs (the Helm chart at deploy/helm/talos/values.yaml sets API_RATE_LIMIT=1000, WEBHOOK_RATE_LIMIT=500, GLOBAL_RATE_LIMIT=10000 by default). Burst is `(limit/5).max(10)` for API, `(limit/6).max(5)` for webhooks, `(limit/2).max(500)` for global. /health, /live, /ready are exempt.".to_string(),
        },
        idempotency: IdempotencyDoc {
            header: "Idempotency-Key".to_string(),
            applies_to: "Opt-in on GraphQL mutations (POST /graphql). Send a unique key per logical operation to make retries safe (exactly-once). Requires Redis; requests WITHOUT the header are unaffected.".to_string(),
            key_format: "1–255 printable-ASCII characters (no spaces or control chars); a UUID per operation is recommended.".to_string(),
            behavior: "The first request with a given key executes and its response is cached. A retry with the SAME key + SAME body replays the cached response (status + body + Content-Type) instead of re-executing. A concurrent duplicate (same key still in flight) returns 409 Conflict. Reusing a key with a DIFFERENT request body returns 422. A malformed key returns 400. Responses are cached for 24h; 5xx responses are NOT cached so the operation can be safely retried.".to_string(),
            replay_header: "idempotent-replayed: true (present only on replayed cache-hit responses)".to_string(),
        },
        authentication: AuthDoc {
            methods: vec![
                "JWT Session (HTTP-only cookies)".to_string(),
                "API Key (Header: X-API-Key)".to_string(),
                "Bearer Token (Header: Authorization: Bearer <token>)".to_string(),
            ],
            // MCP-850 (2026-05-14): pre-fix `jwt_expiry: "7 days"` was
            // misleading — operators reading the docs would assume their
            // JWT access token lasts 7 days. Reality: access token TTL
            // is 15 minutes (talos-auth/src/lib.rs:789); 7 days is the
            // REFRESH token TTL (line 832). An operator caching the
            // access token for 7 days would see frequent 401s after
            // 15 min and not understand why. The new string surfaces
            // both numbers honestly.
            jwt_expiry: "Access token: 15 minutes; refresh token: 7 days (rotated on every refresh).".to_string(),
            // MCP-847 (2026-05-14): render from canonical
            // `ApiKeyScope::ALL` so docs can't drift from the parser.
            // Pre-fix this hand-list advertised FIVE phantom scopes
            // ("modules:read", "modules:write", "executions:read",
            // "executions:write", "webhooks:read", "webhooks:write")
            // that `ApiKeyScope::from_string` doesn't recognize —
            // operators following the docs would create API keys with
            // all-unknown scopes (silently dropped by the parser),
            // land with zero effective permissions, and see
            // "Insufficient API key permissions" on every request
            // with no clue from the docs why.
            api_key_scopes: talos_auth_types::ApiKeyScope::ALL
                .iter()
                .map(|s| ApiKeyScopeDoc {
                    scope: s.to_string(),
                    description: match s {
                        talos_auth_types::ApiKeyScope::Admin => "Full administrative access",
                        talos_auth_types::ApiKeyScope::WorkflowsRead => "Read workflows",
                        talos_auth_types::ApiKeyScope::WorkflowsWrite => "Create and modify workflows",
                        talos_auth_types::ApiKeyScope::SecretsRead => "Read secrets metadata",
                        talos_auth_types::ApiKeyScope::SecretsWrite => "Create and modify secrets",
                        talos_auth_types::ApiKeyScope::WebhooksAccess => "Access webhooks (read + write)",
                    }
                    .to_string(),
                })
                .collect(),
            mfa_required: true,
        },
    }
}

/// JSON API documentation handler
pub async fn api_docs_json_handler() -> Result<Json<ApiDocumentation>, AppError> {
    let docs = generate_api_documentation();
    Ok(Json(docs))
}

/// HTML API documentation handler (simple documentation page)
pub async fn api_docs_html_handler() -> Html<String> {
    let is_production = talos_config::is_production();

    let playground_section = if is_production {
        r##"<div class="notice warning">GraphQL Playground is disabled in production. Use the <a href="/graphql/schema">Schema Endpoint</a> to introspect the API.</div>"##.to_string()
    } else {
        r##"<div class="notice info">Interactive API Explorer available at <a href="/graphql/playground">/graphql/playground</a></div>"##.to_string()
    };

    let playground_link = if is_production {
        "".to_string()
    } else {
        r##"<li><a href="/graphql/playground">Playground (Interactive)</a></li>"##.to_string()
    };

    let version = env!("CARGO_PKG_VERSION");

    let html = format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Talos API Documentation</title>
    <style>
        :root {{ --primary: #4f46e5; --primary-dark: #4338ca; --bg: #f9fafb; --text: #111827; --text-secondary: #6b7280; --border: #e5e7eb; --success: #10b981; --warning: #f59e0b; --code-bg: #1f2937; }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 40px 20px; }}
        header {{ background: linear-gradient(135deg, var(--primary), var(--primary-dark)); color: white; padding: 60px 20px; text-align: center; }}
        header h1 {{ font-size: 2.5rem; margin-bottom: 10px; }}
        header p {{ font-size: 1.2rem; opacity: 0.9; }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 24px; margin-top: 40px; }}
        .card {{ background: white; border-radius: 12px; padding: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); border: 1px solid var(--border); }}
        .card h2 {{ font-size: 1.25rem; margin-bottom: 16px; color: var(--primary); }}
        .card h3 {{ font-size: 1rem; margin: 20px 0 10px; color: var(--text); }}
        .endpoint {{ background: var(--code-bg); border-radius: 6px; padding: 12px; margin: 8px 0; font-family: Monaco, Menlo, monospace; font-size: 0.85rem; }}
        .method {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-weight: 600; font-size: 0.75rem; margin-right: 8px; }}
        .method.get {{ background: var(--success); color: white; }}
        .method.post {{ background: var(--primary); color: white; }}
        .notice {{ border-radius: 8px; padding: 16px; margin: 20px 0; font-size: 0.95rem; }}
        .notice.info {{ background: #dbeafe; border: 1px solid #3b82f6; }}
        .notice.warning {{ background: #fef3c7; border: 1px solid var(--warning); }}
        .notice.success {{ background: #d1fae5; border: 1px solid var(--success); }}
        code {{ background: var(--code-bg); color: #e5e7eb; padding: 2px 6px; border-radius: 4px; font-family: Monaco, Menlo, monospace; font-size: 0.9em; }}
        pre {{ background: var(--code-bg); color: #e5e7eb; padding: 16px; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; margin: 12px 0; }}
        .badge {{ display: inline-block; padding: 2px 8px; background: var(--bg); border: 1px solid var(--border); border-radius: 4px; font-size: 0.75rem; color: var(--text-secondary); margin-right: 8px; }}
        table {{ width: 100%%; border-collapse: collapse; margin: 16px 0; font-size: 0.9rem; }}
        th, td {{ text-align: left; padding: 12px; border-bottom: 1px solid var(--border); }}
        th {{ font-weight: 600; color: var(--text-secondary); font-size: 0.8rem; text-transform: uppercase; }}
        a {{ color: var(--primary); text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
        .section {{ margin-top: 40px; }}
        .section-title {{ font-size: 1.5rem; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid var(--primary); }}
        footer {{ text-align: center; padding: 40px; color: var(--text-secondary); font-size: 0.9rem; }}
    </style>
</head>
<body>
    <header><h1>&#128038; Talos API Documentation</h1><p>Workflow Automation Platform | Version {}</p></header>
    <div class="container">
        {}
        <div class="grid">
            <div class="card">
                <h2>&#128268; GraphQL API</h2>
                <p>Primary API for all Talos operations. Supports queries, mutations, and real-time subscriptions.</p>
                <h3>Endpoints</h3>
                <div class="endpoint"><span class="method post">POST</span>/graphql</div>
                <div class="endpoint"><span class="method get">WS</span>/graphql (WebSocket for subscriptions)</div>
                <h3>Resources</h3>
                <ul>
                    <li><a href="/graphql/schema">Schema (SDL)</a></li>
                    {}
                    <li><a href="/api/docs.json">JSON Documentation</a></li>
                </ul>
            </div>
            <div class="card">
                <h2>&#128272; Authentication</h2>
                <p>Multiple authentication methods supported with granular API key scopes.</p>
                <h3>Methods</h3>
                <ul>
                    <li><strong>JWT Session</strong> - HTTP-only cookies</li>
                    <li><strong>API Key</strong> - Header: <code>X-API-Key</code></li>
                    <li><strong>Bearer Token</strong> - Header: <code>Authorization: Bearer &lt;token&gt;</code></li>
                </ul>
                <div class="notice success">Two-factor authentication required for sensitive operations</div>
            </div>
            <div class="card">
                <h2>&#9201; Rate Limits</h2>
                <!-- MCP-855 (2026-05-14): match corrected JSON doc.
                     MCP-850/851 picked values from the test helper
                     (RATE_LIMIT_API_REQUESTS default 300) — production
                     env is API_RATE_LIMIT (default 100). Helm sets
                     1000/500/10000 by default. -->
                <table><tr><th>Endpoint</th><th>Code default</th><th>Helm default</th></tr><tr><td>GraphQL / API (per IP)</td><td>100/minute</td><td>1000/minute</td></tr><tr><td>Webhooks (per IP)</td><td>60/minute</td><td>500/minute</td></tr><tr><td>Global (system-wide)</td><td>1000/minute</td><td>10000/minute</td></tr></table>
                <p>Per-IP and global limits enforced. Env vars: <code>API_RATE_LIMIT</code>, <code>WEBHOOK_RATE_LIMIT</code>, <code>GLOBAL_RATE_LIMIT</code>. Burst sizes are derived: API = <code>(limit/5).max(10)</code>, webhook = <code>(limit/6).max(5)</code>, global = <code>(limit/2).max(500)</code>. Probe paths (<code>/health</code>, <code>/live</code>, <code>/ready</code>) are exempt.</p>
                <p>Rate limit headers included in all responses:</p>
                <ul>
                    <li><code>X-RateLimit-Limit</code></li>
                    <li><code>X-RateLimit-Remaining</code></li>
                    <li><code>X-RateLimit-Reset</code></li>
                </ul>
            </div>
            <div class="card">
                <h2>&#127973; Health Checks</h2>
                <p>Monitor system status and dependencies.</p>
                <div class="endpoint"><span class="method get">GET</span><a href="/health">/health</a></div>
                <div class="endpoint"><span class="method get">GET</span><a href="/health/redis">/health/redis</a></div>
                <div class="endpoint"><span class="method get">GET</span><a href="/health/nats">/health/nats</a></div>
            </div>
            <div class="card">
                <h2>&#128260; Idempotency</h2>
                <p>Make retried mutations safe (exactly-once) by sending an <code>Idempotency-Key</code> header. Opt-in &mdash; requests without the header are unaffected.</p>
                <h3>Usage</h3>
                <div class="endpoint"><span class="method post">POST</span>/graphql + <code>Idempotency-Key: &lt;uuid&gt;</code></div>
                <p>A retry with the same key + same body replays the cached response (stamped <code>idempotent-replayed: true</code>). Concurrent duplicate &rarr; <code>409</code>; key reused with a different body &rarr; <code>422</code>; malformed key &rarr; <code>400</code>. Cached 24h; 5xx responses are not cached so they stay retryable.</p>
            </div>
        </div>
        <div class="section">
            <h2 class="section-title">&#128202; GraphQL Example Queries</h2>
            <div class="card">
                <h3>Get Node Templates</h3>
                <pre>query GetTemplates {{ nodeTemplates {{ id name description category version inputs outputs }} }}</pre>
                <h3>My Compiled Modules</h3>
                <pre>query MyModules {{ myModules {{ id templateId name compiledAt executionCount }} }}</pre>
                <h3>Create Module from Template</h3>
                <pre>mutation CreateModule($input: CreateModuleInput!) {{ createModuleFromTemplate(input: $input) {{ id name status }} }}</pre>
            </div>
        </div>
        <div class="section">
            <h2 class="section-title">&#128279; REST Endpoints</h2>
            <div class="card">
                <table>
                    <!-- MCP-851 (2026-05-14): mirror JSON-doc corrections
                         MCP-848 / MCP-849. Pre-fix:
                           /metrics: "Admin" auth (wrong — session/JWT only,
                              no API key path).
                           /metrics: "Prometheus metrics" desc (wrong —
                              that's /metrics/prometheus).
                           /webhooks/:id: "HMAC/API Key" auth (no API key
                              auth path; HMAC sig OR verification_token).
                           /oauth/:provider/start: fictional path (real
                              route is /auth/oauth/:provider/login).
                           /api/registry/modules: "API Key" auth (wrong —
                              REGISTRY_PUBLISH_TOKEN bearer); also the
                              modules-list path is aspirational, real
                              route is /api/registry/publish. -->
                    <tr><th>Endpoint</th><th>Method</th><th>Auth</th><th>Description</th></tr>
                    <tr><td>/health</td><td><span class="method get">GET</span></td><td>None</td><td>System health check (DB + Redis + NATS)</td></tr>
                    <tr><td>/metrics</td><td><span class="method get">GET</span></td><td>Session / JWT</td><td>Authenticated dashboard JSON</td></tr>
                    <tr><td>/metrics/prometheus</td><td><span class="method get">GET</span></td><td>PROMETHEUS_SCRAPE_TOKEN bearer</td><td>Prometheus scrape (text format, in-cluster only)</td></tr>
                    <tr><td>/webhooks/:id</td><td><span class="method post">POST</span></td><td>HMAC signature OR verification_token</td><td>Trigger webhook</td></tr>
                    <tr><td>/auth/oauth/:provider/login</td><td><span class="method get">GET</span></td><td>Session (browser)</td><td>OAuth initiation</td></tr>
                    <tr><td>/api/registry/publish</td><td><span class="method post">POST</span></td><td>REGISTRY_PUBLISH_TOKEN bearer</td><td>Publish a compiled module to catalog (operator-only)</td></tr>
                </table>
            </div>
        </div>
    </div>
    <footer>
        <p>Talos Workflow Automation Platform | Built with Rust &#129408;</p>
        <p>For support, contact the platform team.</p>
    </footer>
</body>
</html>"##,
        version, playground_section, playground_link
    );

    Html(html)
}

/// Create router for API documentation endpoints
pub fn create_docs_router() -> Router {
    Router::new()
        .route("/docs", get(api_docs_html_handler))
        .route("/docs.json", get(api_docs_json_handler))
        .route("/graphql/schema", get(graphql_schema_handler))
        .route("/graphql/playground", get(graphql_playground_handler))
}

/// Middleware to add documentation-related headers
pub async fn docs_headers_middleware(
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        header::LINK,
        header::HeaderValue::from_static("</docs>; rel=\"help\""),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_api_documentation() {
        let docs = generate_api_documentation();
        assert!(!docs.version.is_empty());
        assert!(!docs.graphql.endpoint.is_empty());
        assert!(!docs.rest_endpoints.is_empty());
        assert!(!docs.authentication.api_key_scopes.is_empty());
    }

    #[test]
    fn test_endpoint_doc_structure() {
        let endpoint = EndpointDoc {
            path: "/test".to_string(),
            method: "GET".to_string(),
            description: "Test endpoint".to_string(),
            authentication: "None".to_string(),
            scopes: vec![],
            rate_limit: "100/min".to_string(),
            example_request: None,
            example_response: None,
        };
        let json = serde_json::to_string(&endpoint).expect("EndpointDoc must be serializable");
        assert!(json.contains("/test"));
        assert!(json.contains("GET"));
    }
}
