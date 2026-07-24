//! Route assembly, route-local middleware, and HTTP handlers for the
//! controller binary — moved VERBATIM out of `controller/src/main.rs` in the
//! 2026-07 decomposition. `build_router` itself (every `.route(...)`/`.nest(...)`
//! registration) now lives HERE, at the bottom of this module. Structural-lint
//! check 2 greps BOTH `controller/src/main.rs` AND this file for
//! `.route(`/`.nest(` path strings to enforce the route <-> nginx-ConfigMap
//! alignment, so the guardrail follows the registrations. This module owns the
//! handler/middleware bodies those registrations reference (CORS, health/probes,
//! CSRF seeding, metrics, REST auth, GraphQL, WebSocket, OAuth login/callback,
//! and the RFC 0010 worker self-registration endpoint + its helpers).
use crate::*;

/// RFC 0010 P2 inc.4: load the active `worker_identities` registry and install it
/// as job_protocol's dynamic verifying-key overlay (union with the env base).
/// Returns the number of keys installed. A stored key that is not a canonical
/// Ed25519 point is skipped with a warning rather than poisoning the snapshot —
/// one bad row can't strand the fleet (same fail-open-per-entry posture as the
/// env-registry parser). Shared by the boot load, the periodic refresh task, and
/// (inc.4c) the eager refresh after a registration write.
pub(crate) async fn refresh_worker_key_overlay(
    repo: &talos_worker_identity_repository::WorkerIdentityRepository,
) -> anyhow::Result<usize> {
    let entries = repo.load_active_registry().await?;
    let mut mapped = Vec::with_capacity(entries.len());
    for entry in entries {
        match talos_workflow_job_protocol::parse_ed25519_verifying_key_bytes(&entry.public_key) {
            Ok(vk) => mapped.push((entry.worker_id, vk)),
            Err(err) => tracing::warn!(
                target: "talos_engine",
                worker_id = %entry.worker_id,
                error = %err,
                "skipping malformed worker_identities public key"
            ),
        }
    }
    let installed = mapped.len();
    talos_workflow_job_protocol::set_dynamic_worker_public_keys(mapped);
    Ok(installed)
}

// ===== RFC 0010 P2 inc.4c: in-cluster worker self-registration endpoint =====
//
// `POST /internal/worker-key` — an autoscaling worker registers its Ed25519
// public key at boot without an operator touching a ConfigMap. Because workers
// run untrusted WASM and are credential-free, this endpoint is defended in depth:
//   1. NetworkPolicy (chart) restricts ingress to worker pods, in-cluster only —
//      the route is never exposed via nginx/Traefik (`no-nginx-route`).
//   2. A constant-time shared bearer token (TALOS_WORKER_REGISTRATION_TOKEN)
//      gates callers; when it is unset the route is not even mounted.
//   3. An Ed25519 proof-of-possession over the request proves the caller holds
//      the private key for the key it is registering (job_protocol PoP helpers).
//   4. A freshness window bounds replay of a captured request; registration is
//      idempotent so replay is otherwise benign.
//   5. The inc.4a per-worker active-key cap bounds table inflation.
//   6. TRUST-ON-FIRST-USE (P2 hardening): the shared token proves "a legit
//      worker pod", not a specific worker_id, so this path binds each worker_id
//      to its FIRST registered key. After that, only an idempotent refresh of
//      that exact active key is accepted — a different key, a revoked key, or a
//      claim on a retired worker_id is a 409 (`register_tofu`). Without this, a
//      compromised token-holder could register its own key under another
//      worker's id and impersonate it for result signing / P3 secret claims.
//      Rotation and revocation reversal are operator actions (the
//      `register-worker-identity` CLI, DB-credentialed) — workers never
//      generate keys in-pod, so a legitimate new key always accompanies an
//      operator anyway.
//
//   7. PER-WORKER PROVISIONING TOKENS (P2 hardening inc.2): a bearer that is
//      not the shared token is treated as a single-use provisioning token —
//      operator-minted, expiring, stored as SHA-256 only, and (when bound to a
//      worker_id) redeemable only for that worker. Consumption is atomic inside
//      the registration transaction; a refused registration does not burn the
//      token. `TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1` is the migration
//      end-state: shared token and wildcard tokens are refused, so EVERY
//      registration is an explicit operator grant for one worker_id — closing
//      the first-come-first-served residual TOFU leaves on never-before-seen
//      worker_ids.
//
// Residual (documented in the RFC): while enforcement is OFF (migration
// window), a shared-token/wildcard holder can still claim a never-before-seen
// worker_id first. mTLS client-certs with a worker_id-bound SAN remain the
// long-term alternative.

/// Registration-auth config, injected as an axum `Extension` on the internal
/// sub-router. At least one scheme is configured whenever the route is mounted.
/// No `Debug` derive — `shared_token` is a live bearer credential (check 37).
#[derive(Clone)]
pub(crate) struct WorkerRegAuth {
    /// Legacy shared bearer (`TALOS_WORKER_REGISTRATION_TOKEN`). `None` in a
    /// bound-token-only deployment.
    pub(crate) shared_token: Option<std::sync::Arc<String>>,
    /// `TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1` — the migration end-state:
    /// only single-use provisioning tokens BOUND to a worker_id register;
    /// the shared token and wildcard tokens are refused. Mirrors the
    /// accept-legacy-then-require rollout P1/P2 used for signing schemes.
    pub(crate) require_bound: bool,
}

/// Which authentication path a presented bearer takes. Decided by constant-time
/// comparison against the shared token; everything that is NOT the shared
/// token is treated as a provisioning-token candidate and resolved against the
/// DB (hashed lookup), so the classifier itself leaks nothing about validity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegBearerPath {
    /// Matches the shared token and enforcement is off → TOFU registration.
    LegacyShared,
    /// Matches the shared token but bound-token enforcement is on → refuse
    /// (distinct variant only so the handler can log the policy hit; the
    /// client response stays generic).
    SharedRefusedByPolicy,
    /// Anything else → try single-use provisioning-token redemption.
    Provisioning,
}

/// Classify the presented (non-empty) bearer.
fn classify_registration_bearer(
    provided: &str,
    shared: Option<&str>,
    require_bound: bool,
) -> RegBearerPath {
    use subtle::ConstantTimeEq;
    let is_shared = shared.is_some_and(|s| {
        // Length check first (ct_eq requires equal length); the compare itself
        // is constant-time so the token can't be recovered by timing.
        provided.len() == s.len() && bool::from(provided.as_bytes().ct_eq(s.as_bytes()))
    });
    match (is_shared, require_bound) {
        (true, false) => RegBearerPath::LegacyShared,
        (true, true) => RegBearerPath::SharedRefusedByPolicy,
        (false, _) => RegBearerPath::Provisioning,
    }
}

#[derive(serde::Deserialize)]
pub(crate) struct WorkerKeyRegistrationRequest {
    worker_id: String,
    /// Hex Ed25519 verifying key (32 bytes) being registered.
    public_key: String,
    #[serde(default)]
    supports_sealing: bool,
    /// Unix-millis when the worker built the request (freshness).
    issued_at_ms: u64,
    /// Anti-grinding nonce, bound into the proof.
    nonce: String,
    /// Hex Ed25519 signature (64 bytes) over the canonical PoP message.
    proof: String,
}

/// Freshness tolerances for a registration request. Asymmetric like `rpc_auth`:
/// generous on the past (clock skew + in-flight latency), tight on the future.
const WORKER_REG_PAST_MS: u64 = 300_000;
const WORKER_REG_FUTURE_MS: u64 = 60_000;

/// Freshness window for a registration request: reject stale (past the window)
/// or future-dated requests. Pure so it is unit-testable without a live server.
/// The client-facing message leaks no internal state.
fn check_registration_freshness(
    issued_at_ms: u64,
    now_ms: u64,
) -> Result<(), (axum::http::StatusCode, &'static str)> {
    use axum::http::StatusCode;
    if issued_at_ms.saturating_add(WORKER_REG_PAST_MS) < now_ms {
        return Err((StatusCode::BAD_REQUEST, "registration request expired"));
    }
    if issued_at_ms > now_ms.saturating_add(WORKER_REG_FUTURE_MS) {
        return Err((
            StatusCode::BAD_REQUEST,
            "registration issued_at is in the future",
        ));
    }
    Ok(())
}

/// SHA-256 hex of a presented bearer — the shape stored in
/// `worker_provisioning_tokens.token_hash`. The raw token is neither stored
/// nor used in any SQL comparison (lint check 41 discipline).
pub(crate) fn provisioning_token_hash(raw: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(Sha256::digest(raw.as_bytes()))
}

/// Extract a `Bearer <token>` value from the Authorization header.
fn bearer_token(headers: &axum::http::HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn worker_reg_error(
    status: axum::http::StatusCode,
    message: &str,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    (status, axum::Json(serde_json::json!({ "error": message })))
}

pub(crate) async fn register_worker_key_handler(
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(auth): Extension<WorkerRegAuth>,
    headers: axum::http::HeaderMap,
    axum::Json(req): axum::Json<WorkerKeyRegistrationRequest>,
) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    use axum::http::StatusCode;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);

    // 1) Bearer presence + freshness. Which auth path the bearer takes is
    //    decided AFTER shape + proof-of-possession pass, so a garbage request
    //    can never consume a single-use provisioning token.
    let Some(provided_bearer) = bearer_token(&headers) else {
        return worker_reg_error(StatusCode::UNAUTHORIZED, "missing bearer token");
    };
    if let Err((status, msg)) = check_registration_freshness(req.issued_at_ms, now_ms) {
        return worker_reg_error(status, msg);
    }

    // 2) Shape validation — worker_id charset + 32-byte canonical Ed25519 point.
    if let Err(e) = talos_workflow_job_protocol::validate_worker_id(&req.worker_id) {
        return worker_reg_error(StatusCode::BAD_REQUEST, leak_safe_validation(&e));
    }
    let public_key = match hex::decode(req.public_key.trim())
        .ok()
        .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
    {
        Some(pk) => pk,
        None => {
            return worker_reg_error(
                StatusCode::BAD_REQUEST,
                "public_key must be 64-char hex (32-byte Ed25519 key)",
            )
        }
    };
    let proof = match hex::decode(req.proof.trim()) {
        Ok(p) => p,
        Err(_) => return worker_reg_error(StatusCode::BAD_REQUEST, "proof must be hex"),
    };

    // 3) Proof-of-possession: the request is signed by the private key for the
    //    key being registered, binding every field.
    if talos_workflow_job_protocol::verify_worker_registration_proof(
        &public_key,
        &req.worker_id,
        req.supports_sealing,
        req.issued_at_ms,
        &req.nonce,
        &proof,
    )
    .is_err()
    {
        // Deliberately generic — do not distinguish "bad key" from "bad sig".
        return worker_reg_error(StatusCode::UNAUTHORIZED, "proof-of-possession failed");
    }

    // 4) Auth-path decision + persistence, then (on success) an eager refresh
    //    of the verify overlay so the worker's very first result verifies
    //    immediately. Shared token → TOFU rule (first key wins; only that key
    //    may refresh itself here). Anything else → single-use provisioning
    //    token: bound tokens carry operator-grade rotation semantics, wildcard
    //    tokens carry TOFU semantics and are refused entirely under
    //    TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1.
    let repo = talos_worker_identity_repository::WorkerIdentityRepository::new(db_pool);
    let path = classify_registration_bearer(
        provided_bearer,
        auth.shared_token.as_deref().map(String::as_str),
        auth.require_bound,
    );
    let outcome = match path {
        RegBearerPath::SharedRefusedByPolicy => {
            tracing::warn!(
                target: "talos_security",
                event_kind = "worker_reg_shared_token_refused",
                worker_id = %req.worker_id,
                "shared registration token presented but bound-token enforcement \
                 (TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN) is on; refusing. Mint a \
                 worker_id-bound provisioning token for this worker instead."
            );
            return worker_reg_error(StatusCode::UNAUTHORIZED, "invalid registration token");
        }
        RegBearerPath::LegacyShared => repo
            .register_tofu(&req.worker_id, &public_key, req.supports_sealing)
            .await
            .map(|o| match o {
                talos_worker_identity_repository::TofuOutcome::Registered => {
                    talos_worker_identity_repository::TokenRegisterOutcome::Registered
                }
                talos_worker_identity_repository::TofuOutcome::IdentityConflict => {
                    talos_worker_identity_repository::TokenRegisterOutcome::IdentityConflict
                }
            }),
        RegBearerPath::Provisioning => {
            // Hash the presented bearer; only the digest touches SQL. An
            // unknown/used/expired/revoked/misbound token collapses into ONE
            // client-facing 401 below.
            let token_hash = provisioning_token_hash(provided_bearer);
            repo.register_with_provisioning_token(
                &token_hash,
                &req.worker_id,
                &public_key,
                req.supports_sealing,
                auth.require_bound,
            )
            .await
        }
    };

    match outcome {
        Ok(talos_worker_identity_repository::TokenRegisterOutcome::Registered) => {
            if let Err(e) = refresh_worker_key_overlay(&repo).await {
                // Non-fatal: the periodic task will pick it up within its interval.
                tracing::warn!(
                    target: "talos_engine",
                    error = %e,
                    "eager worker-key overlay refresh after registration failed"
                );
            }
            tracing::info!(
                target: "talos_engine",
                event_kind = "worker_key_registered",
                worker_id = %req.worker_id,
                supports_sealing = req.supports_sealing,
                auth_path = ?path,
                "worker self-registered an Ed25519 identity key"
            );
            (
                StatusCode::OK,
                axum::Json(serde_json::json!({ "status": "registered" })),
            )
        }
        Ok(talos_worker_identity_repository::TokenRegisterOutcome::InvalidToken) => {
            // Server-side detail, generic client response: presence only, never
            // the token value.
            tracing::warn!(
                target: "talos_security",
                event_kind = "worker_reg_token_invalid",
                worker_id = %req.worker_id,
                "worker-key registration refused: no eligible provisioning token \
                 (unknown, used, expired, revoked, bound to another worker_id, or \
                 wildcard under bound-token enforcement)"
            );
            worker_reg_error(StatusCode::UNAUTHORIZED, "invalid registration token")
        }
        Ok(talos_worker_identity_repository::TokenRegisterOutcome::IdentityConflict) => {
            // The single loudest signal this endpoint can emit: a token-holder
            // tried to bind a key that is NOT this worker_id's trusted key —
            // either in-fleet impersonation or an unmanaged rotation. Public
            // key material only (never the bearer token).
            tracing::warn!(
                target: "talos_security",
                event_kind = "worker_key_tofu_conflict",
                worker_id = %req.worker_id,
                submitted_public_key = %hex::encode(public_key),
                auth_path = ?path,
                "worker-key registration REFUSED: worker_id already has a bound \
                 identity and the submitted key does not match its active key. \
                 Possible in-fleet impersonation attempt; legitimate rotation \
                 goes through the register-worker-identity operator CLI or a \
                 worker_id-bound provisioning token."
            );
            worker_reg_error(
                StatusCode::CONFLICT,
                "worker_id already has a registered identity; rotation requires operator action",
            )
        }
        Ok(talos_worker_identity_repository::TokenRegisterOutcome::CapReached) => worker_reg_error(
            StatusCode::TOO_MANY_REQUESTS,
            "worker already holds the maximum active keys; deactivate one first",
        ),
        Err(e) => {
            // Log full error server-side; return a generic message (no schema leak).
            tracing::error!(
                target: "talos_engine",
                worker_id = %req.worker_id,
                error = %e,
                "worker-key registration DB write failed"
            );
            worker_reg_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "registration failed (see server logs)",
            )
        }
    }
}

/// Collapse the job_protocol validation error to one of a small set of fixed,
/// leak-safe messages (the raw error only ever describes the charset rule, but
/// this keeps the response surface stable and audited).
fn leak_safe_validation(_e: &str) -> &'static str {
    "invalid worker_id (allowed: A-Z a-z 0-9 . - _, non-empty, bounded length)"
}

// ---------- CORS Middleware ----------
/// MCP-1057 (2026-05-15): canonical CORS header values shared by every
/// CORS-response-emitting site (`cors_options`, `cors_middleware`'s
/// OPTIONS branch, and `cors_middleware`'s non-OPTIONS branch). Pre-fix
/// these three string literals were inlined at 3 sites with identical
/// content — same N-inline-copies drift class as MCP-1037..1056. Any
/// future change (add a new method, accept a new header, change the
/// preflight max-age) now lands in ONE place.
///
/// Comment on `CORS_ALLOW_METHODS`: explicitly restricted to methods
/// actually used by the API. PUT/DELETE are only called from
/// server-side code (not cross-origin browser requests), so omitting
/// them reduces the attack surface for CSRF.
pub(crate) const CORS_ALLOW_METHODS: &str = "GET, POST, OPTIONS";
pub(crate) const CORS_ALLOW_HEADERS: &str = "Content-Type, Authorization, X-API-Key, X-CSRF-Token";
pub(crate) const CORS_MAX_AGE: &str = "3600";

// MCP-1172 (2026-05-17): `resolve_allowed_origin` removed.
// Both consumers (`cors_options` + `cors_middleware`) now read the
// request's `Origin` header and check against
// `talos_config::is_allowed_origin` directly (MCP-1168 + MCP-1172),
// so the cached-single-string helper has no remaining users.
// `talos_config::ALLOWED_ORIGINS` is the canonical multi-value
// allowlist; reading the raw env at request-time was the source of
// the multi-origin ACAO drift bug that MCP-1168 closed.

pub(crate) async fn cors_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    use axum::http::Method;

    // MCP-1168 (2026-05-17): per-request Origin echo against the
    // talos_config::is_allowed_origin allowlist instead of
    // unconditionally binding the raw `ALLOWED_ORIGIN` env value.
    //
    // Pre-fix `resolve_allowed_origin()` returned the WHOLE
    // ALLOWED_ORIGIN string verbatim. For single-origin deployments
    // this worked; for multi-origin (`ALLOWED_ORIGIN=https://a.com,
    // https://b.com` — explicitly supported by talos_config's
    // ALLOWED_ORIGINS multi-value parsing AND by the
    // SECURITY-WARNING-on-multi log at talos-config/src/lib.rs:264)
    // the `Access-Control-Allow-Origin` response header became
    // `https://a.com,https://b.com` — invalid per RFC 6454 / CORS
    // spec, which requires exactly one origin when paired with
    // `Access-Control-Allow-Credentials: true` (set below). Browsers
    // reject the malformed value → CORS fails → multi-origin deploys
    // broke silently.
    //
    // Fix: read the request's Origin header, check against the
    // talos-config allowlist (which already splits on `,` and
    // validates scheme), echo it back if allowed, otherwise omit
    // the ACAO header entirely. Browsers without ACAO refuse the
    // cross-origin response — fail-closed for unknown origins.
    // `Vary: Origin` is added so caches don't serve a cached
    // allowed-origin response to a different-origin request.
    let request_origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let echoed_origin: Option<String> = request_origin
        .as_deref()
        .filter(|o| talos_config::is_allowed_origin(o))
        .map(|s| s.to_string());

    // Handle preflight OPTIONS requests immediately
    if req.method() == Method::OPTIONS {
        let mut response = Response::new(axum::body::Body::empty());
        *response.status_mut() = axum::http::StatusCode::OK;

        let headers = response.headers_mut();
        // MCP-1057: canonical CORS header consts.
        // MCP-1168: only set ACAO when the request's Origin is in
        // the allowlist. Browsers without ACAO refuse the response,
        // which is the correct CORS deny shape.
        if let Some(o) = &echoed_origin {
            if let Ok(v) = HeaderValue::from_str(o) {
                headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
            }
        }
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_static(CORS_ALLOW_METHODS),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_HEADERS,
            HeaderValue::from_static(CORS_ALLOW_HEADERS),
        );
        headers.insert(
            header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            HeaderValue::from_static("true"),
        );
        headers.insert(
            header::ACCESS_CONTROL_MAX_AGE,
            HeaderValue::from_static(CORS_MAX_AGE),
        );
        // MCP-1168: cache key MUST vary on Origin — without this a
        // CDN/proxy could serve a response with ACAO=https://a.com
        // to a subsequent request from https://b.com.
        headers.insert(header::VARY, HeaderValue::from_static("Origin"));

        return response;
    }

    // For all other requests, process normally and add CORS headers to response
    let mut response = next.run(req).await;

    let headers = response.headers_mut();
    if let Some(o) = &echoed_origin {
        if let Ok(v) = HeaderValue::from_str(o) {
            headers.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
        }
    }
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static(CORS_ALLOW_METHODS),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static(CORS_ALLOW_HEADERS),
    );
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        HeaderValue::from_static("true"),
    );
    // MCP-1168: append-or-set `Vary: Origin`. The security_headers
    // layer sets `Vary: Cookie` already; both must apply so caches
    // partition by both axes.
    match headers.get(header::VARY) {
        Some(existing)
            if existing.to_str().ok().is_some_and(|s| {
                s.split(',')
                    .any(|p| p.trim().eq_ignore_ascii_case("Origin"))
            }) =>
        {
            // Origin already in Vary — leave existing value untouched.
        }
        Some(existing) => {
            if let Ok(existing_str) = existing.to_str() {
                let combined = format!("{existing_str}, Origin");
                if let Ok(v) = HeaderValue::from_str(&combined) {
                    headers.insert(header::VARY, v);
                }
            }
        }
        None => {
            headers.insert(header::VARY, HeaderValue::from_static("Origin"));
        }
    }

    response
}

// ---------- Aggregate health check handler ----------
/// Comprehensive health check that reports on all subsystems (Postgres, Redis, NATS).
/// Returns 200 with `{"status":"ok"}` when all critical checks pass,
/// or 503 with `{"status":"degraded"}` when the database is unreachable.
/// Each sub-check has a 2-second timeout to avoid blocking the readiness probe.
///
/// SECURITY: Returns minimal information to prevent information leakage.
/// Detailed status is logged server-side only.
pub(crate) async fn health_check(
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(redis_client): Extension<Option<std::sync::Arc<redis::Client>>>,
    Extension(nats_client): Extension<Option<std::sync::Arc<async_nats::Client>>>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    use serde_json::json;
    use std::time::Duration;

    let check_timeout = Duration::from_secs(2);

    // --- Database check (2s timeout) ---
    let db_ok = tokio::time::timeout(check_timeout, async {
        sqlx::query("SELECT 1").execute(&db_pool).await.is_ok()
    })
    .await
    .unwrap_or(false);

    // --- Redis check (2s timeout) ---
    let redis_ok = if let Some(ref client) = redis_client {
        tokio::time::timeout(check_timeout, async {
            match client.get_multiplexed_async_connection().await {
                Ok(mut conn) => redis::cmd("PING")
                    .query_async::<String>(&mut conn)
                    .await
                    .is_ok(),
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    } else {
        // Not configured is not a failure
        true
    };

    // --- NATS check (2s timeout) ---
    let nats_ok = if let Some(ref client) = nats_client {
        tokio::time::timeout(check_timeout, async {
            client.connection_state() == async_nats::connection::State::Connected
        })
        .await
        .unwrap_or(false)
    } else {
        // Not configured is not a failure
        true
    };

    // Database is critical - if it's down, return 503
    // Redis/NATS are optional - if down but DB is up, return 200 with degraded status
    let (http_status, status_str) = if !db_ok {
        (axum::http::StatusCode::SERVICE_UNAVAILABLE, "degraded")
    } else if !redis_ok || !nats_ok {
        (axum::http::StatusCode::OK, "degraded")
    } else {
        (axum::http::StatusCode::OK, "ok")
    };

    // SECURITY: Log detailed status server-side only
    if !db_ok {
        tracing::error!("Health check: database connectivity failed");
    }
    if !redis_ok && redis_client.is_some() {
        tracing::warn!("Health check: Redis connectivity failed");
    }
    if !nats_ok && nats_client.is_some() {
        tracing::warn!("Health check: NATS connectivity failed");
    }

    // Return minimal information to prevent information leakage
    let body = json!({
        "status": status_str,
    });

    (http_status, axum::Json(body)).into_response()
}

// ---------- Redis health check endpoint ----------
pub(crate) async fn health_check_redis(
    Extension(redis_client): Extension<Option<std::sync::Arc<redis::Client>>>,
) -> Result<&'static str, axum::http::StatusCode> {
    if let Some(client) = redis_client {
        // Test Redis connection
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| {
                tracing::error!("Redis health check failed: connection error: {}", e);
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            })?;

        // Test PING command
        redis::cmd("PING")
            .query_async::<String>(&mut conn)
            .await
            .map_err(|e| {
                tracing::error!("Redis health check failed: PING error: {}", e);
                axum::http::StatusCode::SERVICE_UNAVAILABLE
            })?;

        Ok("OK")
    } else {
        tracing::warn!("Redis health check failed: client not configured");
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

// ---------- NATS health check endpoint ----------
pub(crate) async fn health_check_nats(
    Extension(nats_client): Extension<Option<std::sync::Arc<async_nats::Client>>>,
) -> Result<&'static str, axum::http::StatusCode> {
    if let Some(client) = nats_client {
        // Test NATS connection by checking server info
        if client.connection_state() == async_nats::connection::State::Connected {
            Ok("OK")
        } else {
            tracing::error!("NATS health check failed: not connected");
            Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
        }
    } else {
        tracing::warn!("NATS health check failed: client not configured");
        Err(axum::http::StatusCode::SERVICE_UNAVAILABLE)
    }
}

// ---------- Kubernetes-style liveness probe ----------
/// Lightweight check that the process is responsive. Does NOT check subsystems.
/// Use for Kubernetes `livenessProbe` — if this fails, the pod should be restarted.
pub(crate) async fn liveness_probe() -> &'static str {
    "OK"
}

/// Seed the double-submit CSRF cookie for first-page-load. The frontend GETs
/// this once before its first POST `/graphql`; subsequent mutations rotate
/// the cookie via the regular csrf_protection_graphql middleware on
/// `graphql_routes`. Idempotent: returns 200 with no new cookie if the
/// client already presented one.
///
/// Builds the Set-Cookie header by hand so it doesn't depend on
/// CookieManagerLayer being wired in this router branch — relying on
/// layered cookies through merged sub-routers produced silent no-cookie
/// responses in production (root cause not pinned down; this handler
/// removes the indirection entirely).
pub(crate) async fn seed_csrf_handler(headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::http::{header, HeaderValue, StatusCode};
    use rand::RngCore;

    let already_has_cookie = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|s| {
            // Match either at the start or after a "; " — guards against a
            // cookie name that's a substring of another cookie's value.
            s.split(';')
                .any(|part| part.trim_start().starts_with("talos_csrf_token="))
        })
        .unwrap_or(false);

    let mut response = axum::response::Response::new(axum::body::Body::from("ok"));
    *response.status_mut() = StatusCode::OK;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    // MCP-582: per-session response with `Set-Cookie` of a unique
    // 32-byte CSRF token — MUST NOT be cached or shared between
    // clients. RFC 7234 forbids shared caches from serving Set-Cookie
    // responses to other clients by default, but operator-deployed
    // caches (CloudFlare, Varnish, nginx) can be misconfigured. Setting
    // `Cache-Control: no-store` is the explicit denial that all
    // RFC-compliant caches must honour. Also covers the "already has
    // cookie" branch where no Set-Cookie is issued but the response
    // body is still per-session-flow context. `Vary: Cookie` is
    // belt-and-suspenders: if a cache DOES try to cache despite
    // no-store, the Cookie request header becomes part of the cache
    // key so two users with different cookies never share an entry.
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, private"),
    );
    response
        .headers_mut()
        .insert(header::VARY, HeaderValue::from_static("Cookie"));

    if !already_has_cookie {
        let mut bytes = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let token = hex::encode(bytes);

        // Frontend reads this cookie via JS to populate X-CSRF-Token, so it
        // CANNOT be HttpOnly. Secure in prod (HTTPS only), SameSite=Strict
        // mirrors what csrf::csrf_protection writes on the rotation path.
        let secure_attr = if config::is_production() {
            "; Secure"
        } else {
            ""
        };
        let value = format!("talos_csrf_token={token}; Path=/; SameSite=Strict{secure_attr}");

        match HeaderValue::from_str(&value) {
            Ok(v) => {
                response.headers_mut().insert(header::SET_COOKIE, v);
            }
            Err(e) => {
                tracing::error!(
                    error = %e,
                    "seed_csrf_handler: failed to encode Set-Cookie value"
                );
            }
        }
    }

    response
}

// ---------- Kubernetes-style readiness probe ----------
/// Full subsystem check: database (critical), Redis, NATS.
/// Use for Kubernetes `readinessProbe` — if this fails, the pod should be removed
/// from the load balancer but NOT restarted.
///
/// Returns 200 when the instance can serve traffic, 503 when it cannot.
pub(crate) async fn readiness_probe(
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(redis_client): Extension<Option<std::sync::Arc<redis::Client>>>,
    Extension(nats_client): Extension<Option<std::sync::Arc<async_nats::Client>>>,
) -> Result<axum::response::Response, axum::response::Response> {
    use axum::response::IntoResponse;
    use serde_json::json;
    use std::time::Duration;

    let check_timeout = Duration::from_secs(2);

    // Database is mandatory — if it's down, the instance cannot serve traffic
    let db_ok = tokio::time::timeout(check_timeout, async {
        sqlx::query("SELECT 1").execute(&db_pool).await.is_ok()
    })
    .await
    .unwrap_or(false);

    if !db_ok {
        tracing::error!("Readiness probe: database connectivity failed");
        let body = json!({ "ready": false, "reason": "database_unavailable" });
        return Err((
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(body),
        )
            .into_response());
    }

    // Redis and NATS are optional — their absence degrades but doesn't block
    let redis_ok = if let Some(ref client) = redis_client {
        tokio::time::timeout(check_timeout, async {
            match client.get_multiplexed_async_connection().await {
                Ok(mut conn) => redis::cmd("PING")
                    .query_async::<String>(&mut conn)
                    .await
                    .is_ok(),
                Err(_) => false,
            }
        })
        .await
        .unwrap_or(false)
    } else {
        true
    };

    let nats_ok = if let Some(ref client) = nats_client {
        client.connection_state() == async_nats::connection::State::Connected
    } else {
        true
    };

    let body = json!({
        "ready": true,
        "subsystems": {
            "database": db_ok,
            "redis": redis_ok,
            "nats": nats_ok,
        }
    });

    Ok((axum::http::StatusCode::OK, axum::Json(body)).into_response())
}

// ---------- Prometheus scrape endpoint ----------
//
// Gated by a shared-secret `PROMETHEUS_SCRAPE_TOKEN` bearer — in K8s,
// this should only be reachable on an internal Service/port that the
// ServiceMonitor targets. Unauthenticated in dev only.
pub(crate) async fn prometheus_metrics_handler(
    headers: axum::http::HeaderMap,
) -> Result<axum::response::Response, (axum::http::StatusCode, String)> {
    // MCP-591 (2026-05-12): treat empty-string env as "no token
    // configured". Pre-fix `PROMETHEUS_SCRAPE_TOKEN=""` produced
    // `Ok("")` → `expected = ""`, then `got.ct_eq(expected)` returned
    // true vacuously for any caller with a missing/empty bearer (got
    // defaults to "") — auth passed and the production fail-closed
    // path was skipped. Empty `expected` carries no entropy, so
    // route to the unset branch which fail-closes in production.
    // Sibling fix to MCP-590 in talos-registry.
    let configured = std::env::var("PROMETHEUS_SCRAPE_TOKEN")
        .ok()
        .filter(|v| !v.is_empty());
    if let Some(expected) = configured {
        use subtle::ConstantTimeEq as _;
        let got = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|h| h.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("");
        if got.as_bytes().ct_eq(expected.as_bytes()).unwrap_u8() == 0 {
            return Err((
                axum::http::StatusCode::UNAUTHORIZED,
                "invalid prometheus scrape token".to_string(),
            ));
        }
    } else if crate::config::is_production() {
        return Err((
            axum::http::StatusCode::FORBIDDEN,
            "PROMETHEUS_SCRAPE_TOKEN must be set in production".to_string(),
        ));
    }

    let m = metrics::global().ok_or_else(|| {
        (
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            "metrics registry not initialised".to_string(),
        )
    })?;
    let body = m.render_prometheus().map_err(|e| {
        tracing::error!(error = %e, "prometheus render failed");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "encoding failed".to_string(),
        )
    })?;
    let mut resp = axum::response::Response::new(axum::body::Body::from(body));
    resp.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        axum::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
    );
    Ok(resp)
}

// ---------- Metrics endpoint ----------
pub(crate) async fn metrics_handler(
    Extension(db_pool): Extension<sqlx::PgPool>,
    Extension(schema): Extension<TalosSchema>,
    cookies: tower_cookies::Cookies,
    headers: axum::http::HeaderMap,
) -> Result<impl axum::response::IntoResponse, (axum::http::StatusCode, String)> {
    use serde_json::json;

    // Extract token from cookie or Authorization header
    let token = cookies
        .get("talos_access_token")
        .map(|c| c.value().to_string())
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()))
        })
        .ok_or_else(|| {
            (
                axum::http::StatusCode::UNAUTHORIZED,
                "Authentication required (cookie or Bearer token)".to_string(),
            )
        })?;

    // Verify token and extract user_id
    let auth_service = schema
        .data::<std::sync::Arc<AuthService>>()
        .ok_or_else(|| {
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Auth service not available".to_string(),
            )
        })?;

    let claims = auth_service.verify_token(&token).map_err(|_| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "Invalid or expired token".to_string(),
        )
    })?;

    let user_id = uuid::Uuid::parse_str(&claims.sub).map_err(|_| {
        (
            axum::http::StatusCode::UNAUTHORIZED,
            "Invalid user ID in token".to_string(),
        )
    })?;

    // Gather user-specific metrics
    let webhook_stats = sqlx::query_as::<_, (i64, i64, i64, i64, f64)>(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(trigger_count), 0)::bigint,
            COALESCE(SUM(success_count), 0)::bigint,
            COALESCE(SUM(error_count), 0)::bigint,
            COALESCE(AVG(avg_response_ms), 0.0)::float
        FROM webhook_triggers
        WHERE user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        tracing::error!(user_id = %user_id, error = %e, "Failed to fetch webhook stats");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to fetch metrics".to_string(),
        )
    })?;

    // MCP-676 (2026-05-13): the `secrets` table has THREE legacy
    // ownership columns from drift across the early schema: `user_id`
    // (001_initial_schema, never written by any code path),
    // `created_by` (001_initial_schema, written by `INSERT INTO
    // secrets` in talos-secrets-manager), and `owner_user_id`
    // (007_missing_columns, backfilled from created_by in
    // 20260410100005). The CANONICAL column is `owner_user_id` —
    // every write site sets both `created_by` and `owner_user_id`
    // to the creating user; nothing populates `user_id`. Pre-fix the
    // user-stats endpoint queried `WHERE user_id = $1` and silently
    // returned (count=0, sum=0) for every user regardless of how
    // many secrets they actually owned. UX bug, not a security bug
    // — but the broken column reference is a copy-paste hazard for
    // future code and worth fixing alongside the equivalent
    // talos-workflow-repository::get_provisioned_secrets gap.
    let secret_stats = sqlx::query_as::<_, (i64, i64)>(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(access_count), 0)::bigint
        FROM secrets
        WHERE owner_user_id = $1
        "#,
    )
    .bind(user_id)
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        tracing::error!(user_id = %user_id, error = %e, "Failed to fetch secret stats");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to fetch metrics".to_string(),
        )
    })?;

    // Phase 5: reads from the unified `modules` table (filter to user-authored
    // sandbox/extracted rows so catalog counts don't double-count per user).
    let module_stats = sqlx::query_as::<_, (i64, i64, i64)>(
        r#"
        SELECT
            COUNT(*)::bigint,
            COALESCE(SUM(usage_count), 0)::bigint,
            COALESCE(SUM(size_bytes), 0)::bigint
        FROM modules
        WHERE user_id = $1 AND kind IN ('sandbox', 'extracted')
        "#,
    )
    .bind(user_id)
    .fetch_one(&db_pool)
    .await
    .map_err(|e| {
        tracing::error!(user_id = %user_id, error = %e, "Failed to fetch module stats");
        (
            axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to fetch metrics".to_string(),
        )
    })?;

    let metrics = json!({
        "status": "healthy",
        "webhooks": {
            "total_listeners": webhook_stats.0,
            "total_triggers": webhook_stats.1,
            "total_successes": webhook_stats.2,
            "total_errors": webhook_stats.3,
            "avg_response_time_ms": webhook_stats.4,
        },
        "secrets": {
            "total_secrets": secret_stats.0,
            "total_accesses": secret_stats.1,
        },
        "modules": {
            "total_modules": module_stats.0,
            "total_executions": module_stats.1,
            "total_size_mb": (module_stats.2 as f64 / 1_048_576.0),
        },
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    Ok(axum::Json(metrics))
}

// ---------- REST API Authentication Middleware ----------
pub(crate) async fn rest_auth_middleware(
    cookies: tower_cookies::Cookies,
    headers: axum::http::HeaderMap,
    Extension(auth_service): Extension<std::sync::Arc<AuthService>>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, axum::http::StatusCode> {
    // MCP-531: log COOKIE-header PRESENCE only — never its value.
    //
    // Pre-fix this site emitted `Cookie header: {:?}` at debug level,
    // which prints the entire Cookie header via `HeaderValue::Debug`.
    // The Cookie header carries JWT access + refresh tokens
    // (`talos_access_token=eyJ…`, `talos_refresh_token=eyJ…`), so any
    // operator running with `RUST_LOG=debug` (common in dev, used in
    // production for transient troubleshooting) was writing every
    // request's session credentials into the log aggregator verbatim.
    //
    // Per CLAUDE.md "Security Rules": NEVER log sensitive values
    // (tokens, cookies, API keys, secrets). Log presence only.
    tracing::debug!(
        cookie_header_present = headers.contains_key(axum::http::header::COOKIE),
        "REST auth middleware - cookie header presence",
    );

    // Insert the request headers into extensions for downstream handlers that may need them
    req.extensions_mut().insert(headers.clone());

    // Try to get token from cookie first, then fall back to Authorization header.
    // Logs presence only — never any token material, even truncated.
    // talos_access_token is a JWT today (header bytes are non-secret) but a
    // truncated-prefix log is still a footgun the next time the format
    // changes, and "cookie token present" is the only diagnostic this
    // path needs.
    let token = cookies
        .get("talos_access_token")
        .map(|c| {
            tracing::debug!("REST auth - cookie token present");
            c.value().to_string()
        })
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| {
                    s.strip_prefix("Bearer ").map(|t| {
                        tracing::debug!("REST auth - Found Bearer token");
                        t.to_string()
                    })
                })
        });

    if token.is_none() {
        tracing::debug!("REST auth - No token found in cookies or headers");
        tracing::debug!("REST auth - Returning 401");
        return Err(axum::http::StatusCode::UNAUTHORIZED);
    }

    // Verify token
    if let Some(token_str) = token {
        if let Ok(claims) = auth_service.verify_token(&token_str) {
            if let Ok(user_id) = uuid::Uuid::parse_str(&claims.sub) {
                // MCP-587 (2026-05-12): enforce 2FA at the REST
                // middleware boundary. Pre-fix this middleware verified
                // the token but ignored `claims.is_2fa_verified` — a
                // pre-2FA token (issued by login when the user has TOTP
                // enabled but hasn't completed verify_two_factor yet)
                // sailed through every REST endpoint behind this
                // middleware: approval gates, Slack app creation, Gmail
                // / Slack integration management.
                //
                // The OAuth callback comment at line ~5141 explicitly
                // warns about exactly this bypass class — "Hardcoding
                // `true` here would bypass 2FA for anyone who can
                // complete an OAuth handshake … i.e. Google-account
                // compromise = Talos session, even when the user thinks
                // TOTP is protecting them." Same bypass shape, just at
                // the REST entry point instead of the OAuth one.
                //
                // GraphQL injects `IsTwoFactorVerified` into the
                // request context so resolvers can decide; REST has no
                // resolver layer so the middleware is the only gate.
                // Fail-closed: reject with 403 + structured message
                // pointing the caller at the 2FA-verification endpoint.
                if !claims.is_2fa_verified {
                    tracing::warn!(
                        user_id = %user_id,
                        "REST auth: pre-2FA token rejected — caller must complete TOTP verification before reaching REST endpoints"
                    );
                    return Err(axum::http::StatusCode::FORBIDDEN);
                }
                tracing::debug!(
                    "REST auth - Authenticated user {}, inserting into extensions",
                    user_id
                );
                // Insert user_id into request extensions so handlers can extract it
                req.extensions_mut().insert(user_id);
                tracing::debug!("REST auth - Extension inserted, calling next");
                let response = next.run(req).await;
                tracing::debug!("REST auth - Handler completed");
                return Ok(response);
            } else {
                tracing::debug!("REST auth - Invalid user_id in claims");
            }
        } else {
            tracing::debug!("REST auth - Token verification failed");
        }
    }

    // If no valid authentication, return 401
    tracing::debug!("REST auth - Returning 401");
    Err(axum::http::StatusCode::UNAUTHORIZED)
}

// ---------- GraphQL HTTP handler ----------
pub(crate) async fn graphql_handler(
    ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    schema: Extension<TalosSchema>,
    cookies: tower_cookies::Cookies,
    headers: axum::http::HeaderMap,
    req: GraphQLRequest,
) -> GraphQLResponse {
    let mut req = req.into_inner();

    // Extract the REAL client IP via the RFC-7239 trusted-proxy walk — NOT the
    // raw socket peer. Behind the chart's nginx frontend, `addr.ip()` is the
    // proxy pod IP for every request; using it here collapses ALL login/signup/
    // refresh/2FA traffic onto a single shared auth-limiter bucket (the auth
    // limiter is a hardcoded 5/min keyed on this `ip_address`), so 6 attempts a
    // minute from anywhere would 429 the entire platform's login surface — a
    // trivial unauthenticated DoS — and every audit-log row would record the
    // proxy IP instead of the attacker. Mirrors the MCP-1097 fix in
    // `mcp_auth_middleware`. `extract_client_ip` rejects XFF spoofing and, when
    // the peer is NOT a trusted proxy (direct-connection deploys), returns the
    // peer IP unchanged — so this is regression-free outside a proxy topology.
    static TRUSTED_PROXIES: std::sync::LazyLock<rate_limit::TrustedProxies> =
        std::sync::LazyLock::new(rate_limit::TrustedProxies::from_env);
    let ip_address =
        Some(rate_limit::extract_client_ip(addr.ip(), &headers, &TRUSTED_PROXIES).to_string());

    // Extract user agent
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    // Create request metadata for audit logging
    let metadata = api::schema::RequestMetadata {
        ip_address,
        user_agent,
    };

    // Inject metadata into GraphQL context
    req = req.data(metadata);

    // Try to get token from cookie first, then fall back to Authorization header
    let token = cookies
        .get("talos_access_token")
        .map(|c| c.value().to_string())
        .or_else(|| {
            headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.strip_prefix("Bearer ").map(|t| t.to_string()))
        });

    // Inject Cookies into GraphQL context for mutations to set cookies
    req = req.data(cookies);

    // Try API key authentication first (X-API-Key header)
    // MERELY presenting the header commits the request to the API-key lane:
    // a present-but-invalid key fails CLOSED (below), it is NOT downgraded to
    // the ambient session cookie. This is the security pairing for the CSRF
    // exemption in `talos-csrf::is_api_key_request` — CSRF is skipped for
    // X-API-Key requests, so if a bogus key could silently fall back to the
    // victim's cookie, an attacker's cross-origin page could send a junk
    // X-API-Key to bypass CSRF and ride the session. Failing closed removes
    // that path.
    let api_key_header_present = headers.contains_key("X-API-Key");
    let mut authenticated = false;
    // Tracks a JWT session that authenticated but has NOT completed 2FA
    // (password-only). API keys are always 2FA-verified; unauthenticated
    // requests stay `false` so the login/signup flow keeps working.
    let mut pre_2fa_session = false;
    if let Some(api_key) = headers.get("X-API-Key").and_then(|h| h.to_str().ok()) {
        // Get API key service from schema data
        if let Some(api_key_service) = schema.0.data::<std::sync::Arc<api_keys::ApiKeyService>>() {
            if let Ok((user_id, scopes)) = api_key_service.validate_key(api_key).await {
                // Inject user_id into GraphQL context
                req = req.data(user_id);
                // Inject scopes so resolvers can enforce fine-grained authorization.
                // JWT-authenticated requests do NOT inject ApiKeyScopes, so the absence
                // of this data in context signals "full access via session token".
                req = req.data(crate::api::schema::ApiKeyScopes(scopes));
                // API keys skip 2FA
                req = req.data(crate::api::schema::IsTwoFactorVerified(true));
                authenticated = true;
                tracing::debug!("Authenticated via API key for user {}", user_id);
            } else {
                tracing::debug!(
                    "X-API-Key present but invalid — failing closed (no cookie fallback)"
                );
            }
        }
    }

    // Fall back to JWT token authentication ONLY when no API key was
    // presented. See the api_key_header_present rationale above.
    if !authenticated && !api_key_header_present {
        if let Some(token_str) = token {
            // Get auth service from schema data
            if let Some(auth_service) = schema.0.data::<std::sync::Arc<AuthService>>() {
                if let Ok(claims) = auth_service.verify_token(&token_str) {
                    if let Ok(user_id) = uuid::Uuid::parse_str(&claims.sub) {
                        // Inject user_id into GraphQL context
                        req = req.data(user_id);
                        // Inject 2FA verification status
                        req = req.data(crate::api::schema::IsTwoFactorVerified(
                            claims.is_2fa_verified,
                        ));
                        pre_2fa_session = !claims.is_2fa_verified;
                        tracing::debug!(
                            "Authenticated via JWT for user {} (2FA verified: {})",
                            user_id,
                            claims.is_2fa_verified
                        );
                    }
                }
            }
        }
    }

    // Security review 2026-07-19 (P3): a password-verified but TOTP-pending
    // session may only run the 2FA-completion / bootstrap operations. This is
    // the read-surface counterpart to `require_2fa` on mutations and the REST
    // middleware's pre-2FA 403 — without it, a pre-2FA JWT could read the whole
    // GraphQL query surface (workflows, executions, decrypted agent memory,
    // secret metadata). Fails closed on unparseable/ambiguous operations.
    if pre_2fa_session
        && !api::schema::pre_2fa_operation_allowed(&req.query, req.operation_name.as_deref())
    {
        tracing::debug!("Refused pre-2FA GraphQL operation (2FA not completed)");
        return GraphQLResponse::from(async_graphql::Response::from_errors(vec![
            async_graphql::ServerError::new(
                "Two-Factor Authentication required. Complete 2FA verification to \
                 access this resource.",
                None,
            ),
        ]));
    }

    let mut response = schema.execute(req).await;

    // Scrub internal error details in all non-development environments
    // (production, staging, test, etc.) to avoid leaking sensitive information.
    //
    // Two-layer policy:
    //   1. EXPLICIT MARKER (preferred). Resolvers that want a user-facing
    //      error message call `.extend_safe()` which sets `extensions.safe
    //      = true`. Any error with that marker passes through verbatim.
    //      `api/schema/mod.rs::is_safe_error` is the canonical reader.
    //   2. SUBSTRING FALLBACK. Older paths haven't been migrated to
    //      `.extend_safe()` yet — keep them whitelisted by message
    //      content so a refactor doesn't accidentally start scrubbing
    //      legitimate errors. New code MUST use `.extend_safe()` rather
    //      than relying on substring matches.
    //
    // Errors that match neither layer get replaced with the generic
    // "Internal server error" string. The full original error is logged
    // server-side via `tracing::error!` for debugging.
    if !config::is_development() {
        for error in &mut response.errors {
            tracing::error!("GraphQL Error: {:?}", error);

            if crate::api::schema::is_safe_error(error) {
                continue; // explicitly marked safe — keep verbatim
            }

            // MCP-1051 (2026-05-15): route through canonical
            // `is_safe_error_substring` helper. Pre-fix the
            // whitelist substrings were inlined here AND in
            // `scripts/lint-structural.sh::check 14` — two copies
            // that could drift if a future change adds/removes a
            // substring on only one side. The const + helper in
            // talos-api/src/schema/mod.rs is now the single source
            // of truth for the scrubber path; the lint still
            // hardcodes the list but the const documents itself as
            // the parity reference.
            let msg = error.message.as_str();
            if !crate::api::schema::is_safe_error_substring(msg) {
                error.message = "Internal server error".to_string();
            }
        }
    }

    response.into()
}

// ---------- GraphQL Playground ----------
pub(crate) async fn graphql_playground() -> impl axum::response::IntoResponse {
    axum::response::Html(async_graphql::http::graphiql_source(
        "/graphql",
        Some("/ws"),
    ))
}

// ---------- WebSocket Handler with Authentication ----------
pub(crate) async fn websocket_handler(
    ws: WebSocketUpgrade,
    cookies: tower_cookies::Cookies,
    headers: axum::http::HeaderMap,
    Extension(schema): Extension<TalosSchema>,
    Extension(auth_service): Extension<std::sync::Arc<AuthService>>,
) -> Response {
    // Extract access token from cookie (secure: httpOnly cookie, not JavaScript)
    let access_token = cookies
        .get("talos_access_token")
        .map(|c| c.value().to_string());

    // Origin is captured from the upgrade request and validated inside
    // `handle_websocket_auth` to defend against Cross-Site WebSocket
    // Hijacking. Browsers always send Origin on WS handshakes; reverse
    // proxies must forward it (see chart nginx /ws location).
    let origin = headers.get(axum::http::header::ORIGIN).cloned();

    // MCP-1039: cap inbound WS message size. Default tungstenite limit
    // is 64 MiB per message / 16 MiB per frame — any authenticated
    // client can ship 64 MiB Text frames that the GraphQL handler then
    // serde_json-parses (O(N)). Legitimate graphql-ws control frames
    // (connection_init, subscribe, complete, ping) and the largest
    // expected subscription event (execution_updates with per-node
    // output) all fit comfortably under 1 MiB. Sibling defense-in-depth
    // to MCP-1014 (WIT outbound body cap) and MCP-1013 (XML/JSON input
    // cap) — every caller-controlled byte boundary on the controller
    // needs an explicit cap appropriate to the protocol, not the
    // upstream library's default.
    ws.max_message_size(1024 * 1024)
        .max_frame_size(1024 * 1024)
        .protocols(["graphql-ws"])
        .on_upgrade(move |socket| {
            ws_auth::handle_websocket_auth(socket, schema, auth_service, access_token, origin)
        })
}

// ---------- OAuth handlers ----------

#[derive(serde::Deserialize)]
pub struct OAuthLoginQuery {
    scopes: Option<String>,
}

/// Initiate OAuth login flow
pub(crate) async fn oauth_login_handler(
    axum::extract::Path(provider): axum::extract::Path<String>,
    axum::extract::Query(query): axum::extract::Query<OAuthLoginQuery>,
    Extension(oauth_service): Extension<std::sync::Arc<OAuthService>>,
    cookies: tower_cookies::Cookies,
) -> Result<impl axum::response::IntoResponse, (axum::http::StatusCode, String)> {
    use axum::response::Redirect;

    let provider = OAuthProvider::from_str(&provider).map_err(|e| {
        (
            axum::http::StatusCode::BAD_REQUEST,
            format!("Invalid provider: {}", e),
        )
    })?;

    let extra_scopes: Option<Vec<String>> = query
        .scopes
        .map(|s| s.split(',').map(|s| s.to_string()).collect());
    // MCP-995 (2026-05-15): log full error server-side, return a
    // generic message to the client. Pre-fix the body echoed
    // `e: anyhow::Error` verbatim — `get_authorization_url` errors
    // include:
    //   * "X OAuth is not configured. Set environment variables."
    //     (leaks operator config state to an unauthenticated endpoint)
    //   * Underlying Redis errors from `store_state_token` (connection
    //     state, auth failures)
    // CLAUDE.md security rule: "NEVER return internal error details to
    // API clients. Log full errors server-side, return generic
    // messages." Same rule MCP-275/581 applied to OAuth callback paths
    // in talos-atlassian / gmail / slack / google_calendar handlers —
    // extend the same discipline to the controller's
    // `/auth/oauth/{provider}/login` initiator.
    let provider_for_log = format!("{:?}", provider);
    let (auth_url, _csrf_token, session_nonce) = oauth_service
        .get_authorization_url(provider, extra_scopes)
        .await
        .map_err(|e| {
            tracing::error!(
                provider = %provider_for_log,
                error = %e,
                "OAuth login: failed to generate auth URL"
            );
            (
                axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "OAuth login unavailable. Contact your administrator.".to_string(),
            )
        })?;

    // S1 (login-CSRF / session-fixation defense): bind the OAuth `state`
    // nonce to THIS browser. `get_authorization_url` persisted only the
    // SHA-256 of `session_nonce`; we hand the plaintext back to the browser
    // as an HttpOnly cookie and require it to match on the callback
    // (`handle_callback` → `validate_state_token`). Without this, a valid
    // `state` proves only "Talos issued this URL", not "issued to this
    // browser" — the classic OAuth login-CSRF hole. Cookie attributes are
    // centralised in talos-api so the REST + GraphQL login paths stay in
    // lockstep (see `set_oauth_session_binding_cookie`).
    talos_api::schema::auth::set_oauth_session_binding_cookie(&cookies, &session_nonce);

    // Redirect to OAuth provider.
    Ok(Redirect::temporary(&auth_url))
}

/// Handle OAuth callback
pub(crate) async fn oauth_callback_handler(
    axum::extract::Path(provider): axum::extract::Path<String>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    Extension(oauth_service): Extension<std::sync::Arc<OAuthService>>,
    Extension(auth_service): Extension<std::sync::Arc<AuthService>>,
    Extension(google_calendar_service): Extension<
        std::sync::Arc<google_calendar::GoogleCalendarService>,
    >,
    cookies: tower_cookies::Cookies,
) -> std::result::Result<impl axum::response::IntoResponse, axum::http::StatusCode> {
    use axum::response::Redirect;
    // MCP-1040: `tower_cookies::Cookie` no longer used directly — the
    // canonical `set_session_cookies` helper handles cookie construction.

    let provider_enum =
        OAuthProvider::from_str(&provider).map_err(|_e| axum::http::StatusCode::BAD_REQUEST)?;

    // Extract authorization code and state parameter
    //
    // MCP-623 (2026-05-12): route through `talos_config::get_frontend_url()`
    // so the empty-env-var bug class (MCP-615 sibling) doesn't apply. Pre-fix
    // `env::var("FRONTEND_URL").unwrap_or_else(|_| default)` returned `""`
    // for an empty env value, then `format!("{}/auth/callback?...", "")`
    // produced a leading-slash relative redirect. Browsers interpret that
    // as same-origin, so single-host deployments survive but split-origin
    // deployments redirect users to the controller host's `/auth/callback`
    // instead of the frontend. Helm `values.yaml` placeholder
    // `frontendUrl: ""` would have hit this. The helper now applies the
    // canonical `.ok().filter(|v| !v.is_empty())` shape (MCP-615) so empty
    // values fall through to the documented `http://localhost:3000` default.
    let frontend_url = talos_config::get_frontend_url();

    let code = match params.get("code") {
        Some(c) => c,
        None => {
            let error_msg = params
                .get("error")
                .map(|s| s.as_str())
                .unwrap_or("missing_code");
            tracing::warn!("OAuth callback missing code. Error: {}", error_msg);
            // MCP-1094: sanitise provider-supplied error before
            // reflecting into the dashboard redirect URL.
            let safe_error = talos_config::sanitize_oauth_error_code(error_msg);
            return Ok(Redirect::temporary(&format!(
                "{}/auth/callback?error={}",
                frontend_url,
                urlencoding::encode(safe_error)
            )));
        }
    };

    let state = params.get("state").map(|s| s.to_string());

    // S1: read the browser-session binding cookie set at login time. The
    // callback consume path requires it to match the hash stored alongside
    // the `state` row (login-CSRF defense). Legacy state rows with a NULL
    // binding hash skip the check, so an in-flight login started before this
    // change still completes. Clear the cookie regardless — it's single-use.
    let session_binding = cookies
        .get(talos_api::schema::auth::OAUTH_SESSION_BINDING_COOKIE)
        .map(|c| c.value().to_string());
    if session_binding.is_some() {
        talos_api::schema::auth::clear_oauth_session_binding_cookie(&cookies);
    }

    // Handle OAuth callback with CSRF validation
    let user_info = match oauth_service
        .handle_callback(
            provider_enum.clone(),
            code.to_string(),
            state,
            session_binding.as_deref(),
        )
        .await
    {
        Ok(info) => info,
        Err(e) => {
            tracing::error!("❌ OAuth callback error: {}", e);
            oauth_service
                .log_oauth_event(
                    None,
                    &provider_enum,
                    "login_failed",
                    false,
                    Some(&e.to_string()),
                )
                .await
                .ok();
            return Ok(Redirect::temporary(&format!(
                "{}/auth/callback?error={}",
                frontend_url,
                urlencoding::encode("csrf_mismatch")
            )));
        }
    };

    // Store user_info for potential Google Calendar integration
    let user_info_clone = user_info.clone();

    // Link or create user
    let (user_id, is_new_user) = oauth_service
        .link_or_create_user(provider_enum.clone(), user_info, None)
        .await
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // RFC 0004: give brand-new OAuth users a personal organization (their
    // org-as-tenant home), mirroring the GraphQL signup path. Best-effort
    // + idempotent — `create_personal_org` repairs a miss, and existing
    // users already have one via the M1 backfill, so this never blocks
    // login.
    if is_new_user {
        if let Err(e) = talos_organizations::OrganizationService::create_personal_org(
            &google_calendar_service.db_pool,
            user_id,
            user_info_clone.name.as_deref(),
        )
        .await
        {
            tracing::error!(user_id = %user_id, "Failed to create personal org for new OAuth user (will be repaired): {e}");
        }

        // Phase D2.3: provision the default actor for brand-new OAuth users
        // too (same rationale as the GraphQL signup path — the fallback
        // principal the trg_set_default_actor trigger stamps onto actor-less
        // execution inserts). Best-effort + idempotent; created after the
        // personal org so the org-scoped write has its org.
        let actor_repo =
            talos_actor_repository::ActorRepository::new(google_calendar_service.db_pool.clone());
        if let Err(e) = actor_repo.get_or_create_default_actor(user_id).await {
            tracing::error!(user_id = %user_id, "Failed to create default actor for new OAuth user (will be repaired): {e}");
        }
    }

    // Check if this is a Google OAuth callback with Calendar scopes
    if provider_enum == OAuthProvider::Google {
        let is_calendar_integration = user_info_clone
            .scope
            .as_deref()
            .map(|s| s.contains("calendar"))
            .unwrap_or(false)
            || user_info_clone.refresh_token.is_some();

        if is_calendar_integration {
            // Get or create OAuth account
            let oauth_account = sqlx::query_as::<_, (uuid::Uuid,)>(
                "SELECT id FROM oauth_accounts
                 WHERE user_id = $1 AND provider = 'google'
                 ORDER BY created_at DESC
                 LIMIT 1",
            )
            .bind(user_id)
            .fetch_optional(&google_calendar_service.db_pool)
            .await
            .ok()
            .flatten();

            if let Some((oauth_account_id,)) = oauth_account {
                // Create Google Calendar integration
                let scope_str = user_info_clone.scope.clone().unwrap_or_else(|| "https://www.googleapis.com/auth/calendar.readonly https://www.googleapis.com/auth/calendar.events.readonly".to_string());

                if let (Some(access_token), Some(refresh_token), Some(expires_in)) = (
                    &user_info_clone.access_token,
                    &user_info_clone.refresh_token,
                    user_info_clone.expires_in,
                ) {
                    // MCP-801 (2026-05-14): surface integration-creation
                    // failures truthfully. Pre-fix `let _ = ...await`
                    // discarded the Result and the subsequent ✅ INFO log
                    // fired UNCONDITIONALLY — operators trying to debug a
                    // user's "calendar isn't working" report saw "✅
                    // Created" in the logs and concluded the integration
                    // existed, then chased ghosts elsewhere. Most-likely
                    // failure modes are transient (DB hiccup mid-OAuth-
                    // callback, NATS publish race, integration_state RPC
                    // delivery error); user retries by reconnecting Google
                    // Calendar in the settings UI. Capturing Err here lets
                    // the operator's first log query find the actual
                    // failure cause instead of silently-misleading success.
                    // Same misleading-success class as MCP-737/738/800.
                    // OAuth callback flow continues regardless — the login
                    // itself succeeded; only the calendar bolt-on failed.
                    match google_calendar_service
                        .create_or_update_integration(
                            user_id,
                            oauth_account_id,
                            access_token.clone(),
                            refresh_token.clone(),
                            expires_in,
                            scope_str,
                        )
                        .await
                    {
                        Ok(_) => {
                            tracing::info!(
                                "✅ Created Google Calendar integration for user {}",
                                user_id
                            );
                        }
                        Err(e) => {
                            tracing::error!(
                                target: "talos_audit",
                                user_id = %user_id,
                                oauth_account_id = %oauth_account_id,
                                error = ?e,
                                "Google Calendar integration creation failed during OAuth callback — \
                                 user can retry by reconnecting in settings; underlying error logged"
                            );
                        }
                    }
                } else {
                    tracing::warn!("⚠️ Failed to create Google Calendar integration for user {} because refresh_token or access_token is missing (likely user did not grant offline access on first prompt).", user_id);
                }
            }
        }
    }

    // Log successful OAuth login
    oauth_service
        .log_oauth_event(
            Some(user_id),
            &provider_enum,
            if is_new_user {
                "signup_oauth"
            } else {
                "login_oauth"
            },
            true,
            None,
        )
        .await
        .ok();

    // Get user details
    let user = auth_service
        .get_user(user_id)
        .await
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // Generate tokens.
    //
    // SECURITY: if the user has TOTP enabled, mint a PRE-2FA token (the same
    // shape `auth_service.login()` returns for password+TOTP users). The
    // frontend then redirects to the TOTP entry page; verify_two_factor
    // upgrades to a fully-verified session. Hardcoding `true` here would
    // bypass 2FA for anyone who can complete an OAuth handshake with the
    // upstream provider — i.e. Google-account compromise = Talos session,
    // even when the user thinks TOTP is protecting them.
    let is_2fa_verified = !user.totp_enabled.unwrap_or(false);
    let access_token = auth_service
        .generate_access_token(&user, is_2fa_verified)
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    let refresh_token = auth_service
        .generate_refresh_token(user_id, is_2fa_verified)
        .await
        .map_err(|_e| axum::http::StatusCode::INTERNAL_SERVER_ERROR)?;

    // Set httpOnly cookies.
    // MCP-1040 (2026-05-15): canonical session-cookie installer.
    // MCP-763 originally fixed a `set_secure(true)` vs `is_production`
    // gating drift between this OAuth callback and the login mutation;
    // MCP-1040 collapses both call paths into the single
    // `talos_api::schema::auth::set_session_cookies` helper so future
    // policy changes (TTL, SameSite, Partitioned, Domain) can't drift
    // back into asymmetry.
    talos_api::schema::auth::set_session_cookies(&cookies, &access_token, &refresh_token);

    // Redirect to frontend with success indicator
    Ok(Redirect::temporary(&format!(
        "{}/auth/callback?success=true",
        frontend_url
    )))
}

#[cfg(test)]
mod worker_registration_auth_tests {
    use super::{
        check_registration_freshness, classify_registration_bearer, provisioning_token_hash,
        RegBearerPath, WORKER_REG_FUTURE_MS, WORKER_REG_PAST_MS,
    };
    use axum::http::StatusCode;

    const NOW: u64 = 1_700_000_000_000;
    const TOKEN: &str = "s3cret-registration-token";

    #[test]
    fn accepts_fresh_timestamps() {
        assert!(check_registration_freshness(NOW, NOW).is_ok());
        // Within the past window and the future window.
        assert!(check_registration_freshness(NOW - WORKER_REG_PAST_MS + 1, NOW).is_ok());
        assert!(check_registration_freshness(NOW + WORKER_REG_FUTURE_MS, NOW).is_ok());
    }

    #[test]
    fn rejects_stale_and_future_dated() {
        // One ms past the past window.
        assert_eq!(
            check_registration_freshness(NOW - WORKER_REG_PAST_MS - 1, NOW)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
        // One ms past the future window.
        assert_eq!(
            check_registration_freshness(NOW + WORKER_REG_FUTURE_MS + 1, NOW)
                .unwrap_err()
                .0,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn shared_token_classification_respects_enforcement_flag() {
        // Exact shared-token match, enforcement off → legacy TOFU path.
        assert_eq!(
            classify_registration_bearer(TOKEN, Some(TOKEN), false),
            RegBearerPath::LegacyShared
        );
        // Same match under enforcement → refused-by-policy (handler logs, 401).
        assert_eq!(
            classify_registration_bearer(TOKEN, Some(TOKEN), true),
            RegBearerPath::SharedRefusedByPolicy
        );
    }

    #[test]
    fn non_shared_bearers_route_to_the_provisioning_path() {
        // Same length, different content (the ct_eq branch).
        let wrong = "S3cret-registration-token";
        assert_eq!(wrong.len(), TOKEN.len());
        assert_eq!(
            classify_registration_bearer(wrong, Some(TOKEN), false),
            RegBearerPath::Provisioning
        );
        // Different length (the length guard before ct_eq).
        assert_eq!(
            classify_registration_bearer("short", Some(TOKEN), false),
            RegBearerPath::Provisioning
        );
        // Bound-token-only deployment: no shared token configured at all.
        assert_eq!(
            classify_registration_bearer(TOKEN, None, true),
            RegBearerPath::Provisioning
        );
    }

    #[test]
    fn token_hash_is_sha256_hex_of_the_raw_bearer() {
        // Pinned vector so the CLI mint and the endpoint redeem can never
        // drift: sha256("wpt_test") — independently verifiable.
        assert_eq!(
            provisioning_token_hash("wpt_test"),
            "137e7e89843ad7a07606e9cf6fc91eb2e95f9be2612a320c3945dd2e22227da0"
        );
    }
}

/// Route / middleware / Extension assembly for the whole HTTP surface.
/// Extracted verbatim from `main()`. CRITICAL ordering invariants preserved
/// byte-for-byte (see the inline comments): layers run bottom-up; the
/// governor + global rate-limit layers are production-only; `mcp_router` and
/// `probe_routes` are merged AFTER the rate-limit layers so MCP traffic and
/// kubelet probes can never be 429'd; merged sub-routers re-attach the
/// Extension layers their handlers need.
pub(crate) fn build_router(
    db_pool: sqlx::Pool<sqlx::Postgres>,
    redis_client: Option<std::sync::Arc<redis::Client>>,
    nats_client: Option<std::sync::Arc<async_nats::Client>>,
    core: &CoreServices,
    services: &PlatformServices,
    limiters: &RateLimiters,
    bundle: &SchemaBundle,
    actor_repo: std::sync::Arc<actor_repository::ActorRepository>,
    ollama_client: std::sync::Arc<talos_llm::OllamaClient>,
) -> anyhow::Result<Router> {
    let secrets_manager = core.secrets_manager.clone();
    let registry = core.registry.clone();
    let compiler = core.compiler.clone();
    let worker_shared_key = services.worker_shared_key.clone();
    let worker_manager = services.worker_manager.clone();
    let dlp_service = services.dlp_service.clone();
    let module_execution_service = services.module_execution_service.clone();
    let slack_api_client = services.slack_api_client.clone();
    let slack_integration_service = services.slack_integration_service.clone();
    let gmail_integration_service = services.gmail_integration_service.clone();
    let google_cloud_integration_service = services.google_cloud_integration_service.clone();
    let google_cloud_write_service = services.google_cloud_write_service.clone();
    let google_cloud_full_service = services.google_cloud_full_service.clone();
    let github_connect_service = services.github_connect_service.clone();
    let gmail_watch_service = services.gmail_watch_service.clone();
    let gmail_pubsub_verifier = services.gmail_pubsub_verifier.clone();
    let gcp_watch_service = services.gcp_watch_service.clone();
    let gcp_pubsub_verifier = services.gcp_pubsub_verifier.clone();
    let gcp_pubsub_audience = services.gcp_pubsub_audience.clone();
    let atlassian_integration_service = services.atlassian_integration_service.clone();
    let gmail_api_client = services.gmail_api_client.clone();
    let google_calendar_service = services.google_calendar_service.clone();
    let circuit_breaker = services.circuit_breaker.clone();
    let webhook_router = services.webhook_router.clone();
    let auth_service = services.auth_service.clone();
    let oauth_service = services.oauth_service.clone();
    let idempotency_service = services.idempotency_service.clone();
    let api_limiter = limiters.api_limiter.clone();
    let webhook_limiter = limiters.webhook_limiter.clone();
    let global_limiter = limiters.global_limiter.clone();
    let whitelist = limiters.whitelist.clone();
    let trusted_proxies = limiters.trusted_proxies.clone();
    let schema = bundle.schema.clone();
    let runtime = bundle.runtime.clone();
    let llm_client = bundle.llm_client.clone();
    let workflow_repo = bundle.workflow_repo.clone();
    let module_repo = bundle.module_repo.clone();
    let execution_repo = bundle.execution_repo.clone();
    let workflow_creation_service = bundle.workflow_creation_service.clone();
    let hot_update_service = bundle.hot_update_service.clone();
    let execution_orchestration_service = bundle.execution_orchestration_service.clone();
    let workflow_manifest_service = bundle.workflow_manifest_service.clone();
    let replay_service = bundle.replay_service.clone();
    let inline_compile_service = bundle.inline_compile_service.clone();
    let search_service = bundle.search_service.clone();
    // RFC 0010 P3 (M4): the SAME process-wide claim-based-sealing handle main
    // resolved for the webhook router. `shared_envelope_sealing_handle` is
    // memoized in a `OnceLock`, so this returns the identical `InFlightSeals` +
    // claim subject the claim responder subscribes to (never a second store),
    // for the Gmail-push + Google-Calendar-push fire-and-forget dispatch paths.
    let module_sealing_handle: Option<talos_integration_helpers::ModuleSealingHandle> = nats_client
        .as_ref()
        .and_then(talos_engine::nats_run::shared_envelope_sealing_handle);
    let failure_analysis_service = bundle.failure_analysis_service.clone();
    let actor_lifecycle_service = bundle.actor_lifecycle_service.clone();
    // ---------- Rate limiting configuration ----------
    // Global rate limit configuration using tower_governor
    // Recommended: 10 requests per second per IP to prevent brute-force attacks
    let governor_conf = std::sync::Arc::new(
        tower_governor::governor::GovernorConfigBuilder::default()
            .per_second(10)
            .burst_size(20)
            .finish()
            .ok_or_else(|| anyhow::anyhow!("Failed to build rate limiter"))?,
    );
    let governor_layer = tower_governor::GovernorLayer::new(governor_conf);

    // Simple handler for CORS preflight (OPTIONS) requests.
    // MCP-1172 (2026-05-17): per-request Origin echo against the
    // talos_config::is_allowed_origin allowlist — sibling fix to
    // MCP-1168 which closed the same bug on `cors_middleware`. This
    // handler is dead code in any deployment that has
    // `cors_middleware` layered (the middleware's OPTIONS
    // short-circuit returns its own response first), but the route
    // bindings still register it; a future PR scoping down or
    // removing `cors_middleware` would resurrect this handler with
    // the raw-env-bind bug (multi-origin deployments emit
    // comma-separated ACAO, browsers reject). Preventive parity:
    // validate request Origin against allowlist, echo back if
    // allowed, omit if not, append `Vary: Origin`.
    async fn cors_options(headers: axum::http::HeaderMap) -> impl axum::response::IntoResponse {
        use axum::body::Body;

        let echoed_origin: Option<String> = headers
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .filter(|o| talos_config::is_allowed_origin(o))
            .map(|s| s.to_string());

        // MCP-1057: canonical CORS header consts.
        let mut builder = axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .header(header::ACCESS_CONTROL_ALLOW_METHODS, CORS_ALLOW_METHODS)
            .header(header::ACCESS_CONTROL_ALLOW_HEADERS, CORS_ALLOW_HEADERS)
            .header(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, "true")
            .header(header::ACCESS_CONTROL_MAX_AGE, CORS_MAX_AGE)
            .header(header::VARY, "Origin");
        if let Some(o) = &echoed_origin {
            builder = builder.header(header::ACCESS_CONTROL_ALLOW_ORIGIN, o);
        }
        builder
            .body(Body::empty())
            .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::empty()))
    }

    // ---------- Axum router ----------
    // Create GraphQL routes with API rate limiting and CSRF protection
    // GraphiQL playground is only enabled in development for security
    let is_production = config::is_production();

    let graphql_route = if is_production {
        // Production: POST only (no GraphiQL playground)
        post(graphql_handler).options(cors_options)
    } else {
        // Development: POST + GET for GraphiQL playground
        post(graphql_handler)
            .options(cors_options)
            .get(graphql_playground)
    };

    let graphql_routes = Router::new()
        .route("/graphql", graphql_route)
        .route("/ws", get(websocket_handler))
        // Limit request body — prevents oversized GraphQL documents from
        // exhausting memory before the query depth/complexity limits fire.
        // L5: shares `csrf::GRAPHQL_MAX_BODY_BYTES` with the CSRF middleware's
        // dev body-buffer cap so the two limits can never silently diverge.
        .layer(DefaultBodyLimit::max(csrf::GRAPHQL_MAX_BODY_BYTES))
        // Opt-in request idempotency. Registered BEFORE the CSRF/rate-limit
        // layers so it is INNER of them (they run first); a request without an
        // `Idempotency-Key` header takes a zero-touch passthrough, so existing
        // traffic is unaffected. Present + valid key → exactly-once via the
        // begin/complete reservation (closes the double-execution window on
        // retried mutations like triggerWorkflow). `idempotency_service` is
        // `None` when Redis is unconfigured → the middleware passes through.
        .layer(from_fn(idempotency::idempotency_middleware))
        .layer(Extension(idempotency_service.clone()))
        // CSRF protection (production only for mutations, lenient in dev)
        .layer(from_fn(csrf::csrf_protection_graphql))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()))
        .layer(Extension(auth_service.clone()))
        .layer(Extension(schema.clone()));

    // Create webhook routes with webhook rate limiting and size limits
    let webhook_routes = Router::new()
        .route("/webhooks/{id}", post(webhooks::webhook_handler))
        // Limit webhook body size to 1MB to prevent memory exhaustion DoS
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Create authenticated routes for human-in-the-loop approvals
    // MCP-1158 (2026-05-16): tight body limit. `ApprovalPayload` is
    // `{ approved: bool }` — ~16 bytes on the wire. Pre-fix the route
    // inherited axum's 2 MiB default which let an authenticated user
    // (or compromised account) burn ~10 ms of JSON-parse CPU per
    // request × rate-limit budget = real DoS pressure on controller
    // heap, even with auth gating. The unauthenticated sibling
    // `/approvals/{token}/{action}` already had a 4 KiB explicit
    // cap — this was the inverted-threat-model side of that pair
    // (authenticated endpoint with 500x more body slack than the
    // public one for an identical-shape action). Same trust-boundary
    // input-cap class as MCP-1148 (URL byte cap) and MCP-1013/1014
    // (XML/JSON/body byte caps).
    let approval_routes = Router::new()
        .route(
            "/api/approvals/{execution_id}",
            post(webhooks::approval_handler),
        )
        .layer(DefaultBodyLimit::max(4096))
        .layer(from_fn(rest_auth_middleware))
        .layer(Extension(auth_service.clone()))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Create OAuth routes (no rate limiting needed - redirects only)
    let oauth_routes = Router::new()
        .route("/auth/oauth/{provider}/login", get(oauth_login_handler))
        .route(
            "/auth/oauth/{provider}/callback",
            get(oauth_callback_handler),
        )
        .layer(Extension(oauth_service.clone()))
        .layer(Extension(auth_service.clone()))
        .layer(Extension(google_calendar_service.clone()));

    // Create Slack API proxy routes
    // NOTE: Layers execute in REVERSE order (bottom-up)
    // MCP-1158 (2026-05-16): tight body limit. `SlackApiParams` is
    // `{ bot_token: String, endpoint: Option<String> }` — bot_token
    // is a fixed-format ~80-char Slack secret, endpoint a short API
    // path (~100 chars). Semantic ceiling ~200 bytes; 8 KiB explicit
    // limit gives ~40x headroom for future fields without inheriting
    // axum's 2 MiB default. Same audit class as the approval_routes
    // fix above — authenticated REST POSTs with tiny payloads.
    let slack_api_routes = Router::new()
        // MCP-976: POST so the bot_token in the JSON body doesn't land
        // in nginx access logs / browser history / referer headers
        // as it would on a GET ?bot_token= query. Also matches the
        // frontend (SlackBrowser.tsx) which has always POSTed JSON.
        .route("/api/slack/channels", post(slack::list_channels_handler))
        .route("/api/slack/users", post(slack::list_users_handler))
        .route("/api/slack/apps/create", post(slack::create_app_handler))
        .with_state(slack_api_client.clone())
        .layer(DefaultBodyLimit::max(8192))
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Create Slack integration management routes
    // NOTE: Layers execute in REVERSE order (bottom-up)
    // So layer added LAST runs FIRST!
    let slack_integration_routes = Router::new()
        .route(
            "/api/slack/integrations",
            get(slack::list_integrations_handler),
        )
        .route(
            "/api/slack/integrations/{id}",
            get(slack::get_integration_handler),
        )
        .route(
            "/api/slack/integrations/{id}",
            axum::routing::delete(slack::disconnect_integration_handler),
        )
        .route("/api/slack/connect", get(slack::connect_slack_handler))
        .with_state(slack_integration_service.clone())
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Slack OAuth callback — NO auth middleware (mirrors gmail/atlassian).
    // Cross-site redirects from slack.com don't carry the session cookie
    // (SameSite=Strict), so the auth'd router above 401'd the callback before
    // `slack_callback_handler` ran — breaking the Slack connect flow. The
    // handler authenticates via the state token (bound to user_id at
    // /connect time, which IS behind auth) — its signature takes no
    // `Extension<Uuid>`, identical to the working gmail/atlassian callbacks.
    let slack_callback_route = Router::new()
        .route("/api/slack/callback", get(slack::slack_callback_handler))
        .with_state(slack_integration_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Create Gmail integration management routes
    // NOTE: Layers execute in REVERSE order (bottom-up)
    let gmail_integration_routes = Router::new()
        .route(
            "/api/gmail/integrations",
            get(gmail::list_integrations_handler),
        )
        .route(
            "/api/gmail/integrations/{id}",
            get(gmail::get_integration_handler),
        )
        .route(
            "/api/gmail/integrations/{id}",
            axum::routing::delete(gmail::disconnect_integration_handler),
        )
        .route("/api/gmail/connect", get(gmail::connect_gmail_handler))
        .with_state(gmail_integration_service.clone())
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Gmail OAuth callback — NO auth middleware.
    // Cross-site redirects from accounts.google.com don't carry session cookies
    // (SameSite policy). The user is identified via the state token instead.
    let gmail_callback_route = Router::new()
        .route("/api/gmail/callback", get(gmail::gmail_callback_handler))
        .with_state(gmail_integration_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Create Google Cloud integration management routes (authenticated).
    // NOTE: Layers execute in REVERSE order (bottom-up).
    let gcp_integration_routes = Router::new()
        .route(
            "/api/gcp/integrations",
            get(google_cloud::list_integrations_handler),
        )
        .route(
            "/api/gcp/integrations/{id}",
            get(google_cloud::get_integration_handler),
        )
        .route(
            "/api/gcp/integrations/{id}",
            axum::routing::delete(google_cloud::disconnect_integration_handler),
        )
        .route("/api/gcp/connect", get(google_cloud::connect_gcp_handler))
        .route(
            "/api/gcp/projects",
            get(google_cloud::list_projects_handler),
        )
        .with_state(google_cloud_integration_service.clone())
        // Write-tier (provisioning) consent uses the SAME connect handler with
        // the write-service state — separate route, separate OAuth consent.
        .merge(
            Router::new()
                .route(
                    "/api/gcp/connect-write",
                    get(google_cloud::connect_gcp_handler),
                )
                .with_state(google_cloud_write_service.clone()),
        )
        // Full-tier (Phase D impersonation base) consent — broad cloud-platform,
        // host-reserved. Same connect handler, full-service state.
        .merge(
            Router::new()
                .route(
                    "/api/gcp/connect-full",
                    get(google_cloud::connect_gcp_handler),
                )
                .with_state(google_cloud_full_service.clone()),
        )
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Google Cloud OAuth callback — NO auth middleware.
    // Cross-site redirects from accounts.google.com don't carry session cookies
    // (SameSite policy). The user is identified via the state token instead.
    // BOTH consent tiers share this registered redirect URI; the handler
    // routes by the state token's provider.
    let gcp_callback_route = Router::new()
        .route("/api/gcp/callback", get(google_cloud::gcp_callback_handler))
        .with_state(std::sync::Arc::new(google_cloud::GcpOAuthServices {
            read: google_cloud_integration_service.clone(),
            write: google_cloud_write_service.clone(),
            full: google_cloud_full_service.clone(),
        }))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // GitHub App connect — initiate (authenticated). Returns the install URL.
    // Plus the authenticated installations list (for the Integrations UI).
    let github_connect_route = Router::new()
        .route(
            "/api/github/connect",
            get(talos_github_connect::connect_github_handler),
        )
        .route(
            "/api/github/installations",
            get(talos_github_connect::list_github_installations_handler),
        )
        .with_state(github_connect_service.clone())
        .layer(from_fn(rest_auth_middleware)) // injects Extension<Uuid>
        .layer(Extension(auth_service.clone()))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // GitHub App Setup-URL callback — NO auth middleware. A cross-site redirect
    // from github.com carries no SameSite=Strict session cookie; the user is
    // recovered from the single-use state token instead (B2b-2).
    let github_setup_callback_route = Router::new()
        .route(
            "/api/github/setup",
            get(talos_github_connect::github_setup_callback_handler),
        )
        .with_state(github_connect_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Gmail watch-channel management routes (user-scoped). Only wired
    // when the push service is configured — otherwise the state
    // doesn't exist to manage.
    // MCP-1159 (2026-05-16): 16 KiB body cap (sibling sweep to
    // MCP-1158). `CreateGmailWatchRequest` is `{ integration_id, label_ids?,
    // module_id? }` where label_ids is bounded by Gmail's
    // per-watch limit (50 labels × ~100 chars + framing ≈ 6 KiB worst
    // case). 16 KiB gives ~2.5x headroom. Renew/test handlers take no
    // body but inherit the same cap.
    let gmail_watch_channel_routes = gmail_watch_service.as_ref().map(|svc| {
        Router::new()
            .route(
                "/api/gmail/watch-channels",
                get(gmail::handlers::list_watch_channels_handler),
            )
            .route(
                "/api/gmail/watch-channels",
                post(gmail::handlers::create_watch_channel_handler),
            )
            .route(
                "/api/gmail/watch-channels/{channel_uuid}/renew",
                post(gmail::handlers::renew_watch_channel_handler),
            )
            .route(
                "/api/gmail/watch-channels/{channel_uuid}/test",
                post(gmail::handlers::test_watch_channel_handler),
            )
            .route(
                "/api/gmail/watch-channels/{channel_uuid}",
                axum::routing::delete(gmail::handlers::stop_watch_channel_handler),
            )
            .with_state(svc.clone())
            .layer(DefaultBodyLimit::max(16 * 1024))
            .layer(from_fn(rest_auth_middleware))
            .layer(Extension(auth_service.clone()))
            .layer(from_fn(rate_limit::rate_limit_middleware))
            .layer(Extension(api_limiter.clone()))
            .layer(Extension(whitelist.clone()))
    });

    // Pub/Sub push receiver. PUBLIC — no session auth. JWT from
    // Google's OIDC keys is the sole authenticator (see
    // gmail::pubsub_jwt). Only wired when both the verifier and
    // watch service are available.
    let gmail_pubsub_route =
        if let (Some(verifier), Some(watch)) = (&gmail_pubsub_verifier, &gmail_watch_service) {
            // Dispatch context is optional — when NATS or the
            // worker shared key aren't configured, the push handler
            // still verifies + syncs but doesn't publish WASM jobs.
            // That's useful for bootstrap / dev-without-worker
            // setups; production always has both.
            let dispatch_ctx: Option<gmail::dispatch::GmailDispatchContext> =
                match (nats_client.as_ref(), worker_shared_key.as_ref()) {
                    (Some(nats), Some(key)) => Some(gmail::dispatch::GmailDispatchContext {
                        registry: std::sync::Arc::new(registry::ModuleRegistry::new(
                            db_pool.clone(),
                            redis_client.clone(),
                        )),
                        execution_service: module_execution_service.clone(),
                        nats: nats.clone(),
                        worker_shared_key: key.clone(),
                        redis: redis_client.clone(),
                        db_pool: db_pool.clone(),
                        secrets_manager: Some(secrets_manager.clone()),
                        // RFC 0010 P3 (M4): shared claim-based-sealing handle.
                        sealing_handle: module_sealing_handle.clone(),
                    }),
                    _ => {
                        tracing::warn!(
                            "Gmail push dispatch disabled (NATS or WORKER_SHARED_KEY missing); \
                             pushes will sync + advance cursor but NOT run WASM modules"
                        );
                        None
                    }
                };

            let state = std::sync::Arc::new(gmail::handlers::PubsubHandlerState {
                verifier: verifier.clone(),
                watch_service: watch.clone(),
                dispatch: dispatch_ctx,
            });
            Some(
                Router::new()
                    .route(
                        "/api/gmail/pubsub",
                        post(gmail::handlers::pubsub_push_handler),
                    )
                    .with_state(state)
                    // MCP-1159 (2026-05-16): 64 KiB body cap on the
                    // PUBLIC Pub/Sub push receiver. The envelope shape
                    // is fixed by Google (`{ message: { data: base64,
                    // messageId, publishTime }, subscription }`) where
                    // `data` is a base64 JSON of `{ emailAddress,
                    // historyId }` — realistic total <5 KiB. Without
                    // this layer the receiver inherited axum's 2 MiB
                    // default; a forged-Bearer attacker (or a Google
                    // mis-routed push) could waste serde_json parse
                    // CPU on multi-MB bodies before JWT verify even
                    // runs. JWT verification fires AFTER body extract
                    // here — the cap is the only thing standing
                    // between an unauthenticated POST and a multi-MB
                    // parse. 64 KiB gives 12x headroom over the
                    // realistic ceiling for future envelope extensions.
                    .layer(DefaultBodyLimit::max(64 * 1024))
                    .layer(from_fn(rate_limit::rate_limit_middleware))
                    .layer(Extension(webhook_limiter.clone()))
                    .layer(Extension(whitelist.clone())),
            )
        } else {
            None
        };

    // Admin-only gmail operations. Same two-gate model as gcal:
    // ENABLE_ADMIN_OPS=1 + X-Admin-Secret header.
    let gmail_admin_routes = gmail_watch_service.as_ref().map(|svc| {
        Router::new()
            .route("/api/admin/gmail/watch", post(gmail::admin::create_watch))
            .route("/api/admin/gmail/stop-all", post(gmail::admin::stop_all))
            .with_state(svc.clone())
            .layer(from_fn(rate_limit::rate_limit_middleware))
            .layer(Extension(api_limiter.clone()))
            .layer(Extension(whitelist.clone()))
    });

    // ---------- Google Cloud watch-channel routes (user-scoped) ----------
    // Only wired when the push service is configured (GCP_PUBSUB_AUDIENCE
    // set). 16 KiB body cap: `CreateGcpWatchRequest` is a handful of
    // small fields (uuids + an SA email + a display name); the
    // renew-less test/stop handlers take no body but inherit the cap.
    let gcp_watch_channel_routes = gcp_watch_service.as_ref().map(|svc| {
        Router::new()
            .route(
                "/api/gcp/watch-channels",
                get(google_cloud::handlers::list_watch_channels_handler),
            )
            .route(
                "/api/gcp/watch-channels",
                post(google_cloud::handlers::create_watch_channel_handler),
            )
            .route(
                "/api/gcp/watch-channels/{channel_uuid}/test",
                post(google_cloud::handlers::test_watch_channel_handler),
            )
            .route(
                "/api/gcp/watch-channels/{channel_uuid}",
                axum::routing::delete(google_cloud::handlers::stop_watch_channel_handler),
            )
            .with_state(svc.clone())
            .layer(DefaultBodyLimit::max(16 * 1024))
            .layer(from_fn(rest_auth_middleware))
            .layer(Extension(auth_service.clone()))
            .layer(from_fn(rate_limit::rate_limit_middleware))
            .layer(Extension(api_limiter.clone()))
            .layer(Extension(whitelist.clone()))
    });

    // Cloud Monitoring push receiver. PUBLIC — no session auth. The
    // Google-signed OIDC JWT (audience + per-watch service account) is
    // the sole authenticator (see google_cloud::handlers). Only wired
    // when the verifier, watch service, AND audience are all present.
    let gcp_pubsub_route = if let (Some(verifier), Some(watch), Some(audience)) = (
        &gcp_pubsub_verifier,
        &gcp_watch_service,
        &gcp_pubsub_audience,
    ) {
        let dispatch_ctx: Option<google_cloud::dispatch::GcpDispatchContext> =
            match (nats_client.as_ref(), worker_shared_key.as_ref()) {
                (Some(nats), Some(key)) => Some(google_cloud::dispatch::GcpDispatchContext {
                    registry: std::sync::Arc::new(registry::ModuleRegistry::new(
                        db_pool.clone(),
                        redis_client.clone(),
                    )),
                    execution_service: module_execution_service.clone(),
                    nats: nats.clone(),
                    worker_shared_key: key.clone(),
                    redis: redis_client.clone(),
                    db_pool: db_pool.clone(),
                    integrations: google_cloud_integration_service.clone(),
                    secrets_manager: Some(secrets_manager.clone()),
                    // RFC 0010 P3 (M4): shared claim-based-sealing handle —
                    // the sibling the original M4 sweep missed (found live
                    // 2026-07-17: first real Pub/Sub push refused under
                    // `required`).
                    sealing_handle: module_sealing_handle.clone(),
                }),
                _ => {
                    tracing::warn!(
                        "GCP push dispatch disabled (NATS or WORKER_SHARED_KEY missing); \
                         pushes will be recorded but NOT run WASM modules"
                    );
                    None
                }
            };

        let state = std::sync::Arc::new(google_cloud::handlers::PubsubHandlerState {
            verifier: verifier.clone(),
            expected_audience: audience.clone(),
            watch_service: watch.clone(),
            dispatch: dispatch_ctx,
        });
        Some(
            Router::new()
                .route(
                    "/api/gcp/pubsub/{watch_token}",
                    post(google_cloud::handlers::pubsub_push_handler),
                )
                .with_state(state)
                // 256 KiB body cap on the PUBLIC push receiver. Unlike
                // Gmail's tiny `{ emailAddress, historyId }` envelope, a
                // Cloud Monitoring incident carries documentation /
                // policy / condition text that can run to tens of KiB.
                // 256 KiB gives generous headroom while still bounding an
                // unauthenticated multi-MB parse (JWT verify runs AFTER
                // body extract — the cap is the only guard before it).
                // Sizing rationale mirrors MCP-1159.
                .layer(DefaultBodyLimit::max(256 * 1024))
                .layer(from_fn(rate_limit::rate_limit_middleware))
                .layer(Extension(webhook_limiter.clone()))
                .layer(Extension(whitelist.clone())),
        )
    } else {
        None
    };

    // Admin-only GCP operations. Same two-gate model as gmail/gcal.
    let gcp_admin_routes = gcp_watch_service.as_ref().map(|svc| {
        Router::new()
            .route(
                "/api/admin/gcp/watch",
                post(google_cloud::admin::create_watch),
            )
            .route(
                "/api/admin/gcp/stop-all",
                post(google_cloud::admin::stop_all),
            )
            .with_state(svc.clone())
            .layer(from_fn(rate_limit::rate_limit_middleware))
            .layer(Extension(api_limiter.clone()))
            .layer(Extension(whitelist.clone()))
    });

    // Create Gmail API proxy routes
    // NOTE: Layers execute in REVERSE order (bottom-up)
    let gmail_api_routes = Router::new()
        .route("/api/gmail/labels", get(gmail::list_labels_handler))
        .route("/api/gmail/profile", get(gmail::get_profile_handler))
        .with_state(gmail_api_client.clone())
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Create Atlassian (Jira) integration routes (auth-protected)
    // NOTE: Layers execute in REVERSE order (bottom-up)
    let atlassian_integration_routes = Router::new()
        .route(
            "/api/atlassian/integrations",
            get(atlassian::list_integrations_handler),
        )
        .route(
            "/api/atlassian/integrations/{id}",
            axum::routing::delete(atlassian::disconnect_integration_handler),
        )
        .route("/api/atlassian/connect", get(atlassian::connect_handler))
        .with_state(atlassian_integration_service.clone())
        .layer(from_fn(rest_auth_middleware))
        .layer(Extension(auth_service.clone()))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Atlassian OAuth callback — NO auth middleware.
    // Cross-site redirects from auth.atlassian.com don't carry session cookies
    // (SameSite policy). The user is identified via the state token instead.
    let atlassian_callback_route = Router::new()
        .route("/api/atlassian/callback", get(atlassian::callback_handler))
        .with_state(atlassian_integration_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Briefing HTML endpoint — authenticated, returns latest morning briefing as HTML.
    // MCP-680: SecretsManager Extension lets the handler decrypt
    // `output_data_enc` on production deploys (handler returned 404 for
    // every user pre-fix because the SELECT filtered plaintext-only).
    let briefing_routes = Router::new()
        .route(
            "/api/briefings/latest",
            get(integrations::latest_briefing_handler),
        )
        .layer(from_fn(rest_auth_middleware))
        .layer(Extension(auth_service.clone()))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()))
        .layer(Extension(secrets_manager.clone()));

    // Create Google Calendar integration management routes (auth‑protected)
    // NOTE: Layers execute in REVERSE order (bottom‑up)
    let google_calendar_routes = Router::new()
        .route(
            "/api/google-calendar/integrations",
            get(google_calendar::handlers::list_integrations_handler),
        )
        .route(
            "/api/google-calendar/integrations/{id}",
            get(google_calendar::handlers::get_integration_handler),
        )
        .route(
            "/api/google-calendar/integrations/{id}",
            axum::routing::delete(google_calendar::handlers::disconnect_integration_handler),
        )
        .route(
            "/api/google-calendar/integrations/{id}/calendars",
            get(google_calendar::handlers::list_calendars_handler),
        )
        .route(
            "/api/google-calendar/watch/create",
            post(google_calendar::handlers::create_watch_handler),
        )
        .route(
            "/api/google-calendar/watch-channels",
            get(google_calendar::handlers::list_watch_channels_handler),
        )
        .route(
            "/api/google-calendar/watch-channels/{channel_uuid}/renew",
            post(google_calendar::handlers::renew_watch_channel_handler),
        )
        .route(
            "/api/google-calendar/watch-channels/{channel_uuid}/test",
            post(google_calendar::handlers::test_watch_channel_handler),
        )
        .route(
            "/api/google-calendar/watch-channels/{channel_uuid}",
            axum::routing::delete(google_calendar::handlers::stop_watch_channel_handler),
        )
        // Dedicated Calendar OAuth connect (authenticated). Returns the Google
        // authorize URL; identity is bound into the CSRF state token so the
        // (unauthenticated) callback recovers the user from the token.
        .route(
            "/api/google-calendar/connect",
            get(google_calendar::handlers::connect_calendar_handler),
        )
        .with_state(google_calendar_service.clone())
        // MCP-1159 (2026-05-16): 8 KiB body cap. `CreateWatchRequest`
        // is `{ integration_id: Uuid, calendar_id: String, webhook_url:
        // Option<String> }` — UUID (36) + calendar_id (email-shaped
        // ~80 or "primary") + webhook URL (~200 chars). ~500 bytes
        // worst case; 8 KiB cap is ~16x headroom. Renew/test routes
        // take no body. Same sibling-sweep pattern as the gmail
        // watch-channel routes above (MCP-1158 / MCP-1159 family).
        .layer(DefaultBodyLimit::max(8 * 1024))
        .layer(from_fn(rest_auth_middleware)) // Runs 5th (last) - needs auth_service extension
        .layer(Extension(auth_service.clone())) // Runs 4th - provides auth_service to middleware above
        .layer(from_fn(rate_limit::rate_limit_middleware)) // Runs 3rd
        .layer(Extension(api_limiter.clone())) // Runs 2nd
        .layer(Extension(whitelist.clone())); // Runs 1st (first)

    // Public human-in-the-loop approval gate routes.
    // Authentication is the cryptographically random token embedded in the URL.
    // Rate-limited with the webhook limiter to prevent enumeration.
    let approval_gate_routes = Router::new()
        .route(
            "/approvals/{token}/{action}",
            // GET renders a confirmation page with a POST form — keeps
            // the action unsafe (link previews, prefetchers, proxies
            // can GET a shared URL without side effects). POST actually
            // resolves the gate + triggers the continuation workflow.
            get(webhooks::approval_gate_preview).post(webhooks::approval_gate_handler),
        )
        .layer(DefaultBodyLimit::max(4096))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Public one-click ops-alert severity-correction routes (email
    // capability URLs). Same trust model as the approval gates above:
    // the cryptographically random token in the path IS the auth, GET
    // renders a confirm page only (prefetch-safe), POST applies the
    // correction, and the webhook limiter guards enumeration.
    let correction_routes = Router::new()
        .route(
            "/corrections/{token}/{severity}",
            get(webhooks::correction_preview).post(webhooks::correction_apply),
        )
        .layer(DefaultBodyLimit::max(4096))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Public one-click approve/reject routes for SUSPENDED confidence-gate
    // executions (email capability URLs). Same trust model as the approval
    // gates and corrections above: the cryptographically random token in
    // the path IS the auth, GET renders a confirm page only (prefetch-safe),
    // POST applies the decision via the shared record-then-resume path, and
    // the webhook limiter guards enumeration. Distinct from
    // /approvals/{token} (that's the continuation-gate subsystem); these
    // resume a paused execution's checkpoint (submit_workflow_approval path).
    let approval_action_routes = Router::new()
        .route(
            "/approval-actions/{token}/{action}",
            get(webhooks::approval_action_preview).post(webhooks::approval_action_apply),
        )
        .layer(DefaultBodyLimit::max(4096))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Public suspension callback routes.
    // Auth is the 64-hex correlation_id (256-bit random) embedded in the URL.
    // Rate-limited to prevent enumeration brute-force.
    let suspension_callback_routes = Router::new()
        .route(
            "/api/callbacks/{correlation_id}",
            post(webhooks::suspension_callback_handler),
        )
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Google Calendar webhook endpoint (PUBLIC - no auth, uses X-Goog-Channel-Token for verification)
    // Note: redis_client, nats_client, and module_execution_service extensions come from shared app layers
    let google_calendar_webhook_routes = Router::new()
        .route(
            "/api/google-calendar/webhook",
            post(google_calendar::handlers::webhook_notification_handler),
        )
        .with_state(google_calendar_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Dedicated Calendar OAuth callback (PUBLIC — no session auth). Identity is
    // recovered from the single-use CSRF state token inside handle_callback;
    // cross-site redirects from Google don't carry the SameSite session cookie.
    // Rate-limited with the webhook limiter to prevent state-token enumeration.
    let google_calendar_callback_routes = Router::new()
        .route(
            "/api/google-calendar/callback",
            get(google_calendar::handlers::calendar_callback_handler),
        )
        .with_state(google_calendar_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(webhook_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Admin-only gcal operations. Gated by:
    //   1. ENABLE_ADMIN_OPS=1 env var ("big red button" — unset in prod)
    //   2. X-Admin-Secret header vs ADMIN_SECRET_KEY (constant-time compare)
    // Every successful call is audit-logged with event_type="admin_*".
    // Handlers live in google_calendar::admin; see that module for
    // the full defense-in-depth rationale.
    let gcal_admin_routes = Router::new()
        .route(
            "/api/admin/google-calendar/watch",
            post(google_calendar::admin::create_watch),
        )
        .route(
            "/api/admin/google-calendar/stop-all",
            post(google_calendar::admin::stop_all),
        )
        .route(
            "/api/admin/google-calendar/stop-orphan",
            post(google_calendar::admin::stop_orphan),
        )
        .with_state(google_calendar_service.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // Combine all routes

    // Admin routes
    let admin_routes = Router::new()
        .route(
            "/api/admin/secrets/invalidate-cache",
            post(
                |headers: axum::http::HeaderMap,
                 State(secrets_manager): State<std::sync::Arc<secrets::SecretsManager>>| async move {
                    // GATE 1: ENABLE_ADMIN_OPS must be truthy. The gcal admin
                    // path (`google_calendar/admin.rs`) has documented this as the
                    // "big red button" — operators leave it unset in prod so a
                    // leaked ADMIN_SECRET_KEY alone doesn't grant access. Pairing
                    // env-var + secret is the canonical pattern; this route was
                    // missing the env-var half.
                    //
                    // MCP-1064 (2026-05-15): routed through
                    // `talos_config::admin_ops_enabled()` to fix cross-site
                    // drift. Pre-fix this site required the literal `"1"`,
                    // while the gmail / gcal sibling sites accepted
                    // `"1" | "true"`. Operator setting `ENABLE_ADMIN_OPS=true`
                    // would enable gmail/gcal admin but NOT this route. All
                    // three now accept the canonical `true | 1 | yes | on`.
                    if !talos_config::admin_ops_enabled() {
                        tracing::warn!(
                            "admin secrets endpoint hit but ENABLE_ADMIN_OPS is unset/false"
                        );
                        return (axum::http::StatusCode::NOT_FOUND, "Not found");
                    }

                    let admin_secret = std::env::var("ADMIN_SECRET_KEY").unwrap_or_default();
                    let provided_secret = headers.get("X-Admin-Secret").and_then(|h| h.to_str().ok()).unwrap_or("");

                    // GATE 2: constant-time secret compare.
                    //
                    // MCP-983 (2026-05-15): direct ct_eq on slices. Pre-fix
                    // padded both inputs to a 512-byte buffer ("ct_eq always
                    // runs regardless of length, preventing length leakage")
                    // — but when `admin_secret.len() > 512` only the FIRST
                    // 512 bytes participated in the byte comparison. An
                    // attacker who knew those 512 bytes (plus the configured
                    // length, leaked via the explicit `a.len() == b.len()`
                    // check) could authenticate against any longer suffix.
                    // Subtle's slice `ct_eq` returns Choice(0) immediately
                    // on length mismatch and runs constant-time over equal-
                    // length contents; the residual length signal is
                    // sub-jitter for sensibly-sized admin secrets. Same fix
                    // applied to sibling sites talos-gmail/src/admin.rs and
                    // talos-google-calendar/src/admin.rs.
                    use subtle::ConstantTimeEq;
                    let is_match = admin_secret
                        .as_bytes()
                        .ct_eq(provided_secret.as_bytes())
                        .unwrap_u8()
                        == 1;

                    if !admin_secret.is_empty() && is_match {
                        // MCP-800 (2026-05-14): surface invalidate_dek_cache
                        // failures truthfully. Pre-fix `let _ = ...await`
                        // discarded the Result and the admin always saw a
                        // 200 "DEK cache invalidated successfully" — even
                        // when the underlying audit-log write or in-memory
                        // cache mutation failed. This is the admin
                        // operator's primary signal post-DEK-rotation /
                        // post-incident; misleading "success" lets them
                        // believe an actor's WASM-resident plaintext DEK
                        // was purged when it wasn't. Same misleading-
                        // success class as MCP-737 (graph-mutation
                        // handlers) and MCP-738 (duplicate/deploy
                        // workflow). Underlying error is logged at ERROR
                        // server-side; admin sees a generic 500 to avoid
                        // leaking internal failure detail (sqlx schema,
                        // KEK provider state, etc.).
                        match secrets_manager
                            .invalidate_dek_cache(None, "ADMIN_API", None)
                            .await
                        {
                            Ok(_) => (
                                axum::http::StatusCode::OK,
                                "DEK cache invalidated successfully",
                            ),
                            Err(e) => {
                                tracing::error!(
                                    target: "talos_audit",
                                    error = ?e,
                                    "admin invalidate_dek_cache failed — DEK plaintext may still be cached"
                                );
                                (
                                    axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                                    "Failed to invalidate DEK cache",
                                )
                            }
                        }
                    } else {
                        (axum::http::StatusCode::UNAUTHORIZED, "Unauthorized")
                    }
                },
            ),
        )
        .with_state(secrets_manager.clone())
        .layer(from_fn(rate_limit::rate_limit_middleware))
        .layer(Extension(api_limiter.clone()))
        .layer(Extension(whitelist.clone()));

    // The MCP state re-uses the vault-backed Arc built above at line ~1783
    // — a single client instance shared by GraphQL + MCP ensures rotation
    // propagates through both surfaces identically.

    // MCP-680 (2026-05-13): wire SecretsManager so analytics output-reading
    // queries (`get_completed_executions_output` etc.) can decrypt
    // `output_data_enc` rows. Without this the analytics surface would be
    // blind to every completed execution in encryption-enabled deploys
    // (production default) — per-node timing breakdowns showed empty for
    // every workflow.
    let analytics_repo = std::sync::Arc::new(
        analytics_repository::AnalyticsRepository::new(db_pool.clone())
            .with_secrets_manager(secrets_manager.clone()),
    );

    let advanced_repo = std::sync::Arc::new(advanced_repository::AdvancedRepository::new(
        db_pool.clone(),
    ));

    // workflow_repo, module_repo, execution_repo, and actor_repo are
    // constructed earlier (alongside the cross-protocol services) so
    // they're shared with the GraphQL ctx.data wiring. The Arc is
    // cheap to clone here.

    let mcp_routes = mcp::create_router(
        registry.clone(),
        db_pool.clone(),
        runtime.clone(),
        compiler.clone(),
        nats_client.clone(),
        llm_client,
        circuit_breaker.clone(),
        dlp_service.clone(),
        workflow_repo,
        execution_repo,
        analytics_repo,
        advanced_repo,
        actor_repo,
        module_repo,
        secrets_manager.clone(),
        workflow_creation_service.clone(),
        hot_update_service.clone(),
        execution_orchestration_service.clone(),
        workflow_manifest_service.clone(),
        replay_service.clone(),
        inline_compile_service.clone(),
        search_service.clone(),
        failure_analysis_service.clone(),
        actor_lifecycle_service.clone(),
        Some(ollama_client),
    );

    // MCP routes are added separately to avoid the global governor rate limiter.
    // MCP has its own per-agent rate limiter (1000 req/min).
    let mcp_router = Router::new().nest("/mcp", mcp_routes);

    // Probe + scrape routes are merged AFTER the rate-limit layers below, so
    // kubelet liveness/readiness/startup probes and Prometheus scrapes can
    // never be rate-limited. With Traefik on `externalTrafficPolicy: Cluster`,
    // probes share the node IP with all SNAT'd external traffic — without this
    // bypass, a busy site evicts probes from the per-IP bucket, the kubelet
    // marks the pod NotReady, traffic gets a 502, and the cycle repeats.
    //
    // This sub-router needs its own copies of the extensions its handlers
    // depend on (db_pool, redis_client, nats_client) because the Extension
    // layers added to the main router only wrap routes registered before
    // those layers. See is_rate_limit_exempt_path() for the path list — it
    // mirrors the routes here as a defence-in-depth check.
    let probe_routes = Router::new()
        .route("/", get(|| async { "Talos Controller is running" }))
        .route("/health", get(health_check))
        .route("/health/redis", get(health_check_redis))
        .route("/health/nats", get(health_check_nats))
        .route("/live", get(liveness_probe)) // no-nginx-route: kubelet-only probe
        .route("/ready", get(readiness_probe)) // no-nginx-route: kubelet-only probe
        // Prometheus scrape target — returns the full registry in text
        // exposition format. Shared-secret auth via PROMETHEUS_SCRAPE_TOKEN
        // (Bearer). Scrape this on an internal-only Service in K8s; do not
        // expose publicly. See deploy/observability/alerts.yaml for the
        // alert rules that consume these series.
        .route("/metrics/prometheus", get(prometheus_metrics_handler)) // no-nginx-route: in-cluster scrape only
        // Dedicated double-submit CSRF cookie seeder. The frontend GETs
        // this once before its first POST `/graphql` to ensure the cookie
        // is set. Lives in `probe_routes` (no rate limiting, no auth) and
        // sets the Set-Cookie header directly so it doesn't depend on
        // CookieManagerLayer's interaction with merged sub-routers — that
        // layering was unreliable and produced silent no-Set-Cookie
        // responses (debugged 2026-04-25).
        .route("/auth/csrf", get(seed_csrf_handler))
        .layer(Extension(db_pool.clone()))
        .layer(Extension(redis_client.clone()))
        .layer(Extension(nats_client.clone()));

    // RFC 0010 P2 inc.4c: in-cluster worker self-registration. Mounted ONLY when
    // a registration credential scheme is configured — the legacy shared token
    // (TALOS_WORKER_REGISTRATION_TOKEN) and/or bound-token enforcement
    // (TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN=1, provisioning tokens minted via
    // the mint-worker-provisioning-token CLI). Fail-closed: neither ⇒ no route
    // ⇒ 404. Merged after the rate-limit layers like probe_routes, so it
    // carries its own Extensions (db_pool + the auth config) and a small body
    // cap. Access is further restricted to worker pods by the chart
    // NetworkPolicy; it is never exposed via nginx (`no-nginx-route`).
    let worker_reg_shared_token = std::env::var("TALOS_WORKER_REGISTRATION_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(std::sync::Arc::new);
    let worker_reg_require_bound = std::env::var("TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            matches!(v.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(false);
    let internal_routes = if worker_reg_shared_token.is_some() || worker_reg_require_bound {
        tracing::info!(
            require_bound_token = worker_reg_require_bound,
            shared_token_accepted = worker_reg_shared_token.is_some() && !worker_reg_require_bound,
            "Worker self-registration endpoint enabled at POST /internal/worker-key"
        );
        Router::new()
            .route(
                "/internal/worker-key",
                axum::routing::post(register_worker_key_handler),
            ) // no-nginx-route: RFC0010 in-cluster worker self-registration
            .layer(axum::extract::DefaultBodyLimit::max(4096))
            .layer(Extension(db_pool.clone()))
            .layer(Extension(WorkerRegAuth {
                shared_token: worker_reg_shared_token,
                require_bound: worker_reg_require_bound,
            }))
    } else {
        tracing::info!(
            "Worker self-registration endpoint disabled (TALOS_WORKER_REGISTRATION_TOKEN and \
             TALOS_WORKER_REG_REQUIRE_BOUND_TOKEN unset); use the register-worker-identity CLI \
             or TALOS_WORKER_PUBLIC_KEYS env"
        );
        Router::new()
    };

    let app = Router::new()
        // Authenticated user-facing metrics dashboard. Stays inside the
        // rate-limited router; the unauthenticated Prometheus scrape lives
        // in `probe_routes` above.
        .route("/metrics", get(metrics_handler)) // no-nginx-route: authenticated metrics dashboard, accessed via /graphql proxy
        .merge(api_docs::create_docs_router())
        .merge(graphql_routes)
        .merge(webhook_routes)
        .merge(approval_routes)
        .merge(oauth_routes)
        .merge(slack_api_routes)
        .merge(slack_integration_routes)
        .merge(slack_callback_route)
        .merge(admin_routes)
        .merge(gmail_api_routes)
        .merge(gmail_integration_routes)
        .merge(gmail_callback_route)
        .merge(gcp_integration_routes)
        .merge(gcp_callback_route)
        .merge(github_connect_route)
        .merge(github_setup_callback_route);
    // Optional gmail push routes — `None` when GMAIL_PUBSUB_TOPIC
    // wasn't configured at startup.
    let app = if let Some(r) = gmail_watch_channel_routes {
        app.merge(r)
    } else {
        app
    };
    let app = if let Some(r) = gmail_pubsub_route {
        app.merge(r)
    } else {
        app
    };
    let app = if let Some(r) = gmail_admin_routes {
        app.merge(r)
    } else {
        app
    };
    // Optional GCP push routes — `None` when GCP_PUBSUB_AUDIENCE wasn't
    // configured at startup.
    let app = if let Some(r) = gcp_watch_channel_routes {
        app.merge(r)
    } else {
        app
    };
    let app = if let Some(r) = gcp_pubsub_route {
        app.merge(r)
    } else {
        app
    };
    let app = if let Some(r) = gcp_admin_routes {
        app.merge(r)
    } else {
        app
    };
    let app = app
        .merge(atlassian_integration_routes)
        .merge(atlassian_callback_route)
        // Briefing HTML endpoint — authenticated, returns latest morning briefing as HTML
        .merge(briefing_routes)
        // Integration provider registry — public, returns static metadata + config status
        .route(
            "/api/integrations/providers",
            get(integrations::providers_handler),
        )
        // Public endpoint for client configuration (no auth required)
        // The route still needs access to the GoogleCalendarService for the client ID
        // and redirect URI, so we attach the same shared state as the other Google
        // Calendar routes. This keeps the router type uniform and preserves the
        // `into_make_service_with_connect_info` method.
        .merge(
            Router::new()
                .route(
                    "/api/google-calendar/client-config",
                    get(google_calendar::handlers::client_config_handler),
                )
                .with_state(google_calendar_service.clone()),
        )
        .merge(approval_gate_routes)
        .merge(correction_routes)
        .merge(approval_action_routes)
        .merge(suspension_callback_routes)
        .merge(google_calendar_routes)
        .merge(google_calendar_webhook_routes)
        .merge(google_calendar_callback_routes)
        .merge(gcal_admin_routes)
        // M-8 (talos-registry review): /api/registry/publish writes
        // globally-visible catalog rows (`kind='catalog', user_id=NULL`)
        // that every authenticated user can install. The endpoint is
        // operator-only — driven by `scripts/util/talos-publish.py` —
        // and protected at the handler layer by a shared bearer-token
        // check (`REGISTRY_PUBLISH_TOKEN`). Production deploys MUST set
        // the env var or the endpoint refuses POSTs with 503.
        // Single-tenant operators set the token; multi-tenant should
        // disable nginx routing for /api/registry/* entirely.
        .nest(
            "/api/registry",
            registry::api::registry_router().with_state(registry.clone()),
        )
        // Cookie support
        .layer(CookieManagerLayer::new())
        // Add shared extensions for all routes
        .layer(Extension(db_pool.clone()))
        // MCP-1131 (2026-05-16): `.clone()` so `webhook_router` stays
        // in scope for the graceful_shutdown callback below; the
        // shutdown callback calls `webhook_router.shutdown_dlq()`
        // before the tokio runtime aborts the DLQ batch processor.
        // Closes the "DLQ messages in-flight" concern from MCP-667.
        .layer(Extension(webhook_router.clone()))
        // Registry shared with approval gate handler for continuation workflow dispatch
        .layer(Extension(registry.clone()))
        .layer(Extension(redis_client.clone()))
        .layer(Extension(nats_client.clone()))
        .layer(Extension(Some(module_execution_service.clone())))
        .layer(Extension(Some(worker_manager.clone())))
        .layer(Extension(worker_shared_key.clone()))
        // Shared runtime and secrets manager — used by webhook handlers to execute
        // downstream workflow nodes in-process (workflow chaining).
        .layer(Extension(Some(runtime.clone())))
        .layer(Extension(Some(secrets_manager.clone())))
        // Shared orchestration service — the one-click approve/reject email
        // links (/approval-actions/{token}) apply decisions through the same
        // record-then-resume write path as submit_workflow_approval.
        .layer(Extension(Some(execution_orchestration_service.clone())))
        // RFC 0010 P3 (M4): shared claim-based-sealing handle for the
        // Google-Calendar push handler (fire-and-forget module dispatch).
        .layer(Extension(module_sealing_handle.clone()))
        // Trusted proxy list — used by rate_limit_middleware to decide whether to
        // trust X-Forwarded-For headers. Shared across all rate-limited routes.
        .layer(Extension(trusted_proxies));

    // Conditionally add global rate limiting (only in production)
    let app = if config::is_production() {
        app.layer(from_fn(rate_limit::global_rate_limit_middleware))
            .layer(Extension(global_limiter))
    } else {
        tracing::info!("Global rate limiter DISABLED in development mode");
        app
    };

    // Apply tower_governor IP rate limiting only in production.
    // In development the burst of simultaneous GraphQL queries on page load
    // (AuthenticatedApp, Dashboard, WorkflowStatsPanel, etc.) routinely exceeds
    // the 20-token burst cap and produces spurious 429s.
    let app = if config::is_production() {
        app.layer(governor_layer)
    } else {
        tracing::info!("tower_governor IP rate limiter DISABLED in development mode");
        app
    };
    let app = app
        // Merge MCP routes AFTER governor so they're exempt from IP rate limiting
        .merge(mcp_router)
        // Same for probe + scrape routes — see `probe_routes` definition.
        .merge(probe_routes)
        // RFC 0010 P2 inc.4c worker self-registration (empty router when the
        // token is unset, so this merge is a no-op in that mode).
        .merge(internal_routes)
        // Request ID for tracing and audit logging (generates/propagates X-Request-ID)
        .layer(from_fn(request_id::request_id_middleware))
        // Security headers (apply to all responses)
        .layer(from_fn(security_headers::add_security_headers))
        // CORS - must be last layer (runs first) to handle OPTIONS preflight
        .layer(from_fn(cors_middleware));

    Ok(app)
}
