use axum::{
    body::Body,
    http::{Method, Request, Response, StatusCode},
    middleware::Next,
};
use rand::RngCore;
use tower_cookies::{Cookie, Cookies};

use dashmap::DashMap;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

const CSRF_TOKEN_LENGTH: usize = 32;
const CSRF_COOKIE_NAME: &str = "talos_csrf_token";
const CSRF_HEADER_NAME: &str = "X-CSRF-Token";
const GRACE_PERIOD_SECONDS: u64 = 15;

/// Maximum GraphQL request body size (bytes). SINGLE SOURCE OF TRUTH for both
/// the `/graphql` route's `DefaultBodyLimit::max(..)` AND the dev-only body
/// buffering in [`csrf_protection_graphql`] (L5, 2026-05-28 review).
///
/// Pre-L5 the CSRF middleware buffered the body with a hard-coded 1 MiB cap
/// while the route allowed 5 MiB, so a legitimate 1–5 MiB mutation was rejected
/// with a misleading "Failed to read request body" 400 — the effective limit
/// was silently 1 MiB. Both sites now reference this const so they can never
/// drift again. (In production the CSRF middleware no longer reads the body at
/// all — see `csrf_protection_graphql` — so this cap applies only to the
/// dev-introspection inspection path; the route's `DefaultBodyLimit` is the
/// real production ceiling.)
pub const GRAPHQL_MAX_BODY_BYTES: usize = 5 * 1024 * 1024;

/// MCP-1145 (2026-05-16): defense-in-depth max-entries cap on the
/// rotation grace cache. Sibling pattern to MCP-1093/1132/1137
/// (workspace-wide audit rule: every TTL-bounded in-memory cache needs
/// BOTH read-path eviction AND periodic sweep AND a max-entries cap).
///
/// Pre-fix the grace cache had time-based eviction via
/// `prune_grace_cache()` (1s interval) but no upper bound on entry
/// count. At 10k mutation req/s with token rotation on every request,
/// the cache could grow to ~600k entries in steady state during a
/// sustained flood before the 15s GRACE_PERIOD pruner caught up — at
/// ~130 bytes/entry (64-hex-char String + Instant + DashMap overhead)
/// that's ~78 MB of attacker-influenced heap. Each entry is dropped
/// after 15s, so it's bounded — but only at a rate the pruner can keep
/// up with.
///
/// 50k matches `NONCE_CACHE_MAX_ENTRIES` in talos-memory. Legitimate
/// concurrent rotations should never approach this — typical browser
/// rotates one token per mutation; even a 1000-user / 50 req/s burst
/// only generates 1000-50000 entries in the 15s window. Operators who
/// hit the cap should expect to see the structured WARN
/// `event_kind = "csrf_grace_cache_cap_hit"` in logs and investigate
/// for sustained mutation flood (DDoS) before raising the cap.
const GRACE_CACHE_MAX_ENTRIES: usize = 50_000;

/// In-memory cache of recently rotated CSRF tokens.
/// This prevents race conditions where parallel requests are sent before the
/// browser has updated its cookie jar with the newly rotated token.
static TOKEN_GRACE_CACHE: OnceLock<DashMap<String, Instant>> = OnceLock::new();

fn get_grace_cache() -> &'static DashMap<String, Instant> {
    TOKEN_GRACE_CACHE.get_or_init(DashMap::new)
}

/// MCP-1145: gated insert into the rotation grace cache. When at-cap,
/// skip the insert and emit a structured WARN so operators can
/// correlate cache-saturation with mutation-traffic spikes. The
/// callers (`csrf_protection` + `csrf_protection_graphql`) treat the
/// grace cache as best-effort — failing to insert means a racing
/// parallel request with the now-rotated token won't be admitted via
/// the grace path; the user-visible failure is a single 403 on the
/// racing request, not session breakage. Same fail-closed posture as
/// the canonical nonce-cache cap-hit handling.
fn insert_grace_token(token: String) {
    let cache = get_grace_cache();
    // Racy overshoot acceptable — defense-in-depth, not a strict
    // boundary. The pruner runs every 1s; a few-entry overshoot
    // between the cap check and insert costs nothing meaningful.
    if cache.len() >= GRACE_CACHE_MAX_ENTRIES {
        tracing::warn!(
            target: "talos_csrf",
            event_kind = "csrf_grace_cache_cap_hit",
            size = cache.len(),
            cap = GRACE_CACHE_MAX_ENTRIES,
            "CSRF rotation grace cache at capacity; skipping insert (racing parallel requests with the just-rotated token will see a single 403)"
        );
        return;
    }
    cache.insert(token, Instant::now());
}

/// L-15: prune expired tokens from the grace cache, but rate-limit the
/// O(n) walk so sustained mutation traffic doesn't pay it on every
/// request. We track the last successful prune in a `Mutex<Instant>`
/// (acquired with `try_lock` — if another thread is already pruning,
/// skip this iteration entirely). At a 1s minimum interval, even at
/// 10k req/s the prune cost is amortised across 10k calls.
fn prune_grace_cache() {
    static LAST_PRUNE: OnceLock<std::sync::Mutex<Instant>> = OnceLock::new();
    const PRUNE_MIN_INTERVAL_SECS: u64 = 1;

    let last_prune =
        LAST_PRUNE.get_or_init(|| std::sync::Mutex::new(Instant::now() - Duration::from_secs(60)));

    // Non-blocking try-lock: if another thread is already inside the
    // critical section we skip — they'll handle the prune.
    let Ok(mut last) = last_prune.try_lock() else {
        return;
    };
    if last.elapsed() < Duration::from_secs(PRUNE_MIN_INTERVAL_SECS) {
        return;
    }

    let cache = get_grace_cache();
    cache.retain(|_, instant| instant.elapsed() < Duration::from_secs(GRACE_PERIOD_SECONDS));
    *last = Instant::now();
}

/// Generate a cryptographically secure random CSRF token
pub fn generate_csrf_token() -> String {
    let mut token_bytes = vec![0u8; CSRF_TOKEN_LENGTH];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    hex::encode(token_bytes)
}

/// MCP-1075 (2026-05-16): canonical CSRF cookie builder. Pre-fix four
/// inline copies of `Cookie::new ... set_http_only(false) ...
/// set_secure(is_production) ... set_same_site(Strict) ... set_path("/")`
/// existed across `csrf_protection` (seed + rotate) and
/// `csrf_protection_graphql` (seed + rotate). Same N-inline-copies
/// drift class as the session cookies (MCP-1040/1041) and the
/// canonical bool/env helpers (MCP-1060/1064/1065/1066). Extracting
/// the builder means a future change to CSRF cookie attributes
/// (e.g., changing SameSite to Lax for cross-subdomain support,
/// adding a Max-Age, tightening Domain) lands in ONE place.
///
/// Attributes:
/// - `HttpOnly = false` — frontend reads this via JS to populate the
///   X-CSRF-Token request header (double-submit pattern).
/// - `Secure = is_production()` — HTTPS-only in prod.
/// - `SameSite = Strict` — never sent on cross-site requests.
/// - `Path = /` — sent on every same-origin request.
///
/// The `seed_csrf_handler` in `controller/main.rs` builds the
/// Set-Cookie header by hand (NOT via this builder) because of the
/// 2026-04-25 CookieManagerLayer-merge-router debugging episode. Its
/// attribute set is identical; the divergence is API-only (tower-
/// cookies' Cookie vs hand-formatted header string).
fn build_csrf_cookie(token: String) -> Cookie<'static> {
    let mut cookie = Cookie::new(CSRF_COOKIE_NAME, token);
    cookie.set_http_only(false);
    cookie.set_secure(talos_config::is_production());
    cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    cookie.set_path("/");
    cookie
}

/// CSRF protection middleware using double-submit cookie pattern
pub async fn csrf_protection(
    cookies: Cookies,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, String)> {
    let method = request.method();
    let path = request.uri().path();

    // Skip CSRF protection for safe methods (GET, HEAD, OPTIONS)
    if matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        // Ensure CSRF token exists in cookie for future mutations
        if cookies.get(CSRF_COOKIE_NAME).is_none() {
            cookies.add(build_csrf_cookie(generate_csrf_token()));
        }

        let response = next.run(request).await;
        return Ok(response);
    }

    // MCP-1086 (2026-05-16): removed dead `path == "/health" ||
    // path == "/metrics"` skip. The safe-methods branch above already
    // handles GET requests to those endpoints (which is all they
    // support today). The previous skip applied ONLY to non-safe
    // methods (POST/PUT/DELETE/PATCH) on /health and /metrics —
    // currently a no-op because no POST handlers exist on those
    // routes, but a latent hazard: if a future PR adds a POST handler
    // (e.g., POST /metrics for resetting metric state, POST /health
    // for triggering custom health probes), CSRF would silently
    // bypass with no operator signal. Defence-in-depth: fail-closed
    // on unrecognised mutation paths.

    // Skip CSRF for webhook endpoints (they use HMAC signatures)
    if path.starts_with("/webhooks/") {
        let response = next.run(request).await;
        return Ok(response);
    }

    // For mutations (POST, PUT, DELETE, PATCH), validate CSRF token
    let cookie_token = cookies.get(CSRF_COOKIE_NAME).map(|c| c.value().to_string());

    let header_token = request
        .headers()
        .get(CSRF_HEADER_NAME)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    prune_grace_cache();

    match (cookie_token, header_token) {
        (Some(cookie), Some(header)) => {
            // MCP-592 (2026-05-12): reject empty cookie/header values
            // before the constant-time compare. Pre-fix two empty
            // strings would match (`ct_eq(&[], &[]) == true`), so a
            // mutation request with cookie="" and header="" — which
            // can happen via a manual `document.cookie="talos_csrf="`
            // overwrite or a buggy proxy stripping the value but
            // preserving the cookie name — silently authenticated.
            // The legitimate generation path always produces a 64-
            // hex-char token, so a non-empty length check is a no-op
            // for real traffic and closes the empty-value bypass.
            // Sibling fix class to MCP-590/591 (empty-env-var auth
            // bypass).
            if cookie.is_empty() || header.is_empty() {
                tracing::warn!("CSRF token empty value rejected");
                return Err((
                    StatusCode::FORBIDDEN,
                    "CSRF token validation failed".to_string(),
                ));
            }
            let matches_current =
                constant_time_eq::constant_time_eq(cookie.as_bytes(), header.as_bytes());
            let matches_grace = !matches_current && get_grace_cache().contains_key(&header);

            if matches_current || matches_grace {
                // CSRF tokens match (either current or recently rotated)
                // Rotate token for the next request.
                // Add the token being replaced (the cookie token) to the grace cache
                // so parallel requests already in flight can still succeed.
                // MCP-1145: gated insert with cap-hit logging.
                insert_grace_token(cookie);
                cookies.add(build_csrf_cookie(generate_csrf_token()));

                let response = next.run(request).await;
                Ok(response)
            } else {
                tracing::warn!("CSRF token mismatch for {} {}", method, path);
                Err((
                    StatusCode::FORBIDDEN,
                    "CSRF token validation failed".to_string(),
                ))
            }
        }
        (None, _) => {
            tracing::warn!("Missing CSRF cookie for {} {}", method, path);
            Err((
                StatusCode::FORBIDDEN,
                "CSRF token required (cookie missing)".to_string(),
            ))
        }
        (_, None) => {
            tracing::warn!("Missing CSRF header for {} {}", method, path);
            Err((
                StatusCode::FORBIDDEN,
                "CSRF token required (header missing)".to_string(),
            ))
        }
    }
}

/// GraphQL-specific CSRF protection
/// This variant allows GraphQL introspection queries without CSRF
pub async fn csrf_protection_graphql(
    cookies: Cookies,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (StatusCode, String)> {
    let method = request.method();

    // Skip CSRF protection for safe methods
    if matches!(method, &Method::GET | &Method::HEAD | &Method::OPTIONS) {
        // Ensure CSRF token exists for GraphiQL
        if cookies.get(CSRF_COOKIE_NAME).is_none() {
            cookies.add(build_csrf_cookie(generate_csrf_token()));
        }

        let response = next.run(request).await;
        return Ok(response);
    }

    // MCP-1066 (2026-05-15): canonical resolver. Pre-fix case-sensitive
    // `== "true"` matched the controller startup guard's predicate by
    // chance; both sites now share `talos_config::dev_csrf_bypass_enabled()`
    // so any future bypass-consuming site that uses `bool_env_or_default`
    // can't diverge (e.g. accepting `=1` while production startup
    // stays inert).
    let is_production = talos_config::is_production();
    let allow_dev_bypass = !is_production && talos_config::dev_csrf_bypass_enabled();

    // L5 (2026-05-28 review): only BUFFER the request body when we actually
    // need to inspect it. The CSRF token check below uses headers + cookies
    // ONLY — never the body — so the sole reason to read the body is the
    // dev-only introspection bypass (and the explicit dev unsafe bypass), both
    // of which require `!is_production`. In production we therefore pass the
    // request through UNTOUCHED: no buffering of up to GRAPHQL_MAX_BODY_BYTES
    // per mutation, and — critically — no body-size cap that can diverge from
    // the route's `DefaultBodyLimit`. (Pre-L5 the body was always buffered with
    // a hard-coded 1 MiB `to_bytes` cap while the route allowed 5 MiB, so any
    // legitimate 1–5 MiB mutation was rejected with a misleading 400; the
    // effective limit was silently 1 MiB.) Both the dev cap here and the route
    // limit now reference the shared `GRAPHQL_MAX_BODY_BYTES` const.
    //
    // This also subsumes MCP-1106 (production short-circuit of the introspection
    // parse): production never even reads the body now, which is strictly
    // cheaper than the prior lazy-evaluation short-circuit.
    let request = if is_production {
        request
    } else {
        let (parts, body) = request.into_parts();
        let body_bytes = match axum::body::to_bytes(body, GRAPHQL_MAX_BODY_BYTES).await {
            Ok(bytes) => bytes,
            Err(e) => {
                tracing::error!("Failed to read request body for CSRF check: {}", e);
                return Err((
                    StatusCode::BAD_REQUEST,
                    "Failed to read request body".to_string(),
                ));
            }
        };

        // L-16: identify introspection by parsing the GraphQL document, not
        // by substring sniffing the raw body. Substring sniff produced false
        // positives (a mutation containing the literal string "__schema"
        // inside a string argument was misclassified as introspection and
        // CSRF-bypassed in dev), so we now parse the JSON envelope and
        // walk the operation/selection tree.
        //
        // Defense-in-depth: introspection bypass only applies in dev anyway.
        // Even with a false-positive sniff, production stayed safe (production
        // doesn't reach this branch at all) — this fix tightens dev so the
        // CSRF gate isn't accidentally weakened by misleading payloads.
        if allow_dev_bypass || is_pure_introspection_request(&String::from_utf8_lossy(&body_bytes)) {
            if allow_dev_bypass {
                tracing::warn!(
                    "⚠️ DANGER: Skipping CSRF for GraphQL request due to ALLOW_DEV_UNSAFE_CSRF_BYPASS=true"
                );
            } else {
                tracing::info!("Allowing GraphQL introspection query without CSRF in development");
            }

            let request = Request::from_parts(parts, Body::from(body_bytes));
            let response = next.run(request).await;
            return Ok(response);
        }

        // Reconstruct request with body for subsequent middleware.
        Request::from_parts(parts, Body::from(body_bytes))
    };

    // For production or non-introspection queries, enforce CSRF
    let cookie_token = cookies.get(CSRF_COOKIE_NAME).map(|c| c.value().to_string());

    let header_token = request
        .headers()
        .get(CSRF_HEADER_NAME)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    prune_grace_cache();

    match (cookie_token, header_token) {
        (Some(cookie), Some(header)) => {
            // MCP-592 (2026-05-12): reject empty cookie/header values
            // before the constant-time compare. Pre-fix two empty
            // strings would match (`ct_eq(&[], &[]) == true`), so a
            // mutation request with cookie="" and header="" — which
            // can happen via a manual `document.cookie="talos_csrf="`
            // overwrite or a buggy proxy stripping the value but
            // preserving the cookie name — silently authenticated.
            // The legitimate generation path always produces a 64-
            // hex-char token, so a non-empty length check is a no-op
            // for real traffic and closes the empty-value bypass.
            // Sibling fix class to MCP-590/591 (empty-env-var auth
            // bypass).
            if cookie.is_empty() || header.is_empty() {
                tracing::warn!("CSRF token empty value rejected");
                return Err((
                    StatusCode::FORBIDDEN,
                    "CSRF token validation failed".to_string(),
                ));
            }
            let matches_current =
                constant_time_eq::constant_time_eq(cookie.as_bytes(), header.as_bytes());
            let matches_grace = !matches_current && get_grace_cache().contains_key(&header);

            if matches_current || matches_grace {
                // Rotate CSRF token after each mutation.
                // Add the token being replaced to the grace cache.
                // MCP-1145: gated insert with cap-hit logging.
                insert_grace_token(cookie);
                cookies.add(build_csrf_cookie(generate_csrf_token()));

                let response = next.run(request).await;
                Ok(response)
            } else {
                tracing::warn!("CSRF token mismatch for GraphQL mutation");
                Err((
                    StatusCode::FORBIDDEN,
                    "CSRF token validation failed".to_string(),
                ))
            }
        }
        (None, _) => {
            tracing::warn!("Missing CSRF cookie for GraphQL mutation");
            Err((
                StatusCode::FORBIDDEN,
                "CSRF token required (cookie missing)".to_string(),
            ))
        }
        (_, None) => {
            tracing::warn!("Missing CSRF header for GraphQL mutation");
            Err((
                StatusCode::FORBIDDEN,
                "CSRF token required (header missing)".to_string(),
            ))
        }
    }
}

/// L-16: detect "this is a pure GraphQL introspection request" without
/// being fooled by user data that happens to contain `__schema`.
///
/// Conservative heuristic — better to require CSRF on a borderline case
/// than to bypass it. We only return `true` when:
///   1. The body parses as JSON,
///   2. The `query` field exists and is a string,
///   3. The query body (after stripping string literals) STILL contains
///      `__schema` or `__type` outside any string context.
///
/// Stripping string literals catches the common false positive
/// (`{ "query": "mutation { setValue(v: \"__schema lookalike\") }" }`).
/// We don't full-parse GraphQL syntax (would pull in async-graphql-parser
/// just for this check); the strip-string-literals approximation handles
/// every realistic dev/test introspection client correctly.
fn is_pure_introspection_request(body: &str) -> bool {
    let Ok(json) = serde_json::from_str::<serde_json::Value>(body) else {
        return false;
    };
    let Some(query) = json.get("query").and_then(|v| v.as_str()) else {
        return false;
    };
    let stripped = strip_graphql_string_literals(query);
    stripped.contains("__schema") || stripped.contains("__type")
}

/// Remove the *contents* of GraphQL string literals (both `"..."` and
/// `"""..."""`) so introspection-marker substring matches against the
/// resulting text only see operation syntax, not user-supplied strings.
fn strip_graphql_string_literals(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let c = bytes[i];
        if c == b'"' {
            // Detect block string """..."""
            let is_block = i + 2 < bytes.len() && bytes[i + 1] == b'"' && bytes[i + 2] == b'"';
            if is_block {
                // skip until terminating triple quote
                i += 3;
                while i + 2 < bytes.len()
                    && !(bytes[i] == b'"' && bytes[i + 1] == b'"' && bytes[i + 2] == b'"')
                {
                    i += 1;
                }
                i = (i + 3).min(bytes.len());
            } else {
                // Standard string literal: skip until unescaped closing quote
                i += 1;
                while i < bytes.len() {
                    if bytes[i] == b'\\' && i + 1 < bytes.len() {
                        i += 2;
                        continue;
                    }
                    if bytes[i] == b'"' {
                        i += 1;
                        break;
                    }
                    i += 1;
                }
            }
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_csrf_token() {
        let token1 = generate_csrf_token();
        let token2 = generate_csrf_token();

        // Tokens should be different
        assert_ne!(token1, token2);

        // Tokens should be hex strings of correct length
        assert_eq!(token1.len(), CSRF_TOKEN_LENGTH * 2); // 2 hex chars per byte
        assert!(token1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn introspection_detected_in_real_introspection_query() {
        let body = r#"{"query":"query { __schema { types { name } } }"}"#;
        assert!(is_pure_introspection_request(body));
    }

    #[test]
    fn introspection_detected_for_typename() {
        let body = r#"{"query":"query { __type(name: \"User\") { name } }"}"#;
        assert!(is_pure_introspection_request(body));
    }

    #[test]
    fn introspection_not_detected_when_marker_in_string_literal() {
        // Pre-fix, this would have matched on the substring `__schema`
        // inside the string argument.
        let body = r#"{"query":"mutation { setValue(v: \"contains __schema lookalike\") { id } }"}"#;
        assert!(!is_pure_introspection_request(body));
    }

    #[test]
    fn introspection_not_detected_for_non_json_body() {
        assert!(!is_pure_introspection_request("not json"));
        assert!(!is_pure_introspection_request(""));
    }

    #[test]
    fn introspection_not_detected_when_query_field_missing() {
        let body = r#"{"variables":{"x":"__schema"}}"#;
        assert!(!is_pure_introspection_request(body));
    }
}

/// MCP-1145 (2026-05-16): grace-cache max-entries cap.
#[cfg(test)]
mod grace_cache_cap_tests {
    use super::*;

    /// Serialise tests that touch the process-global TOKEN_GRACE_CACHE
    /// — parallel test runs would race each other's `cache.clear()`
    /// and pre-fill assertions. Same pattern as the rpc_auth
    /// NONCE_TEST_LOCK in talos-memory.
    static GRACE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn grace_test_lock() -> std::sync::MutexGuard<'static, ()> {
        GRACE_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Below-cap inserts succeed; the cache holds what we put in.
    #[test]
    fn insert_succeeds_below_cap() {
        let _g = grace_test_lock();
        get_grace_cache().clear();
        let token = generate_csrf_token();
        insert_grace_token(token.clone());
        assert!(get_grace_cache().contains_key(&token));
        get_grace_cache().clear();
    }

    /// At-cap inserts are skipped — cache size stays bounded. Pre-fill
    /// to capacity directly via DashMap (bypassing `insert_grace_token`)
    /// for speed, then attempt one more insert via the gated helper
    /// and confirm the cache didn't grow.
    #[test]
    fn at_cap_insert_skipped() {
        let _g = grace_test_lock();
        get_grace_cache().clear();
        let cache = get_grace_cache();

        for i in 0..GRACE_CACHE_MAX_ENTRIES {
            cache.insert(format!("wedge-{}", i), Instant::now());
        }
        assert_eq!(cache.len(), GRACE_CACHE_MAX_ENTRIES);

        let new_token = generate_csrf_token();
        insert_grace_token(new_token.clone());
        assert!(!cache.contains_key(&new_token));
        assert_eq!(cache.len(), GRACE_CACHE_MAX_ENTRIES);

        cache.clear();
    }

    /// After the pruner drops expired entries, fresh inserts resume.
    /// Direct insert with a backdated Instant simulates an expired
    /// entry; the retain (same predicate `prune_grace_cache` runs)
    /// removes it.
    #[test]
    fn expired_entries_drain_via_prune() {
        let _g = grace_test_lock();
        get_grace_cache().clear();
        let cache = get_grace_cache();

        let expired_token = "expired-token".to_string();
        let backdated = Instant::now()
            .checked_sub(Duration::from_secs(60))
            .unwrap_or(Instant::now());
        cache.insert(expired_token.clone(), backdated);

        cache.retain(|_, instant| instant.elapsed() < Duration::from_secs(GRACE_PERIOD_SECONDS));

        assert!(!cache.contains_key(&expired_token));
        cache.clear();
    }
}
