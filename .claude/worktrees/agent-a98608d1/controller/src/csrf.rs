// CSRF utilities are currently not invoked directly in the test suite.
// Suppress dead‑code warnings for this module.
#![allow(dead_code)]
use axum::{
    body::Body,
    http::{Method, Request, Response, StatusCode},
    middleware::Next,
};
use rand::Rng;
use tower_cookies::{Cookie, Cookies};

const CSRF_TOKEN_LENGTH: usize = 32;
const CSRF_COOKIE_NAME: &str = "talos_csrf_token";
const CSRF_HEADER_NAME: &str = "X-CSRF-Token";

/// Generate a cryptographically secure random CSRF token
pub fn generate_csrf_token() -> String {
    let mut rng = rand::thread_rng();
    let token_bytes: Vec<u8> = (0..CSRF_TOKEN_LENGTH).map(|_| rng.gen()).collect();
    hex::encode(token_bytes)
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
            let token = generate_csrf_token();
            let mut cookie = Cookie::new(CSRF_COOKIE_NAME, token.clone());
            cookie.set_http_only(false); // Must be readable by JavaScript
                                         // Secure flag must only be set over HTTPS; in HTTP dev environments browsers
                                         // silently discard Secure cookies, which breaks the CSRF flow entirely.
            let is_production = std::env::var("RUST_ENV").unwrap_or_default() == "production";
            cookie.set_secure(is_production);
            cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            cookie.set_path("/");
            cookies.add(cookie);
        }

        let response = next.run(request).await;
        return Ok(response);
    }

    // Skip CSRF for health and metrics endpoints (no mutations)
    if path == "/health" || path == "/metrics" {
        let response = next.run(request).await;
        return Ok(response);
    }

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

    match (cookie_token, header_token) {
        (Some(cookie), Some(header)) if cookie == header => {
            // CSRF tokens match - allow request

            let response = next.run(request).await;
            Ok(response)
        }
        (Some(_), Some(_)) => {
            // CSRF tokens don't match
            tracing::warn!("CSRF token mismatch for {} {}", method, path);
            Err((
                StatusCode::FORBIDDEN,
                "CSRF token validation failed".to_string(),
            ))
        }
        (None, _) => {
            // No CSRF cookie
            tracing::warn!("Missing CSRF cookie for {} {}", method, path);
            Err((
                StatusCode::FORBIDDEN,
                "CSRF token required (cookie missing)".to_string(),
            ))
        }
        (_, None) => {
            // No CSRF header
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
            let token = generate_csrf_token();
            let mut cookie = Cookie::new(CSRF_COOKIE_NAME, token.clone());
            cookie.set_http_only(false); // GraphiQL needs to read this
            let is_production = std::env::var("RUST_ENV").unwrap_or_default() == "production";
            cookie.set_secure(is_production);
            cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
            cookie.set_path("/");
            cookies.add(cookie);
        }

        let response = next.run(request).await;
        return Ok(response);
    }

    let is_production = std::env::var("RUST_ENV").unwrap_or_default() == "production";
    let allow_dev_bypass = !is_production
        && std::env::var("ALLOW_DEV_UNSAFE_CSRF_BYPASS")
            .map(|v| v == "true")
            .unwrap_or(false);

    // Get request body bytes to check if it's an introspection query
    let (parts, body) = request.into_parts();
    let body_bytes = match axum::body::to_bytes(body, 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(e) => {
            tracing::error!("Failed to read request body for CSRF check: {}", e);
            return Err((
                StatusCode::BAD_REQUEST,
                "Failed to read request body".to_string(),
            ));
        }
    };

    let body_str = String::from_utf8_lossy(&body_bytes);
    let is_introspection = body_str.contains("__schema") || body_str.contains("__type");

    if allow_dev_bypass {
        if is_introspection {
            tracing::warn!(
                "⚠️ DANGER: Skipping CSRF for GraphQL introspection request due to ALLOW_DEV_UNSAFE_CSRF_BYPASS=true"
            );

            let request = Request::from_parts(parts, Body::from(body_bytes));
            let response = next.run(request).await;
            return Ok(response);
        } else {
            tracing::warn!(
                "⚠️ ALLOW_DEV_UNSAFE_CSRF_BYPASS=true is set, but CSRF is still enforced for non-introspection queries to prevent accidental bypass"
            );
        }
    } else if !is_production && is_introspection {
        // Require explicit header for introspection bypass in dev to prevent implicit bypasses
        if parts
            .headers
            .get("x-dev-bypass")
            .and_then(|v| v.to_str().ok())
            == Some("true")
        {
            let request = Request::from_parts(parts, Body::from(body_bytes));
            let response = next.run(request).await;
            return Ok(response);
        }
    }

    // Reconstruct request with body for subsequent middleware
    let request = Request::from_parts(parts, Body::from(body_bytes));

    // For production or non-introspection queries, enforce CSRF
    let cookie_token = cookies.get(CSRF_COOKIE_NAME).map(|c| c.value().to_string());

    let header_token = request
        .headers()
        .get(CSRF_HEADER_NAME)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    match (cookie_token, header_token) {
        (Some(cookie), Some(header)) if cookie == header => {
            let response = next.run(request).await;
            Ok(response)
        }
        (Some(_), Some(_)) => {
            tracing::warn!("CSRF token mismatch for GraphQL mutation");
            Err((
                StatusCode::FORBIDDEN,
                "CSRF token validation failed".to_string(),
            ))
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
}
