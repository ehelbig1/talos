use axum::{
    body::Body,
    http::{header, HeaderValue, Request, Response},
    middleware::Next,
};

/// Middleware to add security headers to all responses
pub async fn add_security_headers(
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, (axum::http::StatusCode, String)> {
    let mut response = next.run(request).await;

    let headers = response.headers_mut();

    // Content Security Policy (CSP)
    // This prevents XSS attacks by controlling what resources can be loaded
    let csp_value = if std::env::var("RUST_ENV").unwrap_or_default() == "production" {
        // STRICT CSP for production - NO unsafe-inline, unsafe-eval, or data: URIs
        // data: in img-src/font-src allows SVG-based XSS vectors; removed for production.
        // wss: added to connect-src to allow secure WebSocket connections.
        "default-src 'self'; \
         script-src 'self'; \
         style-src 'self'; \
         img-src 'self' https:; \
         font-src 'self'; \
         connect-src 'self' wss:; \
         frame-ancestors 'none'; \
         base-uri 'self'; \
         form-action 'self'"
    } else {
        // More relaxed CSP for development (allows GraphiQL, hot reload, etc.)
        "default-src 'self'; \
         script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
         style-src 'self' 'unsafe-inline'; \
         img-src 'self' data: https:; \
         font-src 'self' data:; \
         connect-src 'self' ws: wss:; \
         frame-ancestors 'none'; \
         base-uri 'self'; \
         form-action 'self'"
    };

    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(csp_value),
    );

    // HTTP Strict Transport Security (HSTS)
    // Forces HTTPS connections for 1 year
    // Auto-enabled in production, can be explicitly enabled/disabled via ENABLE_HSTS env var
    let enable_hsts = std::env::var("ENABLE_HSTS")
        .map(|v| v == "true")
        .unwrap_or_else(|_| std::env::var("RUST_ENV").unwrap_or_default() == "production");

    if enable_hsts {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains; preload"),
        );
    }

    // X-Frame-Options: Prevents clickjacking
    // 'DENY' means the page cannot be displayed in a frame
    headers.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));

    // X-Content-Type-Options: Prevents MIME type sniffing
    // Forces browser to respect the Content-Type header
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    // X-XSS-Protection: Legacy XSS protection (for older browsers)
    // Modern browsers use CSP, but this helps older browsers
    headers.insert(
        "X-XSS-Protection",
        HeaderValue::from_static("1; mode=block"),
    );

    // Referrer-Policy: Controls how much referrer information is sent
    // 'strict-origin-when-cross-origin' provides good balance
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("strict-origin-when-cross-origin"),
    );

    // Permissions-Policy (formerly Feature-Policy)
    // Restricts which browser features can be used
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static(
            "geolocation=(), \
             microphone=(), \
             camera=(), \
             payment=(), \
             usb=(), \
             magnetometer=(), \
             gyroscope=(), \
             accelerometer=()",
        ),
    );

    // X-Permitted-Cross-Domain-Policies: Adobe Flash/PDF cross-domain policy
    // 'none' blocks all cross-domain requests
    headers.insert(
        "X-Permitted-Cross-Domain-Policies",
        HeaderValue::from_static("none"),
    );

    // Cross-Origin Opener Policy – needed for the OAuth popup window to be able
    // to access its `closed` property from the opener. "same-origin" isolates
    // the site from others while still allowing the popup communication.
    headers.insert(
        "Cross-Origin-Opener-Policy",
        HeaderValue::from_static("same-origin"),
    );

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request, middleware};
    use tower::ServiceExt;

    #[tokio::test]
    async fn test_security_headers_added() {
        use axum::Router;

        let app = Router::new()
            .route("/", axum::routing::get(|| async { "OK" }))
            .layer(middleware::from_fn(add_security_headers));

        let response = app
            .oneshot(
                Request::builder()
                    .uri("/")
                    .body(Body::empty())
                    .expect("Failed to build test request"),
            )
            .await
            .unwrap();

        let headers = response.headers();

        // Check CSP
        assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));

        // Check X-Frame-Options
        assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");

        // Check X-Content-Type-Options
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );

        // Check Referrer-Policy
        assert!(headers.contains_key(header::REFERRER_POLICY));
    }
}
