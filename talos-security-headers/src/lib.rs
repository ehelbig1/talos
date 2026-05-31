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
    // CSP violation reporting — opt-in via CSP_REPORT_URI env var.
    // When set, production CSP violations are reported to the specified endpoint
    // (e.g. an internal /api/csp-report route or a third-party like report-uri.com).
    // We use the modern Reporting-Endpoints + report-to directive rather than the
    // deprecated report-uri.
    //
    // MCP-502 (history): filter empty / invalid CSP_REPORT_URI values so the CSP
    // doesn't reference a `report-to` group that has no valid endpoint.
    //
    // MCP-1108 (2026-05-16): the entire CSP + Reporting-Endpoints
    // computation is now cached in `LazyLock<HeaderValue>` so the
    // per-request cost is one HeaderMap insert (and a clone) per
    // header. Pre-fix every response paid:
    //
    // * `env::var("CSP_REPORT_URI")` — process-wide environ-mutex lock
    //   + `String` allocation (even when the var is unset).
    // * Two `.filter()` predicates (one of which logs a WARN per
    //   request on a misconfigured URI — log spam class same as
    //   MCP-1107).
    // * `talos_config::is_production()` — another env::var call.
    // * `format!("{csp_value}{csp_report_directive}")` allocating a
    //   fresh String on every response when reporting is configured.
    // * `HeaderValue::from_str(&full_csp)` parsing the result.
    //
    // CSP_REPORT_URI is a deploy-time env var — set once at pod-spec
    // time, never mutated at runtime. Same caching contract as
    // MCP-1060 (JWT_REQUIRE_AUD), MCP-1072 (ENABLE_HSTS), MCP-1107
    // (ALLOWED_ORIGIN). Operators changing CSP_REPORT_URI restart
    // the process.
    let (csp_header_value, reporting_endpoints_value) = csp_and_reporting_headers();
    headers.insert(header::CONTENT_SECURITY_POLICY, csp_header_value.clone());
    if let Some(reporting_value) = reporting_endpoints_value {
        headers.insert("Reporting-Endpoints", reporting_value.clone());
    }

    // HTTP Strict Transport Security (HSTS)
    // Forces HTTPS connections for 1 year
    // Auto-enabled in production, can be explicitly enabled/disabled via ENABLE_HSTS env var
    //
    // MCP-1072 (2026-05-15): routed through `bool_env_or_default` so
    // canonical truthy/falsy tokens override the production default
    // uniformly. Pre-fix `.map(|v| v == "true")` was case-sensitive
    // exact-match → `ENABLE_HSTS=0` / `=false` / `=no` in PRODUCTION
    // silently fell through to `is_production()` = true and HSTS
    // stayed enabled, contradicting the comment's "can be explicitly
    // enabled/disabled" promise. Also fixed: `=1` / `=yes` / `=on`
    // / `=TRUE` (capital) now enable HSTS in dev (the canonical
    // truthy set). Sibling drift class to MCP-1060/1064/1065/1066.
    let enable_hsts = talos_config::bool_env_or_default("ENABLE_HSTS", talos_config::is_production());

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

    // Cache-Control: Prevents caching of sensitive data in browsers/proxies
    // no-store: Never store any version of the response
    // no-cache: Must revalidate with server before using cached responses
    // must-revalidate: Strictly follow freshness information
    // private: Response is specific to a single user (not shared caches)
    // max-age=0: Consider responses immediately stale
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store, no-cache, must-revalidate, private, max-age=0"),
    );

    // Vary: Cookie — instructs caches that the response varies per cookie value.
    // Without this, CDNs and intermediate proxies may serve a cached authenticated
    // response to a different user whose request lacks the session cookie.
    headers.insert(header::VARY, HeaderValue::from_static("Cookie"));

    // Pragma: Legacy HTTP/1.0 no-cache directive
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));

    // Expires: Legacy header set to past date to prevent caching
    headers.insert(header::EXPIRES, HeaderValue::from_static("0"));

    // Cross-Origin Opener Policy – needed for the OAuth popup window to be able
    // to access its `closed` property from the opener. "same-origin" isolates
    // the site from others while still allowing the popup communication.
    headers.insert(
        "Cross-Origin-Opener-Policy",
        HeaderValue::from_static("same-origin"),
    );

    // Cross-Origin Resource Policy (CORP)
    // Prevents cross-origin embedding of resources
    headers.insert(
        "Cross-Origin-Resource-Policy",
        HeaderValue::from_static("same-origin"),
    );

    // Cross-Origin Embedder Policy (COEP)
    // Requires explicit CORP/CORS for cross-origin resources
    headers.insert(
        "Cross-Origin-Embedder-Policy",
        HeaderValue::from_static("require-corp"),
    );

    // X-DNS-Prefetch-Control
    // Prevents DNS prefetching which can leak user browsing information
    headers.insert("X-DNS-Prefetch-Control", HeaderValue::from_static("off"));

    // X-Download-Options (Internet Explorer/Edge)
    // Prevents IE from executing downloads in the site context
    headers.insert("X-Download-Options", HeaderValue::from_static("noopen"));

    Ok(response)
}

/// MCP-1108: cache the CSP + Reporting-Endpoints header pair once
/// per process. See the call-site comment in `add_security_headers`
/// for the per-request cost saved.
fn csp_and_reporting_headers() -> &'static (HeaderValue, Option<HeaderValue>) {
    static CACHED: std::sync::LazyLock<(HeaderValue, Option<HeaderValue>)> =
        std::sync::LazyLock::new(|| {
            let csp_report_endpoint = std::env::var("CSP_REPORT_URI")
                .ok()
                .filter(|s| !s.is_empty())
                .filter(|s| {
                    let ok = s.starts_with("https://")
                        || s.starts_with("http://")
                        || s.starts_with('/');
                    if !ok {
                        tracing::warn!(
                            "CSP_REPORT_URI does not start with http://, https://, or '/' — \
                             ignoring. CSP violation reporting will be disabled."
                        );
                    }
                    ok
                });

            let csp_value: &'static str = if talos_config::is_production() {
                // STRICT CSP for production - NO unsafe-inline, unsafe-eval, or data: URIs.
                "default-src 'self'; \
                 script-src 'self'; \
                 style-src 'self'; \
                 img-src 'self' https:; \
                 font-src 'self'; \
                 connect-src 'self' wss:; \
                 object-src 'none'; \
                 frame-ancestors 'none'; \
                 base-uri 'self'; \
                 form-action 'self'"
            } else {
                // More relaxed CSP for development (allows GraphiQL, hot reload, etc.).
                "default-src 'self'; \
                 script-src 'self' 'unsafe-inline' 'unsafe-eval'; \
                 style-src 'self' 'unsafe-inline'; \
                 img-src 'self' data: https:; \
                 font-src 'self' data:; \
                 connect-src 'self' ws: wss:; \
                 object-src 'none'; \
                 frame-ancestors 'none'; \
                 base-uri 'self'; \
                 form-action 'self'"
            };

            let csp_header_value: HeaderValue = match csp_report_endpoint.as_deref() {
                Some(_) => {
                    let full = format!("{csp_value}; report-to csp-endpoint");
                    HeaderValue::from_str(&full)
                        .unwrap_or_else(|_| HeaderValue::from_static(csp_value))
                }
                None => HeaderValue::from_static(csp_value),
            };

            let reporting_value: Option<HeaderValue> = csp_report_endpoint.as_deref().and_then(|uri| {
                HeaderValue::from_str(&format!("csp-endpoint=\"{uri}\"")).ok()
            });

            (csp_header_value, reporting_value)
        });
    &CACHED
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
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap();

        let headers = response.headers();

        // Check CSP — incl. explicit object-src 'none' (parity with the SPA's
        // nginx CSP; <object>/<embed> must not fall back to default-src 'self').
        assert!(headers.contains_key(header::CONTENT_SECURITY_POLICY));
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(
            csp.contains("object-src 'none'"),
            "CSP must explicitly deny plugin objects: {csp}"
        );
        assert!(csp.contains("frame-ancestors 'none'"), "CSP must deny framing: {csp}");

        // Check X-Frame-Options
        assert_eq!(headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");

        // Check X-Content-Type-Options
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff"
        );

        // Check Referrer-Policy
        assert!(headers.contains_key(header::REFERRER_POLICY));

        // Check Cache-Control
        let cache_control = headers
            .get(header::CACHE_CONTROL)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(cache_control.contains("no-store"));
        assert!(cache_control.contains("no-cache"));
        assert!(cache_control.contains("private"));

        // Check Pragma
        assert_eq!(headers.get(header::PRAGMA).unwrap(), "no-cache");

        // Check Expires
        assert_eq!(headers.get(header::EXPIRES).unwrap(), "0");

        // Check Cross-Origin-Resource-Policy
        assert_eq!(
            headers.get("Cross-Origin-Resource-Policy").unwrap(),
            "same-origin"
        );

        // Check Cross-Origin-Embedder-Policy
        assert_eq!(
            headers.get("Cross-Origin-Embedder-Policy").unwrap(),
            "require-corp"
        );

        // Check X-DNS-Prefetch-Control
        assert_eq!(headers.get("X-DNS-Prefetch-Control").unwrap(), "off");

        // Check X-Download-Options
        assert_eq!(headers.get("X-Download-Options").unwrap(), "noopen");
    }
}
