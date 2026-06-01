use axum::{
    extract::{Json, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
pub struct PublishTemplateReq {
    pub name: String,
    pub category: String,
    pub description: String,
    pub config_schema: serde_json::Value,
    pub oci_url: String,
    pub code_template: Option<String>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub allowed_secrets: Vec<String>,
    #[serde(default)]
    pub requires_approval_for: Vec<String>,
}

#[derive(Serialize)]
pub struct PublishTemplateResp {
    pub success: bool,
    pub message: String,
}

pub fn registry_router() -> Router<Arc<super::ModuleRegistry>> {
    Router::new().route("/publish", post(publish_template))
}

/// Env var holding the shared bearer token required to call
/// `POST /api/registry/publish`.
///
/// M-8 (talos-registry review): pre-fix this endpoint was mounted in
/// production with no auth middleware, so anyone with network reach to
/// the controller could insert globally-visible catalog rows
/// (`kind='catalog', user_id=NULL`) — hijack catalog names via
/// ON CONFLICT, inject misleading metadata (allowed_hosts/secrets),
/// point oci_url at attacker registries.
///
/// The fix is a shared bearer-token gate on the route itself rather than
/// the surrounding `rest_auth_middleware` because the only legitimate
/// caller is the operator-run `scripts/util/talos-publish.py` (NOT a
/// cookie-bearing browser session), and CI publishes need an
/// authentication mechanism that survives an unattended environment.
///
/// Production: set `REGISTRY_PUBLISH_TOKEN` to a high-entropy random
/// string (>= 32 chars). publish.py sends `Authorization: Bearer
/// $TOKEN`. Unset means the endpoint refuses ALL POSTs in production.
/// Dev: unset env disables the gate (dev workflows use the endpoint
/// without ceremony).
const PUBLISH_TOKEN_ENV: &str = "REGISTRY_PUBLISH_TOKEN";

/// Constant-time-compare two byte strings for the token check. Routes
/// through `subtle::ConstantTimeEq` so attacker can't time-side-channel
/// the matching prefix length. Length mismatch returns false without
/// touching the comparison loop, preserving the constant-time property
/// for the equal-length case (the only case that matters).
fn tokens_match(provided: &str, expected: &str) -> bool {
    use subtle::ConstantTimeEq;
    if provided.len() != expected.len() {
        return false;
    }
    provided.as_bytes().ct_eq(expected.as_bytes()).into()
}

/// Extract bearer token from `Authorization: Bearer <token>` header.
fn bearer_from_headers(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

/// Returns Ok(()) if the request is authorized, Err(response) otherwise.
fn check_publish_authorized(
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<PublishTemplateResp>)> {
    // MCP-590 (2026-05-12): treat empty-string env as "no token
    // configured". Pre-fix `REGISTRY_PUBLISH_TOKEN=""` produced
    // `configured = Some("")`, which then matched any request with
    // a missing or empty bearer (length-zero ct_eq returns true
    // vacuously) — bypassing the production fail-closed branch.
    // Empty `expected` is operationally meaningless (no entropy);
    // route it to the unset branch so production correctly returns
    // 503 instead of accepting unauthenticated POSTs.
    let configured = std::env::var(PUBLISH_TOKEN_ENV)
        .ok()
        .filter(|v| !v.is_empty());
    match (configured.as_deref(), talos_config::is_production()) {
        (Some(expected), _) => {
            // Token configured — require a matching bearer in every request,
            // dev and prod alike.
            let provided = bearer_from_headers(headers).unwrap_or("");
            if !tokens_match(provided, expected) {
                tracing::warn!(
                    target: "talos_registry",
                    event_kind = "publish_unauthorized",
                    "Rejected /api/registry/publish: bearer token missing or did not match"
                );
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(PublishTemplateResp {
                        success: false,
                        message: "Unauthorized".to_string(),
                    }),
                ));
            }
            Ok(())
        }
        (None, true) => {
            // Production without a configured token = bail. Operator MUST
            // explicitly opt in to publish capability.
            tracing::warn!(
                target: "talos_registry",
                event_kind = "publish_no_token",
                "Rejected /api/registry/publish in production: REGISTRY_PUBLISH_TOKEN not set"
            );
            Err((
                StatusCode::SERVICE_UNAVAILABLE,
                Json(PublishTemplateResp {
                    success: false,
                    message:
                        "Catalog publish endpoint disabled — set REGISTRY_PUBLISH_TOKEN to enable"
                            .to_string(),
                }),
            ))
        }
        (None, false) => {
            // Dev: no token configured = open. Local workflows iterate without
            // the ceremony of setting an env var.
            Ok(())
        }
    }
}

async fn publish_template(
    State(registry): State<Arc<super::ModuleRegistry>>,
    headers: HeaderMap,
    Json(payload): Json<PublishTemplateReq>,
) -> impl IntoResponse {
    // M-8: bearer-token gate. See `check_publish_authorized` for policy.
    if let Err(resp) = check_publish_authorized(&headers) {
        return resp;
    }

    // Validate allowed_hosts at the API boundary
    if let Err(msg) = super::validate_allowed_hosts(&payload.allowed_hosts) {
        return (
            StatusCode::BAD_REQUEST,
            Json(PublishTemplateResp {
                success: false,
                message: msg,
            }),
        );
    }
    // MCP-1124: validate allowed_secrets at the API boundary too.
    if let Err(msg) = super::validate_allowed_secrets(&payload.allowed_secrets) {
        return (
            StatusCode::BAD_REQUEST,
            Json(PublishTemplateResp {
                success: false,
                message: msg,
            }),
        );
    }

    // Phase 5: write the unified `modules` table directly with `kind =
    // 'catalog'`. ON CONFLICT (name) WHERE user_id IS NULL matches the
    // `modules_catalog_name_uniq` partial unique index, giving catalog
    // entries a stable UUID across re-publishes. `code_template` maps to
    // `source_code`; legacy `*_id` aliases remain NULL because brand-new
    // catalog entries never existed in the pre-Phase-1 tables.
    let result = sqlx::query(
        "INSERT INTO modules ( \
             user_id, name, kind, category, description, config_schema, source_code, oci_url, \
             allowed_hosts, allowed_secrets, requires_approval_for, \
             language, created_at, updated_at \
         ) \
         VALUES ( \
             NULL, $1, 'catalog', $2, $3, $4, $5, $6, \
             $7, $8, $9, \
             'rust', NOW(), NOW() \
         ) \
         ON CONFLICT (name) WHERE user_id IS NULL DO UPDATE SET \
             category               = EXCLUDED.category, \
             description            = EXCLUDED.description, \
             source_code            = EXCLUDED.source_code, \
             config_schema          = EXCLUDED.config_schema, \
             oci_url                = EXCLUDED.oci_url, \
             allowed_hosts          = EXCLUDED.allowed_hosts, \
             allowed_secrets        = EXCLUDED.allowed_secrets, \
             requires_approval_for  = EXCLUDED.requires_approval_for, \
             updated_at             = NOW()",
    )
    .bind(&payload.name)
    .bind(&payload.category)
    .bind(&payload.description)
    .bind(&payload.config_schema)
    .bind(payload.code_template.unwrap_or_else(|| "".to_string()))
    .bind(&payload.oci_url)
    .bind(&payload.allowed_hosts)
    .bind(&payload.allowed_secrets)
    .bind(&payload.requires_approval_for)
    .execute(&registry.db_pool)
    .await;

    match result {
        Ok(_) => (
            StatusCode::OK,
            Json(PublishTemplateResp {
                success: true,
                message: format!("Template '{}' published successfully.", payload.name),
            }),
        ),
        Err(e) => {
            // M-9: sqlx errors carry schema names, constraint names, and
            // query fragments — leaking them via the API response would
            // give an attacker an interactive schema-introspection
            // oracle (and pre-M-8 the endpoint was unauthenticated, so
            // any reachable attacker could exercise it freely). Log the
            // full error server-side; return a generic message.
            tracing::error!(
                target: "talos_registry",
                event_kind = "publish_template_failed",
                template_name = %payload.name,
                error = %e,
                "Database error while publishing catalog template"
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(PublishTemplateResp {
                    success: false,
                    message: "Failed to publish template (see server logs)".to_string(),
                }),
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers_with_bearer(token: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        h
    }

    /// Serialize the three tests that mutate `PUBLISH_TOKEN_ENV`.
    /// Cargo runs unit tests in parallel by default, so concurrent
    /// `set_var` / `remove_var` on the same env var produces flakes
    /// (one test's `remove_var` can land between another test's
    /// `set_var` and its assertion). Tests that touch this env var
    /// MUST take the lock for the duration of their setup + assert
    /// + teardown.
    fn env_var_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        // Recover from poisoned mutex (a panic during a previous test
        // run shouldn't break subsequent tests' setup) — the inner ()
        // value carries no state.
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn tokens_match_constant_time() {
        assert!(tokens_match("abc", "abc"));
        assert!(!tokens_match("abc", "abd"));
        assert!(!tokens_match("abc", "abcd"));
        assert!(!tokens_match("", "x"));
        assert!(tokens_match("", ""));
    }

    #[test]
    fn bearer_extraction_strips_prefix() {
        let h = headers_with_bearer("hello-token");
        assert_eq!(bearer_from_headers(&h), Some("hello-token"));
    }

    #[test]
    fn bearer_extraction_rejects_missing_header() {
        assert_eq!(bearer_from_headers(&HeaderMap::new()), None);
    }

    #[test]
    fn bearer_extraction_rejects_non_bearer_scheme() {
        let mut h = HeaderMap::new();
        h.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_static("Basic dXNlcjpwYXNz"),
        );
        assert_eq!(bearer_from_headers(&h), None);
    }

    #[test]
    fn bearer_extraction_rejects_empty_token() {
        let h = headers_with_bearer("");
        assert_eq!(bearer_from_headers(&h), None);
    }

    #[test]
    fn unauthorized_when_token_configured_but_missing() {
        let _g = env_var_lock();
        std::env::set_var(PUBLISH_TOKEN_ENV, "expected-token");
        let h = HeaderMap::new();
        let res = check_publish_authorized(&h);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().0, StatusCode::UNAUTHORIZED);
        std::env::remove_var(PUBLISH_TOKEN_ENV);
    }

    #[test]
    fn unauthorized_when_token_does_not_match() {
        let _g = env_var_lock();
        std::env::set_var(PUBLISH_TOKEN_ENV, "expected-token");
        let h = headers_with_bearer("wrong-token");
        let res = check_publish_authorized(&h);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().0, StatusCode::UNAUTHORIZED);
        std::env::remove_var(PUBLISH_TOKEN_ENV);
    }

    #[test]
    fn authorized_when_token_matches() {
        let _g = env_var_lock();
        std::env::set_var(PUBLISH_TOKEN_ENV, "expected-token");
        let h = headers_with_bearer("expected-token");
        assert!(check_publish_authorized(&h).is_ok());
        std::env::remove_var(PUBLISH_TOKEN_ENV);
    }

    /// MCP-590: an empty-string env var must NOT authenticate any
    /// request with an empty/missing bearer. Pre-fix, `tokens_match("",
    /// "")` returned true (vacuous length-zero ct_eq) and the
    /// production path accepted unauthenticated POSTs to
    /// `/api/registry/publish`. Treat empty env as "no token
    /// configured", which routes through the unset branch.
    #[test]
    fn empty_env_var_does_not_open_endpoint_in_production() {
        let _g = env_var_lock();
        // Force production mode for this assert; reset afterwards to
        // avoid leaking the env into sibling tests.
        let prev_env = std::env::var("RUST_ENV").ok();
        std::env::set_var(PUBLISH_TOKEN_ENV, "");
        std::env::set_var("RUST_ENV", "production");
        let res = check_publish_authorized(&HeaderMap::new());
        // Cleanup BEFORE asserting so a failure doesn't leak the env.
        std::env::remove_var(PUBLISH_TOKEN_ENV);
        match prev_env {
            Some(v) => std::env::set_var("RUST_ENV", v),
            None => std::env::remove_var("RUST_ENV"),
        }
        // Production with empty env should hit the "no token
        // configured" branch and return 503.
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);
    }
}
