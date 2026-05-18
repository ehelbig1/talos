pub mod mutations;
pub mod queries;

use tower_cookies::{Cookie, Cookies};

/// MCP-1040 (2026-05-15): canonical session-cookie installer.
///
/// Five inline copies of the same 14-line `Cookie::new ... cookies.add`
/// boilerplate previously existed (four in `auth/mutations.rs` and one
/// in `controller/src/main.rs::oauth_callback_handler`). Same drift
/// hazard as MCP-1037 (duplicate validate_payload_size) and MCP-1038
/// (cross-protocol MAX_RUST_CODE_BYTES): a future policy change
/// (extend TTL, change SameSite, add `Domain=`, add `Partitioned`)
/// would need to update N sites and a missed site would silently
/// leave one auth flow at the old policy.
///
/// Settings locked here:
/// - HttpOnly: true (defeats XSS extraction)
/// - Secure: `is_production()` (HTTPS-only in prod; off in dev for
///   localhost compatibility)
/// - SameSite: Strict (defeats CSRF on auth POSTs)
/// - Path: "/" (visible to all routes)
/// - Access TTL: 15 min (short — refreshable via the refresh-cookie path)
/// - Refresh TTL: 7 days (long — but rotates on every refresh)
pub fn set_session_cookies(cookies: &Cookies, access_token: &str, refresh_token: &str) {
    let is_production = talos_config::is_production();

    let mut access_cookie = Cookie::new("talos_access_token", access_token.to_string());
    access_cookie.set_http_only(true);
    access_cookie.set_secure(is_production);
    access_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    access_cookie.set_path("/");
    access_cookie.set_max_age(tower_cookies::cookie::time::Duration::minutes(15));
    cookies.add(access_cookie);

    let mut refresh_cookie = Cookie::new("talos_refresh_token", refresh_token.to_string());
    refresh_cookie.set_http_only(true);
    refresh_cookie.set_secure(is_production);
    refresh_cookie.set_same_site(tower_cookies::cookie::SameSite::Strict);
    refresh_cookie.set_path("/");
    refresh_cookie.set_max_age(tower_cookies::cookie::time::Duration::days(7));
    cookies.add(refresh_cookie);
}

/// MCP-1041 (2026-05-15): canonical session-cookie remover. The
/// inverse of [`set_session_cookies`] — must clear EVERY cookie that
/// setter added, with the SAME path the setter used (`/`). Without
/// the explicit `.path("/")`, `tower_cookies` computes the default
/// path from the request URI (e.g. `/graphql`), and the original
/// `Path=/` cookies persist in the browser after server-side session
/// revocation — confusing failure mode where the user appears
/// logged-in client-side after a successful logout call.
///
/// Two inline copies of this 2-line `remove` pair previously existed
/// in `auth/mutations.rs::logout` and `::logout_all_sessions`. Same
/// drift class as MCP-1040 — if [`set_session_cookies`] ever adds a
/// third cookie (e.g. a separate CSRF token cookie or a Domain=
/// variant), the removal path MUST stay in sync or sessions partially
/// linger.
pub fn clear_session_cookies(cookies: &Cookies) {
    cookies.remove(Cookie::build(("talos_access_token", "")).path("/").build());
    cookies.remove(Cookie::build(("talos_refresh_token", "")).path("/").build());
}
