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

/// S1 (login-CSRF defense, 2026-06-23): cookie name carrying the
/// browser-session binding for the OAuth `state` nonce. Set at login
/// (REST `/auth/oauth/{provider}/login` AND the GraphQL `oauthLoginUrl`
/// query), consumed + cleared on the REST callback. Centralised here so
/// the REST and GraphQL login paths set byte-identical cookie attributes
/// — same drift hazard MCP-1040 closed for the session cookies.
pub const OAUTH_SESSION_BINDING_COOKIE: &str = "talos_oauth_session";

/// Install the OAuth session-binding cookie (S1).
///
/// `get_authorization_url` persists only the SHA-256 of `nonce`; the
/// plaintext lives only in this cookie and is required to match on the
/// callback. NEVER log `nonce`.
///
/// Settings locked here:
/// - HttpOnly: true (defeats XSS extraction)
/// - Secure: `is_production()` (HTTPS-only in prod; off in dev)
/// - SameSite: **Lax** — the provider redirect back to the callback is a
///   top-level cross-site navigation; `Strict` would withhold the cookie
///   and break every login. Lax still blocks the cross-site POST/iframe
///   vectors. (This is the one place auth cookies must NOT be Strict.)
/// - Path: "/" (callback lives under a different path than login)
/// - TTL: 10 min (matches the state-token freshness window)
pub fn set_oauth_session_binding_cookie(cookies: &Cookies, nonce: &str) {
    let mut binding = Cookie::new(OAUTH_SESSION_BINDING_COOKIE, nonce.to_string());
    binding.set_http_only(true);
    binding.set_secure(talos_config::is_production());
    binding.set_same_site(tower_cookies::cookie::SameSite::Lax);
    binding.set_path("/");
    binding.set_max_age(tower_cookies::cookie::time::Duration::minutes(10));
    cookies.add(binding);
}

/// Clear the OAuth session-binding cookie (S1). Single-use — removed on
/// the callback whether or not validation succeeds. Same `Path=/` the
/// setter used (see [`clear_session_cookies`] for the path-mismatch
/// failure mode).
pub fn clear_oauth_session_binding_cookie(cookies: &Cookies) {
    cookies.remove(
        Cookie::build((OAUTH_SESSION_BINDING_COOKIE, ""))
            .path("/")
            .build(),
    );
}

#[cfg(test)]
mod cookie_security_tests {
    use super::{clear_session_cookies, set_session_cookies, Cookies};
    use tower_cookies::cookie::SameSite;

    /// CLAUDE.md security rule: auth cookies MUST be HttpOnly + Secure +
    /// SameSite=Strict. A regression that drops any of these is a real hole
    /// (HttpOnly off → XSS can read the session token; Secure off in prod →
    /// MITM over HTTP; SameSite≠Strict → CSRF surface). This pins the setter
    /// so such a regression fails at PR time instead of shipping silently.
    #[test]
    fn session_cookies_carry_the_security_flags() {
        let cookies = Cookies::default();
        set_session_cookies(&cookies, "access-tok-value", "refresh-tok-value");

        let list = cookies.list();
        let access = list
            .iter()
            .find(|c| c.name() == "talos_access_token")
            .expect("access-token cookie must be set");
        let refresh = list
            .iter()
            .find(|c| c.name() == "talos_refresh_token")
            .expect("refresh-token cookie must be set");

        for (label, c) in [("access", access), ("refresh", refresh)] {
            assert_eq!(c.http_only(), Some(true), "{label} cookie must be HttpOnly");
            assert_eq!(
                c.same_site(),
                Some(SameSite::Strict),
                "{label} cookie must be SameSite=Strict"
            );
            assert_eq!(c.path(), Some("/"), "{label} cookie must be Path=/");
            assert!(
                c.max_age().is_some(),
                "{label} cookie must have a bounded Max-Age"
            );
            // Secure is tied to the production flag (false in dev so localhost
            // http works); assert the tie rather than a fixed value.
            assert_eq!(
                c.secure(),
                Some(talos_config::is_production()),
                "{label} cookie Secure flag must follow is_production()"
            );
        }
    }

    /// MCP-1041 logout-completeness: [`clear_session_cookies`] must remove
    /// EVERY cookie [`set_session_cookies`] adds. The documented drift hazard
    /// is "if the setter ever adds a third cookie, the removal path MUST stay
    /// in sync or sessions partially linger" — a real hole (the user appears
    /// logged-in client-side after a successful server-side logout). This
    /// drives set→clear and asserts no live auth cookie survives, so a setter
    /// that gains a cookie without a matching remover fails at PR time.
    #[test]
    fn clear_removes_every_cookie_the_setter_adds() {
        let cookies = Cookies::default();
        set_session_cookies(&cookies, "access-tok-value", "refresh-tok-value");
        assert!(
            !cookies.list().is_empty(),
            "precondition: setter must add cookies"
        );

        clear_session_cookies(&cookies);

        // tower_cookies' delta-`remove` drops a delta-added cookie entirely;
        // any auth cookie left with a live (non-empty) value means the remover
        // did not clear what the setter added — set/clear drifted.
        let survivors: Vec<String> = cookies
            .list()
            .iter()
            .filter(|c| c.name().starts_with("talos_") && !c.value().is_empty())
            .map(|c| c.name().to_string())
            .collect();
        assert!(
            survivors.is_empty(),
            "clear_session_cookies left auth cookies behind (set/clear drift, MCP-1041): {survivors:?}"
        );
    }
}
