//! Browser binding for integration CONNECT flows — the account-link twin of the
//! login flow's S1 binding ([`crate::generate_oauth_session_binding`]).
//!
//! A connect `state` row binds the Talos `user_id` that STARTED the flow, and the
//! callback is a cross-site redirect that carries no session (the auth cookies
//! are `SameSite=Strict`). So until 2026-09-25 nothing proved that the browser
//! completing consent was the browser that started it: an attacker could start a
//! connect under their OWN account, hand the victim the authorize URL, and when
//! the victim consented the victim's refresh token was stored under the
//! attacker's `user_id` (gmail, google-calendar, gcp, slack, atlassian), and the
//! same shape reached the GitHub App install flow.
//!
//! The fix is the login flow's: a per-browser nonce in an `HttpOnly`
//! `SameSite=Lax` cookie, with only its SHA-256 stored on the state row, and the
//! callback required to present a cookie whose hash matches. `Lax`, not
//! `Strict`: the provider's redirect back is a top-level cross-site navigation,
//! which `Strict` would strip.
//!
//! **One cookie, reused.** The connect handler REUSES the browser's existing
//! binding when its cookie carries a well-formed one, so two connects started in
//! two tabs of one browser do not invalidate each other; it is the login flow's
//! cookie name that is single-use, not this one. The value alone is worth
//! nothing to an attacker: it matches only state rows this browser started.

use http::header::{COOKIE, SET_COOKIE};
use http::{HeaderMap, HeaderValue};
use uuid::Uuid;

use crate::{constant_time_eq, hash_oauth_session_binding};

/// The connect-binding cookie. Distinct from the login flow's
/// `talos_oauth_session`, which the login callback CLEARS on every use — sharing
/// it would let a login in one tab break a connect in another.
pub const CONNECT_BINDING_COOKIE: &str = "talos_oauth_connect";

/// Cookie lifetime; matches the state row's 10-minute freshness window.
pub const CONNECT_BINDING_MAX_AGE_SECS: i64 = 600;

/// A per-browser binding nonce for an integration connect flow.
///
/// Holds the PLAINTEXT nonce, so `Debug` is redacted and nothing here logs it.
pub struct BrowserBinding {
    nonce: String,
}

impl std::fmt::Debug for BrowserBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("BrowserBinding(<redacted>)")
    }
}

impl BrowserBinding {
    /// The browser's existing binding when its request carries exactly one
    /// well-formed connect cookie; otherwise a fresh one.
    pub fn for_request(headers: &HeaderMap) -> Self {
        match presented_connect_binding(headers) {
            Some(nonce) => Self { nonce },
            None => Self::fresh(),
        }
    }

    /// A new binding: ~244 bits from two v4 UUIDs, hex — the login flow's shape.
    pub fn fresh() -> Self {
        Self {
            nonce: format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple()),
        }
    }

    /// SHA-256 hex of the nonce — the only form that is ever persisted.
    pub fn hash(&self) -> String {
        hash_oauth_session_binding(&self.nonce)
    }

    /// The `Set-Cookie` value the connect response must carry. `Secure` follows
    /// `is_production()`, exactly as the login binding cookie does.
    pub fn set_cookie_header(&self) -> HeaderValue {
        // The nonce is hex and the attributes are literals, so this cannot fail;
        // a failure would mean the nonce shape changed, which the unit tests pin.
        HeaderValue::from_str(&self.set_cookie_string(talos_config::is_production()))
            .expect("connect-binding cookie is ASCII by construction")
    }

    /// `(SET_COOKIE, value)` — a ready-to-use axum response-header pair.
    pub fn set_cookie_pair(&self) -> (http::HeaderName, HeaderValue) {
        (SET_COOKIE, self.set_cookie_header())
    }

    fn set_cookie_string(&self, secure: bool) -> String {
        format!(
            "{CONNECT_BINDING_COOKIE}={}; Path=/; Max-Age={CONNECT_BINDING_MAX_AGE_SECS}; HttpOnly; SameSite=Lax{}",
            self.nonce,
            if secure { "; Secure" } else { "" }
        )
    }

    #[cfg(test)]
    pub(crate) fn nonce_for_test(&self) -> &str {
        &self.nonce
    }
}

/// The connect-binding nonce a callback request presents, if exactly one
/// well-formed value is present.
///
/// Two DIFFERENT values for the name (a cookie set on a narrower path, or
/// tossed from a sibling host) is ambiguous, and an ambiguous binding is no
/// binding: `None`, which the consume refuses.
pub fn presented_connect_binding(headers: &HeaderMap) -> Option<String> {
    let mut found: Option<String> = None;
    for raw in headers.get_all(COOKIE) {
        let Ok(line) = raw.to_str() else { continue };
        for pair in line.split(';') {
            let Some((name, value)) = pair.trim().split_once('=') else {
                continue;
            };
            if name.trim() != CONNECT_BINDING_COOKIE {
                continue;
            }
            let value = value.trim();
            if !is_well_formed_nonce(value) {
                return None;
            }
            match &found {
                Some(prev) if prev != value => return None,
                _ => found = Some(value.to_string()),
            }
        }
    }
    found
}

/// 64 lowercase hex chars — exactly what [`BrowserBinding::fresh`] mints.
fn is_well_formed_nonce(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// The verdict of comparing a consumed state row's binding against the cookie
/// the callback presented. Only [`BindingCheck::Matches`] admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingCheck {
    /// The cookie's hash equals the row's.
    Matches,
    /// The row carries no binding — a row written before this rule, or by a
    /// writer that skipped it. Refused: an unbound state is the defect itself.
    StateUnbound,
    /// The callback presented no (unambiguous, well-formed) cookie.
    NoCookie,
    /// A cookie was presented and its hash differs — a different browser.
    Mismatch,
}

impl BindingCheck {
    /// The log/audit token. Never carries a value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Matches => "matches",
            Self::StateUnbound => "state_unbound",
            Self::NoCookie => "no_cookie",
            Self::Mismatch => "mismatch",
        }
    }
}

/// Compare a consumed row's stored binding hash with the presented nonce.
/// Constant-time over the hex digests (a timing oracle on the compare would
/// leak the cookie a byte at a time).
pub fn check_connect_binding(stored_hash: Option<&str>, presented: Option<&str>) -> BindingCheck {
    let Some(stored) = stored_hash else {
        return BindingCheck::StateUnbound;
    };
    let Some(nonce) = presented else {
        return BindingCheck::NoCookie;
    };
    let provided = hash_oauth_session_binding(nonce);
    if constant_time_eq(stored.as_bytes(), provided.as_bytes()) {
        BindingCheck::Matches
    } else {
        BindingCheck::Mismatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(cookie_lines: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for line in cookie_lines {
            h.append(COOKIE, HeaderValue::from_str(line).unwrap());
        }
        h
    }

    #[test]
    fn a_fresh_binding_is_well_formed_and_distinct() {
        let a = BrowserBinding::fresh();
        let b = BrowserBinding::fresh();
        assert!(is_well_formed_nonce(a.nonce_for_test()));
        assert_ne!(a.nonce_for_test(), b.nonce_for_test());
        assert_eq!(a.hash(), hash_oauth_session_binding(a.nonce_for_test()));
    }

    #[test]
    fn the_cookie_is_httponly_lax_root_path_and_ten_minutes() {
        let b = BrowserBinding::fresh();
        let dev = b.set_cookie_string(false);
        assert!(dev.starts_with(&format!("{CONNECT_BINDING_COOKIE}={};", b.nonce_for_test())));
        assert!(dev.contains("; HttpOnly"));
        assert!(
            dev.contains("; SameSite=Lax"),
            "Strict would strip it on the provider redirect"
        );
        assert!(dev.contains("; Path=/"));
        assert!(dev.contains("; Max-Age=600"));
        assert!(!dev.contains("Secure"));
        assert!(b.set_cookie_string(true).ends_with("; Secure"));
    }

    #[test]
    fn a_request_cookie_is_reused_so_two_tabs_share_one_binding() {
        let first = BrowserBinding::fresh();
        let h = headers(&[&format!(
            "other=1; {CONNECT_BINDING_COOKIE}={}; x=y",
            first.nonce_for_test()
        )]);
        let second = BrowserBinding::for_request(&h);
        assert_eq!(second.nonce_for_test(), first.nonce_for_test());
        assert_eq!(second.hash(), first.hash());
    }

    #[test]
    fn a_malformed_or_absent_cookie_mints_a_fresh_binding() {
        let none = BrowserBinding::for_request(&HeaderMap::new());
        assert!(is_well_formed_nonce(none.nonce_for_test()));
        let bad = headers(&[&format!("{CONNECT_BINDING_COOKIE}=NOT-HEX")]);
        assert_eq!(presented_connect_binding(&bad), None);
        assert!(is_well_formed_nonce(
            BrowserBinding::for_request(&bad).nonce_for_test()
        ));
    }

    #[test]
    fn two_different_values_are_ambiguous_and_present_nothing() {
        let a = BrowserBinding::fresh();
        let b = BrowserBinding::fresh();
        let split = headers(&[
            &format!("{CONNECT_BINDING_COOKIE}={}", a.nonce_for_test()),
            &format!("{CONNECT_BINDING_COOKIE}={}", b.nonce_for_test()),
        ]);
        assert_eq!(presented_connect_binding(&split), None);
        // The SAME value twice (HTTP/2 split cookie headers) is not ambiguous.
        let dup = headers(&[
            &format!("{CONNECT_BINDING_COOKIE}={}", a.nonce_for_test()),
            &format!("{CONNECT_BINDING_COOKIE}={}", a.nonce_for_test()),
        ]);
        assert_eq!(
            presented_connect_binding(&dup).as_deref(),
            Some(a.nonce_for_test())
        );
    }

    #[test]
    fn the_login_cookie_does_not_count_as_a_connect_binding() {
        let a = BrowserBinding::fresh();
        let h = headers(&[&format!("talos_oauth_session={}", a.nonce_for_test())]);
        assert_eq!(presented_connect_binding(&h), None);
    }

    #[test]
    fn only_the_matching_browser_passes_the_check() {
        let victim = BrowserBinding::fresh();
        let attacker = BrowserBinding::fresh();
        let row = attacker.hash();
        assert_eq!(
            check_connect_binding(Some(&row), Some(attacker.nonce_for_test())),
            BindingCheck::Matches
        );
        assert_eq!(
            check_connect_binding(Some(&row), Some(victim.nonce_for_test())),
            BindingCheck::Mismatch
        );
        assert_eq!(
            check_connect_binding(Some(&row), None),
            BindingCheck::NoCookie
        );
        assert_eq!(
            check_connect_binding(None, Some(attacker.nonce_for_test())),
            BindingCheck::StateUnbound
        );
    }

    #[test]
    fn debug_never_prints_the_nonce() {
        let b = BrowserBinding::fresh();
        let dbg = format!("{b:?}");
        assert!(!dbg.contains(b.nonce_for_test()));
    }
}
