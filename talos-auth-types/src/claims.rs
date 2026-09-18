use serde::{Deserialize, Serialize};

/// JWT claim set used by the Talos controller.
///
/// `iss` and `aud` are validated in `verify_token` to prevent tokens
/// issued by other systems (or misrouted cross-service tokens) from
/// being accepted. Tokens issued by this service carry `aud: "talos"`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    /// User id (UUID rendered as string — kept as `String` so this
    /// crate stays free of a `uuid` dependency).
    pub sub: String,
    pub email: String,
    /// Expiration timestamp (seconds since epoch, per JWT convention).
    pub exp: usize,
    /// Issued-at timestamp (seconds since epoch, per JWT convention).
    pub iat: usize,
    /// The session is not waiting on a second factor: either the account has
    /// no second factor enrolled, or one was verified. It does NOT mean a
    /// second factor was proven — see [`Claims::second_factor_verified`].
    pub is_2fa_verified: bool,
    /// A second factor (TOTP or backup code) was VERIFIED for this session —
    /// at a 2FA login, or by the session that enrolled 2FA. The privileged
    /// operations (key material, security controls) require it. Defaults to
    /// `false`, so a token minted before the field existed fails closed.
    #[serde(default)]
    pub second_factor_verified: bool,
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub aud: Option<String>,
    /// Active organization (the tenant, per RFC 0004) this token operates
    /// under — a UUID string, set to the user's personal org by default
    /// or to a shared org the user has switched into. The controller
    /// stamps `SET LOCAL app.current_org_id` from this for RLS.
    ///
    /// `#[serde(default)]` keeps it backward-compatible: tokens minted
    /// before this field existed deserialize with `org == ""`, and the
    /// resolution path falls back to the user's personal org. So a
    /// rollout never invalidates in-flight tokens.
    #[serde(default)]
    pub org: String,
}

/// How a session was authenticated — the ONE value every token-minting site
/// passes, so the two flags stored on a session (`is_2fa_verified`,
/// `second_factor_verified`) are derived together and cannot disagree.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionAuth {
    /// Password verified; the account has 2FA enrolled and the code has not
    /// been verified yet. Only the pre-2FA surface is reachable.
    PendingSecondFactor,
    /// Password (or OAuth) only, on an account with no second factor
    /// enrolled. Ordinary operations proceed; privileged ones are refused.
    PasswordOnly,
    /// A second factor was verified for this session.
    SecondFactorVerified,
}

impl SessionAuth {
    /// The state a fresh password or OAuth login starts in.
    #[must_use]
    pub const fn at_login(two_factor_enrolled: bool) -> Self {
        if two_factor_enrolled {
            Self::PendingSecondFactor
        } else {
            Self::PasswordOnly
        }
    }

    /// Rebuild the state from a stored session row. A row claiming a
    /// verified second factor while still pending is contradictory and reads
    /// as pending (the more restrictive state).
    #[must_use]
    pub const fn from_flags(is_2fa_verified: bool, second_factor_verified: bool) -> Self {
        match (is_2fa_verified, second_factor_verified) {
            (false, _) => Self::PendingSecondFactor,
            (true, false) => Self::PasswordOnly,
            (true, true) => Self::SecondFactorVerified,
        }
    }

    /// Not waiting on a second factor (the historical `is_2fa_verified`).
    #[must_use]
    pub const fn is_2fa_verified(self) -> bool {
        !matches!(self, Self::PendingSecondFactor)
    }

    /// A second factor was verified.
    #[must_use]
    pub const fn second_factor_verified(self) -> bool {
        matches!(self, Self::SecondFactorVerified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_factor_defaults_to_unverified_for_old_tokens() {
        let json = r#"{"sub":"u","email":"e","exp":1,"iat":1,"is_2fa_verified":true,"iss":""}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert!(claims.is_2fa_verified);
        assert!(
            !claims.second_factor_verified,
            "an old token must fail closed"
        );
    }

    #[test]
    fn session_auth_flags_round_trip_and_fail_closed() {
        for s in [
            SessionAuth::PendingSecondFactor,
            SessionAuth::PasswordOnly,
            SessionAuth::SecondFactorVerified,
        ] {
            assert_eq!(
                SessionAuth::from_flags(s.is_2fa_verified(), s.second_factor_verified()),
                s
            );
        }
        // Only a verified second factor sets the privileged flag.
        assert!(!SessionAuth::PasswordOnly.second_factor_verified());
        assert!(!SessionAuth::PendingSecondFactor.second_factor_verified());
        // A contradictory row reads as the more restrictive state.
        assert_eq!(
            SessionAuth::from_flags(false, true),
            SessionAuth::PendingSecondFactor
        );
        assert_eq!(
            SessionAuth::at_login(true),
            SessionAuth::PendingSecondFactor
        );
        assert_eq!(SessionAuth::at_login(false), SessionAuth::PasswordOnly);
    }

    #[test]
    fn aud_is_optional_for_back_compat() {
        let json = r#"{"sub":"u","email":"e","exp":1,"iat":1,"is_2fa_verified":false,"iss":""}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert!(claims.aud.is_none());
    }

    #[test]
    fn org_is_optional_for_back_compat() {
        // A token minted before the `org` claim existed must still
        // deserialize (RFC 0004 rollout safety) — `org` defaults to "".
        let json = r#"{"sub":"u","email":"e","exp":1,"iat":1,"is_2fa_verified":false,"iss":""}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert!(claims.org.is_empty());
    }
}
