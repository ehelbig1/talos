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
    pub is_2fa_verified: bool,
    #[serde(default)]
    pub iss: String,
    #[serde(default)]
    pub aud: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aud_is_optional_for_back_compat() {
        let json = r#"{"sub":"u","email":"e","exp":1,"iat":1,"is_2fa_verified":false,"iss":""}"#;
        let claims: Claims = serde_json::from_str(json).unwrap();
        assert!(claims.aud.is_none());
    }
}
