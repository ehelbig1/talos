//! Security boundary tests for JWT/auth edge cases.
//!
//! These tests exercise the controller's `AuthService::verify_token` and
//! token generation logic without requiring a live database connection.

use chrono::{Duration, Utc};
use controller::auth::{AuthService, Claims};
use jsonwebtoken::{encode, EncodingKey, Header};
use uuid::Uuid;

/// Create an AuthService backed by a lazy (not connected) pool.
/// Only methods that do NOT touch the database can be called.
fn make_auth_service(secret: &str) -> AuthService {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();
    AuthService::new(pool, secret.to_string(), 12, None).unwrap()
}

/// Helper: build a test User struct (no DB required).
fn test_user() -> controller::auth::User {
    controller::auth::User {
        id: Uuid::new_v4(),
        email: "jwt-test@example.com".to_string(),
        password_hash: "not-a-real-hash".to_string(),
        name: Some("JWT Tester".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login_at: None,
        is_active: true,
        failed_login_attempts: 0,
        locked_until: None,
        totp_secret: None,
        totp_enabled: None,
    }
}

// ---------------------------------------------------------------------------
// Expired token rejection
// ---------------------------------------------------------------------------

#[tokio::test]
async fn expired_token_is_rejected() {
    let service = make_auth_service("test-jwt-secret-key-for-tests!!!");

    // Manually craft a token that expired 1 hour ago.
    let now = Utc::now();
    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        email: "expired@example.com".to_string(),
        exp: (now - Duration::hours(1)).timestamp() as usize,
        iat: (now - Duration::hours(2)).timestamp() as usize,
        is_2fa_verified: false,
        iss: "talos".to_string(),
        aud: Some("talos".to_string()),
        org: String::new(),
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(b"test-jwt-secret-key-for-tests!!!"),
    )
    .expect("encoding should succeed");

    let result = service.verify_token(&token);
    assert!(result.is_err(), "Expired token must be rejected");
    let err_msg = result.unwrap_err().to_string().to_lowercase();
    assert!(
        err_msg.contains("expired") || err_msg.contains("exp"),
        "Error should mention expiration: {}",
        err_msg
    );
}

// ---------------------------------------------------------------------------
// Token with tampered payload (invalid signature)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn tampered_payload_is_rejected() {
    let service = make_auth_service("correct-secret-for-tamper-test!!");
    let user = test_user();
    let token = service
        .generate_access_token(&user, false)
        .expect("token generation should succeed");

    // Tamper: decode the payload, modify it, re-encode without the correct key.
    // A JWT is three base64url segments separated by dots.
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have 3 parts");

    // Decode the payload segment.
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("base64 decode payload");
    let mut payload: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("parse payload JSON");

    // Tamper: change the email claim.
    payload["email"] = serde_json::json!("attacker@evil.com");

    let tampered_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
    let tampered_token = format!("{}.{}.{}", parts[0], tampered_payload, parts[2]);

    let result = service.verify_token(&tampered_token);
    assert!(
        result.is_err(),
        "Token with tampered payload must fail signature verification"
    );
}

// ---------------------------------------------------------------------------
// Empty and malformed JWT strings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn empty_token_is_rejected() {
    let service = make_auth_service("secret-for-empty-test!!!!!!!!!!!!");
    let result = service.verify_token("");
    assert!(result.is_err(), "Empty token string must be rejected");
}

#[tokio::test]
async fn garbage_string_is_rejected() {
    let service = make_auth_service("secret-for-garbage-test!!!!!!!!!");
    let result = service.verify_token("this-is-not-a-jwt");
    assert!(result.is_err(), "Non-JWT string must be rejected");
}

#[tokio::test]
async fn two_part_token_is_rejected() {
    let service = make_auth_service("secret-for-two-part-test!!!!!!!!");
    // A JWT requires exactly 3 dot-separated segments.
    let result = service.verify_token("header.payload");
    assert!(result.is_err(), "Two-part token must be rejected");
}

#[tokio::test]
async fn token_with_empty_segments_is_rejected() {
    let service = make_auth_service("secret-for-empty-segments!!!!!!!");
    let result = service.verify_token("..");
    assert!(
        result.is_err(),
        "Token with empty segments must be rejected"
    );
}

#[tokio::test]
async fn token_with_null_bytes_is_rejected() {
    let service = make_auth_service("secret-for-null-bytes!!!!!!!!!!!!");
    let result = service.verify_token("eyJ\0.pay\0load.sig\0");
    assert!(
        result.is_err(),
        "Token containing null bytes must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Token signed with wrong secret (wrong issuer key)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn token_from_different_secret_is_rejected() {
    let service_a = make_auth_service("secret-A-for-cross-key-test!!!!!");
    let service_b = make_auth_service("secret-B-for-cross-key-test!!!!!");

    let user = test_user();
    let token = service_a
        .generate_access_token(&user, false)
        .expect("token generation with secret A");

    let result = service_b.verify_token(&token);
    assert!(
        result.is_err(),
        "Token signed with secret A must not verify with secret B"
    );
}

// ---------------------------------------------------------------------------
// Algorithm confusion: token signed with "none"
// ---------------------------------------------------------------------------

#[tokio::test]
async fn alg_none_token_is_rejected() {
    let service = make_auth_service("secret-for-alg-none-test!!!!!!!!");

    // Craft a token with alg: none (a classic JWT bypass).
    let header = r#"{"alg":"none","typ":"JWT"}"#;
    let claims = Claims {
        sub: Uuid::new_v4().to_string(),
        email: "alg-none@evil.com".to_string(),
        exp: (Utc::now() + Duration::hours(1)).timestamp() as usize,
        iat: Utc::now().timestamp() as usize,
        is_2fa_verified: false,
        iss: "talos".to_string(),
        aud: Some("talos".to_string()),
        org: String::new(),
    };
    let payload = serde_json::to_string(&claims).unwrap();

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
    let payload_b64 = URL_SAFE_NO_PAD.encode(payload.as_bytes());

    // alg:none tokens have an empty signature segment.
    let none_token = format!("{}.{}.", header_b64, payload_b64);

    let result = service.verify_token(&none_token);
    assert!(
        result.is_err(),
        "Token with alg:none must be rejected (algorithm confusion attack)"
    );
}

// ---------------------------------------------------------------------------
// Token with future iat (issued-at in the future)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn valid_token_verifies_successfully() {
    let service = make_auth_service("secret-for-happy-path!!!!!!!!!!!!");
    let user = test_user();
    let token = service
        .generate_access_token(&user, true)
        .expect("token generation should succeed");
    let claims = service
        .verify_token(&token)
        .expect("valid token should verify");
    assert_eq!(claims.email, user.email);
    assert_eq!(claims.sub, user.id.to_string());
}

// ---------------------------------------------------------------------------
// Very long token strings
// ---------------------------------------------------------------------------

#[tokio::test]
async fn extremely_long_token_is_rejected() {
    let service = make_auth_service("secret-for-long-token!!!!!!!!!!!!");
    let long_token = "a".repeat(100_000);
    let result = service.verify_token(&long_token);
    assert!(
        result.is_err(),
        "Extremely long token string must be rejected"
    );
}
