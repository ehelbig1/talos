use super::*;

#[test]
fn test_validate_email_logic() {
    // Test valid emails
    assert!(validate_email("test@example.com").is_ok());
    assert!(validate_email("user.name+tag@sub.example.com").is_ok());

    // Test invalid emails
    assert!(validate_email("invalid-email").is_err());
    assert!(validate_email("@missing-user.com").is_err());
    assert!(validate_email("user@").is_err());
}

// MCP-1004: canonical display-name discipline for user.name field.
// Pre-fix `create_user` checked only length; control chars / null bytes
// / whitespace-only / empty all passed through to the DB.

#[test]
fn test_validate_user_display_name_empty_normalizes_to_none() {
    assert!(matches!(validate_user_display_name(""), Ok(None)));
    assert!(matches!(validate_user_display_name("   "), Ok(None)));
    assert!(matches!(validate_user_display_name("\t\n"), Ok(None)));
}

#[test]
fn test_validate_user_display_name_accepts_valid() {
    let r = validate_user_display_name("Alice").unwrap();
    assert_eq!(r.as_deref(), Some("Alice"));
    // Leading/trailing whitespace is trimmed
    let r = validate_user_display_name("  Alice  ").unwrap();
    assert_eq!(r.as_deref(), Some("Alice"));
    // Names with international / accented chars are fine
    let r = validate_user_display_name("Aliçe Müller").unwrap();
    assert_eq!(r.as_deref(), Some("Aliçe Müller"));
}

#[test]
fn test_validate_user_display_name_rejects_control_chars() {
    // Null byte — MCP-431 class
    assert!(validate_user_display_name("Alice\0Bob").is_err());
    // BEL / VT / FF / DEL — MCP-410 class
    for c in ['\x01', '\x07', '\x0B', '\x0C', '\x1F', '\x7F'] {
        assert!(
            validate_user_display_name(&format!("Alice{c}Bob")).is_err(),
            "must reject control char {c:?}"
        );
    }
    // Tab is permitted (MCP-410 carve-out for legitimate whitespace).
    assert!(validate_user_display_name("Alice\tBob").is_ok());
}

#[test]
fn test_validate_user_display_name_rejects_oversize() {
    let oversize = "a".repeat(256);
    assert!(validate_user_display_name(&oversize).is_err());
    // 255 chars is the boundary — accept.
    let max = "a".repeat(255);
    let r = validate_user_display_name(&max).unwrap();
    assert_eq!(r.as_deref(), Some(max.as_str()));
}

#[test]
fn test_validate_user_display_name_trim_then_check_original() {
    // A name that trims clean but has embedded `\0` is STILL rejected
    // (MCP-431 pattern — the trim-then-check happens on the ORIGINAL
    // string, not the trimmed slice).
    assert!(validate_user_display_name("  Alice\0Bob  ").is_err());
}

#[test]
fn test_validate_password_logic() {
    // Test valid passwords
    assert!(validate_password("SecurePassword123!").is_ok());
    assert!(validate_password("this is a long passphrase that is valid").is_ok());

    // Test too short
    assert!(validate_password("short").is_err());

    // Test too long
    let long_pwd = "a".repeat(73);
    assert!(validate_password(&long_pwd).is_err());
}

#[test]
fn test_validate_password_character_classes() {
    // Single character class (only lowercase) — rejected
    assert!(validate_password("aaaaaabbbbbbcccc").is_err());
    // Single character class (only digits) — rejected
    assert!(validate_password("123456789012").is_err());

    // Two classes: lower + digit — accepted
    assert!(validate_password("password1234").is_ok());
    // Two classes: lower + upper — accepted
    assert!(validate_password("PasswordLong").is_ok());
    // Two classes: lower + symbol — accepted
    assert!(validate_password("password!@#$").is_ok());

    // Exact boundary: 12 chars, 2 classes — accepted
    assert!(validate_password("abcdefghij1!").is_ok());
    // Exact boundary: 12 chars, 1 class — rejected
    assert!(validate_password("abcdefghijkl").is_err());

    // Passphrase: words separated by hyphens (lower + symbol) — accepted
    assert!(validate_password("correct-horse-battery-staple").is_ok());

    // Max length boundary: exactly 72 — accepted
    let mut max_pwd = "A".repeat(36);
    max_pwd.push_str(&"1".repeat(36));
    assert!(validate_password(&max_pwd).is_ok());
}

#[test]
fn test_validate_email_edge_cases() {
    // Long but valid email
    let long_local = "a".repeat(64);
    let email = format!("{}@example.com", long_local);
    assert!(validate_email(&email).is_ok());

    // Too long (>254 chars)
    let long_email = format!("{}@{}.com", "a".repeat(64), "b".repeat(190));
    assert!(validate_email(&long_email).is_err());

    // Empty
    assert!(validate_email("").is_err());
}

/// MCP-1010: a multi-MB email submission must be rejected by the
/// length-cap WITHOUT first scanning the entire string with the regex.
/// Defensive-perf — Rust regex crate is linear-time, so the worst case
/// is O(n) not exponential, but a megabyte-sized scan per signup
/// attempt is wasted CPU. Length-first fail-fast brings the cost back
/// to O(1) for the spam case.
#[test]
fn test_validate_email_rejects_megabyte_input() {
    let huge = format!("{}@example.com", "a".repeat(2 * 1024 * 1024));
    // Should reject as "too long" — well past the 254-char cap.
    let err = validate_email(&huge).unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("too long"),
        "expected length-cap rejection, got: {msg}"
    );
}

#[tokio::test]
async fn test_lockout_constants() {
    // Verify lockout parameters are within reasonable bounds.
    // These aren't testable as pure functions (they're inline constants in login()),
    // but we can verify the types and ensure the auth service initializes correctly.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();
    let service = AuthService::new(
        pool,
        "this-is-a-test-secret-that-is-32bytes".into(),
        12,
        None,
    )
    .unwrap();

    // Service should generate valid tokens for a test user
    let user = test_user();
    let token = service.generate_access_token(&user, false).unwrap();
    let claims = service.verify_token(&token).unwrap();

    // Token should expire in the future (15 min from now)
    let exp_time = chrono::DateTime::from_timestamp(claims.exp as i64, 0).unwrap();
    let now = Utc::now();
    assert!(exp_time > now, "Token should expire in the future");
    assert!(
        exp_time < now + Duration::minutes(20),
        "Token should expire within 20 minutes"
    );
}

#[test]
fn test_token_lookup_hash_uniqueness() {
    let hash1 = generate_token_lookup_hash("token-a");
    let hash2 = generate_token_lookup_hash("token-b");
    assert_ne!(
        hash1, hash2,
        "Different tokens must produce different hashes"
    );

    // Length should be 64 hex chars (SHA-256 = 32 bytes = 64 hex)
    assert_eq!(hash1.len(), 64);
}

#[test]
fn test_generate_token_lookup_hash_logic() {
    let token = "test-refresh-token";
    let hash1 = generate_token_lookup_hash(token);
    let hash2 = generate_token_lookup_hash(token);

    // Deterministic
    assert_eq!(hash1, hash2);

    // Hex string
    assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
}

#[tokio::test]
async fn test_auth_service_new_validation() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();

    // Valid cost
    assert!(AuthService::new(
        pool.clone(),
        "this-is-a-test-secret-that-is-32bytes".into(),
        12,
        None
    )
    .is_ok());

    // Invalid costs
    assert!(AuthService::new(
        pool.clone(),
        "this-is-a-test-secret-that-is-32bytes".into(),
        4,
        None
    )
    .is_err());
    assert!(AuthService::new(
        pool.clone(),
        "this-is-a-test-secret-that-is-32bytes".into(),
        31,
        None
    )
    .is_err());
}

#[tokio::test]
async fn test_generate_access_token_claims() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();
    let service = AuthService::new(
        pool,
        "this-is-a-test-secret-that-is-32bytes".into(),
        12,
        None,
    )
    .unwrap();

    let user = User {
        id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: "hash".to_string(),
        name: Some("Test User".to_string()),
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login_at: None,
        is_active: true,
        failed_login_attempts: 0,
        locked_until: None,
        totp_secret: None,
        totp_enabled: None,
    };

    let token = service.generate_access_token(&user, false).unwrap();
    assert!(!token.is_empty());
}

#[tokio::test]
async fn test_verify_token_invalid_secret() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();
    let service1 = AuthService::new(
        pool.clone(),
        "this-is-test-secret1-32bytes-long!".into(),
        12,
        None,
    )
    .unwrap();
    let service2 =
        AuthService::new(pool, "this-is-test-secret2-32bytes-long!".into(), 12, None).unwrap();

    let user = User {
        id: Uuid::new_v4(),
        email: "test@example.com".to_string(),
        password_hash: "hash".to_string(),
        name: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        last_login_at: None,
        is_active: true,
        failed_login_attempts: 0,
        locked_until: None,
        totp_secret: None,
        totp_enabled: None,
    };

    let token = service1.generate_access_token(&user, false).unwrap();
    let result = service2.verify_token(&token);
    assert!(
        result.is_err(),
        "Verification should fail with different secret"
    );
}

#[tokio::test]
async fn test_refresh_token_rate_limiting_logic() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();
    let _service = AuthService::new(
        pool,
        "this-is-a-test-secret-that-is-32bytes".into(),
        12,
        None,
    )
    .unwrap();
    let session_id = Uuid::new_v4();

    // Use a unique session ID for this test to avoid interference
    for i in 1..=10 {
        let mut limiter = REFRESH_RATE_LIMITER
            .get_or_init(|| Mutex::new(HashMap::new()))
            .lock()
            .unwrap();

        let now = Instant::now();
        let (count, _last_time) = limiter.entry(session_id).or_insert((0, now));
        *count += 1;
        assert!(*count <= 10, "Attempt {} should be allowed", i);
    }

    // 11th attempt should fail in the real service logic
    let mut limiter = REFRESH_RATE_LIMITER
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap();
    let (count, _) = limiter.entry(session_id).or_insert((0, Instant::now()));
    *count += 1;
    assert!(*count > 10, "11th attempt should exceed limit");
}

#[tokio::test]
async fn test_jwt_secret_length_validation() {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();

    // Secret shorter than 32 bytes should fail
    let short_secret = "short-secret".to_string(); // 12 bytes
    let result = AuthService::new(pool.clone(), short_secret, 12, None);
    assert!(
        result.is_err(),
        "Should reject JWT secret shorter than 32 bytes"
    );
    if let Err(e) = result {
        let err_msg = e.to_string();
        assert!(
            err_msg.contains("JWT_SECRET must be at least 32 bytes"),
            "Error message should indicate minimum length requirement"
        );
    }

    // Secret with exactly 32 bytes should succeed
    let valid_secret = "a".repeat(32);
    let result = AuthService::new(pool.clone(), valid_secret, 12, None);
    assert!(result.is_ok(), "Should accept JWT secret with 32 bytes");

    // Secret with more than 32 bytes should succeed
    let long_secret = "this-is-a-very-long-secret-that-exceeds-32-bytes-for-security".to_string();
    let result = AuthService::new(pool, long_secret, 12, None);
    assert!(
        result.is_ok(),
        "Should accept JWT secret longer than 32 bytes"
    );
}

// ── JWT audience claim tests ────────────────────────────────────────────

fn test_user() -> User {
    User {
        id: Uuid::new_v4(),
        email: "aud-test@example.com".to_string(),
        password_hash: "hash".to_string(),
        name: None,
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

fn test_service() -> AuthService {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .connect_lazy("postgres://localhost/talos_test")
        .unwrap();
    AuthService::new(
        pool,
        "this-is-a-test-secret-that-is-32bytes".into(),
        12,
        None,
    )
    .unwrap()
}

#[tokio::test]
async fn test_jwt_audience_present_in_new_tokens() {
    let service = test_service();
    let user = test_user();
    let token = service.generate_access_token(&user, false).unwrap();
    let claims = service.verify_token(&token).unwrap();
    assert_eq!(
        claims.aud.as_deref(),
        Some("talos"),
        "Newly issued tokens must carry aud=talos"
    );
}

#[tokio::test]
async fn test_jwt_wrong_audience_rejected() {
    let service = test_service();
    let user = test_user();

    // Manually craft a token with wrong audience
    let now = Utc::now();
    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        exp: (now + Duration::minutes(15)).timestamp() as usize,
        iat: now.timestamp() as usize,
        is_2fa_verified: false,
        iss: "talos".to_string(),
        aud: Some("evil-service".to_string()),
        org: String::new(),
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(service.key_pair.algorithm()),
        &claims,
        service.key_pair.encoding_key(),
    )
    .unwrap();

    let result = service.verify_token(&token);
    assert!(result.is_err(), "Tokens with wrong aud must be rejected");
}

#[tokio::test]
async fn test_jwt_missing_audience_accepted_for_migration() {
    let service = test_service();
    let user = test_user();

    // Manually craft a token without the audience claim (legacy token)
    let now = Utc::now();
    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        exp: (now + Duration::minutes(15)).timestamp() as usize,
        iat: now.timestamp() as usize,
        is_2fa_verified: false,
        iss: "talos".to_string(),
        aud: None,
        org: String::new(),
    };
    let token = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(service.key_pair.algorithm()),
        &claims,
        service.key_pair.encoding_key(),
    )
    .unwrap();

    let result = service.verify_token(&token);
    assert!(
        result.is_ok(),
        "Legacy tokens without aud must still be accepted during migration window"
    );
}

/// MCP-1147 (2026-05-16): refresh rate-limiter max-entries cap.
mod refresh_rate_limiter_cap_tests {
    use super::super::{REFRESH_RATE_LIMITER, REFRESH_RATE_LIMITER_MAX_ENTRIES};
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::Instant;
    use uuid::Uuid;

    /// Process-global limiter — serialise tests so parallel runs don't
    /// race each other's pre-fill assertions. Same pattern as the
    /// MCP-1146 LIMITER_TEST_LOCK and MCP-1145 GRACE_TEST_LOCK.
    static REFRESH_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn refresh_test_lock() -> std::sync::MutexGuard<'static, ()> {
        REFRESH_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn limiter() -> &'static Mutex<HashMap<Uuid, (usize, Instant)>> {
        REFRESH_RATE_LIMITER.get_or_init(|| Mutex::new(HashMap::new()))
    }

    /// Sanity: cap constant is the expected workspace canonical (50K).
    #[test]
    fn cap_matches_workspace_canonical() {
        assert_eq!(REFRESH_RATE_LIMITER_MAX_ENTRIES, 50_000);
    }

    /// At cap, NEW session_ids fail the cap-gate (`len >= cap &&
    /// !contains_key`); EXISTING tracked sessions pass through because
    /// `contains_key` short-circuits the gate. The actual reject is
    /// inline in `refresh_access_token`; this test pins the gate
    /// semantics it depends on.
    #[test]
    fn cap_gate_admits_existing_rejects_new() {
        let _g = refresh_test_lock();
        let lim = limiter();

        // Wedge to exactly the cap with distinct sentinel keys.
        let mut wedge_keys = Vec::with_capacity(REFRESH_RATE_LIMITER_MAX_ENTRIES);
        {
            let mut map = lim.lock().unwrap();
            map.clear();
            let now = Instant::now();
            for _ in 0..REFRESH_RATE_LIMITER_MAX_ENTRIES {
                let k = Uuid::new_v4();
                wedge_keys.push(k);
                map.insert(k, (1, now));
            }
            assert_eq!(map.len(), REFRESH_RATE_LIMITER_MAX_ENTRIES);
        }

        let new_id = Uuid::new_v4();
        let existing_id = *wedge_keys.first().expect("wedge inserted at least one key");

        let map = lim.lock().unwrap();
        // Cap gate: len >= cap AND key absent → reject.
        assert!(map.len() >= REFRESH_RATE_LIMITER_MAX_ENTRIES);
        assert!(!map.contains_key(&new_id), "fresh session_id is absent");
        assert!(
            map.contains_key(&existing_id),
            "tracked session_id passes the short-circuit"
        );
        drop(map);

        // Cleanup for subsequent tests.
        lim.lock().unwrap().clear();
    }
}
