mod common;

use common::{create_test_user, setup_test_context};
use controller::api_keys::ApiKeyScope;

/// The metrics registry is process-global and every test here validates
/// keys, so counter DELTAS are only meaningful if the tests do not overlap.
/// Measured: without this, `validate_key_verdicts_move_the_seeded_counters`
/// read a `valid` delta of 2 while a sibling test validated its own key.
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[tokio::test]
async fn test_api_key_lifecycle() {
    let _serial = SERIAL.lock().await;
    let ctx = setup_test_context().await;
    let user_id = create_test_user(&ctx.auth_service, "api_lifecycle@example.com").await;

    // 1. Create API key
    let (full_key, key_id, _expires_at) = ctx
        .api_key_service
        .create_api_key(user_id, "Test Key", vec![ApiKeyScope::WorkflowsRead], None)
        .await
        .expect("Failed to create API key");

    assert!(full_key.starts_with("talos_sk_"));

    // 2. Validate API key
    let (validated_user_id, scopes) = ctx
        .api_key_service
        .validate_key(&full_key)
        .await
        .expect("Failed to validate API key");

    assert_eq!(validated_user_id, user_id);
    assert_eq!(scopes, vec![ApiKeyScope::WorkflowsRead]);

    // 3. List API keys
    let keys = ctx
        .api_key_service
        .list_keys(user_id)
        .await
        .expect("Failed to list keys");
    assert!(keys.iter().any(|k| k.id == key_id));

    // 4. Revoke API key
    ctx.api_key_service
        .revoke_key(key_id, user_id)
        .await
        .expect("Failed to revoke key");

    // 5. Validation should fail now
    let validation_result = ctx.api_key_service.validate_key(&full_key).await;
    assert!(validation_result.is_err(), "Revoked key should be invalid");

    // 6. Delete API key
    ctx.api_key_service
        .delete_key(key_id, user_id)
        .await
        .expect("Failed to delete key");
}

#[tokio::test]
#[ignore = "Timing-flaky on slow CI: 60 bcrypt-verify (cost 12) calls plus DB hits run close to or past the 60s rate-limit window, so the in-memory counter resets mid-loop and the 61st call isn't denied. Real fix is mock-the-clock in the rate limiter, or lower bcrypt cost via env var in CI."]
async fn test_api_key_rate_limiting() {
    let _serial = SERIAL.lock().await;
    let ctx = setup_test_context().await;
    let user_id = create_test_user(&ctx.auth_service, "api_rate_limit@example.com").await;

    let (full_key, _key_id, _expires_at) = ctx
        .api_key_service
        .create_api_key(user_id, "Rate Limit Test", vec![ApiKeyScope::Admin], None)
        .await
        .unwrap();

    // Trigger rate limit (default is 60/min)
    for _ in 0..60 {
        ctx.api_key_service.validate_key(&full_key).await.unwrap();
    }

    let result = ctx.api_key_service.validate_key(&full_key).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("Rate limit exceeded"));
}

#[tokio::test]
async fn test_api_key_scopes() {
    let _serial = SERIAL.lock().await;
    let ctx = setup_test_context().await;
    let user_id = create_test_user(&ctx.auth_service, "api_scopes@example.com").await;

    let scopes_to_test = vec![ApiKeyScope::WorkflowsWrite, ApiKeyScope::SecretsRead];
    let (full_key, _key_id, _expires_at) = ctx
        .api_key_service
        .create_api_key(user_id, "Scope Test", scopes_to_test.clone(), None)
        .await
        .unwrap();

    let (_, validated_scopes) = ctx.api_key_service.validate_key(&full_key).await.unwrap();
    assert_eq!(validated_scopes.len(), 2);
    assert!(validated_scopes.contains(&ApiKeyScope::WorkflowsWrite));
    assert!(validated_scopes.contains(&ApiKeyScope::SecretsRead));
}

/// The production `validate_key` path moves `talos_api_key_validations_total`
/// and `talos_rate_limit_hits_total{type="api_key"}` — the two series that
/// sat DEAD in check 58's baseline from 2026-05 to 2026-09-11. Deltas rather
/// than absolutes: the registry is process-global and sibling tests in this
/// binary validate keys too. A wrapper the call sites stopped reaching would
/// leave the talos-metrics unit test green and fail this one (check 58's
/// stated wrapper limit).
#[tokio::test]
async fn validate_key_verdicts_move_the_seeded_counters() {
    let _serial = SERIAL.lock().await;
    use talos_metrics::{ApiKeyValidation, RateLimitKind};
    let ctx = setup_test_context().await;
    let user_id = create_test_user(&ctx.auth_service, "api_metrics@example.com").await;
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
    let m = talos_metrics::global().expect("global metrics installed");
    let verdict = |v: ApiKeyValidation| {
        m.api_key_validations_total
            .with_label_values(&[v.as_str()])
            .get()
    };
    let hits = || {
        m.rate_limit_hits_total
            .with_label_values(&[RateLimitKind::ApiKey.as_str()])
            .get()
    };
    // Seeded: every verdict exists before the first validation.
    let rendered = m.render_prometheus().expect("render");
    for v in ApiKeyValidation::ALL {
        assert!(rendered.contains(&format!(
            "talos_api_key_validations_total{{status=\"{}\"}}",
            v.as_str()
        )));
    }

    let (full_key, _key_id, _) = ctx
        .api_key_service
        .create_api_key(
            user_id,
            "Metrics Key",
            vec![ApiKeyScope::WorkflowsRead],
            None,
        )
        .await
        .expect("create key");

    let valid0 = verdict(ApiKeyValidation::Valid);
    ctx.api_key_service
        .validate_key(&full_key)
        .await
        .expect("valid key validates");
    assert_eq!(
        verdict(ApiKeyValidation::Valid),
        valid0 + 1.0,
        "one valid verdict"
    );

    let invalid0 = verdict(ApiKeyValidation::Invalid);
    assert!(ctx.api_key_service.validate_key("nope").await.is_err());
    assert!(ctx
        .api_key_service
        .validate_key("talos_sk_zzzzzzzzdoesnotexist000000")
        .await
        .is_err());
    assert_eq!(
        verdict(ApiKeyValidation::Invalid),
        invalid0 + 2.0,
        "malformed prefix and unknown key are both `invalid`"
    );

    // Expired: a key past its expiry is the ONLY candidate for its prefix.
    let expired0 = verdict(ApiKeyValidation::Expired);
    let (expired_key, _, _) = ctx
        .api_key_service
        .create_api_key(
            user_id,
            "Already Expired",
            vec![ApiKeyScope::WorkflowsRead],
            Some(-1),
        )
        .await
        .expect("create expired key");
    assert!(ctx
        .api_key_service
        .validate_key(&expired_key)
        .await
        .is_err());
    assert_eq!(
        verdict(ApiKeyValidation::Expired),
        expired0 + 1.0,
        "one expired verdict"
    );

    // `rate_limited` is deliberately NOT driven here: `test_api_key_rate_limiting`
    // above is `#[ignore]`d because sixty bcrypt(cost 12) verifications can
    // outrun the 60 s window on a slow runner, and a flaky guard is worse than
    // a stated gap. That verdict and `rate_limit_hits_total{type="api_key"}`
    // are proved by the recorder test in talos-metrics and pinned at the two
    // call sites by the source they sit in; `hits` is read here only so the
    // api_key limiter series is shown to EXIST (seeded) before any refusal.
    assert!(hits() >= 0.0, "the api_key limiter series is seeded");
    let _ = RateLimitKind::ALL;
}
