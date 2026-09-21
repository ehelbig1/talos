//! Refresh-token rotation makes a stolen token self-announcing: the thief's
//! first use succeeds and deletes the session, so the legitimate client's
//! next refresh misses. `rotated_session_audit` turns that miss into
//! evidence and `revoke_all_sessions` is the response — the platform's ONLY
//! automated stolen-credential response.
//!
//! Until 2026-09-21 that control produced NO machine-readable output: its one
//! `target: "talos_security_alert"` line was the sole emitter of that target
//! in the workspace and nothing subscribed to it, so a detection and a
//! non-detection rendered identically to every dashboard and every rule. And
//! its own read was written `if let Ok(Some(..))`, which put a DATABASE
//! FAILURE in the same branch as "no audit row" — on a blip the control
//! silently did not run and a replayed token left every other session alive.
//!
//! This binary drives the PRODUCTION `AuthService::refresh_access_token`
//! through every arm the control can take and reads
//! `talos_auth_token_reuse_total{outcome}` and
//! `talos_auth_rotation_audit_arm_total{outcome}` off the process-global
//! registry as DELTAS. It exists beside the talos-auth unit tests because of
//! check 58's stated wrapper limit: those prove the classifier decides
//! correctly, this proves every path a refresh can take REACHES the recorder
//! — and, for the two unreadable arms, that the control says so instead of
//! reporting a clean bill.
//!
//! ONE test function on purpose: the metrics registry is process-global.
mod common;

use common::{create_test_user, setup_test_context};
use sqlx::PgPool;
use talos_auth::{AuthService, SessionAuth};
use talos_metrics::{RotationAuditArmOutcome, TalosMetrics, TokenReuseOutcome};
use uuid::Uuid;

async fn live_sessions(pool: &PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM user_sessions WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count sessions")
}

async fn audit_rows(pool: &PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT count(*) FROM rotated_session_audit WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count audit rows")
}

async fn reuse_events(pool: &PgPool, user: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM auth_audit_log \
         WHERE user_id = $1 AND event_type = 'refresh_token_reuse_detected'",
    )
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("count auth events")
}

/// Hide the detector's own table, and restore it. A renamed relation is how
/// a read fails under a live pool without taking the rest of the request
/// down with it — the session lookup, the bcrypt verify and the rotation all
/// still work, which is exactly the state the three-way split is about.
async fn with_audit_table_hidden(pool: &PgPool) {
    sqlx::query("ALTER TABLE rotated_session_audit RENAME TO rotated_session_audit_hidden")
        .execute(pool)
        .await
        .expect("hide audit table");
}

async fn restore_audit_table(pool: &PgPool) {
    sqlx::query("ALTER TABLE rotated_session_audit_hidden RENAME TO rotated_session_audit")
        .execute(pool)
        .await
        .expect("restore audit table");
}

/// Every arm of the reuse detector moves its own series, the caller's answer
/// is the same generic refusal on all of them, and an unreadable detector is
/// never reported as a clean bill.
#[tokio::test]
async fn every_arm_of_the_reuse_detector_is_visible() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    talos_metrics::set_global(TalosMetrics::new().expect("metrics"));
    let m = talos_metrics::global().expect("global metrics installed");
    let reuse = |o: TokenReuseOutcome| m.token_reuse_total.with_label_values(&[o.as_str()]).get();
    let arm = |o: RotationAuditArmOutcome| {
        m.rotation_audit_arm_total
            .with_label_values(&[o.as_str()])
            .get()
    };

    // Cost 10 is the lowest `AuthService::new` accepts (it refuses anything
    // outside 10..=14) and keeps six rotations to a few seconds; the service
    // verifies whatever cost the stored hash carries.
    let auth = AuthService::new(
        pool.clone(),
        "test_secret_must_be_at_least_32_chars_long".to_string(),
        10,
        None,
    )
    .expect("auth service");
    let user = create_test_user(&ctx.auth_service, "reuse-probe@example.com").await;

    // ── 1. a rotation ARMS the detector ─────────────────────────────────
    let armed_before = arm(RotationAuditArmOutcome::Armed);
    let t1 = auth
        .generate_refresh_token(user, SessionAuth::SecondFactorVerified)
        .await
        .expect("issue first refresh token");
    let (_access, _t2, _user, _verified) = auth
        .refresh_access_token(&t1)
        .await
        .expect("first refresh rotates");
    assert_eq!(
        arm(RotationAuditArmOutcome::Armed) - armed_before,
        1.0,
        "a rotation that wrote its audit row must count as armed"
    );
    assert_eq!(
        audit_rows(&pool, user).await,
        1,
        "the retired token's lookup hash must be recorded"
    );
    assert_eq!(live_sessions(&pool, user).await, 1);

    // ── 2. reusing the retired token INSIDE the grace window ────────────
    // Two tabs racing one rotation land here; revoking everything would be
    // the wrong trade, so this is counted and NOT acted on.
    let grace_before = reuse(TokenReuseOutcome::WithinGrace);
    let err = auth
        .refresh_access_token(&t1)
        .await
        .expect_err("a retired token is refused");
    assert!(
        err.to_string().contains("Invalid or expired refresh token"),
        "caller answer must be the generic refusal, got: {err}"
    );
    assert_eq!(
        reuse(TokenReuseOutcome::WithinGrace) - grace_before,
        1.0,
        "a tab race must be counted as within_grace"
    );
    assert_eq!(
        live_sessions(&pool, user).await,
        1,
        "a tab race must NOT revoke the user's sessions"
    );

    // ── 3. reusing it PAST the grace window: detect and respond ─────────
    sqlx::query(
        "UPDATE rotated_session_audit SET rotated_at = NOW() - INTERVAL '60 seconds' \
         WHERE user_id = $1",
    )
    .bind(user)
    .execute(&pool)
    .await
    .expect("age the audit row past the grace window");

    let detected_before = reuse(TokenReuseOutcome::Detected);
    let err = auth
        .refresh_access_token(&t1)
        .await
        .expect_err("a replayed token is refused");
    assert!(
        err.to_string().contains("Invalid or expired refresh token"),
        "detection must not change the caller's answer — that would be an \
         oracle telling a thief their token was recognised"
    );
    assert_eq!(
        reuse(TokenReuseOutcome::Detected) - detected_before,
        1.0,
        "a replay past the grace window must be counted as detected"
    );
    assert_eq!(
        live_sessions(&pool, user).await,
        0,
        "detection must revoke EVERY session for the affected user"
    );
    assert_eq!(
        reuse_events(&pool, user).await,
        1,
        "detection must leave an auth_audit_log row"
    );

    // ── 4. a token that was never rotated is NOT reuse ──────────────────
    let not_reused_before = reuse(TokenReuseOutcome::NotReused);
    let err = auth
        .refresh_access_token("00000000000000000000000000000000")
        .await
        .expect_err("garbage is refused");
    assert!(err.to_string().contains("Invalid or expired refresh token"));
    assert_eq!(
        reuse(TokenReuseOutcome::NotReused) - not_reused_before,
        1.0,
        "a stale bookmark must be counted as not_reused"
    );

    // ── 5. an UNREADABLE detector is not a clean bill ───────────────────
    // A live session the control must not touch, and the retired token from
    // step 1 — which a working detector would now call reuse.
    let t3 = auth
        .generate_refresh_token(user, SessionAuth::SecondFactorVerified)
        .await
        .expect("issue a second session");
    assert_eq!(live_sessions(&pool, user).await, 1);

    with_audit_table_hidden(&pool).await;
    let unreadable_before = reuse(TokenReuseOutcome::DetectorUnreadable);
    let clean_bill_before = reuse(TokenReuseOutcome::NotReused);
    let detected_before = reuse(TokenReuseOutcome::Detected);
    let err = auth
        .refresh_access_token(&t1)
        .await
        .expect_err("the refresh is still refused when the detector cannot run");
    assert!(
        err.to_string().contains("Invalid or expired refresh token"),
        "the REQUEST fails closed even when the control cannot run"
    );
    assert_eq!(
        reuse(TokenReuseOutcome::DetectorUnreadable) - unreadable_before,
        1.0,
        "an unreadable detector must say so"
    );
    assert_eq!(
        reuse(TokenReuseOutcome::NotReused) - clean_bill_before,
        0.0,
        "an unreadable detector must NEVER be reported as not_reused — that \
         is the defect this split exists to remove"
    );
    assert_eq!(
        reuse(TokenReuseOutcome::Detected) - detected_before,
        0.0,
        "and it must not claim a detection it did not make"
    );
    assert_eq!(
        live_sessions(&pool, user).await,
        1,
        "an unreadable detector must not revoke anything"
    );

    // ── 6. a rotation whose ARM fails still succeeds, and is counted ────
    // The INSERT is best-effort by design: failing a legitimate refresh over
    // reuse detection would be the worse trade. What was missing is that the
    // failure — which disarms the detector for that token — left nothing but
    // a warn!.
    let failed_before = arm(RotationAuditArmOutcome::Failed);
    let armed_before = arm(RotationAuditArmOutcome::Armed);
    let (_access, t4, _user, _verified) = auth
        .refresh_access_token(&t3)
        .await
        .expect("a rotation must still succeed when the detector cannot be armed");
    assert!(!t4.is_empty(), "the user must get their new token");
    assert_eq!(
        arm(RotationAuditArmOutcome::Failed) - failed_before,
        1.0,
        "a rotation that could not arm the detector must count as failed"
    );
    assert_eq!(
        arm(RotationAuditArmOutcome::Armed) - armed_before,
        0.0,
        "and must not also count as armed"
    );
    restore_audit_table(&pool).await;

    // ── 7. a detection whose RESPONSE fails is not a completed one ──────
    // Reaching `revoke_failed` needs the audit read to SUCCEED and the
    // revoke DELETE to FAIL — nothing else in the workspace produces that
    // pair. A BEFORE DELETE trigger on `user_sessions` is the one way to
    // get exactly it: the session lookup, the bcrypt verify and the
    // detector's own read all keep working, and only `revoke_all_sessions`
    // fails. Without this case, a call site that hard-codes `Detected` and
    // ignores the revoke result passes every other test here.
    let t5 = auth
        .generate_refresh_token(user, SessionAuth::SecondFactorVerified)
        .await
        .expect("issue a third session");
    let (_access, _t6, _user, _verified) = auth
        .refresh_access_token(&t5)
        .await
        .expect("rotate to arm the detector");
    sqlx::query(
        "UPDATE rotated_session_audit SET rotated_at = NOW() - INTERVAL '60 seconds' \
         WHERE user_id = $1",
    )
    .bind(user)
    .execute(&pool)
    .await
    .expect("age the audit row");

    sqlx::query(
        r#"CREATE OR REPLACE FUNCTION talos_test_block_session_delete() RETURNS trigger
           LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''blocked by test''; END;'"#,
    )
    .execute(&pool)
    .await
    .expect("create blocking function");
    sqlx::query(
        "CREATE TRIGGER talos_test_block_session_delete BEFORE DELETE ON user_sessions \
         FOR EACH ROW EXECUTE FUNCTION talos_test_block_session_delete()",
    )
    .execute(&pool)
    .await
    .expect("install blocking trigger");

    let revoke_failed_before = reuse(TokenReuseOutcome::RevokeFailed);
    let detected_before = reuse(TokenReuseOutcome::Detected);
    let sessions_before = live_sessions(&pool, user).await;
    let err = auth
        .refresh_access_token(&t5)
        .await
        .expect_err("a replayed token is refused");
    assert!(
        err.to_string().contains("Invalid or expired refresh token"),
        "a failed response must not change the caller's answer either"
    );
    assert_eq!(
        reuse(TokenReuseOutcome::RevokeFailed) - revoke_failed_before,
        1.0,
        "a detection whose revoke failed must be counted as revoke_failed"
    );
    assert_eq!(
        reuse(TokenReuseOutcome::Detected) - detected_before,
        0.0,
        "and must NOT be counted as a completed response — the thief's own \
         session is still alive"
    );
    assert_eq!(
        live_sessions(&pool, user).await,
        sessions_before,
        "the response provably did not happen"
    );
    sqlx::query("DROP TRIGGER talos_test_block_session_delete ON user_sessions")
        .execute(&pool)
        .await
        .expect("drop blocking trigger");

    // The control for the whole binary: the two families are separate, and
    // between them they carry every arm the control can take.
    assert_eq!(TokenReuseOutcome::ALL.len(), 5);
    assert_eq!(RotationAuditArmOutcome::ALL.len(), 2);
}
