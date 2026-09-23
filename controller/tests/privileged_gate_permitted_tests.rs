//! The privileged gate's ADMITTING outcome, on the production path (package
//! DY, 2026-09-23).
//!
//! `talos-api`'s own unit tests drive five of the seven
//! `PrivilegedOpOutcome` values through a real `async_graphql` schema, but
//! every one of them is a refusal: the two that need a real `users` row —
//! `permitted` and `not_enrolled` — are only reachable once the gate's
//! enrolment read can actually answer.
//!
//! That gap is not cosmetic, and it was MEASURED rather than assumed: a
//! mutation narrowing the recorder to `if !outcome.permitted()` SURVIVED the
//! whole talos-api suite. Counting only refusals is precisely the defect this
//! package exists to remove — it leaves the refusal rate with no denominator,
//! so a deployment nobody has been refused on and one whose gate is not wired
//! render identically, which is the reading the series was added to make
//! impossible. These two tests are what close it.
//!
//! DB tests on the `common` harness, so CTRL_TESTS, not TC_TESTS (64b).

mod common;

use async_graphql::{Context, EmptyMutation, EmptySubscription, Object, Result, Schema};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use talos_api::schema::{require_second_factor, IsTwoFactorVerified, SecondFactorVerified};
use talos_auth::AuthService;
use talos_metrics::PrivilegedOpOutcome as O;
use uuid::Uuid;

/// Stands in for any of the fifteen privileged mutations: it calls the same
/// gate, by the same name, with the same context data a resolver has.
struct PrivilegedQuery;

#[Object]
impl PrivilegedQuery {
    async fn rotate_something(&self, ctx: &Context<'_>) -> Result<bool> {
        require_second_factor(ctx).await?;
        Ok(true)
    }
}

async fn seed_user(pool: &Pool<Postgres>, enrolled: bool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'dy')")
        .bind(id)
        .bind(format!("dy-privileged-{id}@example.com"))
        .execute(pool)
        .await
        .expect("seed user");
    sqlx::query("UPDATE users SET totp_enabled = $2 WHERE id = $1")
        .bind(id)
        .bind(enrolled)
        .execute(pool)
        .await
        .expect("set enrolment");
    id
}

/// The registry is process-global and both tests here read absolute values,
/// so they must not interleave — the same lesson the throttle recorder test
/// taught inside `talos-api`: a test that passes alone and fails beside its
/// sibling is measuring the sibling, not the code.
static SERIES_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn metrics() -> &'static Arc<talos_metrics::TalosMetrics> {
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("registry"));
    talos_metrics::global().expect("installed")
}

fn read(m: &talos_metrics::TalosMetrics, o: O) -> u64 {
    m.privileged_op_total
        .with_label_values(&[o.as_str()])
        .get()
        .round() as u64
}

/// Drive the gate for `user` with a session that proved its second factor,
/// against a real `AuthService` reading a real row.
async fn run_gate(pool: &Pool<Postgres>, user: Uuid) -> async_graphql::Response {
    let auth = AuthService::new(
        pool.clone(),
        "test-secret-key-for-testing-only-min-32-chars".to_string(),
        10,
        None,
    )
    .expect("auth service");
    let schema = Schema::build(PrivilegedQuery, EmptyMutation, EmptySubscription).finish();
    schema
        .execute(
            async_graphql::Request::new("{ rotateSomething }")
                .data(IsTwoFactorVerified(true))
                .data(SecondFactorVerified(true))
                .data(user)
                .data(Arc::new(auth)),
        )
        .await
}

/// THE DENOMINATOR. An admitted privileged call must move `permitted`, and
/// must move nothing else — without this, a recorder narrowed to refusals is
/// invisible to every other test in this package.
#[tokio::test]
async fn an_admitted_privileged_call_is_counted_as_permitted() {
    let _guard = SERIES_LOCK.lock().await;
    let ctx = common::setup_test_context().await;
    let user = seed_user(&ctx.db_pool, true).await;
    let m = metrics();

    let before: Vec<(O, u64)> = O::ALL.iter().map(|o| (*o, read(m, *o))).collect();
    let res = run_gate(&ctx.db_pool, user).await;
    assert!(
        res.errors.is_empty(),
        "a verified, still-enrolled session must be admitted: {:?}",
        res.errors
    );

    for (o, b) in before {
        let want = u64::from(o.as_str() == O::Permitted.as_str());
        assert_eq!(
            read(m, o) - b,
            want,
            "outcome {}: expected delta {want}",
            o.as_str()
        );
    }
}

/// The other outcome a real row makes reachable: the session verified a second
/// factor, and the account no longer has one enrolled. Refused — the privilege
/// is withdrawn at once rather than when the session expires — and counted as
/// its own reason, not folded into `not_verified` (which would send an
/// operator looking at the session instead of the account).
#[tokio::test]
async fn a_withdrawn_enrolment_is_counted_as_not_enrolled() {
    let _guard = SERIES_LOCK.lock().await;
    let ctx = common::setup_test_context().await;
    let user = seed_user(&ctx.db_pool, false).await;
    let m = metrics();

    let before_not_enrolled = read(m, O::NotEnrolled);
    let before_permitted = read(m, O::Permitted);
    let res = run_gate(&ctx.db_pool, user).await;
    assert_eq!(
        res.errors.len(),
        1,
        "an account with no second factor enrolled must be refused"
    );
    assert_eq!(read(m, O::NotEnrolled), before_not_enrolled + 1);
    assert_eq!(
        read(m, O::Permitted),
        before_permitted,
        "a refusal must never move the admitting value"
    );
}
