//! `ADAPTIVE_RANK_LOOKBACK_DAYS` is documented in two places as a training
//! window clamped to `[1, 3650]` days. A hardcoded row cap
//! (`talos_memory_ranking::TRAINING_FETCH_CAP`, 20 000) binds first, and the
//! Phase-1 fetch is `ORDER BY created_at DESC LIMIT $cap`, so widening the
//! window adds only OLDER rows — which sort last and are never read.
//!
//! Measured on the reference fleet 2026-09-09 for the one truncating actor
//! (~2 900 provenance rows/day): the configured 30-day window was a fitted
//! **6.56 days**, and the fetched row set was byte-identical at 7, 30, 60, 90,
//! 365 and 3650 days. The knob is effective DOWNWARD only.
//!
//! The disclosure that already existed is denominated in ROWS, and its counts
//! MOVE when the inert knob is turned: raising 30 → 90 grows
//! `window_rows_dropped` from 52 642 to 90 805 while the fitted coefficients do
//! not change a bit, which reads as the change taking effect. So the fit now
//! also records the window in DAYS, and this binary pins the READ that carries
//! it to the operator digest.
//!
//! **Why a DB test and not a unit test.** `recent_rank_fits` is a
//! `sqlx::query_as` over a runtime `&str` (check 88's class): nothing type-checks
//! its JSON path expressions, so a projection that quietly yields NULL — the
//! shape of mutation M8 in `AGENT_NOTES.md` — compiles, ships, and renders the
//! window as "unknown" on every fit. Every pure half of this disclosure is
//! covered by unit tests in `talos-memory-ranking` and `talos-operator-digest`;
//! this is the half neither of them can see.
//!
//! `mod common` (DATABASE_URL) harness, so CTRL_TESTS and not TC_TESTS (64b).

mod common;

use chrono::Utc;
use talos_actor_repository::ActorRepository;
use uuid::Uuid;

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, email: &str) -> Uuid {
    sqlx::query_scalar("INSERT INTO users (email, password_hash) VALUES ($1, 'x') RETURNING id")
        .bind(email)
        .fetch_one(pool)
        .await
        .expect("seed user")
}

/// Seed one actor carrying a stored rank model. `fetch` is the `fetch` object
/// verbatim, so a test can seed a PRE-DISCLOSURE artifact (no `fetch` key at
/// all) as easily as a current one.
async fn seed_actor_with_model(
    pool: &sqlx::Pool<sqlx::Postgres>,
    user_id: Uuid,
    name: &str,
    fetch: Option<serde_json::Value>,
) -> Uuid {
    let mut model = serde_json::json!({
        "w_relevance": 0.8, "w_recency": 0.9, "w_importance": 1.3, "w_access": 1.1,
        "bias": 1.5,
        "feature_mean": [0.5, 0.7, 0.9, 0.9],
        "feature_std": [0.1, 0.3, 0.1, 0.2],
        "n_examples": 20_000,
        "fitted_at": Utc::now(),
    });
    if let Some(f) = fetch {
        model["fetch"] = f;
    }
    sqlx::query_scalar(
        "INSERT INTO actors (user_id, name, status, metadata) \
         VALUES ($1, $2, 'active', jsonb_build_object('rank_weights', $3::jsonb)) RETURNING id",
    )
    .bind(user_id)
    .bind(name)
    .bind(serde_json::to_string(&model).expect("model json"))
    .fetch_one(pool)
    .await
    .expect("seed actor with model")
}

/// The read that carries the window to the digest must return BOTH new fields.
///
/// The control is in the same run and is the half that matters: a
/// pre-disclosure artifact — a real state, since `RankWeights.fetch` is
/// `#[serde(default)]` and every model written before #654 lacks it — must come
/// back as `None`/`None`, never as a manufactured window. A projection that
/// returned a constant would pass the first assertion and fail this one.
#[tokio::test]
async fn recent_rank_fits_carries_the_training_window_in_days() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool, &format!("rankwin-{}@example.com", Uuid::new_v4())).await;

    // A TRUNCATED fit: the live shape, 30 days configured and 6.56 seen.
    seed_actor_with_model(
        &pool,
        user,
        "rankwin-truncated",
        Some(serde_json::json!({
            "n_fetched": 20_000,
            "fetch_cap": 20_000,
            "n_available": 72_642,
            "configured_lookback_days": 30,
            "oldest_fetched_age_days": 6.56,
        })),
    )
    .await;
    // A PRE-DISCLOSURE artifact: no `fetch` object at all.
    seed_actor_with_model(&pool, user, "rankwin-legacy", None).await;

    let fits = ActorRepository::new(pool.clone())
        .recent_rank_fits(user, 7)
        .await
        .expect("recent_rank_fits must run against the real schema");
    assert_eq!(
        fits.len(),
        2,
        "both seeded models are inside the 7-day window"
    );

    let truncated = fits
        .iter()
        .find(|f| f.actor == "rankwin-truncated")
        .expect("the truncated fit");
    assert_eq!(
        truncated.configured_lookback_days,
        Some(30),
        "the knob the operator set must survive the read — without it the \
         digest cannot say the configured window was not the one used"
    );
    let oldest = truncated
        .oldest_fetched_age_days
        .expect("the oldest row's age must survive the read");
    assert!(
        (oldest - 6.56).abs() < 1e-6,
        "expected 6.56 days, got {oldest}"
    );
    // The row accounting this sits beside must still be read too.
    assert_eq!(truncated.n_fetched, Some(20_000));
    assert_eq!(truncated.n_available, Some(72_642));

    let legacy = fits
        .iter()
        .find(|f| f.actor == "rankwin-legacy")
        .expect("the pre-disclosure fit");
    assert_eq!(
        (
            legacy.configured_lookback_days,
            legacy.oldest_fetched_age_days
        ),
        (None, None),
        "a model with no `fetch` object is UNKNOWN provenance, not a complete \
         window — a projection returning a constant would pass the assertions \
         above and fail here"
    );
    assert_eq!(legacy.n_examples, 20_000, "the model itself still reads");
}

/// What the tick writes must be what the read gets back.
///
/// The two are joined only by JSON key names in a runtime `&str` — nothing in
/// the type system connects `FetchProvenance`'s serde field names to the
/// `metadata->'rank_weights'->'fetch'->>'…'` paths in `recent_rank_fits`. A
/// rename on either side is a silent NULL, which the digest renders as
/// "coverage unknown" on every fit forever.
#[tokio::test]
async fn the_stored_provenance_round_trips_through_the_digest_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool, &format!("rankrt-{}@example.com", Uuid::new_v4())).await;

    // Built by the PRODUCTION constructor, serialized by the PRODUCTION impl —
    // so the key names under test are the ones the training tick really writes.
    let fetch = talos_memory_ranking::FetchProvenance::new(
        20_000,
        20_000,
        Some(72_642),
        Some(30),
        Some(6.555),
    );
    seed_actor_with_model(
        &pool,
        user,
        "rankrt-actor",
        Some(serde_json::to_value(fetch).expect("serialize provenance")),
    )
    .await;

    let fits = ActorRepository::new(pool.clone())
        .recent_rank_fits(user, 7)
        .await
        .expect("recent_rank_fits");
    let f = fits.first().expect("the seeded fit");
    assert_eq!(f.configured_lookback_days, Some(30));
    assert!((f.oldest_fetched_age_days.expect("age") - 6.555).abs() < 1e-6);

    // And the derived disclosure agrees with the type it came from.
    assert!(fetch.truncated());
    assert!(fetch.lookback_inert(), "30 configured, 6.555 seen");
    assert!((fetch.lookback_shortfall_days().expect("shortfall") - 23.445).abs() < 1e-6);
}
