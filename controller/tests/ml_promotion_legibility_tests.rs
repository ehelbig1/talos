//! The promotion decision the platform knows but could not say (2026-07-30).
//!
//! Four defects, one theme: a model's lifecycle gate was never re-judged, and
//! every surface that reported on it described a different version than the
//! one the reader would assume. Measured on the live database before this
//! change: `inbox-classifier-personal` sat in `shadow` with `auto_advance:
//! true` since 2026-07-14, its newest STORED policy verdict was v31's
//! (2026-07-25, blaming `follow_up has 1 < 3`), 30 of its 44 versions carried
//! no verdict at all, 40 `follow_up` corrections and 161 examples had been
//! banked since — and `last_policy_eval_at` was stamped minutes ago.
//!
//! # Why these tests need a database
//!
//! The pure predicates (`talos_ml::should_evaluate`,
//! `talos_ml::classify_pending`, `loop_health`'s verdict lift) are unit-tested
//! in their own crates. What they cannot catch is the wiring: that
//! `run_policy_tick` reads the ATTEMPT clock and stamps the ROTATION cursor —
//! two columns, two SQL statements, and the entire defect was that they were
//! one. A pure test of the predicate passes just as happily when the caller
//! feeds it the wrong column. So the tick is driven for real here, against
//! rows, and the two clocks are read back separately.
//!
//! # Isolation
//!
//! check-43 isolated-DB harness (`common::isolated_db_pool`): a `CREATE
//! DATABASE … TEMPLATE` clone, dropped on scope exit. `run_policy_tick` scans
//! EVERY policy-bearing model in its database, which is another reason these
//! cannot run against a shared one.
//!
//! No test here sets `ML_POLICY_EVAL_MIN_INTERVAL_SECS`: the env is
//! process-wide and these run in parallel. Scenarios are expressed by moving
//! the stored timestamps instead, against the 3600 s default.

mod common;

use std::sync::Arc;
use talos_ml::{DatasetService, LifecycleService, ModelRegistry, VersionMetricsInput};
use uuid::Uuid;

type Pool = sqlx::Pool<sqlx::Postgres>;

fn set_master_key() {
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

async fn services(pool: &Pool) -> (LifecycleService, DatasetService) {
    set_master_key();
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    (LifecycleService::new(sm.clone()), DatasetService::new(sm))
}

async fn seed_user(pool: &Pool, id: Uuid) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(format!("{id}@ml-legibility.test"))
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_dataset(pool: &Pool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_datasets (id, user_id, name, task_type) \
         VALUES ($1, $2, $3, 'classification')",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("ds-{id}"))
    .execute(pool)
    .await
    .expect("seed dataset");
    id
}

/// A policy-bearing model — `policy_json <> '{}'` is what makes the evaluator
/// pick it up at all.
async fn seed_model(
    pool: &Pool,
    user_id: Uuid,
    name: &str,
    dataset_id: Option<Uuid>,
    state: &str,
    policy: serde_json::Value,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, dataset_id, config_json, \
                                lifecycle_state, policy_json) \
         VALUES ($1, $2, $3, 'classification', $4, '{}'::jsonb, $5, $6)",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .bind(dataset_id)
    .bind(state)
    .bind(&policy)
    .execute(pool)
    .await
    .expect("seed model");
    id
}

/// One labeled example. The features are a dummy envelope: nothing in these
/// tests decrypts them — they exist to be COUNTED (`examples_since_verdict`)
/// and to make the dataset non-empty.
async fn seed_example(pool: &Pool, dataset_id: Uuid, user_id: Uuid, label: &str, created_at: &str) {
    sqlx::query(
        "INSERT INTO ml_examples (id, dataset_id, user_id, features_enc, features_key_id, \
                                  features_format, label_json, source, created_at) \
         VALUES ($1, $2, $3, '\\x00'::bytea, $4, 3, $5::jsonb, 'correction', $6::timestamptz)",
    )
    .bind(Uuid::new_v4())
    .bind(dataset_id)
    .bind(user_id)
    .bind(Uuid::new_v4())
    .bind(serde_json::json!({ "label": label }).to_string())
    .bind(created_at)
    .execute(pool)
    .await
    .expect("seed example");
}

fn metrics_with(policy_decision: Option<serde_json::Value>) -> serde_json::Value {
    let report: talos_ml::EvalReport = serde_json::from_value(serde_json::json!({
        "accuracy": 0.8, "total": 100, "abstained": 0, "per_class": {},
        "gold": { "accuracy": 0.55, "total": 120, "abstained": 0, "per_class": {} },
    }))
    .expect("report fixture");
    talos_ml::build_version_metrics(VersionMetricsInput {
        backend: "knn-pgvector",
        holdout_fraction: 0.2,
        report: &report,
        params: &serde_json::json!({ "k": 7 }),
        backend_comparison: vec![],
        evaluator: "scheduled",
        policy_decision,
        dataset_rows: Some(500),
        embedding_model: None,
    })
}

async fn seed_version(
    pool: &Pool,
    model_id: Uuid,
    user_id: Uuid,
    metrics: &serde_json::Value,
    trained_at: &str,
) -> Uuid {
    let mut conn = pool.acquire().await.expect("acquire");
    let row = ModelRegistry::create_version(
        &mut conn,
        model_id,
        user_id,
        None,
        "knn-pgvector",
        None,
        metrics,
    )
    .await
    .expect("create version");
    drop(conn);
    sqlx::query("UPDATE ml_model_versions SET trained_at = $2::timestamptz WHERE id = $1")
        .bind(row.id)
        .bind(trained_at)
        .execute(pool)
        .await
        .expect("pin trained_at");
    row.id
}

/// The evaluator's two clocks, read back separately.
async fn clocks(
    pool: &Pool,
    model_id: Uuid,
) -> (
    Option<chrono::DateTime<chrono::Utc>>,
    Option<chrono::DateTime<chrono::Utc>>,
) {
    sqlx::query_as(
        "SELECT last_policy_eval_at, last_policy_eval_attempt_at FROM ml_models WHERE id = $1",
    )
    .bind(model_id)
    .fetch_one(pool)
    .await
    .expect("read evaluator clocks")
}

async fn backdate_attempt(pool: &Pool, model_id: Uuid, interval: &str) {
    sqlx::query(&format!(
        "UPDATE ml_models SET last_policy_eval_attempt_at = NOW() - INTERVAL '{interval}' \
         WHERE id = $1"
    ))
    .bind(model_id)
    .execute(pool)
    .await
    .expect("backdate attempt clock");
}

/// Drive one tick and require that it VISITED a specific model.
///
/// Back-to-back ticks are a test-only cadence — production runs them
/// `ML_POLICY_EVAL_INTERVAL_SECS` (600 s) apart — and they race a detail of
/// the evaluator's clean-up: the eval-not-runnable path ends in `drop(tx)`,
/// which schedules the ROLLBACK on the connection rather than awaiting it, so
/// the per-model `pg_try_advisory_xact_lock` can still be held microseconds
/// later. The next tick then takes the "another replica is evaluating this,
/// skip cleanly" branch — CORRECT behaviour that simply is not the branch
/// these tests mean to exercise.
///
/// So: retry until the model's rotation cursor moves, bounded. The retry can
/// never mask a missing stamp (that would exhaust the budget and fail); it
/// only absorbs a visit the tick legitimately declined.
async fn tick_visiting(pool: &Pool, ds: &DatasetService, ls: &LifecycleService, model_id: Uuid) {
    let (before, _) = clocks(pool, model_id).await;
    for attempt in 1..=20 {
        talos_ml::run_policy_tick(pool, ds, ls)
            .await
            .expect("policy tick");
        let (after, _) = clocks(pool, model_id).await;
        if after > before {
            return;
        }
        assert!(
            attempt < 20,
            "the evaluator never visited {model_id} in 20 ticks — the rotation cursor is \
             not being stamped"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn touch_dataset(pool: &Pool, dataset_id: Uuid, interval: &str) {
    sqlx::query(&format!(
        "UPDATE ml_datasets SET updated_at = NOW() - INTERVAL '{interval}' WHERE id = $1"
    ))
    .bind(dataset_id)
    .execute(pool)
    .await
    .expect("touch dataset");
}

// ── D1: the evaluator actually re-judges ───────────────────────────────────

/// THE defect, driven through the real tick.
///
/// Three consecutive ticks with no time passing. The ROTATION cursor must
/// advance on every one of them (that is what keeps a large fleet cycling),
/// and the ATTEMPT clock must advance exactly ONCE (that is the debounce).
/// Before the split these were the same column, so the cursor's per-tick
/// stamp kept the debounce permanently satisfied and the attempt never
/// happened at all — the state a live model sat in for five days.
#[tokio::test]
async fn repeated_ticks_advance_the_cursor_every_time_and_attempt_once() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (ls, ds) = services(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    let dataset_id = seed_dataset(&pool, user_id).await;
    let model_id = seed_model(
        &pool,
        user_id,
        "inbox-classifier-personal",
        Some(dataset_id),
        "shadow",
        serde_json::json!({ "min_examples": 50, "auto_advance": true }),
    )
    .await;

    let (c0, a0) = clocks(&pool, model_id).await;
    assert!(c0.is_none() && a0.is_none(), "a fresh model has no clocks");

    talos_ml::run_policy_tick(&pool, &ds, &ls)
        .await
        .expect("tick 1");
    let (c1, a1) = clocks(&pool, model_id).await;
    let c1 = c1.expect("the visit stamped the rotation cursor");
    let a1 = a1.expect("a never-attempted model must be evaluated on its first visit");

    tick_visiting(&pool, &ds, &ls, model_id).await;
    tick_visiting(&pool, &ds, &ls, model_id).await;
    let (c3, a3) = clocks(&pool, model_id).await;

    assert!(
        c3.expect("cursor") > c1,
        "the rotation cursor must advance on EVERY visit — it is what stops a \
         fleet larger than one tick's scan cap from starving its tail"
    );
    assert_eq!(
        a3.expect("attempt clock"),
        a1,
        "two further visits inside the debounce window must NOT re-attempt: \
         one eval per model per ML_POLICY_EVAL_MIN_INTERVAL_SECS is the storm bound"
    );
}

/// Once the debounce window has elapsed AND the dataset has been written
/// since the last attempt, the model is re-judged — while the rotation cursor
/// is only minutes old. That combination is precisely what the pre-split code
/// could not express: one column cannot be both "visited ten minutes ago" and
/// "last judged two hours ago".
#[tokio::test]
async fn a_stale_attempt_with_a_changed_dataset_is_re_judged() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (ls, ds) = services(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    let dataset_id = seed_dataset(&pool, user_id).await;
    let model_id = seed_model(
        &pool,
        user_id,
        "inbox-classifier-personal",
        Some(dataset_id),
        "shadow",
        serde_json::json!({ "min_examples": 50 }),
    )
    .await;

    talos_ml::run_policy_tick(&pool, &ds, &ls)
        .await
        .expect("tick 1");
    let (cursor_1, attempt_1) = clocks(&pool, model_id).await;
    let attempt_1 = attempt_1.expect("first visit attempts");

    // Two hours since the last attempt; the dataset was written one hour ago.
    // The cursor stays where tick 1 left it — seconds old.
    backdate_attempt(&pool, model_id, "2 hours").await;
    touch_dataset(&pool, dataset_id, "1 hour").await;

    tick_visiting(&pool, &ds, &ls, model_id).await;
    let (cursor_2, attempt_2) = clocks(&pool, model_id).await;
    let attempt_2 = attempt_2.expect("attempt clock");
    assert!(
        attempt_2 > attempt_1,
        "an hour-stale verdict over a dataset that has changed must be re-judged"
    );
    assert!(
        cursor_2.expect("cursor") > cursor_1.expect("cursor"),
        "the cursor still moves; it is simply no longer the debounce input"
    );

    // …and the dataset-change test still holds independently: an elapsed
    // window over UNCHANGED data must not spend an eval.
    backdate_attempt(&pool, model_id, "2 hours").await;
    touch_dataset(&pool, dataset_id, "3 hours").await;
    let (_, before) = clocks(&pool, model_id).await;
    tick_visiting(&pool, &ds, &ls, model_id).await;
    let (_, after) = clocks(&pool, model_id).await;
    assert_eq!(
        after, before,
        "unchanged data must not be re-scored just because an hour passed"
    );
}

/// The drift-only path must not consume the eval budget. A `fast_primary`
/// model is governed by the drift guard alone; it is VISITED (cursor moves)
/// but never ATTEMPTS an evaluation, however hot its dataset.
#[tokio::test]
async fn the_drift_only_path_does_not_spend_an_eval_attempt() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (ls, ds) = services(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    let dataset_id = seed_dataset(&pool, user_id).await;
    let model_id = seed_model(
        &pool,
        user_id,
        "fast-model",
        Some(dataset_id),
        "fast_primary",
        serde_json::json!({ "min_examples": 1, "demote_below_agreement": 0.7 }),
    )
    .await;
    touch_dataset(&pool, dataset_id, "1 second").await;

    talos_ml::run_policy_tick(&pool, &ds, &ls)
        .await
        .expect("tick");
    let (cursor, attempt) = clocks(&pool, model_id).await;
    assert!(cursor.is_some(), "the drift check DID visit the model");
    assert!(
        attempt.is_none(),
        "fast_primary is the drift guard's alone — it must never spend an eval"
    );
}

/// FAIRNESS, proved past the per-tick cap (phase 2). Two ticks must reach
/// every one of 30 policy-bearing models: the rotation cursor is what makes
/// `ORDER BY last_policy_eval_at ASC NULLS FIRST` cycle, and a model that is
/// visited without being stamped re-occupies a slot forever.
///
/// This also measures the DEPLOY TRANSIENT the two-clock split creates: every
/// pre-existing row has a NULL attempt clock, so each policy-bearing model
/// gets exactly ONE eval attempt, at most `MODELS_PER_TICK` per tick and then
/// one per `ML_POLICY_EVAL_MIN_INTERVAL_SECS` per model thereafter.
#[tokio::test]
async fn every_model_past_the_per_tick_cap_is_reached_within_two_ticks() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (ls, ds) = services(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    let cap = talos_ml::MODELS_PER_TICK;
    for i in 0..(cap + 5) {
        let dataset_id = seed_dataset(&pool, user_id).await;
        seed_model(
            &pool,
            user_id,
            &format!("m{i:03}"),
            Some(dataset_id),
            "shadow",
            serde_json::json!({ "min_examples": 50 }),
        )
        .await;
    }

    async fn stamped(pool: &Pool, column: &str) -> i64 {
        sqlx::query_scalar(&format!(
            "SELECT COUNT(*)::bigint FROM ml_models WHERE {column} IS NOT NULL"
        ))
        .fetch_one(pool)
        .await
        .expect("count stamped rows")
    }

    talos_ml::run_policy_tick(&pool, &ds, &ls)
        .await
        .expect("tick 1");
    assert_eq!(
        stamped(&pool, "last_policy_eval_at").await,
        cap,
        "one tick visits exactly MODELS_PER_TICK models"
    );
    talos_ml::run_policy_tick(&pool, &ds, &ls)
        .await
        .expect("tick 2");
    assert_eq!(
        stamped(&pool, "last_policy_eval_at").await,
        cap + 5,
        "the tail must be reached on the next tick — that is what the cursor is for"
    );
    assert_eq!(
        stamped(&pool, "last_policy_eval_attempt_at").await,
        cap + 5,
        "the deploy transient is exactly one attempt per model, spread over ceil(n/cap) ticks"
    );
}

/// A model whose `policy_json` does not PARSE must still rotate. It used not
/// to: the skip returned before the cursor stamp, so such a model kept a NULL
/// cursor and — sorting `NULLS FIRST` — re-took a slot of the LIMIT window on
/// every tick. Measured at 26 unparseable models plus one healthy one: the
/// healthy model was visited once and then never again across four further
/// ticks, so the drift guard AND the policy evaluator stopped for the whole
/// tenant. Skipping the MODEL is right; skipping the ROTATION starves its
/// neighbours.
#[tokio::test]
async fn an_unparseable_policy_cannot_starve_its_neighbours() {
    let (pool, _db) = common::isolated_db_pool().await;
    let (ls, ds) = services(&pool).await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    for i in 0..(talos_ml::MODELS_PER_TICK + 1) {
        let dataset_id = seed_dataset(&pool, user_id).await;
        seed_model(
            &pool,
            user_id,
            &format!("bad{i:03}"),
            Some(dataset_id),
            "shadow",
            // Non-empty (so the evaluator picks it up) and unparseable
            // (`PolicyJson` is deny_unknown_fields).
            serde_json::json!({ "totally_bogus_key": i }),
        )
        .await;
    }
    let healthy_ds = seed_dataset(&pool, user_id).await;
    let healthy = seed_model(
        &pool,
        user_id,
        "zz-healthy",
        Some(healthy_ds),
        "shadow",
        serde_json::json!({ "min_examples": 50 }),
    )
    .await;

    // Enough ticks to visit everything at least once, then more.
    for _ in 0..3 {
        talos_ml::run_policy_tick(&pool, &ds, &ls)
            .await
            .expect("tick");
    }
    let (first, _) = clocks(&pool, healthy).await;
    let first = first.expect("the healthy model is reached at all");
    for _ in 0..3 {
        talos_ml::run_policy_tick(&pool, &ds, &ls)
            .await
            .expect("tick");
    }
    let (last, _) = clocks(&pool, healthy).await;
    assert!(
        last.expect("cursor") > first,
        "a model that cannot be evaluated must still rotate, or it starves every \
         model behind it in the cursor order"
    );
}

// ── D3: what the report says about which version ───────────────────────────

/// The loop-health panel must carry the newest STORED verdict — which is
/// usually neither the promoted nor the latest version — with its own version,
/// its own date, and its reasons byte-for-byte.
#[tokio::test]
async fn loop_health_surfaces_the_newest_stored_verdict_with_its_own_identity() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    let dataset_id = seed_dataset(&pool, user_id).await;
    let model_id = seed_model(
        &pool,
        user_id,
        "inbox-classifier-personal",
        Some(dataset_id),
        "shadow",
        serde_json::json!({ "min_corrections_per_class": 3, "auto_advance": true }),
    )
    .await;

    let unmet = "min_corrections_per_class: 'follow_up' has 1 < 3";
    // v1 judged; v2 and v3 recorded with no verdict — the live 30-of-44 shape.
    let judged = seed_version(
        &pool,
        model_id,
        user_id,
        &metrics_with(Some(
            serde_json::json!({ "satisfied": false, "unmet": [unmet] }),
        )),
        "2026-07-25T09:30:00Z",
    )
    .await;
    for at in ["2026-07-27T09:30:00Z", "2026-07-29T09:30:00Z"] {
        seed_version(&pool, model_id, user_id, &metrics_with(None), at).await;
    }
    let mut conn = pool.acquire().await.expect("acquire");
    ModelRegistry::promote_version(&mut conn, model_id, judged)
        .await
        .expect("promote v1");
    drop(conn);

    let health = talos_ml::loop_health(&pool, user_id)
        .await
        .expect("loop health");
    let m = &health["models"].as_array().expect("models")[0];

    let verdict = &m["policy_verdict"];
    assert_eq!(verdict["source_version"], 1);
    assert_eq!(verdict["measured_at"], "2026-07-25T09:30:00.000Z");
    assert_eq!(verdict["satisfied"], false);
    assert_eq!(verdict["unmet"][0], unmet, "reasons are copied verbatim");
    assert_eq!(
        verdict["versions_since_verdict"], 2,
        "two evaluations have been recorded since the last judged one"
    );

    // D3a: a `shadow` model serves NOTHING, and the note must say so.
    assert_eq!(m["serves_production"], false);
    let serving_note = m["gold_promoted_serving_note"].as_str().expect("note");
    assert!(serving_note.contains("SERVES NOTHING"), "{serving_note}");
    assert!(
        !m["gold_provenance_note"]
            .as_str()
            .expect("note")
            .to_ascii_lowercase()
            .contains("always the serving"),
        "the provenance note must not assert serving for a shadow model"
    );

    // D3c: the shadow agreement is annotated with the version it measures —
    // the PROMOTED one (v1), not the latest (v3) whose numbers sit in `gold`.
    assert_eq!(m["shadow"]["measures_version"], 1);
    assert_eq!(m["latest_version"], 3);
    assert!(m["shadow"]["note"]
        .as_str()
        .expect("shadow note")
        .contains("PROMOTED version"));
}

/// Phase 2: `serves_production` must answer with BOTH conditions the serving
/// path checks. `ml_set_lifecycle` will advance a never-promoted model all the
/// way to `hybrid`, where it passes the lifecycle gate and still serves
/// nothing — `serve_predict_batch` fails `NotPromoted`. Reporting the gate
/// alone would assert a serving claim the code does not check, which is the
/// exact class this change exists to retire.
#[tokio::test]
async fn a_hybrid_model_with_no_promoted_version_is_not_reported_as_serving() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    let dataset_id = seed_dataset(&pool, user_id).await;
    let model_id = seed_model(
        &pool,
        user_id,
        "advanced-but-never-promoted",
        Some(dataset_id),
        "hybrid",
        serde_json::json!({ "min_examples": 50 }),
    )
    .await;
    // A version EXISTS — it was simply never promoted, so
    // production_version_id stays NULL.
    seed_version(
        &pool,
        model_id,
        user_id,
        &metrics_with(None),
        "2026-07-29T09:30:00Z",
    )
    .await;

    let health = talos_ml::loop_health(&pool, user_id)
        .await
        .expect("loop health");
    let m = &health["models"].as_array().expect("models")[0];
    assert_eq!(m["lifecycle_state"], "hybrid");
    assert!(m["promoted_version"].is_null());
    assert_eq!(
        m["serves_production"], false,
        "the lifecycle gate passes, but there is nothing to serve: {m}"
    );
    let note = m["gold_promoted_serving_note"].as_str().expect("note");
    assert!(note.contains("SERVES NOTHING"), "{note}");
    assert!(note.contains("NO promoted version"), "{note}");
}

/// A model no version of which has ever been judged must render "not
/// evaluated" — never a verdict. This is the majority state on the live
/// system, so a default here would be wrong most of the time.
#[tokio::test]
async fn an_unjudged_model_renders_a_null_verdict_not_an_unsatisfied_one() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    let dataset_id = seed_dataset(&pool, user_id).await;
    let model_id = seed_model(
        &pool,
        user_id,
        "never-judged",
        Some(dataset_id),
        "shadow",
        serde_json::json!({ "min_examples": 50 }),
    )
    .await;
    seed_version(
        &pool,
        model_id,
        user_id,
        &metrics_with(None),
        "2026-07-29T09:30:00Z",
    )
    .await;

    let health = talos_ml::loop_health(&pool, user_id)
        .await
        .expect("loop health");
    let m = &health["models"].as_array().expect("models")[0];
    assert!(
        m["policy_verdict"].is_null(),
        "absent means not evaluated: {m}"
    );
    assert!(m["policy_verdict_note"]
        .as_str()
        .expect("note")
        .contains("never 'satisfied' and never 'unsatisfied'"));
}

// ── D4: the parked decision reaches needs_me ───────────────────────────────

/// The measured live state, end to end: a stale verdict over banked evidence
/// becomes ONE item naming the model, the version, the date, the count and the
/// stored reasons.
#[tokio::test]
async fn a_stale_verdict_over_new_evidence_becomes_one_needs_me_item() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    let dataset_id = seed_dataset(&pool, user_id).await;
    let model_id = seed_model(
        &pool,
        user_id,
        "inbox-classifier-personal",
        Some(dataset_id),
        "shadow",
        serde_json::json!({ "min_corrections_per_class": 3, "auto_advance": true }),
    )
    .await;
    let unmet = "min_corrections_per_class: 'follow_up' has 1 < 3";
    seed_version(
        &pool,
        model_id,
        user_id,
        &metrics_with(Some(
            serde_json::json!({ "satisfied": false, "unmet": [unmet] }),
        )),
        "2026-07-25T09:30:00Z",
    )
    .await;
    // Two examples banked BEFORE the verdict (already accounted for) and
    // three after (the evidence nothing has re-judged).
    for at in ["2026-07-20T09:30:00Z", "2026-07-24T09:30:00Z"] {
        seed_example(&pool, dataset_id, user_id, "follow_up", at).await;
    }
    for at in [
        "2026-07-26T09:30:00Z",
        "2026-07-27T09:30:00Z",
        "2026-07-28T09:30:00Z",
    ] {
        seed_example(&pool, dataset_id, user_id, "follow_up", at).await;
    }

    let items = talos_ml::pending_ml_decisions(&pool, user_id, 10)
        .await
        .expect("pending ml decisions");
    assert_eq!(items.len(), 1, "one model, one item: {items:?}");
    let item = &items[0];
    assert_eq!(item.kind, talos_ml::PendingKind::VerdictStale);
    assert_eq!(item.verdict_version, Some(1));
    assert_eq!(
        item.examples_since_verdict, 3,
        "only rows created AFTER the verdict count as unjudged evidence"
    );
    assert_eq!(item.unmet, vec![unmet.to_string()]);
    assert!(item.next_action().contains(unmet));
    assert!(item.next_action().contains("3 labeled examples"));
}

/// A model whose verdict is CURRENT parks no decision, and neither does a
/// `fast_primary` model (whose policy is never re-judged by design). The panel
/// must not grow with every healthy model.
#[tokio::test]
async fn current_verdicts_and_fast_primary_models_park_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;

    let healthy_ds = seed_dataset(&pool, user_id).await;
    let healthy = seed_model(
        &pool,
        user_id,
        "a-healthy",
        Some(healthy_ds),
        "shadow",
        serde_json::json!({ "min_examples": 50, "auto_advance": true }),
    )
    .await;
    seed_version(
        &pool,
        healthy,
        user_id,
        &metrics_with(Some(
            serde_json::json!({ "satisfied": false, "unmet": ["min_examples: 3 < 50"] }),
        )),
        "2026-07-29T09:30:00Z",
    )
    .await;
    seed_example(&pool, healthy_ds, user_id, "x", "2026-07-28T09:30:00Z").await;

    let fast_ds = seed_dataset(&pool, user_id).await;
    let fast = seed_model(
        &pool,
        user_id,
        "b-fast",
        Some(fast_ds),
        "fast_primary",
        serde_json::json!({ "min_examples": 1 }),
    )
    .await;
    seed_version(
        &pool,
        fast,
        user_id,
        &metrics_with(Some(serde_json::json!({ "satisfied": true, "unmet": [] }))),
        "2026-07-01T09:30:00Z",
    )
    .await;
    seed_example(&pool, fast_ds, user_id, "x", "2026-07-28T09:30:00Z").await;

    let items = talos_ml::pending_ml_decisions(&pool, user_id, 10)
        .await
        .expect("pending ml decisions");
    assert!(
        items.is_empty(),
        "a current verdict and a fast_primary model are both working as \
         designed: {items:?}"
    );
}

/// A satisfied gate with `auto_advance` off is the decision the platform
/// deliberately refuses to make — and the one `ml_lifecycle_policy_satisfied`
/// had no consumer for.
#[tokio::test]
async fn a_satisfied_gate_with_auto_advance_off_is_listed_as_the_operators_call() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id).await;
    let dataset_id = seed_dataset(&pool, user_id).await;
    let model_id = seed_model(
        &pool,
        user_id,
        "cleared-model",
        Some(dataset_id),
        "shadow",
        serde_json::json!({ "min_examples": 1, "auto_advance": false }),
    )
    .await;
    seed_version(
        &pool,
        model_id,
        user_id,
        &metrics_with(Some(serde_json::json!({ "satisfied": true, "unmet": [] }))),
        "2026-07-29T09:30:00Z",
    )
    .await;

    let items = talos_ml::pending_ml_decisions(&pool, user_id, 10)
        .await
        .expect("pending ml decisions");
    assert_eq!(items.len(), 1);
    assert_eq!(
        items[0].kind,
        talos_ml::PendingKind::PolicySatisfiedAwaitingHuman
    );
    let action = items[0].next_action();
    assert!(action.contains("shadow -> hybrid"), "{action}");
    assert!(action.contains("The decision is yours."), "{action}");
}

/// Tenancy: the reader is scoped by `user_id` like every other reader in this
/// crate. Another tenant's parked decision must not appear in this operator's
/// inbox.
#[tokio::test]
async fn pending_decisions_are_scoped_to_their_owner() {
    let (pool, _db) = common::isolated_db_pool().await;
    let mine = Uuid::new_v4();
    let theirs = Uuid::new_v4();
    seed_user(&pool, mine).await;
    seed_user(&pool, theirs).await;

    let ds = seed_dataset(&pool, theirs).await;
    let m = seed_model(
        &pool,
        theirs,
        "their-model",
        Some(ds),
        "shadow",
        serde_json::json!({ "min_examples": 1, "auto_advance": false }),
    )
    .await;
    seed_version(
        &pool,
        m,
        theirs,
        &metrics_with(Some(serde_json::json!({ "satisfied": true, "unmet": [] }))),
        "2026-07-29T09:30:00Z",
    )
    .await;

    assert_eq!(
        talos_ml::pending_ml_decisions(&pool, theirs, 10)
            .await
            .expect("owner sees it")
            .len(),
        1
    );
    assert!(
        talos_ml::pending_ml_decisions(&pool, mine, 10)
            .await
            .expect("other tenant")
            .is_empty(),
        "another tenant's parked decision must never reach this inbox"
    );
}
