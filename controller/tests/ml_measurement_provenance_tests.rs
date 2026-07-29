//! #609's closing integration test: a promoted version's numbers must be
//! attributed to the PROMOTED version, against a real database.
//!
//! # Why this exists
//!
//! #588 was an accuracy attributed to the wrong model version. #608 built the
//! measurement envelope; #609 wired it into the ML readers. Both landed with
//! PURE unit tests over the envelope builders — which cannot catch the defect
//! class they were written for, because the mis-attribution happens in the
//! SQL: `list_models_for_review` joins `ml_model_versions` on
//! `m.production_version_id`, and every provenance column it projects
//! (`version`, `backend`, `trained_at`, `metrics_json #>> '{report,total}'`)
//! comes off that joined row. Swap the join to the LATEST version — or let a
//! future "helpful" `ORDER BY version DESC LIMIT 1` creep in — and every unit
//! test still passes while the card confidently reports the newest eval's
//! numbers under the serving version's name. #609's review left two surviving
//! mutations for exactly this reason (its E and D).
//!
//! # The seed
//!
//! One model, two versions, and the PROMOTED one is the OLDER one — the
//! configuration that makes "promoted" and "latest" distinguishable. Every
//! value that could be confused between the two rows is DISTINCT: accuracy,
//! `report.total`, gold accuracy, gold total, `trained_at`, `dataset_rows`,
//! and backend. So a swapped expectation cannot pass by coincidence; there is
//! no field on which the two versions agree.
//!
//! # Isolation
//!
//! Runs on the check-43 isolated-DB harness (`common::isolated_db_pool`): a
//! `CREATE DATABASE … TEMPLATE` clone of the migrated template, dropped on
//! scope exit. Nothing is written to the template or to any shared database.

mod common;

use serde_json::json;
use talos_ml::{ModelRegistry, VersionMetricsInput};
use uuid::Uuid;

// ── The seed's pinned values ────────────────────────────────────────────────
//
// Pairwise distinct on purpose (see the module docs). Named rather than
// inlined so a reader can see at a glance that no two are equal.

/// v1 — the OLDER version, and the one that gets PROMOTED.
const PROMOTED_ACCURACY: f64 = 0.42;
const PROMOTED_TOTAL: i64 = 137;
const PROMOTED_GOLD_ACCURACY: f64 = 0.094;
const PROMOTED_GOLD_TOTAL: i64 = 44;
const PROMOTED_DATASET_ROWS: i64 = 611;
const PROMOTED_BACKEND: &str = "knn-pgvector";
const PROMOTED_TRAINED_AT: &str = "2026-03-11T08:15:00Z";
const PROMOTED_TRAINED_AT_RFC: &str = "2026-03-11T08:15:00.000Z";
const PROMOTED_MEASURED_AT: &str = "2026-03-11T08:14:52.500Z";

/// v2 — the NEWER version. Evaluated, never promoted.
const LATEST_ACCURACY: f64 = 0.87;
const LATEST_TOTAL: i64 = 402;
const LATEST_GOLD_ACCURACY: f64 = 0.486;
const LATEST_GOLD_TOTAL: i64 = 35;
const LATEST_DATASET_ROWS: i64 = 908;
// Both backends must satisfy `ml_model_versions_backend_check`; they are
// different so a mis-attributed row is visible on this axis too.
const LATEST_BACKEND: &str = "logistic-regression";
const LATEST_TRAINED_AT: &str = "2026-07-27T16:45:00Z";
const LATEST_TRAINED_AT_RFC: &str = "2026-07-27T16:45:00.000Z";
const LATEST_MEASURED_AT: &str = "2026-07-27T16:44:31.250Z";

async fn seed_user(pool: &sqlx::Pool<sqlx::Postgres>, id: Uuid, email: &str) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) \
         VALUES ($1, $2, 'not-a-real-hash', true) ON CONFLICT (id) DO NOTHING",
    )
    .bind(id)
    .bind(email)
    .execute(pool)
    .await
    .expect("seed user");
}

async fn seed_model(pool: &sqlx::Pool<sqlx::Postgres>, user_id: Uuid, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, config_json, lifecycle_state) \
         VALUES ($1, $2, $3, 'classification', '{}'::jsonb, 'shadow')",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed model");
    id
}

/// Build a version's `metrics_json` through the PRODUCTION assembly point
/// (`build_version_metrics`), not a hand-written blob.
///
/// This is what makes assertion (e) meaningful: `dataset_rows` and
/// `measured_at` reach the row the same way a real eval puts them there, so a
/// regression in the stamping (a dropped key, a `now()` substitution) fails
/// here instead of being papered over by a test fixture that stamps them
/// itself.
fn stamped_metrics(
    accuracy: f64,
    total: i64,
    gold_accuracy: f64,
    gold_total: i64,
    dataset_rows: i64,
    backend: &str,
    measured_at: &str,
) -> serde_json::Value {
    let report_json = json!({
        "accuracy": accuracy,
        "total": total,
        "abstained": 0,
        "per_class": {},
        "measured_at": measured_at,
        "gold": {
            "accuracy": gold_accuracy,
            "total": gold_total,
            "abstained": 0,
            "per_class": {},
            "measured_at": measured_at,
        },
    });
    let report: talos_ml::EvalReport =
        serde_json::from_value(report_json).expect("report fixture parses as an EvalReport");
    talos_ml::build_version_metrics(VersionMetricsInput {
        backend,
        holdout_fraction: 0.2,
        report: &report,
        params: &json!({ "k": 9 }),
        backend_comparison: vec![json!({ "backend": backend, "macro_f1": accuracy })],
        evaluator: "manual",
        policy_decision: None,
        dataset_rows: Some(dataset_rows),
        embedding_model: Some("nomic-embed-text".to_string()),
    })
}

/// Create a version through the production writer, then pin its `trained_at`.
///
/// `create_version` is the real write path (advisory lock, `MAX(version) + 1`,
/// artifact sha) and stamps `trained_at` from the DB's `NOW()`. The READ side
/// is what this test is about, so the timestamp is then set to a fixed instant
/// — otherwise "the promoted row's date" and "the latest row's date" would be
/// milliseconds apart and a mis-attribution would be invisible.
async fn seed_version(
    pool: &sqlx::Pool<sqlx::Postgres>,
    model_id: Uuid,
    user_id: Uuid,
    backend: &str,
    metrics: &serde_json::Value,
    trained_at: &str,
) -> Uuid {
    let mut conn = pool.acquire().await.expect("acquire");
    let row =
        ModelRegistry::create_version(&mut conn, model_id, user_id, None, backend, None, metrics)
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

/// The full seed: one model, v1 (older) promoted, v2 (newer) not.
async fn seed_promoted_older_than_latest(
    pool: &sqlx::Pool<sqlx::Postgres>,
    user_id: Uuid,
    model_name: &str,
) -> (Uuid, Uuid, Uuid) {
    let model_id = seed_model(pool, user_id, model_name).await;
    let v1 = seed_version(
        pool,
        model_id,
        user_id,
        PROMOTED_BACKEND,
        &stamped_metrics(
            PROMOTED_ACCURACY,
            PROMOTED_TOTAL,
            PROMOTED_GOLD_ACCURACY,
            PROMOTED_GOLD_TOTAL,
            PROMOTED_DATASET_ROWS,
            PROMOTED_BACKEND,
            PROMOTED_MEASURED_AT,
        ),
        PROMOTED_TRAINED_AT,
    )
    .await;
    let v2 = seed_version(
        pool,
        model_id,
        user_id,
        LATEST_BACKEND,
        &stamped_metrics(
            LATEST_ACCURACY,
            LATEST_TOTAL,
            LATEST_GOLD_ACCURACY,
            LATEST_GOLD_TOTAL,
            LATEST_DATASET_ROWS,
            LATEST_BACKEND,
            LATEST_MEASURED_AT,
        ),
        LATEST_TRAINED_AT,
    )
    .await;

    // Promote the OLDER one. This is the whole point of the fixture: after
    // this, `production_version_id` and "the newest version" disagree.
    let mut conn = pool.acquire().await.expect("acquire");
    ModelRegistry::promote_version(&mut conn, model_id, v1)
        .await
        .expect("promote v1");
    drop(conn);

    (model_id, v1, v2)
}

// ── (a) + (d) ───────────────────────────────────────────────────────────────

/// #609 mutation E. The review surface's envelope must describe the SERVING
/// version, and the assertion has to be over every provenance field at once —
/// a reader who trusts `n` but not `measured_at` has learned nothing.
///
/// Assertion (d) rides here too: `n` comes from
/// `(v.metrics_json #>> '{report,total}')::int8`, a jsonb-path projection with
/// an int8 cast that no test exercised before this one. A typo in the path or
/// a cast that silently NULLs would previously have shipped as a missing
/// envelope, which is invisible (the field is `skip_serializing_if`-omitted).
#[tokio::test]
async fn review_envelope_describes_the_promoted_version_not_the_latest() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "review@ml-provenance.test").await;
    let (model_id, _v1, _v2) =
        seed_promoted_older_than_latest(&pool, user_id, "inbox-classifier").await;

    let mut conn = pool.acquire().await.expect("acquire");
    let rows = ModelRegistry::list_models_for_review(&mut conn, user_id)
        .await
        .expect("list models for review");
    let row = rows
        .iter()
        .find(|r| r.model_id == model_id)
        .expect("the seeded model is listed");

    // The bare float (the live GraphQL/frontend column) is the promoted one.
    assert_eq!(row.promoted_version, Some(1), "v1 is the serving version");
    assert_eq!(row.promoted_accuracy, Some(PROMOTED_ACCURACY));
    assert_ne!(
        row.promoted_accuracy,
        Some(LATEST_ACCURACY),
        "the latest version's accuracy must never appear here"
    );
    assert_eq!(row.promoted_backend.as_deref(), Some(PROMOTED_BACKEND));

    let m = row
        .promoted_accuracy_measurement
        .as_ref()
        .expect("a promoted version with a report.total must carry an envelope");
    assert_eq!(m.value, PROMOTED_ACCURACY);
    // (d): the `#>> '{report,total}'` int8 projection, exercised.
    assert_eq!(
        m.n, PROMOTED_TOTAL as u64,
        "n must be the PROMOTED version's report.total ({PROMOTED_TOTAL}), not the latest's ({LATEST_TOTAL})"
    );
    assert_eq!(m.source_version.as_deref(), Some("v1"));
    assert_eq!(
        m.measured_at.as_deref(),
        Some(PROMOTED_TRAINED_AT_RFC),
        "measured_at must be the promoted row's trained_at"
    );
    assert_ne!(m.measured_at.as_deref(), Some(LATEST_TRAINED_AT_RFC));
    // The interval is real, and it is the interval for THIS denominator.
    let ci = m.ci95.expect("a rate envelope carries its Wilson interval");
    assert!(
        ci[0] < PROMOTED_ACCURACY && ci[1] > PROMOTED_ACCURACY,
        "{ci:?}"
    );
    assert!(m.population.is_some(), "the population must be stated");
}

/// An UNPROMOTED model gets no envelope at all — never one built from
/// whichever version happens to be newest, and never a fabricated zero.
#[tokio::test]
async fn an_unpromoted_model_carries_no_envelope() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "unpromoted@ml-provenance.test").await;
    let model_id = seed_model(&pool, user_id, "never-promoted").await;
    seed_version(
        &pool,
        model_id,
        user_id,
        LATEST_BACKEND,
        &stamped_metrics(
            LATEST_ACCURACY,
            LATEST_TOTAL,
            LATEST_GOLD_ACCURACY,
            LATEST_GOLD_TOTAL,
            LATEST_DATASET_ROWS,
            LATEST_BACKEND,
            LATEST_MEASURED_AT,
        ),
        LATEST_TRAINED_AT,
    )
    .await;

    let mut conn = pool.acquire().await.expect("acquire");
    let rows = ModelRegistry::list_models_for_review(&mut conn, user_id)
        .await
        .expect("list models for review");
    let row = rows
        .iter()
        .find(|r| r.model_id == model_id)
        .expect("the model is listed even unpromoted");
    assert_eq!(row.promoted_version, None);
    assert_eq!(row.promoted_accuracy, None);
    assert!(
        row.promoted_accuracy_measurement.is_none(),
        "an unpromoted model must not borrow the latest version's numbers"
    );
    // …and the key is OMITTED from JSON rather than nulled.
    let v = serde_json::to_value(row).expect("serialize summary");
    assert!(
        v.get("promoted_accuracy_measurement").is_none(),
        "absent means not measured; a null reads as 0.0 to half the consumers: {v}"
    );
}

// ── (b) ─────────────────────────────────────────────────────────────────────

/// The loop-health panel's two gold arms must each advertise their OWN
/// identity. `gold` answers "are corrections being learned right now" (latest);
/// `gold_promoted` answers "what does the thing that actually runs score"
/// (promoted). Presenting either under the other's version/date is #588 one
/// level down.
#[tokio::test]
async fn loop_health_arms_carry_their_own_identity() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "loop@ml-provenance.test").await;
    seed_promoted_older_than_latest(&pool, user_id, "inbox-classifier").await;

    let health = talos_ml::loop_health(&pool, user_id)
        .await
        .expect("loop health");
    let models = health["models"].as_array().expect("models array");
    assert_eq!(models.len(), 1, "one seeded model: {health}");
    let m = &models[0];

    assert_eq!(m["promoted_version"], 1);
    assert_eq!(m["latest_version"], 2);
    assert_eq!(m["promoted_backend"], PROMOTED_BACKEND);
    assert_eq!(m["promoted_trained_at"], PROMOTED_TRAINED_AT_RFC);
    assert_eq!(m["latest_trained_at"], LATEST_TRAINED_AT_RFC);
    assert_eq!(
        m["gold_promoted_is_stale"], true,
        "serving v1 while v2 has been evaluated IS stale"
    );

    // The LATEST arm.
    let gold = &m["gold"];
    assert_eq!(gold["accuracy"], LATEST_GOLD_ACCURACY);
    assert_eq!(gold["total"], LATEST_GOLD_TOTAL);
    assert_eq!(gold["source_version"], 2);
    assert_eq!(gold["measured_at"], LATEST_TRAINED_AT_RFC);

    // The PROMOTED arm — every field different from the latest arm's.
    let gp = &m["gold_promoted"];
    assert_eq!(gp["accuracy"], PROMOTED_GOLD_ACCURACY);
    assert_eq!(gp["total"], PROMOTED_GOLD_TOTAL);
    assert_eq!(gp["source_version"], 1);
    assert_eq!(gp["measured_at"], PROMOTED_TRAINED_AT_RFC);

    // No field is shared, so no swap of the two arms can pass.
    assert_ne!(gold["accuracy"], gp["accuracy"]);
    assert_ne!(gold["total"], gp["total"]);
    assert_ne!(gold["source_version"], gp["source_version"]);
    assert_ne!(gold["measured_at"], gp["measured_at"]);
}

/// The FALLBACK arm: a model whose only version is the promoted one. `gold`
/// falls back to the promoted block, and must then advertise the PROMOTED
/// identity rather than borrowing a "latest" one it does not have.
#[tokio::test]
async fn loop_health_fallback_advertises_the_promoted_identity() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "fallback@ml-provenance.test").await;
    let model_id = seed_model(&pool, user_id, "single-version-classifier").await;
    let v1 = seed_version(
        &pool,
        model_id,
        user_id,
        PROMOTED_BACKEND,
        &stamped_metrics(
            PROMOTED_ACCURACY,
            PROMOTED_TOTAL,
            PROMOTED_GOLD_ACCURACY,
            PROMOTED_GOLD_TOTAL,
            PROMOTED_DATASET_ROWS,
            PROMOTED_BACKEND,
            PROMOTED_MEASURED_AT,
        ),
        PROMOTED_TRAINED_AT,
    )
    .await;
    let mut conn = pool.acquire().await.expect("acquire");
    ModelRegistry::promote_version(&mut conn, model_id, v1)
        .await
        .expect("promote");
    drop(conn);

    let health = talos_ml::loop_health(&pool, user_id)
        .await
        .expect("loop health");
    let m = &health["models"].as_array().expect("models")[0];
    assert_eq!(m["promoted_version"], 1);
    assert_eq!(m["latest_version"], 1);
    assert_eq!(
        m["gold_promoted_is_stale"], false,
        "promoted IS the latest — nothing is stale"
    );
    assert_eq!(
        m["gold"], m["gold_promoted"],
        "the fallback is the same block"
    );
    assert_eq!(m["gold"]["source_version"], 1);
    assert_eq!(m["gold"]["measured_at"], PROMOTED_TRAINED_AT_RFC);
}

// ── (c) + (e) ───────────────────────────────────────────────────────────────

/// `list_versions` is the ONE projection behind the model card's `versions`
/// array (`handle_get_model_card` embeds its result verbatim as
/// `"versions": versions`). Before #609 neither reader projected `trained_at`,
/// so a card rendered a promoted accuracy with no indication of whether it was
/// measured this morning or in March.
///
/// (e) rides here: `dataset_rows` and `measured_at` were stamped into
/// `metrics_json` by the production assembly point on the way in, and must
/// come back out of Postgres unchanged. That closes #609 mutation D — the
/// stamping had unit coverage, the ROUND TRIP had none.
#[tokio::test]
async fn version_rows_project_trained_at_and_round_trip_their_provenance() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = Uuid::new_v4();
    seed_user(&pool, user_id, "card@ml-provenance.test").await;
    let (model_id, _v1, _v2) =
        seed_promoted_older_than_latest(&pool, user_id, "inbox-classifier").await;

    let mut conn = pool.acquire().await.expect("acquire");
    let versions = ModelRegistry::list_versions(&mut conn, model_id)
        .await
        .expect("list versions");
    assert_eq!(versions.len(), 2);
    // Newest first, per the method's contract.
    assert_eq!(versions[0].version, 2);
    assert_eq!(versions[1].version, 1);

    // (c) — both rows carry their own trained_at, and they differ.
    assert_eq!(
        versions[0].trained_at.as_deref(),
        Some(LATEST_TRAINED_AT_RFC)
    );
    assert_eq!(
        versions[1].trained_at.as_deref(),
        Some(PROMOTED_TRAINED_AT_RFC)
    );
    assert_ne!(versions[0].trained_at, versions[1].trained_at);
    assert_eq!(versions[0].status, "trained", "v2 was never promoted");
    assert_eq!(versions[1].status, "promoted", "v1 is the serving version");

    // (e) — the stamped provenance survives the round trip through jsonb,
    // per row, with the two rows' values kept apart.
    let latest_metrics = &versions[0].metrics_json;
    let promoted_metrics = &versions[1].metrics_json;
    assert_eq!(latest_metrics["dataset_rows"], LATEST_DATASET_ROWS);
    assert_eq!(promoted_metrics["dataset_rows"], PROMOTED_DATASET_ROWS);
    assert_eq!(latest_metrics["measured_at"], LATEST_MEASURED_AT);
    assert_eq!(promoted_metrics["measured_at"], PROMOTED_MEASURED_AT);
    assert_eq!(latest_metrics["embedding_model"], "nomic-embed-text");
    assert_eq!(latest_metrics["report"]["total"], LATEST_TOTAL);
    assert_eq!(promoted_metrics["report"]["total"], PROMOTED_TOTAL);
    // `measured_at` is the eval's own stamp and is NOT the row's trained_at —
    // conflating them is how a "when was this measured" answer gets invented.
    assert_ne!(
        promoted_metrics["measured_at"], PROMOTED_TRAINED_AT_RFC,
        "the carried eval stamp and the row's INSERT time are different instants"
    );

    // The exact JSON `handle_get_model_card` embeds under `"versions"`. The
    // card handler needs a full `McpState` to invoke, so this asserts on the
    // value it passes through rather than on the handler — the projection,
    // which is the part that can drift, is identical.
    let card_versions = serde_json::to_value(&versions).expect("serialize versions");
    let arr = card_versions.as_array().expect("array");
    for (i, want) in [LATEST_TRAINED_AT_RFC, PROMOTED_TRAINED_AT_RFC]
        .iter()
        .enumerate()
    {
        assert_eq!(
            arr[i]["trained_at"], *want,
            "the card's versions[{i}] must carry trained_at: {card_versions}"
        );
        assert!(arr[i]["metrics_json"]["dataset_rows"].is_i64());
    }
}
