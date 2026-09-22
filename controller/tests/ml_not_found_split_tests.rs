//! A read that FAILED is not a row that is ABSENT.
//!
//! Six ML tool handlers resolved a model with
//! `let Ok(Some(model)) = ModelRegistry::resolve_by_*(…) else { return
//! mcp_error(…, "Model not found") }`, which puts a pool timeout, a
//! projection drift and a renamed table in the SAME branch as "no such
//! model" — and four of the six are MUTATING tools (`promote_model`,
//! `set_policy`, `set_lifecycle`, `reset_shadow_window`), where that
//! sentence sends an operator hunting a deletion that never happened while
//! the database is the thing that is broken. Recorded open since #789;
//! `get_model_card` had made the split alone (2026-09-08).
//!
//! Two SERVICE-layer sites had the same defect one layer down: a
//! `_ => return Err(…NotFound)` wildcard over
//! `dataset.dataset_tenancy(…)`, whose own `ok_or_else` folds an absent
//! dataset into `Err`, so the wildcard swallowed a real read failure too.
//!
//! This binary drives the PRODUCTION paths — `controller::mcp::ml::dispatch`
//! for the handler, `talos_ml::resolve_disagreement` and
//! `talos_ml::start_teacher_audit` for the services — with the underlying
//! table renamed out from under a live pool, which is how a read fails
//! while everything around it keeps working. It exists beside the
//! `classify_model_lookup` unit tests because those prove the classifier
//! decides correctly and cannot see whether a CALL SITE still uses it.
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use serde_json::Value;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

const NOT_FOUND: &str = "Model not found";
const UNAVAILABLE: &str = "NOT a statement that the model is absent";

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'ml split')",
    )
    .bind(id)
    .bind(format!("ml-split-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_dataset(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
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

async fn seed_model(pool: &Pool<Postgres>, user_id: Uuid, dataset_id: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO ml_models (id, user_id, name, task_type, config_json, lifecycle_state, \
                                policy_json, dataset_id) \
         VALUES ($1, $2, $3, 'classification', '{}'::jsonb, 'llm_only', '{}'::jsonb, $4)",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("m-{id}"))
    .bind(dataset_id)
    .execute(pool)
    .await
    .expect("seed model");
    id
}

/// One divergence, recorded through the PRODUCTION recorder — the same
/// call the live classify leg makes, so the row shape cannot drift from it.
async fn seed_disagreement(
    ls: &talos_ml::LifecycleService,
    pool: &Pool<Postgres>,
    model: Uuid,
    user: Uuid,
) -> Uuid {
    let mut conn = pool.acquire().await.unwrap();
    ls.record_disagreement(
        &mut conn,
        model,
        user,
        None,
        Some(&format!("k-{}", Uuid::new_v4())),
        "Subject: 50% off — weekend sale ends Sunday",
        Some(("to_read", 0.9)),
        "archive",
        "divergence",
    )
    .await
    .expect("record disagreement")
}

async fn rename(pool: &Pool<Postgres>, from: &str, to: &str) {
    sqlx::query(&format!("ALTER TABLE {from} RENAME TO {to}"))
        .execute(pool)
        .await
        .unwrap_or_else(|e| panic!("rename {from} -> {to}: {e}"));
}

/// The HANDLER layer, through the production MCP dispatch. `ml_set_policy`
/// is one of the four MUTATING tools, which is where the wrong sentence
/// costs the most.
#[tokio::test]
async fn an_unreadable_model_registry_does_not_report_a_missing_model() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let state = mcp_common::mcp_state(pool.clone()).await;
    let model = seed_model(&pool, user, None).await;

    let call = |tool: &'static str, args: Value| {
        let state = state.clone();
        async move {
            controller::mcp::ml::dispatch(
                tool,
                Some(serde_json::json!(1)),
                &args,
                &state,
                mcp_common::agent(user),
            )
            .await
            .unwrap_or_else(|| panic!("{tool} is dispatched"))
        }
    };
    let policy = serde_json::json!({ "min_examples": 50, "auto_advance": false });

    // CONTROL 1: a model that really is absent still says so, and the
    // instrument records `NotFound`.
    let absent = call(
        "ml_set_policy",
        serde_json::json!({ "model_id": Uuid::new_v4(), "policy": policy }),
    )
    .await;
    let text = mcp_common::text_json(&absent).to_string();
    assert!(text.contains(NOT_FOUND), "absent model must say so: {text}");
    assert_eq!(absent.error_kind, Some(talos_mcp::McpErrorKind::NotFound));

    // The defect: with the registry unreadable the caller used to be told
    // the model was gone.
    rename(&pool, "ml_models", "ml_models_away").await;
    let unreadable = call(
        "ml_set_policy",
        serde_json::json!({ "model_id": model, "policy": policy }),
    )
    .await;
    let text = mcp_common::text_json(&unreadable).to_string();
    assert!(
        text.contains(UNAVAILABLE),
        "an unreadable registry must disclaim absence: {text}"
    );
    assert!(
        !text.contains(NOT_FOUND),
        "an unreadable registry must NOT report a missing model: {text}"
    );
    assert_eq!(
        unreadable.error_kind,
        Some(talos_mcp::McpErrorKind::Failed),
        "and the instrument must record a platform failure, not a declined lookup"
    );
    rename(&pool, "ml_models_away", "ml_models").await;

    // CONTROL 2: with the table back, the same model resolves and the tool
    // serves — the refusal above was the read, not the request.
    let served = call(
        "ml_set_policy",
        serde_json::json!({ "model_id": model, "policy": policy }),
    )
    .await;
    assert_eq!(served.error_kind, None, "the tool must serve once readable");
}

/// SERVICE layer 1: `resolve_disagreement`'s dataset-ownership belt. The
/// wildcard reported a read failure as `NotFound`, which the handler renders
/// as "Disagreement not found or already handled".
#[tokio::test]
async fn an_unreadable_dataset_does_not_report_a_missing_disagreement() {
    let (pool, _db) = common::isolated_db_pool().await;
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let user = seed_user(&pool).await;
    let dataset = seed_dataset(&pool, user).await;
    let model = seed_model(&pool, user, Some(dataset)).await;

    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"));
    sm.initialize().await.expect("init secrets");
    let lifecycle = talos_ml::LifecycleService::new(sm.clone());
    let dsvc = talos_ml::DatasetService::new(sm);

    // The defect: the belt's own read fails, and the caller is told the
    // disagreement is gone.
    let d1 = seed_disagreement(&lifecycle, &pool, model, user).await;
    rename(&pool, "ml_datasets", "ml_datasets_away").await;
    let err = talos_ml::resolve_disagreement(&pool, &lifecycle, &dsvc, d1, user, Some("a"))
        .await
        .expect_err("an unreadable dataset must refuse");
    assert!(
        matches!(err, talos_ml::ResolveError::Internal(_)),
        "an unreadable dataset must be Internal, not NotFound: {err:?}"
    );
    rename(&pool, "ml_datasets_away", "ml_datasets").await;

    // CONTROL: a dataset that exists but belongs to someone ELSE is still a
    // single NotFound — the enumeration property the wildcard was protecting
    // is untouched.
    let other = seed_user(&pool).await;
    let foreign = seed_dataset(&pool, other).await;
    sqlx::query("UPDATE ml_models SET dataset_id = $1 WHERE id = $2")
        .bind(foreign)
        .bind(model)
        .execute(&pool)
        .await
        .expect("repoint model at a foreign dataset");
    let d2 = seed_disagreement(&lifecycle, &pool, model, user).await;
    let err = talos_ml::resolve_disagreement(&pool, &lifecycle, &dsvc, d2, user, Some("a"))
        .await
        .expect_err("a foreign dataset must refuse");
    assert!(
        matches!(err, talos_ml::ResolveError::NotFound),
        "a foreign dataset must stay NotFound: {err:?}"
    );
    // What the belt is FOR: a correction must not land in a dataset the
    // caller does not own, and the disagreement must stay open.
    //
    // MEASURED LIMIT, stated: removing the belt's `t.user_id == user_id`
    // guard does NOT move either of these — the call still answers
    // `NotFound`, no row is appended and the status stays `pending`, because
    // something downstream refuses too. That guard predates this package
    // (the pre-fix wildcard carried it), so it is not a clause this change
    // introduced; these two assertions are a regression guard for the day a
    // downstream change stops holding, not a test that can fail today.
    let appended: i64 =
        sqlx::query_scalar("SELECT count(*) FROM ml_examples WHERE dataset_id = $1")
            .bind(foreign)
            .fetch_one(&pool)
            .await
            .expect("count foreign examples");
    assert_eq!(appended, 0, "no correction may land in a foreign dataset");
    let status: String = sqlx::query_scalar("SELECT status FROM ml_disagreements WHERE id = $1")
        .bind(d2)
        .fetch_one(&pool)
        .await
        .expect("read disagreement status");
    assert_eq!(
        status, "pending",
        "a refused correction must not resolve the row"
    );
}

/// SERVICE layer 2: `start_teacher_audit`'s identical belt, which the
/// handler renders as "Model not found". The tenancy check runs BEFORE the
/// locality gate and before any LLM call, so the classify closure below is
/// never invoked.
#[tokio::test]
async fn an_unreadable_dataset_does_not_report_a_missing_model_to_the_teacher_audit() {
    let (pool, _db) = common::isolated_db_pool().await;
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
    let user = seed_user(&pool).await;
    let dataset = seed_dataset(&pool, user).await;
    let model = seed_model(&pool, user, Some(dataset)).await;
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets"));
    sm.initialize().await.expect("init secrets");
    let dsvc = talos_ml::DatasetService::new(sm);
    let never = |_req: talos_ml::TeacherRequest| async move {
        panic!("the LLM must not be reached — the tenancy belt refuses first")
    };

    rename(&pool, "ml_datasets", "ml_datasets_away").await;
    let err = talos_ml::start_teacher_audit(&pool, &dsvc, user, model, 1, None, never)
        .await
        .expect_err("an unreadable dataset must refuse");
    assert!(
        matches!(err, talos_ml::TeacherAuditError::Internal(_)),
        "an unreadable dataset must be Internal, not NotFound: {err:?}"
    );
    rename(&pool, "ml_datasets_away", "ml_datasets").await;

    // CONTROL: a foreign dataset is still the single NotFound.
    let other = seed_user(&pool).await;
    let foreign = seed_dataset(&pool, other).await;
    sqlx::query("UPDATE ml_models SET dataset_id = $1 WHERE id = $2")
        .bind(foreign)
        .bind(model)
        .execute(&pool)
        .await
        .expect("repoint model at a foreign dataset");
    let never2 = |_req: talos_ml::TeacherRequest| async move { panic!("LLM must not be reached") };
    let err = talos_ml::start_teacher_audit(&pool, &dsvc, user, model, 1, None, never2)
        .await
        .expect_err("a foreign dataset must refuse");
    assert!(
        matches!(err, talos_ml::TeacherAuditError::NotFound),
        "a foreign dataset must stay NotFound: {err:?}"
    );
}

/// The file's PRODUCTION text: line comments and column-0 `#[cfg(test)]`
/// modules removed. Both matter — this package's own unit tests call the
/// classifier and its doc comments quote the shape it replaced, so a naive
/// scan counts them and reads as green (or red) for the wrong reason.
/// Conservative in the safe direction, per check 58: a mis-detected region
/// end leaves test code IN the haystack, which over-reports.
fn production_code(src: &str) -> String {
    let mut out = Vec::new();
    let mut in_test_mod = false;
    for line in src.lines() {
        if !in_test_mod && line.starts_with("#[cfg(test)]") {
            in_test_mod = true;
            continue;
        }
        if in_test_mod {
            if line == "}" {
                in_test_mod = false;
            }
            continue;
        }
        if line.trim_start().starts_with("//") {
            continue;
        }
        out.push(line);
    }
    out.join("\n")
}

/// Every model-resolving handler goes through the one home, and the shape
/// the defect took cannot come back.
///
/// TEXTUAL, and stated as such: it proves the call sites NAME the classifier,
/// not that they honour its answer. The behavioural half is the dispatch test
/// above, which can only reach one handler per rename.
#[test]
fn every_model_lookup_goes_through_the_one_home() {
    let code = production_code(include_str!("../../talos-mcp-handlers/src/ml.rs"));

    assert_eq!(
        code.matches("classify_model_lookup(").count(),
        7,
        "seven handlers resolve a model: eval, promote, set_policy, set_lifecycle, \
         reset_shadow_window, disagreements, get_model_card"
    );
    assert!(
        !code.contains("let Ok(Some("),
        "the collapsing shape must not return to ml.rs"
    );
    assert!(
        !code.contains(r#"mcp_error(req_id, -32000, "Model not found")"#),
        "an unclassified \"Model not found\" must not return to ml.rs"
    );
    // The two service-layer belts read the THREE-valued lookup, not the
    // two-valued `dataset_tenancy` whose own ok_or_else folds absent into Err.
    for (path, src) in [
        (
            "correction.rs",
            include_str!("../../talos-ml/src/correction.rs"),
        ),
        (
            "teacher_audit.rs",
            include_str!("../../talos-ml/src/teacher_audit.rs"),
        ),
    ] {
        let code = production_code(src);
        assert!(
            code.contains("lookup_dataset_tenancy("),
            "{path} must read the three-valued tenancy lookup"
        );
        assert!(
            !code.contains("dataset.dataset_tenancy("),
            "{path} must not read the two-valued one"
        );
    }
}
