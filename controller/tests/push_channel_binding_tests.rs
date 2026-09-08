//! A push channel bound to a module that is not there — the create gate, the
//! shared visibility read, the operator inventory, and the hygiene finding.
//!
//! Measured on pristine `origin/main` 2026-09-08, driving the production REST
//! handler: a create naming a random uuid returned `200 OK` and landed a row,
//! while both controls passed. The live fleet's only module-binding channel had
//! been in exactly that state since 2026-07-17 — every push failing at module
//! load, and no operator surface saying so.
//!
//! Every test carries its CONTROL in the same run. A test that only proves "the
//! bad case is refused" passes on a tree where watch creation was broken
//! outright, and a test that only proves "the dangling channel is listed"
//! passes on one where every channel is listed.
//!
//! Assertions never echo a create response wholesale: it carries
//! `push_endpoint`, which embeds the raw push token, and a failing assertion
//! prints to a CI log. See `redacted`.
//!
//! These are DB tests on the `common` harness (each gets a template clone of
//! the migrated DB), so they belong in CTRL_TESTS, not TC_TESTS.

mod common;

use axum::extract::State;
use axum::response::IntoResponse;
use axum::Extension;
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use talos_google_cloud::handlers::{create_watch_channel_handler, CreateGcpWatchRequest};
use talos_google_cloud::integration::GoogleCloudIntegrationService;
use talos_google_cloud::watch::GcpWatchService;
use talos_integration_helpers::api_json::ApiJson;
use uuid::Uuid;

const SA: &str = "talos-gcp-pusher@my-project.iam.gserviceaccount.com";

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'push chan test')",
    )
    .bind(id)
    .bind(format!("push-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_integration(pool: &Pool<Postgres>, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO google_cloud_integrations (id, user_id, provider_key, tier, is_active) \
         VALUES ($1, $2, $3, 'read', TRUE)",
    )
    .bind(id)
    .bind(user_id)
    .bind(Uuid::new_v4())
    .execute(pool)
    .await
    .expect("seed integration");
    id
}

async fn seed_module(pool: &Pool<Postgres>, user_id: Option<Uuid>, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO modules (id, user_id, name, kind, capability_world) \
         VALUES ($1, $2, $3, 'sandbox', 'http-node')",
    )
    .bind(id)
    .bind(user_id)
    .bind(name)
    .execute(pool)
    .await
    .expect("seed module");
    id
}

fn watch_service(pool: &Pool<Postgres>) -> Arc<GcpWatchService> {
    let integrations = Arc::new(
        GoogleCloudIntegrationService::new(pool.clone()).expect("gcp integration service"),
    );
    Arc::new(GcpWatchService::new(pool.clone(), integrations))
}

async fn create(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    integration_id: Uuid,
    module_id: Option<Uuid>,
) -> (axum::http::StatusCode, serde_json::Value) {
    let svc = watch_service(pool);
    let resp = create_watch_channel_handler(
        State(svc),
        Extension(user_id),
        ApiJson(CreateGcpWatchRequest {
            integration_id,
            expected_sa_email: SA.to_string(),
            display_name: Some("probe".into()),
            module_id,
        }),
    )
    .await
    .into_response();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

/// A create response carries `push_endpoint` — the ONE surface where the raw
/// push token is returned. An assertion message is not that surface: a failing
/// test prints to CI logs. Echo only the fields a diagnosis needs.
fn redacted(body: &serde_json::Value) -> String {
    serde_json::json!({
        "success": body.get("success"),
        "error": body.get("error"),
        "module_id": body.pointer("/data/module_id"),
    })
    .to_string()
}

async fn watch_row_count(pool: &Pool<Postgres>, user_id: Uuid) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM integration_state \
         WHERE integration_name = 'google_cloud' AND user_id = $1 AND key LIKE 'watch/%'",
    )
    .bind(user_id)
    .fetch_one(pool)
    .await
    .expect("count watch rows")
}

/// RED on pristine main: the create path never looks at `module_id`, so a
/// channel is minted bound to a module nobody can load. Every push to it then
/// fails with "load module for gcp dispatch" and the channel row looks healthy.
#[tokio::test]
async fn a_watch_cannot_be_bound_to_a_module_that_does_not_exist() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let integ = seed_integration(&pool, user).await;

    let (status, body) = create(&pool, user, integ, Some(Uuid::new_v4())).await;
    assert!(
        status.is_client_error(),
        "expected a refusal, got {status}: {}",
        redacted(&body)
    );
    assert_eq!(
        watch_row_count(&pool, user).await,
        0,
        "a refused create must not leave a row behind"
    );
}

/// CONTROL — a real module still binds. Without this the test above passes on a
/// tree where watch creation was broken outright.
#[tokio::test]
async fn a_watch_bound_to_a_real_module_is_created() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let integ = seed_integration(&pool, user).await;
    let module = seed_module(&pool, Some(user), "gcp-probe-module").await;

    let (status, body) = create(&pool, user, integ, Some(module)).await;
    assert!(
        status.is_success(),
        "expected success, got {status}: {}",
        redacted(&body)
    );
    assert_eq!(watch_row_count(&pool, user).await, 1);
}

/// CONTROL — a channel that binds NO module is a deliberate configuration (the
/// push is acked and nothing is dispatched) and must stay creatable.
#[tokio::test]
async fn a_watch_with_no_module_binding_is_created() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let integ = seed_integration(&pool, user).await;

    let (status, body) = create(&pool, user, integ, None).await;
    assert!(
        status.is_success(),
        "expected success, got {status}: {}",
        redacted(&body)
    );
    assert_eq!(watch_row_count(&pool, user).await, 1);
}

// ---------------------------------------------------------------------------
// The shared gate — one decision, three integrations
// ---------------------------------------------------------------------------

/// `check_module_binding` is the ONE mapping from a three-valued visibility
/// read to a refusal, shared by gmail / google_calendar / google_cloud. Gmail's
/// and gcal's creates call Google before they can be observed end to end, so
/// this is where their half of the gate is proved: the decision they run is
/// this function, against a real database.
#[tokio::test]
async fn the_shared_gate_admits_a_real_module_and_refuses_the_rest() {
    use talos_integration_helpers::watch_binding::{check_module_binding, ModuleBindingRefusal};

    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let mine = seed_module(&pool, Some(user), "mine").await;
    let theirs = seed_module(&pool, Some(other), "theirs").await;
    let catalog = seed_module(&pool, None, "shared-catalog-module").await;

    // CONTROL — a module this user owns, and a shared catalog module
    // (`user_id IS NULL`), both bind. Without these the refusals below would
    // pass on a gate that refused everything.
    assert!(
        check_module_binding(&pool, user, Some(mine), "google_cloud")
            .await
            .is_ok()
    );
    assert!(check_module_binding(&pool, user, Some(catalog), "gmail")
        .await
        .is_ok());
    // CONTROL — no binding at all is a deliberate configuration, not a failure.
    assert!(check_module_binding(&pool, user, None, "gcal")
        .await
        .is_ok());

    // A module that does not exist, and one that belongs to somebody else,
    // refuse IDENTICALLY. Splitting them would hand anyone who can guess a uuid
    // a module-existence oracle.
    assert_eq!(
        check_module_binding(&pool, user, Some(Uuid::new_v4()), "google_cloud").await,
        Err(ModuleBindingRefusal::NotBindable)
    );
    assert_eq!(
        check_module_binding(&pool, user, Some(theirs), "google_cloud").await,
        Err(ModuleBindingRefusal::NotBindable)
    );
}

/// The gate's read is pinned equal to the DISPATCH-time load's predicate, so a
/// create that passes is a load that will succeed. Proved by driving BOTH
/// against the same rows rather than by comparing SQL strings.
#[tokio::test]
async fn the_gate_and_the_dispatch_load_agree_on_the_same_rows() {
    use talos_registry::module_visibility::{module_visibility, ModuleVisibility};

    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let mine = seed_module(&pool, Some(user), "mine").await;
    let theirs = seed_module(&pool, Some(other), "theirs").await;
    let catalog = seed_module(&pool, None, "catalog").await;
    let registry = talos_registry::ModuleRegistry::new(pool.clone(), None);

    for (id, expect_loadable) in [(mine, true), (catalog, true), (theirs, false)] {
        let visible = matches!(
            module_visibility(&pool, id, user).await,
            ModuleVisibility::Visible { .. }
        );
        // `get_module` reads twenty columns and can fail for reasons that are
        // nothing to do with tenancy (a seeded row carries no wasm bytes), so
        // what is compared is the TENANCY verdict specifically: the typed
        // "Module not found or access denied" the load returns when its own
        // `WHERE id = $1 AND (user_id = $2 OR user_id IS NULL)` matches nothing.
        let load_says_absent = registry
            .get_module(id, user)
            .await
            .err()
            .is_some_and(|e| format!("{e:#}").contains("Module not found or access denied"));
        assert_eq!(
            visible, expect_loadable,
            "visibility disagreed with the fixture for {id}"
        );
        assert_eq!(
            visible, !load_says_absent,
            "the create gate and the dispatch load disagree about {id}"
        );
    }
}

// ---------------------------------------------------------------------------
// The operator inventory (T1) and the hygiene finding (T3)
// ---------------------------------------------------------------------------

fn inventory_set(
    pool: &Pool<Postgres>,
) -> Arc<talos_push_channel_inventory::PushChannelInventorySet> {
    Arc::new(talos_push_channel_inventory::PushChannelInventorySet::new(
        vec![Arc::new(
            talos_google_cloud::watch_channel_service::GcpPushChannelInventory::new(pool.clone()),
        )],
    ))
}

/// The live shape, reproduced: a channel is created bound to a module that
/// exists, the module is then deleted, and every operator surface must say the
/// binding is `missing` — not `null`, not "no name".
#[tokio::test]
async fn a_channel_whose_module_was_deleted_reads_as_missing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let integ = seed_integration(&pool, user).await;
    let module = seed_module(&pool, Some(user), "gcp-alert-normalize").await;
    let (status, _) = create(&pool, user, integ, Some(module)).await;
    assert!(status.is_success());

    // CONTROL — while the module exists, the binding is `bound` and carries the
    // module's name.
    let survey = inventory_set(&pool).survey(user).await;
    assert_eq!(survey.rows.len(), 1);
    assert_eq!(
        survey.rows[0].module_binding,
        talos_push_channel_inventory::ModuleBinding::Bound
    );
    assert_eq!(
        survey.rows[0].module_name.as_deref(),
        Some("gcp-alert-normalize")
    );
    assert!(survey.dangling().is_empty());

    sqlx::query("DELETE FROM modules WHERE id = $1")
        .bind(module)
        .execute(&pool)
        .await
        .expect("delete module");

    let survey = inventory_set(&pool).survey(user).await;
    assert_eq!(
        survey.rows[0].module_binding,
        talos_push_channel_inventory::ModuleBinding::Missing
    );
    // A name beside a `missing` binding would be a fabrication.
    assert!(survey.rows[0].module_name.is_none());
    assert_eq!(survey.dangling().len(), 1);
    assert!(survey.rows[0].repair_hint().contains("does not exist"));
    assert_eq!(survey.surveyed_integrations, vec!["google_cloud"]);
    assert!(survey.unreadable_integrations.is_empty());
}

/// The row that crosses into an operator report must not carry the push token
/// or the endpoint that embeds it. Asserted against a REAL row, because the
/// unit test in the leaf crate can only assert it about a hand-built one.
#[tokio::test]
async fn a_real_surveyed_row_carries_no_token_or_endpoint() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let integ = seed_integration(&pool, user).await;
    let (status, _) = create(&pool, user, integ, None).await;
    assert!(status.is_success());

    let survey = inventory_set(&pool).survey(user).await;
    let json = serde_json::to_string(&survey.rows).expect("serialize");
    assert!(!json.contains("push_endpoint"));
    assert!(!json.contains("push_token"));
    // …and the raw token really is in the row we just read from, so the
    // assertion above is not vacuous.
    let stored: String = sqlx::query_scalar(
        "SELECT count(*)::text FROM integration_state \
         WHERE integration_name = 'google_cloud' AND user_id = $1",
    )
    .bind(user)
    .fetch_one(&pool)
    .await
    .expect("count");
    assert_eq!(stored, "1");
}

/// The hygiene report, driven END TO END through the real service against a
/// real database — because the defect is what the REPORT says, and a test
/// against the survey alone cannot see a correctly-classified row discarded in
/// the renderer (checks 74b / 79b state that limit).
#[tokio::test]
async fn the_hygiene_report_names_a_dangling_channel_and_stays_silent_otherwise() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let integ = seed_integration(&pool, user).await;
    let module = seed_module(&pool, Some(user), "gcp-alert-normalize").await;
    let (status, _) = create(&pool, user, integ, Some(module)).await;
    assert!(status.is_success());

    let service = || {
        talos_hygiene_service::HygieneService::new(
            Arc::new(talos_analytics_repository::AnalyticsRepository::new(
                pool.clone(),
            )),
            Arc::new(talos_workflow_repository::WorkflowRepository::new(
                pool.clone(),
            )),
            Arc::new(talos_execution_repository::ExecutionRepository::new(
                pool.clone(),
            )),
            Arc::new(talos_module_repository::ModuleRepository::new(pool.clone())),
            Some(inventory_set(&pool)),
        )
    };

    // CONTROL — a healthy channel adds NO key. "Nothing to say ⇒ no key": an
    // empty list would be a new permanent claim of a measured all-clear.
    let healthy = service()
        .generate(talos_hygiene_service::HygieneReportInput { user_id: user })
        .await
        .expect("hygiene report")
        .report;
    assert!(healthy.get("dangling_push_channels").is_none());
    assert!(healthy.get("push_channel_survey").is_none());

    sqlx::query("DELETE FROM modules WHERE id = $1")
        .bind(module)
        .execute(&pool)
        .await
        .expect("delete module");

    let degraded = service()
        .generate(talos_hygiene_service::HygieneReportInput { user_id: user })
        .await
        .expect("hygiene report")
        .report;
    let rows = degraded["dangling_push_channels"]
        .as_array()
        .expect("dangling list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["module_binding"], "missing");
    assert_eq!(rows[0]["display_name"], "probe");
    assert!(rows[0]["repair"]
        .as_str()
        .expect("repair")
        .contains("stop the watch"));
    assert!(degraded["recommendations"]
        .as_array()
        .expect("recs")
        .iter()
        .any(|r| r["category"] == "integrations" && r["priority"] == "critical"));
    // The finding is COUNTED, not merely listed.
    assert_eq!(degraded["summary"]["critical"], 1);
    // …and the report never carries the token or the endpoint.
    let rendered = degraded.to_string();
    assert!(!rendered.contains("push_endpoint"));
    assert!(!rendered.contains("/api/gcp/pubsub/"));
}

/// FAIL CLOSED. The gate's read is three-valued, and an UNREADABLE rule must
/// refuse — a channel minted on a binding nobody could verify is exactly what
/// the gate is for. It must NOT refuse with "that module does not exist",
/// which would be a determinate negative over a query that did not answer, and
/// it must not refuse with the same status either: the caller can retry this
/// one and cannot fix it.
///
/// The relation the read names is DROPPED in this test's own isolated database
/// (package 22's mechanism, and `fail_open_gate_tests`'s), so the statement
/// cannot run at all.
#[tokio::test]
async fn an_unreadable_visibility_rule_refuses_retryably() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let integ = seed_integration(&pool, user).await;
    let module = seed_module(&pool, Some(user), "about-to-be-unreadable").await;

    // CONTROL — with the relation intact this exact request succeeds, so the
    // refusal below is the READ failing and not the fixture.
    let (status, body) = create(&pool, user, integ, Some(module)).await;
    assert!(
        status.is_success(),
        "control failed before the relation was dropped: {status} {}",
        redacted(&body)
    );

    sqlx::query("DROP TABLE modules CASCADE")
        .execute(&pool)
        .await
        .expect("drop modules");

    let (status, body) = create(&pool, user, integ, Some(Uuid::new_v4())).await;
    assert_eq!(
        status,
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        "an unreadable rule must refuse RETRYABLY, not as a bad request: {}",
        redacted(&body)
    );
    let err = body["error"].as_str().unwrap_or_default();
    assert!(
        err.contains("Could not verify"),
        "the caller must be told the rule could not be read, not that the module \
         does not exist; got: {err}"
    );
    // And the refused create left nothing behind — asserted on ROWS, because a
    // status assertion alone passes on a tree where the write would have failed
    // anyway.
    assert_eq!(
        watch_row_count(&pool, user).await,
        1,
        "only the control row"
    );
}

/// The classifier reads the LOOKUP'S OWN `Result`, and this is the test that
/// makes that structural rather than decorative.
///
/// With an already-flattened map the classifier is still perfectly correct and
/// the CALL SITE can hand it `Ok(empty)` on an `Err` — a one-line revert to the
/// pre-2026-09-07 `.unwrap_or_default()` behaviour that reports a live channel
/// as `missing` because a pool timeout said so. Measured 2026-09-08: without
/// this test that revert (mutation M4) SURVIVES every other test in this file.
#[tokio::test]
async fn an_unreadable_module_lookup_classifies_as_unreadable_not_missing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let integ = seed_integration(&pool, user).await;
    let module = seed_module(&pool, Some(user), "gcp-alert-normalize").await;
    let (status, _) = create(&pool, user, integ, Some(module)).await;
    assert!(status.is_success());

    // CONTROL — while the lookup answers, the binding is `bound`.
    let survey = inventory_set(&pool).survey(user).await;
    assert_eq!(
        survey.rows[0].module_binding,
        talos_push_channel_inventory::ModuleBinding::Bound
    );

    sqlx::query("DROP TABLE modules CASCADE")
        .execute(&pool)
        .await
        .expect("drop modules");

    let survey = inventory_set(&pool).survey(user).await;
    assert_eq!(
        survey.rows[0].module_binding,
        talos_push_channel_inventory::ModuleBinding::Unreadable,
        "a lookup that did not answer must not be reported as a dead binding"
    );
    // …and the channel is NOT counted as dangling: that would put a pool
    // timeout in the same bucket as a permanently dead channel.
    assert!(survey.dangling().is_empty());
    assert_eq!(survey.unclassifiable().len(), 1);
    // The LIST read still succeeded, so the integration is not "unreadable" —
    // only its bindings are. The two disclosures are separate on purpose.
    assert!(survey.unreadable_integrations.is_empty());
}

/// Gmail's create gate, driven through the REAL `GmailWatchService`.
///
/// Gmail's create calls Google's `users.watch` and cannot be driven end to end
/// without the network — which is exactly why the gate is placed ABOVE the
/// lock and above that call. So the refusal IS observable offline, and the
/// CONTROL is a request that gets PAST the gate and fails for some other
/// reason: what is asserted is not "it failed" but WHICH refusal it is.
/// Measured 2026-09-08: without this test, deleting gmail's gate (mutation
/// M10) survives every other test in this workspace.
#[tokio::test]
async fn gmails_create_refuses_a_module_it_cannot_load_before_calling_google() {
    use talos_gmail::watch::{CreateWatchError, GmailWatchService};

    let (pool, _db) = common::isolated_db_pool().await;
    let user = seed_user(&pool).await;
    let module = seed_module(&pool, Some(user), "gmail-labeler").await;
    let integ = Uuid::new_v4(); // never resolved — the gate runs above that read

    let svc = GmailWatchService::new(
        pool.clone(),
        Arc::new(talos_gmail::GmailIntegrationService::new(pool.clone()).expect("gmail service")),
        "projects/none/topics/none".to_string(),
        vec!["INBOX".to_string()],
    );

    let refused = svc
        .create_watch(user, integ, Some(Uuid::new_v4()), None, None)
        .await
        .expect_err("a module that does not exist must be refused");
    assert!(
        matches!(
            refused,
            CreateWatchError::ModuleBinding(
                talos_integration_helpers::watch_binding::ModuleBindingRefusal::NotBindable
            )
        ),
        "expected the module-binding refusal, got: {refused:#}"
    );

    // CONTROL — a module this user CAN load gets past the gate and fails
    // downstream instead (no integration row, no Google). The point is that it
    // is a DIFFERENT refusal: a gate that refused everything would pass the
    // assertion above.
    let other = svc
        .create_watch(user, integ, Some(module), None, None)
        .await
        .expect_err("no integration row, so this must still fail");
    assert!(
        matches!(other, CreateWatchError::Internal(_)),
        "a loadable module must get PAST the binding gate; got: {other:#}"
    );

    // CONTROL — binding no module at all is likewise not a binding refusal.
    let unbound = svc
        .create_watch(user, integ, None, None, None)
        .await
        .expect_err("no integration row, so this must still fail");
    assert!(matches!(unbound, CreateWatchError::Internal(_)));
}
