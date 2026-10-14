//! Jira (Atlassian) push: a registered webhook that starts a WORKFLOW
//! (2026-10-12).
//!
//! The webhook URL is one fixed address for the whole deployment, so whose a
//! delivery is can only come from the registration its webhook id names. The
//! assertions here are on rows and on what the stand-in for Atlassian was
//! asked:
//!
//! * a webhook is registered only for the caller's own connection, and
//!   everything refusable without Atlassian is refused before it is called;
//! * a delivery with a valid token starts the bound workflow ONCE, as the
//!   registration's owner, with identifiers only; a repeated delivery, an
//!   unknown webhook id and an ambiguous one start nothing;
//! * one user's delivery never starts another user's workflow, even when a
//!   row is made to point at it;
//! * binding follows the calendar channel's ownership rules, by integration
//!   name through the same set the tools use;
//! * a refresh moves the expiry, a failed one is recorded on the row, and the
//!   hourly task does both;
//! * deleting a channel, or disconnecting the connection, deletes the webhook
//!   at Atlassian and the row here.
//!
//! The refusals of a token that does not verify (bad signature, `none`,
//! RS256, expired, no header) are asserted "before any database read" in
//! `talos-atlassian`'s own unit tests, against a pool that cannot connect.
//!
//! A delivery on a live workflow is driven as far as the execution row the
//! trigger creates for the registration's user; this harness has no dispatch
//! bus, so what a worker then does with it is not. For the same reason the
//! trigger reports, after creating the row, that it could not dispatch, and
//! the receiver records that like any other start that did not complete
//! (`trigger_failed`). Those rows are counted apart from the refusals a test
//! is about (`refusals` / `undispatched`). The trigger input is not stored
//! until a run is dispatched, so what a start carries is pinned through the
//! workflow's own input schema: the trigger service refuses any other input.
//! An in-process HTTP server stands in for Atlassian. `common` harness (a
//! template clone per test).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::routing::{post, put};
use axum::{Extension, Json, Router};
use std::sync::atomic::{AtomicI64, AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use talos_atlassian::push::{
    bind_registration_workflow, JiraPushChannelInventory, JiraPushError, JiraPushProvisioner,
    JiraPushRegistration, ReconnectReason, UpstreamFailure, INTEGRATION_NAME, WEBHOOK_PATH,
};
use talos_atlassian::push_receiver::{
    jira_push_trigger_input, run_planned_starts, webhook_handler, PushReceipt, ReceiptNote,
};
use talos_atlassian::AtlassianIntegrationService;
use talos_execution_orchestration::ExecutionOrchestrationService;
use talos_push_channel_inventory::{
    BindWorkflowRefusal, ProvisionRefusalKind, PushChannelInventory, PushChannelInventorySet,
};
use uuid::Uuid;

/// The app's client secret: what Atlassian signs a delivery with.
const CLIENT_SECRET: &str = "test-client-secret-of-enough-length";
const PUBLIC_BASE: &str = "https://talos.example.com";
const SCOPE_WITH_WEBHOOKS: &str = "read:jira-work offline_access manage:jira-webhook";

/// What the stand-in for Atlassian was asked, and how it is told to answer.
struct FakeAtlassian {
    /// The id the next registration is given. A test sets it to make two
    /// sites issue the same id.
    next_webhook_id: AtomicI64,
    /// Webhook ids the listing reports, per site.
    live: Mutex<Vec<(String, i64)>>,
    registrations: Mutex<Vec<(String, String, serde_json::Value)>>,
    refreshes: AtomicUsize,
    deletes: Mutex<Vec<(String, i64)>>,
    /// Non-zero: the status every refresh / delete / register answers with.
    refresh_status: AtomicU16,
    delete_status: AtomicU16,
    /// True: a registration answers 200 with `errors` and creates nothing.
    reject_registration: std::sync::atomic::AtomicBool,
    expiration_ms: AtomicI64,
}

fn bearer_of(headers: &HeaderMap) -> String {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string()
}

async fn register(
    State(a): State<Arc<FakeAtlassian>>,
    Path(cloud): Path<String>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> Json<serde_json::Value> {
    a.registrations
        .lock()
        .unwrap()
        .push((cloud.clone(), bearer_of(&headers), body));
    if a.reject_registration.load(Ordering::SeqCst) {
        return Json(serde_json::json!({
            "webhookRegistrationResult": [{"errors": ["The clause is not supported."]}]
        }));
    }
    let id = a.next_webhook_id.fetch_add(1, Ordering::SeqCst);
    a.live.lock().unwrap().push((cloud, id));
    Json(serde_json::json!({ "webhookRegistrationResult": [{"createdWebhookId": id}] }))
}

async fn list(
    State(a): State<Arc<FakeAtlassian>>,
    Path(cloud): Path<String>,
) -> Json<serde_json::Value> {
    let values: Vec<serde_json::Value> = a
        .live
        .lock()
        .unwrap()
        .iter()
        .filter(|(c, _)| *c == cloud)
        .map(|(_, id)| serde_json::json!({"id": id, "expirationDate": a.expiration_ms.load(Ordering::SeqCst)}))
        .collect();
    Json(serde_json::json!({ "startAt": 0, "maxResults": 100, "isLast": true, "values": values }))
}

async fn delete(
    State(a): State<Arc<FakeAtlassian>>,
    Path(cloud): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> StatusCode {
    let status = a.delete_status.load(Ordering::SeqCst);
    if status != 0 {
        return StatusCode::from_u16(status).unwrap();
    }
    for id in body["webhookIds"].as_array().cloned().unwrap_or_default() {
        let id = id.as_i64().unwrap();
        a.deletes.lock().unwrap().push((cloud.clone(), id));
        a.live
            .lock()
            .unwrap()
            .retain(|(c, i)| !(*c == cloud && *i == id));
    }
    StatusCode::ACCEPTED
}

async fn refresh(
    State(a): State<Arc<FakeAtlassian>>,
    Path(_cloud): Path<String>,
    Json(_body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    a.refreshes.fetch_add(1, Ordering::SeqCst);
    let status = a.refresh_status.load(Ordering::SeqCst);
    if status != 0 {
        return (
            StatusCode::from_u16(status).unwrap(),
            Json(serde_json::json!({"errorMessages": ["unavailable"]})),
        );
    }
    (
        StatusCode::OK,
        Json(serde_json::json!({ "expirationDate": a.expiration_ms.load(Ordering::SeqCst) })),
    )
}

struct World {
    svc: Arc<AtlassianIntegrationService>,
    creds: Arc<talos_oauth::OAuthCredentialService>,
    pool: sqlx::Pool<sqlx::Postgres>,
    atlassian: Arc<FakeAtlassian>,
    api_base: String,
    _db: common::TestDb,
}

async fn world() -> World {
    let (pool, db) = common::isolated_db_pool().await;
    let atlassian = Arc::new(FakeAtlassian {
        next_webhook_id: AtomicI64::new(1000),
        live: Mutex::new(Vec::new()),
        registrations: Mutex::new(Vec::new()),
        refreshes: AtomicUsize::new(0),
        deletes: Mutex::new(Vec::new()),
        refresh_status: AtomicU16::new(0),
        delete_status: AtomicU16::new(0),
        reject_registration: std::sync::atomic::AtomicBool::new(false),
        expiration_ms: AtomicI64::new(
            (chrono::Utc::now() + chrono::Duration::days(30)).timestamp_millis(),
        ),
    });
    let app = Router::new()
        .route(
            "/ex/jira/{cloud}/rest/api/3/webhook",
            post(register).get(list).delete(delete),
        )
        .route("/ex/jira/{cloud}/rest/api/3/webhook/refresh", put(refresh))
        .with_state(atlassian.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let api_base = format!("http://{}", listener.local_addr().expect("addr"));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    let secrets =
        Arc::new(controller::secrets::SecretsManager::new(pool.clone()).expect("secrets manager"));
    secrets.initialize().await.expect("initialize secrets");
    let creds = Arc::new(talos_oauth::OAuthCredentialService::new(
        pool.clone(),
        secrets,
    ));
    let svc = service(&pool, &creds, &api_base, PUBLIC_BASE);
    World {
        svc,
        creds,
        pool,
        atlassian,
        api_base,
        _db: db,
    }
}

fn service(
    pool: &sqlx::Pool<sqlx::Postgres>,
    creds: &Arc<talos_oauth::OAuthCredentialService>,
    api_base: &str,
    public_base: &str,
) -> Arc<AtlassianIntegrationService> {
    let svc = AtlassianIntegrationService::with_client_for_tests(
        pool.clone(),
        "test-client-id",
        CLIENT_SECRET,
        "https://talos.example.com/api/atlassian/callback",
    )
    .with_credentials_service(creds.clone());
    svc.with_push_endpoints_for_tests(api_base, public_base);
    Arc::new(svc)
}

async fn user(w: &World) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@jira-push.test"))
    .execute(&w.pool)
    .await
    .expect("user");
    user
}

/// Connect a Jira site for a user: (cloud id, connection id). The token is
/// stored the way a real connect stores it, with an hour left on it.
async fn connect_site(
    w: &World,
    user: Uuid,
    scope: &str,
    account_id: Option<&str>,
) -> (String, Uuid) {
    connect_site_at(w, user, scope, account_id, "https://example.atlassian.net").await
}

/// [`connect_site`] on a stated site address.
async fn connect_site_at(
    w: &World,
    user: Uuid,
    scope: &str,
    account_id: Option<&str>,
    site_url: &str,
) -> (String, Uuid) {
    let cloud_id = Uuid::new_v4().to_string();
    let integration: Uuid = sqlx::query_scalar(
        "INSERT INTO atlassian_integrations (user_id, cloud_id, site_url, display_name, scope, account_id) \
         VALUES ($1, $2, $5, 'Example Site', $3, $4) RETURNING id",
    )
    .bind(user)
    .bind(&cloud_id)
    .bind(scope)
    .bind(account_id)
    .bind(site_url)
    .fetch_one(&w.pool)
    .await
    .expect("connection");
    w.creds
        .store_credentials(
            user,
            "atlassian",
            &cloud_id,
            &format!("access-token-of-{user}"),
            Some("test-refresh-token"),
            talos_oauth::oauth_expires_at(Some(3600)),
            scope,
            vec![],
        )
        .await
        .expect("store the token");
    (cloud_id, integration)
}

/// A user with one connected site that may register a webhook.
async fn user_with_jira(w: &World) -> (Uuid, String, Uuid) {
    let user = user(w).await;
    let account = format!("557058:{}", Uuid::new_v4());
    let (cloud_id, integration) = connect_site(w, user, SCOPE_WITH_WEBHOOKS, Some(&account)).await;
    (user, cloud_id, integration)
}

async fn registered(w: &World, user: Uuid) -> JiraPushRegistration {
    let (registration, created) = w
        .svc
        .register_push_channel(user, None)
        .await
        .expect("register");
    assert!(created);
    registration
}

async fn registration_rows(w: &World, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM atlassian_webhook_registrations WHERE user_id = $1")
        .bind(user)
        .fetch_one(&w.pool)
        .await
        .expect("count registrations")
}

async fn stored_binding(w: &World, user: Uuid) -> Option<Uuid> {
    let rows = JiraPushChannelInventory::new(w.pool.clone())
        .list_channels(user)
        .await
        .expect("list channels");
    assert_eq!(rows.len(), 1, "one channel for this user");
    rows[0].workflow_id
}

async fn audit(w: &World, user: Uuid, event_type: &str) -> Vec<(bool, Option<String>)> {
    sqlx::query_as(
        "SELECT success, error_message FROM google_calendar_audit_log \
         WHERE user_id = $1 AND event_type = $2 ORDER BY created_at",
    )
    .bind(user)
    .bind(event_type)
    .fetch_all(&w.pool)
    .await
    .expect("audit rows")
}

/// Why starts for this user were refused, leaving out the harness's own
/// "created but not dispatched" rows (see the module docs).
async fn refusals(w: &World, user: Uuid) -> Vec<String> {
    audit(w, user, "jira_workflow_not_started")
        .await
        .into_iter()
        .filter_map(|(_, reason)| reason)
        .filter(|reason| reason != "trigger_failed")
        .collect()
}

/// Starts that created their execution and then had no bus to dispatch on.
async fn undispatched(w: &World, user: Uuid) -> i64 {
    audit(w, user, "jira_workflow_not_started")
        .await
        .into_iter()
        .filter(|(_, reason)| reason.as_deref() == Some("trigger_failed"))
        .count() as i64
}

/// Make the workflow accept exactly one trigger input and nothing else. The
/// trigger service validates the input before it creates an execution, so an
/// execution existing afterwards means the start carried exactly this.
async fn accept_only(w: &World, workflow: Uuid, jira_push: serde_json::Value) {
    sqlx::query("UPDATE workflows SET input_schema = $1 WHERE id = $2")
        .bind(serde_json::json!({
            "type": "object",
            "required": ["jira_push"],
            "additionalProperties": false,
            "properties": { "jira_push": { "enum": [jira_push] } },
        }))
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("set the input schema");
}

async fn executions(w: &World, workflow: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflow_executions WHERE workflow_id = $1")
        .bind(workflow)
        .fetch_one(&w.pool)
        .await
        .expect("count executions")
}

fn delivery_token() -> String {
    jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({
            "iss": "example-app",
            "exp": (chrono::Utc::now() + chrono::Duration::minutes(3)).timestamp(),
            // A delivery token is single-use; Atlassian's carry a `jti`.
            "jti": Uuid::new_v4().to_string(),
        }),
        &jsonwebtoken::EncodingKey::from_secret(CLIENT_SECRET.as_bytes()),
    )
    .expect("sign")
}

fn delivery_headers(identifier: Option<&str>) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", delivery_token()).parse().unwrap(),
    );
    if let Some(identifier) = identifier {
        headers.insert(
            "X-Atlassian-Webhook-Identifier",
            identifier.parse().unwrap(),
        );
    }
    headers
}

/// A delivery as Atlassian sends one: the matched ids, the event, and the
/// whole issue — whose content must go nowhere.
fn delivery_body(webhook_ids: &[i64]) -> String {
    delivery_body_for_issue(webhook_ids, "PROJ-7")
}

fn delivery_body_for_issue(webhook_ids: &[i64], issue_key: &str) -> String {
    serde_json::json!({
        "timestamp": chrono::Utc::now().timestamp_millis(),
        "webhookEvent": "jira:issue_updated",
        "matchedWebhookIds": webhook_ids,
        "user": {"displayName": "Someone Example"},
        "issue": {
            "id": "10001",
            "self": "https://example.atlassian.net/rest/api/3/issue/10001",
            "key": issue_key,
            "fields": {
                "summary": "Quarterly numbers",
                "description": "private notes",
                "assignee": {"displayName": "Someone Example"},
            },
        },
        "changelog": {"items": [{"field": "status", "toString": "Confidential review"}]},
    })
    .to_string()
}

async fn deliver(w: &World, webhook_ids: &[i64], identifier: Option<&str>) -> PushReceipt {
    w.svc
        .receive_push(
            &delivery_headers(identifier),
            Body::from(delivery_body(webhook_ids)),
        )
        .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_webhook_is_registered_only_for_the_callers_own_connection() {
    let w = world().await;
    let (alice, alice_cloud, _) = user_with_jira(&w).await;
    let (bob, bob_cloud, _) = user_with_jira(&w).await;
    let nobody = user(&w).await;

    // Her own connection, named or not: one webhook, asked for with her own
    // token, for her own issues, delivered to this deployment's one address.
    let (first, created) = w
        .svc
        .register_push_channel(alice, None)
        .await
        .expect("register");
    assert!(created);
    assert_eq!(
        (first.user_id, first.cloud_id.as_str()),
        (alice, alice_cloud.as_str())
    );
    assert_eq!(first.url, format!("{PUBLIC_BASE}{WEBHOOK_PATH}"));
    assert_eq!(first.workflow_id, None, "a new channel starts nothing");
    let days_left = (first.expires_at.expect("an expiry") - chrono::Utc::now()).num_days();
    assert!((29..=30).contains(&days_left), "{days_left}");
    let account: String =
        sqlx::query_scalar("SELECT account_id FROM atlassian_integrations WHERE user_id = $1")
            .bind(alice)
            .fetch_one(&w.pool)
            .await
            .expect("account id");
    {
        let asked = w.atlassian.registrations.lock().unwrap();
        assert_eq!(asked.len(), 1);
        let (cloud, bearer, body) = &asked[0];
        assert_eq!(cloud, &alice_cloud);
        assert_eq!(bearer, &format!("Bearer access-token-of-{alice}"));
        assert_eq!(body["url"], format!("{PUBLIC_BASE}{WEBHOOK_PATH}"));
        assert_eq!(
            body["webhooks"][0]["jqlFilter"],
            format!("assignee = \"{account}\"")
        );
    }
    assert_eq!(audit(&w, alice, "jira_webhook_registered").await.len(), 1);

    // Asking again returns the one she has; Atlassian is not asked.
    let (again, created) = w
        .svc
        .register_push_channel(alice, Some(&alice_cloud))
        .await
        .expect("register again");
    assert!(!created);
    assert_eq!(again.id, first.id);
    assert_eq!(w.atlassian.registrations.lock().unwrap().len(), 1);

    // Bob's connection is not hers to register for, and is said the way a
    // site that does not exist is. Nor can someone with no connection.
    for (who, cloud) in [
        (alice, Some(bob_cloud.as_str())),
        (alice, Some("no-such-site")),
        (nobody, None),
        (nobody, Some(alice_cloud.as_str())),
    ] {
        let refused = w.svc.register_push_channel(who, cloud).await.unwrap_err();
        assert!(
            matches!(refused, JiraPushError::ConnectionNotFound),
            "{who} {cloud:?}: {refused}"
        );
        assert_eq!(refused.user_facing_message(), "No such Jira connection.");
    }
    assert_eq!(w.atlassian.registrations.lock().unwrap().len(), 1);
    assert_eq!(registration_rows(&w, bob).await, 0);
    assert_eq!(registration_rows(&w, nobody).await, 0);
    assert_eq!(registration_rows(&w, alice).await, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registration_that_cannot_work_is_refused_before_atlassian_is_asked() {
    let w = world().await;

    // A connection made before the webhook scope was asked for.
    let old = user(&w).await;
    connect_site(&w, old, "read:jira-work offline_access", Some("557058:abc")).await;
    assert!(matches!(
        w.svc.register_push_channel(old, None).await.unwrap_err(),
        JiraPushError::NeedsReconnect(ReconnectReason::MissingWebhookScope)
    ));

    // No account id recorded, or one that could not be written into a filter.
    for account in [None, Some("abc\" OR project = SECRET")] {
        let who = user(&w).await;
        connect_site(&w, who, SCOPE_WITH_WEBHOOKS, account).await;
        assert!(matches!(
            w.svc.register_push_channel(who, None).await.unwrap_err(),
            JiraPushError::NeedsReconnect(ReconnectReason::MissingAccountId)
        ));
    }

    // Two connections and no site named.
    let two = user(&w).await;
    connect_site(&w, two, SCOPE_WITH_WEBHOOKS, Some("557058:abc")).await;
    let (second_cloud, _) = connect_site(&w, two, SCOPE_WITH_WEBHOOKS, Some("557058:abc")).await;
    assert!(matches!(
        w.svc.register_push_channel(two, None).await.unwrap_err(),
        JiraPushError::ConnectionAmbiguous
    ));

    // An address Atlassian cannot deliver to: said with the variable to set.
    let (ok_user, _, _) = user_with_jira(&w).await;
    for base in [
        "http://localhost:8000",
        "http://talos.example.com",
        "https://127.0.0.1",
    ] {
        let local = service(&w.pool, &w.creds, &w.api_base, base);
        let refused = local
            .register_push_channel(ok_user, None)
            .await
            .unwrap_err();
        assert!(
            matches!(refused, JiraPushError::WebhookUrlNotUsable(_)),
            "{base}"
        );
        assert!(refused
            .user_facing_message()
            .contains("ATLASSIAN_WEBHOOK_BASE_URL"));
    }

    assert_eq!(
        w.atlassian.registrations.lock().unwrap().len(),
        0,
        "none of these reached Atlassian"
    );

    // Named, the second site registers; and a registration Atlassian answers
    // 200 to but does not create leaves no row behind.
    w.svc
        .register_push_channel(two, Some(&second_cloud))
        .await
        .expect("the named site");
    w.atlassian
        .reject_registration
        .store(true, Ordering::SeqCst);
    let refused = w
        .svc
        .register_push_channel(ok_user, None)
        .await
        .unwrap_err();
    assert!(matches!(
        refused,
        JiraPushError::Upstream {
            failure: UpstreamFailure::Rejected,
            ..
        }
    ));
    assert!(!refused.user_facing_message().contains("clause"));
    assert_eq!(registration_rows(&w, ok_user).await, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_starts_the_bound_workflow_once_as_the_registrations_owner() {
    let w = world().await;
    let (alice, cloud, _) = user_with_jira(&w).await;
    let registration = registered(&w, alice).await;
    let workflow = common::create_test_workflow(&w.pool, alice, "on-jira-change").await;
    let state = mcp_common::mcp_state(w.pool.clone()).await;
    let orchestration = state.execution_orchestration_service.clone();

    // Registered and unbound: the delivery is taken and starts nothing.
    let receipt = deliver(&w, &[registration.webhook_id], Some("delivery-0")).await;
    assert_eq!(
        receipt.note,
        ReceiptNote::Accepted {
            matched: 1,
            off_site: 0,
            ambiguous: 0,
            rate_limited: 0,
            capped: 0,
            duplicates: 0
        }
    );
    assert!(receipt.starts.is_empty());

    bind_registration_workflow(&w.pool, alice, registration.id, Some(workflow))
        .await
        .expect("bind");
    // The workflow takes exactly this and nothing else: four identifiers.
    let identifiers = serde_json::json!({
        "cloud_id": cloud,
        "webhook_id": registration.webhook_id,
        "event": "jira:issue_updated",
        "issue_key": "PROJ-7",
    });
    accept_only(&w, workflow, identifiers.clone()).await;

    // Bound: one start, for her workflow, as her, with identifiers only.
    let receipt = deliver(&w, &[registration.webhook_id], Some("delivery-1")).await;
    assert_eq!(receipt.status(), StatusCode::OK);
    assert_eq!(receipt.starts.len(), 1);
    let start = &receipt.starts[0];
    assert_eq!(
        (start.user_id, start.workflow_id, start.registration_id),
        (alice, workflow, registration.id)
    );
    let carried = jira_push_trigger_input(start);
    assert_eq!(carried, serde_json::json!({ "jira_push": identifiers }));
    let rendered = format!("{start:?} {carried}");
    for content in [
        "Quarterly",
        "private",
        "Someone",
        "Confidential",
        "atlassian.net",
    ] {
        assert!(
            !rendered.contains(content),
            "{content} reached the start: {rendered}"
        );
    }
    run_planned_starts(&w.pool, Some(&orchestration), &receipt.starts).await;
    // The execution exists, so the trigger service accepted the input — and
    // it accepts only the four identifiers above.
    assert_eq!(executions(&w, workflow).await, 1);
    assert!(refusals(&w, alice).await.is_empty());
    let owner: Uuid =
        sqlx::query_scalar("SELECT user_id FROM workflow_executions WHERE workflow_id = $1")
            .bind(workflow)
            .fetch_one(&w.pool)
            .await
            .expect("the execution's user");
    assert_eq!(owner, alice, "started as the registration's owner");
    let last: Option<chrono::DateTime<chrono::Utc>> = sqlx::query_scalar(
        "SELECT last_delivery_at FROM atlassian_webhook_registrations WHERE id = $1",
    )
    .bind(registration.id)
    .fetch_one(&w.pool)
    .await
    .expect("last delivery");
    assert!(last.is_some());

    // Atlassian retries with the same identifier: nothing is started again.
    let again = deliver(&w, &[registration.webhook_id], Some("delivery-1")).await;
    assert_eq!(
        again.note,
        ReceiptNote::Accepted {
            matched: 1,
            off_site: 0,
            ambiguous: 0,
            rate_limited: 0,
            capped: 0,
            duplicates: 1
        }
    );
    assert!(again.starts.is_empty());
    run_planned_starts(&w.pool, Some(&orchestration), &again.starts).await;
    assert_eq!(executions(&w, workflow).await, 1);

    // A different delivery is a different event.
    let next = deliver(&w, &[registration.webhook_id], Some("delivery-2")).await;
    assert_eq!(next.starts.len(), 1);
    run_planned_starts(&w.pool, Some(&orchestration), &next.starts).await;
    assert_eq!(executions(&w, workflow).await, 2);
    assert!(refusals(&w, alice).await.is_empty());
    assert_eq!(
        undispatched(&w, alice).await,
        2,
        "this harness has no bus: each created execution is recorded as not dispatched"
    );

    // An issue key that is not a plain key is not passed on at all, so the
    // start no longer carries what the workflow accepts and is refused.
    let odd = w
        .svc
        .receive_push(
            &delivery_headers(Some("delivery-odd-key")),
            Body::from(delivery_body_for_issue(
                &[registration.webhook_id],
                "PROJ-7/../../Quarterly numbers",
            )),
        )
        .await;
    assert_eq!(odd.starts.len(), 1);
    assert_eq!(odd.starts[0].issue_key, None);
    run_planned_starts(&w.pool, Some(&orchestration), &odd.starts).await;
    assert_eq!(refusals(&w, alice).await, ["input_refused"]);
    assert_eq!(executions(&w, workflow).await, 2);

    // The workflow is switched off: a row with a reason from the closed set,
    // no execution, and the delivery itself is still a 200.
    sqlx::query("UPDATE workflows SET is_enabled = false WHERE id = $1")
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("switch the workflow off");
    let off = deliver(&w, &[registration.webhook_id], Some("delivery-3")).await;
    assert_eq!(off.status(), StatusCode::OK);
    run_planned_starts(&w.pool, Some(&orchestration), &off.starts).await;
    assert_eq!(
        refusals(&w, alice).await,
        ["input_refused", "workflow_not_live"]
    );
    assert!(audit(&w, alice, "jira_workflow_not_started")
        .await
        .iter()
        .all(|(success, _)| !success));
    assert_eq!(executions(&w, workflow).await, 2);
    sqlx::query("UPDATE workflows SET is_enabled = true WHERE id = $1")
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("switch the workflow on");

    // No trigger service wired: said so, not silently nothing.
    let unwired = deliver(&w, &[registration.webhook_id], Some("delivery-4")).await;
    run_planned_starts(&w.pool, None, &unwired.starts).await;
    assert_eq!(
        refusals(&w, alice).await,
        [
            "input_refused",
            "workflow_not_live",
            "trigger_service_not_wired"
        ]
    );
    assert_eq!(executions(&w, workflow).await, 2);

    // Nothing a ticket says reached the audit log.
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM google_calendar_audit_log WHERE metadata::text LIKE '%Quarterly%' \
         OR metadata::text LIKE '%private%' OR metadata::text LIKE '%PROJ-7%' \
         OR coalesce(error_message, '') LIKE '%Quarterly%'",
    )
    .fetch_one(&w.pool)
    .await
    .expect("scan audit");
    assert_eq!(leaked, 0);
}

/// The route itself, as the controller mounts it: the handler answers and
/// the start it calls for happens after the answer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_route_answers_and_then_starts_the_workflow() {
    use tower::ServiceExt;
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let registration = registered(&w, alice).await;
    let workflow = common::create_test_workflow(&w.pool, alice, "on-jira-change").await;
    bind_registration_workflow(&w.pool, alice, registration.id, Some(workflow))
        .await
        .expect("bind");
    let state = mcp_common::mcp_state(w.pool.clone()).await;
    let orchestration: Option<Arc<ExecutionOrchestrationService>> =
        Some(state.execution_orchestration_service.clone());
    let app = Router::new()
        .route(WEBHOOK_PATH, post(webhook_handler))
        .with_state(w.svc.clone())
        .layer(Extension(orchestration));

    let post_delivery = |authorization: Option<String>| {
        let mut request = axum::http::Request::builder()
            .method("POST")
            .uri(WEBHOOK_PATH)
            .header("X-Atlassian-Webhook-Identifier", "delivery-over-http");
        if let Some(authorization) = authorization {
            request = request.header(header::AUTHORIZATION, authorization);
        }
        app.clone().oneshot(
            request
                .body(Body::from(delivery_body(&[registration.webhook_id])))
                .unwrap(),
        )
    };

    // No token, and a token signed with something else: 401, and nothing is
    // recorded as handled (the same identifier is accepted below).
    assert_eq!(
        post_delivery(None).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let forged = jsonwebtoken::encode(
        &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
        &serde_json::json!({"exp": chrono::Utc::now().timestamp() + 120}),
        &jsonwebtoken::EncodingKey::from_secret(b"another-secret-of-enough-length-"),
    )
    .unwrap();
    assert_eq!(
        post_delivery(Some(format!("Bearer {forged}")))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let handled: i64 = sqlx::query_scalar("SELECT count(*) FROM atlassian_webhook_deliveries")
        .fetch_one(&w.pool)
        .await
        .expect("count deliveries");
    assert_eq!(handled, 0);
    // A fixed wait is the right shape for an absence (see `eventually`).
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;
    assert_eq!(executions(&w, workflow).await, 0);

    let accepted = post_delivery(Some(format!("Bearer {}", delivery_token())))
        .await
        .unwrap();
    assert_eq!(accepted.status(), StatusCode::OK);
    let pool = w.pool.clone();
    common::eventually_default("the delivery's workflow start", || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM workflow_executions WHERE workflow_id = $1",
            )
            .bind(workflow)
            .fetch_one(&pool)
            .await
            .expect("count executions")
                == 1
        }
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unknown_or_ambiguous_webhook_id_starts_nothing() {
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let (bob, _, _) = user_with_jira(&w).await;
    let state = mcp_common::mcp_state(w.pool.clone()).await;
    let orchestration = state.execution_orchestration_service.clone();

    // Two sites issue the same webhook id to two different users.
    w.atlassian.next_webhook_id.store(4242, Ordering::SeqCst);
    let alices = registered(&w, alice).await;
    w.atlassian.next_webhook_id.store(4242, Ordering::SeqCst);
    let bobs = registered(&w, bob).await;
    assert_eq!((alices.webhook_id, bobs.webhook_id), (4242, 4242));
    assert_ne!(alices.cloud_id, bobs.cloud_id);
    let alice_wf = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bob_wf = common::create_test_workflow(&w.pool, bob, "bobs").await;
    bind_registration_workflow(&w.pool, alice, alices.id, Some(alice_wf))
        .await
        .expect("bind alice");
    bind_registration_workflow(&w.pool, bob, bobs.id, Some(bob_wf))
        .await
        .expect("bind bob");

    // An id Talos never registered: accepted (Atlassian must not retry what
    // will never match) and nothing is started.
    let unknown = deliver(&w, &[999_999], Some("delivery-unknown")).await;
    assert_eq!(
        unknown.note,
        ReceiptNote::Accepted {
            matched: 0,
            off_site: 0,
            ambiguous: 0,
            rate_limited: 0,
            capped: 0,
            duplicates: 0
        }
    );
    assert!(unknown.starts.is_empty());

    // The shared id: the delivery does not say which site sent it, so neither
    // user's workflow is started, and each is told why.
    let ambiguous = deliver(&w, &[4242], Some("delivery-ambiguous")).await;
    assert_eq!(
        ambiguous.note,
        ReceiptNote::Accepted {
            matched: 2,
            off_site: 0,
            ambiguous: 2,
            rate_limited: 0,
            capped: 0,
            duplicates: 0
        }
    );
    assert!(ambiguous.starts.is_empty());
    run_planned_starts(&w.pool, Some(&orchestration), &ambiguous.starts).await;
    assert_eq!(executions(&w, alice_wf).await, 0);
    assert_eq!(executions(&w, bob_wf).await, 0);
    for who in [alice, bob] {
        let rows = audit(&w, who, "jira_workflow_not_started").await;
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].1.as_deref(), Some("ambiguous_webhook_id"));
    }
    // Withheld, so not recorded as handled either.
    let handled: i64 = sqlx::query_scalar("SELECT count(*) FROM atlassian_webhook_deliveries")
        .fetch_one(&w.pool)
        .await
        .expect("count deliveries");
    assert_eq!(handled, 0);

    // A registration with an id of its own is not affected by its neighbours.
    let (carol, _, _) = user_with_jira(&w).await;
    w.atlassian.next_webhook_id.store(5000, Ordering::SeqCst);
    let carols = registered(&w, carol).await;
    let carol_wf = common::create_test_workflow(&w.pool, carol, "carols").await;
    bind_registration_workflow(&w.pool, carol, carols.id, Some(carol_wf))
        .await
        .expect("bind carol");
    let mixed = deliver(&w, &[4242, 5000], Some("delivery-mixed")).await;
    assert_eq!(
        mixed.note,
        ReceiptNote::Accepted {
            matched: 3,
            off_site: 0,
            ambiguous: 2,
            rate_limited: 0,
            capped: 0,
            duplicates: 0
        }
    );
    assert_eq!(mixed.starts.len(), 1);
    assert_eq!(mixed.starts[0].user_id, carol);
    run_planned_starts(&w.pool, Some(&orchestration), &mixed.starts).await;
    assert_eq!(executions(&w, carol_wf).await, 1);
    assert_eq!(executions(&w, alice_wf).await, 0);
    assert_eq!(executions(&w, bob_wf).await, 0);
}

/// More matching registrations than the receiver reads must not turn an
/// ambiguous webhook id into an unambiguous one: the row limit would
/// otherwise hide the id's second site, and the first would be started.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_that_matches_more_registrations_than_are_read_starts_nothing() {
    let w = world().await;
    // 255 registrations ahead of the one that matters: 51 webhook ids, each
    // on five sites, all one user's.
    let crowd = user(&w).await;
    sqlx::query(
        "INSERT INTO atlassian_webhook_registrations (user_id, cloud_id, webhook_id, url) \
         SELECT $1, 'crowd-' || lpad(i::text, 3, '0'), 100 + (i / 5), 'https://talos.example.com/x' \
         FROM generate_series(0, 254) AS i",
    )
    .bind(crowd)
    .execute(&w.pool)
    .await
    .expect("the crowd");
    // Webhook id 9000 on TWO sites, each bound to its owner's workflow. Sorted
    // after the crowd, only the first of the two falls inside 256 rows.
    let mut bound = Vec::new();
    for site in ["zz-site-a", "zz-site-b"] {
        let owner = user(&w).await;
        let workflow = common::create_test_workflow(&w.pool, owner, site).await;
        sqlx::query(
            "INSERT INTO atlassian_webhook_registrations \
                 (user_id, cloud_id, webhook_id, url, workflow_id) \
             VALUES ($1, $2, 9000, 'https://talos.example.com/x', $3)",
        )
        .bind(owner)
        .bind(site)
        .bind(workflow)
        .execute(&w.pool)
        .await
        .expect("a registration of the shared id");
        // Its connection, on the site the deliveries below are about: the
        // test is about ambiguity, not about the site binding.
        sqlx::query(
            "INSERT INTO atlassian_integrations (user_id, cloud_id, site_url, display_name, scope) \
             VALUES ($1, $2, 'https://example.atlassian.net', 'Example Site', $3)",
        )
        .bind(owner)
        .bind(site)
        .bind(SCOPE_WITH_WEBHOOKS)
        .execute(&w.pool)
        .await
        .expect("the owner's connection");
        bound.push(workflow);
    }

    let mut ids: Vec<i64> = (100..151).collect();
    ids.push(9000);
    let receipt = deliver(&w, &ids, Some("delivery-crowded")).await;
    assert_eq!(receipt.note, ReceiptNote::TooManyRegistrations);
    assert_eq!(receipt.status(), StatusCode::OK);
    assert!(receipt.starts.is_empty(), "{:?}", receipt.starts);
    let state = mcp_common::mcp_state(w.pool.clone()).await;
    run_planned_starts(
        &w.pool,
        Some(&state.execution_orchestration_service),
        &receipt.starts,
    )
    .await;
    for workflow in bound {
        assert_eq!(executions(&w, workflow).await, 0);
    }

    // Without the crowd in the delivery, the shared id is seen whole and is
    // withheld as ambiguous, as ever.
    let alone = deliver(&w, &[9000], Some("delivery-alone")).await;
    assert_eq!(
        alone.note,
        ReceiptNote::Accepted {
            matched: 2,
            off_site: 0,
            ambiguous: 2,
            rate_limited: 0,
            capped: 0,
            duplicates: 0
        }
    );
    assert!(alone.starts.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_users_delivery_cannot_start_another_users_workflow() {
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let (bob, _, _) = user_with_jira(&w).await;
    let alices = registered(&w, alice).await;
    let bobs = registered(&w, bob).await;
    assert_ne!(alices.webhook_id, bobs.webhook_id);
    let alice_wf = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bob_wf = common::create_test_workflow(&w.pool, bob, "bobs").await;
    bind_registration_workflow(&w.pool, alice, alices.id, Some(alice_wf))
        .await
        .expect("bind alice");
    bind_registration_workflow(&w.pool, bob, bobs.id, Some(bob_wf))
        .await
        .expect("bind bob");
    let state = mcp_common::mcp_state(w.pool.clone()).await;
    let orchestration = state.execution_orchestration_service.clone();

    // A delivery for her webhook starts hers and only hers.
    let hers = deliver(&w, &[alices.webhook_id], Some("delivery-a")).await;
    assert_eq!(hers.starts.len(), 1);
    assert_eq!(
        (hers.starts[0].user_id, hers.starts[0].workflow_id),
        (alice, alice_wf)
    );
    run_planned_starts(&w.pool, Some(&orchestration), &hers.starts).await;
    assert_eq!(executions(&w, alice_wf).await, 1);
    assert_eq!(executions(&w, bob_wf).await, 0);

    // A delivery that matched both starts each as its own user.
    let both = deliver(
        &w,
        &[alices.webhook_id, bobs.webhook_id],
        Some("delivery-ab"),
    )
    .await;
    let mut planned: Vec<(Uuid, Uuid)> = both
        .starts
        .iter()
        .map(|s| (s.user_id, s.workflow_id))
        .collect();
    planned.sort();
    let mut expected = vec![(alice, alice_wf), (bob, bob_wf)];
    expected.sort();
    assert_eq!(planned, expected);
    run_planned_starts(&w.pool, Some(&orchestration), &both.starts).await;
    assert_eq!(executions(&w, alice_wf).await, 2);
    assert_eq!(executions(&w, bob_wf).await, 1);
    let strangers: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM workflow_executions e JOIN workflows w ON w.id = e.workflow_id \
         WHERE e.user_id <> w.user_id",
    )
    .fetch_one(&w.pool)
    .await
    .expect("scan executions");
    assert_eq!(
        strangers, 0,
        "every execution belongs to its workflow's owner"
    );

    // Her row is made to name HIS workflow, behind the bind's back. The start
    // is still made as her, and the trigger does not find his workflow for
    // her: a binding is never what makes a workflow startable.
    sqlx::query("UPDATE atlassian_webhook_registrations SET workflow_id = $1 WHERE id = $2")
        .bind(bob_wf)
        .bind(alices.id)
        .execute(&w.pool)
        .await
        .expect("point her row at his workflow");
    let crossed = deliver(&w, &[alices.webhook_id], Some("delivery-crossed")).await;
    assert_eq!(crossed.starts.len(), 1);
    assert_eq!(crossed.starts[0].user_id, alice);
    run_planned_starts(&w.pool, Some(&orchestration), &crossed.starts).await;
    assert_eq!(
        executions(&w, bob_wf).await,
        1,
        "his workflow was not started"
    );
    assert_eq!(refusals(&w, alice).await, ["workflow_not_found"]);
    assert!(refusals(&w, bob).await.is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_workflow_is_bound_only_by_its_owner_to_the_owners_own_channel() {
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let (bob, _, _) = user_with_jira(&w).await;
    let alices = registered(&w, alice).await;
    let bobs = registered(&w, bob).await;
    let alice_wf = common::create_test_workflow(&w.pool, alice, "alices").await;
    let bob_wf = common::create_test_workflow(&w.pool, bob, "bobs").await;

    // Her own workflow, her own channel.
    bind_registration_workflow(&w.pool, alice, alices.id, Some(alice_wf))
        .await
        .expect("bind");
    assert_eq!(stored_binding(&w, alice).await, Some(alice_wf));
    assert_eq!(audit(&w, alice, "jira_workflow_bound").await.len(), 1);

    // Bob's workflow on her channel, and one that does not exist: refused,
    // said the same way, and her binding is what it was.
    for not_hers in [bob_wf, Uuid::new_v4()] {
        assert_eq!(
            bind_registration_workflow(&w.pool, alice, alices.id, Some(not_hers))
                .await
                .unwrap_err(),
            BindWorkflowRefusal::WorkflowNotBindable
        );
    }
    assert_eq!(stored_binding(&w, alice).await, Some(alice_wf));

    // Her workflow on Bob's channel: his channel is not hers to bind, and it
    // is left with no binding. Nor may Bob point his channel at her workflow.
    assert_eq!(
        bind_registration_workflow(&w.pool, alice, bobs.id, Some(alice_wf))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::ChannelNotFound
    );
    assert_eq!(
        bind_registration_workflow(&w.pool, bob, bobs.id, Some(alice_wf))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::WorkflowNotBindable
    );
    assert_eq!(stored_binding(&w, bob).await, None);
    assert_eq!(
        bind_registration_workflow(&w.pool, alice, Uuid::new_v4(), Some(alice_wf))
            .await
            .unwrap_err(),
        BindWorkflowRefusal::ChannelNotFound
    );
    // Clearing someone else's binding is refused like binding it.
    assert_eq!(
        bind_registration_workflow(&w.pool, bob, alices.id, None)
            .await
            .unwrap_err(),
        BindWorkflowRefusal::ChannelNotFound
    );
    assert_eq!(stored_binding(&w, alice).await, Some(alice_wf));

    // The path the tools take: by integration name, through the set. The
    // same rules, and the row an operator sees.
    let set = PushChannelInventorySet::new(vec![Arc::new(JiraPushChannelInventory::new(
        w.pool.clone(),
    ))])
    .with_provisioners(vec![Arc::new(JiraPushProvisioner::new(w.svc.clone()))]);
    assert_eq!(
        set.bind_workflow(INTEGRATION_NAME, alice, alices.id, Some(bob_wf))
            .await,
        Err(BindWorkflowRefusal::WorkflowNotBindable)
    );
    assert_eq!(
        set.bind_workflow(INTEGRATION_NAME, bob, alices.id, Some(bob_wf))
            .await,
        Err(BindWorkflowRefusal::ChannelNotFound),
        "another user cannot bind this channel, even to a workflow of their own"
    );
    assert_eq!(
        set.bind_workflow("gcal", alice, alices.id, Some(alice_wf))
            .await,
        Err(BindWorkflowRefusal::UnknownIntegration)
    );
    assert_eq!(
        set.bind_workflow(INTEGRATION_NAME, alice, alices.id, None)
            .await,
        Ok(())
    );
    assert_eq!(stored_binding(&w, alice).await, None);
    assert_eq!(audit(&w, alice, "jira_workflow_unbound").await.len(), 1);

    let survey = set.survey(alice).await;
    assert_eq!(survey.surveyed_integrations, [INTEGRATION_NAME]);
    assert_eq!(survey.rows.len(), 1);
    let row = serde_json::to_value(&survey.rows[0]).unwrap();
    assert_eq!(row["integration"], "atlassian");
    assert_eq!(row["channel_id"], alices.id.to_string());
    assert_eq!(row["display_name"], "Example Site");
    assert_eq!(row["module_binding"], "none");
    let rendered = row.to_string();
    for hidden in ["atlassian.net", "talos.example.com", "access-token", "4242"] {
        assert!(!rendered.contains(hidden), "{hidden}: {rendered}");
    }

    // Deleting the workflow clears the binding rather than leaving a row
    // that names nothing.
    bind_registration_workflow(&w.pool, alice, alices.id, Some(alice_wf))
        .await
        .expect("bind again");
    sqlx::query("DELETE FROM workflows WHERE id = $1")
        .bind(alice_wf)
        .execute(&w.pool)
        .await
        .expect("delete the workflow");
    assert_eq!(stored_binding(&w, alice).await, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_refresh_moves_the_expiry_and_a_failed_one_is_recorded() {
    let w = world().await;
    let (alice, cloud, _) = user_with_jira(&w).await;
    let (bob, _, _) = user_with_jira(&w).await;
    let registration = registered(&w, alice).await;
    let row = || async {
        sqlx::query_as::<
            _,
            (
                Option<chrono::DateTime<chrono::Utc>>,
                Option<chrono::DateTime<chrono::Utc>>,
                Option<String>,
            ),
        >(
            "SELECT expires_at, refresh_failed_at, refresh_error \
             FROM atlassian_webhook_registrations WHERE id = $1",
        )
        .bind(registration.id)
        .fetch_one(&w.pool)
        .await
        .expect("registration row")
    };

    // Fresh: not due.
    assert!(w
        .svc
        .registrations_needing_refresh()
        .await
        .expect("list")
        .is_empty());

    // Two days from expiry: due, and a refresh takes Atlassian's new date.
    let soon = chrono::Utc::now() + chrono::Duration::days(2);
    sqlx::query("UPDATE atlassian_webhook_registrations SET expires_at = $1 WHERE id = $2")
        .bind(soon)
        .bind(registration.id)
        .execute(&w.pool)
        .await
        .expect("age the registration");
    let due = w.svc.registrations_needing_refresh().await.expect("list");
    assert_eq!(due.len(), 1);
    assert_eq!((due[0].id, due[0].user_id), (registration.id, alice));

    let new_expiry = chrono::Utc::now() + chrono::Duration::days(30);
    w.atlassian
        .expiration_ms
        .store(new_expiry.timestamp_millis(), Ordering::SeqCst);
    // Someone else cannot refresh it, and Atlassian is not asked.
    assert!(matches!(
        w.svc
            .refresh_push_channel(bob, registration.id)
            .await
            .unwrap_err(),
        JiraPushError::RegistrationNotFound
    ));
    assert_eq!(w.atlassian.refreshes.load(Ordering::SeqCst), 0);

    let refreshed = w
        .svc
        .refresh_push_channel(alice, registration.id)
        .await
        .expect("refresh");
    assert_eq!(refreshed.timestamp_millis(), new_expiry.timestamp_millis());
    let (expires_at, failed_at, error) = row().await;
    assert_eq!(
        expires_at.unwrap().timestamp_millis(),
        new_expiry.timestamp_millis()
    );
    assert_eq!((failed_at, error), (None, None));
    assert_eq!(audit(&w, alice, "jira_webhook_refreshed").await.len(), 1);
    assert!(w
        .svc
        .registrations_needing_refresh()
        .await
        .expect("list")
        .is_empty());

    // Atlassian is down: the failure is on the row with its kind, the expiry
    // is what it was, and the operator's list shows it as a blip, not as a
    // dead credential.
    w.atlassian.refresh_status.store(503, Ordering::SeqCst);
    let failed = w
        .svc
        .refresh_push_channel(alice, registration.id)
        .await
        .unwrap_err();
    assert!(matches!(
        failed,
        JiraPushError::Upstream {
            failure: UpstreamFailure::Server { status: 503 },
            ..
        }
    ));
    let (expires_at, failed_at, error) = row().await;
    assert_eq!(
        expires_at.unwrap().timestamp_millis(),
        new_expiry.timestamp_millis()
    );
    assert!(failed_at.is_some());
    assert_eq!(
        error.as_deref(),
        Some("Jira webhook renewal: HTTP 503 server error")
    );
    let rows = audit(&w, alice, "jira_webhook_refresh_failed").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (rows[0].0, rows[0].1.as_deref()),
        (false, Some("Jira webhook renewal: HTTP 503 server error"))
    );
    let listed = JiraPushChannelInventory::new(w.pool.clone())
        .list_channels(alice)
        .await
        .expect("list channels");
    let failure = listed[0].recent_failure.as_ref().expect("a recent failure");
    assert!(failure.error_message.contains("HTTP 503"));
    assert!(!failure.likely_oauth_failure);

    // Atlassian answers the refresh but no longer lists the webhook (it
    // ignores ids it does not know): that is a failure too, said plainly.
    w.atlassian.refresh_status.store(0, Ordering::SeqCst);
    w.atlassian
        .live
        .lock()
        .unwrap()
        .retain(|(c, _)| *c != cloud);
    assert!(matches!(
        w.svc
            .refresh_push_channel(alice, registration.id)
            .await
            .unwrap_err(),
        JiraPushError::WebhookGone
    ));
    let (_, failed_at, error) = row().await;
    assert!(failed_at.is_some());
    assert_eq!(
        error.as_deref(),
        Some("the webhook no longer exists at Atlassian")
    );

    // Long past its expiry the webhook is gone for good: it is no longer
    // retried every hour, and the list says it expired rather than nothing.
    sqlx::query(
        "UPDATE atlassian_webhook_registrations \
         SET expires_at = now() - interval '8 days', refresh_failed_at = NULL, refresh_error = NULL \
         WHERE id = $1",
    )
    .bind(registration.id)
    .execute(&w.pool)
    .await
    .expect("expire the registration");
    assert!(w
        .svc
        .registrations_needing_refresh()
        .await
        .expect("list")
        .is_empty());
    let listed = JiraPushChannelInventory::new(w.pool.clone())
        .list_channels(alice)
        .await
        .expect("list channels");
    assert_eq!(
        listed[0]
            .recent_failure
            .as_ref()
            .map(|f| f.error_message.as_str()),
        Some(talos_atlassian::push::EXPIRED_WEBHOOK_MESSAGE)
    );
    // A day past its expiry it is still tried.
    sqlx::query(
        "UPDATE atlassian_webhook_registrations SET expires_at = now() - interval '1 day' \
         WHERE id = $1",
    )
    .bind(registration.id)
    .execute(&w.pool)
    .await
    .expect("expire the registration yesterday");
    assert_eq!(
        w.svc
            .registrations_needing_refresh()
            .await
            .expect("list")
            .len(),
        1
    );

    // Listed again, the next success clears the failure.
    w.atlassian
        .live
        .lock()
        .unwrap()
        .push((cloud.clone(), registration.webhook_id));
    w.svc
        .refresh_push_channel(alice, registration.id)
        .await
        .expect("refresh after recovery");
    let (_, failed_at, error) = row().await;
    assert_eq!((failed_at, error), (None, None));
}

/// The hourly task: it refreshes what is due, forgets old delivery ids, and
/// ends as a shutdown when told to stop.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_refresh_task_refreshes_what_is_due_and_stops_on_shutdown() {
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let (bob, _, _) = user_with_jira(&w).await;
    let due = registered(&w, alice).await;
    let fresh = registered(&w, bob).await;
    sqlx::query(
        "UPDATE atlassian_webhook_registrations SET expires_at = now() + interval '3 days' \
         WHERE id = $1",
    )
    .bind(due.id)
    .execute(&w.pool)
    .await
    .expect("age one registration");
    sqlx::query(
        "INSERT INTO atlassian_webhook_deliveries (registration_id, delivery_id, received_at) \
         VALUES ($1, 'old', now() - interval '8 days'), ($1, 'recent', now() - interval '1 day')",
    )
    .bind(due.id)
    .execute(&w.pool)
    .await
    .expect("handled deliveries");

    let (stop, stopped) = tokio::sync::watch::channel(false);
    let task = tokio::spawn(talos_atlassian::push_scheduler::webhook_refresh_task(
        w.svc.clone(),
        stopped,
    ));
    let pool = w.pool.clone();
    common::eventually_default("the due registration's refresh", || {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT expires_at > now() + interval '20 days' \
                 FROM atlassian_webhook_registrations WHERE id = $1",
            )
            .bind(due.id)
            .fetch_one(&pool)
            .await
            .expect("expiry")
        }
    })
    .await;
    stop.send(true).expect("signal shutdown");
    assert_eq!(
        task.await.expect("join"),
        talos_task_supervision::TaskExit::ShuttingDown
    );

    assert_eq!(
        w.atlassian.refreshes.load(Ordering::SeqCst),
        1,
        "only the registration that was due"
    );
    assert_eq!(audit(&w, alice, "jira_webhook_refreshed").await.len(), 1);
    assert!(audit(&w, bob, "jira_webhook_refreshed").await.is_empty());
    let _ = fresh;
    let kept: Vec<String> = sqlx::query_scalar(
        "SELECT delivery_id FROM atlassian_webhook_deliveries WHERE registration_id = $1",
    )
    .bind(due.id)
    .fetch_all(&w.pool)
    .await
    .expect("handled deliveries");
    assert_eq!(kept, ["recent"]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_channel_or_disconnecting_removes_the_webhook_at_atlassian_and_here() {
    let w = world().await;
    let (alice, cloud, integration) = user_with_jira(&w).await;
    let (bob, _, _) = user_with_jira(&w).await;
    let first = registered(&w, alice).await;

    // Not hers to delete: nothing is asked of Atlassian, the row stays.
    assert!(matches!(
        w.svc.delete_push_channel(bob, first.id).await.unwrap_err(),
        JiraPushError::RegistrationNotFound
    ));
    assert!(w.atlassian.deletes.lock().unwrap().is_empty());
    assert_eq!(registration_rows(&w, alice).await, 1);

    // Hers: deleted at Atlassian with the id it issued, and here.
    assert!(w
        .svc
        .delete_push_channel(alice, first.id)
        .await
        .expect("delete"));
    assert_eq!(
        *w.atlassian.deletes.lock().unwrap(),
        [(cloud.clone(), first.webhook_id)]
    );
    assert_eq!(registration_rows(&w, alice).await, 0);
    assert_eq!(audit(&w, alice, "jira_webhook_deleted").await.len(), 1);

    // Atlassian cannot be asked: the channel still goes here, and it is said.
    let second = registered(&w, alice).await;
    w.atlassian.delete_status.store(500, Ordering::SeqCst);
    assert!(!w
        .svc
        .delete_push_channel(alice, second.id)
        .await
        .expect("delete with Atlassian down"));
    assert_eq!(registration_rows(&w, alice).await, 0);
    w.atlassian.delete_status.store(0, Ordering::SeqCst);

    // Disconnecting the connection takes its webhook with it — and only its
    // own: Bob's is untouched.
    let third = registered(&w, alice).await;
    let bobs = registered(&w, bob).await;
    w.svc
        .disconnect_integration(integration, alice)
        .await
        .expect("disconnect");
    assert!(w
        .atlassian
        .deletes
        .lock()
        .unwrap()
        .contains(&(cloud.clone(), third.webhook_id)));
    assert_eq!(registration_rows(&w, alice).await, 0);
    assert_eq!(registration_rows(&w, bob).await, 1);
    assert!(!w
        .atlassian
        .deletes
        .lock()
        .unwrap()
        .iter()
        .any(|(_, id)| *id == bobs.webhook_id));

    // A delivery for the deleted webhook now matches nothing.
    let after = deliver(&w, &[third.webhook_id], Some("delivery-after")).await;
    assert_eq!(
        after.note,
        ReceiptNote::Accepted {
            matched: 0,
            off_site: 0,
            ambiguous: 0,
            rate_limited: 0,
            capped: 0,
            duplicates: 0
        }
    );
}

/// The two tools, through the dispatcher an MCP client reaches them by.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tools_create_and_delete_only_the_callers_own_channel() {
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let (bob, bob_cloud, _) = user_with_jira(&w).await;
    let mut state = mcp_common::mcp_state(w.pool.clone()).await;

    // No set wired: said so, never a silent nothing.
    let unwired = controller::mcp::platform::dispatch(
        "create_jira_push_channel",
        Some(serde_json::json!(1)),
        &serde_json::json!({}),
        &state,
        mcp_common::agent(alice),
    )
    .await
    .expect("dispatched");
    assert!(mcp_common::error_message(&unwired).contains("wired no push-channel set"));

    state.push_channels = Some(Arc::new(
        PushChannelInventorySet::new(vec![Arc::new(JiraPushChannelInventory::new(
            w.pool.clone(),
        ))])
        .with_provisioners(vec![Arc::new(JiraPushProvisioner::new(w.svc.clone()))]),
    ));
    let call = |tool: &'static str, args: serde_json::Value, who: Uuid| {
        let state = &state;
        async move {
            controller::mcp::platform::dispatch(
                tool,
                Some(serde_json::json!(1)),
                &args,
                state,
                mcp_common::agent(who),
            )
            .await
            .expect("dispatched")
        }
    };

    // Bob's site is not hers to watch.
    let refused = call(
        "create_jira_push_channel",
        serde_json::json!({ "cloud_id": bob_cloud }),
        alice,
    )
    .await;
    assert_eq!(
        mcp_common::error_message(&refused),
        "No such Jira connection."
    );
    assert_eq!(registration_rows(&w, bob).await, 0);

    let created = mcp_common::text_json(
        &call("create_jira_push_channel", serde_json::json!({}), alice).await,
    );
    assert_eq!(created["channel"]["integration"], "atlassian");
    assert_eq!(created["channel"]["created"], true);
    let channel_id = created["channel"]["channel_id"]
        .as_str()
        .expect("a channel id")
        .to_string();
    assert_eq!(registration_rows(&w, alice).await, 1);
    let again = mcp_common::text_json(
        &call("create_jira_push_channel", serde_json::json!({}), alice).await,
    );
    assert_eq!(again["channel"]["created"], false);
    assert_eq!(again["channel"]["channel_id"], channel_id);

    // It is listed, and bound, by the same name.
    let listed =
        mcp_common::text_json(&call("list_push_channels", serde_json::json!({}), alice).await);
    assert_eq!(listed["channels"][0]["integration"], "atlassian");
    assert_eq!(listed["channels"][0]["channel_id"], channel_id);
    let workflow = common::create_test_workflow(&w.pool, alice, "on-jira-change").await;
    let bound = mcp_common::text_json(
        &call(
            "set_push_channel_workflow",
            serde_json::json!({
                "integration": "atlassian",
                "channel_id": channel_id,
                "workflow_id": workflow.to_string(),
            }),
            alice,
        )
        .await,
    );
    assert_eq!(bound["workflow_id"], workflow.to_string());
    assert_eq!(stored_binding(&w, alice).await, Some(workflow));

    // Bob cannot delete it; she can.
    let refused = call(
        "delete_jira_push_channel",
        serde_json::json!({ "channel_id": channel_id }),
        bob,
    )
    .await;
    assert!(mcp_common::error_message(&refused).starts_with("No such Jira push channel."));
    assert_eq!(registration_rows(&w, alice).await, 1);
    let deleted = mcp_common::text_json(
        &call(
            "delete_jira_push_channel",
            serde_json::json!({ "channel_id": channel_id }),
            alice,
        )
        .await,
    );
    assert_eq!(deleted["channel_id"], channel_id);
    assert_eq!(registration_rows(&w, alice).await, 0);

    // The set's own answer for a kind of channel it cannot create.
    assert_eq!(
        state
            .push_channels
            .as_ref()
            .unwrap()
            .create_channel("gcal", alice, None)
            .await
            .unwrap_err()
            .kind,
        ProvisionRefusalKind::UnknownIntegration
    );
}

/// A paused deployment defers a delivery that would start something, and
/// takes one that would not. The deferral leaves nothing recorded as handled,
/// so Atlassian's retry starts the workflow once the pause is lifted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_paused_deployment_defers_a_delivery_that_would_start_a_workflow() {
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let registration = registered(&w, alice).await;
    talos_execution_pause::set_execution_paused(&w.pool, true)
        .await
        .expect("pause");

    // Unbound: nothing would start, so the pause is not consulted.
    let unbound = deliver(&w, &[registration.webhook_id], Some("delivery-p0")).await;
    assert_eq!(unbound.status(), StatusCode::OK);

    let workflow = common::create_test_workflow(&w.pool, alice, "on-jira-change").await;
    bind_registration_workflow(&w.pool, alice, registration.id, Some(workflow))
        .await
        .expect("bind");
    let deferred = deliver(&w, &[registration.webhook_id], Some("delivery-p1")).await;
    assert_eq!(deferred.note, ReceiptNote::Deferred);
    assert_eq!(deferred.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(deferred.starts.is_empty());
    let handled: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM atlassian_webhook_deliveries WHERE delivery_id = 'delivery-p1'",
    )
    .fetch_one(&w.pool)
    .await
    .expect("count deliveries");
    assert_eq!(handled, 0, "a deferred delivery is not recorded as handled");

    talos_execution_pause::set_execution_paused(&w.pool, false)
        .await
        .expect("resume");
    let retried = deliver(&w, &[registration.webhook_id], Some("delivery-p1")).await;
    assert_eq!(retried.starts.len(), 1, "the retry is not a duplicate");
}

// ── Security review 2026-10-14: F-1 (site binding), F-2 / F-10 (single-use
//    token), F-4 (bounded dedup) ───────────────────────────────────────────

/// A delivery about `self_host`'s issue, naming `webhook_ids`.
fn delivery_body_on_site(webhook_ids: &[i64], self_host: Option<&str>) -> String {
    let mut issue = serde_json::json!({ "id": "10001", "key": "PROJ-7" });
    if let Some(host) = self_host {
        issue["self"] = serde_json::json!(format!("https://{host}/rest/api/3/issue/10001"));
    }
    serde_json::json!({
        "webhookEvent": "jira:issue_updated",
        "matchedWebhookIds": webhook_ids,
        "issue": issue,
    })
    .to_string()
}

/// A Jira webhook id is unique only within a site. A delivery naming a
/// registration's id but about ANOTHER site — an attacker's own webhook that
/// happens to carry the same id — starts nothing, and is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_whose_site_is_not_the_registrations_starts_nothing() {
    let w = world().await;
    let (victim, _, _) = user_with_jira(&w).await; // example.atlassian.net
    let registration = registered(&w, victim).await;
    let workflow = common::create_test_workflow(&w.pool, victim, "on-jira-change").await;
    bind_registration_workflow(&w.pool, victim, registration.id, Some(workflow))
        .await
        .expect("bind");

    let receipt = w
        .svc
        .receive_push(
            &delivery_headers(Some("from-another-site")),
            Body::from(delivery_body_on_site(
                &[registration.webhook_id],
                Some("other-site.atlassian.net"),
            )),
        )
        .await;
    assert_eq!(receipt.note, ReceiptNote::SiteMismatch { matched: 1 });
    assert_eq!(receipt.status(), StatusCode::ACCEPTED);
    assert!(receipt.starts.is_empty());
    assert_eq!(executions(&w, workflow).await, 0);
    assert_eq!(
        refusals(&w, victim).await,
        vec!["site_mismatch".to_string()]
    );
    let remembered: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM atlassian_webhook_deliveries WHERE registration_id = $1",
    )
    .bind(registration.id)
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(
        remembered, 0,
        "an off-site delivery is not remembered as handled"
    );

    // The same webhook id, about her own site, starts her workflow.
    let own = w
        .svc
        .receive_push(
            &delivery_headers(Some("from-her-site")),
            Body::from(delivery_body_on_site(
                &[registration.webhook_id],
                Some("example.atlassian.net"),
            )),
        )
        .await;
    assert_eq!(own.starts.len(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_delivery_without_a_site_starts_nothing() {
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let registration = registered(&w, alice).await;
    let workflow = common::create_test_workflow(&w.pool, alice, "on-jira-change").await;
    bind_registration_workflow(&w.pool, alice, registration.id, Some(workflow))
        .await
        .expect("bind");
    let receipt = w
        .svc
        .receive_push(
            &delivery_headers(Some("no-self")),
            Body::from(delivery_body_on_site(&[registration.webhook_id], None)),
        )
        .await;
    assert_eq!(receipt.note, ReceiptNote::SiteMismatch { matched: 1 });
    assert!(receipt.starts.is_empty());
}

/// Two sites that hand out the same webhook id: a delivery from one site
/// starts that site's registration only (before 2026-10-14 the id was
/// ambiguous and both were withheld; with the site known it is not).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_same_webhook_id_on_two_sites_starts_only_the_delivering_sites_registration() {
    let w = world().await;
    let alice = user(&w).await;
    let bob = user(&w).await;
    connect_site_at(
        &w,
        alice,
        SCOPE_WITH_WEBHOOKS,
        Some("557058:a"),
        "https://alice-site.atlassian.net",
    )
    .await;
    connect_site_at(
        &w,
        bob,
        SCOPE_WITH_WEBHOOKS,
        Some("557058:b"),
        "https://bob-site.atlassian.net",
    )
    .await;
    w.atlassian.next_webhook_id.store(7, Ordering::SeqCst);
    let alices = registered(&w, alice).await;
    w.atlassian.next_webhook_id.store(7, Ordering::SeqCst);
    let bobs = registered(&w, bob).await;
    assert_eq!((alices.webhook_id, bobs.webhook_id), (7, 7));
    let alice_workflow = common::create_test_workflow(&w.pool, alice, "alice-on-jira").await;
    let bob_workflow = common::create_test_workflow(&w.pool, bob, "bob-on-jira").await;
    bind_registration_workflow(&w.pool, alice, alices.id, Some(alice_workflow))
        .await
        .unwrap();
    bind_registration_workflow(&w.pool, bob, bobs.id, Some(bob_workflow))
        .await
        .unwrap();

    // From Alice's site, naming id 7: Alice's start only.
    let receipt = w
        .svc
        .receive_push(
            &delivery_headers(Some("seven-from-alice")),
            Body::from(delivery_body_on_site(
                &[7],
                Some("alice-site.atlassian.net"),
            )),
        )
        .await;
    let started: Vec<(Uuid, Uuid)> = receipt
        .starts
        .iter()
        .map(|s| (s.user_id, s.workflow_id))
        .collect();
    assert_eq!(started, vec![(alice, alice_workflow)]);
    assert!(
        refusals(&w, bob)
            .await
            .contains(&"site_mismatch".to_string()),
        "Bob's registration is withheld as off-site, and he can find out why"
    );
}

/// A token is single-use: the same token with a different identifier and a
/// different issue starts nothing the second time, and is remembered nowhere.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_replayed_token_starts_nothing_and_records_nothing() {
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let registration = registered(&w, alice).await;
    let workflow = common::create_test_workflow(&w.pool, alice, "on-jira-change").await;
    bind_registration_workflow(&w.pool, alice, registration.id, Some(workflow))
        .await
        .expect("bind");
    let token = delivery_token();
    let headers_with = |identifier: &str| {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        h.insert(
            "X-Atlassian-Webhook-Identifier",
            identifier.parse().unwrap(),
        );
        h
    };
    let first = w
        .svc
        .receive_push(
            &headers_with("one"),
            Body::from(delivery_body(&[registration.webhook_id])),
        )
        .await;
    assert_eq!(first.starts.len(), 1);
    let forged = w
        .svc
        .receive_push(
            &headers_with("two"),
            Body::from(delivery_body_for_issue(
                &[registration.webhook_id],
                "OTHER-1",
            )),
        )
        .await;
    assert_eq!(forged.note, ReceiptNote::Replayed);
    assert!(forged.starts.is_empty());
    let remembered: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM atlassian_webhook_deliveries WHERE registration_id = $1",
    )
    .bind(registration.id)
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(remembered, 1, "the replay inserted nothing");
}

/// A registration holding its cap of remembered deliveries inserts and
/// starts nothing more until the sweep makes room.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_registration_at_its_dedup_cap_starts_nothing_and_inserts_nothing() {
    let w = world().await;
    let (alice, _, _) = user_with_jira(&w).await;
    let registration = registered(&w, alice).await;
    let workflow = common::create_test_workflow(&w.pool, alice, "on-jira-change").await;
    bind_registration_workflow(&w.pool, alice, registration.id, Some(workflow))
        .await
        .expect("bind");
    sqlx::query(
        "INSERT INTO atlassian_webhook_deliveries (registration_id, delivery_id) \
         SELECT $1, 'prior-' || g FROM generate_series(1, $2) AS g",
    )
    .bind(registration.id)
    .bind(talos_atlassian::push_receiver::DEDUP_ROWS_PER_REGISTRATION)
    .execute(&w.pool)
    .await
    .expect("fill to the cap");

    let receipt = deliver(&w, &[registration.webhook_id], Some("one-too-many")).await;
    assert_eq!(
        receipt.note,
        ReceiptNote::Accepted {
            matched: 1,
            off_site: 0,
            ambiguous: 0,
            rate_limited: 0,
            capped: 1,
            duplicates: 0
        }
    );
    assert!(receipt.starts.is_empty());
    let remembered: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM atlassian_webhook_deliveries WHERE registration_id = $1",
    )
    .bind(registration.id)
    .fetch_one(&w.pool)
    .await
    .unwrap();
    assert_eq!(
        remembered,
        talos_atlassian::push_receiver::DEDUP_ROWS_PER_REGISTRATION
    );
    assert_eq!(refusals(&w, alice).await, vec!["dedup_cap".to_string()]);
}
