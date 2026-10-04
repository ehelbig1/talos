//! Action links: a capability URL in a composed message that, when its owner
//! confirms it, starts ONE named workflow with ONE fixed payload (2026-10-04).
//!
//! Driven end to end against a real database:
//! * the `action_links` system node, in a real engine, with the real minter —
//!   a scripted dispatcher stands in for the compose module, which is the
//!   only thing a worker contributes to this path;
//! * the token store's tenancy and single-use guarantees;
//! * the public confirm/apply handlers.
//!
//! What is NOT driven here: a successful start. `trigger` needs NATS, which
//! this harness has none of, so the apply path is exercised up to the
//! refusals that precede an execution (the claim is given back) and the
//! failure that may follow one (the claim is kept).
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::{Extension, Path};
use axum::response::IntoResponse;
use common::{create_test_user, create_test_workflow, setup_test_context};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use talos_execution_repository::action_links::{ActionClaim, ActionLinkRequest, MintRefusal};
use talos_execution_repository::ExecutionRepository;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{
    action_links::{ACTION_LINKS_REPORT, ACTION_LINKS_REQUEST},
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, NodeDispatcher, StepStatus, SystemNodeKind, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

/// Stands in for the worker: returns the output the test scripted.
struct ScriptedDispatcher {
    output: Value,
}

#[async_trait]
impl NodeDispatcher for ScriptedDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Ok(DispatchResult {
            output: self.output.clone(),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        let steps = request
            .steps
            .iter()
            .map(|j| ChainStepResult {
                module_id: j.module_id,
                status: StepStatus::Success,
                output: self.output.clone(),
                error: None,
                execution_time_ms: 0,
            })
            .collect();
        Ok(ChainDispatchResult {
            steps,
            final_output: self.output.clone(),
            overall_status: StepStatus::Success,
        })
    }
}

fn stub_artifact(id: Uuid) -> WasmModuleArtifact {
    WasmModuleArtifact {
        module_id: id,
        content_hash: "stub".into(),
        wasm_bytes: vec![],
        oci_url: None,
        max_fuel: 1_000_000,
        capability_world: "minimal-node".into(),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

/// Run `compose → links` in a real engine as `user`, with the real minter,
/// and return the `links` node's output.
async fn run_links_node(
    pool: &Pool<Postgres>,
    user: Uuid,
    targets: BTreeMap<String, Uuid>,
    compose_output: Value,
) -> Value {
    let compose = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module("compose", compose, None)
        .add_system_node(
            "links",
            SystemNodeKind::ActionLinks {
                targets,
                ttl_hours: Some(24),
            },
        )
        .edge("compose", "links")
        .build()
        .expect("graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(user);
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(compose, stub_artifact(compose)),
    ));
    engine.set_action_link_minter(Arc::new(
        talos_engine::action_link_minter::PostgresActionLinkMinter::new(pool.clone()),
    ));
    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");
    let links = engine
        .node_labels()
        .iter()
        .find(|(_, label)| label.as_str() == "links")
        .map(|(id, _)| *id)
        .expect("the links node is in the graph");

    let ctx = engine
        .run_with_trigger_input_transport(
            Arc::new(ScriptedDispatcher {
                output: compose_output,
            }),
            None,
            json!({}),
            Uuid::new_v4(),
        )
        .await
        .expect("run succeeds");
    ctx.results
        .get(&links)
        .cloned()
        .expect("the links node produced a result")
}

/// The raw token at the end of a minted URL.
fn token_of(url: &str) -> &str {
    let token = url.rsplit('/').next().expect("a path");
    assert!(
        url.contains("/action-links/") && token.len() == 64,
        "not an action link: {url}"
    );
    token
}

async fn body_of(response: axum::response::Response) -> (u16, String) {
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
        .await
        .expect("read body");
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

#[tokio::test]
async fn the_node_mints_links_only_for_its_targets_and_passes_the_message_on() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let owner = create_test_user(&ctx.auth_service, "action_links_owner@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "action_links_stranger@example.com").await;
    let list = create_test_workflow(&pool, owner, "al-list").await;
    let not_theirs = create_test_workflow(&pool, stranger, "al-foreign").await;

    let output = run_links_node(
        &pool,
        owner,
        // The author listed a workflow the running user does not own. The
        // node cannot refuse its own configuration; the mint must.
        BTreeMap::from([("list".into(), list), ("foreign".into(), not_theirs)]),
        json!({
            "subject": "Morning",
            "html": "<a href=\"talos-action:done-1\">done</a> <a href=\"talos-action:x\">x</a> \
                     <a href=\"talos-action:y\">y</a>",
            ACTION_LINKS_REQUEST: [
                { "id": "done-1", "target": "list", "label": "Done: <b>call</b> the dentist",
                  "payload": { "op": "done", "item": 1 } },
                { "id": "x", "target": "nowhere", "label": "x", "payload": {},
                  "fallback": "mailto:me@example.com?subject=x" },
                { "id": "y", "target": "foreign", "label": "y", "payload": {} },
            ],
            // A module cannot author the report.
            ACTION_LINKS_REPORT: { "available": true, "minted": 999 },
        }),
    )
    .await;

    assert!(output.get(ACTION_LINKS_REQUEST).is_none(), "{output}");
    let html = output["html"].as_str().expect("html");
    assert!(!html.contains("talos-action:"), "{html}");
    assert!(
        html.contains("href=\"mailto:me@example.com?subject=x\">x<"),
        "{html}"
    );
    assert!(html.contains("href=\"#\">y<"), "{html}");
    let url = html
        .split("href=\"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("the first link");
    let token = token_of(url);

    let report = &output[ACTION_LINKS_REPORT];
    assert_eq!(report["available"], true, "{report}");
    assert_eq!(report["requested"], 3);
    assert_eq!(report["minted"], 1);
    assert_eq!(
        report["not_minted"],
        json!([
            { "id": "x", "reason": "unknown_target", "fell_back": true },
            { "id": "y", "reason": "workflow_not_owned", "fell_back": false },
        ])
    );

    // Exactly one row, for the owner, naming the listed workflow — and only
    // the HASH of the token.
    let rows: Vec<(Uuid, Uuid, String, String, Value, Option<String>)> = sqlx::query_as(
        "SELECT user_id, workflow_id, token_hash, label, payload, source_node \
         FROM workflow_action_tokens",
    )
    .fetch_all(&pool)
    .await
    .expect("read tokens");
    assert_eq!(rows.len(), 1, "{rows:?}");
    let (user_id, workflow_id, hash, label, payload, source_node) = &rows[0];
    assert_eq!((*user_id, *workflow_id), (owner, list));
    assert_eq!(hash, &talos_text_util::sha256_hex(token));
    assert_ne!(hash, token);
    assert_eq!(label, "Done: <b>call</b> the dentist");
    assert_eq!(payload, &json!({ "op": "done", "item": 1 }));
    assert_eq!(source_node.as_deref(), Some("links"));

    // The confirmation page names the workflow and escapes the label, and
    // looking at it changes nothing.
    for _ in 0..2 {
        let (status, body) = body_of(
            talos_webhooks::action_link_preview(Path(token.to_string()), Extension(pool.clone()))
                .await
                .into_response(),
        )
        .await;
        assert_eq!(status, 200);
        assert!(body.contains("al-list"), "{body}");
        assert!(
            body.contains("Done: &lt;b&gt;call&lt;/b&gt; the dentist"),
            "{body}"
        );
        assert!(
            !body.contains("<b>call</b>"),
            "the label reached the page unescaped"
        );
        assert!(body.contains("method=\"POST\""));
    }
    let used: bool = sqlx::query_scalar("SELECT used_at IS NOT NULL FROM workflow_action_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(!used, "a GET used the link up");
}

/// The store's own guarantees: a workflow that is not the minting user's is
/// refused, and a link is claimed exactly once however it is submitted.
#[tokio::test]
async fn a_link_is_minted_only_for_its_owner_and_claimed_exactly_once() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let owner = create_test_user(&ctx.auth_service, "action_links_claim@example.com").await;
    let stranger = create_test_user(&ctx.auth_service, "action_links_claim2@example.com").await;
    let own = create_test_workflow(&pool, owner, "al-own").await;
    let foreign = create_test_workflow(&pool, stranger, "al-not-own").await;
    let repo = ExecutionRepository::new(pool.clone());

    let request = |workflow_id: Uuid| ActionLinkRequest {
        workflow_id,
        label: "Do it".into(),
        payload: json!({ "n": 1 }),
    };
    let minted = repo
        .mint_action_tokens(
            owner,
            None,
            None,
            None,
            &[request(own), request(foreign), request(Uuid::new_v4())],
        )
        .await
        .expect("mint");
    let token = minted[0].clone().expect("the owner's workflow is minted");
    assert_eq!(minted[1], Err(MintRefusal::WorkflowNotOwned));
    assert_eq!(minted[2], Err(MintRefusal::WorkflowNotOwned));
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workflow_action_tokens")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1, "a refused request left a row");

    // Eight submissions at once: one claim.
    let attempts = futures::future::join_all((0..8).map(|_| {
        let repo = ExecutionRepository::new(pool.clone());
        let token = token.clone();
        async move { repo.claim_action_token(&token).await.expect("claim runs") }
    }))
    .await;
    let claimed: Vec<_> = attempts
        .iter()
        .filter_map(|a| match a {
            ActionClaim::Claimed(context) => Some(context.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        claimed.len(),
        1,
        "a link was claimed {} times",
        claimed.len()
    );
    assert!(attempts
        .iter()
        .all(|a| matches!(a, ActionClaim::Claimed(_) | ActionClaim::AlreadyUsed)));
    let context = &claimed[0];
    assert_eq!((context.user_id, context.workflow_id), (owner, own));
    assert_eq!(context.payload, json!({ "n": 1 }));

    // Given back, it can be claimed again — once.
    repo.release_action_token(context.id).await.unwrap();
    assert!(matches!(
        repo.claim_action_token(&token).await.unwrap(),
        ActionClaim::Claimed(_)
    ));
    // Once it names an execution it is never given back.
    repo.record_action_execution(context.id, Uuid::new_v4())
        .await
        .unwrap();
    repo.release_action_token(context.id).await.unwrap();
    assert!(matches!(
        repo.claim_action_token(&token).await.unwrap(),
        ActionClaim::AlreadyUsed
    ));

    // Unknown, malformed and expired are one answer.
    assert!(matches!(
        repo.claim_action_token(&"0".repeat(64)).await.unwrap(),
        ActionClaim::Invalid
    ));
    assert!(matches!(
        repo.claim_action_token("not-a-token").await.unwrap(),
        ActionClaim::Invalid
    ));
    let fresh = repo
        .mint_action_tokens(owner, None, None, None, &[request(own)])
        .await
        .unwrap()[0]
        .clone()
        .unwrap();
    sqlx::query("UPDATE workflow_action_tokens SET expires_at = NOW() - interval '1 minute' WHERE token_hash = $1")
        .bind(talos_text_util::sha256_hex(&fresh))
        .execute(&pool)
        .await
        .unwrap();
    assert!(repo.lookup_action_token(&fresh).await.unwrap().is_none());
    assert!(matches!(
        repo.claim_action_token(&fresh).await.unwrap(),
        ActionClaim::Invalid
    ));
}

#[tokio::test]
async fn the_apply_page_gives_a_link_back_only_when_nothing_can_have_started() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let owner = create_test_user(&ctx.auth_service, "action_links_apply@example.com").await;
    let workflow = create_test_workflow(&pool, owner, "al-apply").await;
    let repo = ExecutionRepository::new(pool.clone());
    let state = mcp_common::mcp_state(pool.clone()).await;
    let service = Some(state.execution_orchestration_service.clone());

    let mint = || async {
        repo.mint_action_tokens(
            owner,
            None,
            None,
            None,
            &[ActionLinkRequest {
                workflow_id: workflow,
                label: "Start it".into(),
                payload: json!({}),
            }],
        )
        .await
        .unwrap()[0]
            .clone()
            .unwrap()
    };
    let used = |token: String| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, bool>(
                "SELECT used_at IS NOT NULL FROM workflow_action_tokens WHERE token_hash = $1",
            )
            .bind(talos_text_util::sha256_hex(&token))
            .fetch_one(&pool)
            .await
            .unwrap()
        }
    };
    let apply = |token: String, service| {
        let pool = pool.clone();
        async move {
            body_of(
                talos_webhooks::action_link_apply(Path(token), Extension(pool), Extension(service))
                    .await
                    .into_response(),
            )
            .await
        }
    };

    // No service wired: refused BEFORE the claim, so the link is not burned.
    let token = mint().await;
    let (status, _) = apply(token.clone(), None).await;
    assert_eq!(status, 500);
    assert!(
        !used(token.clone()).await,
        "a missing service burned the link"
    );

    // The workflow is switched off: refused before any execution exists, so
    // the link is given back and says so.
    sqlx::query("UPDATE workflows SET is_enabled = false WHERE id = $1")
        .bind(workflow)
        .execute(&pool)
        .await
        .unwrap();
    let (status, body) = apply(token.clone(), service.clone()).await;
    assert_eq!(status, 409, "{body}");
    assert!(body.contains("Not started"), "{body}");
    assert!(body.contains("has not been used up"), "{body}");
    assert!(
        !used(token.clone()).await,
        "a refused start burned the link"
    );
    let executions: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM workflow_executions WHERE workflow_id = $1")
            .bind(workflow)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(executions, 0, "a refused start left an execution");

    // Unknown and expired tokens get the same page, and the same status.
    let (unknown_status, unknown_body) = apply("f".repeat(64), service.clone()).await;
    sqlx::query("UPDATE workflow_action_tokens SET expires_at = NOW() - interval '1 minute' WHERE token_hash = $1")
        .bind(talos_text_util::sha256_hex(&token))
        .execute(&pool)
        .await
        .unwrap();
    let (expired_status, expired_body) = apply(token.clone(), service.clone()).await;
    assert_eq!((unknown_status, expired_status), (404, 404));
    assert_eq!(
        unknown_body, expired_body,
        "the page tells an expired link from an unknown one"
    );
}
