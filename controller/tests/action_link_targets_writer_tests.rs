//! What an action link may start has one rule, whichever tool writes it
//! (2026-10-13).
//!
//! An `action_links` node's `targets` is the list of workflows a link minted
//! by that node may start. `add_action_links_node` refused a malformed list
//! and a workflow that is not the caller's; every other tool that writes or
//! copies a graph stored whatever it was given. The rule now sits in front
//! of the statements that write `workflows.graph_json`
//! (`talos_workflow_repository::action_link_targets`), so these tests drive
//! the real tool handlers and the repository's own write methods with what
//! the dedicated tool refuses and assert that nothing is stored.
//!
//! The mint re-checks ownership on every run, so none of this was a way to
//! START a foreign workflow; `controller/tests/action_links_tests.rs` pins
//! that. This file is about what can be WRITTEN.
//!
//! `common` harness (a template clone per test), so the migrated-database
//! job runs it. The binary sets `TALOS_RLS_SET_ROLE` off itself: see
//! `leave_row_security_unenforced`.

mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};
use serde_json::{json, Value};
use sqlx::{Pool, Postgres};
use std::sync::Arc;
use uuid::Uuid;

use controller::mcp::types::JsonRpcResponse;
use controller::mcp::McpState;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'targets')",
    )
    .bind(id)
    .bind(format!("targets-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

/// A workflow row written by SQL, so a test can hold a graph no tool would
/// now store.
async fn seed_workflow(pool: &Pool<Postgres>, user: Uuid, name: &str, graph: &Value) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, graph_json, module_uri, status) \
         VALUES ($1, $2, $3, $4, 'talos://test-module', 'draft')",
    )
    .bind(id)
    .bind(user)
    .bind(format!("{name}-{id}"))
    .bind(graph.to_string())
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

fn links_node(id: &str, targets: &Value) -> Value {
    json!({
        "id": id,
        "type": "system:action_links",
        "kind": "action_links",
        "data": { "targets": targets },
        "position": { "x": 0, "y": 0 }
    })
}

fn graph_with(nodes: Vec<Value>) -> Value {
    json!({ "nodes": nodes, "edges": [] })
}

async fn stored_graph(pool: &Pool<Postgres>, workflow: Uuid) -> Value {
    let text: String = sqlx::query_scalar("SELECT graph_json::text FROM workflows WHERE id = $1")
        .bind(workflow)
        .fetch_one(pool)
        .await
        .expect("workflow row");
    serde_json::from_str(&text).expect("stored graph is JSON")
}

async fn workflow_count(pool: &Pool<Postgres>, user: Uuid) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM workflows WHERE user_id = $1")
        .bind(user)
        .fetch_one(pool)
        .await
        .expect("count")
}

fn refused(resp: &JsonRpcResponse) -> bool {
    resp.error.is_some()
        || resp
            .result
            .as_ref()
            .and_then(|r| r.get("isError"))
            .and_then(Value::as_bool)
            == Some(true)
}

/// Everything the dedicated tool refuses, as `(what, targets)`.
fn refused_targets(own: Uuid, foreign: Uuid) -> Vec<(&'static str, Value)> {
    let seventeen: serde_json::Map<String, Value> = (0..17)
        .map(|n| (format!("t{n:02}"), json!(own.to_string())))
        .collect();
    vec![
        (
            "another user's workflow",
            json!({ "list": foreign.to_string() }),
        ),
        (
            "a workflow that does not exist",
            json!({ "list": Uuid::new_v4().to_string() }),
        ),
        ("a malformed id", json!({ "list": "not-a-workflow-id" })),
        (
            "a name outside the allowed characters",
            json!({ "bad name!": own.to_string() }),
        ),
        ("seventeen entries", Value::Object(seventeen)),
        ("no entries", json!({})),
        ("a list where a map belongs", json!([own.to_string()])),
        ("a string where a map belongs", json!(own.to_string())),
    ]
}

struct Stack {
    pool: Pool<Postgres>,
    _db: common::TestDb,
    state: Arc<McpState>,
    me: Uuid,
    /// A workflow of mine: a legitimate target.
    own: Uuid,
    /// Another user's workflow.
    foreign: Uuid,
}

/// Row security is left OUT of this binary. Under `talos_app` the
/// `workflows` policy hides another user's row before the rule's own
/// ownership predicate is consulted, so removing that predicate passed every
/// tool-level test here on a machine whose `.env` turns the switch on
/// (measured: one test of twelve failed). A deployment with the switch off,
/// which is the default, rests on the predicate alone. The switch is read
/// once per process, so every test sets it before its first transaction.
fn leave_row_security_unenforced() {
    std::env::set_var("TALOS_RLS_SET_ROLE", "0");
}

async fn stack() -> Stack {
    leave_row_security_unenforced();
    let (pool, db) = common::isolated_db_pool().await;
    let me = seed_user(&pool).await;
    let other = seed_user(&pool).await;
    let own = seed_workflow(&pool, me, "own-target", &graph_with(vec![])).await;
    let foreign = seed_workflow(&pool, other, "foreign-target", &graph_with(vec![])).await;
    let state = Arc::new(mcp_state(pool.clone()).await);
    Stack {
        pool,
        _db: db,
        state,
        me,
        own,
        foreign,
    }
}

async fn graph_tool(stack: &Stack, tool: &str, args: Value) -> JsonRpcResponse {
    controller::mcp::graph::dispatch(tool, Some(json!(1)), &args, &stack.state, agent(stack.me))
        .await
        .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

async fn workflow_tool(stack: &Stack, tool: &str, args: Value) -> JsonRpcResponse {
    controller::mcp::workflows::dispatch(
        tool,
        Some(json!(1)),
        &args,
        stack.state.clone(),
        agent(stack.me),
    )
    .await
    .unwrap_or_else(|| panic!("{tool} is dispatched"))
}

/// The answer for another user's workflow is the answer for one that does
/// not exist: the same words, with only the id the caller typed differing.
fn same_answer_modulo_id(foreign_msg: &str, foreign: Uuid, missing_msg: &str, missing: Uuid) {
    assert_eq!(
        foreign_msg.replace(&foreign.to_string(), "<id>"),
        missing_msg.replace(&missing.to_string(), "<id>"),
        "a refusal must not say whether another user's workflow exists"
    );
}

// ── update_node_config ──────────────────────────────────────────────────────

#[tokio::test]
async fn update_node_config_cannot_write_targets_the_dedicated_tool_refuses() {
    let s = stack().await;
    let good = json!({ "list": s.own.to_string() });
    for action in ["update_config", "merge_config"] {
        for (what, targets) in refused_targets(s.own, s.foreign) {
            let wf = seed_workflow(
                &s.pool,
                s.me,
                "host",
                &graph_with(vec![links_node("links", &good)]),
            )
            .await;
            let resp = graph_tool(
                &s,
                "update_node_config",
                json!({ "workflow_id": wf.to_string(), "node_id": "links", "action": action,
                        "config": { "targets": targets } }),
            )
            .await;
            // Merging an empty map into the node's targets changes nothing,
            // so there is nothing to refuse; what is stored stays as it was.
            let nothing_to_write = action == "merge_config" && what == "no entries";
            if !nothing_to_write {
                assert!(refused(&resp), "{action} stored {what}: {resp:?}");
                let message = error_message(&resp);
                assert!(
                    message.contains("'links'"),
                    "{action}, {what}: the refusal names the node: {message}"
                );
            }
            assert_eq!(
                stored_graph(&s.pool, wf).await["nodes"][0]["data"]["targets"],
                good,
                "{action}, {what}: the stored targets are unchanged"
            );
        }
    }
}

#[tokio::test]
async fn update_node_config_still_writes_a_callers_own_well_formed_target() {
    let s = stack().await;
    let second = seed_workflow(&s.pool, s.me, "second-target", &graph_with(vec![])).await;
    let wf = seed_workflow(
        &s.pool,
        s.me,
        "host",
        &graph_with(vec![links_node(
            "links",
            &json!({ "list": s.own.to_string() }),
        )]),
    )
    .await;
    let resp = graph_tool(
        &s,
        "update_node_config",
        json!({ "workflow_id": wf.to_string(), "node_id": "links", "action": "merge_config",
                "config": { "targets": { "bills": second.to_string() } } }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
    assert_eq!(
        stored_graph(&s.pool, wf).await["nodes"][0]["data"]["targets"]["bills"],
        second.to_string()
    );
}

#[tokio::test]
async fn the_refusal_for_a_foreign_workflow_is_the_refusal_for_a_missing_one() {
    let s = stack().await;
    let missing = Uuid::new_v4();
    let mut messages = Vec::new();
    for id in [s.foreign, missing] {
        let wf = seed_workflow(
            &s.pool,
            s.me,
            "host",
            &graph_with(vec![links_node(
                "links",
                &json!({ "list": s.own.to_string() }),
            )]),
        )
        .await;
        let resp = graph_tool(
            &s,
            "update_node_config",
            json!({ "workflow_id": wf.to_string(), "node_id": "links", "action": "merge_config",
                    "config": { "targets": { "list": id.to_string() } } }),
        )
        .await;
        messages.push(error_message(&resp).replace(&wf.to_string(), "<host>"));
    }
    same_answer_modulo_id(&messages[0], s.foreign, &messages[1], missing);
    assert!(
        messages[0].contains("'list'"),
        "the entry is named: {}",
        messages[0]
    );

    // The dedicated tool gives the same answer for both, too.
    let mut dedicated = Vec::new();
    for id in [s.foreign, missing] {
        let wf = seed_workflow(&s.pool, s.me, "host", &graph_with(vec![])).await;
        let resp = graph_tool(
            &s,
            "add_action_links_node",
            json!({ "workflow_id": wf.to_string(), "node_id": "links",
                    "targets": { "list": id.to_string() } }),
        )
        .await;
        dedicated.push(error_message(&resp).replace(&wf.to_string(), "<host>"));
    }
    same_answer_modulo_id(&dedicated[0], s.foreign, &dedicated[1], missing);
}

// ── the dedicated tool, as the baseline ─────────────────────────────────────

#[tokio::test]
async fn add_action_links_node_refuses_each_of_them_and_stores_nothing() {
    let s = stack().await;
    for (what, targets) in refused_targets(s.own, s.foreign) {
        let wf = seed_workflow(&s.pool, s.me, "host", &graph_with(vec![])).await;
        let resp = graph_tool(
            &s,
            "add_action_links_node",
            json!({ "workflow_id": wf.to_string(), "node_id": "links", "targets": targets }),
        )
        .await;
        assert!(refused(&resp), "{what}: {resp:?}");
        assert_eq!(
            stored_graph(&s.pool, wf).await["nodes"],
            json!([]),
            "{what}: nothing is stored"
        );
    }
}

// ── imports ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn import_workflow_cannot_bring_in_targets_the_dedicated_tool_refuses() {
    let s = stack().await;
    for (what, targets) in refused_targets(s.own, s.foreign) {
        let before = workflow_count(&s.pool, s.me).await;
        let resp = workflow_tool(
            &s,
            "import_workflow",
            json!({ "bundle": { "name": "imported", "graph_json": graph_with(vec![links_node("links", &targets)]) } }),
        )
        .await;
        assert!(refused(&resp), "import stored {what}: {resp:?}");
        assert!(error_message(&resp).contains("'links'"), "{what}: {resp:?}");
        assert_eq!(
            workflow_count(&s.pool, s.me).await,
            before,
            "{what}: no workflow is created"
        );
    }
    // A caller's own target is imported as before.
    let resp = workflow_tool(
        &s,
        "import_workflow",
        json!({ "bundle": { "name": "imported", "graph_json":
            graph_with(vec![links_node("links", &json!({ "list": s.own.to_string() }))]) } }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
}

#[tokio::test]
async fn import_yaml_workflow_cannot_bring_in_targets_the_dedicated_tool_refuses() {
    let s = stack().await;
    let yaml_for = |targets: &Value| {
        format!(
            "name: yaml-links\nnodes:\n  - id: links\n    module: \"system:action_links\"\n    config:\n      targets: {targets}\nedges: []\n"
        )
    };
    for (what, targets) in refused_targets(s.own, s.foreign) {
        let before = workflow_count(&s.pool, s.me).await;
        let resp = workflow_tool(
            &s,
            "import_yaml_workflow",
            json!({ "yaml": yaml_for(&targets) }),
        )
        .await;
        assert!(refused(&resp), "yaml import stored {what}: {resp:?}");
        assert_eq!(
            workflow_count(&s.pool, s.me).await,
            before,
            "{what}: no workflow is created"
        );
    }
    let resp = workflow_tool(
        &s,
        "import_yaml_workflow",
        json!({ "yaml": yaml_for(&json!({ "list": s.own.to_string() })) }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
}

// ── copies ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn copy_node_cannot_carry_refused_targets_into_another_workflow() {
    let s = stack().await;
    for (what, targets) in refused_targets(s.own, s.foreign) {
        // The source holds a node no tool would now store.
        let source = seed_workflow(
            &s.pool,
            s.me,
            "source",
            &graph_with(vec![links_node("links", &targets)]),
        )
        .await;
        let destination = seed_workflow(&s.pool, s.me, "destination", &graph_with(vec![])).await;
        let resp = graph_tool(
            &s,
            "copy_node",
            json!({ "source_workflow_id": source.to_string(), "source_node_id": "links",
                    "target_workflow_id": destination.to_string(), "target_node_id": "links" }),
        )
        .await;
        assert!(refused(&resp), "copy_node carried {what}: {resp:?}");
        assert_eq!(
            stored_graph(&s.pool, destination).await["nodes"],
            json!([]),
            "{what}: the destination is unchanged"
        );
    }
}

#[tokio::test]
async fn clone_and_duplicate_workflow_cannot_carry_refused_targets_into_a_new_workflow() {
    let s = stack().await;
    for (what, targets) in refused_targets(s.own, s.foreign) {
        let source = seed_workflow(
            &s.pool,
            s.me,
            "source",
            &graph_with(vec![links_node("links", &targets)]),
        )
        .await;
        let before = workflow_count(&s.pool, s.me).await;
        let resp = workflow_tool(
            &s,
            "clone_workflow",
            json!({ "workflow_id": source.to_string() }),
        )
        .await;
        assert!(refused(&resp), "clone_workflow carried {what}: {resp:?}");
        let resp = graph_tool(
            &s,
            "duplicate_workflow",
            json!({ "workflow_id": source.to_string() }),
        )
        .await;
        assert!(
            refused(&resp),
            "duplicate_workflow carried {what}: {resp:?}"
        );
        assert_eq!(
            workflow_count(&s.pool, s.me).await,
            before,
            "{what}: no workflow is created"
        );
    }
}

#[tokio::test]
async fn duplicate_workflow_cannot_patch_refused_targets_into_the_copy() {
    let s = stack().await;
    let source = seed_workflow(
        &s.pool,
        s.me,
        "source",
        &graph_with(vec![links_node(
            "links",
            &json!({ "list": s.own.to_string() }),
        )]),
    )
    .await;
    let before = workflow_count(&s.pool, s.me).await;
    let resp = graph_tool(
        &s,
        "duplicate_workflow",
        json!({ "workflow_id": source.to_string(),
                "modifications": { "patch_node_configs": { "links": { "targets": { "list": s.foreign.to_string() } } } } }),
    )
    .await;
    assert!(refused(&resp), "{resp:?}");
    assert_eq!(workflow_count(&s.pool, s.me).await, before);
}

/// The rule is about what a write INTRODUCES. A target already in the stored
/// graph of the workflow being written is not asked about again: a workflow
/// whose target was deleted since must stay editable, and the mint refuses
/// that target on every run whatever the graph says.
#[tokio::test]
async fn a_target_already_stored_does_not_block_a_later_edit_but_a_malformed_list_does() {
    let s = stack().await;
    let gone = Uuid::new_v4();
    let wf = seed_workflow(
        &s.pool,
        s.me,
        "host",
        &graph_with(vec![links_node(
            "links",
            &json!({ "list": gone.to_string() }),
        )]),
    )
    .await;
    let resp = graph_tool(
        &s,
        "duplicate_node",
        json!({ "workflow_id": wf.to_string(), "source_node_id": "links", "new_node_id": "links2" }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
    assert_eq!(
        stored_graph(&s.pool, wf).await["nodes"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    // A list that breaks the shape rules is refused on every write, including
    // a copy inside the same workflow.
    let wf = seed_workflow(
        &s.pool,
        s.me,
        "host",
        &graph_with(vec![links_node(
            "links",
            &json!({ "bad name!": s.own.to_string() }),
        )]),
    )
    .await;
    let resp = graph_tool(
        &s,
        "duplicate_node",
        json!({ "workflow_id": wf.to_string(), "source_node_id": "links", "new_node_id": "links2" }),
    )
    .await;
    assert!(refused(&resp), "{resp:?}");
    assert_eq!(
        stored_graph(&s.pool, wf).await["nodes"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

// ── the repository's own write methods ──────────────────────────────────────

/// Every method that writes `workflows.graph_json`, called directly with a
/// graph that names another user's workflow. A tool added later reaches the
/// table through one of these (`scripts/check-graph-writers.py` refuses a
/// statement that does not).
#[tokio::test]
async fn every_repository_write_refuses_a_target_that_is_not_the_owners() {
    use talos_workflow_repository::{action_targets_refusal, WorkflowRepository};
    let s = stack().await;
    let repo = WorkflowRepository::new(s.pool.clone());
    let bad = graph_with(vec![links_node(
        "links",
        &json!({ "list": s.foreign.to_string() }),
    )])
    .to_string();
    let host = seed_workflow(&s.pool, s.me, "host", &graph_with(vec![])).await;
    let before = workflow_count(&s.pool, s.me).await;
    let version: i64 = sqlx::query_scalar("SELECT graph_version FROM workflows WHERE id = $1")
        .bind(host)
        .fetch_one(&s.pool)
        .await
        .unwrap();
    let mut refusals: Vec<(&str, anyhow::Error)> = Vec::new();
    let mut keep = |name: &'static str, outcome: Option<anyhow::Error>| {
        refusals.push((
            name,
            outcome.unwrap_or_else(|| panic!("{name} stored a foreign target")),
        ));
    };

    keep(
        "create_workflow",
        repo.create_workflow(s.me, "w", &bad, None, &[], &[], None, None, None, None)
            .await
            .err(),
    );
    keep(
        "update_workflow_graph",
        repo.update_workflow_graph(host, s.me, &bad, version)
            .await
            .err(),
    );
    keep(
        "update_workflow_graph_json",
        repo.update_workflow_graph_json(host, s.me, &bad)
            .await
            .err(),
    );
    keep(
        "insert_yaml_imported_workflow",
        repo.insert_yaml_imported_workflow(Uuid::new_v4(), s.me, "w", "", &bad, &[], "yaml-import")
            .await
            .err(),
    );
    keep(
        "insert_duplicated_workflow",
        repo.insert_duplicated_workflow(Uuid::new_v4(), s.me, "w", &bad, &[])
            .await
            .err(),
    );
    keep(
        "insert_published_internal_workflow",
        repo.insert_published_internal_workflow(Uuid::new_v4(), s.me, None, "w", "", &bad)
            .await
            .err(),
    );
    keep(
        "upsert_workflow_graph_by_name (insert)",
        repo.upsert_workflow_graph_by_name(s.me, "by-name", &bad, None)
            .await
            .err(),
    );
    keep(
        "upsert_workflow_graph_by_name (update)",
        repo.upsert_workflow_graph_by_name(s.me, "by-name", &bad, Some(host))
            .await
            .err(),
    );
    {
        let mut conn = s.pool.acquire().await.unwrap();
        keep(
            "insert_workflow_scoped",
            repo.insert_workflow_scoped(&mut conn, "w", &bad, s.me, None, None, Uuid::new_v4())
                .await
                .err(),
        );
        keep(
            "update_workflow_scoped",
            repo.update_workflow_scoped(&mut conn, host, s.me, &[], "w", &bad, None, None, None)
                .await
                .err(),
        );
    }
    keep(
        "ExecutionRepository::update_workflow_graph",
        talos_execution_repository::ExecutionRepository::new(s.pool.clone())
            .update_workflow_graph(host, s.me, &bad, version)
            .await
            .err(),
    );
    keep(
        "insert_promoted_workflow",
        talos_advanced_repository::AdvancedRepository::new(s.pool.clone())
            .insert_promoted_workflow(Uuid::new_v4(), s.me, "w", &bad, &[], None)
            .await
            .err(),
    );

    for (name, error) in &refusals {
        let refusal = action_targets_refusal(error)
            .unwrap_or_else(|| panic!("{name} failed for another reason: {error:#}"));
        let text = refusal.to_string();
        assert!(
            text.contains("'links'") && text.contains("'list'"),
            "{name}: {text}"
        );
    }
    assert_eq!(
        workflow_count(&s.pool, s.me).await,
        before,
        "no row was created"
    );
    assert_eq!(
        stored_graph(&s.pool, host).await,
        graph_with(vec![]),
        "the host is unchanged"
    );
}

/// The organisation path: an editor may save a workflow that is not theirs.
/// A link is minted as the workflow's OWNER, so a target must be the
/// owner's; and the editor must be able to write it too, or an editor could
/// point an owner's workflow at one of the owner's that the editor cannot
/// reach.
#[tokio::test]
async fn an_organisation_editor_may_only_name_the_owners_workflows_they_can_write() {
    use talos_workflow_repository::{action_targets_refusal, GraphWrite, WorkflowRepository};
    let s = stack().await;
    let owner = s.me;
    let editor = seed_user(&s.pool).await;
    let org = common::create_test_organization(&s.pool, "targets org", owner).await;
    let in_org = |id: Uuid| {
        sqlx::query("UPDATE workflows SET org_id = $2 WHERE id = $1")
            .bind(id)
            .bind(org)
            .execute(&s.pool)
    };
    let host = seed_workflow(&s.pool, owner, "host", &graph_with(vec![])).await;
    let shared = seed_workflow(&s.pool, owner, "shared-target", &graph_with(vec![])).await;
    let private = seed_workflow(&s.pool, owner, "private-target", &graph_with(vec![])).await;
    let editors_own = seed_workflow(&s.pool, editor, "editors-own", &graph_with(vec![])).await;
    in_org(host).await.expect("host in org");
    in_org(shared).await.expect("target in org");

    let repo = WorkflowRepository::new(s.pool.clone());
    let graph = |target: Uuid| {
        graph_with(vec![links_node(
            "links",
            &json!({ "list": target.to_string() }),
        )])
        .to_string()
    };
    let mut conn = s.pool.acquire().await.unwrap();
    let mut save = async |target: Uuid| {
        repo.update_workflow_scoped(
            &mut conn,
            host,
            editor,
            &[org],
            "host",
            &graph(target),
            None,
            None,
            None,
        )
        .await
    };

    for (what, target) in [
        (
            "a workflow of the owner's that the editor cannot write",
            private,
        ),
        (
            "the editor's own workflow, which the owner does not own",
            editors_own,
        ),
        ("another user's workflow", s.foreign),
    ] {
        let error = save(target).await.expect_err(what);
        assert!(
            action_targets_refusal(&error).is_some(),
            "{what}: {error:#}"
        );
    }
    assert_eq!(stored_graph(&s.pool, host).await, graph_with(vec![]));

    assert!(
        matches!(
            save(shared).await.expect("the shared target"),
            GraphWrite::Written { .. }
        ),
        "an owner's workflow the editor can write is a target"
    );

    // A user with no access to the host gets the statement's own answer,
    // whatever the graph says.
    let outsider = seed_user(&s.pool).await;
    let outcome = repo
        .update_workflow_scoped(
            &mut conn,
            host,
            outsider,
            &[],
            "host",
            &graph(s.foreign),
            None,
            None,
            None,
        )
        .await
        .expect("no error for a row that is not theirs");
    assert_eq!(outcome, GraphWrite::NotFound);
}

#[tokio::test]
async fn a_caller_can_still_create_and_text_json_reads_the_result() {
    // Guards the harness itself: a refusal assertion means nothing if the
    // tool refuses everything.
    let s = stack().await;
    let wf = seed_workflow(&s.pool, s.me, "host", &graph_with(vec![])).await;
    let resp = graph_tool(
        &s,
        "add_action_links_node",
        json!({ "workflow_id": wf.to_string(), "node_id": "links",
                "targets": { "list": s.own.to_string() } }),
    )
    .await;
    assert!(!refused(&resp), "{resp:?}");
    assert_eq!(text_json(&resp)["node_type"], "action_links");
}
