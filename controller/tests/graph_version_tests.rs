//! `workflows.graph_json` read-modify-writes must not lose an edit (migration
//! `20260925120000`).
//!
//! Every graph mutation tool reads the whole graph, changes one node in Rust,
//! and writes the whole document back. Until 2026-09-25 that write was an
//! unconditional UPDATE, so two overlapping mutations each wrote their own copy
//! and the later one silently discarded the earlier one's change — both calls
//! answered success. These tests pin the compare-and-set that replaced it:
//!
//! * the repository write refuses a stale version and writes nothing;
//! * the trigger — not the writers — owns `graph_version`, so the deliberately
//!   unconditional writers (rollback) still advance it and a racing
//!   read-modify-write sees the conflict;
//! * the GraphQL update honours `expectedGraphVersion`;
//! * END TO END through a real MCP handler: a competing edit committed between
//!   the handler's read and its write is kept, and the handler reports the
//!   conflict instead of "saved". The interleaving is made deterministic by
//!   holding the row lock and watching `pg_stat_activity` for the handler's
//!   blocked UPDATE — no sleeps deciding the outcome.
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use common::{create_test_user, setup_test_context};
use mcp_common::{agent, error_message, mcp_state};
use talos_workflow_repository::{GraphWrite, WorkflowRepository};
use uuid::Uuid;

const MODULE: &str = "00000000-0000-4000-8000-00000000aaaa";

fn graph_with(nodes: &[&str]) -> String {
    let nodes: Vec<serde_json::Value> = nodes
        .iter()
        .map(|id| serde_json::json!({ "id": id, "type": MODULE, "data": {} }))
        .collect();
    serde_json::json!({ "nodes": nodes, "edges": [] }).to_string()
}

fn node_ids(graph_json: &str) -> Vec<String> {
    let g: serde_json::Value = serde_json::from_str(graph_json).expect("stored graph parses");
    g["nodes"]
        .as_array()
        .expect("nodes array")
        .iter()
        .map(|n| n["id"].as_str().expect("node id").to_string())
        .collect()
}

async fn create_workflow(repo: &WorkflowRepository, user: Uuid, graph: &str) -> Uuid {
    repo.create_workflow(
        user,
        &format!("graph-version-{}", &Uuid::new_v4().to_string()[..8]),
        graph,
        None,
        &[],
        &[],
        None,
        None,
        None,
        None,
    )
    .await
    .expect("create workflow")
}

async fn stored_version(pool: &sqlx::PgPool, wf: Uuid) -> i64 {
    sqlx::query_scalar("SELECT graph_version FROM workflows WHERE id = $1")
        .bind(wf)
        .fetch_one(pool)
        .await
        .expect("read graph_version")
}

/// The defect, at the repository: two callers read version v, both write. The
/// first lands; the second is REFUSED and writes nothing — before the fix it
/// landed too and the first caller's node vanished.
#[tokio::test]
async fn two_writers_from_one_read_keep_the_first_and_refuse_the_second() {
    let ctx = setup_test_context().await;
    let user = create_test_user(&ctx.auth_service, "gv_two_writers@example.com").await;
    let repo = WorkflowRepository::new(ctx.db_pool.clone());
    let wf = create_workflow(&repo, user, &graph_with(&["a"])).await;

    let read_a = repo
        .get_workflow_graph_versioned(wf, user)
        .await
        .expect("read")
        .expect("exists");
    let read_b = repo
        .get_workflow_graph_versioned(wf, user)
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(read_a.graph_version, read_b.graph_version);
    let v = read_a.graph_version;

    let first = repo
        .update_workflow_graph(wf, user, &graph_with(&["a", "from_a"]), v)
        .await
        .expect("write a");
    assert_eq!(
        first,
        GraphWrite::Written {
            graph_version: v + 1
        }
    );

    let second = repo
        .update_workflow_graph(wf, user, &graph_with(&["a", "from_b"]), v)
        .await
        .expect("write b executes");
    assert_eq!(
        second,
        GraphWrite::Conflict,
        "a write from a stale read must be refused, not applied over the newer graph"
    );

    let now = repo
        .get_workflow_graph_versioned(wf, user)
        .await
        .expect("read back")
        .expect("exists");
    assert_eq!(
        node_ids(&now.graph_json),
        vec!["a", "from_a"],
        "the first writer's node was discarded by the second (the lost update)"
    );
    assert_eq!(
        now.graph_version,
        v + 1,
        "a refused write must not advance the version"
    );

    // Re-reading and re-applying — what the conflict message tells the caller
    // to do — now succeeds on top of the first edit.
    let retried = repo
        .update_workflow_graph(
            wf,
            user,
            &graph_with(&["a", "from_a", "from_b"]),
            now.graph_version,
        )
        .await
        .expect("retry");
    assert_eq!(
        retried,
        GraphWrite::Written {
            graph_version: v + 2
        }
    );
}

/// The trigger owns the column: the UNCONDITIONAL writer (rollback's
/// `update_workflow_graph_json`) still advances it, so a read-modify-write
/// racing a rollback sees the conflict; a write of identical text, a
/// non-graph column update, and an attempt to set the column directly all
/// leave it alone.
#[tokio::test]
async fn the_trigger_owns_graph_version_for_every_writer() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "gv_trigger@example.com").await;
    let repo = WorkflowRepository::new(pool.clone());
    let wf = create_workflow(&repo, user, &graph_with(&["a"])).await;
    let v = stored_version(&pool, wf).await;

    // Rollback-style overwrite bumps the version…
    repo.update_workflow_graph_json(wf, user, &graph_with(&["restored"]))
        .await
        .expect("overwrite");
    assert_eq!(stored_version(&pool, wf).await, v + 1);
    // …so a read-modify-write that read `v` before the overwrite is refused.
    assert_eq!(
        repo.update_workflow_graph(wf, user, &graph_with(&["a", "late"]), v)
            .await
            .expect("stale write executes"),
        GraphWrite::Conflict
    );

    // Identical text: written, version unchanged (nothing to lose).
    let same = repo
        .update_workflow_graph(wf, user, &graph_with(&["restored"]), v + 1)
        .await
        .expect("same-text write");
    assert_eq!(
        same,
        GraphWrite::Written {
            graph_version: v + 1
        }
    );

    // A non-graph update does not move it.
    sqlx::query("UPDATE workflows SET description = 'edited' WHERE id = $1")
        .bind(wf)
        .execute(&pool)
        .await
        .expect("description update");
    assert_eq!(stored_version(&pool, wf).await, v + 1);

    // A writer cannot set it: an explicit value is overwritten by the trigger,
    // so a buggy `SET graph_version = 0` cannot re-open a stale write's window.
    sqlx::query("UPDATE workflows SET graph_version = 0 WHERE id = $1")
        .bind(wf)
        .execute(&pool)
        .await
        .expect("direct set");
    assert_eq!(stored_version(&pool, wf).await, v + 1);
    assert_eq!(
        repo.update_workflow_graph(wf, user, &graph_with(&["x"]), 0)
            .await
            .expect("write at forged version executes"),
        GraphWrite::Conflict
    );
}

/// The GraphQL `updateWorkflow` path: a stale `expectedGraphVersion` is
/// refused and writes NOTHING (not the graph, not the name); omitting it keeps
/// the historical unconditional write for API callers that never read one.
#[tokio::test]
async fn graphql_update_honours_the_expected_graph_version() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "gv_graphql@example.com").await;
    let repo = WorkflowRepository::new(pool.clone());
    let wf = create_workflow(&repo, user, &graph_with(&["a"])).await;
    let v = stored_version(&pool, wf).await;

    // Something else (an MCP tool) edits the graph after the editor loaded it.
    assert_eq!(
        repo.update_workflow_graph(wf, user, &graph_with(&["a", "mcp_edit"]), v)
            .await
            .expect("mcp edit"),
        GraphWrite::Written {
            graph_version: v + 1
        }
    );

    let mut conn = pool.acquire().await.expect("conn");
    let stale = repo
        .update_workflow_scoped(
            &mut conn,
            wf,
            user,
            &[],
            "renamed-by-editor",
            &graph_with(&["a", "editor_edit"]),
            None,
            None,
            Some(v),
        )
        .await
        .expect("stale editor save executes");
    assert_eq!(stale, GraphWrite::Conflict);
    let (name, graph): (String, String) =
        sqlx::query_as("SELECT name, graph_json FROM workflows WHERE id = $1")
            .bind(wf)
            .fetch_one(&pool)
            .await
            .expect("read back");
    assert_ne!(
        name, "renamed-by-editor",
        "a refused update must write nothing"
    );
    assert_eq!(
        node_ids(&graph),
        vec!["a", "mcp_edit"],
        "the MCP edit was overwritten"
    );

    let current = repo
        .update_workflow_scoped(
            &mut conn,
            wf,
            user,
            &[],
            "renamed-by-editor",
            &graph_with(&["a", "mcp_edit", "editor_edit"]),
            None,
            None,
            Some(v + 1),
        )
        .await
        .expect("current editor save");
    assert_eq!(
        current,
        GraphWrite::Written {
            graph_version: v + 2
        }
    );

    let unconditional = repo
        .update_workflow_scoped(
            &mut conn,
            wf,
            user,
            &[],
            "api-client",
            &graph_with(&["api"]),
            None,
            None,
            None,
        )
        .await
        .expect("unconditional save");
    assert_eq!(
        unconditional,
        GraphWrite::Written {
            graph_version: v + 3
        }
    );

    // Another user's update is NotFound, never Conflict (no existence oracle).
    let stranger = create_test_user(&ctx.auth_service, "gv_graphql_stranger@example.com").await;
    let foreign = repo
        .update_workflow_scoped(
            &mut conn,
            wf,
            stranger,
            &[],
            "pwned",
            &graph_with(&["pwned"]),
            None,
            None,
            Some(v + 3),
        )
        .await
        .expect("foreign save executes");
    assert_eq!(foreign, GraphWrite::NotFound);
}

/// Wait until some backend in this database is blocked on a lock while
/// running a statement that mentions `needle`. Bounded; panics on timeout.
async fn wait_for_blocked_statement(pool: &sqlx::PgPool, needle: &str) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
    loop {
        let blocked: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM pg_stat_activity \
             WHERE datname = current_database() AND wait_event_type = 'Lock' \
               AND query LIKE '%' || $1 || '%'",
        )
        .bind(needle)
        .fetch_one(pool)
        .await
        .expect("poll pg_stat_activity");
        if blocked > 0 {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the handler's graph write never blocked on the row lock"
        );
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
}

/// END TO END through the real `add_skip_condition` MCP handler. The test
/// holds the workflow's row lock, lets the handler READ the graph and reach
/// its WRITE (which blocks on the lock), commits a competing edit in between,
/// then releases. Before the fix the handler's write landed and the competing
/// edit vanished while the handler answered success; now the competing edit is
/// kept and the handler says nothing was saved. The retry then applies on top.
#[tokio::test]
async fn an_mcp_edit_racing_a_concurrent_edit_is_refused_not_applied() {
    let ctx = setup_test_context().await;
    let pool = ctx.db_pool.clone();
    let user = create_test_user(&ctx.auth_service, "gv_mcp_race@example.com").await;
    let repo = WorkflowRepository::new(pool.clone());
    let wf = create_workflow(&repo, user, &graph_with(&["n1"])).await;
    let state = std::sync::Arc::new(mcp_state(pool.clone()).await);

    let mut competing = pool.begin().await.expect("begin competing tx");
    sqlx::query("SELECT 1 FROM workflows WHERE id = $1 FOR UPDATE")
        .bind(wf)
        .execute(&mut *competing)
        .await
        .expect("lock the row");

    let args = serde_json::json!({
        "workflow_id": wf.to_string(),
        "node_id": "n1",
        "skip_condition": "dry_run == true",
    });
    let handler = {
        let state = state.clone();
        let args = args.clone();
        tokio::spawn(async move {
            controller::mcp::graph::dispatch(
                "add_skip_condition",
                Some(serde_json::json!(1)),
                &args,
                &state,
                agent(user),
            )
            .await
            .expect("add_skip_condition is dispatched")
        })
    };

    // The handler has read the graph (reads do not wait on a row lock) and is
    // now blocked in its compare-and-set UPDATE.
    wait_for_blocked_statement(&pool, "WITH written AS").await;

    sqlx::query("UPDATE workflows SET graph_json = $1 WHERE id = $2")
        .bind(graph_with(&["n1", "concurrent"]))
        .bind(wf)
        .execute(&mut *competing)
        .await
        .expect("competing edit");
    competing.commit().await.expect("commit competing edit");

    let resp = handler.await.expect("handler task");
    let msg = error_message(&resp);
    assert!(
        msg.contains("NOTHING was saved"),
        "the racing handler must report a conflict, got: {msg}"
    );

    let after = repo
        .get_workflow_graph(wf, user)
        .await
        .expect("read back")
        .expect("exists");
    assert_eq!(
        node_ids(&after),
        vec!["n1", "concurrent"],
        "the concurrent edit was discarded by the handler's stale write"
    );
    assert!(
        !after.contains("dry_run == true"),
        "a refused write must write nothing"
    );

    // The retry the message asks for applies on top of the concurrent edit.
    let retry = controller::mcp::graph::dispatch(
        "add_skip_condition",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user),
    )
    .await
    .expect("add_skip_condition is dispatched");
    assert!(
        retry.result.as_ref().and_then(|r| r.get("isError")) != Some(&serde_json::json!(true)),
        "retry against the current graph must succeed: {retry:?}"
    );
    let after_retry = repo
        .get_workflow_graph(wf, user)
        .await
        .expect("read back")
        .expect("exists");
    assert_eq!(node_ids(&after_retry), vec!["n1", "concurrent"]);
    assert!(
        after_retry.contains("dry_run == true"),
        "retry did not persist"
    );
}
