//! A gate that cannot read its rule must REFUSE — it must never GRANT.
//!
//! Package 23 (2026-09-07) inventoried every awaited read in
//! `talos-mcp-handlers/src` + `talos-api/src` that is collapsed into a default
//! and classified 110 of them as CLAIMS — a failed read rendered as a
//! reassuring statement. #776 repaired eleven of those. This binary covers the
//! smaller and sharper subset the same inventory names: the reads whose
//! consumer is an ENFORCEMENT DECISION, where the default does not merely make
//! a false statement, it LIFTS THE BOUND.
//!
//! Two shapes are driven here through the REAL MCP dispatch over a real
//! `McpState`, with the read made to fail deterministically by removing the
//! relation it names (package 22's mechanism):
//!
//!  1. the actor CAPABILITY-WORLD CEILING on `run_sandbox` — the highest blast
//!     radius in the package, because `run_sandbox` compiles AND EXECUTES
//!     caller-supplied Rust at the requested world, so a skipped ceiling is a
//!     run rather than an authoring mistake somebody can review later;
//!  2. the per-workflow 100-TAG CAP on `tag_workflow`.
//!
//! Each test carries its CONTROL in the same run: a healthy gate must still
//! refuse for the RIGHT reason (ceiling exceeded) and a healthy success path
//! must stay byte-identical. "The tool refused" is not evidence on its own —
//! the pre-fix path also refused on the cap test, with the wrong diagnosis.
//!
//! The database is a per-test `CREATE DATABASE … TEMPLATE` clone
//! (`common::isolated_db_pool`), so dropping a table here cannot reach any
//! other test or the developer's stack.

#[path = "common/mod.rs"]
mod common;
// The real `McpState` + response helpers, one home (2026-09-08).
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, error_message, mcp_state, text_json};

use uuid::Uuid;

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("p23-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_workflow(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, name, module_uri, graph_json, status, is_enabled) \
         VALUES ($1, $2, 'p23-summary', 'test:p23', '{\"nodes\":[],\"edges\":[]}', 'active', true)",
    )
    .bind(id)
    .bind(user_id)
    .execute(pool)
    .await
    .expect("seed workflow");
    id
}

async fn seed_actor(pool: &sqlx::PgPool, user_id: Uuid, max_world: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, max_capability_world, status) \
         VALUES ($1, $2, $3, $4, 'active')",
    )
    .bind(id)
    .bind(user_id)
    .bind(format!("p26-actor-{id}"))
    .bind(max_world)
    .execute(pool)
    .await
    .expect("seed actor");
    id
}

// ───────────────────────────────────────────────────────────────────────────
// 1. `run_sandbox` — an unreadable capability ceiling must REFUSE, not run.
//
//    Pre-fix the ceiling was read through the LENIENT free function
//    `talos_actor_repository::get_actor_max_world`, which answers `None` on a
//    database error, and the whole gate was `if let Some(max_world) = …`. So a
//    Postgres fault SKIPPED the ceiling and the request proceeded to compile
//    and execute at whatever world the role RBAC above allowed. MCP-545 fixed
//    exactly this shape on the two RUNTIME gates in
//    `talos-workflow-authorization` and never reached the three
//    authoring/compile-time siblings; the lenient function's own body logs
//    "caller may default to permissive ceiling — wire try_get_actor_max_world
//    to fail closed".
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn run_sandbox_refuses_when_the_capability_ceiling_cannot_be_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id, "minimal-node").await;
    let state = mcp_state(pool.clone()).await;

    // A request ABOVE the seeded ceiling. Both arms below stop at the ceiling
    // gate, so neither compiles anything — the assertions are about which
    // refusal is produced, not about the sandbox pipeline.
    let args = serde_json::json!({
        "rust_code": "pub fn run(_input: String) -> String { String::new() }",
        "capability_world": "secrets-node",
        "agent_id": actor_id.to_string(),
    });

    // CONTROL: intact schema. The gate is LIVE and reads the real row, so the
    // refusal names the ceiling it read.
    let ok = controller::mcp::sandbox::dispatch(
        "run_sandbox",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("run_sandbox is dispatched");
    let control_msg = error_message(&ok);
    assert!(
        control_msg.contains("Actor capability ceiling exceeded")
            && control_msg.contains("minimal-node"),
        "with the schema intact the gate must refuse for the RIGHT reason and \
         name the ceiling it read: {control_msg}"
    );

    // The ceiling read now cannot run. `actors` is the table it names.
    sqlx::query("DROP TABLE actors CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the ceiling read names");

    let degraded = controller::mcp::sandbox::dispatch(
        "run_sandbox",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("run_sandbox is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("Could not read this actor's capability-world ceiling"),
        "an unreadable ceiling must REFUSE and say so: {msg}"
    );
    assert!(
        msg.contains("refused rather than run without"),
        "and must say the request was not run, which is the whole difference \
         between this and the pre-fix skip: {msg}"
    );
    assert!(
        !msg.contains("Actor capability ceiling exceeded"),
        "an unreadable ceiling is NOT a ceiling violation — a caller must be \
         able to tell a policy refusal from an unreadable rule: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 2. `compile_custom_sandbox` — the same gate, the same refusal. The two
//    sandbox sites were byte-identical pre-fix, so repairing one and not the
//    other is the shape MCP-545 already produced once.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn compile_custom_sandbox_refuses_when_the_capability_ceiling_cannot_be_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let actor_id = seed_actor(&pool, user_id, "minimal-node").await;
    let state = mcp_state(pool.clone()).await;

    let args = serde_json::json!({
        "name": "p26-compile-probe",
        "rust_code": "pub fn run(_input: String) -> String { String::new() }",
        "capability_world": "secrets-node",
        "agent_id": actor_id.to_string(),
    });

    let ok = controller::mcp::sandbox::dispatch(
        "compile_custom_sandbox",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("compile_custom_sandbox is dispatched");
    let control_msg = error_message(&ok);
    assert!(
        control_msg.contains("Actor capability ceiling exceeded"),
        "control: the live gate refuses a request above the ceiling: {control_msg}"
    );

    sqlx::query("DROP TABLE actors CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the ceiling read names");

    let degraded = controller::mcp::sandbox::dispatch(
        "compile_custom_sandbox",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("compile_custom_sandbox is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("Could not read this actor's capability-world ceiling"),
        "an unreadable ceiling must REFUSE and say so: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 3. `tag_workflow` — an unreadable tag count must REFUSE, not lift the cap.
//
//    STATED LIMIT, so nobody reads more into this than it proves. The count
//    read and the tag write name the SAME column of the SAME table
//    (`workflows.tags`), so no schema mutation can make one fail and the other
//    succeed: this test cannot demonstrate a write landing past a lifted cap.
//    What it pins is the DIAGNOSIS and the disclosure. Pre-fix, with the column
//    gone, `.unwrap_or(0)` read as "this workflow has no tags", the cap was
//    evaluated against a number nobody obtained, `add_tag` was entered, and the
//    caller was told "Failed to tag workflow" — a generic write error that says
//    nothing about the bound. Post-fix the caller is told the cap could not be
//    enforced and that no tag was added. Reverting the site to `.unwrap_or(0)`
//    turns this test red.
// ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tag_workflow_refuses_when_the_tag_cap_cannot_be_read() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id).await;
    let state = mcp_state(pool.clone()).await;

    let args = serde_json::json!({ "workflow_id": wf_id.to_string(), "tag": "p26" });

    // CONTROL: intact schema. The success path is unchanged.
    let ok = controller::mcp::search::dispatch(
        "tag_workflow",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("tag_workflow is dispatched");
    assert!(
        ok.error.is_none(),
        "control run must succeed: {:?}",
        ok.error
    );
    let text = ok
        .result
        .as_ref()
        .and_then(|r| r.pointer("/content/0/text"))
        .and_then(|t| t.as_str())
        .unwrap_or_default()
        .to_string();
    assert!(
        text.contains("added to workflow"),
        "control: the tag is added and reported: {text}"
    );
    let tags: Vec<String> = sqlx::query_scalar("SELECT tags FROM workflows WHERE id = $1")
        .bind(wf_id)
        .fetch_one(&pool)
        .await
        .expect("read back the tags");
    assert_eq!(tags, vec!["p26".to_string()], "the write really happened");

    // The count read now cannot run: `coalesce(array_length(tags, 1), 0)` names
    // a column that is gone.
    sqlx::query("ALTER TABLE workflows DROP COLUMN tags")
        .execute(&pool)
        .await
        .expect("drop the column the count read names");

    let args2 = serde_json::json!({ "workflow_id": wf_id.to_string(), "tag": "p26-second" });
    let degraded = controller::mcp::search::dispatch(
        "tag_workflow",
        Some(serde_json::json!(2)),
        &args2,
        &state,
        agent(user_id),
    )
    .await
    .expect("tag_workflow is dispatched");
    let msg = error_message(&degraded);
    assert!(
        msg.contains("100-tag cap") && msg.contains("could not be enforced"),
        "an unreadable count must refuse ON THE CAP, not fall through to a \
         generic write failure: {msg}"
    );
    assert!(
        msg.contains("No tag was added"),
        "and must say so, because the pre-fix path DID attempt the write: {msg}"
    );
    assert!(
        !msg.contains("Failed to tag workflow"),
        "the pre-fix diagnosis blamed the write; the bound is what could not be \
         read: {msg}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// 4. `get_execution_cost` — a cost of ZERO must not be what a failed read
//    looks like. The DISCLOSURE shape (the `Readings` ledger) rather than the
//    refusal shape: this tool is a report, and the repo's rule for a report is
//    that an unmeasured field renders `null` beside a ledger entry saying so.
//    One test per distinct SHAPE, so this stands for the whole `Readings`
//    group in this package (`whoami`, `get_module_dependents`,
//    `build_execution_trace_json`).
// ───────────────────────────────────────────────────────────────────────────

async fn seed_execution(pool: &sqlx::PgPool, user_id: Uuid, workflow_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    // `workflow_executions.actor_id` is NOT NULL (actor universalization), so
    // the row needs a real actor.
    let actor_id = seed_actor(pool, user_id, "minimal-node").await;
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, actor_id, status, started_at, completed_at) \
         VALUES ($1, $2, $3, $4, 'completed', NOW() - INTERVAL '5 seconds', NOW())",
    )
    .bind(id)
    .bind(workflow_id)
    .bind(user_id)
    .bind(actor_id)
    .execute(pool)
    .await
    .expect("seed execution");
    id
}

#[tokio::test]
async fn execution_cost_reports_unknown_rather_than_zero_when_the_fuel_read_fails() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let wf_id = seed_workflow(&pool, user_id).await;
    let exec_id = seed_execution(&pool, user_id, wf_id).await;
    let state = mcp_state(pool.clone()).await;
    let args = serde_json::json!({ "execution_id": exec_id.to_string() });

    // CONTROL: intact schema, no rollup rows. Zero really is the answer, and it
    // must stay sayable — that is the whole reason the failed read may not也
    // render as zero.
    let ok = controller::mcp::executions::dispatch(
        "get_execution_cost",
        Some(serde_json::json!(1)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_cost is dispatched");
    assert!(
        ok.error.is_none(),
        "control run must succeed: {:?}",
        ok.error
    );
    let body = text_json(&ok);
    assert_eq!(
        body["total_fuel_consumed"].as_i64(),
        Some(0),
        "an execution with no rollup rows genuinely cost 0 fuel: {body}"
    );
    assert!(
        body.get("measurement").is_none() && body.get("readings").is_none(),
        "a fully measured report carries no disclosure: {body}"
    );

    // The fuel read now cannot run. `execution_cost_rollup` is named by that
    // read and by nothing else this handler touches.
    sqlx::query("DROP TABLE execution_cost_rollup CASCADE")
        .execute(&pool)
        .await
        .expect("drop the table the fuel read names");

    let degraded = controller::mcp::executions::dispatch(
        "get_execution_cost",
        Some(serde_json::json!(2)),
        &args,
        &state,
        agent(user_id),
    )
    .await
    .expect("get_execution_cost is dispatched");
    assert!(
        degraded.error.is_none(),
        "a failed cost read is disclosed in the body, not raised: {:?}",
        degraded.error
    );
    let body = text_json(&degraded);
    assert!(
        body["total_fuel_consumed"].is_null() && body["compute_units"].is_null(),
        "an unreadable rollup is UNKNOWN, never a cost of zero: {body}"
    );
    let rendered = serde_json::to_string(&body).expect("serialize");
    assert!(
        rendered.contains("total_fuel_consumed"),
        "and the field that could not be measured must be NAMED in the \
         disclosure, not merely omitted: {rendered}"
    );
    assert!(
        body["total_duration_ms"].as_i64().is_some(),
        "the fields that WERE measured are untouched: {body}"
    );
}

// ───────────────────────────────────────────────────────────────────────────
// The THIRD shape: a periodic permission refresh on a live subscription.
//
// #779 fixed `dlq_updates` to NARROW rather than KEEP the prior permission set
// when a refresh read fails, and recorded the fix as untested — the decision
// lived inside an `async_stream::stream!` body in a GraphQL resolver that
// needs a schema, a broadcast channel and a live subscription to reach. It is
// now `talos_api::schema::subscriptions::refresh_dlq_permissions`, and these
// drive it against a real database with the relation each read names removed.
//
// The direction matters more here than in the two gates above. A DLQ payload
// is DLP-scrubbed but still tenant-scoped, and the refresh exists ONLY to
// notice a revocation: preserving the prior set on a failed read is the one
// outcome that defeats it, and it does so for as long as the read keeps
// failing. Both CONTROLS run in the same binary — a healthy non-admin keeps
// its real org list, a healthy admin still bypasses the filter — because
// "the refresh returned nothing" is not evidence on its own.
// ───────────────────────────────────────────────────────────────────────────

/// Provision one org OWNED by `user_id` through the PRODUCTION service, which
/// inserts the owner's `organization_members` row itself — the Testing
/// Conventions rule, and the one a hand-rolled INSERT here drifted from
/// before it was applied (`created_at` is spelled `joined_at` on that table).
async fn seed_org_membership(pool: &sqlx::PgPool, user_id: Uuid) -> Uuid {
    let slug = format!("p30-{}", Uuid::new_v4().simple());
    let org = talos_organizations::OrganizationService::create_org(pool, "p30 org", &slug, user_id)
        .await
        .expect("seed org through the production service");
    org.id
}

#[tokio::test]
async fn an_unreadable_org_membership_narrows_to_own_events_only() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let org_id = seed_org_membership(&pool, user_id).await;
    let actor_repo = talos_actor_repository::ActorRepository::new(pool.clone());

    // CONTROL: a healthy read returns the org the user really belongs to.
    let healthy =
        talos_api::schema::subscriptions::refresh_dlq_permissions(&actor_repo, &pool, user_id)
            .await;
    assert!(!healthy.is_admin);
    assert_eq!(
        healthy.accessible_org_ids,
        vec![org_id],
        "a healthy refresh must return the subscriber's real org list, or the \
         degraded case below proves nothing"
    );

    // Now the membership read cannot answer.
    sqlx::query("DROP TABLE organization_members CASCADE")
        .execute(&pool)
        .await
        .expect("drop membership relation");

    let degraded =
        talos_api::schema::subscriptions::refresh_dlq_permissions(&actor_repo, &pool, user_id)
            .await;
    assert!(
        !degraded.is_admin,
        "an unreadable membership must not promote the subscriber"
    );
    assert!(
        degraded.accessible_org_ids.is_empty(),
        "an unreadable membership refresh must NARROW to own-events-only. \
         Keeping the prior set is the one outcome that defeats a refresh whose \
         entire purpose is to notice a revocation: the subscriber goes on \
         receiving another org's DLQ events for as long as the read keeps \
         failing. Got: {:?}",
        degraded.accessible_org_ids
    );
}

#[tokio::test]
async fn an_unreadable_admin_flag_does_not_preserve_admin_visibility() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let org_id = seed_org_membership(&pool, user_id).await;
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("promote");
    let actor_repo = talos_actor_repository::ActorRepository::new(pool.clone());

    // CONTROL: a real admin bypasses the filter, and the org list is cleared
    // deliberately so a later demotion forces a re-fetch.
    let healthy =
        talos_api::schema::subscriptions::refresh_dlq_permissions(&actor_repo, &pool, user_id)
            .await;
    assert!(healthy.is_admin, "a real platform admin must read as admin");
    assert!(
        healthy.accessible_org_ids.is_empty(),
        "an admin bypasses the tenant filter, so the org list is deliberately \
         cleared (a demotion then forces a re-fetch) — {org_id} must not linger"
    );

    // Now the admin read cannot answer.
    sqlx::query("ALTER TABLE users RENAME COLUMN is_platform_admin TO is_platform_admin_gone")
        .execute(&pool)
        .await
        .expect("rename admin column");

    let degraded =
        talos_api::schema::subscriptions::refresh_dlq_permissions(&actor_repo, &pool, user_id)
            .await;
    assert!(
        !degraded.is_admin,
        "an unreadable admin flag must NOT preserve admin visibility — that \
         bypasses the tenant filter entirely, which is the widest possible \
         reading of a read that did not answer"
    );
    assert!(
        degraded.accessible_org_ids.is_empty(),
        "and it must narrow the org list in the same breath"
    );
}
