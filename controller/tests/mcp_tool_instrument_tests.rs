//! The MCP `tools/call` instrument, and the two statement-count fixes its
//! measurements justified (2026-09-08).
//!
//! Until this change nothing on this platform could say which operator
//! surface is slow: `/metrics/prometheus` carried no per-tool series (the
//! only `talos_*` names matching `mcp|tool|handler|request` were the four
//! `talos_db_pool_*` gauges), the controller log carried no per-call line,
//! and the live Postgres has no `pg_stat_statements`. So a report built from
//! two dozen independent reads had no measured cost anywhere.
//!
//! What this binary pins, and why each needs a ROUND TRIP rather than a unit
//! test:
//!
//! * **The chokepoint increments.** `talos_mcp_handlers::tool_labels`' unit
//!   tests prove the label RULE; they cannot prove that
//!   `handle_tools_call` calls it. Deleting the `record_mcp_tool_call` line
//!   is behaviourally invisible everywhere else.
//! * **The cardinality guard.** The mutation this exists for is a future edit
//!   passing `params.name` through as the label. Three garbage names must
//!   yield ONE series; the assertion is on the registry's own gathered label
//!   values, never on `with_label_values` (which CREATES the series it is
//!   asked about and would make the test pass by manufacturing its own
//!   evidence).
//! * **The two fixes.** Both are statement-count claims, and a statement
//!   count is only observable while the statements are being issued — hence
//!   the `sqlx::query` tracing counter below rather than an after-the-fact
//!   assertion about rows.
//!
//! # How the statements are counted
//!
//! sqlx emits one `tracing` event per executed statement on target
//! `sqlx::query` (`sqlx-core/src/logger.rs`), including the `BEGIN` /
//! `SET LOCAL` / `COMMIT` of a scoped transaction — so these numbers are
//! ROUND TRIPS, which is what latency is paid in. The counter is a
//! THREAD-LOCAL and `#[tokio::test]` builds a CURRENT-THREAD runtime, so
//! each test counts only its own work even when libtest runs the binary's
//! tests in parallel. There is no `pg_stat_statements` on this stack (checked
//! 2026-09-08, live) and adding it is a separate leg of the same change.

#[path = "common/mod.rs"]
mod common;
#[path = "common/mcp.rs"]
mod mcp_common;

use mcp_common::{agent, mcp_state};
use std::cell::Cell;
use std::sync::OnceLock;
use talos_metrics::McpToolOutcome;
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::Layer;
use uuid::Uuid;

// ── statement counting ──────────────────────────────────────────────────

thread_local! {
    static STMTS: Cell<u64> = const { Cell::new(0) };
}

struct SqlxCountLayer;
impl<S: tracing::Subscriber> Layer<S> for SqlxCountLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        if event.metadata().target().starts_with("sqlx::query") {
            STMTS.with(|c| c.set(c.get() + 1));
        }
    }
}

fn install_statement_counter() {
    static ONCE: OnceLock<()> = OnceLock::new();
    ONCE.get_or_init(|| {
        let sub = tracing_subscriber::registry().with(SqlxCountLayer);
        let _ = tracing::subscriber::set_global_default(sub);
    });
}

fn statements() -> u64 {
    STMTS.with(std::cell::Cell::get)
}

// ── metrics ─────────────────────────────────────────────────────────────

/// The ONE installer in this binary.
///
/// `talos_metrics::set_global` is a one-shot `OnceLock`, so a test that
/// installs its own registry and asserts against that local `Arc` is correct
/// only if it wins the race — the production site writes through
/// `talos_metrics::global()`. Returning the INSTALLED registry makes the
/// assertions order-independent; every caller reads DELTAS, because a sibling
/// test may have moved the same series first.
fn installed_metrics() -> std::sync::Arc<talos_metrics::TalosMetrics> {
    if let Some(m) = talos_metrics::global() {
        return m.clone();
    }
    let m = talos_metrics::TalosMetrics::new().expect("metrics registry");
    talos_metrics::set_global(m);
    talos_metrics::global()
        .cloned()
        .expect("a global registry is installed by now")
}

/// Every `(tool, outcome)` label pair present on a metric family, read out of
/// the registry's own gathered output.
///
/// Deliberately NOT `with_label_values(..).get()`: that CREATES the series it
/// is asked about, so a cardinality assertion written that way manufactures
/// the evidence it then checks.
fn label_pairs(
    m: &talos_metrics::TalosMetrics,
    family: &str,
) -> std::collections::BTreeMap<(String, String), f64> {
    let mut out = std::collections::BTreeMap::new();
    for mf in m.registry.gather() {
        if mf.name() != family {
            continue;
        }
        for metric in mf.get_metric() {
            let mut tool = String::new();
            let mut outcome = String::new();
            for l in metric.get_label() {
                match l.name() {
                    "tool" => tool = l.value().to_string(),
                    "outcome" => outcome = l.value().to_string(),
                    _ => {}
                }
            }
            // Counter families carry a counter; histogram families carry a
            // histogram whose sample COUNT is the comparable number.
            let v = if mf.get_field_type() == prometheus::proto::MetricType::COUNTER {
                metric.get_counter().value()
            } else {
                metric.get_histogram().get_sample_count() as f64
            };
            out.insert((tool, outcome), v);
        }
    }
    out
}

fn call(tool: &str, args: serde_json::Value) -> controller::mcp::types::JsonRpcRequest {
    controller::mcp::types::JsonRpcRequest {
        jsonrpc: "2.0".to_string(),
        id: Some(serde_json::json!("probe")),
        method: "tools/call".to_string(),
        params: Some(serde_json::json!({ "name": tool, "arguments": args })),
    }
}

async fn seed_user(pool: &sqlx::PgPool) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, created_at, updated_at) \
         VALUES ($1, $2, 'x', NOW(), NOW())",
    )
    .bind(id)
    .bind(format!("p33-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

// ── Leg A: the instrument ───────────────────────────────────────────────

#[tokio::test]
async fn the_chokepoint_records_a_series_for_a_real_tool_call() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let m = installed_metrics();

    let before = label_pairs(&m, "talos_mcp_tool_calls_total")
        .get(&("whoami".to_string(), "ok".to_string()))
        .copied()
        .unwrap_or(0.0);
    let before_h = label_pairs(&m, "talos_mcp_tool_duration_seconds")
        .get(&("whoami".to_string(), "ok".to_string()))
        .copied()
        .unwrap_or(0.0);

    let resp = controller::mcp::handle_tools_call(
        call("whoami", serde_json::json!({})),
        state.clone(),
        agent(user_id),
    )
    .await;
    assert_eq!(
        talos_mcp_handlers::tool_labels::classify_outcome(&resp),
        McpToolOutcome::Ok,
        "whoami on a healthy database is the control for this whole binary"
    );

    let after = label_pairs(&m, "talos_mcp_tool_calls_total")
        .get(&("whoami".to_string(), "ok".to_string()))
        .copied()
        .unwrap_or(0.0);
    let after_h = label_pairs(&m, "talos_mcp_tool_duration_seconds")
        .get(&("whoami".to_string(), "ok".to_string()))
        .copied()
        .unwrap_or(0.0);
    assert_eq!(
        after - before,
        1.0,
        "the counter must move exactly once per tools/call"
    );
    assert_eq!(
        after_h - before_h,
        1.0,
        "the histogram must observe exactly once per tools/call — one record \
         site writes both, so a drift here means the two were split"
    );
}

#[tokio::test]
async fn an_unknown_tool_name_records_exactly_one_unknown_series() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let m = installed_metrics();

    // Three names a caller could invent, including a long one. If a future
    // edit passed `params.name` through as the label, this alone would mint
    // three series — and an attacker with `/mcp` access could mint unbounded
    // ones. That is the mutation this test exists for.
    let invented = [
        "definitely_not_a_tool",
        "../../etc/passwd",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ];
    let before = label_pairs(&m, "talos_mcp_tool_calls_total")
        .get(&("unknown".to_string(), "unknown_tool".to_string()))
        .copied()
        .unwrap_or(0.0);

    for name in invented {
        let resp = controller::mcp::handle_tools_call(
            call(name, serde_json::json!({})),
            state.clone(),
            agent(user_id),
        )
        .await;
        assert_eq!(
            talos_mcp_handlers::tool_labels::classify_outcome(&resp),
            McpToolOutcome::UnknownTool
        );
    }

    let pairs = label_pairs(&m, "talos_mcp_tool_calls_total");
    for name in invented {
        assert!(
            !pairs.keys().any(|(t, _)| t == name),
            "the caller's own string reached the label set: {name}"
        );
    }
    let after = pairs
        .get(&("unknown".to_string(), "unknown_tool".to_string()))
        .copied()
        .unwrap_or(0.0);
    assert_eq!(
        after - before,
        3.0,
        "all three invented names must land on the single `unknown` series"
    );
}

#[tokio::test]
async fn the_instrument_leaves_the_response_byte_identical() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let _ = installed_metrics();

    // The same tool through the instrumented chokepoint and through the
    // domain dispatch it wraps. The instrument OBSERVES; if it ever decorated
    // or re-serialised, these would differ.
    let via_chokepoint = controller::mcp::handle_tools_call(
        call(
            "describe_capability_world",
            serde_json::json!({"capability_world":"minimal"}),
        ),
        state.clone(),
        agent(user_id),
    )
    .await;
    let via_dispatch = controller::mcp::configuration::dispatch(
        "describe_capability_world",
        Some(serde_json::json!("probe")),
        &serde_json::json!({"capability_world":"minimal"}),
        &state,
        agent(user_id),
    )
    .await
    .expect("describe_capability_world is dispatched");

    assert_eq!(
        serde_json::to_string(&via_chokepoint).unwrap(),
        serde_json::to_string(&via_dispatch).unwrap(),
        "the instrument must not alter a single byte of the tool's answer"
    );
}

#[tokio::test]
async fn a_caller_fault_records_refused_and_a_server_fault_records_error() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let m = installed_metrics();

    // A missing required argument is -32602 — the CALLER can fix it. Folding
    // it into `error` would make a client looping on a typo indistinguishable
    // from a database outage, which is the split the outcome label is for.
    let before = label_pairs(&m, "talos_mcp_tool_calls_total")
        .get(&("get_workflow".to_string(), "refused".to_string()))
        .copied()
        .unwrap_or(0.0);
    let resp = controller::mcp::handle_tools_call(
        call("get_workflow", serde_json::json!({})),
        state.clone(),
        agent(user_id),
    )
    .await;
    assert_eq!(
        talos_mcp_handlers::tool_labels::classify_outcome(&resp),
        McpToolOutcome::Refused,
        "a missing required argument is a refusal, not a server error"
    );
    let after = label_pairs(&m, "talos_mcp_tool_calls_total")
        .get(&("get_workflow".to_string(), "refused".to_string()))
        .copied()
        .unwrap_or(0.0);
    assert_eq!(after - before, 1.0);
}

// ── Leg B: the two statement-count fixes ────────────────────────────────

/// Seed `n` workflows with a two-module graph and NO capabilities — the exact
/// population `get_ids_without_capabilities` returns.
async fn seed_uncapabilized(pool: &sqlx::PgPool, user_id: Uuid, n: usize) -> Vec<Uuid> {
    let m1 = Uuid::new_v4();
    let m2 = Uuid::new_v4();
    for (id, world) in [(m1, "http-node"), (m2, "minimal-node")] {
        sqlx::query(
            "INSERT INTO modules (id, name, kind, capability_world, user_id) \
             VALUES ($1, $2, 'sandbox', $3, $4)",
        )
        .bind(id)
        .bind(format!("m-{id}"))
        .bind(world)
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed module");
    }
    let mut ids = Vec::new();
    for i in 0..n {
        let id = Uuid::new_v4();
        let graph = serde_json::json!({
            "nodes": [
                {"id": "a", "type": m1.to_string()},
                {"id": "b", "type": m2.to_string()},
                {"id": "c", "type": m1.to_string()}
            ],
            "edges": [{"source": "a", "target": "c"}, {"source": "b", "target": "c"}]
        });
        sqlx::query(
            "INSERT INTO workflows (id, name, module_uri, graph_json, user_id, status, capabilities) \
             VALUES ($1, $2, '', $3, $4, 'active', '{}')",
        )
        .bind(id)
        .bind(format!("wf-{i}-{id}"))
        .bind(graph.to_string())
        .bind(user_id)
        .execute(pool)
        .await
        .expect("seed workflow");
        ids.push(id);
    }
    ids
}

/// The N+1 fix, asserted as a statement count AND as an identical answer.
///
/// Before: `1 + 4N` statements — one graph+capabilities read, one world read,
/// one kind read and one UPDATE per workflow, serially, inside a background
/// `tokio::spawn` competing with live requests for the same pool. Measured at
/// **27 for N = 6** on a fleet-shaped scratch database; the reader that feeds
/// it is `LIMIT 100`, so the worst case was 401.
///
/// After: a constant three (`= ANY($1)` graphs, `= ANY($1)` module
/// attributes, one bulk `UPDATE … FROM jsonb_array_elements`).
///
/// The count alone would pass for a batched path that computed the WRONG
/// tags, so the tags are compared against the per-workflow path's own answer
/// on an identical population.
#[tokio::test]
async fn the_capability_heal_is_constant_in_page_size_and_answers_identically() {
    install_statement_counter();
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;

    // Population A — driven by the per-workflow path, one workflow at a time.
    let a = seed_uncapabilized(&pool, user_id, 6).await;
    let before_loop = statements();
    for id in &a {
        talos_mcp_handlers::analytics::auto_suggest_capabilities(*id, user_id, &pool).await;
    }
    let loop_statements = statements() - before_loop;

    // Population B — the same six shapes, driven by the batched path.
    let b = seed_uncapabilized(&pool, user_id, 6).await;
    let before_bulk = statements();
    talos_mcp_handlers::analytics::auto_suggest_capabilities_bulk(&b, user_id, &pool).await;
    let bulk_statements = statements() - before_bulk;

    assert!(
        loop_statements >= 4 * a.len() as u64,
        "the per-workflow path should cost at least 4 statements per workflow, \
         got {loop_statements} for {}",
        a.len()
    );
    assert!(
        bulk_statements <= 4,
        "the batched path must be constant in page size, got {bulk_statements} \
         statements for {} workflows",
        b.len()
    );

    // Identical answer. Both populations have the same graph shape, so the
    // tag sets must match exactly — a count-only assertion would pass over a
    // batched path that tagged everything `[]`.
    let caps_a: Vec<Vec<String>> = fetch_caps(&pool, &a).await;
    let caps_b: Vec<Vec<String>> = fetch_caps(&pool, &b).await;
    assert!(
        !caps_a[0].is_empty(),
        "control: the per-workflow path must have tagged something, got {:?}",
        caps_a[0]
    );
    assert_eq!(
        caps_a, caps_b,
        "the batched path must produce the per-workflow path's answer"
    );
}

async fn fetch_caps(pool: &sqlx::PgPool, ids: &[Uuid]) -> Vec<Vec<String>> {
    let mut out = Vec::new();
    for id in ids {
        let caps: Vec<String> =
            sqlx::query_scalar("SELECT COALESCE(capabilities, '{}') FROM workflows WHERE id = $1")
                .bind(id)
                .fetch_one(pool)
                .await
                .expect("read capabilities");
        out.push(caps);
    }
    out
}

/// An operator tag set between the read and the write must survive — the
/// guard that makes the heal idempotent, and the one a bulk UPDATE is most
/// likely to lose.
#[tokio::test]
async fn the_bulk_heal_never_overwrites_an_explicit_tag() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let ids = seed_uncapabilized(&pool, user_id, 2).await;
    sqlx::query("UPDATE workflows SET capabilities = ARRAY['operator-chose-this'] WHERE id = $1")
        .bind(ids[0])
        .execute(&pool)
        .await
        .expect("operator tag");

    talos_mcp_handlers::analytics::auto_suggest_capabilities_bulk(&ids, user_id, &pool).await;

    let caps = fetch_caps(&pool, &ids).await;
    assert_eq!(
        caps[0],
        vec!["operator-chose-this".to_string()],
        "an explicit tag must survive the heal"
    );
    assert!(
        !caps[1].is_empty(),
        "control: the untagged sibling in the same page must still be tagged"
    );
}

/// The CALL SITE, which the test above structurally cannot see.
///
/// `the_capability_heal_is_constant_in_page_size_and_answers_identically`
/// drives `auto_suggest_capabilities_bulk` directly, so reverting
/// `session_start`'s spawn to `for wf_id in ids { … }` leaves it green — the
/// call-site limit checks 74b and 79b state as their own. This drives the real
/// tool through the real chokepoint and counts what its BACKGROUND spawn
/// issues, which is the only place that revert is visible.
#[tokio::test]
async fn session_starts_heal_spawn_is_batched_at_the_call_site() {
    install_statement_counter();
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let ids = seed_uncapabilized(&pool, user_id, 6).await;
    let state = mcp_state(pool.clone()).await;
    let _ = installed_metrics();

    let resp = controller::mcp::handle_tools_call(
        call("session_start", serde_json::json!({})),
        state.clone(),
        agent(user_id),
    )
    .await;
    assert_eq!(
        talos_mcp_handlers::tool_labels::classify_outcome(&resp),
        McpToolOutcome::Ok,
        "control: session_start must succeed, or the spawn never fires and a \
         background count of zero would look like a fix"
    );

    // Drain the spawn. `#[tokio::test]` builds a current-thread runtime, so the
    // spawned task runs on THIS thread and its statements land in this test's
    // thread-local counter.
    let before = statements();
    tokio::time::sleep(std::time::Duration::from_millis(2500)).await;
    let background = statements() - before;

    let caps = fetch_caps(&pool, &ids).await;
    assert!(
        caps.iter().all(|c| !c.is_empty()),
        "control: the heal must actually have tagged the page, got {caps:?}"
    );
    assert!(
        background <= 8,
        "session_start's capability heal issued {background} background \
         statements for {} workflows; the per-workflow loop is back (it cost \
         1 + 4N, measured at 27 for N = 6)",
        ids.len()
    );
}

/// The SQL guard, driven DIRECTLY — because the caller's own filter hides it.
///
/// `the_bulk_heal_never_overwrites_an_explicit_tag` above passes with the
/// `AND (w.capabilities IS NULL OR w.capabilities = '{}')` clause DELETED
/// (measured), because `auto_suggest_capabilities_bulk` skips an
/// already-tagged workflow in Rust before it ever builds the assignment. The
/// SQL clause is what covers the gap the Rust filter cannot: a tag written
/// BETWEEN the read and the write. That race is not injectable from a test,
/// so the clause is driven at the repository instead, with an assignment the
/// caller would never construct.
#[tokio::test]
async fn the_bulk_write_refuses_a_workflow_that_already_has_tags() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let ids = seed_uncapabilized(&pool, user_id, 2).await;
    sqlx::query("UPDATE workflows SET capabilities = ARRAY['set-after-the-read'] WHERE id = $1")
        .bind(ids[0])
        .execute(&pool)
        .await
        .expect("operator tag");

    let repo = talos_analytics_repository::AnalyticsRepository::new(pool.clone());
    let written = repo
        .set_capabilities_if_empty_bulk(
            &[
                (ids[0], vec!["heal-computed-this".to_string()]),
                (ids[1], vec!["heal-computed-this".to_string()]),
            ],
            user_id,
        )
        .await
        .expect("bulk write");

    assert_eq!(
        written, 1,
        "the write must skip the row that acquired a tag after the read"
    );
    let caps = fetch_caps(&pool, &ids).await;
    assert_eq!(caps[0], vec!["set-after-the-read".to_string()]);
    assert_eq!(
        caps[1],
        vec!["heal-computed-this".to_string()],
        "control: the still-empty sibling in the same statement must be written"
    );
}

/// Batching changed the BLAST RADIUS of a failed module read, so the batched
/// path refuses to write rather than degrading.
///
/// The per-workflow path swallowed this read and, on failure, wrote the
/// graph-STRUCTURE tags alone. One workflow at a time that is an accident;
/// for a page of 100 it is one, and the `if empty` guard makes it PERMANENT —
/// a structure-only-tagged workflow is no longer uncapabilized, so the heal
/// never revisits it. The failure is injected by renaming the column the read
/// names, which leaves `workflows` untouched so the control is meaningful.
#[tokio::test]
async fn a_failed_module_read_writes_no_tags_rather_than_partial_ones() {
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let ids = seed_uncapabilized(&pool, user_id, 3).await;

    // Control: the healthy path tags all three.
    talos_mcp_handlers::analytics::auto_suggest_capabilities_bulk(&ids, user_id, &pool).await;
    let healthy = fetch_caps(&pool, &ids).await;
    assert!(
        healthy.iter().all(|c| !c.is_empty()),
        "control: a healthy page must be tagged, got {healthy:?}"
    );

    // Degraded: a fresh page, with the attribute read's column gone.
    let degraded_ids = seed_uncapabilized(&pool, user_id, 3).await;
    sqlx::query("ALTER TABLE modules RENAME COLUMN capability_world TO capability_world_gone")
        .execute(&pool)
        .await
        .expect("rename the column the read names");

    talos_mcp_handlers::analytics::auto_suggest_capabilities_bulk(&degraded_ids, user_id, &pool)
        .await;

    let after = fetch_caps(&pool, &degraded_ids).await;
    assert!(
        after.iter().all(std::vec::Vec::is_empty),
        "a failed module read must write NOTHING — structure-only tags would be \
         permanent, since the if-empty guard stops the heal revisiting the row. Got {after:?}"
    );
}

/// `get_system_health` issued the SAME statement twice — once discarded to
/// `.is_ok()` as a connectivity probe, then again for its value — and that
/// statement carries an unbounded `COUNT(*)` over `workflow_executions`.
/// Measured at 10.3 ms + 5.7 ms of the tool's 31.9 ms on a fleet-shaped
/// scratch database.
///
/// The assertion is a CEILING on statements rather than an exact number: the
/// tool issues nine other reads whose transaction shape is not this change's
/// business, and pinning their total would make an unrelated edit fail here.
/// What must not come back is a second `get_system_status_counts`.
#[tokio::test]
async fn system_health_reads_the_status_counts_once() {
    install_statement_counter();
    let (pool, _db) = common::isolated_db_pool().await;
    let user_id = seed_user(&pool).await;
    let state = mcp_state(pool.clone()).await;
    let _ = installed_metrics();

    // Admin: the tool refuses a non-admin above every read, which would make
    // a statement count of zero look like a fix.
    sqlx::query("UPDATE users SET is_platform_admin = true WHERE id = $1")
        .bind(user_id)
        .execute(&pool)
        .await
        .expect("promote");

    let before = statements();
    let resp = controller::mcp::handle_tools_call(
        call("get_system_health", serde_json::json!({})),
        state.clone(),
        agent(user_id),
    )
    .await;
    let issued = statements() - before;

    let body: serde_json::Value = serde_json::from_str(
        resp.result
            .as_ref()
            .and_then(|r| r.pointer("/content/0/text"))
            .and_then(|t| t.as_str())
            .expect("a text result"),
    )
    .expect("system health renders JSON");
    assert_eq!(
        body.get("database_connected"),
        Some(&serde_json::json!(true)),
        "control: the healthy path must still report a connected database"
    );
    assert_eq!(
        body.get("total_workflows"),
        Some(&serde_json::json!(0)),
        "control: the counts must still come from the read, not from a default"
    );
    assert!(
        issued <= 15,
        "get_system_health issued {issued} statements; the duplicate \
         get_system_status_counts is back (it cost 3: the statement plus its \
         scoped transaction's BEGIN and COMMIT)"
    );
}

/// The batched graph read's `user_id` must be LOAD-BEARING, not decorative.
///
/// Added by the orchestrator in validation, because a mutation SURVIVED
/// everything else in this package: replacing
/// `WHERE id = ANY($1) AND user_id = $2` with a predicate that ignores the
/// bind left all 152 unit tests, all four DB binaries and every one of the
/// 88 structural checks green. Check 70 is the guard for exactly this shape
/// and is scoped to WRITES, so it correctly says nothing here.
///
/// It is LATENT today and that is stated rather than dressed up: the method's
/// only caller (`auto_suggest_capabilities_bulk`) receives ids from
/// `get_ids_without_capabilities(user_id)`, which is already user-scoped, so
/// own-user ids return own-user rows whatever the predicate says. What the
/// mutation costs is the METHOD's contract: it is `pub`, it takes a
/// `user_id`, and its per-id sibling
/// (`get_workflow_graph_and_capabilities`) really is tenant-scoped — so a
/// future caller passing ids from a graph scan or a capability resolution
/// would read another tenant's `graph_json` through a parameter that looks
/// like a gate. This test makes that parameter's absence observable.
#[tokio::test]
async fn the_batched_graph_read_refuses_another_tenants_ids() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let owned = seed_uncapabilized(&pool, owner, 1).await;
    let foreign = seed_uncapabilized(&pool, stranger, 1).await;

    let repo = talos_analytics_repository::AnalyticsRepository::new(pool.clone());

    // CONTROL: the owner's own id resolves, so an empty answer below cannot
    // be an empty database or a broken seed.
    let mine = repo
        .get_workflow_graphs_and_capabilities(&owned, owner)
        .await
        .expect("the owner's own graph reads");
    assert_eq!(
        mine.len(),
        1,
        "control: the owner's own id must resolve through the batched read"
    );

    // The finding: another tenant's id, asked for as this user.
    let theirs = repo
        .get_workflow_graphs_and_capabilities(&foreign, owner)
        .await
        .expect("the read itself succeeds");
    assert!(
        theirs.is_empty(),
        "the batched read returned another tenant's workflow ({} row(s)); its \
         `user_id` bind is decorative, and every future caller that does not \
         pre-scope its id list inherits a cross-tenant read",
        theirs.len()
    );

    // And a MIXED page must return only the caller's half — the shape a
    // future caller with a graph-derived id list actually has.
    let mut mixed = owned.clone();
    mixed.extend_from_slice(&foreign);
    let got = repo
        .get_workflow_graphs_and_capabilities(&mixed, owner)
        .await
        .expect("the mixed read succeeds");
    assert_eq!(
        got.len(),
        1,
        "a mixed page must yield only the caller's row"
    );
    assert_eq!(
        got[0].0, owned[0],
        "and it must be the caller's own workflow"
    );
}
