//! The `__memory_write__` envelope must obey the actor's write ceiling (#750).
//!
//! # What this pins, and why a unit test could not
//!
//! `actors.max_write_ceiling` is ONE control with TWO enforcement surfaces. A
//! module reaches `actor_memory` either by calling `agent_memory::set` (gated
//! in the worker at `TalosContext::write_ceiling_refuses`) or by RETURNING
//! `{"__memory_write__": {…}}` and letting the controller persist it on node
//! completion. The second path had no ceiling reference of any kind, so a
//! `readonly` actor was refused one route and permitted the other **on the
//! same job** — and the node output still said the write succeeded.
//!
//! Proven live 2026-09-04 before the fix: actor `probe-750-readonly`
//! (`max_write_ceiling = 'readonly'`), a one-node workflow running a
//! `minimal-node` module — a world whose `get_module_info.mutation_profile`
//! correctly reports it can mutate NOTHING — completed successfully and
//! `actor_memory` gained a row. No process logged a gate decision.
//!
//! These tests drive the PRODUCTION chain end to end: a real
//! `ParallelWorkflowEngine`, the real `ControllerNodeHook` bound to a real
//! Postgres pool, a real graph, and a stub dispatcher standing in only for the
//! worker (which is where the module's output comes from and nothing else).
//! The assertion is on the DATABASE, not on a helper's return value — #724's
//! lesson: a guard that drives the helper instead of the call site stays green
//! when the call site is rewired.
//!
//! Deliberately written to COMPILE on pristine `main` (string literals instead
//! of the new `reserved_keys::MEMORY_WRITE_REFUSED` constant, no new
//! signatures in the test's own calls) so it fails there BY ASSERTION —
//! `assert_eq!(rows, 0)` seeing 1 — rather than by a compile error, which
//! proves nothing about behaviour.
//!
//! Runs in CI via `scripts/test-integration.sh` (**CTRL_TESTS**), invoked by
//! quality.yml's `integration` job as `make test-integration`. It uses the
//! `common` harness, so it needs `DATABASE_URL` pointed at a migrated template
//! database — which is what CTRL_TESTS supplies and TC_TESTS does not
//! (sub-leg 64b).

mod common;

use std::sync::Arc;

use async_trait::async_trait;
use serde_json::json;
use talos_workflow_engine::WorkflowGraphBuilder;
use talos_workflow_engine_core::{
    BoxError, ChainDispatchRequest, ChainDispatchResult, ChainStepResult, DispatchJob,
    DispatchResult, NodeDispatcher, StepStatus, WasmModuleArtifact,
};
use talos_workflow_engine_test_utils::{memory::InMemoryModuleFetcher, minimal_engine};
use uuid::Uuid;

/// Enforcement is a per-process `OnceLock`, so it must be set before the first
/// read anywhere in this binary. Every test here wants it ON; the flag-OFF
/// (staged-rollout default) case is covered by the pure unit tests in
/// `talos_workflow_engine::write_ceiling_gate`, which take `enforced` as a
/// parameter precisely so it need not be a process global.
fn enforce_write_ceiling() {
    std::env::set_var("TALOS_WRITE_CEILING_ENFORCED", "1");
    std::env::set_var(
        "TALOS_MASTER_KEY",
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    );
}

/// Stands in for the worker: returns whatever output the test scripted, which
/// is the only thing the worker contributes to this path.
struct EnvelopeDispatcher {
    output: serde_json::Value,
}

#[async_trait]
impl NodeDispatcher for EnvelopeDispatcher {
    async fn dispatch(&self, _job: DispatchJob) -> Result<DispatchResult, BoxError> {
        Ok(DispatchResult {
            output: self.output.clone(),
        })
    }

    async fn dispatch_chain(
        &self,
        request: ChainDispatchRequest,
    ) -> Result<ChainDispatchResult, BoxError> {
        let steps: Vec<ChainStepResult> = request
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
        // The live probe's module was `minimal-node`, whose mutation profile
        // is empty — the point being that this write route needs no
        // capability at all.
        capability_world: "minimal-node".into(),
        allowed_hosts: vec![],
        allowed_methods: vec![],
        allowed_secrets: vec![],
        requires_approval_for: vec![],
        integration_name: None,
        config: None,
    }
}

/// Seed a user, its personal org, and one actor at the given ceiling.
async fn seed_actor(pool: &sqlx::Pool<sqlx::Postgres>, ceiling: &str) -> Uuid {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'h', true)",
    )
    .bind(user)
    .bind(format!("wc-{user}@talos.test"))
    .execute(pool)
    .await
    .expect("seed user");
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("wcorg-{tag}"))
    .bind(format!("wcorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");
    let actor = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO actors (id, user_id, name, org_id, max_write_ceiling) \
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(actor)
    .bind(user)
    .bind(format!("wc-actor-{tag}"))
    .bind(org)
    .bind(ceiling)
    .execute(pool)
    .await
    .expect("seed actor");
    actor
}

/// Register the real memory crypto hook (Phase B: writes have no plaintext
/// fallback, so without this a permitted write fails and the control case
/// would pass for the wrong reason).
async fn register_crypto(pool: &sqlx::Pool<sqlx::Postgres>) {
    let sm = Arc::new(controller::secrets::SecretsManager::new(pool.clone()).unwrap());
    sm.initialize().await.unwrap();
    talos_memory::register_memory_crypto_hook(Arc::new(
        talos_memory_crypto::SecretsManagerMemoryCrypto::new(sm.clone()),
    ));
}

/// Run one node whose output carries `envelope`, under `ceiling`, through the
/// real engine + real `ControllerNodeHook`. Returns the node's final output.
async fn run_one_node(
    pool: &sqlx::Pool<sqlx::Postgres>,
    actor: Uuid,
    ceiling: talos_workflow_engine_core::WriteCeiling,
    envelope: serde_json::Value,
) -> serde_json::Value {
    let module = Uuid::new_v4();
    let graph = WorkflowGraphBuilder::new()
        .add_module(module.to_string(), module, None)
        .build()
        .expect("graph builds");

    let mut engine = minimal_engine();
    engine.set_user_id(Uuid::new_v4());
    engine.set_module_fetcher(Arc::new(
        InMemoryModuleFetcher::new().with_module(module, stub_artifact(module)),
    ));
    // The two values under test, stamped exactly as `apply_actor_to_engine`
    // stamps them on a live dispatch.
    engine.set_actor_id(actor);
    engine.set_max_write_ceiling(ceiling);
    // The REAL controller hook — the thing that owns the actor_memory write.
    engine.set_node_hook(Arc::new(talos_engine::node_hook::ControllerNodeHook::new(
        pool.clone(),
    )));

    engine
        .load_graph_from_json(&serde_json::to_string(&graph).unwrap())
        .await
        .expect("load graph");

    let ctx = engine
        .run_with_trigger_input_transport(
            Arc::new(EnvelopeDispatcher { output: envelope }),
            None,
            json!({}),
            Uuid::new_v4(),
        )
        .await
        .expect("run succeeds");

    // One module node + the synthetic `__trigger__`; return the module's.
    ctx.results
        .get(&module)
        .cloned()
        .expect("module node produced a result")
}

/// Poll for the row, because the hook persists on a `tokio::spawn`.
async fn count_memory_rows(pool: &sqlx::Pool<sqlx::Postgres>, actor: Uuid, key: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM actor_memory WHERE actor_id = $1 AND key = $2",
    )
    .bind(actor)
    .bind(key)
    .fetch_one(pool)
    .await
    .expect("count actor_memory")
}

async fn wait_for_memory_row(pool: &sqlx::Pool<sqlx::Postgres>, actor: Uuid, key: &str) -> i64 {
    for _ in 0..100 {
        let n = count_memory_rows(pool, actor, key).await;
        if n > 0 {
            return n;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    count_memory_rows(pool, actor, key).await
}

/// One test, three phases, ONE database — and the reason is worth stating
/// rather than leaving as an oddity. `talos_memory::register_memory_crypto_hook`
/// is a process-wide `OnceLock` (first registration wins), so three parallel
/// `#[tokio::test]`s on three isolated databases would all encrypt through
/// whichever pool registered first: the other two would write ciphertext keyed
/// by a DEK that does not exist in their own database, and their writes would
/// fail. Measured, not hypothesised — the first version of this file was three
/// tests and the CONTROL failed with `left: 0, right: 1` while the refusal test
/// "passed", which is the worst possible arrangement: the negative assertion
/// would have gone green for the wrong reason.
///
/// # Phase 1 — the regression (the live #750 shape)
///
/// On pristine `main` this FAILS at the row assertion: the write lands.
///
/// # Phase 2 — the control
///
/// Same graph, same hook, same enforcement, only the ceiling differs. Without
/// it, a "fix" that broke `__memory_write__` for EVERY actor would pass
/// phase 1.
///
/// # Phase 3 — the spoof guard
///
/// Engine-authored keys are never caller-authorable (check 77's rule, and
/// `build_judge_envelope`'s insert-or-REMOVE rule). A module that fabricates
/// its own refusal marker must not make a PERMITTED write look declined —
/// otherwise an operator auditing "which writes were refused" is reading
/// module data as engine data.
#[tokio::test]
async fn write_ceiling_gates_the_memory_write_envelope() {
    enforce_write_ceiling();
    let (pool, _db) = common::isolated_db_pool().await;
    register_crypto(&pool).await;

    // ── Phase 1: readonly actor, enforcement on → REFUSED ────────────────
    let ro_actor = seed_actor(&pool, "readonly").await;
    let ro_key = format!("probe750/{}", Uuid::new_v4());
    let refused_output = run_one_node(
        &pool,
        ro_actor,
        talos_workflow_engine_core::WriteCeiling::ReadOnly,
        json!({
            "__memory_write__": {
                "key": ro_key,
                "memory_type": "working",
                "value": {"note": "the module believes it wrote this"}
            },
            "written_key": ro_key,
        }),
    )
    .await;

    // Give the (absent) spawned write every chance to land before concluding
    // it did not — a sleep here makes the pre-fix failure deterministic rather
    // than a race we happened to win.
    tokio::time::sleep(std::time::Duration::from_millis(750)).await;
    assert_eq!(
        count_memory_rows(&pool, ro_actor, &ro_key).await,
        0,
        "phase 1: a readonly actor's __memory_write__ envelope must not reach actor_memory"
    );

    // "No row" is ALSO what a silent drop looks like, so the refusal must be
    // STATED. The module cannot know it was refused, and its own
    // `written_key` still claims success.
    let refused = refused_output
        .get("__memory_write_refused__")
        .expect("phase 1: the node output must record the refusal, not merely omit the write");
    assert_eq!(
        refused.get("reason").and_then(|v| v.as_str()),
        Some("write-ceiling"),
        "phase 1: refusal must carry the worker's policy token"
    );
    assert_eq!(
        refused.get("ceiling").and_then(|v| v.as_str()),
        Some("readonly")
    );
    // The envelope must be GONE, not merely flagged: leaving it in place keeps
    // a refused write one careless reader away from being honoured.
    assert!(
        refused_output.get("__memory_write__").is_none(),
        "phase 1: the refused envelope must be removed from the node output"
    );

    // ── Phase 2: write actor, enforcement on → PERSISTS ──────────────────
    let rw_actor = seed_actor(&pool, "write").await;
    let rw_key = format!("probe750-control/{}", Uuid::new_v4());
    let ok_output = run_one_node(
        &pool,
        rw_actor,
        talos_workflow_engine_core::WriteCeiling::Write,
        json!({
            // `scratchpad` is the one memory type the service does NOT embed,
            // so the permitted write needs no embedding provider in CI. The
            // ceiling gate is memory-type agnostic; this choice is about the
            // control's dependencies, not its subject.
            "__memory_write__": {
                "key": rw_key,
                "memory_type": "scratchpad",
                "value": {"note": "permitted"}
            }
        }),
    )
    .await;
    assert_eq!(
        wait_for_memory_row(&pool, rw_actor, &rw_key).await,
        1,
        "phase 2: a write-ceiling actor's __memory_write__ envelope must still persist"
    );
    assert!(
        ok_output.get("__memory_write_refused__").is_none(),
        "phase 2: a permitted write must not be annotated as refused"
    );
    assert!(
        ok_output.get("__memory_write__").is_some(),
        "phase 2: a permitted envelope must survive to the lifecycle hook"
    );

    // ── Phase 3: module-fabricated refusal marker is stripped ────────────
    let spoof_key = format!("probe750-spoof/{}", Uuid::new_v4());
    let spoof_output = run_one_node(
        &pool,
        rw_actor,
        talos_workflow_engine_core::WriteCeiling::Write,
        json!({
            "__memory_write__": {"key": spoof_key, "memory_type": "scratchpad", "value": 1},
            "__memory_write_refused__": {"key": "fabricated", "reason": "write-ceiling"}
        }),
    )
    .await;
    assert!(
        spoof_output.get("__memory_write_refused__").is_none(),
        "phase 3: a module-supplied __memory_write_refused__ must be stripped unconditionally"
    );
    assert_eq!(
        wait_for_memory_row(&pool, rw_actor, &spoof_key).await,
        1,
        "phase 3: the spoof attempt must not have blocked the real write"
    );
}
