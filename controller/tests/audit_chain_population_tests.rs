//! The audit-chain sweep must enumerate the id space the WRITER keys.
//!
//! # The defect
//!
//! The WORM ledger is keyed PER JOB. `worker/src/main.rs` builds the worker's
//! `execution_context` as `(req.workflow_execution_id, req.job_id,
//! req.module_uri)`; `runtime.rs` turns the first two into
//! `ExecutionLedger::new(workflow_id, execution_id)`; the audit consumer writes
//! `format!("{execution_id}/{min}_{max}_{nanos}.jsonl")`. And `job_id` IS
//! `module_executions.id` — `engine_dispatch_single.rs` mints it and passes it
//! as `ExecutionStartedContext { id: job_id, .. }`, the primary key of the row
//! it inserts.
//!
//! `run_chain_verification_sweep` enumerated `workflow_executions`. So every
//! prefix it named was one the writer never uses, and `verify_chain` over an
//! empty event set answers `ok == true` — there are no gaps, no broken links
//! and no bad signatures in nothing.
//!
//! Measured live 2026-09-06, both directions, on the dev stack:
//!
//! * 200 of 200 most-recent settled `module_executions` ids ARE ledger
//!   prefixes; 0 of 200 most-recent settled `workflow_executions` ids are.
//! * 200 of 200 newest ledger prefixes resolve to a `module_executions` row;
//!   0 resolve to a `workflow_executions` row.
//! * Driving the REAL `verify_execution_chain` against the live store with
//!   read-capable credentials: the pair
//!   `(module_executions.workflow_execution_id, module_executions.id)` returns
//!   `ok=true total_events=1 breaks=0 sigs_checked=true` (6 of 6 sampled);
//!   `(workflow_executions.workflow_id, module_executions.id)` — the binding a
//!   reader would GUESS from the field name `workflow_id` — returns
//!   `ok=false breaks=1`; and the pre-fix sweep's own shape returns
//!   `ok=true total_events=0`, the verified-nothing.
//!
//! # What these tests drive, and what they cannot
//!
//! `talos_audit_ledger::enumerate_sweep_jobs` and
//! `latest_verifiable_ledger_target` are the REAL statements the sweep and
//! `security_audit` issue — extracted, not paraphrased, for the reason
//! `updated_at_maintenance_tests` records: a hand-written statement in a test
//! can be green over the shape the writer actually issues, and the whole
//! defect here was a SELECT naming the wrong table.
//!
//! They CANNOT drive `run_chain_verification_sweep` end to end: that needs an
//! S3 endpoint, and this workspace has no S3 test harness (no localstack, no
//! mock, no bucket fixture). The verification half is covered by the
//! `talos-audit-ledger` unit tests and by the live probe recorded above; the
//! ENUMERATION half — which is what was wrong — is covered here.
//!
//! MAIN-VOCABULARY TWIN. Against `origin/main` @ 3fb8c921 the sweep's query is
//! `SELECT id, workflow_id FROM workflow_executions …`. Every test below seeds
//! a workflow execution AND its module executions, so on main the enumeration
//! returns the workflow-execution ids and each assertion below fails on the
//! id it gets back — not by compile error, because the twin is the same
//! statement text against the same seeded rows.
//!
//! These are DB tests on the `common` harness (a template clone of the
//! migrated DB per test), so they belong in CTRL_TESTS, not TC_TESTS
//! (sub-leg 64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_audit_ledger::{
    enumerate_sweep_jobs, latest_verifiable_ledger_target, LedgerTarget, LEDGER_KEY_SPACE,
};
use uuid::Uuid;

struct Tenant {
    user: Uuid,
    org: Uuid,
    workflow: Uuid,
    actor: Uuid,
    module: Uuid,
}

async fn seed_tenant(pool: &Pool<Postgres>) -> Tenant {
    let tag = Uuid::new_v4();
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@chain-population.test"))
    .execute(pool)
    .await
    .expect("seed user");

    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) \
         VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("chainorg-{tag}"))
    .bind(format!("chainorg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .expect("seed org");

    let workflow = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) \
         VALUES ($1, $2, $3, $4, 'test://none', '{}'::jsonb)",
    )
    .bind(workflow)
    .bind(user)
    .bind(org)
    .bind(format!("chainwf-{tag}"))
    .execute(pool)
    .await
    .expect("seed workflow");

    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("chainactor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .expect("seed actor");

    let module = Uuid::new_v4();
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(module)
        .bind(format!("chainmod-{module}"))
        .execute(pool)
        .await
        .expect("seed module");

    Tenant {
        user,
        org,
        workflow,
        actor,
        module,
    }
}

/// One terminal `workflow_executions` row, `age_secs` old.
async fn seed_workflow_execution(pool: &Pool<Postgres>, t: &Tenant, age_secs: i64) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, org_id, actor_id, status, started_at, completed_at) \
         VALUES ($1, $2, $3, $4, $5, 'completed', \
                 NOW() - (INTERVAL '1 second' * $6), NOW() - (INTERVAL '1 second' * $6))",
    )
    .bind(id)
    .bind(t.workflow)
    .bind(t.user)
    .bind(t.org)
    .bind(t.actor)
    .bind(age_secs)
    .execute(pool)
    .await
    .expect("seed workflow execution");
    id
}

/// One terminal `module_executions` row under `parent`, `age_secs` old.
/// `parent: None` seeds the NULL-`workflow_execution_id` shape — the column is
/// nullable, and a row without one has no genesis pair to verify.
async fn seed_module_execution(
    pool: &Pool<Postgres>,
    t: &Tenant,
    parent: Option<Uuid>,
    age_secs: i64,
) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_executions \
             (id, module_id, user_id, actor_id, org_id, status, trigger_type, \
              workflow_execution_id, started_at, completed_at) \
         VALUES ($1, $2, $3, $4, $5, 'completed', 'manual', $6, \
                 NOW() - (INTERVAL '1 second' * $7), NOW() - (INTERVAL '1 second' * $7))",
    )
    .bind(id)
    .bind(t.module)
    .bind(t.user)
    .bind(t.actor)
    .bind(t.org)
    .bind(parent)
    .bind(age_secs)
    .execute(pool)
    .await
    .expect("seed module execution");
    id
}

// ── enumerate_sweep_jobs ────────────────────────────────────────────────────

/// **THE BUG.** The sweep must return MODULE-execution ids, and it must return
/// them PAIRED with the workflow execution the ledger's genesis hash is bound
/// to.
///
/// MAIN-VOCABULARY TWIN: `SELECT id, workflow_id FROM workflow_executions …`
/// against these same rows returns `[(wf_exec, workflow)]` — one row, the
/// wrong id, and the `contains(&me)` assertions below fail on it.
#[tokio::test]
async fn the_sweep_enumerates_module_executions_not_workflow_executions() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let wf_exec = seed_workflow_execution(&pool, &t, 600).await;
    let me_a = seed_module_execution(&pool, &t, Some(wf_exec), 600).await;
    let me_b = seed_module_execution(&pool, &t, Some(wf_exec), 601).await;

    let rows = enumerate_sweep_jobs(&pool, 7200, 120, 500)
        .await
        .expect("enumeration must not fail");
    let ids: Vec<Uuid> = rows.iter().map(|(id, _)| *id).collect();

    assert!(
        ids.contains(&me_a) && ids.contains(&me_b),
        "the sweep must name both module executions ({LEDGER_KEY_SPACE}); got {ids:?}"
    );
    assert!(
        !ids.contains(&wf_exec),
        "the sweep must NOT name the workflow execution — the writer never uses it as a \
         prefix, and verify_chain answers an empty prefix ok=true"
    );

    // And the PAIR: each row must carry the workflow execution the genesis
    // hash is bound to. A sweep that got the prefix right and the genesis half
    // wrong reports a break on every healthy chain — measured live at
    // ok=false, breaks=1.
    for (id, parent) in &rows {
        if *id == me_a || *id == me_b {
            assert_eq!(
                *parent,
                Some(wf_exec),
                "the genesis half must be module_executions.workflow_execution_id"
            );
        }
    }
}

/// Two jobs under ONE workflow execution are TWO chains. The grain is not a
/// detail: a workflow execution with four module dispatches has four separate
/// hash chains in the bucket, and verifying one says nothing about the others.
#[tokio::test]
async fn every_job_is_its_own_chain() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let wf_exec = seed_workflow_execution(&pool, &t, 600).await;
    let mut seeded = Vec::new();
    for i in 0..4 {
        seeded.push(seed_module_execution(&pool, &t, Some(wf_exec), 600 + i).await);
    }

    let rows = enumerate_sweep_jobs(&pool, 7200, 120, 500)
        .await
        .expect("enumeration");
    let ids: Vec<Uuid> = rows.iter().map(|(id, _)| *id).collect();
    for id in &seeded {
        assert!(ids.contains(id), "job {id} was not enumerated");
    }
    assert_eq!(
        rows.len(),
        4,
        "four dispatches under one run are four chains, not one"
    );
}

/// The settle floor and the lookback window still bound the population — the
/// predicate moved tables, it did not lose its guards.
///
/// A just-finished job's audit batch may still be in flight to the object
/// store, so verifying it would report a false sequence gap; a job older than
/// the lookback belongs to an earlier pass.
#[tokio::test]
async fn the_settle_floor_and_lookback_window_still_bound_the_population() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let wf_exec = seed_workflow_execution(&pool, &t, 600).await;

    let too_fresh = seed_module_execution(&pool, &t, Some(wf_exec), 10).await;
    let in_window = seed_module_execution(&pool, &t, Some(wf_exec), 600).await;
    let too_old = seed_module_execution(&pool, &t, Some(wf_exec), 20_000).await;

    let ids: Vec<Uuid> = enumerate_sweep_jobs(&pool, 7200, 120, 500)
        .await
        .expect("enumeration")
        .into_iter()
        .map(|(id, _)| id)
        .collect();

    assert!(ids.contains(&in_window));
    assert!(
        !ids.contains(&too_fresh),
        "a job inside the settle window would report a false sequence gap"
    );
    assert!(
        !ids.contains(&too_old),
        "a job older than the lookback belongs to an earlier pass"
    );
}

/// A job with NO workflow execution comes BACK from the query with its NULL
/// intact — it is a STANDALONE dispatch (module-bound webhook / push), which
/// the sweep verifies under the `(job_id, job_id)` genesis its builder signed
/// with and discloses as `ChainSweepStats::standalone` (2026-09-11).
///
/// "0 of 48,577 rows carry a NULL there" (measured 2026-09-06) was an
/// artefact: the chain runner re-parented every such row onto the chain it
/// fired, which is what broke those rows' verification in the first place.
#[tokio::test]
async fn a_job_with_no_workflow_execution_is_returned_for_counting() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let orphan = seed_module_execution(&pool, &t, None, 600).await;

    let rows = enumerate_sweep_jobs(&pool, 7200, 120, 500)
        .await
        .expect("enumeration");
    let found = rows
        .iter()
        .find(|(id, _)| *id == orphan)
        .expect("an unbound job must still be returned, so the sweep can COUNT it");
    assert_eq!(
        found.1, None,
        "and it must arrive with a NULL genesis half, not a fabricated one"
    );
}

/// Non-terminal jobs are out of scope: a running dispatch has not written its
/// terminal anchor event, so its chain is legitimately incomplete.
#[tokio::test]
async fn only_terminal_jobs_are_enumerated() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let wf_exec = seed_workflow_execution(&pool, &t, 600).await;
    let running = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO module_executions \
             (id, module_id, user_id, actor_id, org_id, status, trigger_type, \
              workflow_execution_id, started_at, completed_at) \
         VALUES ($1, $2, $3, $4, $5, 'running', 'manual', $6, \
                 NOW() - INTERVAL '600 seconds', NOW() - INTERVAL '600 seconds')",
    )
    .bind(running)
    .bind(t.module)
    .bind(t.user)
    .bind(t.actor)
    .bind(t.org)
    .bind(wf_exec)
    .execute(&pool)
    .await
    .expect("seed running module execution");

    let ids: Vec<Uuid> = enumerate_sweep_jobs(&pool, 7200, 120, 500)
        .await
        .expect("enumeration")
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert!(!ids.contains(&running));
}

// ── latest_verifiable_ledger_target ─────────────────────────────────────────

/// `security_audit`'s round-trip check must pick a MODULE execution too, and
/// resolve the same pair — otherwise the check grades a population the
/// standing sweep never looks at, which is the thing `CHAIN_SETTLE_SECS`
/// having one home was supposed to prevent.
///
/// MAIN-VOCABULARY TWIN: `latest_verifiable_execution` returns
/// `(workflow_executions.id, workflow_executions.workflow_id)` — the assertion
/// below fails on both halves.
#[tokio::test]
async fn the_security_audit_candidate_is_a_module_execution() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let wf_exec = seed_workflow_execution(&pool, &t, 600).await;
    let newest = seed_module_execution(&pool, &t, Some(wf_exec), 300).await;
    let _older = seed_module_execution(&pool, &t, Some(wf_exec), 900).await;

    let target = latest_verifiable_ledger_target(&pool, 120)
        .await
        .expect("query must not fail")
        .expect("a settled module execution is eligible");

    assert_eq!(
        target,
        LedgerTarget {
            module_execution_id: newest,
            workflow_execution_id: Some(wf_exec),
        },
        "the candidate must be the newest settled MODULE execution, paired with its run"
    );
    // The two accessors must not be swapped: `execution_id` is the S3 prefix.
    assert_eq!(target.execution_id(), newest.to_string());
    assert_eq!(target.genesis_workflow_id(), wf_exec.to_string());
    assert_ne!(
        target.genesis_workflow_id(),
        t.workflow.to_string(),
        "the genesis half is the WORKFLOW EXECUTION, not workflows.id — the live probe \
         measured the latter as ok=false, breaks=1"
    );
}

/// A candidate that does not exist is `Ok(None)` — a quiet deployment. The
/// three-valued contract (`Ok(Some)` / `Ok(None)` / `Err`) is what stops a
/// database blip rendering as "there is nothing to verify".
#[tokio::test]
async fn no_eligible_job_is_ok_none_not_an_error() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let wf_exec = seed_workflow_execution(&pool, &t, 600).await;
    // Inside the settle window only.
    seed_module_execution(&pool, &t, Some(wf_exec), 10).await;

    let target = latest_verifiable_ledger_target(&pool, 120)
        .await
        .expect("a quiet deployment is not an error");
    assert!(target.is_none());
}

/// A job with no workflow execution cannot be a CANDIDATE — the check would
/// carries its own id as the genesis half — the standalone contract every
/// module-bound builder signs with — so it IS a candidate, under `(job, job)`,
/// and the target says so rather than fabricating a run id. Until 2026-09-11
/// the probe excluded these rows as "unbindable".
#[tokio::test]
async fn a_standalone_job_is_offered_under_its_own_genesis() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    let standalone = seed_module_execution(&pool, &t, None, 600).await;

    let target = latest_verifiable_ledger_target(&pool, 120)
        .await
        .expect("query")
        .expect("a settled standalone job is a verifiable candidate");
    assert_eq!(target.module_execution_id, standalone);
    assert_eq!(
        target.workflow_execution_id, None,
        "no run id is fabricated"
    );
    assert!(target.is_standalone());
    assert_eq!(
        target.genesis_workflow_id(),
        standalone.to_string(),
        "verified under (job_id, job_id), exactly as the worker sealed it"
    );
}
