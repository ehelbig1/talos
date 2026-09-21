//! Two controller replicas observing `talos.results.*`, on a live broker.
//!
//! Drives the PRODUCTION `talos_job_result_observer::spawn_job_result_observer`
//! twice — two NATS connections and TWO databases holding the same
//! module-execution ids, so which replica handled a result is observable.
//!
//! ONE test function on purpose: the observer binds the fixed production
//! subject in a broker-wide queue group, and the unparseable-result counter
//! is a process global.
mod common;

use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use talos_job_result_observer::{handle_result_message, ObservedResult};
use talos_module_executions::ModuleExecutionService;
use talos_workflow_engine_core::{WorkerKeyRing, WorkerSharedKey};
use talos_workflow_job_protocol::{JobResult, JobStatus};
use uuid::Uuid;

const KEY: &[u8] = b"job-result-observer-test-key-0123456789abcdef";
/// A failure text the shared classifier has a bucket for, so "derived" below
/// is distinguishable from "stored nothing".
const FAILURE_TEXT: &str = "Out of fuel: the module exhausted its fuel budget";
const WARMUPS: usize = 60;
const RESULTS: usize = 50;

fn ring() -> WorkerKeyRing {
    WorkerKeyRing::new(WorkerSharedKey::new(KEY.to_vec()), [])
}

fn signed(job_id: Uuid, status: JobStatus, key: &[u8]) -> Vec<u8> {
    let mut r = JobResult {
        job_id,
        status,
        output_payload: serde_json::json!({"ok": true, "error": FAILURE_TEXT}).into(),
        logs: vec![],
        execution_time_ms: 7,
        signature: vec![],
        result_nonce: String::new(),
        worker_id: String::new(),
        crypto_scheme: 0,
        llm_usage: vec![],
    };
    r.sign_with_worker_id(key, "worker-test").expect("sign");
    serde_json::to_vec(&r).expect("serialize")
}

struct Seed {
    user: Uuid,
    actor: Uuid,
    module: Uuid,
    execs: Vec<Uuid>,
}

/// The same rows, by the same ids, in each replica's database.
async fn seed(pool: &sqlx::Pool<sqlx::Postgres>, s: &Seed) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(s.user)
    .bind(format!("{}@job-result-observer.test", s.user))
    .execute(pool)
    .await
    .expect("user");
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(s.actor)
        .bind(s.user)
        .bind(format!("actor-{}", s.actor))
        .execute(pool)
        .await
        .expect("actor");
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(s.module)
        .bind(format!("m-{}", s.module))
        .execute(pool)
        .await
        .expect("module");
    sqlx::query(
        "INSERT INTO module_executions (id, module_id, user_id, actor_id, status, trigger_type) \
         SELECT e, $2, $3, $4, 'running', 'webhook' FROM unnest($1::uuid[]) AS e",
    )
    .bind(&s.execs)
    .bind(s.module)
    .bind(s.user)
    .bind(s.actor)
    .execute(pool)
    .await
    .expect("module executions");
}

async fn with_status(pool: &sqlx::Pool<sqlx::Postgres>, ids: &[Uuid], status: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM module_executions WHERE id = ANY($1) AND status = $2")
        .bind(ids)
        .bind(status)
        .fetch_one(pool)
        .await
        .expect("count")
}

fn service(pool: &sqlx::Pool<sqlx::Postgres>) -> Arc<ModuleExecutionService> {
    Arc::new(ModuleExecutionService::new(
        pool.clone(),
        Arc::new(talos_dlp_provider::DlpService::from_env()),
    ))
}

/// Poll until `probe` holds or 10 s pass.
async fn eventually<F, Fut>(what: &str, mut probe: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    for _ in 0..200 {
        if probe().await {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("timed out waiting for: {what}");
}

#[tokio::test(flavor = "multi_thread")]
async fn one_replica_handles_each_worker_result() {
    let Ok(url) = std::env::var("TALOS_TEST_NATS_URL") else {
        eprintln!("SKIP: TALOS_TEST_NATS_URL unset");
        return;
    };
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
    let unparseable = || {
        talos_metrics::global()
            .expect("metrics")
            .job_results_dropped_unparseable_total
            .get()
    };
    let publisher = async_nats::connect(&url).await.expect("publisher");
    let ids = |n: usize| (0..n).map(|_| Uuid::new_v4()).collect::<Vec<_>>();
    let (warm, ok, failed, forged, ctl) = (ids(WARMUPS), ids(RESULTS), ids(10), ids(5), ids(10));
    let s = Seed {
        user: Uuid::new_v4(),
        actor: Uuid::new_v4(),
        module: Uuid::new_v4(),
        execs: [&warm[..], &ok, &failed, &forged, &ctl].concat(),
    };

    // ── CONTROL: on this broker, two PLAIN subscribers each driving the
    // production per-message handler BOTH handle every result. So "one
    // replica" below is the queue group's doing, not the rig's.
    {
        let mut pools = Vec::new();
        let mut tasks = Vec::new();
        let mut dbs = Vec::new();
        for _ in 0..2 {
            let (pool, db) = common::isolated_db_pool().await;
            seed(&pool, &s).await;
            let conn = async_nats::connect(&url).await.expect("connect");
            let mut sub = conn.subscribe("ctl.results.*").await.expect("sub");
            // Same-connection round trip: the SUB is live before we publish.
            let inbox = conn.new_inbox();
            let mut echo = conn.subscribe(inbox.clone()).await.expect("echo sub");
            conn.publish(inbox, "x".into()).await.expect("echo pub");
            echo.next().await.expect("echo");
            let svc = service(&pool);
            tasks.push(tokio::spawn(async move {
                let _conn = conn;
                let ring = ring();
                while let Some(msg) = sub.next().await {
                    let _ = handle_result_message(&msg.payload, &svc, Some(&ring)).await;
                }
            }));
            pools.push(pool);
            dbs.push(db);
        }
        for id in &ctl {
            publisher
                .publish(
                    format!("ctl.results.{id}"),
                    signed(*id, JobStatus::Success, KEY).into(),
                )
                .await
                .expect("publish");
        }
        let (a, b) = (pools[0].clone(), pools[1].clone());
        let ctl_ids = ctl.clone();
        eventually("both plain subscribers to handle all ten", || {
            let (a, b, ids) = (a.clone(), b.clone(), ctl_ids.clone());
            async move {
                with_status(&a, &ids, "completed").await + with_status(&b, &ids, "completed").await
                    == 20
            }
        })
        .await;
        for t in tasks {
            t.abort();
        }
    }

    // ── Two production observers.
    let mut pools = Vec::new();
    let mut dbs = Vec::new();
    for _ in 0..2 {
        let (pool, db) = common::isolated_db_pool().await;
        seed(&pool, &s).await;
        talos_job_result_observer::spawn_job_result_observer(
            Arc::new(async_nats::connect(&url).await.expect("connect")),
            service(&pool),
            Some(ring()),
        );
        pools.push(pool);
        dbs.push(db);
    }
    let (a, b) = (pools[0].clone(), pools[1].clone());

    // Readiness is per replica: the observer subscribes inside its spawned
    // task, so feed warm-ups until EACH replica has handled one.
    let mut both = false;
    for id in &warm {
        publisher
            .publish(
                format!("talos.results.{id}"),
                signed(*id, JobStatus::Success, KEY).into(),
            )
            .await
            .expect("publish");
        tokio::time::sleep(Duration::from_millis(60)).await;
        if with_status(&a, &warm, "completed").await > 0
            && with_status(&b, &warm, "completed").await > 0
        {
            both = true;
            break;
        }
    }
    assert!(both, "both replicas must be serving before the measurement");

    // ── Success results: each handled by exactly one replica.
    for id in &ok {
        publisher
            .publish(
                format!("talos.results.{id}"),
                signed(*id, JobStatus::Success, KEY).into(),
            )
            .await
            .expect("publish");
    }
    // ── Failed results.
    for id in &failed {
        publisher
            .publish(
                format!("talos.results.{id}"),
                signed(*id, JobStatus::Failed, KEY).into(),
            )
            .await
            .expect("publish");
    }
    // ── Forged (signed under another key) and unparseable.
    for id in &forged {
        publisher
            .publish(
                format!("talos.results.{id}"),
                signed(
                    *id,
                    JobStatus::Success,
                    b"some-other-key-some-other-key-0000",
                )
                .into(),
            )
            .await
            .expect("publish");
    }
    let unparseable_before = unparseable();
    for i in 0..5 {
        publisher
            .publish(format!("talos.results.junk{i}"), "not json".into())
            .await
            .expect("publish");
    }

    {
        let (a, b, ok, failed) = (a.clone(), b.clone(), ok.clone(), failed.clone());
        eventually("every result to be handled somewhere", move || {
            let (a, b, ok, failed) = (a.clone(), b.clone(), ok.clone(), failed.clone());
            async move {
                with_status(&a, &ok, "completed").await + with_status(&b, &ok, "completed").await
                    >= RESULTS as i64
                    && with_status(&a, &failed, "failed").await
                        + with_status(&b, &failed, "failed").await
                        >= 10
                    && unparseable() - unparseable_before >= 5.0
            }
        })
        .await;
    }
    // Let a would-be second delivery land before counting.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let (oa, ob) = (
        with_status(&a, &ok, "completed").await,
        with_status(&b, &ok, "completed").await,
    );
    assert_eq!(
        oa + ob,
        RESULTS as i64,
        "each success result must be handled by exactly one replica (a={oa}, b={ob})"
    );
    assert!(
        oa > 0 && ob > 0,
        "both replicas must serve (a={oa}, b={ob})"
    );
    assert_eq!(
        with_status(&a, &failed, "failed").await + with_status(&b, &failed, "failed").await,
        10,
        "each failed result must be handled by exactly one replica"
    );
    assert_eq!(
        unparseable() - unparseable_before,
        5.0,
        "an unparseable result must be counted once for the fleet, not once per replica"
    );
    for pool in [&a, &b] {
        assert_eq!(
            with_status(pool, &forged, "running").await,
            5,
            "a result signed under another key must change nothing"
        );
    }

    // The handler's own verdicts, on rows nothing else has touched.
    let svc = service(&a);
    let fresh = forged[0];
    assert_eq!(
        handle_result_message(
            &signed(fresh, JobStatus::Success, b"wrong"),
            &svc,
            Some(&ring())
        )
        .await,
        ObservedResult::Unverified
    );
    assert_eq!(
        handle_result_message(b"{", &svc, Some(&ring())).await,
        ObservedResult::Unparseable
    );
    assert_eq!(
        handle_result_message(
            &signed(fresh, JobStatus::TimedOut, KEY),
            &svc,
            Some(&ring())
        )
        .await,
        ObservedResult::Failed
    );
    // The CAUSE the observer stores: a TimedOut status is the timeout bucket
    // (the classifier's own spelling), and a plain Failed derives its cause
    // from the same text it stores.
    let error_type = |pool: sqlx::Pool<sqlx::Postgres>, id: Uuid| async move {
        sqlx::query_scalar::<_, Option<String>>(
            "SELECT error_type FROM module_executions WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&pool)
        .await
        .expect("error_type")
    };
    assert_eq!(
        error_type(a.clone(), fresh).await.as_deref(),
        Some(talos_engine::module_error_type::TIMEOUT_BUCKET)
    );
    let derived = talos_engine::module_error_type::derive_error_type("failed", Some(FAILURE_TEXT));
    assert!(
        derived.is_some() && derived != Some(talos_engine::module_error_type::TIMEOUT_BUCKET),
        "the fixture text must classify, and not as a timeout: {derived:?}"
    );
    let failed_pool = if with_status(&a, &failed[..1], "failed").await == 1 {
        a.clone()
    } else {
        b.clone()
    };
    assert_eq!(
        error_type(failed_pool, failed[0]).await.as_deref(),
        derived,
        "a plain Failed result must store the cause the classifier derives from its text"
    );
    assert_eq!(
        handle_result_message(
            &signed(forged[1], JobStatus::Success, KEY),
            &svc,
            Some(&ring())
        )
        .await,
        ObservedResult::Completed
    );
    // A writer that cannot reach its database is reported, not swallowed.
    let (dead_pool, _dead_db) = common::isolated_db_pool().await;
    let dead = service(&dead_pool);
    dead_pool.close().await;
    assert_eq!(
        handle_result_message(
            &signed(forged[2], JobStatus::Success, KEY),
            &dead,
            Some(&ring())
        )
        .await,
        ObservedResult::WriteFailed
    );
    assert_eq!(
        handle_result_message(
            &signed(forged[2], JobStatus::Failed, KEY),
            &dead,
            Some(&ring())
        )
        .await,
        ObservedResult::WriteFailed
    );
    drop(dbs);
}
