//! Two controller replicas relaying `wasm.log.*`, on a live broker.
//!
//! Drives the PRODUCTION `talos_wasm_log_relay::spawn_wasm_log_relay` twice —
//! two NATS connections, two broadcast channels, and TWO databases holding
//! the same execution ids, so which replica stored a line is observable.
//!
//! ONE test function on purpose: the relay binds the fixed production
//! subject `wasm.log.*` in a broker-wide queue group, so two tests running in
//! parallel in this binary would take each other's lines.
mod common;

use futures::StreamExt;
use std::sync::Arc;
use std::time::Duration;
use talos_engine_events::ExecutionEvent;
use talos_module_executions::ModuleExecutionService;
use uuid::Uuid;

const LINES: usize = 50;

struct Replica {
    pool: sqlx::Pool<sqlx::Postgres>,
    rx: tokio::sync::broadcast::Receiver<ExecutionEvent>,
    _db: common::TestDb,
}

struct Ids {
    user: Uuid,
    actor: Uuid,
    module: Uuid,
    workflow: Uuid,
    wf_exec: Uuid,
    mod_exec: Uuid,
}

/// The same rows, by the same ids, in each replica's database.
async fn seed(pool: &sqlx::Pool<sqlx::Postgres>, ids: &Ids) {
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(ids.user)
    .bind(format!("{}@wasm-log-relay.test", ids.user))
    .execute(pool)
    .await
    .expect("user");
    sqlx::query("INSERT INTO actors (id, user_id, name) VALUES ($1, $2, $3)")
        .bind(ids.actor)
        .bind(ids.user)
        .bind(format!("actor-{}", ids.actor))
        .execute(pool)
        .await
        .expect("actor");
    sqlx::query("INSERT INTO modules (id, name, kind) VALUES ($1, $2, 'sandbox')")
        .bind(ids.module)
        .bind(format!("m-{}", ids.module))
        .execute(pool)
        .await
        .expect("module");
    sqlx::query(
        "INSERT INTO workflows (id, name, user_id, module_uri, graph_json) \
         VALUES ($1, $2, $3, 'm', '{}'::jsonb)",
    )
    .bind(ids.workflow)
    .bind(format!("wf-{}", ids.workflow))
    .bind(ids.user)
    .execute(pool)
    .await
    .expect("workflow");
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, status, actor_id) \
         VALUES ($1, $2, $3, 'running', $4)",
    )
    .bind(ids.wf_exec)
    .bind(ids.workflow)
    .bind(ids.user)
    .bind(ids.actor)
    .execute(pool)
    .await
    .expect("workflow execution");
    sqlx::query(
        "INSERT INTO module_executions (id, module_id, user_id, actor_id, status, trigger_type) \
         VALUES ($1, $2, $3, $4, 'running', 'webhook')",
    )
    .bind(ids.mod_exec)
    .bind(ids.module)
    .bind(ids.user)
    .bind(ids.actor)
    .execute(pool)
    .await
    .expect("module execution");
}

async fn start_replica(url: &str, ids: &Ids) -> Replica {
    let (pool, db) = common::isolated_db_pool().await;
    seed(&pool, ids).await;
    let nats = Arc::new(async_nats::connect(url).await.expect("connect"));
    let (tx, rx) = tokio::sync::broadcast::channel(1024);
    talos_wasm_log_relay::spawn_wasm_log_relay(
        nats,
        Arc::new(talos_execution_repository::ExecutionRepository::new(
            pool.clone(),
        )),
        Arc::new(ModuleExecutionService::new(
            pool.clone(),
            Arc::new(talos_dlp_provider::DlpService::from_env()),
        )),
        tx,
    );
    Replica { pool, rx, _db: db }
}

/// Both replicas' row counts, once the fleet total reaches `expected` or the
/// deadline passes.
///
/// The broadcast channel and the persist subscription are DIFFERENT NATS
/// subscriptions on different tasks, so `drain` going quiet says nothing about
/// whether the INSERTs have landed — waiting on one and asserting on the other
/// is a race, and it is the race that failed this test on a loaded CI runner
/// (16 of 50 rows, 8 per replica, with every broadcast already delivered).
/// The orphan-counter assertion below this already polls for exactly this
/// reason; the row assertions did not.
///
/// This changes no assertion: a relay that genuinely drops or duplicates a
/// line still fails, with the same message, after the deadline.
async fn rows_until(
    a: &sqlx::Pool<sqlx::Postgres>,
    b: &sqlx::Pool<sqlx::Postgres>,
    table: &str,
    exec: Uuid,
    like: &str,
    expected: i64,
) -> (i64, i64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let (ra, rb) = (
            rows(a, table, exec, like).await,
            rows(b, table, exec, like).await,
        );
        if ra + rb >= expected || tokio::time::Instant::now() >= deadline {
            return (ra, rb);
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

async fn rows(pool: &sqlx::Pool<sqlx::Postgres>, table: &str, exec: Uuid, like: &str) -> i64 {
    // `table` is one of two literals below, never input.
    sqlx::query_scalar(&format!(
        "SELECT count(*) FROM {table} WHERE execution_id = $1 AND message LIKE $2"
    ))
    .bind(exec)
    .bind(like)
    .fetch_one(pool)
    .await
    .expect("count")
}

async fn publish(nats: &async_nats::Client, exec: Uuid, message: &str) {
    let body = serde_json::json!({"execution_id": exec, "level": "INFO", "message": message});
    nats.publish(format!("wasm.log.{exec}"), body.to_string().into())
        .await
        .expect("publish");
}

/// Drain `rx` until it has been quiet for 400 ms; count events whose text
/// contains `needle`.
async fn drain(rx: &mut tokio::sync::broadcast::Receiver<ExecutionEvent>, needle: &str) -> usize {
    let mut n = 0;
    while let Ok(Ok(ev)) = tokio::time::timeout(Duration::from_millis(400), rx.recv()).await {
        if ev
            .log_message
            .as_deref()
            .is_some_and(|m| m.contains(needle))
        {
            n += 1;
        }
    }
    n
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_replicas_store_each_line_once_and_both_broadcast_it() {
    let Ok(url) = std::env::var("TALOS_TEST_NATS_URL") else {
        eprintln!("SKIP: TALOS_TEST_NATS_URL unset");
        return;
    };
    let ids = Ids {
        user: Uuid::new_v4(),
        actor: Uuid::new_v4(),
        module: Uuid::new_v4(),
        workflow: Uuid::new_v4(),
        wf_exec: Uuid::new_v4(),
        mod_exec: Uuid::new_v4(),
    };
    let publisher = async_nats::connect(&url).await.expect("publisher");

    // ── CONTROL: on this broker, two PLAIN subscribers each persisting
    // through the production per-message function store every line twice. So
    // "once" below is the queue group's doing, not the rig's.
    {
        let (pool, _db) = common::isolated_db_pool().await;
        seed(&pool, &ids).await;
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let conn = async_nats::connect(&url).await.expect("connect");
            let mut sub = conn
                .subscribe(format!("wasm.log.{}", ids.wf_exec))
                .await
                .expect("sub");
            // Same-connection round trip: the SUB is live before we publish.
            let inbox = conn.new_inbox();
            let mut echo = conn.subscribe(inbox.clone()).await.expect("echo sub");
            conn.publish(inbox, "x".into()).await.expect("echo pub");
            echo.next().await.expect("echo");
            let repo = talos_execution_repository::ExecutionRepository::new(pool.clone());
            let service = ModuleExecutionService::new(
                pool.clone(),
                Arc::new(talos_dlp_provider::DlpService::from_env()),
            );
            tasks.push(tokio::spawn(async move {
                let _keep = conn;
                for _ in 0..10 {
                    let msg = sub.next().await.expect("control message");
                    talos_wasm_log_relay::persist_log_message(&msg, &repo, &service).await;
                }
            }));
        }
        for i in 0..10 {
            publish(&publisher, ids.wf_exec, &format!("control {i}")).await;
        }
        for t in tasks {
            tokio::time::timeout(Duration::from_secs(20), t)
                .await
                .expect("control relay finished")
                .expect("join");
        }
        assert_eq!(
            rows(&pool, "workflow_execution_logs", ids.wf_exec, "control %").await,
            20,
            "two plain subscribers must double the rows, or the rig proves nothing"
        );
    }

    // ── Two production relays.
    let mut a = start_replica(&url, &ids).await;
    let mut b = start_replica(&url, &ids).await;

    // Ready = each replica has STORED a warm-up line (its queue-group SUB is
    // live) and BROADCAST one (its plain SUB is live). The relay subscribes
    // inside spawned tasks, so only an effect proves a SUB landed.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let (mut a_heard, mut b_heard) = (false, false);
    loop {
        publish(&publisher, ids.wf_exec, "warmup").await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        a_heard |= drain_nonblocking(&mut a.rx);
        b_heard |= drain_nonblocking(&mut b.rx);
        let a_rows = rows(&a.pool, "workflow_execution_logs", ids.wf_exec, "warmup").await;
        let b_rows = rows(&b.pool, "workflow_execution_logs", ids.wf_exec, "warmup").await;
        if a_heard && b_heard && a_rows > 0 && b_rows > 0 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "relays never became ready (heard a={a_heard} b={b_heard}, rows a={a_rows} b={b_rows})"
        );
    }
    drain(&mut a.rx, "warmup").await;
    drain(&mut b.rx, "warmup").await;

    // ── Workflow-execution lines.
    for i in 0..LINES {
        publish(&publisher, ids.wf_exec, &format!("line {i}")).await;
    }
    // ── Standalone module-execution lines (the `module_execution_logs` route).
    for i in 0..LINES {
        publish(&publisher, ids.mod_exec, &format!("modline {i}")).await;
    }
    // ── Lines for an execution NO table knows: discarded, and counted ONCE
    // per line for the fleet — the persist half owns the orphan counter, so
    // two replicas must not report one lost line twice.
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
    let orphans = || {
        talos_metrics::global()
            .expect("metrics")
            .wasm_log_orphaned_total
            .with_label_values(&[talos_wasm_log_relay::WASM_LOG_ORPHAN_NO_EXECUTION_ROW])
            .get()
    };
    let orphans_before = orphans();
    let nobody = Uuid::new_v4();
    for i in 0..5 {
        publish(&publisher, nobody, &format!("orphan {i}")).await;
    }
    let a_lines = drain(&mut a.rx, "] line ").await;
    let b_lines = drain(&mut b.rx, "] line ").await;
    // `drain` already waited out 400 ms of quiet on each channel.

    let (wf_a, wf_b) = rows_until(
        &a.pool,
        &b.pool,
        "workflow_execution_logs",
        ids.wf_exec,
        "line %",
        LINES as i64,
    )
    .await;
    assert_eq!(
        wf_a + wf_b,
        LINES as i64,
        "each workflow log line is stored by exactly one replica (a={wf_a}, b={wf_b}); \
         broadcasts delivered a={a_lines} b={b_lines} of {LINES} — if the broadcasts are \
         COMPLETE the persist INSERTs merely lagged past the wait, and if they are SHORT \
         the broker dropped messages to a slow consumer, which is a different defect"
    );
    assert!(
        wf_a > 0 && wf_b > 0,
        "both replicas are members (a={wf_a}, b={wf_b})"
    );

    let (mod_a, mod_b) = rows_until(
        &a.pool,
        &b.pool,
        "module_execution_logs",
        ids.mod_exec,
        "modline %",
        LINES as i64,
    )
    .await;
    assert_eq!(
        mod_a + mod_b,
        LINES as i64,
        "each module log line is stored by exactly one replica (a={mod_a}, b={mod_b})"
    );

    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while orphans() - orphans_before < 5.0 && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await; // a second copy would land now
    assert_eq!(
        orphans() - orphans_before,
        5.0,
        "a line that lands nowhere is counted once, not once per replica"
    );

    // Every replica's live channel carried every line, exactly once.
    assert_eq!(
        a_lines, LINES,
        "replica a's subscribers missed or repeated lines"
    );
    assert_eq!(
        b_lines, LINES,
        "replica b's subscribers missed or repeated lines"
    );
}

/// True if anything was waiting on `rx`.
fn drain_nonblocking(rx: &mut tokio::sync::broadcast::Receiver<ExecutionEvent>) -> bool {
    let mut any = false;
    while rx.try_recv().is_ok() {
        any = true;
    }
    any
}
