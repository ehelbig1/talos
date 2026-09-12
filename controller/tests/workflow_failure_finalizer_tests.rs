//! The workflow-failure finalizer has ONE home. Measured on the #828 deploy
//! (2026-09-12): two `failed` workflow rows since boot and
//! `talos_workflow_executions_total{status="failure"}` at 0 — the scheduler's
//! failure path was one of EIGHT raw `UPDATE … SET status = 'failed'` sites
//! outside the two counted repositories. This binary drives the home and the
//! actor repository's delegating methods against real rows, reading the
//! counters the alerts read. One test function, because the metrics registry
//! is a process global (`execution_metrics_tests`' shape).
//!
//! `common` harness (a template clone per test), so CTRL_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_actor_repository::ActorRepository;
use uuid::Uuid;

struct Seeded {
    user: Uuid,
    workflow: Uuid,
    actor: Uuid,
}

async fn seed_tenant(pool: &Pool<Postgres>) -> Seeded {
    let user = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, is_active) VALUES ($1, $2, 'x', true)",
    )
    .bind(user)
    .bind(format!("{user}@wf-fail.test"))
    .execute(pool)
    .await
    .unwrap();
    let tag = Uuid::new_v4();
    let org: Uuid = sqlx::query_scalar(
        "INSERT INTO organizations (name, slug, owner_id, is_personal) VALUES ($1, $2, $3, true) RETURNING id",
    )
    .bind(format!("wforg-{tag}"))
    .bind(format!("wforg-{tag}"))
    .bind(user)
    .fetch_one(pool)
    .await
    .unwrap();
    let workflow = Uuid::new_v4();
    sqlx::query("INSERT INTO workflows (id, user_id, org_id, name, module_uri, graph_json) VALUES ($1, $2, $3, $4, 'test://none', '{}'::jsonb)")
        .bind(workflow)
        .bind(user)
        .bind(org)
        .bind(format!("wf-{tag}"))
        .execute(pool)
        .await
        .unwrap();
    let actor = Uuid::new_v4();
    sqlx::query("INSERT INTO actors (id, user_id, name, org_id) VALUES ($1, $2, $3, $4)")
        .bind(actor)
        .bind(user)
        .bind(format!("wfactor-{tag}"))
        .bind(org)
        .execute(pool)
        .await
        .unwrap();
    Seeded {
        user,
        workflow,
        actor,
    }
}

async fn new_execution(pool: &Pool<Postgres>, t: &Seeded, status: &str) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) VALUES ($1, $2, $3, $4, $5, NOW() - interval '3 seconds')",
    )
    .bind(id)
    .bind(t.workflow)
    .bind(t.user)
    .bind(t.actor)
    .bind(status)
    .execute(pool)
    .await
    .unwrap();
    id
}

async fn status_of(pool: &Pool<Postgres>, id: Uuid) -> (String, Option<String>) {
    sqlx::query_as("SELECT status, error_message FROM workflow_executions WHERE id = $1")
        .bind(id)
        .fetch_one(pool)
        .await
        .unwrap()
}

#[tokio::test]
async fn the_home_counts_what_it_finalizes_and_refuses_what_it_must() {
    let (pool, _db) = common::isolated_db_pool().await;
    let t = seed_tenant(&pool).await;
    talos_metrics::set_global(talos_metrics::TalosMetrics::new().expect("metrics"));
    let m = talos_metrics::global().expect("global metrics installed");
    let count = |status: &str| {
        m.workflow_executions_total
            .with_label_values(&[status])
            .get()
    };
    let hist = |status: &str| {
        m.workflow_execution_duration_seconds
            .with_label_values(&[status])
            .get_sample_count()
    };

    // A running row: finalized, counted, measured.
    let running = new_execution(&pool, &t, "running").await;
    let (c0, h0) = (count("failure"), hist("failure"));
    let n =
        talos_workflow_repository::fail_workflow_execution_unless_terminal(&pool, running, "boom")
            .await
            .unwrap();
    assert_eq!(n, 1);
    let (st, msg) = status_of(&pool, running).await;
    assert_eq!((st.as_str(), msg.as_deref()), ("failed", Some("boom")));
    assert_eq!(
        count("failure") - c0,
        1.0,
        "the failure counter must move exactly once"
    );
    assert_eq!(
        hist("failure") - h0,
        1,
        "the duration histogram must observe the row's own duration"
    );

    // A queued row (a trigger-path failure before dispatch): finalized too —
    // the actor repository's former `= 'running'` guard would have left it
    // queued forever.
    let queued = new_execution(&pool, &t, "queued").await;
    let c1 = count("failure");
    assert_eq!(
        talos_workflow_repository::fail_workflow_execution_unless_terminal(
            &pool,
            queued,
            "no dispatch"
        )
        .await
        .unwrap(),
        1
    );
    assert_eq!(status_of(&pool, queued).await.0, "failed");
    assert_eq!(count("failure") - c1, 1.0);

    // Terminal and crash-recovery-owned rows: refused, uncounted, untouched.
    for owned in ["completed", "failed", "cancelled", "resuming"] {
        let id = new_execution(&pool, &t, owned).await;
        let c = count("failure");
        assert_eq!(
            talos_workflow_repository::fail_workflow_execution_unless_terminal(&pool, id, "late")
                .await
                .unwrap(),
            0,
            "{owned} must not be finalized by a dispatcher-side failure"
        );
        assert_eq!(status_of(&pool, id).await.0, owned);
        assert_eq!(
            count("failure"),
            c,
            "{owned}: refused finalizations must not count"
        );
    }

    // The actor repository's three former raw sites, through their public methods.
    let repo = ActorRepository::new(pool.clone());
    let a = new_execution(&pool, &t, "running").await;
    let c2 = count("failure");
    repo.fail_execution(a, "handoff failed").await.unwrap();
    assert_eq!(status_of(&pool, a).await.0, "failed");
    assert_eq!(
        count("failure") - c2,
        1.0,
        "ActorRepository::fail_execution must count"
    );

    let b = new_execution(&pool, &t, "running").await;
    let c3 = count("failure");
    repo.fail_execution_nats_unavailable(b).await.unwrap();
    assert_eq!(
        status_of(&pool, b).await,
        (
            "failed".to_string(),
            Some("NATS client not available".to_string())
        )
    );
    assert_eq!(count("failure") - c3, 1.0);

    let c = new_execution(&pool, &t, "running").await;
    let (s0, hs0) = (count("success"), hist("success"));
    repo.complete_execution(c, &serde_json::json!({"ok": true}))
        .await
        .unwrap();
    assert_eq!(status_of(&pool, c).await.0, "completed");
    assert_eq!(
        count("success") - s0,
        1.0,
        "ActorRepository::complete_execution must count success"
    );
    assert_eq!(hist("success") - hs0, 1);

    // And the same completion on a `resuming` row now lands (the former guard
    // was `= 'running'` only — check 46's class).
    let d = new_execution(&pool, &t, "resuming").await;
    repo.complete_execution(d, &serde_json::json!({}))
        .await
        .unwrap();
    assert_eq!(status_of(&pool, d).await.0, "completed");
}
