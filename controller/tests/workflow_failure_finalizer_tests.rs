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

    // The stale sweep's janitor write. Until 2026-09-21 it carried its own
    // UPDATE and recorded nothing, so a run a controller restart orphaned was
    // a `failed` row the failure counter never saw.
    let sweep = talos_execution_repository::ExecutionRepository::new(pool.clone());
    let stale = new_execution(&pool, &t, "running").await;
    let (c4, h4) = (count("failure"), hist("failure"));
    assert!(sweep
        .fail_stale_execution(stale, "Auto-cleaned: execution stale")
        .await
        .unwrap());
    assert_eq!(
        status_of(&pool, stale).await,
        (
            "failed".to_string(),
            Some("Auto-cleaned: execution stale".to_string())
        )
    );
    assert_eq!(
        count("failure") - c4,
        1.0,
        "a run the stale sweep fails must be counted as a failure"
    );
    assert_eq!(hist("failure") - h4, 1);

    // The janitor's guard is `running` ONLY: it must not take a `resuming`
    // row from crash recovery, start a `queued` one's failure, or re-fail a
    // finished row — and what it does not finalize it does not count.
    for owned in ["resuming", "queued", "completed", "failed", "cancelled"] {
        let id = new_execution(&pool, &t, owned).await;
        let c = count("failure");
        assert!(
            !sweep
                .fail_stale_execution(id, "should not land")
                .await
                .unwrap(),
            "the stale sweep must leave a {owned} row alone"
        );
        assert_eq!(status_of(&pool, id).await.0, owned);
        assert_eq!(count("failure"), c, "a refused {owned} row must not count");
    }

    // ── 2026-09-21 (package DH): five more failure writers that counted
    // nothing. Enumerated by STATEMENT, multi-line aware — check 46 and the
    // AG pin both read single lines, and these are written across several.

    // (1) The continuation / handoff path's `AdvancedRepository::fail_execution`
    // — the platform's busiest start path.
    let advanced = talos_advanced_repository::AdvancedRepository::new(pool.clone());
    let lost = new_execution(&pool, &t, "running").await;
    let (c, h) = (count("failure"), hist("failure"));
    advanced
        .fail_execution(lost, "Workflow not found")
        .await
        .unwrap();
    assert_eq!(status_of(&pool, lost).await.0, "failed");
    assert_eq!(
        count("failure") - c,
        1.0,
        "the continuation failure must count"
    );
    assert_eq!(hist("failure") - h, 1);
    // …and its guard is kept: a `resuming` row is crash recovery's.
    let owned = new_execution(&pool, &t, "resuming").await;
    let c = count("failure");
    advanced.fail_execution(owned, "no").await.unwrap();
    assert_eq!(status_of(&pool, owned).await.0, "resuming");
    assert_eq!(count("failure"), c);

    // (2) Crash recovery's two exits.
    let exec_repo = talos_execution_repository::ExecutionRepository::new(pool.clone());
    let resuming = new_execution(&pool, &t, "resuming").await;
    let running_now = new_execution(&pool, &t, "running").await;
    let (c, h) = (count("failure"), hist("failure"));
    assert!(exec_repo
        .fail_resuming_execution(resuming, "dispatch failed")
        .await
        .unwrap());
    assert!(
        !exec_repo
            .fail_resuming_execution(running_now, "no")
            .await
            .unwrap(),
        "guard: `resuming` only"
    );
    assert_eq!(status_of(&pool, running_now).await.0, "running");
    assert_eq!(count("failure") - c, 1.0);
    assert_eq!(hist("failure") - h, 1);

    let wedged_a = new_execution(&pool, &t, "resuming").await;
    let wedged_b = new_execution(&pool, &t, "resuming").await;
    let fresh = new_execution(&pool, &t, "resuming").await;
    sqlx::query("ALTER TABLE workflow_executions DISABLE TRIGGER USER")
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE workflow_executions SET updated_at = NOW() - interval '30 minutes' WHERE id = ANY($1)",
    )
    .bind(vec![wedged_a, wedged_b])
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("ALTER TABLE workflow_executions ENABLE TRIGGER USER")
        .execute(&pool)
        .await
        .unwrap();
    let epoch_before: i64 =
        sqlx::query_scalar("SELECT epoch FROM workflow_executions WHERE id = $1")
            .bind(wedged_a)
            .fetch_one(&pool)
            .await
            .unwrap();
    let c = count("failure");
    assert_eq!(exec_repo.reclaim_orphaned_resuming(10).await.unwrap(), 2);
    assert_eq!(
        count("failure") - c,
        2.0,
        "once per reclaimed run, not per call"
    );
    assert_eq!(
        status_of(&pool, fresh).await.0,
        "resuming",
        "inside the grace"
    );
    let epoch_after: i64 =
        sqlx::query_scalar("SELECT epoch FROM workflow_executions WHERE id = $1")
            .bind(wedged_a)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(epoch_after, epoch_before + 1, "the fence bump is kept");
    assert_eq!(exec_repo.reclaim_orphaned_resuming(0).await.unwrap(), 0);

    // (3) The operator's stale-execution cleanups: counted, and recorded in the
    // cleanup's own transaction with what they actually did.
    sqlx::query("UPDATE workflow_executions SET status = 'failed' WHERE status IN ('running', 'resuming') AND user_id = $1")
        .bind(t.user)
        .execute(&pool)
        .await
        .unwrap();
    let old_a = new_execution(&pool, &t, "running").await;
    let old_b = new_execution(&pool, &t, "running").await;
    let old_c = new_execution(&pool, &t, "running").await;
    let young = new_execution(&pool, &t, "running").await;
    let old_resuming = new_execution(&pool, &t, "resuming").await;
    sqlx::query(
        "UPDATE workflow_executions SET started_at = NOW() - interval '3 hours' WHERE id = ANY($1)",
    )
    .bind(vec![old_a, old_b, old_c, old_resuming])
    .execute(&pool)
    .await
    .unwrap();
    let other = seed_tenant(&pool).await;
    let theirs = new_execution(&pool, &other, "running").await;
    sqlx::query(
        "UPDATE workflow_executions SET started_at = NOW() - interval '3 hours' WHERE id = $1",
    )
    .bind(theirs)
    .execute(&pool)
    .await
    .unwrap();

    // Hygiene: bounded to the previewed ids — and another user's id in the
    // list is not touched.
    let (c, h) = (count("failure"), hist("failure"));
    assert_eq!(
        exec_repo
            .cleanup_stale_executions_by_ids(&[old_a, young, theirs], 120, t.user)
            .await
            .unwrap(),
        1
    );
    assert_eq!(count("failure") - c, 1.0);
    assert_eq!(hist("failure") - h, 1);
    assert_eq!(status_of(&pool, young).await.0, "running", "not old enough");
    assert_eq!(
        status_of(&pool, theirs).await.0,
        "running",
        "not this user's"
    );
    assert_eq!(
        status_of(&pool, old_b).await.0,
        "running",
        "not in the list"
    );

    // The MCP tool: user-wide by age.
    let c = count("failure");
    assert_eq!(
        exec_repo
            .cleanup_stale_executions(120, t.user)
            .await
            .unwrap(),
        2
    );
    assert_eq!(count("failure") - c, 2.0);
    assert_eq!(
        status_of(&pool, old_resuming).await.0,
        "resuming",
        "crash recovery's"
    );
    assert_eq!(status_of(&pool, theirs).await.0, "running");
    // Nothing left to clean: nothing counted, nothing recorded.
    let c = count("failure");
    assert_eq!(
        exec_repo
            .cleanup_stale_executions(120, t.user)
            .await
            .unwrap(),
        0
    );
    assert_eq!(count("failure"), c);

    let events: Vec<(String, String, serde_json::Value, Option<Uuid>)> = sqlx::query_as(
        "SELECT event_type, summary, details, user_id FROM admin_event_log \
         WHERE resource_type = 'execution' ORDER BY created_at, id",
    )
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(
        events.len(),
        2,
        "one record per cleanup that failed something"
    );
    assert_eq!(events[0].0, "executions_hygiene_stale_cleanup");
    assert_eq!(events[0].2["failed_count"], 1);
    assert_eq!(
        events[0].2["execution_ids"],
        serde_json::json!([old_a.to_string()])
    );
    assert_eq!(events[1].0, "executions_stale_cleanup");
    assert_eq!(events[1].3, Some(t.user));
    assert_eq!(events[1].2["failed_count"], 2);
    assert_eq!(events[1].2["older_than_minutes"], 120);
    assert_eq!(events[1].2["listed_truncated"], false);
    let mut listed: Vec<String> = events[1].2["execution_ids"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    listed.sort();
    let mut want = vec![old_b.to_string(), old_c.to_string()];
    want.sort();
    assert_eq!(listed, want);
    for (_, summary, _, _) in &events {
        assert!(
            summary.contains("marked failed") && !summary.contains("deleted"),
            "the record must say what happened — these runs are failed, not deleted: {summary}"
        );
    }

    // The record lists at most 1000 ids and says so, beside the TRUE count
    // (`details` over 1 MiB are dropped whole, and the tool is unbounded).
    sqlx::query(
        "INSERT INTO workflow_executions (id, workflow_id, user_id, actor_id, status, started_at) \
         SELECT gen_random_uuid(), $1, $2, $3, 'running', NOW() - interval '3 hours' \
         FROM generate_series(1, 1001)",
    )
    .bind(t.workflow)
    .bind(t.user)
    .bind(t.actor)
    .execute(&pool)
    .await
    .unwrap();
    let c = count("failure");
    assert_eq!(
        exec_repo
            .cleanup_stale_executions(120, t.user)
            .await
            .unwrap(),
        1001
    );
    assert_eq!(count("failure") - c, 1001.0);
    let big: serde_json::Value = sqlx::query_scalar(
        "SELECT details FROM admin_event_log WHERE resource_type = 'execution' \
         ORDER BY created_at DESC, id DESC LIMIT 1",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(big["failed_count"], 1001, "the TRUE count");
    assert_eq!(big["execution_ids"].as_array().unwrap().len(), 1000);
    assert_eq!(big["listed_truncated"], true);

    // A cleanup that cannot be recorded does not happen — and counts nothing.
    let unrecorded = new_execution(&pool, &t, "running").await;
    sqlx::query(
        "UPDATE workflow_executions SET started_at = NOW() - interval '3 hours' WHERE id = $1",
    )
    .bind(unrecorded)
    .execute(&pool)
    .await
    .unwrap();
    sqlx::query("ALTER TABLE admin_event_log RENAME TO admin_event_log_away")
        .execute(&pool)
        .await
        .unwrap();
    let c = count("failure");
    assert!(exec_repo
        .cleanup_stale_executions(120, t.user)
        .await
        .is_err());
    assert!(exec_repo
        .cleanup_stale_executions_by_ids(&[unrecorded], 120, t.user)
        .await
        .is_err());
    assert_eq!(status_of(&pool, unrecorded).await.0, "running");
    assert_eq!(
        count("failure"),
        c,
        "a rolled-back cleanup must count nothing"
    );
}
