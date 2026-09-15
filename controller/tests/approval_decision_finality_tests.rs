//! An approval decision is FINAL (package BH, 2026-09-15).
//!
//! GraphQL `approveExecution` / `denyExecution` wrote the decision through
//! `decide_execution_approval_scoped`, which had no `status = 'pending'` guard
//! (its MCP sibling always had one). A denied approval could be re-decided as
//! approved and the denier's `decided_by` / `decided_at` / `reason`
//! overwritten; with the UI's decide-then-resume flow that was a path from a
//! denial to a run. The statement is guarded now, and the rule's one home is
//! the `trg_execution_approvals_decision_final` trigger, which refuses the
//! change for ANY writer.
//!
//! Every refusal is checked against the ROW, not only against the returned
//! value: an outcome alone would pass on a statement that had overwritten the
//! decision and then reported otherwise.
//!
//! DB tests on the `common` harness, so CTRL_TESTS, not TC_TESTS (64b).

mod common;

use sqlx::{Pool, Postgres};
use talos_execution_repository::{ApprovalDecision, ApprovalDecisionWrite, ExecutionRepository};
use uuid::Uuid;

async fn seed_user(pool: &Pool<Postgres>) -> Uuid {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'approval finality')",
    )
    .bind(id)
    .bind(format!("approval-finality-{id}@example.com"))
    .execute(pool)
    .await
    .expect("seed user");
    id
}

async fn seed_pending_approval(pool: &Pool<Postgres>, workflow_id: Uuid) -> Uuid {
    sqlx::query_scalar(
        "INSERT INTO execution_approvals (workflow_id, execution_id, node_id) \
         VALUES ($1, gen_random_uuid(), gen_random_uuid()) RETURNING id",
    )
    .bind(workflow_id)
    .fetch_one(pool)
    .await
    .expect("seed approval")
}

#[derive(Debug, PartialEq, Eq)]
struct Decision {
    status: String,
    decided_by: Option<Uuid>,
    decided_at: Option<chrono::DateTime<chrono::Utc>>,
    reason: Option<String>,
}

async fn decision(pool: &Pool<Postgres>, id: Uuid) -> Decision {
    let (status, decided_by, decided_at, reason) = sqlx::query_as::<
        _,
        (
            String,
            Option<Uuid>,
            Option<chrono::DateTime<chrono::Utc>>,
            Option<String>,
        ),
    >(
        "SELECT status, decided_by, decided_at, reason FROM execution_approvals WHERE id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .expect("read decision");
    Decision {
        status,
        decided_by,
        decided_at,
        reason,
    }
}

/// Drive the production write exactly as the GraphQL resolvers do: on a
/// `begin_user_scoped` transaction, committed afterwards.
async fn decide(
    pool: &Pool<Postgres>,
    user: Uuid,
    approval: Uuid,
    decision: ApprovalDecision,
    reason: &str,
) -> ApprovalDecisionWrite {
    let repo = ExecutionRepository::new(pool.clone());
    let mut tx = talos_db::begin_user_scoped(pool, user)
        .await
        .expect("scoped tx");
    let outcome = repo
        .decide_execution_approval_scoped(&mut tx, approval, user, decision, Some(reason))
        .await
        .expect("decision write");
    tx.commit().await.expect("commit");
    outcome
}

/// The defect, reproduced through the production call: deny, then approve the
/// same id. The second call must be refused AND leave the denial untouched.
#[tokio::test]
async fn a_denied_approval_cannot_be_re_decided_as_approved() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let workflow = common::create_test_workflow(&pool, owner, "approval-finality").await;
    let approval = seed_pending_approval(&pool, workflow).await;

    // CONTROL: a pending approval is decided.
    assert_eq!(
        decide(
            &pool,
            owner,
            approval,
            ApprovalDecision::Denied,
            "not today"
        )
        .await,
        ApprovalDecisionWrite::Decided
    );
    let denied = decision(&pool, approval).await;
    assert_eq!(denied.status, "denied");
    assert_eq!(denied.decided_by, Some(owner));

    let flip = decide(
        &pool,
        owner,
        approval,
        ApprovalDecision::Approved,
        "changed my mind",
    )
    .await;
    assert_eq!(
        flip,
        ApprovalDecisionWrite::AlreadyDecided {
            status: "denied".to_string()
        }
    );
    assert_eq!(
        decision(&pool, approval).await,
        denied,
        "status, decider, decision time and reason are all unchanged"
    );
    assert_eq!(
        flip.refusal_message().as_deref(),
        Some("Approval request was already denied; an approval decision is final")
    );
}

/// "Already decided" is told to the OWNER only. Anyone else — and a missing
/// id — gets the pre-existing not-found sentence and changes nothing.
#[tokio::test]
async fn a_non_owner_learns_nothing_and_changes_nothing() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let workflow = common::create_test_workflow(&pool, owner, "approval-stranger").await;

    let pending = seed_pending_approval(&pool, workflow).await;
    assert_eq!(
        decide(&pool, stranger, pending, ApprovalDecision::Approved, "x").await,
        ApprovalDecisionWrite::NotFound
    );
    assert_eq!(decision(&pool, pending).await.status, "pending");

    let decided = seed_pending_approval(&pool, workflow).await;
    let _ = decide(&pool, owner, decided, ApprovalDecision::Approved, "ok").await;
    assert_eq!(
        decide(&pool, stranger, decided, ApprovalDecision::Denied, "x").await,
        ApprovalDecisionWrite::NotFound,
        "a stranger is not told the row exists, let alone its status"
    );
    assert_eq!(
        decide(
            &pool,
            owner,
            Uuid::new_v4(),
            ApprovalDecision::Approved,
            "x"
        )
        .await,
        ApprovalDecisionWrite::NotFound
    );
}

/// The trigger is the rule's one home: a writer with NO guard — a raw UPDATE,
/// standing in for a future third writer or a reverted guard — is refused with
/// SQLSTATE 23514 on a decided row, and admitted on a pending one.
#[tokio::test]
async fn the_database_refuses_any_writer_that_changes_a_decision() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let workflow = common::create_test_workflow(&pool, owner, "approval-trigger").await;
    let approval = seed_pending_approval(&pool, workflow).await;

    // CONTROL: pending → decided is the allowed transition.
    sqlx::query(
        "UPDATE execution_approvals SET status = 'approved', decided_by = $2, decided_at = NOW(), reason = 'ok' WHERE id = $1",
    )
    .bind(approval)
    .bind(owner)
    .execute(&pool)
    .await
    .expect("pending → approved is allowed");
    let approved = decision(&pool, approval).await;

    for (column_change, sql) in [
        (
            "status",
            "UPDATE execution_approvals SET status = 'denied' WHERE id = $1",
        ),
        (
            "decided_by",
            "UPDATE execution_approvals SET decided_by = gen_random_uuid() WHERE id = $1",
        ),
        (
            "decided_at",
            "UPDATE execution_approvals SET decided_at = NOW() - interval '1 day' WHERE id = $1",
        ),
        (
            "reason",
            "UPDATE execution_approvals SET reason = 'rewritten' WHERE id = $1",
        ),
    ] {
        let err = sqlx::query(sql)
            .bind(approval)
            .execute(&pool)
            .await
            .expect_err(column_change);
        assert_eq!(
            err.as_database_error().and_then(|d| d.code()).as_deref(),
            Some("23514"),
            "{column_change}: {err}"
        );
    }
    assert_eq!(decision(&pool, approval).await, approved);

    // Non-decision columns stay writable on a decided row.
    sqlx::query("UPDATE execution_approvals SET required_for = ARRAY['x'] WHERE id = $1")
        .bind(approval)
        .execute(&pool)
        .await
        .expect("a non-decision column may change");
}

/// The MCP / email-link writer was already guarded; its "already decided"
/// answer (0 rows) must still be an ordinary 0, not a trigger error.
#[tokio::test]
async fn the_guarded_mcp_writer_still_reports_zero_rows_for_a_decided_approval() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let workflow = common::create_test_workflow(&pool, owner, "approval-mcp").await;
    let execution_id: Uuid = sqlx::query_scalar(
        "INSERT INTO execution_approvals (workflow_id, execution_id, node_id) \
         VALUES ($1, gen_random_uuid(), gen_random_uuid()) RETURNING execution_id",
    )
    .bind(workflow)
    .fetch_one(&pool)
    .await
    .unwrap();
    let repo = ExecutionRepository::new(pool.clone());

    assert_eq!(
        repo.update_execution_approval_decision(execution_id, "approved", owner, Some("ok"))
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        repo.update_execution_approval_decision(execution_id, "denied", owner, Some("no"))
            .await
            .expect("a guarded writer never reaches the trigger"),
        0
    );
}

/// The application-level ownership predicate, on its OWN. The resolvers run
/// the write on a `begin_user_scoped` transaction, where the `workflows` RLS
/// policy ALSO hides a stranger's workflow — so the test above passes even with
/// the `w.user_id = $2` predicate deleted from the "already decided" read
/// (measured: that mutation survived it). This drives the same method on an
/// UNSCOPED transaction, where the policy's unset-GUC arm permits every row and
/// the predicate is the only thing between a stranger and the row's status.
#[tokio::test]
async fn the_ownership_predicate_holds_without_the_rls_backstop() {
    let (pool, _db) = common::isolated_db_pool().await;
    let owner = seed_user(&pool).await;
    let stranger = seed_user(&pool).await;
    let workflow = common::create_test_workflow(&pool, owner, "approval-unscoped").await;
    let approval = seed_pending_approval(&pool, workflow).await;
    let _ = decide(&pool, owner, approval, ApprovalDecision::Approved, "ok").await;

    let repo = ExecutionRepository::new(pool.clone());
    let mut tx = pool.begin().await.expect("unscoped tx");
    let outcome = repo
        .decide_execution_approval_scoped(
            &mut tx,
            approval,
            stranger,
            ApprovalDecision::Denied,
            Some("x"),
        )
        .await
        .expect("decision write");
    tx.commit().await.expect("commit");
    assert_eq!(outcome, ApprovalDecisionWrite::NotFound);
    assert_eq!(decision(&pool, approval).await.status, "approved");
}
