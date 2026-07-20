//! Actor execution budget prechecks — status + hourly/lifetime budget
//! gates run before admitting a new workflow execution.
//!
//! Extracted verbatim from `talos-mcp-handlers/src/actor.rs` (2026-07-02)
//! so the actor-lifecycle service (handoff dispatch) can enforce the same
//! gates without depending on the handler crate. The handler crate
//! re-exports these under the legacy `crate::actor::*` paths, so existing
//! callers (`executions.rs` enqueue batch gate, `workflows.rs` dispatch
//! gate) are unchanged. Pure composition over `ActorRepository` methods —
//! no raw SQL lives here.

use uuid::Uuid;

/// Check actor status and budget before allowing a new workflow execution.
/// Returns Ok(()) if execution is allowed, Err(message) if it should be rejected.
/// Budget policy row fetched from `actor_budget_policies`. Pulled into a
/// struct so the three budget checks can share a single load + operate on
/// typed fields.
#[derive(Debug, Clone)]
pub struct ActorBudget {
    pub max_executions_per_hour: Option<i32>,
    pub max_executions_total: Option<i64>,
    pub on_budget_exceeded: String,
    /// R2 token ledger: daily LLM token ceiling (prompt + completion over
    /// the trailing 24 h from the `llm_usage` ledger). `None` = unlimited.
    pub max_llm_tokens_per_day: Option<i64>,
}

/// Load the budget policy for an actor. Returns `Ok(None)` if no policy
/// exists (meaning: unlimited budget). Returns `Err` only on genuine DB
/// failure so callers can distinguish "no policy" from "fetch failed".
///
/// MCP-875 (2026-05-14): sanitize the propagated error. Pre-fix the
/// `map_err(|e| format!("Failed to load actor budget: {e}"))` leaked the
/// raw sqlx error into the user-facing error string — column names,
/// query fragments, FK relations could land in a GraphQL/MCP error
/// surface visible to any caller of the dispatch path. Now the
/// underlying error is logged via `tracing::error!` (operator signal
/// retained) and the user-facing String is a generic
/// "(database error). Retry…" shape mirroring `check_actor_status`
/// (MCP-874). Sibling to the broader MCP-872/873/874 sweep.
pub async fn load_actor_budget(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
) -> Result<Option<ActorBudget>, String> {
    let repo = crate::ActorRepository::new(pool.clone());
    let policy = repo.get_actor_budget_policy(actor_id).await.map_err(|e| {
        tracing::error!(
            actor_id = %actor_id,
            error = %e,
            "load_actor_budget: get_actor_budget_policy failed"
        );
        "Failed to load actor budget (database error). Retry the request; \
             if the issue persists, check controller logs."
            .to_string()
    })?;
    Ok(policy.map(|p| ActorBudget {
        max_executions_per_hour: p.max_executions_per_hour,
        max_executions_total: p.max_executions_total,
        on_budget_exceeded: p.on_budget_exceeded,
        max_llm_tokens_per_day: p.max_llm_tokens_per_day,
    }))
}

/// Verify the actor exists and is in an executable state. Returns `Err` if
/// the actor is missing, suspended, or terminated.
///
/// MCP-874 (2026-05-14): explicit match with Err arm. Pre-fix
/// `repo.get_actor_status(actor_id).await.ok().flatten()` collapsed DB
/// errors into `None`, so a Postgres hiccup, connection-pool exhaustion,
/// or query timeout was indistinguishable from a real missing-actor hit.
/// Both surfaced as "Actor not found" — fail-closed semantically (the
/// dispatch path refused execution either way), but the misleading error
/// message led operators to chase phantom "user deleted their actor"
/// reports instead of investigating the actual DB issue. Same
/// discriminator-swallow class as MCP-838/839/840/841/842/845.
pub async fn check_actor_status(pool: &sqlx::PgPool, actor_id: Uuid) -> Result<(), String> {
    let repo = crate::ActorRepository::new(pool.clone());
    let status = match repo.get_actor_status(actor_id).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(
                actor_id = %actor_id,
                error = %e,
                "check_actor_status: get_actor_status failed"
            );
            return Err("Failed to verify actor status (database error). \
                 Retry the request; if the issue persists, check controller logs."
                .to_string());
        }
    };
    match status.as_deref() {
        None => Err("Actor not found".to_string()),
        Some("suspended") => Err(
            "Actor is suspended. Resume it with update_actor_status before executing.".to_string(),
        ),
        Some("terminated") => Err("Actor is terminated and cannot execute workflows.".to_string()),
        _ => Ok(()),
    }
}

/// Enforce the rolling 1-hour execution budget. On violation, optionally
/// suspends the actor when the policy is `on_budget_exceeded == "suspend"`.
pub async fn check_actor_hour_budget(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    budget: &ActorBudget,
) -> Result<(), String> {
    check_actor_hour_budget_for_batch(pool, actor_id, budget, 1).await
}

/// MCP-566: batch-aware sibling of `check_actor_hour_budget`. See the
/// rationale on `check_execution_allowed_for_batch`. `batch_size` is the
/// number of executions about to be admitted in one logical operation;
/// the gate refuses if `count + batch_size > max_per_hour`.
pub async fn check_actor_hour_budget_for_batch(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    budget: &ActorBudget,
    batch_size: i64,
) -> Result<(), String> {
    let Some(max_per_hour) = budget.max_executions_per_hour else {
        return Ok(());
    };
    let repo = crate::ActorRepository::new(pool.clone());
    // MCP-366 (2026-05-11): pre-fix `.unwrap_or(0)` silently fell back
    // to count=0 on any DB error, so a transient Postgres failure
    // bypassed the per-hour execution budget — actor at 1000/hr could
    // keep firing during DB hiccups. SECURITY-relevant fail-OPEN on a
    // budget gate. Now fail-CLOSED: log the error server-side and
    // reject the precheck so the operator sees "budget check failed"
    // instead of silently overrunning their declared limit.
    let count = match repo.count_executions_last_hour(actor_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                actor_id = %actor_id,
                error = %e,
                "count_executions_last_hour failed; refusing execution to avoid budget bypass"
            );
            return Err(
                "Budget pre-check failed (database error). Refusing execution to avoid silent budget bypass; retry after the database recovers.".to_string()
            );
        }
    };

    // MCP-566: batch-aware check. `count + batch_size > max_per_hour`
    // refuses any batch that would push the rolling 1-hour count past
    // the cap. batch_size=1 preserves the historical `>=` semantics
    // (count >= max ↔ count + 1 > max).
    if count + batch_size > max_per_hour as i64 {
        if budget.on_budget_exceeded == "suspend" {
            // Look up the actor's owning user_id so the suspend call
            // satisfies the L T4-2 SQL ownership gate. Internal
            // pre-execution path; if the lookup fails we skip the
            // auto-suspend (the cap-exceeded error still surfaces to
            // the caller, so budget enforcement holds either way).
            //
            // MCP-875 (2026-05-14): log owner-lookup failures distinctly
            // from "actor has no owner" so operators see when the
            // on_budget_exceeded=suspend policy silently fails to fire
            // due to a DB issue. Mirrors the MCP-804 logging pattern on
            // the suspend_actor UPDATE failure right below — without
            // this, the two operator-relevant "auto-suspend didn't
            // happen" outcomes had asymmetric telemetry.
            let owner = match repo.get_actor_owner_user_id(actor_id).await {
                Ok(o) => o,
                Err(e) => {
                    tracing::warn!(
                        target: "talos_audit",
                        actor_id = %actor_id,
                        error = %e,
                        "check_actor_hour_budget_for_batch: owner lookup failed — \
                         skipping auto-suspend, but cap-exceeded rejection still fires"
                    );
                    None
                }
            };
            if let Some(uid) = owner {
                // MCP-804 (2026-05-14): log suspend_actor failures. The
                // cap-exceeded error is still surfaced to the caller below,
                // so this execution is correctly rejected; the
                // operator-visibility gap is that on_budget_exceeded=
                // "suspend" policy SILENTLY does not actually suspend
                // when the UPDATE fails. Operators see the actor still
                // 'active' despite the policy stamp and the budget hit
                // — confusing audit-trail review. WARN with
                // `target: "talos_audit"`.
                if let Err(ue) = repo.suspend_actor(actor_id, uid).await {
                    tracing::warn!(
                        target: "talos_audit",
                        actor_id = %actor_id,
                        user_id = %uid,
                        error = %ue,
                        "check_actor_hour_budget_for_batch: auto-suspend UPDATE failed — actor stays 'active' despite on_budget_exceeded=suspend policy; rejecting this execution proceeds normally"
                    );
                }
            }
        }
        return Err(format!(
            "Actor budget exceeded: {} executions in the last hour + {} requested would exceed cap {}. \
             on_budget_exceeded={}",
            count, batch_size, max_per_hour, budget.on_budget_exceeded
        ));
    }
    Ok(())
}

/// Enforce the lifetime total execution budget.
pub async fn check_actor_total_budget(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    budget: &ActorBudget,
) -> Result<(), String> {
    check_actor_total_budget_for_batch(pool, actor_id, budget, 1).await
}

/// MCP-566: batch-aware sibling of `check_actor_total_budget`.
pub async fn check_actor_total_budget_for_batch(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    budget: &ActorBudget,
    batch_size: i64,
) -> Result<(), String> {
    let Some(max_total) = budget.max_executions_total else {
        return Ok(());
    };
    let repo = crate::ActorRepository::new(pool.clone());
    // MCP-366 (2026-05-11): same fail-CLOSED fix as
    // check_actor_hourly_budget — pre-fix unwrap_or(0) silently bypassed
    // the lifetime execution budget on DB errors.
    let count = match repo.count_total_executions(actor_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(
                actor_id = %actor_id,
                error = %e,
                "count_total_executions failed; refusing execution to avoid budget bypass"
            );
            return Err(
                "Budget pre-check failed (database error). Refusing execution to avoid silent budget bypass; retry after the database recovers.".to_string()
            );
        }
    };
    // MCP-566: batch-aware. `count + batch_size > max_total` refuses any
    // batch that would push the lifetime count past the cap.
    if count + batch_size > max_total {
        return Err(format!(
            "Actor budget exceeded: {} total executions + {} requested would exceed lifetime cap {}. \
             Increase the budget with set_actor_budget.",
            count, batch_size, max_total
        ));
    }
    Ok(())
}

/// R2 token ledger: fast-fail pre-check for the daily LLM token ceiling.
/// The hard cap is the atomic backstop inside
/// `create_execution_under_concurrency_limit` (advisory-lock-serialized,
/// same transaction as the INSERT); this pre-check mirrors the per-hour /
/// total pattern — cheap rejection before any dispatch work, fail-CLOSED
/// on DB error (MCP-366 class: a silent 0 on error would bypass the cap).
/// Batch size is irrelevant here (the ledger counts tokens, not
/// executions), so there is no `_for_batch` sibling.
pub async fn check_actor_llm_token_budget(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    budget: &ActorBudget,
) -> Result<(), String> {
    let Some(cap) = budget.max_llm_tokens_per_day else {
        return Ok(());
    };
    let repo = crate::ActorRepository::new(pool.clone());
    let used = match repo.sum_llm_tokens_last_24h(actor_id).await {
        Ok(u) => u,
        Err(e) => {
            tracing::error!(
                actor_id = %actor_id,
                error = %e,
                "sum_llm_tokens_last_24h failed; refusing execution to avoid budget bypass"
            );
            return Err(
                "Budget pre-check failed (database error). Refusing execution to avoid silent budget bypass; retry after the database recovers.".to_string()
            );
        }
    };
    if used >= cap {
        return Err(format!(
            "Actor budget exceeded: {used} LLM tokens consumed in the last 24 hours reaches cap {cap}. \
             on_budget_exceeded={}. Raise max_llm_tokens_per_day with set_actor_budget or wait for the window to roll.",
            budget.on_budget_exceeded
        ));
    }
    Ok(())
}

/// Full execution precheck: status + budget. Composed from the smaller
/// helpers above so callers can run individual checks as needed (e.g., a
/// dry-run endpoint might want status-only without budget enforcement).
pub async fn check_execution_allowed(pool: &sqlx::PgPool, actor_id: Uuid) -> Result<(), String> {
    check_execution_allowed_for_batch(pool, actor_id, 1).await
}

/// MCP-566: batch-aware version of `check_execution_allowed`. Pre-fix
/// `enqueue_workflow` called `check_execution_allowed` once per batch, so
/// an actor with `max_executions_per_hour = N` could be enqueued with a
/// batch of size > N as long as the *current* hourly count was below N.
/// The gate checked `count >= N` rather than `count + batch_size > N` —
/// effectively making the cap "N + (max batch size)" instead of N.
///
/// This sibling closes that gap. Existing `check_execution_allowed`
/// callers (trigger / replay / retry / scheduler / engine chains /
/// continuation / webhooks) pass batch_size=1 implicitly and see no
/// behaviour change. `enqueue_workflow` and any future bulk dispatcher
/// MUST pass the real `inputs.len()`.
///
/// Reject-whole semantics: if the batch would push count over the cap,
/// refuse the entire enqueue. Partial admission (insert only the prefix
/// that fits) would complicate the response shape and is something
/// `create_executions_batch_under_concurrency_limit` already does for
/// the *workflow* concurrency cap — letting the actor budget cap have
/// the same semantics would be ambiguous.
pub async fn check_execution_allowed_for_batch(
    pool: &sqlx::PgPool,
    actor_id: Uuid,
    batch_size: i64,
) -> Result<(), String> {
    check_actor_status(pool, actor_id).await?;
    let budget = load_actor_budget(pool, actor_id).await?;
    let Some(budget) = budget else {
        return Ok(());
    };
    check_actor_hour_budget_for_batch(pool, actor_id, &budget, batch_size).await?;
    check_actor_total_budget_for_batch(pool, actor_id, &budget, batch_size).await?;
    check_actor_llm_token_budget(pool, actor_id, &budget).await?;
    Ok(())
}
