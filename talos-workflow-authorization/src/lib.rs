//! Workflow-creator authorization gate.
//!
//! Verifies that an actor exists, is active, has budget for another
//! workflow, and that every module in the workflow's graph fits under
//! the actor's `max_capability_world` ceiling. Used by
//! `mcp::workflows::handle_create_workflow` (and any future
//! workflow-creation surface — e.g. `create_workflow_from_spec`,
//! template-instantiate flows). Phase 4 of the create-workflow refactor;
//! the rest of the helpers live in
//! [`talos_workflow_creation_helpers`] (pure, state-free).
//!
//! ## Why this is its own module
//!
//! All three checks are security gates with explicit error semantics —
//! a bug here either lets a workflow exist that shouldn't (budget /
//! ceiling bypass), or rejects one that should (false positive). Pulling
//! them out of the 1000-line monolith handler makes the contract
//! reviewable in isolation; the pure rank-comparison logic is unit-
//! tested below so a future tweak to the rank table can't quietly
//! invert the gate.
//!
//! ## Error mapping
//!
//! Each [`CreatorAuthError`] variant maps 1:1 to an MCP error code in
//! the handler. Variant docstrings document the mapping; the user-
//! facing string the handler emits is intentionally NOT in the error
//! itself (variants carry structured fields so the formatting can
//! change without invalidating callers). The single rejection message
//! for `ActorNotFoundOrInactive` ("not found, not active, or belongs
//! to a different user") is deliberate — splitting it would let an
//! attacker enumerate other users' actors.

use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use talos_workflow_repository::WorkflowRepository;

/// Successful authorization outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatorAuthorization {
    /// `actor_id` was not provided. The workflow is created without an
    /// owning actor; no budget or ceiling enforcement applies.
    Unbound,
    /// `actor_id` was verified, active, within budget, and within the
    /// capability-world ceiling. Caller stamps the actor onto the
    /// workflow row.
    Authorized { actor_id: Uuid },
}

/// Why authorization was rejected. Variants map 1:1 to MCP error
/// codes — see each variant's doc.
#[derive(Debug)]
pub enum CreatorAuthError {
    /// MCP `-32002`. Single message used in the handler so the
    /// rejection reason can't enumerate other users' actors.
    ActorNotFoundOrInactive,
    /// MCP `-32000`. Actor's `max_workflow_count` budget is exhausted
    /// (current count ≥ limit).
    BudgetExhausted { limit: i32 },
    /// MCP `-32003`. A module in the workflow uses a capability world
    /// (e.g. `agent-node`) that exceeds the actor's
    /// `max_capability_world` ceiling. Carries the offending module +
    /// both ranks so the handler can format a diagnostic message and
    /// `tracing::warn!` can log structured fields.
    CapabilityCeilingViolation {
        module_id: Uuid,
        module_world: String,
        max_world: String,
        req_rank: u8,
        max_rank: u8,
    },
    /// Database failure during one of the lookups (actor, count,
    /// module worlds). Caller should map to the generic database_error
    /// MCP response — never echo the inner Postgres text to the
    /// client.
    Database(anyhow::Error),
}

/// Pure: given the actor's max-world rank and the resolved per-module
/// worlds, return `Err` on the first module that exceeds the ceiling.
/// Matches the original handler's short-circuit semantics.
///
/// MCP-461: unknown ACTOR world strings fail closed via
/// [`talos_capability_world::actor_world_rank_strict`]. Pre-fix,
/// `world_rank` returned 7 (most-privileged) for unknown values on
/// BOTH sides of the comparison — that's the right default for an
/// unknown MODULE world (treat as needing the highest ceiling) but the
/// WRONG default for an unknown ACTOR world (a malformed / legacy
/// actor row would silently inherit a tier-7 ceiling and every
/// module's check would pass). The actor-side strict lookup returns
/// `None` for non-[`ACTOR_CEILING_WORLDS`] strings; we surface that as
/// the same `CapabilityCeilingViolation` shape (max_rank=0, the most
/// restrictive) so existing operator surfaces continue to display
/// "ceiling exceeded" instead of silently letting privilege escalate.
///
/// Module-side unknown still ranks as 7 — the existing fail-closed
/// default that protects against a new module world bypassing a
/// tier-1 actor.
pub fn check_capability_ceiling(
    max_world: &str,
    module_worlds: &[(Uuid, String)],
) -> Result<(), CreatorAuthError> {
    let max_rank = match talos_capability_world::actor_world_rank_strict(max_world) {
        Some(r) => r,
        None => {
            // Unknown actor ceiling — fail every module check by
            // pinning the ceiling at rank 0. The first module-world
            // rank > 0 surfaces as the standard CapabilityCeilingViolation
            // diagnostic with max_rank=0 + max_world echoed unchanged
            // so operators see exactly which value tripped the gate.
            // Handle the edge case where the actor has zero module
            // references (an empty workflow): no module triggers the
            // loop, so we explicitly reject below with a synthetic
            // violation against a sentinel module_id.
            if module_worlds.is_empty() {
                return Err(CreatorAuthError::CapabilityCeilingViolation {
                    module_id: Uuid::nil(),
                    module_world: "(no modules)".to_string(),
                    max_world: max_world.to_string(),
                    req_rank: 1,
                    max_rank: 0,
                });
            }
            0
        }
    };
    for (mid, world) in module_worlds {
        let req_rank = talos_capability_world::world_rank(world);
        // Wasm-security review 2026-05-28 (HIGH): gate on the partial-order
        // lattice, not the linear rank. `req_rank > max_rank` wrongly admitted
        // lattice-INCOMPARABLE siblings (e.g. a `cache-node` ceiling admitting a
        // `secrets-node` module — `Secrets ⊄ Cache`). `ceiling_permits` is the
        // canonical gate; `req_rank`/`max_rank` are retained only for the
        // operator-facing diagnostic. The lattice strictly subsumes the rank
        // check (every subset edge has rank(sub) <= rank(super)).
        if !talos_capability_world::ceiling_permits(max_world, world) {
            return Err(CreatorAuthError::CapabilityCeilingViolation {
                module_id: *mid,
                module_world: world.clone(),
                max_world: max_world.to_string(),
                req_rank,
                max_rank,
            });
        }
    }
    Ok(())
}

/// Run all three creator-authorization checks in sequence:
/// 1. Actor exists, is owned by `user_id`, is `active`.
/// 2. `max_workflow_count` budget (when set) leaves room for one more.
/// 3. Every module in `module_ids` fits under the actor's
///    `max_capability_world` ceiling.
///
/// `Ok(CreatorAuthorization::Unbound)` when `workflow_agent_id` is
/// `None` — workflows can be created without an actor binding (no
/// budget / ceiling enforcement applies). `Ok(Authorized)` when all
/// three checks pass.
pub async fn authorize_workflow_creator(
    workflow_repo: &WorkflowRepository,
    db_pool: &PgPool,
    workflow_agent_id: Option<Uuid>,
    user_id: Uuid,
    module_ids: &[Uuid],
) -> Result<CreatorAuthorization, CreatorAuthError> {
    let Some(agent_id) = workflow_agent_id else {
        return Ok(CreatorAuthorization::Unbound);
    };

    // 1. Identity + ownership + active status.
    let actor = workflow_repo
        .get_actor(agent_id, user_id)
        .await
        .map_err(CreatorAuthError::Database)?
        .ok_or(CreatorAuthError::ActorNotFoundOrInactive)?;
    if actor.status != "active" {
        return Err(CreatorAuthError::ActorNotFoundOrInactive);
    }

    // 2. Budget (skip when actor has no max_workflow_count cap).
    if let Some(max) = actor.max_workflow_count {
        let current = workflow_repo
            .count_actor_workflows(agent_id)
            .await
            .map_err(CreatorAuthError::Database)?;
        if current >= max as i64 {
            return Err(CreatorAuthError::BudgetExhausted { limit: max });
        }
    }

    // 3. Capability-world ceiling (skip when actor has no ceiling set,
    // i.e. legacy actors that predate the column).
    //
    // BUG-46: Ceiling enforcement queries BOTH node_templates and
    // wasm_modules — user-facing modules live in node_templates,
    // wasm_modules only carries compiled artifacts from sandbox builds.
    // BUG-47: DISTINCT ON (id) preferring node_templates (src=1) over
    // wasm_modules (src=2) prevents the stale 'automation-node' default
    // on compiled catalog rows from producing false-positive ceiling
    // violations. The DB-side fix lives in the repo method; the
    // structured warn! below logs enough context to spot a regression.
    //
    // MCP-545: use `try_get_actor_max_world` (Result-returning) instead
    // of the lenient free function `get_actor_max_world` (returns None
    // on DB error). Pre-fix a transient Postgres error here returned
    // None, which caused this `if let Some(...)` block to be SKIPPED —
    // letting the actor CREATE a workflow with modules above their
    // ceiling during the hiccup window. Same fail-open class as the
    // trigger-side fix below; bubble DB errors as
    // `CreatorAuthError::Database`.
    let actor_repo_for_ceiling = talos_actor_repository::ActorRepository::new(db_pool.clone());
    let max_world_opt = actor_repo_for_ceiling
        .try_get_actor_max_world(agent_id)
        .await
        .map_err(CreatorAuthError::Database)?;
    if let Some(max_world) = max_world_opt {
        tracing::debug!(
            agent_id = %agent_id,
            max_world = %max_world,
            module_count = module_ids.len(),
            "create_workflow: enforcing capability ceiling"
        );
        if !module_ids.is_empty() {
            let module_worlds_map = workflow_repo
                .get_module_capability_worlds(module_ids)
                .await
                .map_err(CreatorAuthError::Database)?;
            tracing::debug!(
                agent_id = %agent_id,
                found_worlds = module_worlds_map.len(),
                "create_workflow: resolved module capability worlds"
            );
            // Flatten the map to a slice so the pure helper stays
            // slice-based (testable without HashMap). HashMap iteration
            // order is non-deterministic — matches the original
            // handler's `for (mid, world) in &module_worlds` semantics
            // (which was also non-deterministic across rebuilds).
            let module_worlds: Vec<(Uuid, String)> = module_worlds_map.into_iter().collect();
            if let Err(e) = check_capability_ceiling(&max_world, &module_worlds) {
                if let CreatorAuthError::CapabilityCeilingViolation {
                    module_id,
                    module_world,
                    max_world: mw,
                    req_rank,
                    max_rank,
                } = &e
                {
                    tracing::warn!(
                        agent_id = %agent_id,
                        module_id = %module_id,
                        module_world = %module_world,
                        req_rank = req_rank,
                        max_rank = max_rank,
                        max_world = %mw,
                        "create_workflow: BLOCKED — capability ceiling violation"
                    );
                }
                return Err(e);
            }
        }
    }

    Ok(CreatorAuthorization::Authorized { actor_id: agent_id })
}

// ── Trigger-time authorization ───────────────────────────────────────────────
//
// At workflow trigger time we re-run a parallel set of checks. Different from
// creator-time:
//   * Terminal-state rejections (`archived`, `terminated`) get distinct
//     user-facing messages — operators want the difference visible because
//     archived is recoverable via clone, terminated is not.
//   * Budget enforcement runs through `ActorRepository::check_execution_allowed`
//     which is broader than creator-time (per-hour + total + on_budget_exceeded),
//     not just `max_workflow_count`.
//   * Module IDs come from the workflow's stored graph, not a caller-supplied
//     list — so any post-create graph edits are subject to the ceiling.

/// Successful trigger-time authorization outcome. Mirrors
/// [`CreatorAuthorization`] but tagged separately so callers can't
/// accidentally forward a create-time decision into a trigger gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerAuthorization {
    /// `actor_id` was not provided. Trigger proceeds without an owning
    /// actor; no budget or ceiling enforcement applies.
    Unbound,
    /// `actor_id` was verified and within all gates.
    Authorized { actor_id: Uuid },
}

/// Why trigger-time authorization was rejected.
#[derive(Debug)]
pub enum TriggerAuthError {
    /// MCP `-32000`. Actor is in the irreversible `archived` terminal state.
    ActorArchived,
    /// MCP `-32000`. Actor is in the irreversible `terminated` terminal state.
    ActorTerminated,
    /// MCP `-32000`. Actor lookup returned None — either the id doesn't
    /// exist or it belongs to a different user. Single message used by the
    /// handler so the rejection can't enumerate other users' actors.
    ActorNotFoundOrInactive,
    /// MCP `-32000`. `ActorRepository::check_execution_allowed` rejected
    /// the trigger; the inner string carries the user-facing message
    /// (suspended / budget-exhausted / etc.) verbatim.
    ExecutionDenied(String),
    /// MCP `-32003`. A workflow node uses a capability world (e.g. `agent-node`)
    /// that exceeds the actor's `max_capability_world` ceiling. Same shape
    /// as [`CreatorAuthError::CapabilityCeilingViolation`] so the handler
    /// formatting stays consistent.
    CapabilityCeilingViolation {
        module_id: Uuid,
        module_world: String,
        max_world: String,
        req_rank: u8,
        max_rank: u8,
    },
    /// Database failure. Caller maps to generic `database_error`.
    Database(anyhow::Error),
}

/// Allowlist of accepted `trigger_type` values. Synthesized triggers (webhook,
/// scheduler, sub-workflow dispatch) need a stable label so downstream filters
/// can distinguish them from human-driven `manual` runs.
pub const VALID_TRIGGER_TYPES: &[&str] = &[
    "actor_dispatch",
    "agent_dispatch", // legacy alias kept for backward compat with old callers
    "manual",
    "webhook",
    "scheduled",
    "api",
];

/// Pure: resolve `trigger_type` from an optional caller-supplied value plus
/// the actor-bound flag.
///
/// Cascade:
/// 1. Caller supplied a value in [`VALID_TRIGGER_TYPES`] → use it verbatim.
/// 2. Caller supplied an unknown value → reject with `Err(message)` so the
///    handler emits MCP `-32602`.
/// 3. Caller didn't supply → `actor_dispatch` when `has_actor` is true,
///    else `manual`.
///
/// The `Err` variant carries a user-facing string ready to forward; the
/// handler doesn't need to template it.
/// Outcome of a fast actor-dispatch lifecycle check.
///
/// Used by test paths (`test_workflow`, `test_workflow_draft`) that need
/// the same archived/terminated rejection as `authorize_workflow_trigger`
/// but skip budget + capability-ceiling enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ActorDispatchLifecycle {
    /// Actor exists, is owned by the user, and is in a non-terminal status.
    Ok,
    /// Actor row not found, or owned by a different user.
    NotFound,
    /// Actor is in the irreversible `archived` state.
    Archived,
    /// Actor is in the irreversible `terminated` state.
    Terminated,
}

/// Map an actor row's `status` string to an [`ActorDispatchLifecycle`].
///
/// Pure: extracted so the (single) source of "what counts as archived
/// vs terminated vs alive" can be unit-tested without a DB. Any value
/// other than `archived` / `terminated` is treated as `Ok` — this
/// matches the historical handler behavior where `active` / `paused` /
/// other transient states all dispatch normally.
pub fn classify_actor_dispatch_status(status: &str) -> ActorDispatchLifecycle {
    match status {
        "archived" => ActorDispatchLifecycle::Archived,
        "terminated" => ActorDispatchLifecycle::Terminated,
        _ => ActorDispatchLifecycle::Ok,
    }
}

/// Lightweight actor-dispatch lifecycle gate for paths that don't need
/// the full [`authorize_workflow_trigger`] machinery (budget /
/// capability-ceiling enforcement).
///
/// Returns:
/// * `Ok(Ok)` — actor exists, non-terminal, owned by the user.
/// * `Ok(NotFound | Archived | Terminated)` — caller should reject.
/// * `Err(_)` — DB error; caller should surface as a generic db error.
///
/// Mirrors the archived/terminated rejection in
/// `authorize_workflow_trigger` so `test_workflow` and
/// `test_workflow_draft` stay in lockstep with the trigger path.
pub async fn check_actor_dispatch_lifecycle(
    workflow_repo: &WorkflowRepository,
    actor_id: Uuid,
    user_id: Uuid,
) -> Result<ActorDispatchLifecycle> {
    let actor = workflow_repo.get_actor(actor_id, user_id).await?;
    Ok(match actor {
        Some(a) => classify_actor_dispatch_status(&a.status),
        None => ActorDispatchLifecycle::NotFound,
    })
}

pub fn resolve_trigger_type(supplied: Option<&str>, has_actor: bool) -> Result<String, String> {
    match supplied {
        Some(s) if VALID_TRIGGER_TYPES.contains(&s) => Ok(s.to_string()),
        Some(s) => {
            // MCP-1030: cap reflected trigger_type at 64 chars.
            let preview = talos_text_util::bounded_preview(s, 64);
            Err(format!(
                "Invalid trigger_type '{preview}'. Valid values: {}",
                VALID_TRIGGER_TYPES.join(", ")
            ))
        }
        None if has_actor => Ok("actor_dispatch".to_string()),
        None => Ok("manual".to_string()),
    }
}

/// Pure: extract candidate module-id UUIDs from a workflow graph JSON
/// blob. Filters out `system:` nodes (which carry textual types, not
/// UUIDs) and any node whose `type` doesn't parse as a UUID.
///
/// Used by trigger-time authorization to know which modules to ask the
/// repo about for capability-ceiling enforcement. Returns an empty Vec
/// for malformed JSON — trigger-time-auth treats "no modules to check"
/// as a passing ceiling gate, which is correct: an empty / system-only
/// graph fails downstream at engine load with a clearer message.
pub fn extract_graph_module_ids(graph_json: &str) -> Vec<Uuid> {
    serde_json::from_str::<serde_json::Value>(graph_json)
        .ok()
        .and_then(|g| g.get("nodes").and_then(|n| n.as_array()).cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|n| {
            n.get("type")
                .and_then(|t| t.as_str())
                .filter(|s| !s.starts_with("system:"))
                .and_then(|s| s.parse::<Uuid>().ok())
        })
        .collect()
}

/// Run trigger-time authorization checks in sequence:
/// 1. Actor exists, is owned by `user_id`, is not in a terminal state.
/// 2. `ActorRepository::check_execution_allowed` (budget + status broader gate).
/// 3. Every module in the workflow's graph fits under the actor's
///    `max_capability_world` ceiling.
///
/// Returns [`TriggerAuthorization::Unbound`] when `trigger_agent_id` is
/// `None` — manual triggers without an owning actor skip all three gates.
///
/// Mirrors [`authorize_workflow_creator`] in shape; differences are
/// documented at the module level above. Reuses [`check_capability_ceiling`]
/// for the rank comparison so the pure logic is single-sourced.
pub async fn authorize_workflow_trigger(
    workflow_repo: &WorkflowRepository,
    actor_repo: &talos_actor_repository::ActorRepository,
    // MCP-545: `db_pool` is now unused — the capability-ceiling lookup
    // routes through `actor_repo.try_get_actor_max_world` (Result-form)
    // instead of the free-function `get_actor_max_world(db_pool, ...)`
    // which silently fail-OPENED on DB errors. Parameter retained on
    // the signature for backwards compatibility with `trigger.rs` and
    // `mutations.rs` callsites; underscore-prefixed to suppress the
    // unused-arg lint without forcing a churn-PR on every caller.
    _db_pool: &PgPool,
    trigger_agent_id: Option<Uuid>,
    user_id: Uuid,
    graph_json: &str,
) -> Result<TriggerAuthorization, TriggerAuthError> {
    let Some(agent_id) = trigger_agent_id else {
        return Ok(TriggerAuthorization::Unbound);
    };

    // 1. Identity + ownership + terminal-state distinction.
    let actor = workflow_repo
        .get_actor(agent_id, user_id)
        .await
        .map_err(TriggerAuthError::Database)?
        .ok_or(TriggerAuthError::ActorNotFoundOrInactive)?;
    match actor.status.as_str() {
        "archived" => return Err(TriggerAuthError::ActorArchived),
        "terminated" => return Err(TriggerAuthError::ActorTerminated),
        _ => {}
    }

    // 2. Broader execution gate (budget per-hour + total, status). The
    //    inner String is already user-facing — surface it verbatim.
    if let Err(msg) = actor_repo.check_execution_allowed(agent_id).await {
        return Err(TriggerAuthError::ExecutionDenied(msg));
    }

    // 3. Capability ceiling re-verification. Modules come from the
    //    workflow's stored graph (not caller-supplied) — keeps the gate
    //    honest against post-create graph edits.
    //
    // MCP-545: use `try_get_actor_max_world` (Result) instead of the
    // lenient `get_actor_max_world` (returns None on DB error). Pre-fix
    // a transient Postgres error here returned None, which caused this
    // `if let Some(...)` block to be SKIPPED — bypassing the capability
    // ceiling for the actor entirely. An actor with `max_capability_world
    // = http-node` could trigger a workflow containing `agent-node`
    // modules during the hiccup window. Fail-closed: bubble DB errors
    // as `TriggerAuthError::Database` so the trigger refuses cleanly
    // rather than silently downgrading the gate. The `Ok(None)` case
    // (no grant row — permissive default) keeps the existing behaviour.
    let max_world_opt = match actor_repo.try_get_actor_max_world(agent_id).await {
        Ok(opt) => opt,
        Err(e) => return Err(TriggerAuthError::Database(e)),
    };
    if let Some(max_world) = max_world_opt {
        let module_ids = extract_graph_module_ids(graph_json);
        tracing::debug!(
            agent_id = %agent_id,
            max_world = %max_world,
            graph_module_count = module_ids.len(),
            "trigger_workflow: enforcing capability ceiling"
        );
        if !module_ids.is_empty() {
            let module_worlds_map = workflow_repo
                .get_module_capability_worlds(&module_ids)
                .await
                .map_err(TriggerAuthError::Database)?;
            tracing::debug!(
                agent_id = %agent_id,
                found_worlds = module_worlds_map.len(),
                "trigger_workflow: resolved module capability worlds"
            );
            let module_worlds: Vec<(Uuid, String)> = module_worlds_map.into_iter().collect();
            // Reuse the pure check; map CreatorAuthError → TriggerAuthError so
            // the trigger-side error type stays distinct.
            if let Err(creator_err) = check_capability_ceiling(&max_world, &module_worlds) {
                if let CreatorAuthError::CapabilityCeilingViolation {
                    module_id,
                    module_world,
                    max_world,
                    req_rank,
                    max_rank,
                } = creator_err
                {
                    tracing::warn!(
                        agent_id = %agent_id,
                        module_id = %module_id,
                        module_world = %module_world,
                        req_rank = req_rank,
                        max_rank = max_rank,
                        max_world = %max_world,
                        "trigger_workflow: BLOCKED — capability ceiling violation"
                    );
                    return Err(TriggerAuthError::CapabilityCeilingViolation {
                        module_id,
                        module_world,
                        max_world,
                        req_rank,
                        max_rank,
                    });
                }
                // The pure helper only emits CapabilityCeilingViolation, but
                // be explicit so a future variant addition surfaces here.
                unreachable!("check_capability_ceiling only emits CapabilityCeilingViolation");
            }
        }
    }

    Ok(TriggerAuthorization::Authorized { actor_id: agent_id })
}

#[cfg(test)]
mod tests {
    //! Pure-logic tests for [`check_capability_ceiling`].
    //!
    //! The async `authorize_workflow_creator` is integration-tested
    //! end-to-end via the MCP handler suite (testcontainers Postgres);
    //! the unit gate here pins the rank-comparison invariant in
    //! isolation so a tweak to `world_rank`'s table can't silently
    //! invert the gate.
    use super::*;

    fn module(world: &str) -> (Uuid, String) {
        (Uuid::new_v4(), world.to_string())
    }

    #[test]
    fn ceiling_check_passes_when_all_modules_at_or_below_max() {
        let modules = vec![
            module("http-node"),    // rank 1
            module("network-node"), // rank 2
            module("llm-node"),     // rank 2
        ];
        assert!(check_capability_ceiling("network-node", &modules).is_ok());
    }

    #[test]
    fn ceiling_check_passes_at_exact_max() {
        let modules = vec![module("agent-node")]; // rank 6
        assert!(check_capability_ceiling("agent-node", &modules).is_ok());
    }

    #[test]
    fn ceiling_check_rejects_first_violation_with_diagnostic_fields() {
        let lower = (Uuid::new_v4(), "http-node".to_string());
        let violator = (Uuid::new_v4(), "agent-node".to_string());
        let after_violator = (Uuid::new_v4(), "automation-node".to_string());
        let modules = vec![lower, violator.clone(), after_violator];
        let err = check_capability_ceiling("http-node", &modules).unwrap_err();
        let CreatorAuthError::CapabilityCeilingViolation {
            module_id,
            module_world,
            max_world,
            req_rank,
            max_rank,
        } = err
        else {
            panic!("expected CapabilityCeilingViolation, got {:?}", err);
        };
        assert_eq!(module_id, violator.0, "reports first violator");
        assert_eq!(module_world, "agent-node");
        assert_eq!(max_world, "http-node");
        assert_eq!(req_rank, 6, "agent-node rank");
        assert_eq!(max_rank, 1, "http-node rank");
    }

    #[test]
    fn ceiling_check_unknown_world_treated_as_most_privileged() {
        // Defense in depth: a freshly-added world that the rank table
        // hasn't been updated for must NOT silently pass under a
        // tier-1 ceiling. world_rank returns 7 for unknown.
        let modules = vec![module("brand-new-thing-node")];
        let err = check_capability_ceiling("http-node", &modules).unwrap_err();
        match err {
            CreatorAuthError::CapabilityCeilingViolation { req_rank, .. } => {
                assert_eq!(req_rank, 7, "unknown world ranks as max-privileged");
            }
            other => panic!("expected CapabilityCeilingViolation, got {:?}", other),
        }
    }

    #[test]
    fn ceiling_check_empty_module_list_passes() {
        // Workflows with zero module-backed nodes (pure structural)
        // can't violate the ceiling.
        assert!(check_capability_ceiling("http-node", &[]).is_ok());
    }

    /// MCP-461: an actor with a malformed / legacy `max_capability_world`
    /// (not in [`ACTOR_CEILING_WORLDS`]) MUST NOT silently inherit a
    /// tier-7 ceiling. Pre-fix `world_rank("tier1")` returned 7
    /// (unknown=max), so EVERY module's `req_rank > 7` check was false
    /// and the gate let everything through.
    #[test]
    fn ceiling_check_rejects_unknown_actor_world() {
        // Typo / legacy / SQL-injected value — not in ACTOR_CEILING_WORLDS.
        let modules = vec![module("http-node")];
        let err = check_capability_ceiling("tier1", &modules).unwrap_err();
        let CreatorAuthError::CapabilityCeilingViolation {
            max_world,
            max_rank,
            ..
        } = err
        else {
            panic!("expected CapabilityCeilingViolation");
        };
        assert_eq!(
            max_world, "tier1",
            "echoes the unrecognised actor world for operator-visible diagnostics"
        );
        assert_eq!(
            max_rank, 0,
            "unknown actor world is pinned to rank 0 so every module check trips"
        );
    }

    /// MCP-461: even with zero modules in the workflow, an unknown
    /// actor world must reject. Otherwise an actor with a corrupted
    /// ceiling could create empty-shell workflows (which then get
    /// modules added later via add_node_to_workflow) and bypass the
    /// ceiling entirely at create time.
    #[test]
    fn ceiling_check_unknown_actor_world_rejects_empty_workflow() {
        let err = check_capability_ceiling("not-a-real-world", &[]).unwrap_err();
        assert!(matches!(
            err,
            CreatorAuthError::CapabilityCeilingViolation { .. }
        ));
    }

    /// MCP-461: KNOWN actor worlds keep their original behaviour —
    /// empty workflows pass, valid modules within ceiling pass, etc.
    #[test]
    fn ceiling_check_known_actor_worlds_still_work() {
        for world in [
            "minimal-node",
            "http-node",
            "llm-node",
            "agent-node",
            "automation-node",
        ] {
            assert!(
                check_capability_ceiling(world, &[]).is_ok(),
                "known actor world {} should pass with empty modules",
                world
            );
        }
    }

    #[test]
    fn ceiling_check_minimal_world_blocks_everything_else() {
        let modules = vec![module("http-node")];
        let err = check_capability_ceiling("minimal-node", &modules).unwrap_err();
        assert!(matches!(
            err,
            CreatorAuthError::CapabilityCeilingViolation { .. }
        ));
    }

    // ── resolve_trigger_type tests ────────────────────────────────────────

    #[test]
    fn trigger_type_passes_through_valid_supplied_value() {
        assert_eq!(
            resolve_trigger_type(Some("webhook"), false).unwrap(),
            "webhook"
        );
        assert_eq!(
            resolve_trigger_type(Some("scheduled"), true).unwrap(),
            "scheduled"
        );
    }

    #[test]
    fn trigger_type_rejects_unknown_supplied_with_helpful_msg() {
        let err = resolve_trigger_type(Some("totally-bogus"), true).unwrap_err();
        assert!(err.contains("totally-bogus"));
        assert!(err.contains("Valid values"));
        // Allowlist entries appear in the message.
        assert!(err.contains("manual"));
        assert!(err.contains("webhook"));
    }

    #[test]
    fn trigger_type_default_when_actor_bound_is_actor_dispatch() {
        assert_eq!(resolve_trigger_type(None, true).unwrap(), "actor_dispatch");
    }

    #[test]
    fn trigger_type_default_when_no_actor_is_manual() {
        assert_eq!(resolve_trigger_type(None, false).unwrap(), "manual");
    }

    #[test]
    fn trigger_type_legacy_agent_dispatch_alias_passes() {
        // Backward-compat path: callers using the old "agent_dispatch" key
        // should still succeed (no rename forced on them).
        assert_eq!(
            resolve_trigger_type(Some("agent_dispatch"), true).unwrap(),
            "agent_dispatch"
        );
    }

    // ── extract_graph_module_ids tests ────────────────────────────────────

    #[test]
    fn extract_graph_module_ids_returns_uuid_typed_nodes() {
        let mid = Uuid::new_v4();
        let json = serde_json::json!({
            "nodes": [
                { "id": "n1", "type": mid.to_string() },
                { "id": "n2", "type": "system:collect" },
            ]
        })
        .to_string();
        let out = extract_graph_module_ids(&json);
        assert_eq!(out, vec![mid]);
    }

    #[test]
    fn extract_graph_module_ids_skips_system_prefix() {
        let json = serde_json::json!({
            "nodes": [
                { "id": "n1", "type": "system:judge" },
                { "id": "n2", "type": "system:trigger" },
            ]
        })
        .to_string();
        assert!(extract_graph_module_ids(&json).is_empty());
    }

    #[test]
    fn extract_graph_module_ids_skips_non_uuid_types() {
        let json = serde_json::json!({
            "nodes": [
                { "id": "n1", "type": "not-a-uuid" },
                { "id": "n2" },                         // missing type
                { "id": "n3", "type": 42 },             // non-string type
            ]
        })
        .to_string();
        assert!(extract_graph_module_ids(&json).is_empty());
    }

    #[test]
    fn extract_graph_module_ids_returns_empty_on_malformed_json() {
        assert!(extract_graph_module_ids("not json").is_empty());
        assert!(extract_graph_module_ids("{}").is_empty());
        assert!(extract_graph_module_ids(r#"{"nodes": "not-array"}"#).is_empty());
    }

    #[test]
    fn extract_graph_module_ids_preserves_insertion_order() {
        let m1 = Uuid::new_v4();
        let m2 = Uuid::new_v4();
        let json = serde_json::json!({
            "nodes": [
                { "id": "first", "type": m1.to_string() },
                { "id": "skip", "type": "system:collect" },
                { "id": "second", "type": m2.to_string() },
            ]
        })
        .to_string();
        assert_eq!(extract_graph_module_ids(&json), vec![m1, m2]);
    }

    // -- classify_actor_dispatch_status --

    #[test]
    fn classify_archived_status() {
        assert_eq!(
            classify_actor_dispatch_status("archived"),
            ActorDispatchLifecycle::Archived
        );
    }

    #[test]
    fn classify_terminated_status() {
        assert_eq!(
            classify_actor_dispatch_status("terminated"),
            ActorDispatchLifecycle::Terminated
        );
    }

    #[test]
    fn classify_active_status_is_ok() {
        assert_eq!(
            classify_actor_dispatch_status("active"),
            ActorDispatchLifecycle::Ok
        );
    }

    #[test]
    fn classify_paused_status_is_ok() {
        // Paused dispatches normally — the trigger handler returns the
        // user-facing budget message via check_execution_allowed instead.
        assert_eq!(
            classify_actor_dispatch_status("paused"),
            ActorDispatchLifecycle::Ok
        );
    }

    #[test]
    fn classify_unknown_status_is_ok() {
        // Any unknown status defaults to Ok — keeps the gate from
        // false-rejecting on schema additions that haven't shipped here.
        assert_eq!(
            classify_actor_dispatch_status("brand-new-state"),
            ActorDispatchLifecycle::Ok
        );
    }

    #[test]
    fn classify_empty_status_is_ok() {
        assert_eq!(
            classify_actor_dispatch_status(""),
            ActorDispatchLifecycle::Ok
        );
    }
}
