//! Clone an actor — ONE implementation for the MCP `clone_actor` tool and the
//! GraphQL `cloneActor` mutation (package BM, 2026-09-15).
//!
//! The two surfaces had drifted into two different operations under one name.
//! Measured against the MCP handler, the GraphQL mutation — the one the web
//! UI's Actors page and actor summary panel call — did NOT:
//!
//! * check the user's capability ceiling against the source actor's world.
//!   Revoking a user's grant does not lower their existing actors, so a clone
//!   through GraphQL minted a NEW actor above the revoked ceiling, which the
//!   MCP tool refuses;
//! * enforce the per-user actor limit (the atomic INSERT … WHERE count < cap);
//! * copy the source's secret grants, its budget policy (the spend ceiling) or
//!   its approval policies — a dashboard clone of a budgeted actor came up with
//!   no spend limit and no approval gates, and said nothing;
//! * validate the name beyond its length.
//!
//! Latent on the reference fleet (0 clones ever; one user holding the top
//! grant; 5 of 10 actors carry a budget policy that a dashboard clone would
//! have dropped). Every operator-recognised MCP string is kept verbatim.

use talos_actor_repository::ActorRepository;
use uuid::Uuid;

/// The per-user actor cap. Enforced atomically in the INSERT.
pub const MAX_ACTORS_PER_USER: i64 = 1000;

/// Upper bound on the post-clone embedding backfill, and the bound used when
/// the copied-row count is UNKNOWN (an unmeasurable clone still gets a bounded
/// backfill rather than none).
pub const MAX_CLONE_BACKFILL_ROWS: i64 = 10_000;

/// Which surface asked, for the action-log text only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneOrigin {
    Mcp,
    Dashboard,
}

impl CloneOrigin {
    const fn label(self) -> &'static str {
        match self {
            Self::Mcp => "MCP",
            Self::Dashboard => "dashboard",
        }
    }
}

/// One clone request. `new_name: None` means "Copy of <source name>".
#[derive(Debug, Clone)]
pub struct CloneActorRequest {
    pub user_id: Uuid,
    pub source_actor_id: Uuid,
    pub new_name: Option<String>,
    /// Already validated by the caller; `None` inherits the source's.
    pub description_override: Option<String>,
    pub origin: CloneOrigin,
}

/// What a completed clone did. The three copies that run AFTER the actor row
/// commits are `Option`: `None` means the copy could not be measured (the
/// actor exists; the copy may be partial), and `readings` names which.
#[derive(Debug, Clone)]
pub struct CloneActorOutcome {
    pub new_actor_id: Uuid,
    pub name: String,
    pub source_name: String,
    pub max_capability_world: String,
    pub secret_grants_copied: usize,
    pub budget_copied: Option<bool>,
    pub approval_policies_copied: Option<i64>,
    pub memories_copied: Option<i64>,
    pub readings: talos_measurement::Readings,
}

/// Why a clone was refused or failed before the actor row committed.
#[derive(Debug, thiserror::Error)]
pub enum CloneActorError {
    #[error("{0}")]
    InvalidName(&'static str),
    #[error("Source actor not found or access denied")]
    SourceNotFound,
    #[error("could not read the source actor")]
    SourceUnreadable(#[source] anyhow::Error),
    #[error("could not read the user's capability grant")]
    CeilingUnreadable(#[source] anyhow::Error),
    #[error("capability ceiling '{user_ceiling}' does not permit '{source_world}'")]
    CeilingExceeded {
        user_ceiling: String,
        source_world: String,
    },
    #[error("An actor named '{0}' already exists")]
    NameTaken(String),
    #[error("Actor limit reached")]
    LimitReached,
    #[error("clone insert failed")]
    InsertFailed(#[source] anyhow::Error),
}

impl CloneActorError {
    /// Stable JSON-RPC code, verbatim from the pre-extraction MCP handler.
    pub fn jsonrpc_code(&self) -> i32 {
        match self {
            Self::InvalidName(_) | Self::NameTaken(_) | Self::LimitReached => -32602,
            Self::SourceNotFound | Self::InsertFailed(_) | Self::SourceUnreadable(_) => -32000,
            Self::CeilingUnreadable(_) | Self::CeilingExceeded { .. } => -32603,
        }
    }

    /// A policy refusal (as opposed to a failure) — the MCP instrument's
    /// denied/failed split.
    pub fn is_refusal(&self) -> bool {
        matches!(self, Self::SourceNotFound | Self::CeilingExceeded { .. })
    }

    /// Caller-safe text. Internal errors never reach the caller.
    pub fn user_facing_message(&self) -> String {
        match self {
            Self::InvalidName(m) => (*m).to_string(),
            Self::SourceNotFound => "Source actor not found or access denied".to_string(),
            Self::SourceUnreadable(_) => "Database error".to_string(),
            Self::CeilingUnreadable(_) => {
                "Could not verify your capability ceiling — try again.".to_string()
            }
            Self::CeilingExceeded {
                user_ceiling,
                source_world,
            } => format!(
                "Your capability ceiling is '{user_ceiling}'. Cloning an actor with \
                 '{source_world}' requires a higher grant."
            ),
            Self::NameTaken(n) => format!("An actor named '{n}' already exists"),
            Self::LimitReached => {
                "Actor limit reached (1000). Delete unused actors before cloning.".to_string()
            }
            Self::InsertFailed(_) => "Failed to create cloned actor".to_string(),
        }
    }
}

/// The shared actor-name rule (create / update / clone).
pub fn validate_actor_name(name: &str) -> Result<(), &'static str> {
    if name.trim().is_empty() {
        return Err("Actor name must be a non-empty, non-whitespace string");
    }
    if name.len() > 100 {
        return Err("Actor name must be 1–100 characters");
    }
    if talos_validation::reject_control_chars(
        "Actor name",
        name,
        talos_validation::LineMode::SingleLine,
    )
    .is_err()
    {
        return Err("Actor name cannot contain control characters or null bytes");
    }
    Ok(())
}

/// The ordered gates before any write: name, source (ownership), ceiling.
/// Pure over its inputs so the decision is unit-tested without a database.
pub fn check_clone_gates(
    source_name: &str,
    requested_name: Option<&str>,
    source_world: &str,
    user_ceiling: &str,
) -> Result<String, CloneActorError> {
    let name = match requested_name {
        Some(n) => n.to_string(),
        None => format!("Copy of {source_name}"),
    };
    validate_actor_name(&name).map_err(CloneActorError::InvalidName)?;
    if !talos_capability_world::ceiling_permits(user_ceiling, source_world) {
        return Err(CloneActorError::CeilingExceeded {
            user_ceiling: user_ceiling.to_string(),
            source_world: source_world.to_string(),
        });
    }
    Ok(name)
}

/// Clone `req.source_actor_id` for `req.user_id`.
///
/// Order: validate the requested name → read the source (ownership-scoped) →
/// read the user's ceiling (fail closed) → refuse a source above it → atomic
/// limit-checked INSERT carrying the source's world, secret grants and three
/// ceilings → copy budget policy, approval policies and memories (post-commit,
/// each disclosed in `readings` if it could not be measured) → backfill
/// embeddings for copied memories → action log on both actors.
pub async fn clone_actor(
    pool: &sqlx::PgPool,
    actor_repo: &ActorRepository,
    req: CloneActorRequest,
) -> Result<CloneActorOutcome, CloneActorError> {
    if let Some(n) = req.new_name.as_deref() {
        validate_actor_name(n).map_err(CloneActorError::InvalidName)?;
    }
    let source = actor_repo
        .get_source_actor_for_clone(req.source_actor_id, req.user_id)
        .await
        .map_err(CloneActorError::SourceUnreadable)?
        .ok_or(CloneActorError::SourceNotFound)?;
    let user_ceiling = actor_repo
        .user_capability_ceiling(req.user_id)
        .await
        .map_err(CloneActorError::CeilingUnreadable)?;
    let name = check_clone_gates(
        &source.name,
        req.new_name.as_deref(),
        &source.max_capability_world,
        &user_ceiling,
    )?;
    let description = req.description_override.or(source.description.clone());

    let new_actor_id = Uuid::new_v4();
    let rows = actor_repo
        .insert_actor_with_grants_and_limit_check(
            new_actor_id,
            req.user_id,
            &name,
            description.as_deref(),
            &source.max_capability_world,
            &source.secret_grants,
            &source.ceilings,
            MAX_ACTORS_PER_USER,
        )
        .await
        .map_err(|e| {
            let s = e.to_string();
            if s.contains("unique") || s.contains("duplicate") {
                CloneActorError::NameTaken(name.clone())
            } else {
                CloneActorError::InsertFailed(e)
            }
        })?;
    if rows == 0 {
        return Err(CloneActorError::LimitReached);
    }

    // The actor row is committed; a failure below leaves a PARTIAL clone, so
    // each copy is disclosed rather than defaulted (a `false` / `0` would read
    // as "the source had nothing to copy").
    let mut readings = talos_measurement::Readings::new();
    let budget_copied = readings.record(
        "budget_copied",
        actor_repo
            .copy_budget_policy(new_actor_id, req.source_actor_id)
            .await,
    );
    let approval_policies_copied = readings.record(
        "approval_policies_copied",
        actor_repo
            .copy_approval_policies(new_actor_id, req.source_actor_id)
            .await,
    );
    // Semantic + episodic only (working/scratchpad are ephemeral). The same-user
    // gate inside is a tenancy boundary.
    let memories_copied = readings.record(
        "memories_copied",
        actor_repo
            .clone_actor_memories(req.user_id, new_actor_id, req.source_actor_id)
            .await,
    );
    // The bulk copy skips embedding; an UNKNOWN count still backfills, bounded.
    if memories_copied != Some(0) {
        let cap = memories_copied
            .unwrap_or(MAX_CLONE_BACKFILL_ROWS)
            .min(MAX_CLONE_BACKFILL_ROWS);
        let pool = pool.clone();
        tokio::spawn(async move {
            if let Err(e) =
                talos_actor_memory_service::backfill_embeddings_for_actor(&pool, new_actor_id, cap)
                    .await
            {
                tracing::warn!(
                    actor_id = %new_actor_id,
                    error = %e,
                    "clone_actor: post-clone backfill failed"
                );
            }
        });
    }

    let origin = req.origin.label();
    talos_actor_repository::spawn_log_action(
        pool.clone(),
        new_actor_id,
        "created",
        None,
        None,
        match memories_copied {
            Some(n) => format!(
                "Actor '{name}' cloned from '{}' ({n} memories copied) via {origin}",
                source.name
            ),
            None => format!(
                "Actor '{name}' cloned from '{}' (memory copy FAILED — count unknown, not zero) via {origin}",
                source.name
            ),
        },
        Some(serde_json::json!({
            "source_actor_id": req.source_actor_id,
            "max_capability_world": source.max_capability_world,
            "budget_copied": budget_copied,
            "approval_policies_copied": approval_policies_copied,
            "memories_copied": memories_copied,
            "not_measured": readings.not_measured(),
        })),
    );
    talos_actor_repository::spawn_log_action(
        pool.clone(),
        req.source_actor_id,
        "cloned",
        None,
        None,
        format!("Actor cloned as '{name}' via {origin}"),
        Some(serde_json::json!({ "clone_id": new_actor_id })),
    );

    Ok(CloneActorOutcome {
        new_actor_id,
        name,
        source_name: source.name,
        max_capability_world: source.max_capability_world,
        secret_grants_copied: source.secret_grants.len(),
        budget_copied,
        approval_policies_copied,
        memories_copied,
        readings,
    })
}

#[cfg(test)]
mod gate_tests {
    use super::*;

    #[test]
    fn a_source_above_the_user_ceiling_is_refused() {
        let err = check_clone_gates("src", Some("c"), "automation-node", "http-node").unwrap_err();
        assert!(matches!(err, CloneActorError::CeilingExceeded { .. }));
        assert_eq!(err.jsonrpc_code(), -32603);
        assert!(err.is_refusal());
        assert_eq!(
            err.user_facing_message(),
            "Your capability ceiling is 'http-node'. Cloning an actor with 'automation-node' requires a higher grant."
        );
        // CONTROL: within the ceiling passes.
        assert_eq!(
            check_clone_gates("src", Some("c"), "http-node", "automation-node").unwrap(),
            "c"
        );
    }

    #[test]
    fn a_lattice_incomparable_sibling_is_refused() {
        // Neither contains the other: the partial-order gate, not a rank compare.
        assert!(!talos_capability_world::ceiling_permits(
            "database-node",
            "messaging-node"
        ));
        assert!(matches!(
            check_clone_gates("src", None, "messaging-node", "database-node"),
            Err(CloneActorError::CeilingExceeded { .. })
        ));
    }

    #[test]
    fn the_default_name_is_derived_and_validated() {
        assert_eq!(
            check_clone_gates("Research", None, "minimal-node", "http-node").unwrap(),
            "Copy of Research"
        );
        let long = "x".repeat(95);
        assert!(matches!(
            check_clone_gates(&long, None, "minimal-node", "http-node"),
            Err(CloneActorError::InvalidName(_))
        ));
        assert!(matches!(
            check_clone_gates("s", Some("bad\u{0}name"), "minimal-node", "http-node"),
            Err(CloneActorError::InvalidName(_))
        ));
    }

    #[test]
    fn internal_failures_never_reach_the_caller() {
        let e = CloneActorError::InsertFailed(anyhow::anyhow!("relation actors: secret detail"));
        assert_eq!(e.user_facing_message(), "Failed to create cloned actor");
        let e = CloneActorError::SourceUnreadable(anyhow::anyhow!("schema detail"));
        assert_eq!(e.user_facing_message(), "Database error");
        assert!(!e.is_refusal());
    }
}
