/// ActorRepository — centralises all SQL for the actors domain.
///
/// Follows the ExecutionRepository pattern: plain struct, `new(db_pool)`,
/// all methods `pub async fn`, return `anyhow::Result<T>` so callers can `?`.
/// Public enforcement helpers (`check_execution_allowed`, `get_actor_max_world`)
/// are methods on this struct (removing the free-function `&PgPool` parameter).
/// Handlers in `mcp/agents.rs` should be thin wrappers that call these
/// methods and format the JSON-RPC response.
use anyhow::Result;
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::{PgPool, Row};
use std::sync::Arc;
use uuid::Uuid;

pub mod budget_precheck;

// ─────────────────────────────────────────────────────────────────────────────
// Row DTOs
// ─────────────────────────────────────────────────────────────────────────────

/// Duplicated from workflow_repository for use by actor-domain callers.
/// The canonical copy lives in workflow_repository.rs; keep in sync.
#[derive(Debug)]
pub struct ActorRow {
    pub id: Uuid,
    pub name: String,
    pub status: String,
    pub max_workflow_count: Option<i32>,
    pub max_executions_per_hour: Option<i32>,
    pub max_executions_total: Option<i64>,
}

/// Duplicated from workflow_repository for use by actor-domain callers.
#[derive(Debug)]
pub struct ActorMemory {
    pub key: String,
    pub value: serde_json::Value,
}

/// Full actor detail row returned by `get_actor_detail`.
#[derive(Debug)]
pub struct ActorDetail {
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub secret_grants: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
}

/// Summary row returned by `list_actors`.
#[derive(Debug)]
pub struct ActorSummaryRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub workflow_count: i64,
    pub total_executions: i64,
    pub last_active: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

/// Summary row returned by `get_actor_post_mutation_summary` — the columns
/// the GraphQL `ActorSummary` type needs after a create / update / status /
/// clone mutation. Distinct from `ActorSummaryRow` because it also exposes
/// `updated_at` (mutations are timestamped) and lets `status` /
/// `max_capability_world` be NULL so the GraphQL layer can apply its
/// "active" / "minimal-node" defaults uniformly.
#[derive(Debug)]
pub struct ActorPostMutationSummary {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: Option<String>,
    pub max_capability_world: Option<String>,
    pub workflow_count: i64,
    pub total_executions: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Execution stats sub-row returned by `get_actor_execution_stats`.
#[derive(Debug)]
pub struct ActorExecStats {
    pub total: i64,
    pub last_24h: i64,
    pub completed: i64,
    pub failed: i64,
}

/// Budget policy row returned by `get_actor_budget_policy`.
#[derive(Debug)]
pub struct ActorBudgetPolicy {
    pub max_executions_per_hour: Option<i32>,
    pub max_executions_total: Option<i64>,
    pub max_fuel_per_execution: Option<i64>,
    pub max_fuel_per_hour: Option<i64>,
    pub max_outbound_requests_per_hour: Option<i32>,
    pub max_workflow_count: Option<i32>,
    pub max_workflows_per_minute: i32,
    pub max_compilations_per_hour: i32,
    pub on_budget_exceeded: String,
}

/// Budget summary row returned by `get_actor_budget_summary` (used in get_actor_summary).
#[derive(Debug)]
pub struct ActorBudgetSummary {
    pub max_executions_per_hour: Option<i32>,
    pub max_workflow_count: Option<i32>,
    pub on_budget_exceeded: String,
}

/// Approval policy row returned by `list_actor_approval_policies`.
#[derive(Debug)]
pub struct ApprovalPolicyRow {
    pub id: Uuid,
    pub trigger_condition: String,
    pub approval_mode: String,
    pub approvers: Option<Vec<String>>,
    pub created_at: Option<DateTime<Utc>>,
}

/// Action log entry returned by `get_actor_action_log`.
#[derive(Debug)]
pub struct ActionLogEntry {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub action_type: String,
    pub workflow_id: Option<Uuid>,
    pub execution_id: Option<Uuid>,
    pub summary: String,
    pub details: Option<serde_json::Value>,
}

/// Active memory entry returned by `list_actor_memories`.
#[derive(Debug)]
pub struct ActorMemoryEntry {
    pub key: String,
    pub memory_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
    pub value_bytes: i32,
}

/// Active memory value entry returned by `get_actor_memory`.
#[derive(Debug)]
pub struct ActorMemoryValue {
    pub value: serde_json::Value,
    pub memory_type: String,
    pub expires_at: Option<DateTime<Utc>>,
    pub updated_at: DateTime<Utc>,
}

/// Capability grant row returned by `list_capability_grants`.
#[derive(Debug)]
pub struct CapabilityGrantRow {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub max_capability_world: String,
    pub granted_by: Option<Uuid>,
    pub granted_at: DateTime<Utc>,
    pub notes: Option<String>,
}

/// Capability grant detail row returned by `get_user_capability_grant`.
#[derive(Debug)]
pub struct UserCapabilityGrant {
    pub max_capability_world: String,
    pub granted_by: Option<Uuid>,
    pub granted_at: DateTime<Utc>,
    pub notes: Option<String>,
}

/// Source actor row returned by `get_source_actor_for_clone`.
#[derive(Debug)]
pub struct SourceActorCloneRow {
    pub max_capability_world: String,
    pub description: Option<String>,
    pub secret_grants: Vec<String>,
}

/// Lightweight actor projection returned by `get_actor_basic_info` — used by
/// `handle_update_actor` to render its post-update response without re-fetching
/// the full summary.
#[derive(Debug)]
pub struct ActorBasicInfo {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub updated_at: Option<DateTime<Utc>>,
}

/// Compact actor row returned by `list_active_actors_basic` — fields needed
/// by `suggest_actor_for_task` for keyword fallback scoring.
#[derive(Debug)]
pub struct ActorBasicSummary {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub max_capability_world: String,
}

/// Row returned by `find_actors_by_memory_similarity` — actor identity plus
/// the best (max) cosine similarity score across its semantic memories.
#[derive(Debug)]
pub struct ActorMemorySimilarityRow {
    pub actor_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub max_capability_world: String,
    pub best_score: f64,
    pub memory_count: i64,
}

/// Memory row returned by `find_few_shot_examples_*`. `score` is None when
/// the keyword fallback path was used.
#[derive(Debug)]
pub struct MemoryExample {
    pub key: String,
    pub value: serde_json::Value,
    pub memory_type: String,
    pub score: Option<f64>,
}

/// Compact actor row for the A2A agent-card handler.
#[derive(Debug)]
pub struct ActorCardInfo {
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
}

/// Published workflow projection for the A2A agent-card handler.
#[derive(Debug)]
pub struct PublishedWorkflowRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub capabilities: Vec<String>,
}

/// Full actor summary returned by `get_actor_full_summary` — single-query
/// consolidation of actor detail + execution stats + counts + budget policy.
#[derive(Debug)]
pub struct ActorFullSummary {
    // Actor core
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub secret_grants: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub metadata: Option<serde_json::Value>,
    // Execution stats
    pub exec_total: i64,
    pub exec_last_24h: i64,
    pub exec_completed: i64,
    pub exec_failed: i64,
    // Counts
    pub workflow_count: i64,
    pub memory_count: i64,
    pub approval_policy_count: i64,
    // Budget (optional)
    pub budget_max_executions_per_hour: Option<i32>,
    pub budget_max_workflow_count: Option<i32>,
    pub budget_on_exceeded: Option<String>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Repository
// ─────────────────────────────────────────────────────────────────────────────

/// Description stamped on every auto-provisioned default actor (kept in one
/// place so the lazy `insert_default_actor` path and the backfill migration
/// read identically).
const DEFAULT_ACTOR_DESCRIPTION: &str =
    "Auto-provisioned fallback actor — ensures every execution has an owning actor.";

/// True when an `anyhow` error wraps a Postgres unique-constraint violation.
/// Used to distinguish a lost create-race / name collision from a real error
/// in `get_or_create_default_actor`.
fn is_unique_violation(e: &anyhow::Error) -> bool {
    e.downcast_ref::<sqlx::Error>()
        .and_then(|se| se.as_database_error())
        .is_some_and(|db| db.is_unique_violation())
}

pub struct ActorRepository {
    db_pool: PgPool,
    /// Optional SecretsManager — when set, `complete_execution` encrypts
    /// `output_data` at rest the same way `ExecutionRepository::mark_execution_completed`
    /// does. None in test contexts and pre-encryption-wiring construction sites.
    secrets_manager: Option<Arc<talos_secrets_manager::SecretsManager>>,
}

impl ActorRepository {
    pub fn new(db_pool: PgPool) -> Self {
        Self {
            db_pool,
            secrets_manager: None,
        }
    }

    /// Open a write transaction scoped to the creator's **personal org**
    /// (RFC 0006 org-pin / RFC 0005 S3). The `actors` BEFORE-INSERT trigger
    /// `trg_set_org_id` (migration 20260529140000) stamps `org_id` = the
    /// owner's personal org, so creates do NOT bind `org_id` themselves —
    /// this helper only needs to set `app.current_org_id` to that same org so
    /// the org-pin RLS `WITH CHECK` enforces (`org_id = app.current_org_id`)
    /// once the fail-closed flip is on. Both sides resolve the org the same
    /// way (`owner_id = $user AND is_personal`), so they match by
    /// construction. Falls back to a user-scoped tx when the personal org is
    /// absent (the trigger then leaves `org_id` NULL → the policy's
    /// `org_id IS NULL → permit` clause). Latent while `TALOS_RLS_SET_ROLE`
    /// is off (sets the GUCs, no role switch). The caller MUST commit.
    async fn begin_personal_org_write(
        &self,
        user_id: Uuid,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>> {
        let personal_org: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM organizations WHERE owner_id = $1 AND is_personal")
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(match personal_org {
            Some(org) => {
                talos_db::begin_org_scoped(
                    &self.db_pool,
                    &talos_tenancy::OrgScope::new(org, user_id),
                )
                .await?
            }
            None => talos_db::begin_user_scoped(&self.db_pool, user_id).await?,
        })
    }

    /// Builder: attach SecretsManager so output-writing methods encrypt at rest.
    pub fn with_encryption(mut self, sm: Arc<talos_secrets_manager::SecretsManager>) -> Self {
        self.secrets_manager = Some(sm);
        self
    }

    // ── Actor identity ─────────────────────────────────────────────────────

    /// Verify that an actor exists and belongs to the given user.
    /// Returns the actor's UUID on success, or None if not found / access denied.
    pub async fn find_actor_for_user(&self, actor_id: Uuid, user_id: Uuid) -> Result<Option<Uuid>> {
        // RFC 0005 S3: self-scope on a per-user tx so the actors RLS policy
        // backstops this ownership gate for ALL callers (the MCP actor
        // handlers + the GraphQL post-mutation summary), no per-caller
        // change. The query filters `user_id = $2`; the scope mirrors it.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let exists: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM actors WHERE id = $1 AND user_id = $2")
                .bind(actor_id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(exists)
    }

    /// Insert a new actor record. Returns a DB error on unique constraint violation
    /// (caller should check `e.to_string().contains("unique")` for duplicate-name handling).
    pub async fn insert_actor(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        name: &str,
        description: Option<&str>,
        max_capability_world: &str,
    ) -> Result<()> {
        // RFC 0006 / RFC 0005 S3: scope to the owner's personal org so the
        // org-pin WITH CHECK enforces (org_id is trigger-stamped, not bound).
        let mut tx = self.begin_personal_org_write(user_id).await?;
        sqlx::query(
            "INSERT INTO actors (id, user_id, name, description, max_capability_world) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(name)
        .bind(description)
        .bind(max_capability_world)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Find the user's auto-provisioned default actor, if it exists.
    pub async fn find_default_actor(&self, user_id: Uuid) -> Result<Option<Uuid>> {
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let id: Option<Uuid> =
            sqlx::query_scalar("SELECT id FROM actors WHERE user_id = $1 AND is_default LIMIT 1")
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?;
        tx.commit().await?;
        Ok(id)
    }

    /// Insert one default actor (`is_default = true`). Policy defaults
    /// (Tier-2 + network-node) are baked in here so creation is consistent
    /// across the lazy path and the backfill migration. Propagates the raw
    /// error so the caller can distinguish a unique-constraint collision.
    async fn insert_default_actor(&self, actor_id: Uuid, user_id: Uuid, name: &str) -> Result<()> {
        let mut tx = self.begin_personal_org_write(user_id).await?;
        sqlx::query(
            "INSERT INTO actors \
             (id, user_id, name, description, max_capability_world, max_llm_tier, is_default) \
             VALUES ($1, $2, $3, $4, 'network-node', 'tier2', true)",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(name)
        .bind(DEFAULT_ACTOR_DESCRIPTION)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Return the user's default actor id, creating it on first call.
    ///
    /// The default actor is the fallback principal so that every execution has
    /// an owning actor (see [`resolve_effective_actor`]). Idempotent and
    /// race-safe: the `idx_one_default_actor_per_user` partial unique index
    /// guarantees a single winner; a losing racer re-selects the winner's row.
    /// If a *non-default* actor literally named `Default` already occupies the
    /// `(user_id, name)` slot, this falls back to a uniquely-named default.
    ///
    /// [`resolve_effective_actor`]: Self::resolve_effective_actor
    pub async fn get_or_create_default_actor(&self, user_id: Uuid) -> Result<Uuid> {
        if let Some(id) = self.find_default_actor(user_id).await? {
            return Ok(id);
        }
        let actor_id = Uuid::new_v4();
        match self
            .insert_default_actor(actor_id, user_id, "Default")
            .await
        {
            Ok(()) => Ok(actor_id),
            Err(e) if is_unique_violation(&e) => {
                // Either another racer created the default (partial-default
                // index), or a non-default actor named 'Default' holds the
                // (user_id, name) slot. Prefer an existing default…
                if let Some(id) = self.find_default_actor(user_id).await? {
                    return Ok(id);
                }
                // …otherwise it was the name collision — retry once, unique name.
                let alt = Uuid::new_v4();
                let alt_name = format!("Default ({})", &alt.to_string()[..8]);
                self.insert_default_actor(alt, user_id, &alt_name).await?;
                Ok(alt)
            }
            Err(e) => Err(e),
        }
    }

    /// Resolve the effective actor for a dispatch: the caller's explicit actor
    /// if supplied, otherwise the user's default actor. NEVER returns `None` —
    /// this is the core of "every execution gets an actor". Callers that today
    /// pass `actor_id: None` into a job/execution should route through here.
    pub async fn resolve_effective_actor(
        &self,
        user_id: Uuid,
        explicit: Option<Uuid>,
    ) -> Result<Uuid> {
        match explicit {
            Some(a) => Ok(a),
            None => self.get_or_create_default_actor(user_id).await,
        }
    }

    /// List actors for a user with optional status and inactivity filters.
    pub async fn list_actors(
        &self,
        user_id: Uuid,
        status_filter: Option<&str>,
        inactive_days: Option<i64>,
    ) -> Result<Vec<ActorSummaryRow>> {
        // RFC 0005 S3: self-scope (see find_actor_for_user). The
        // actors/workflows/workflow_executions joins all pick up the
        // backstop; the query already filters `a.user_id = $1`.
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let rows = sqlx::query(
            "SELECT a.id, a.name, a.description, a.status, a.max_capability_world, a.created_at,
                    COUNT(DISTINCT w.id)  AS workflow_count,
                    COUNT(DISTINCT e.id)  AS total_executions,
                    MAX(e.started_at)     AS last_active
             FROM actors a
             LEFT JOIN workflows w           ON w.actor_id = a.id
             LEFT JOIN workflow_executions e ON e.actor_id = a.id
             WHERE a.user_id = $1
               AND ($2::text IS NULL OR a.status = $2)
             GROUP BY a.id
             HAVING ($3::bigint IS NULL
                  OR MAX(e.started_at) < now() - make_interval(days => $3::int)
                  OR MAX(e.started_at) IS NULL)
             ORDER BY a.created_at DESC",
        )
        .bind(user_id)
        .bind(status_filter)
        .bind(inactive_days)
        .fetch_all(&mut *tx)
        .await?;
        tx.commit().await?;

        let result = rows
            .iter()
            .map(|r| ActorSummaryRow {
                id: r.get("id"),
                name: r.get("name"),
                description: r.get("description"),
                status: r.get("status"),
                max_capability_world: r.get("max_capability_world"),
                workflow_count: r.get("workflow_count"),
                total_executions: r.get("total_executions"),
                last_active: r.get("last_active"),
                created_at: r.get("created_at"),
            })
            .collect();
        Ok(result)
    }

    /// Fetch full actor detail (name, description, status, capability world, grants, metadata).
    pub async fn get_actor_detail(&self, actor_id: Uuid) -> Result<Option<ActorDetail>> {
        let row = sqlx::query(
            "SELECT name, description, status, max_capability_world, secret_grants, created_at, metadata \
             FROM actors WHERE id = $1",
        )
        .bind(actor_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| ActorDetail {
            name: r.get("name"),
            description: r.get("description"),
            status: r.get("status"),
            max_capability_world: r.get("max_capability_world"),
            secret_grants: r.get("secret_grants"),
            created_at: r.get("created_at"),
            metadata: r.get("metadata"),
        }))
    }

    /// Re-fetch the columns the GraphQL `ActorSummary` type needs after a
    /// mutation (create / update / status / clone). Returns `None` iff the
    /// `(actor_id, user_id)` pair doesn't match — caller should treat that as
    /// "not found / access denied" identically to the way the original
    /// inline `WHERE id = $1 AND user_id = $2` did.
    ///
    /// `workflow_count` and `total_executions` are computed via correlated
    /// subqueries — same shape the inline copies used pre-extraction so the
    /// row-count / cost is bit-identical. Both `(actor_id)` indexes already
    /// exist (`workflows.actor_id`, `workflow_executions.workflow_id` ->
    /// `workflows.actor_id`) so the subqueries are index-only scans.
    pub async fn get_actor_post_mutation_summary(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ActorPostMutationSummary>> {
        // RFC 0005 S3: self-scope (see find_actor_for_user). Real org
        // visibility isn't needed — the actor + its count subqueries are
        // all the caller's own (a.user_id = $2).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let row = sqlx::query(
            "SELECT a.id, a.name, a.description, a.status, a.max_capability_world, \
                    a.created_at, a.updated_at, \
                    (SELECT COUNT(*) FROM workflows w WHERE w.actor_id = a.id) AS workflow_count, \
                    (SELECT COUNT(*) FROM workflow_executions we \
                     JOIN workflows w ON w.id = we.workflow_id \
                     WHERE w.actor_id = a.id) AS total_executions \
             FROM actors a WHERE a.id = $1 AND a.user_id = $2",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;

        Ok(row.map(|r| ActorPostMutationSummary {
            id: r.get("id"),
            name: r.get("name"),
            description: r.get("description"),
            status: r.get("status"),
            max_capability_world: r.get("max_capability_world"),
            workflow_count: r.get::<Option<i64>, _>("workflow_count").unwrap_or(0),
            total_executions: r.get::<Option<i64>, _>("total_executions").unwrap_or(0),
            created_at: r.get("created_at"),
            updated_at: r.get("updated_at"),
        }))
    }

    /// Fetch a full summary of an actor in a single query using LATERAL joins.
    /// Replaces what was previously 6 sequential queries.
    pub async fn get_actor_full_summary(&self, actor_id: Uuid) -> Result<Option<ActorFullSummary>> {
        let row = sqlx::query(
            "SELECT a.name, a.description, a.status, a.max_capability_world, \
                    a.secret_grants, a.created_at, a.metadata, \
                    COALESCE(e.total, 0)        AS exec_total, \
                    COALESCE(e.last_24h, 0)     AS exec_last_24h, \
                    COALESCE(e.completed, 0)    AS exec_completed, \
                    COALESCE(e.failed, 0)       AS exec_failed, \
                    COALESCE(w.cnt, 0)          AS workflow_count, \
                    COALESCE(m.cnt, 0)          AS memory_count, \
                    bp.max_executions_per_hour, bp.max_workflow_count, bp.on_budget_exceeded, \
                    COALESCE(ap.cnt, 0)         AS approval_policy_count \
             FROM actors a \
             LEFT JOIN LATERAL ( \
                 SELECT COUNT(*)                                                         AS total, \
                        COUNT(*) FILTER (WHERE started_at > now() - INTERVAL '24 hours') AS last_24h, \
                        COUNT(*) FILTER (WHERE status = 'completed')                      AS completed, \
                        COUNT(*) FILTER (WHERE status = 'failed')                         AS failed \
                 FROM workflow_executions WHERE actor_id = a.id \
             ) e ON true \
             LEFT JOIN LATERAL ( \
                 SELECT COUNT(*) AS cnt FROM workflows \
                 WHERE actor_id = a.id AND (status IS NULL OR status != 'archived') \
             ) w ON true \
             LEFT JOIN LATERAL ( \
                 SELECT COUNT(*) AS cnt FROM actor_memory \
                 WHERE actor_id = a.id AND (expires_at IS NULL OR expires_at > now()) \
             ) m ON true \
             LEFT JOIN actor_budget_policies bp ON bp.actor_id = a.id \
             LEFT JOIN LATERAL ( \
                 SELECT COUNT(*) AS cnt FROM actor_approval_policies WHERE actor_id = a.id \
             ) ap ON true \
             WHERE a.id = $1",
        )
        .bind(actor_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| ActorFullSummary {
            name: r.get("name"),
            description: r.get("description"),
            status: r.get("status"),
            max_capability_world: r.get("max_capability_world"),
            secret_grants: r.get("secret_grants"),
            created_at: r.get("created_at"),
            metadata: r.get("metadata"),
            exec_total: r.get("exec_total"),
            exec_last_24h: r.get("exec_last_24h"),
            exec_completed: r.get("exec_completed"),
            exec_failed: r.get("exec_failed"),
            workflow_count: r.get("workflow_count"),
            memory_count: r.get("memory_count"),
            approval_policy_count: r.get("approval_policy_count"),
            budget_max_executions_per_hour: r.get("max_executions_per_hour"),
            budget_max_workflow_count: r.get("max_workflow_count"),
            budget_on_exceeded: r.get("on_budget_exceeded"),
        }))
    }

    /// Fetch just the status column for a given actor (used for terminal-state checks).
    pub async fn get_actor_status(&self, actor_id: Uuid) -> Result<Option<String>> {
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(status)
    }

    /// Fetch the status of an actor that must also belong to a given user.
    pub async fn get_actor_status_for_user(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        // RFC 0005 S3: self-scope (see find_actor_for_user).
        let mut tx = talos_db::begin_user_scoped(&self.db_pool, user_id).await?;
        let status: Option<String> =
            sqlx::query_scalar("SELECT status FROM actors WHERE id = $1 AND user_id = $2")
                .bind(actor_id)
                .bind(user_id)
                .fetch_optional(&mut *tx)
                .await?
                .flatten();
        tx.commit().await?;
        Ok(status)
    }

    /// True if the user is a designated platform admin
    /// (cross-tenant operator). Sources the `users.is_platform_admin`
    /// column added by migration `20260506110000` (M T6-1). The
    /// backfill on that migration seeded the flag for every user
    /// already holding `role IN ('owner','admin')` on any
    /// organisation — single-tenant deployments retain their
    /// pre-existing behavior. Multi-tenant deployments can now
    /// distinguish "admin of one org" from "operator of the
    /// platform" so DLQ subscriptions, master-key rotations, and
    /// capability-ceiling grants don't leak cross-tenant.
    ///
    /// Returns `Ok(false)` for unknown users — callers should treat
    /// the "no row found" case identically to "not an admin".
    pub async fn is_platform_admin(&self, user_id: Uuid) -> Result<bool> {
        // `query_scalar` with `Option<bool>` distinguishes "no user
        // row" (returns None → false) from "row exists, value is
        // false" (returns Some(false) → false). Both surfaces fail
        // closed which is the right default.
        let flag: Option<bool> =
            sqlx::query_scalar("SELECT is_platform_admin FROM users WHERE id = $1")
                .bind(user_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(flag.unwrap_or(false))
    }

    // MCP-595 (2026-05-12): `is_org_admin` deleted. It was dead
    // code (zero callers workspace-wide) AND carried a latent bug
    // — the query referenced `organization_id` but the actual
    // column is `org_id`, so the function would have failed at
    // runtime if ever called. The talos-actor-repository review
    // (`reviews/talos-actor-repository.md`) listed this deletion
    // as one of the 7 LOWs but the function survived a previous
    // pass. The canonical org-admin gate lives in
    // `talos-organizations::OrganizationService::check_org_access`
    // (which uses the correct column name); the platform-admin
    // gate is `Self::is_platform_admin`. Future callers needing
    // either should reach for those, not a sibling local helper.

    /// Set an actor's status to 'suspended', scoped to the requesting user.
    ///
    /// L T4-2: SQL gate on `user_id` is defense-in-depth. Every current
    /// caller already verifies ownership via `resolve_actor_via_repo`,
    /// but a future caller bypassing the resolver would otherwise mutate
    /// the wrong row. Returns rows_affected so callers detect the
    /// not-found / cross-tenant case (== 0).
    ///
    /// MCP-646 (2026-05-13): SQL gate also refuses transitions out of
    /// terminal states. Sibling fix to MCP-645 — `handle_suspend_actor`
    /// had the same `get_actor_status(...).await.unwrap_or(None)`
    /// fail-OPEN, and the IRREVERSIBLE doc string for archive/terminate
    /// was actually reversible via a DB hiccup that bypassed the
    /// handler-side guard. Closing at the repo SQL layer makes the
    /// guarantee unconditional.
    pub async fn suspend_actor(&self, actor_id: Uuid, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE actors SET status = 'suspended', updated_at = now() \
             WHERE id = $1 AND user_id = $2 \
             AND status NOT IN ('archived', 'terminated')",
        )
        .bind(actor_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Set an actor's status to 'terminated', scoped to the requesting user.
    /// L T4-2: same defense-in-depth as `suspend_actor`.
    pub async fn terminate_actor(&self, actor_id: Uuid, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE actors SET status = 'terminated', updated_at = now() \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(actor_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Set an actor's status to 'archived', but only if it is not already 'terminated'.
    /// Scoped to the requesting user (L T4-2).
    /// Returns the number of rows affected (0 if actor was already terminated, not found,
    /// or owned by another user).
    pub async fn archive_actor(&self, actor_id: Uuid, user_id: Uuid) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE actors SET status = 'archived', updated_at = now() \
             WHERE id = $1 AND user_id = $2 AND status != 'terminated'",
        )
        .bind(actor_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Update actor status to an arbitrary value (used by update_actor_status handler
    /// for 'active'/'suspended' transitions after terminal-state guard has run).
    /// Scoped to the requesting user (L T4-2).
    ///
    /// MCP-645 (2026-05-13): SQL gate now refuses transitions OUT of
    /// terminal states (`archived` / `terminated`) at the repo layer.
    /// Pre-fix the only terminal-state guard lived in the MCP handler
    /// via `get_actor_status(...).await.unwrap_or(None)`. A DB hiccup
    /// during that lookup returned None, fell through to the catch-all
    /// match arm with no terminal-state error, and the repo SQL
    /// (which had no NOT IN guard) happily set an archived actor's
    /// status back to 'active'. Defense-in-depth at the repo layer
    /// closes that fail-OPEN. Sibling pattern to L T4-2 (SQL-side
    /// `user_id` gating).
    pub async fn update_actor_status(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        new_status: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE actors SET status = $1, updated_at = now() \
             WHERE id = $2 AND user_id = $3 \
             AND status NOT IN ('archived', 'terminated')",
        )
        .bind(new_status)
        .bind(actor_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Count workflows owned by an actor that are not yet archived.
    pub async fn count_active_workflows_for_actor(&self, actor_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflows WHERE actor_id = $1 \
             AND (status IS NULL OR status != 'archived')",
        )
        .bind(actor_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    /// Archive all non-archived workflows owned by actor. Returns the count of rows archived.
    /// Scoped to the requesting user (L T4-2) — only workflows whose owning actor
    /// belongs to this user can be archived through this path.
    pub async fn archive_actor_workflows(&self, actor_id: Uuid, user_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "WITH updated AS (
                UPDATE workflows SET status = 'archived', updated_at = now()
                WHERE actor_id = $1
                  AND (status IS NULL OR status != 'archived')
                  AND EXISTS (SELECT 1 FROM actors WHERE id = $1 AND user_id = $2)
                RETURNING 1
             ) SELECT COUNT(*) FROM updated",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    // ── Secret grants ──────────────────────────────────────────────────────

    /// Append a key_path to an actor's secret_grants array, skipping if already present.
    /// Scoped to the requesting user (L T4-2). Returns rows_affected so callers can
    /// detect not-found / cross-tenant (== 0) vs already-granted (== 0 too — combine
    /// with a pre-check if the distinction matters).
    pub async fn grant_secret_access(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        key_path: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE actors \
             SET secret_grants = array_append(secret_grants, $1), updated_at = now() \
             WHERE id = $2 \
               AND user_id = $3 \
               AND NOT ($1 = ANY(secret_grants))",
        )
        .bind(key_path)
        .bind(actor_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    // ── Budget policies ────────────────────────────────────────────────────

    /// Upsert the budget policy for an actor.
    ///
    /// L T4-2: scoped to the requesting user via an `INSERT ... SELECT
    /// ... WHERE EXISTS` gate. The `actor_budget_policies` table is
    /// keyed on `actor_id` (no `user_id` column), so the gate verifies
    /// the actor belongs to `user_id` via a correlated subquery.
    /// Returns rows_affected so callers can detect not-found /
    /// cross-tenant (== 0).
    #[allow(clippy::too_many_arguments)]
    pub async fn upsert_actor_budget(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        max_executions_per_hour: Option<i32>,
        max_executions_total: Option<i64>,
        max_fuel_per_execution: Option<i64>,
        max_fuel_per_hour: Option<i64>,
        max_outbound_requests_per_hour: Option<i32>,
        max_workflow_count: Option<i32>,
        max_workflows_per_minute: i32,
        max_compilations_per_hour: i32,
        on_budget_exceeded: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "INSERT INTO actor_budget_policies \
             (actor_id, max_executions_per_hour, max_executions_total, max_fuel_per_execution, \
              max_fuel_per_hour, max_outbound_requests_per_hour, max_workflow_count, \
              max_workflows_per_minute, max_compilations_per_hour, on_budget_exceeded, updated_at) \
             SELECT $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, now() \
             WHERE EXISTS (SELECT 1 FROM actors WHERE id = $1 AND user_id = $2) \
             ON CONFLICT (actor_id) DO UPDATE SET \
                 max_executions_per_hour        = EXCLUDED.max_executions_per_hour, \
                 max_executions_total           = EXCLUDED.max_executions_total, \
                 max_fuel_per_execution         = EXCLUDED.max_fuel_per_execution, \
                 max_fuel_per_hour              = EXCLUDED.max_fuel_per_hour, \
                 max_outbound_requests_per_hour = EXCLUDED.max_outbound_requests_per_hour, \
                 max_workflow_count             = EXCLUDED.max_workflow_count, \
                 max_workflows_per_minute       = EXCLUDED.max_workflows_per_minute, \
                 max_compilations_per_hour      = EXCLUDED.max_compilations_per_hour, \
                 on_budget_exceeded             = EXCLUDED.on_budget_exceeded, \
                 updated_at                     = now()",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(max_executions_per_hour)
        .bind(max_executions_total)
        .bind(max_fuel_per_execution)
        .bind(max_fuel_per_hour)
        .bind(max_outbound_requests_per_hour)
        .bind(max_workflow_count)
        .bind(max_workflows_per_minute)
        .bind(max_compilations_per_hour)
        .bind(on_budget_exceeded)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Fetch the full budget policy for an actor (all columns).
    pub async fn get_actor_budget_policy(
        &self,
        actor_id: Uuid,
    ) -> Result<Option<ActorBudgetPolicy>> {
        let row = sqlx::query(
            "SELECT max_executions_per_hour, max_executions_total, max_fuel_per_execution, \
                    max_fuel_per_hour, max_outbound_requests_per_hour, max_workflow_count, \
                    max_workflows_per_minute, max_compilations_per_hour, on_budget_exceeded \
             FROM actor_budget_policies WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| ActorBudgetPolicy {
            max_executions_per_hour: r.get("max_executions_per_hour"),
            max_executions_total: r.get("max_executions_total"),
            max_fuel_per_execution: r.get("max_fuel_per_execution"),
            max_fuel_per_hour: r.get("max_fuel_per_hour"),
            max_outbound_requests_per_hour: r.get("max_outbound_requests_per_hour"),
            max_workflow_count: r.get("max_workflow_count"),
            max_workflows_per_minute: r.get("max_workflows_per_minute"),
            max_compilations_per_hour: r.get("max_compilations_per_hour"),
            on_budget_exceeded: r.get("on_budget_exceeded"),
        }))
    }

    /// Fetch the budget summary columns used by get_actor_summary
    /// (only the three fields rendered in that handler's budget_summary JSON).
    pub async fn get_actor_budget_summary(
        &self,
        actor_id: Uuid,
    ) -> Result<Option<ActorBudgetSummary>> {
        let row = sqlx::query(
            "SELECT max_executions_per_hour, max_workflow_count, on_budget_exceeded \
             FROM actor_budget_policies WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| ActorBudgetSummary {
            max_executions_per_hour: r.get("max_executions_per_hour"),
            max_workflow_count: r.get("max_workflow_count"),
            on_budget_exceeded: r.get("on_budget_exceeded"),
        }))
    }

    /// Count executions for an actor in the rolling last hour.
    pub async fn count_executions_last_hour(&self, actor_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM workflow_executions \
             WHERE actor_id = $1 AND started_at > now() - INTERVAL '1 hour'",
        )
        .bind(actor_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    /// Count total lifetime executions for an actor.
    pub async fn count_total_executions(&self, actor_id: Uuid) -> Result<i64> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM workflow_executions WHERE actor_id = $1")
                .bind(actor_id)
                .fetch_one(&self.db_pool)
                .await?;
        Ok(count)
    }

    /// Look up the owning `user_id` for an actor by id. Returns
    /// `Ok(None)` when the actor doesn't exist. Used by the budget
    /// auto-suspend path in `talos-mcp-handlers/src/actor.rs` to
    /// satisfy the L T4-2 SQL ownership gate without inlining a raw
    /// `SELECT user_id FROM actors` (which the structural lint flags).
    pub async fn get_actor_owner_user_id(&self, actor_id: Uuid) -> Result<Option<Uuid>> {
        let owner: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(owner)
    }

    /// Fetch execution trend for the last 7 days (date + count pairs).
    pub async fn get_execution_trend_7d(&self, actor_id: Uuid) -> Result<Vec<(NaiveDate, i64)>> {
        let rows: Vec<(NaiveDate, i64)> = sqlx::query_as(
            "SELECT DATE_TRUNC('day', started_at)::date AS exec_day, COUNT(*) AS exec_count \
             FROM workflow_executions \
             WHERE actor_id = $1 AND started_at > NOW() - INTERVAL '7 days' \
             GROUP BY exec_day \
             ORDER BY exec_day DESC",
        )
        .bind(actor_id)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows)
    }

    // ── Actor summary helpers ─────────────────────────────────────────────

    /// Aggregate execution stats for get_actor_summary.
    pub async fn get_actor_execution_stats(&self, actor_id: Uuid) -> Result<ActorExecStats> {
        let row = sqlx::query(
            "SELECT COUNT(*)                                                         AS total,
                    COUNT(*) FILTER (WHERE started_at > now() - INTERVAL '24 hours') AS last_24h,
                    COUNT(*) FILTER (WHERE status = 'completed')                      AS completed,
                    COUNT(*) FILTER (WHERE status = 'failed')                         AS failed
             FROM workflow_executions WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row
            .map(|r| ActorExecStats {
                total: r.get("total"),
                last_24h: r.get("last_24h"),
                completed: r.get("completed"),
                failed: r.get("failed"),
            })
            .unwrap_or(ActorExecStats {
                total: 0,
                last_24h: 0,
                completed: 0,
                failed: 0,
            }))
    }

    // Actor memory helpers moved to `crate::actor_memory_service`. All memory
    // reads, writes, forget, and search go through one code path there so
    // embeddings + graph extraction stay consistent.

    /// Count approval policies for an actor.
    pub async fn count_actor_approval_policies(&self, actor_id: Uuid) -> Result<i64> {
        let count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM actor_approval_policies WHERE actor_id = $1")
                .bind(actor_id)
                .fetch_one(&self.db_pool)
                .await?;
        Ok(count)
    }

    // ── Approval policies ──────────────────────────────────────────────────

    /// Insert an approval policy for an actor.
    pub async fn insert_actor_approval_policy(
        &self,
        policy_id: Uuid,
        actor_id: Uuid,
        trigger_condition: &str,
        approval_mode: &str,
        approvers: Option<Vec<String>>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO actor_approval_policies (id, actor_id, trigger_condition, approval_mode, approvers) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(policy_id)
        .bind(actor_id)
        .bind(trigger_condition)
        .bind(approval_mode)
        .bind(approvers)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// List all approval policies for an actor ordered by creation time.
    pub async fn list_actor_approval_policies(
        &self,
        actor_id: Uuid,
    ) -> Result<Vec<ApprovalPolicyRow>> {
        let rows = sqlx::query(
            "SELECT id, trigger_condition, approval_mode, approvers, created_at \
             FROM actor_approval_policies WHERE actor_id = $1 ORDER BY created_at",
        )
        .bind(actor_id)
        .fetch_all(&self.db_pool)
        .await?;

        let result = rows
            .iter()
            .map(|r| ApprovalPolicyRow {
                id: r.get("id"),
                trigger_condition: r.get("trigger_condition"),
                approval_mode: r.get("approval_mode"),
                approvers: r.get("approvers"),
                created_at: r.get("created_at"),
            })
            .collect();
        Ok(result)
    }

    /// Delete an approval policy, verifying ownership through the actor → user chain.
    /// Returns the number of rows deleted (0 = not found or access denied).
    pub async fn delete_actor_approval_policy(
        &self,
        policy_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query(
            "DELETE FROM actor_approval_policies p \
             USING actors a \
             WHERE p.id = $1 AND p.actor_id = a.id AND a.user_id = $2",
        )
        .bind(policy_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Delete an approval policy and RETURN the affected `actor_id`
    /// (if any) so the caller can invalidate that actor's policy
    /// cache. Returns `None` when no row matched.
    ///
    /// Cleaner than `delete_actor_approval_policy` + a separate
    /// SELECT — the RETURNING avoids the extra round-trip.
    pub async fn delete_actor_approval_policy_returning_actor(
        &self,
        policy_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let row: Option<(Uuid,)> = sqlx::query_as(
            "DELETE FROM actor_approval_policies p \
             USING actors a \
             WHERE p.id = $1 AND p.actor_id = a.id AND a.user_id = $2 \
             RETURNING p.actor_id",
        )
        .bind(policy_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|(actor_id,)| actor_id))
    }

    // ── Action log ─────────────────────────────────────────────────────────

    /// Insert an action log entry.
    ///
    /// MCP-979 (2026-05-15): defence-in-depth DLP redact at the
    /// persistence boundary, same fix as MCP-978 applied here for
    /// `insert_admin_event_log`'s sibling. The canonical caller
    /// `spawn_log_action` (line ~2276/2285) already redacts upstream,
    /// but this method is `pub` and the pre-fix doc-comment said
    /// "Caller is responsible for DLP redaction before calling" —
    /// caller-discipline contract is exactly the brittle pattern
    /// MCP-967..978 closed across the workspace. Redact_str /
    /// redact_json are infallible and idempotent; the wrapper's
    /// redaction stays correct and the surface no longer depends on
    /// caller behaviour.
    pub async fn insert_action_log_entry(
        &self,
        actor_id: Uuid,
        action_type: &str,
        workflow_id: Option<Uuid>,
        execution_id: Option<Uuid>,
        summary: &str,
        details: Option<&serde_json::Value>,
    ) -> Result<()> {
        // MCP-1104 (2026-05-16): truncate-then-redact at the helper
        // boundary. The `spawn_log_action` wrapper above (line ~2299)
        // already truncates to 1000 chars BEFORE spawn — but direct
        // callers of this helper (talos-actor-policies::evaluator,
        // talos-mcp-handlers paths) bypass that wrapper and bound the
        // input only by convention (callers pass fixed-shape
        // format!() strings). A future caller passing dynamic
        // user-supplied content would land a multi-MB row in
        // `actor_action_log.summary`, hitting both the DLP regex pass
        // cost AND unbounded persistence — sibling-pattern violation
        // of MCP-1012 / MCP-1018 / MCP-1027 truncate-then-redact
        // discipline. Cap at the helper so the contract is enforced
        // workspace-wide regardless of caller behaviour.
        let truncated_summary = truncate_summary_at_boundary(summary);
        let redacted_summary = talos_dlp_provider::redact_str(&truncated_summary);
        // MCP-1195 (2026-05-17): cap `details` JSONB at 1 MiB BEFORE
        // redact_json. Pre-fix `details.map(redact_json)` paid the
        // full O(N × pattern_count) regex pass on every input — a
        // multi-MB details blob from a misbehaving caller forced an
        // expensive scan AND landed unbounded in
        // `actor_action_log.details` (JSONB column, ~1 GB Postgres
        // limit). Same measure-first-then-redact discipline as
        // MCP-1162 (workflow_execution_logs.metadata) and sibling
        // truncate-first sweep MCP-1160..1167/1181/1193/1194. 1 MiB
        // matches the canonical structured-log-metadata cap.
        let redacted_details = bound_log_details(details);
        sqlx::query(
            "INSERT INTO actor_action_log \
             (actor_id, action_type, workflow_id, execution_id, summary, details) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(actor_id)
        .bind(action_type)
        .bind(workflow_id)
        .bind(execution_id)
        .bind(&redacted_summary)
        .bind(redacted_details.as_ref())
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Fetch actor action log entries with optional timestamp and action-type filters.
    pub async fn get_actor_action_log(
        &self,
        actor_id: Uuid,
        limit: i32,
        since: Option<DateTime<Utc>>,
        action_type_filter: Option<&str>,
    ) -> Result<Vec<ActionLogEntry>> {
        let rows = sqlx::query(
            "SELECT id, timestamp, action_type, workflow_id, execution_id, summary, details \
             FROM actor_action_log \
             WHERE actor_id = $1 \
               AND ($2::timestamptz IS NULL OR timestamp > $2) \
               AND ($3::text IS NULL OR action_type = $3) \
             ORDER BY timestamp DESC \
             LIMIT $4",
        )
        .bind(actor_id)
        .bind(since)
        .bind(action_type_filter)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        let result = rows
            .iter()
            .map(|r| ActionLogEntry {
                id: r.get("id"),
                timestamp: r.get("timestamp"),
                action_type: r.get("action_type"),
                workflow_id: r.get("workflow_id"),
                execution_id: r.get("execution_id"),
                summary: r.get("summary"),
                details: r.get("details"),
            })
            .collect();
        Ok(result)
    }

    // Actor memory read/write/forget/list helpers moved to
    // `crate::actor_memory_service`. See the module docs there.

    // ── Handoff helpers ────────────────────────────────────────────────────

    /// Fetch the graph_json for a workflow that belongs to a given user and is not archived.
    pub async fn get_workflow_graph_for_user(
        &self,
        workflow_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<String>> {
        let graph_json: Option<String> = sqlx::query_scalar(
            "SELECT graph_json FROM workflows WHERE id = $1 AND user_id = $2 \
             AND (status IS NULL OR status != 'archived')",
        )
        .bind(workflow_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(graph_json)
    }

    /// Fetch the active workflow version ID for a workflow.
    pub async fn get_active_workflow_version_id(&self, workflow_id: Uuid) -> Result<Option<Uuid>> {
        let version_id: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM workflow_versions WHERE workflow_id = $1 AND is_active = true",
        )
        .bind(workflow_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(version_id)
    }

    /// Resolve root_execution_id for a parent execution (application-level lineage).
    /// If the parent has a root_execution_id, returns it; otherwise returns the parent id itself.
    ///
    /// L T4-4 — distinguishes "parent IS its own root" (Ok(_) → Some(parent_exec_id))
    /// from "DB error" (Err propagates via `?`). Pre-fix the two were collapsed
    /// into the same arm, so a transient Postgres outage silently broke audit
    /// lineage by writing the parent's id as the root on a chain that
    /// actually had a deeper ancestor.
    pub async fn resolve_root_execution_id(
        &self,
        parent_exec_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        let parent_root: Option<(Option<Uuid>,)> = sqlx::query_as(
            "SELECT root_execution_id FROM workflow_executions WHERE id = $1 AND user_id = $2",
        )
        .bind(parent_exec_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(match parent_root {
            Some((Some(root),)) => Some(root), // parent has an explicit root → inherit it
            _ => Some(parent_exec_id), // parent row missing or root col NULL → parent IS the root
        })
    }

    /// Insert a new workflow execution record for a handoff.
    #[allow(clippy::too_many_arguments)]
    pub async fn insert_handoff_execution(
        &self,
        exec_id: Uuid,
        workflow_id: Uuid,
        user_id: Uuid,
        version_id: Option<Uuid>,
        to_actor_id: Uuid,
        provenance: &serde_json::Value,
        parent_execution_id: Option<Uuid>,
        root_execution_id: Option<Uuid>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO workflow_executions \
             (id, workflow_id, user_id, status, started_at, workflow_version_id, priority, actor_id, provenance, parent_execution_id, root_execution_id) \
             VALUES ($1, $2, $3, 'running', NOW(), $4, 'normal', $5, $6, $7, $8)",
        )
        .bind(exec_id)
        .bind(workflow_id)
        .bind(user_id)
        .bind(version_id)
        .bind(to_actor_id)
        .bind(provenance)
        .bind(parent_execution_id)
        .bind(root_execution_id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Mark a running execution as failed (used in handoff error paths).
    pub async fn fail_execution(&self, exec_id: Uuid, error_message: &str) -> Result<()> {
        // MCP-968 (2026-05-15): DLP-redact at the bind boundary. Same
        // sibling class as MCP-967 (WorkflowRepository /
        // ExecutionRepository mark_execution_failed). Handoff error
        // paths land caller-supplied error text (engine exception
        // strings, NATS-side delivery errors echoing user data) into
        // `workflow_executions.error_message`. Other methods in this
        // file already redact at write boundaries (lines 2244, 2307);
        // this was the lone unscrubbed sibling on the failure-path
        // surface.
        //
        // MCP-1164 (2026-05-17): truncate-then-redact discipline.
        // Sibling to MCP-1161 (WorkflowRepository) and the
        // AdvancedRepository fix in the same commit. Closes the
        // third writer to `workflow_executions.error_message` —
        // see the MCP-1164 doc on AdvancedRepository::fail_execution
        // for the full rationale. 4 KiB ceiling matches the MCP-1160
        // / MCP-1161 sibling caps.
        let truncated: &str = if error_message.len() > 4096 {
            talos_text_util::truncate_at_char_boundary(error_message, 4096)
        } else {
            error_message
        };
        let redacted = talos_dlp_provider::redact_str(truncated);
        sqlx::query(
            "UPDATE workflow_executions SET status = 'failed', error_message = $1, completed_at = NOW() WHERE id = $2 AND status = 'running'",
        )
        .bind(&redacted)
        .bind(exec_id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Mark a running execution as failed with a fixed 'NATS client not available' message.
    pub async fn fail_execution_nats_unavailable(&self, exec_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_executions SET status = 'failed', error_message = 'NATS client not available', completed_at = NOW() WHERE id = $1 AND status NOT IN ('completed', 'failed', 'cancelled', 'resuming')",
        )
        .bind(exec_id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Mark a running execution as completed with output data.
    /// Encrypts `output_data` at rest when SecretsManager is wired
    /// (see `with_encryption`). Otherwise falls back to plaintext write.
    pub async fn complete_execution(
        &self,
        exec_id: Uuid,
        output_data: &serde_json::Value,
    ) -> Result<()> {
        if let Some(sm) = &self.secrets_manager {
            let json_str = serde_json::to_string(output_data)?;
            // MCP-S2: bind the output ciphertext to exec_id so an
            // attacker with DB write capability can't swap user B's
            // execution output onto user A's row to leak it through
            // the GraphQL read path. v3 = AAD-bound + per-context-derived
            // key; per-row format column dispatches so legacy rows still read.
            let (key_id, enc_bytes, format_version) = sm
                .encrypt_value_aad_v3(&json_str, exec_id.as_bytes())
                .await?;
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'completed', output_data = NULL, \
                     output_data_enc = $1, output_enc_key_id = $2, \
                     output_data_format = $3, completed_at = NOW() \
                 WHERE id = $4 AND status = 'running'",
            )
            .bind(&enc_bytes)
            .bind(key_id)
            .bind(format_version)
            .bind(exec_id)
            .execute(&self.db_pool)
            .await?;
        } else {
            // L T4-7: NULL the ciphertext columns symmetrically with the
            // encrypted branch above. Without this, a row that was
            // previously written via the encrypted path then re-written
            // via the plaintext path (test env, post-rotate ad-hoc fix,
            // SecretsManager unwiring during a migration) keeps stale
            // ciphertext alongside the new plaintext. Reads prefer
            // ciphertext when both columns are populated, so the row
            // would decrypt to the OLD output, masking the rewrite.
            //
            // MCP-971 (2026-05-15): DLP-redact plaintext-fallback
            // output. Sibling to the workflow-repository +
            // execution-repository fixes — defence-in-depth even
            // though SecretsManager is wired in production.
            let redacted = talos_dlp_provider::redact_json(output_data);
            sqlx::query(
                "UPDATE workflow_executions \
                 SET status = 'completed', output_data = $1, \
                     output_data_enc = NULL, output_enc_key_id = NULL, \
                     completed_at = NOW() \
                 WHERE id = $2 AND status = 'running'",
            )
            .bind(&redacted)
            .bind(exec_id)
            .execute(&self.db_pool)
            .await?;
        }
        Ok(())
    }

    // ── Human RBAC — capability ceiling management ─────────────────────────

    /// Fetch the user's capability ceiling grant row. Returns None if the user has no explicit grant
    /// (callers should default to 'http-node').
    pub async fn get_user_capability_grant(
        &self,
        user_id: Uuid,
    ) -> Result<Option<UserCapabilityGrant>> {
        let row = sqlx::query(
            "SELECT max_capability_world, granted_by, granted_at, notes \
             FROM user_capability_grants WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| UserCapabilityGrant {
            max_capability_world: r.get("max_capability_world"),
            granted_by: r.get("granted_by"),
            granted_at: r.get("granted_at"),
            notes: r.get("notes"),
        }))
    }

    // ── LLM tier ceiling ──────────────────────────────────────────────────

    // NOTE: `apply_actor_to_engine` (the canonical actor→engine stamp:
    // sets `actor_id` AND `max_llm_tier` together, fail-closed to Tier1
    // on DB error / missing actor) moved to
    // `talos_engine::actor_binding::apply_actor_to_engine` in 2026-07 —
    // a persistence-layer crate must not depend on the workflow engine
    // (lint check 51 now forbids the dep edge). The tier lookup it
    // builds on is `get_actor_max_llm_tier` below.

    /// Resolve an actor's tier ceiling without touching an engine —
    /// for raw `JobRequest` construction paths (Gmail / GCal /
    /// webhook push-notification dispatch) that bypass the engine.
    ///
    /// Returns `Tier1` on any error (fail-closed). Logs at WARN on
    /// lookup failure OR missing actor so operators can correlate
    /// a tier-1 refusal with the underlying cause.
    pub async fn resolve_tier_for_job(
        &self,
        actor_id: Uuid,
    ) -> talos_workflow_job_protocol::LlmTier {
        match self.get_actor_max_llm_tier(actor_id).await {
            Ok(Some(t)) => t,
            Ok(None) => {
                tracing::warn!(
                    %actor_id,
                    "resolve_tier_for_job: actor not found; falling back to Tier1"
                );
                talos_workflow_job_protocol::LlmTier::Tier1
            }
            Err(e) => {
                tracing::error!(
                    %actor_id,
                    error = %e,
                    "resolve_tier_for_job: DB error; falling back to Tier1"
                );
                talos_workflow_job_protocol::LlmTier::Tier1
            }
        }
    }

    /// Fetch the LLM data-egress ceiling for an actor.
    /// Returns `Ok(Some(tier))` on success, `Ok(None)` when the actor
    /// doesn't exist, `Err` on DB failure. Never masks DB errors as
    /// `Tier2` — see `talos_engine::actor_binding::apply_actor_to_engine`
    /// for the fail-closed contract.
    pub async fn get_actor_max_llm_tier(
        &self,
        actor_id: Uuid,
    ) -> Result<Option<talos_workflow_job_protocol::LlmTier>> {
        let row: Option<String> =
            sqlx::query_scalar("SELECT max_llm_tier FROM actors WHERE id = $1")
                .bind(actor_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row
            .as_deref()
            .map(talos_workflow_job_protocol::LlmTier::from_db_str))
    }

    /// Set an actor's LLM data-egress ceiling. Validates user ownership
    /// before mutating. Returns true if the row was updated, false if
    /// the actor doesn't exist or doesn't belong to the user.
    pub async fn set_actor_max_llm_tier(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        tier: talos_workflow_job_protocol::LlmTier,
    ) -> Result<bool> {
        let result =
            sqlx::query("UPDATE actors SET max_llm_tier = $1 WHERE id = $2 AND user_id = $3")
                .bind(tier.as_signing_str())
                .bind(actor_id)
                .bind(user_id)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Fetch only the max_capability_world string for a user (used by user_max_world helper).
    /// Returns None if no explicit grant exists.
    pub async fn get_user_max_capability_world(&self, user_id: Uuid) -> Result<Option<String>> {
        let world: Option<String> = sqlx::query_scalar(
            "SELECT max_capability_world FROM user_capability_grants WHERE user_id = $1",
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(world)
    }

    /// Upsert a capability ceiling grant for a target user.
    pub async fn upsert_capability_grant(
        &self,
        target_user_id: Uuid,
        max_capability_world: &str,
        granter_id: Uuid,
        notes: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO user_capability_grants (user_id, max_capability_world, granted_by, notes) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (user_id) DO UPDATE \
             SET max_capability_world = EXCLUDED.max_capability_world, \
                 granted_by = EXCLUDED.granted_by, \
                 granted_at = now(), \
                 notes = EXCLUDED.notes",
        )
        .bind(target_user_id)
        .bind(max_capability_world)
        .bind(granter_id)
        .bind(notes)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Delete a capability grant for a user. Returns the number of rows deleted.
    pub async fn delete_capability_grant(&self, target_user_id: Uuid) -> Result<u64> {
        let result = sqlx::query("DELETE FROM user_capability_grants WHERE user_id = $1")
            .bind(target_user_id)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }

    /// List all capability grants (admin-only). Returns up to 200 rows.
    pub async fn list_capability_grants(&self) -> Result<Vec<CapabilityGrantRow>> {
        let rows = sqlx::query(
            "SELECT g.user_id, g.max_capability_world, g.granted_by, g.granted_at, g.notes, \
                    u.email \
             FROM user_capability_grants g \
             JOIN users u ON u.id = g.user_id \
             ORDER BY g.granted_at DESC \
             LIMIT 200",
        )
        .fetch_all(&self.db_pool)
        .await?;

        let result = rows
            .iter()
            .map(|r| CapabilityGrantRow {
                user_id: r.get("user_id"),
                email: r.get("email"),
                max_capability_world: r.get("max_capability_world"),
                granted_by: r.get("granted_by"),
                granted_at: r.get("granted_at"),
                notes: r.get("notes"),
            })
            .collect();
        Ok(result)
    }

    // ── clone_actor helpers ────────────────────────────────────────────────

    /// Fetch the fields needed to clone an actor (ownership-checked).
    pub async fn get_source_actor_for_clone(
        &self,
        source_actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<SourceActorCloneRow>> {
        let row = sqlx::query(
            "SELECT name, description, max_capability_world, secret_grants \
             FROM actors WHERE id = $1 AND user_id = $2",
        )
        .bind(source_actor_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| SourceActorCloneRow {
            max_capability_world: r.get("max_capability_world"),
            description: r.try_get("description").unwrap_or(None),
            secret_grants: r.try_get("secret_grants").unwrap_or_default(),
        }))
    }

    /// Insert a cloned actor with explicit secret grants.
    pub async fn insert_actor_with_grants(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        name: &str,
        description: Option<&str>,
        max_capability_world: &str,
        secret_grants: &[String],
    ) -> Result<()> {
        // RFC 0006 / RFC 0005 S3: scope to the owner's personal org so the
        // org-pin WITH CHECK enforces (org_id is trigger-stamped, not bound).
        let mut tx = self.begin_personal_org_write(user_id).await?;
        sqlx::query(
            "INSERT INTO actors (id, user_id, name, description, max_capability_world, secret_grants) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(name)
        .bind(description)
        .bind(max_capability_world)
        .bind(secret_grants)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// MCP-434 (2026-05-11): atomic INSERT/COUNT for clone_actor's
    /// per-user limit gate. Sibling to insert_actor_with_limit_check
    /// (the create_actor variant) but accepts a `secret_grants` array
    /// to preserve the source actor's cross-namespace grants on the
    /// clone.
    ///
    /// Pre-MCP-434 clone_actor ran SELECT COUNT + INSERT as two
    /// statements with MCP-401 fail-CLOSED on the count query. The
    /// remaining gap was the TOCTOU window between the two: N
    /// concurrent clones could each see `count = 999` and all
    /// successfully insert, collectively pushing the user from 999
    /// to 999+N. The atomic `INSERT … SELECT … WHERE count < cap`
    /// closes that window — a concurrent clone race that exceeds
    /// the cap returns rows_affected == 0 for the losers, which the
    /// handler translates to the same "limit reached" error.
    ///
    /// Returns rows_affected (0 if the limit gate fired, 1 on
    /// successful insert). Distinct from insert_actor_with_grants
    /// (always 1) so the handler can branch on the limit-hit case.
    pub async fn insert_actor_with_grants_and_limit_check(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        name: &str,
        description: Option<&str>,
        max_capability_world: &str,
        secret_grants: &[String],
        max_actors_per_user: i64,
    ) -> Result<u64> {
        // RFC 0006 / RFC 0005 S3: scope to the owner's personal org so the
        // org-pin WITH CHECK enforces (org_id is trigger-stamped, not bound).
        let mut tx = self.begin_personal_org_write(user_id).await?;
        let result = sqlx::query(
            "INSERT INTO actors (id, user_id, name, description, max_capability_world, secret_grants) \
             SELECT $1, $2, $3, $4, $5, $6 \
             WHERE (SELECT COUNT(*) FROM actors WHERE user_id = $2) < $7",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(name)
        .bind(description)
        .bind(max_capability_world)
        .bind(secret_grants)
        .bind(max_actors_per_user)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }

    /// Copy the budget policy from a source actor to a new actor (INSERT … SELECT).
    /// Returns true if a policy was copied, false if the source had none.
    pub async fn copy_budget_policy(
        &self,
        new_actor_id: Uuid,
        source_actor_id: Uuid,
    ) -> Result<bool> {
        let result = sqlx::query(
            "INSERT INTO actor_budget_policies \
             (actor_id, max_executions_per_hour, max_executions_total, max_fuel_per_execution, \
              max_fuel_per_hour, max_outbound_requests_per_hour, max_workflow_count, \
              max_workflows_per_minute, max_compilations_per_hour, on_budget_exceeded, updated_at) \
             SELECT $1, max_executions_per_hour, max_executions_total, max_fuel_per_execution, \
                    max_fuel_per_hour, max_outbound_requests_per_hour, max_workflow_count, \
                    max_workflows_per_minute, max_compilations_per_hour, on_budget_exceeded, now() \
             FROM actor_budget_policies WHERE actor_id = $2 \
             ON CONFLICT (actor_id) DO NOTHING",
        )
        .bind(new_actor_id)
        .bind(source_actor_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Copy all approval policies from a source actor to a new actor (INSERT … SELECT).
    /// Returns the count of policies copied.
    pub async fn copy_approval_policies(
        &self,
        new_actor_id: Uuid,
        source_actor_id: Uuid,
    ) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "WITH inserted AS ( \
                 INSERT INTO actor_approval_policies (id, actor_id, trigger_condition, approval_mode, approvers) \
                 SELECT gen_random_uuid(), $1, trigger_condition, approval_mode, approvers \
                 FROM actor_approval_policies WHERE actor_id = $2 \
                 RETURNING 1 \
             ) SELECT COUNT(*) FROM inserted",
        )
        .bind(new_actor_id)
        .bind(source_actor_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(count)
    }

    // ── Public enforcement helpers ─────────────────────────────────────────

    /// Check actor status and budget before allowing a new workflow execution.
    /// Returns Ok(()) if execution is allowed, Err(message) if it should be rejected.
    ///
    /// **Fail-closed on DB error (M T4-1).** Pre-fix every query used
    /// `.unwrap_or(...)` to swallow Postgres errors, silently allowing
    /// dispatch when the DB hiccupped — an actor at its hourly cap
    /// could blast unbounded executions during a transient outage.
    /// Now every query propagates errors as `Err(message)`; callers
    /// (the dispatch path in `talos-execution-orchestration`) refuse
    /// the dispatch on Err. Mirrors `apply_actor_to_engine`'s
    /// fail-closed contract for the same threat class.
    ///
    /// Counts delegated to the public siblings `count_executions_last_hour`
    /// and `count_total_executions` (L T4-6) so the inline path can't
    /// drift from a future window-policy change.
    pub async fn check_execution_allowed(&self, actor_id: Uuid) -> Result<(), String> {
        // Check actor is active. Fail-closed on DB error: refuse to
        // dispatch rather than risk a permissive default.
        let status: Option<String> = sqlx::query_scalar("SELECT status FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_optional(&self.db_pool)
            .await
            .map_err(|e| format!("budget enforcement: status lookup failed: {e}"))?;

        match status.as_deref() {
            None => return Err("Actor not found".to_string()),
            Some("suspended") => {
                return Err(
                    "Actor is suspended. Resume it with update_actor_status before executing."
                        .to_string(),
                )
            }
            Some("terminated") => {
                return Err("Actor is terminated and cannot execute workflows.".to_string())
            }
            _ => {}
        }

        // Check budget policy. Same fail-closed treatment.
        let budget = sqlx::query(
            "SELECT max_executions_per_hour, max_executions_total, on_budget_exceeded \
             FROM actor_budget_policies WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_optional(&self.db_pool)
        .await
        .map_err(|e| format!("budget enforcement: policy lookup failed: {e}"))?;

        let Some(budget) = budget else {
            return Ok(());
        };

        let on_exceeded = budget.get::<String, _>("on_budget_exceeded");

        // Rolling 1-hour check via the public sibling.
        if let Some(max_per_hour) = budget.get::<Option<i32>, _>("max_executions_per_hour") {
            let count = self
                .count_executions_last_hour(actor_id)
                .await
                .map_err(|e| format!("budget enforcement: 1h count lookup failed: {e}"))?;

            if count >= max_per_hour as i64 {
                if on_exceeded == "suspend" {
                    // MCP-646: terminal-state guard for the auto-suspend
                    // path too. An archived actor with a budget policy
                    // would otherwise have its status clobbered from
                    // 'archived' → 'suspended', breaking the IRREVERSIBLE
                    // contract documented on archive_actor. Sibling fix
                    // to the suspend_actor SQL above.
                    if let Err(e) = sqlx::query(
                        "UPDATE actors SET status = 'suspended', updated_at = now() \
                         WHERE id = $1 AND status NOT IN ('archived', 'terminated')",
                    )
                    .bind(actor_id)
                    .execute(&self.db_pool)
                    .await
                    {
                        // Don't mask the budget-exceeded error if the
                        // suspend itself fails — log + continue, since
                        // the caller should still see the cap message
                        // and refuse the dispatch.
                        tracing::warn!(
                            %actor_id,
                            error = %e,
                            "check_execution_allowed: auto-suspend failed (budget still enforced)"
                        );
                    }
                }
                return Err(format!(
                    "Actor budget exceeded: {} executions in the last hour (limit: {}). \
                     on_budget_exceeded={}",
                    count, max_per_hour, on_exceeded
                ));
            }
        }

        // Total lifetime check via the public sibling.
        if let Some(max_total) = budget.get::<Option<i64>, _>("max_executions_total") {
            let count = self
                .count_total_executions(actor_id)
                .await
                .map_err(|e| format!("budget enforcement: total count lookup failed: {e}"))?;

            if count >= max_total {
                return Err(format!(
                    "Actor budget exceeded: {} total executions (limit: {}). Increase the budget with set_actor_budget.",
                    count, max_total
                ));
            }
        }

        Ok(())
    }

    /// Return the max_capability_world for an actor, or None if actor not found.
    /// Mirrors the free function `get_actor_max_world` in agents.rs, using self.db_pool.
    ///
    /// L T4-3 — Logs at `error!` on DB failure before returning None so a
    /// transient outage isn't silently invisible. Callers that need the
    /// strict failure semantics (refuse the dispatch on DB error rather
    /// than fall through to a permissive default) should use
    /// [`Self::try_get_actor_max_world`].
    pub async fn get_actor_max_world(&self, actor_id: Uuid) -> Option<String> {
        match self.try_get_actor_max_world(actor_id).await {
            Ok(world) => world,
            Err(e) => {
                tracing::error!(
                    %actor_id,
                    error = %e,
                    "get_actor_max_world: DB error; returning None (caller may default \
                     to permissive ceiling — wire try_get_actor_max_world to fail closed)"
                );
                None
            }
        }
    }

    /// Strict sibling of [`Self::get_actor_max_world`]: propagates DB
    /// errors instead of silently returning None. New code that gates
    /// authorisation on the ceiling should call this — `Err(_)` on the
    /// caller side means "fail closed; refuse the dispatch."
    pub async fn try_get_actor_max_world(&self, actor_id: Uuid) -> Result<Option<String>> {
        let world: Option<String> =
            sqlx::query_scalar("SELECT max_capability_world FROM actors WHERE id = $1")
                .bind(actor_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(world)
    }

    // ── MCP-handler support: create + update + clone ───────────────────────

    /// Insert an actor with an atomic per-user limit check. The INSERT uses
    /// SELECT ... WHERE COUNT(*) < limit so the count and insert are a single
    /// statement — no TOCTOU race when concurrent create_actor calls land.
    /// Returns the number of rows affected: 1 on success, 0 if the limit was
    /// hit. DB unique-constraint violations propagate as Err.
    pub async fn insert_actor_with_limit_check(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        name: &str,
        description: Option<&str>,
        max_capability_world: &str,
        max_actors_per_user: i64,
    ) -> Result<u64> {
        // RFC 0006 / RFC 0005 S3: scope to the owner's personal org so the
        // org-pin WITH CHECK enforces (org_id is trigger-stamped, not bound).
        let mut tx = self.begin_personal_org_write(user_id).await?;
        let result = sqlx::query(
            "INSERT INTO actors (id, user_id, name, description, max_capability_world) \
             SELECT $1, $2, $3, $4, $5 \
             WHERE (SELECT COUNT(*) FROM actors WHERE user_id = $2) < $6",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(name)
        .bind(description)
        .bind(max_capability_world)
        .bind(max_actors_per_user)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(result.rows_affected())
    }

    /// Count actors owned by a user. Used by clone_actor to enforce the same
    /// per-user cap as create_actor.
    pub async fn count_actors_for_user(&self, user_id: Uuid) -> Result<i64> {
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM actors WHERE user_id = $1")
            .bind(user_id)
            .fetch_one(&self.db_pool)
            .await?;
        Ok(count)
    }

    /// Update name and/or description for an actor scoped to a user.
    /// Either field may be None (no change). Always touches updated_at.
    /// Returns rows affected (0 if not found or no fields to update).
    pub async fn update_actor_name_description(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        new_name: Option<&str>,
        new_description: Option<&str>,
    ) -> Result<u64> {
        // Single statement using COALESCE so we don't have to build dynamic SQL.
        // Passing the existing column value as the fallback when caller didn't
        // supply a new value keeps the query schema constant.
        let result = sqlx::query(
            "UPDATE actors \
             SET name = COALESCE($1, name), \
                 description = CASE WHEN $2::bool THEN $3 ELSE description END, \
                 updated_at = NOW() \
             WHERE id = $4 AND user_id = $5",
        )
        .bind(new_name)
        // Distinguish "caller did not pass description" from "caller cleared it
        // to NULL" via a sidecar bool — we only have the Option<&str> here so
        // any Some("") is treated as a real value, None means leave alone.
        .bind(new_description.is_some())
        .bind(new_description)
        .bind(actor_id)
        .bind(user_id)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Lightweight projection used to render the post-update_actor response.
    pub async fn get_actor_basic_info(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ActorBasicInfo>> {
        let row = sqlx::query(
            "SELECT id, name, description, status, max_capability_world, updated_at \
             FROM actors WHERE id = $1 AND user_id = $2",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;

        Ok(row.map(|r| ActorBasicInfo {
            id: r.get("id"),
            name: r.get("name"),
            description: r.try_get("description").ok().flatten(),
            status: r
                .try_get::<Option<String>, _>("status")
                .ok()
                .flatten()
                .unwrap_or_else(|| "active".to_string()),
            max_capability_world: r
                .try_get::<Option<String>, _>("max_capability_world")
                .ok()
                .flatten()
                .unwrap_or_else(|| "minimal-node".to_string()),
            updated_at: r.try_get("updated_at").ok().flatten(),
        }))
    }

    /// Clone semantic + episodic memories from one actor to another.
    /// Thin delegate to [`talos_memory::clone_memories`].
    ///
    /// **L T4-1: same-user invariant enforced at the SQL boundary.** This is a
    /// TENANCY/privacy boundary, NOT a crypto one — don't copy one user's agent
    /// memory into another user's agent. (Crypto would not stop it: the DEK is
    /// a single system-wide key, not per-user, so a cross-user copy would
    /// decrypt fine — `clone_memories` re-bases each v1/v3 row's AAD on copy
    /// regardless. The earlier "DEK lineage is per-user / target can't decrypt"
    /// rationale was inaccurate.) Both actors must belong to `user_id`;
    /// mismatch fails closed with `anyhow::bail!`.
    pub async fn clone_actor_memories(
        &self,
        user_id: Uuid,
        new_actor_id: Uuid,
        source_actor_id: Uuid,
    ) -> Result<i64> {
        let owners: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM actors WHERE id = ANY($1) AND user_id = $2")
                .bind([new_actor_id, source_actor_id].as_slice())
                .bind(user_id)
                .fetch_all(&self.db_pool)
                .await?;
        if owners.len() != 2 {
            anyhow::bail!(
                "clone_actor_memories: both actors (source={source_actor_id}, target={new_actor_id}) \
                 must belong to user {user_id} (matched {} of 2)",
                owners.len()
            );
        }
        talos_memory::clone_memories(&self.db_pool, source_actor_id, new_actor_id).await
    }

    /// List active actors for a user with just the fields needed by
    /// `suggest_actor_for_task` (id, name, description, max_capability_world).
    /// Capped at `limit` rows.
    pub async fn list_active_actors_basic(
        &self,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ActorBasicSummary>> {
        let rows = sqlx::query(
            "SELECT id, name, description, max_capability_world FROM actors \
             WHERE user_id = $1 AND status = 'active' \
             ORDER BY created_at DESC LIMIT $2",
        )
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| ActorBasicSummary {
                id: r.try_get("id").unwrap_or_default(),
                name: r.try_get("name").unwrap_or_default(),
                description: r.try_get("description").unwrap_or(None),
                max_capability_world: r.try_get("max_capability_world").unwrap_or_default(),
            })
            .collect())
    }

    /// Find actors whose semantic memories most resemble a task embedding.
    /// `embedding_str` must already be in pgvector literal form, e.g.
    /// `"[0.1,0.2,...]"`.
    pub async fn find_actors_by_memory_similarity(
        &self,
        user_id: Uuid,
        embedding_str: &str,
        min_score: f64,
        limit: i64,
    ) -> Result<Vec<ActorMemorySimilarityRow>> {
        let rows = sqlx::query(
            "SELECT am.actor_id, a.name, a.description, a.max_capability_world, \
                    MAX(1.0 - (am.embedding <=> $1::vector)) AS best_score, \
                    COUNT(*) AS memory_count \
             FROM actor_memory am \
             JOIN actors a ON a.id = am.actor_id \
             WHERE a.user_id = $2 AND a.status = 'active' \
               AND am.embedding IS NOT NULL \
               AND am.memory_type = 'semantic' \
               AND (am.expires_at IS NULL OR am.expires_at > now()) \
             GROUP BY am.actor_id, a.name, a.description, a.max_capability_world \
             HAVING MAX(1.0 - (am.embedding <=> $1::vector)) >= $3 \
             ORDER BY best_score DESC \
             LIMIT $4",
        )
        .bind(embedding_str)
        .bind(user_id)
        .bind(min_score)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| ActorMemorySimilarityRow {
                actor_id: r.try_get("actor_id").unwrap_or(Uuid::nil()),
                name: r.try_get("name").unwrap_or_default(),
                description: r.try_get("description").unwrap_or(None),
                max_capability_world: r.try_get("max_capability_world").unwrap_or_default(),
                best_score: r.try_get("best_score").unwrap_or(0.0),
                memory_count: r.try_get("memory_count").unwrap_or(0),
            })
            .collect())
    }

    /// Find few-shot example memories for an actor by embedding similarity.
    /// Embedding string must be in pgvector literal form.
    /// `exclude_kinds` excludes rows whose `metadata->>'kind'` matches any
    /// entry. Mirrors `talos_memory::recall_semantic_filtered` semantics —
    /// NULL metadata / missing kind passes the filter (treated as "not
    /// synthetic" by default), and `cardinality = 0` is a no-op shortcut.
    /// Used by `get_few_shot_examples` to honor the `metadata.kind`
    /// self-recall convention so synthetic LLM outputs (daily_brief, etc.)
    /// don't pollute the prompt context they're being assembled for.
    pub async fn find_few_shot_examples_semantic(
        &self,
        actor_id: Uuid,
        embedding_str: &str,
        memory_type: &str,
        min_score: f64,
        limit: i64,
        exclude_kinds: &[String],
    ) -> Result<Vec<MemoryExample>> {
        let rows = sqlx::query(
            "SELECT key, value_enc, value_key_id, memory_type, \
                    (1.0 - (embedding <=> $2::vector)) AS score \
             FROM actor_memory \
             WHERE actor_id = $1 \
               AND memory_type = $3 \
               AND (expires_at IS NULL OR expires_at > now()) \
               AND embedding IS NOT NULL \
               AND (1.0 - (embedding <=> $2::vector)) >= $4 \
               AND (cardinality($6::text[]) = 0 \
                    OR metadata IS NULL \
                    OR metadata->>'kind' IS NULL \
                    OR metadata->>'kind' != ALL($6::text[])) \
             ORDER BY embedding <=> $2::vector \
             LIMIT $5",
        )
        .bind(actor_id)
        .bind(embedding_str)
        .bind(memory_type)
        .bind(min_score)
        .bind(limit)
        .bind(exclude_kinds)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let value = talos_memory::decrypt_row_value(r)
                .await
                .unwrap_or(serde_json::Value::Null);
            out.push(MemoryExample {
                key: r.try_get("key").unwrap_or_default(),
                value,
                memory_type: r.try_get("memory_type").unwrap_or_default(),
                score: r.try_get("score").ok(),
            });
        }
        Ok(out)
    }

    /// Few-shot example fallback: keyword ILIKE match on `key` only.
    /// `pattern` is the already-escaped LIKE pattern (e.g. `"%foo%"`).
    /// Note: post-Phase-A, the encrypted `value_enc` cannot be substring-
    /// matched at the DB layer; callers relying on value-text fallback now
    /// degrade to key-match only when the semantic path returns no hits.
    pub async fn find_few_shot_examples_keyword(
        &self,
        actor_id: Uuid,
        pattern: &str,
        memory_type: &str,
        limit: i64,
        exclude_kinds: &[String],
    ) -> Result<Vec<MemoryExample>> {
        let rows = sqlx::query(
            "SELECT key, value_enc, value_key_id, memory_type, NULL::float8 AS score \
             FROM actor_memory \
             WHERE actor_id = $1 \
               AND memory_type = $2 \
               AND (expires_at IS NULL OR expires_at > now()) \
               AND key ILIKE $3 \
               AND (cardinality($5::text[]) = 0 \
                    OR metadata IS NULL \
                    OR metadata->>'kind' IS NULL \
                    OR metadata->>'kind' != ALL($5::text[])) \
             ORDER BY updated_at DESC \
             LIMIT $4",
        )
        .bind(actor_id)
        .bind(memory_type)
        .bind(pattern)
        .bind(limit)
        .bind(exclude_kinds)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            let value = talos_memory::decrypt_row_value(r)
                .await
                .unwrap_or(serde_json::Value::Null);
            out.push(MemoryExample {
                key: r.try_get("key").unwrap_or_default(),
                value,
                memory_type: r.try_get("memory_type").unwrap_or_default(),
                score: None,
            });
        }
        Ok(out)
    }

    /// Compact actor projection for `handle_get_agent_card` — name/desc/status/world.
    pub async fn get_actor_card_info(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ActorCardInfo>> {
        let row = sqlx::query(
            "SELECT name, description, status, max_capability_world \
             FROM actors WHERE id = $1 AND user_id = $2",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row.map(|r| ActorCardInfo {
            name: r.try_get("name").unwrap_or_default(),
            description: r
                .try_get::<Option<String>, _>("description")
                .unwrap_or(None),
            status: r.try_get("status").unwrap_or_default(),
            max_capability_world: r.try_get("max_capability_world").unwrap_or_default(),
        }))
    }

    /// Lookup the actor's "default" workflow for `dispatch_to_actor` — return
    /// `Ok(Some(uuid))` ONLY if the actor owns exactly one active (non-archived)
    /// workflow. Otherwise return `Ok(None)` so the caller can produce an
    /// "ambiguous, please specify workflow_id" error listing the candidates.
    /// Filtered by `user_id` for tenant isolation.
    pub async fn find_solo_active_workflow_for_actor(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<Uuid>> {
        // LIMIT 2 lets us distinguish "exactly 1" from ">1" without scanning
        // the full set; cheap on the (actor_id, status) index.
        let rows: Vec<Uuid> = sqlx::query_scalar(
            "SELECT id FROM workflows \
             WHERE actor_id = $1 AND user_id = $2 AND status != 'archived' \
             LIMIT 2",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_all(&self.db_pool)
        .await?;
        if rows.len() == 1 {
            Ok(Some(rows[0]))
        } else {
            Ok(None)
        }
    }

    /// List up to `limit` non-archived workflows for an actor (id + name only).
    /// Used by `dispatch_to_actor` to render the "ambiguous, pick one of..."
    /// error when the actor owns more than one workflow.
    pub async fn list_active_workflows_for_actor_brief(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        limit: i64,
    ) -> Result<Vec<(Uuid, String)>> {
        let rows = sqlx::query(
            "SELECT id, name FROM workflows \
             WHERE actor_id = $1 AND user_id = $2 AND status != 'archived' \
             ORDER BY updated_at DESC LIMIT $3",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| {
                (
                    r.try_get::<Uuid, _>("id").unwrap_or_default(),
                    r.try_get::<String, _>("name").unwrap_or_default(),
                )
            })
            .collect())
    }

    /// List published workflows owned by an actor — projection for the A2A agent card.
    pub async fn list_published_workflows_for_actor(
        &self,
        actor_id: Uuid,
        limit: i64,
    ) -> Result<Vec<PublishedWorkflowRow>> {
        let rows = sqlx::query(
            "SELECT id, name, description, capabilities \
             FROM workflows \
             WHERE actor_id = $1 AND status = 'published' \
             ORDER BY updated_at DESC LIMIT $2",
        )
        .bind(actor_id)
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        Ok(rows
            .iter()
            .map(|r| PublishedWorkflowRow {
                id: r.try_get("id").unwrap_or_default(),
                name: r.try_get("name").unwrap_or_default(),
                description: r.try_get("description").unwrap_or(None),
                capabilities: r.try_get("capabilities").unwrap_or_default(),
            })
            .collect())
    }

    /// Insert an admin event log entry. Used by `spawn_log_admin_event` for
    /// privileged-resource audit trail (MCP agents etc.). Best-effort: callers
    /// typically discard errors and just log them.
    ///
    /// MCP-978 (2026-05-15): defence-in-depth DLP redact inside the
    /// method. The canonical caller `spawn_log_admin_event` (line
    /// ~2244-2253) already runs `redact_str(&summary)` and
    /// `redact_json(&d)` upstream. But this method is `pub` — direct
    /// callers (e.g. `talos-mcp-handlers/src/actor.rs:2990` for the
    /// `actor_llm_tier_ceiling_set` audit event) bind their arguments
    /// straight in. Today every direct caller passes internal trusted
    /// values (enum strings, structured config snapshots) so the gap
    /// isn't exploited, but the architectural rule is "redact at the
    /// persistence boundary" — the method's contract should not depend
    /// on caller discipline. Redact_str and redact_json are infallible
    /// idempotent; re-redacting already-scrubbed text is a no-op.
    /// Same defence-in-depth pattern as MCP-966 (engine event sink).
    pub async fn insert_admin_event_log(
        &self,
        user_id: Uuid,
        event_type: &str,
        resource_type: &str,
        resource_id: Option<Uuid>,
        summary: &str,
        details: Option<&serde_json::Value>,
    ) -> Result<()> {
        // MCP-1104: see insert_action_log_entry doc-comment for the
        // truncate-then-redact rationale. Sibling helper, same fix.
        let truncated_summary = truncate_summary_at_boundary(summary);
        let redacted_summary = talos_dlp_provider::redact_str(&truncated_summary);
        // MCP-1195 (2026-05-17): cap details JSONB at 1 MiB, sibling
        // of the actor_action_log.details fix. admin_event_log writes
        // operator-facing audit context (config snapshots, change
        // diffs) — typical size is small but no upper bound on
        // caller-supplied JSON. Measure-then-cap-then-redact prevents
        // pathological inputs from blowing both regex cost and
        // persisted column size. 1 MiB matches the canonical cap.
        let redacted_details = bound_log_details(details);
        sqlx::query(
            "INSERT INTO admin_event_log \
             (user_id, event_type, resource_type, resource_id, summary, details) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(user_id)
        .bind(event_type)
        .bind(resource_type)
        .bind(resource_id)
        .bind(&redacted_summary)
        .bind(redacted_details.as_ref())
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }
}

/// MCP-1104: Truncate summaries to 1000 chars at a UTF-8 char boundary.
///
/// Matches the `spawn_log_action` / `spawn_log_admin_event` wrappers'
/// pre-spawn truncation (line ~2299 below), so direct callers of
/// `insert_action_log_entry` / `insert_admin_event_log` get the same
/// bound — important because:
///
/// 1. The DLP-redact regex pass runs in O(input size). Without a cap,
///    a multi-MB summary forces the DLP scan to walk every byte.
/// 2. `actor_action_log.summary` and `admin_event_log.summary` are TEXT
///    columns — Postgres accepts ~1 GB rows. An unbounded write
///    persists the full input forever.
///
/// 1000 chars is the same value MCP-1027 chose for the spawn wrappers;
/// real-world summary content is single-line "actor X did Y with
/// outcome Z" shape and fits comfortably.
fn truncate_summary_at_boundary(summary: &str) -> std::borrow::Cow<'_, str> {
    const MAX_SUMMARY_BYTES: usize = 1000;
    if summary.len() <= MAX_SUMMARY_BYTES {
        std::borrow::Cow::Borrowed(summary)
    } else {
        std::borrow::Cow::Owned(format!(
            "{}…",
            talos_text_util::truncate_at_char_boundary(summary, MAX_SUMMARY_BYTES - 3)
        ))
    }
}

/// MCP-1195 (2026-05-17): bound the `details` JSONB at 1 MiB BEFORE
/// Measure-first bound on the `actor_action_log.details` /
/// `admin_event_log.details` JSONB columns.
///
/// MCP-1206 (2026-05-17): collapsed to a thin wrapper around the
/// canonical `talos_dlp_provider::redact_json_bounded` helper. The
/// canonical helper applies the same 1 MiB ceiling
/// (`MAX_LOG_METADATA_BYTES`) and the same measure-first-then-redact
/// discipline this function previously inlined.
///
/// Pre-consolidation event_kind was `log_details_oversized_dropped`;
/// canonical helper emits `log_metadata_oversized_dropped` instead.
/// One canonical event_kind across all log-metadata persistence
/// sites is the right discipline — operator dashboards filtering on
/// the old name should migrate to the new one.
fn bound_log_details(details: Option<&serde_json::Value>) -> Option<serde_json::Value> {
    details.and_then(talos_dlp_provider::redact_json_bounded)
}

/// Convenience wrapper around [`ActorRepository::get_actor_max_world`].
///
/// Avoids the boilerplate of building a one-shot `ActorRepository` for
/// callers that only want this single lookup. Returns `None` if the
/// actor is not found.
pub async fn get_actor_max_world(pool: &sqlx::PgPool, actor_id: Uuid) -> Option<String> {
    ActorRepository::new(pool.clone())
        .get_actor_max_world(actor_id)
        .await
}

/// Fire-and-forget audit log entry (non-blocking, best-effort).
/// DLP redaction is applied to summary and details before storage.
///
/// Pre-extraction lived at `controller::mcp::actor::spawn_log_action`;
/// the canonical home is now this crate. Re-exported under the old
/// path for backwards compatibility.
pub fn spawn_log_action(
    pool: sqlx::PgPool,
    actor_id: Uuid,
    action_type: &'static str,
    workflow_id: Option<Uuid>,
    execution_id: Option<Uuid>,
    summary: String,
    details: Option<serde_json::Value>,
) {
    // MCP-1027 (2026-05-15): truncate ONLY; the inner
    // `insert_action_log_entry` (lib.rs:1044) re-runs
    // `talos_dlp_provider::redact_str` / `redact_json` so doing it here
    // too was wasteful AND in the wrong order (redact-then-truncate
    // means the regex pass scans the full untruncated input). Sibling
    // canonical pattern is MCP-1012's truncate-then-redact (auth_audit_log
    // user_agent) and MCP-1018's webhook_request_log user_agent. Bound
    // the size at the boundary; let the persistence helper handle
    // redaction so there's exactly one DLP pass per write.
    let summary = if summary.len() > 1000 {
        format!(
            "{}…",
            talos_text_util::truncate_at_char_boundary(&summary, 997)
        )
    } else {
        summary
    };
    tokio::spawn(async move {
        let repo = ActorRepository::new(pool);
        // MCP-736 (2026-05-13): sibling-drift fix matching
        // `spawn_log_admin_event` below — log DB failures on the
        // actor-action audit path. Pre-fix `let _ = repo.insert...`
        // silently discarded every error, so under a DB outage the
        // actor forensic trail (terminations, handoffs, module
        // dispatches) silently vanished with no operator signal.
        // The sibling `spawn_log_admin_event` already logs via
        // `tracing::warn!(error = %e, "Failed to write admin_event_log
        // entry (non-fatal)")` — adopt the same shape here. Audit-
        // visibility class MCP-733/734/735.
        if let Err(e) = repo
            .insert_action_log_entry(
                actor_id,
                action_type,
                workflow_id,
                execution_id,
                &summary,
                details.as_ref(),
            )
            .await
        {
            tracing::warn!(
                target: "talos_audit",
                actor_id = %actor_id,
                action_type,
                error = %e,
                "Failed to write actor_action_log entry (non-fatal)"
            );
        }
    });
}

/// Fire-and-forget audit entry for privileged admin-level resources
/// (MCP agents, security toggles, etc.). Writes to `admin_event_log`
/// — distinct from `actor_action_log` which requires an actors FK.
/// DLP redaction is applied to summary and details; summary truncated
/// to 1000 chars at a UTF-8 char boundary. Failures are logged but
/// not propagated to callers.
///
/// Pre-extraction lived at `controller::mcp::actor::spawn_log_admin_event`;
/// the canonical home is now this crate. Re-exported under the old
/// path for backwards compatibility.
pub fn spawn_log_admin_event(
    pool: sqlx::PgPool,
    user_id: Uuid,
    event_type: &'static str,
    resource_type: &'static str,
    resource_id: Option<Uuid>,
    summary: String,
    details: Option<serde_json::Value>,
) {
    // MCP-1027 (2026-05-15): truncate ONLY; the inner
    // `insert_admin_event_log` (lib.rs:2245) handles redaction. See
    // sibling `spawn_log_action` for full rationale (double-redact
    // + wrong order). Truncate at the boundary; persistence helper
    // does the single canonical DLP pass.
    let summary = if summary.len() > 1000 {
        format!(
            "{}…",
            talos_text_util::truncate_at_char_boundary(&summary, 997)
        )
    } else {
        summary
    };
    tokio::spawn(async move {
        let repo = ActorRepository::new(pool);
        if let Err(e) = repo
            .insert_admin_event_log(
                user_id,
                event_type,
                resource_type,
                resource_id,
                &summary,
                details.as_ref(),
            )
            .await
        {
            tracing::warn!(error = %e, "Failed to write admin_event_log entry (non-fatal)");
        }
    });
}

#[cfg(test)]
mod summary_truncation_tests {
    use super::truncate_summary_at_boundary;

    #[test]
    fn short_summary_passes_through_unchanged() {
        let s = "Actor X did Y";
        assert_eq!(&*truncate_summary_at_boundary(s), s);
    }

    #[test]
    fn at_cap_summary_passes_through_unchanged() {
        let s = "x".repeat(1000);
        assert_eq!(&*truncate_summary_at_boundary(&s), s.as_str());
    }

    #[test]
    fn oversized_summary_truncates_with_ellipsis() {
        let s = "x".repeat(2000);
        let truncated = truncate_summary_at_boundary(&s);
        // 1000-byte cap including the ellipsis suffix.
        assert!(truncated.len() <= 1000);
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn oversized_multibyte_summary_truncates_at_char_boundary() {
        // 4-byte chars (CJK / emoji) — must split at char boundary,
        // never mid-byte sequence.
        let s = "中".repeat(400); // 1200 bytes
        let truncated = truncate_summary_at_boundary(&s);
        assert!(truncated.len() <= 1000);
        // Validity check: the truncation must produce a well-formed UTF-8 string.
        assert!(truncated.chars().next().is_some());
    }
}
