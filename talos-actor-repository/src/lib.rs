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

/// What an actor's LLM data-egress ceiling permits for ONE
/// LLM-over-actor-memory attempt (graph-RAG entity extraction OR Phase-3b
/// consolidation). Computed by [`ActorRepository::resolve_llm_tier_decision`];
/// callers select their backend strictly from this — no reading
/// `max_llm_tier` directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LlmTierDecision {
    /// Tier2 actor: any configured backend is permitted (external allowed).
    External,
    /// Tier1 actor on a deployment whose operator has attested the Ollama
    /// backend is on-host: the LOCAL backend ONLY. An external provider is
    /// NEVER consulted on this path, even when a key is present.
    LocalOnly,
    /// No LLM: tier1 without attestation, actor row missing, tier lookup
    /// error, or a future stricter-than-tier1 variant. Fail-closed default —
    /// the memory content never reaches any LLM.
    Skip,
}

/// One active actor row surfaced by the cross-tenant consolidation scan
/// ([`ActorRepository::scan_actors_for_consolidation`]). `max_llm_tier` is
/// carried so the loop can resolve the egress decision from the scanned row
/// (via [`llm_tier_decision_from_tier_str`]) without a per-actor tier lookup
/// (no N+1). The row's org is resolved inside the persist path, so it is not
/// carried here.
#[derive(Debug, Clone)]
pub struct ConsolidationActor {
    pub actor_id: Uuid,
    pub max_llm_tier: String,
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
    /// R2 token ledger: daily LLM token ceiling (prompt + completion,
    /// trailing 24 h). `None` = no ceiling.
    pub max_llm_tokens_per_day: Option<i64>,
}

/// R2 token ledger: one `(provider, model)` usage aggregate to insert into
/// the `llm_usage` ledger. Defined here (not the wire crate) so the
/// repository stays decoupled from the NATS job protocol.
#[derive(Debug, Clone)]
pub struct LlmUsageInsert {
    pub provider: String,
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub calls: i32,
}

/// R2 token ledger: per-(provider, model) usage rollup over a trailing
/// window, returned by `llm_usage_by_user_window` for the weekly report.
#[derive(Debug, Clone)]
pub struct LlmUsageWindowRow {
    pub provider: String,
    pub model: String,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub calls: i64,
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

/// Actor listing row (with workflow/execution counts) returned by
/// `list_actor_summaries_scoped`. Distinct from `ActorSummaryRow`
/// (the MCP `list_actors` shape) — this is the GraphQL `actors` query
/// projection with per-actor execution counts and `updated_at`.
#[derive(Debug, sqlx::FromRow)]
pub struct ActorSummaryWithCountsRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub workflow_count: i64,
    pub execution_count: i64,
}

/// Actor detail row returned by `get_actor_details_scoped`.
#[derive(Debug, sqlx::FromRow)]
pub struct ActorDetailsRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub status: String,
    pub max_capability_world: String,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub workflow_count: i64,
    pub execution_count: i64,
    pub last_active_at: Option<DateTime<Utc>>,
}

/// Per-actor execution status counts returned by
/// `get_actor_execution_counts_scoped`.
#[derive(Debug, sqlx::FromRow)]
pub struct ActorExecutionCountsRow {
    pub total: i64,
    pub successful: i64,
    pub failed: i64,
    pub active: i64,
}

/// Per-actor workflow counts returned by `get_actor_workflow_counts_scoped`.
#[derive(Debug, sqlx::FromRow)]
pub struct ActorWorkflowCountsRow {
    pub total: i64,
    pub active: i64,
}

/// Clone-source row returned by `get_actor_clone_source_scoped`.
#[derive(Debug, sqlx::FromRow)]
pub struct ActorCloneSourceRow {
    pub name: String,
    pub description: Option<String>,
    pub max_capability_world: Option<String>,
}

/// Action-log listing row (no `details` payload) returned by
/// `list_action_log_scoped`.
#[derive(Debug, sqlx::FromRow)]
pub struct ActionLogSummaryRow {
    pub id: Uuid,
    pub action_type: String,
    pub summary: String,
    pub timestamp: DateTime<Utc>,
    pub workflow_id: Option<Uuid>,
    pub execution_id: Option<Uuid>,
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

/// Process-global `user_id → (default actor id, cached-at)` cache for
/// [`ActorRepository::get_or_create_default_actor`].
///
/// Since Phase D2 the authorization gate resolves the default actor on
/// EVERY unbound dispatch — per scheduled tick and per webhook-chain
/// fan-out item — and each resolution is a user-scoped transaction
/// (BEGIN + GUC SETs + SELECT + COMMIT). The mapping it computes is
/// IMMUTABLE once created: the `idx_one_default_actor_per_user` partial
/// unique index guarantees a single default-actor row per user, the
/// row's id is never re-pointed, and actors are archived (never
/// hard-deleted) — so a cached hit can only ever return the same id the
/// SELECT would. Actor STATE (archived/suspended/budget) is deliberately
/// NOT part of this cache's contract: every dispatch path re-reads the
/// actor row through the gate's `get_actor` + `check_execution_allowed`,
/// which fail closed. The TTL is a belt-and-braces bound (a dangling id
/// after out-of-band row deletion heals within one TTL and fails closed
/// downstream in the meantime), not a correctness requirement.
///
/// Process-global (not per-`ActorRepository`) because call sites
/// construct fresh repository handles per dispatch. Bounded per the
/// keyed-cache sweep rule: inserts past `DEFAULT_ACTOR_CACHE_MAX` prune
/// expired entries first and fall back to clearing (cache, not store).
static DEFAULT_ACTOR_CACHE: std::sync::LazyLock<
    std::sync::RwLock<std::collections::HashMap<Uuid, (Uuid, std::time::Instant)>>,
> = std::sync::LazyLock::new(|| std::sync::RwLock::new(std::collections::HashMap::new()));

const DEFAULT_ACTOR_CACHE_TTL: std::time::Duration = std::time::Duration::from_secs(300);
const DEFAULT_ACTOR_CACHE_MAX: usize = 8192;

/// Cache read, extracted for unit testing (`default_actor_cache_tests`).
/// Returns the cached default-actor id when present and unexpired.
pub(crate) fn default_actor_cache_get(user_id: Uuid, now: std::time::Instant) -> Option<Uuid> {
    let cache = DEFAULT_ACTOR_CACHE.read().ok()?;
    cache.get(&user_id).and_then(|(actor_id, cached_at)| {
        (now.duration_since(*cached_at) < DEFAULT_ACTOR_CACHE_TTL).then_some(*actor_id)
    })
}

/// Cache write with the size-bound sweep. A poisoned lock degrades to
/// cache-off (every read misses) rather than panicking a dispatch path.
pub(crate) fn default_actor_cache_put(user_id: Uuid, actor_id: Uuid, now: std::time::Instant) {
    if let Ok(mut cache) = DEFAULT_ACTOR_CACHE.write() {
        if cache.len() >= DEFAULT_ACTOR_CACHE_MAX && !cache.contains_key(&user_id) {
            cache.retain(|_, (_, cached_at)| {
                now.duration_since(*cached_at) < DEFAULT_ACTOR_CACHE_TTL
            });
            if cache.len() >= DEFAULT_ACTOR_CACHE_MAX {
                cache.clear();
            }
        }
        cache.insert(user_id, (actor_id, now));
    }
}

#[derive(Clone)]
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
        // Hot path: the mapping is immutable once created (see the
        // DEFAULT_ACTOR_CACHE doc-comment for why a stale hit is safe),
        // and Phase D2 resolves it on every unbound scheduled fire and
        // chain fan-out item — the cache collapses a user-scoped tx
        // (4 round-trips) to a map read.
        let now = std::time::Instant::now();
        if let Some(id) = default_actor_cache_get(user_id, now) {
            return Ok(id);
        }
        let resolved = self.get_or_create_default_actor_uncached(user_id).await?;
        default_actor_cache_put(user_id, resolved, now);
        Ok(resolved)
    }

    /// The pre-cache body of [`Self::get_or_create_default_actor`].
    async fn get_or_create_default_actor_uncached(&self, user_id: Uuid) -> Result<Uuid> {
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

        rows.iter()
            .map(|r| -> Result<ActorSummaryRow> {
                Ok(ActorSummaryRow {
                    id: r.try_get("id")?,
                    name: r.try_get("name")?,
                    description: r.try_get("description")?,
                    status: r.try_get("status")?,
                    max_capability_world: r.try_get("max_capability_world")?,
                    workflow_count: r.try_get("workflow_count")?,
                    total_executions: r.try_get("total_executions")?,
                    last_active: r.try_get("last_active")?,
                    created_at: r.try_get("created_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
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

        row.map(|r| -> Result<ActorDetail> {
            Ok(ActorDetail {
                name: r.try_get("name")?,
                description: r.try_get("description")?,
                status: r.try_get("status")?,
                max_capability_world: r.try_get("max_capability_world")?,
                secret_grants: r.try_get("secret_grants")?,
                created_at: r.try_get("created_at")?,
                metadata: r.try_get("metadata")?,
            })
        })
        .transpose()
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

        row.map(|r| -> Result<ActorPostMutationSummary> {
            Ok(ActorPostMutationSummary {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                description: r.try_get("description")?,
                status: r.try_get("status")?,
                max_capability_world: r.try_get("max_capability_world")?,
                workflow_count: r.try_get::<Option<i64>, _>("workflow_count")?.unwrap_or(0),
                total_executions: r
                    .try_get::<Option<i64>, _>("total_executions")?
                    .unwrap_or(0),
                created_at: r.try_get("created_at")?,
                updated_at: r.try_get("updated_at")?,
            })
        })
        .transpose()
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

        row.map(|r| -> Result<ActorFullSummary> {
            Ok(ActorFullSummary {
                name: r.try_get("name")?,
                description: r.try_get("description")?,
                status: r.try_get("status")?,
                max_capability_world: r.try_get("max_capability_world")?,
                secret_grants: r.try_get("secret_grants")?,
                created_at: r.try_get("created_at")?,
                metadata: r.try_get("metadata")?,
                exec_total: r.try_get("exec_total")?,
                exec_last_24h: r.try_get("exec_last_24h")?,
                exec_completed: r.try_get("exec_completed")?,
                exec_failed: r.try_get("exec_failed")?,
                workflow_count: r.try_get("workflow_count")?,
                memory_count: r.try_get("memory_count")?,
                approval_policy_count: r.try_get("approval_policy_count")?,
                budget_max_executions_per_hour: r.try_get("max_executions_per_hour")?,
                budget_max_workflow_count: r.try_get("max_workflow_count")?,
                budget_on_exceeded: r.try_get("on_budget_exceeded")?,
            })
        })
        .transpose()
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
        max_llm_tokens_per_day: Option<i64>,
    ) -> Result<u64> {
        let result = sqlx::query(
            "INSERT INTO actor_budget_policies \
             (actor_id, max_executions_per_hour, max_executions_total, max_fuel_per_execution, \
              max_fuel_per_hour, max_outbound_requests_per_hour, max_workflow_count, \
              max_workflows_per_minute, max_compilations_per_hour, on_budget_exceeded, \
              max_llm_tokens_per_day, updated_at) \
             SELECT $1, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, now() \
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
                 max_llm_tokens_per_day         = EXCLUDED.max_llm_tokens_per_day, \
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
        .bind(max_llm_tokens_per_day)
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
                    max_workflows_per_minute, max_compilations_per_hour, on_budget_exceeded, \
                    max_llm_tokens_per_day \
             FROM actor_budget_policies WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_optional(&self.db_pool)
        .await?;

        row.map(|r| -> Result<ActorBudgetPolicy> {
            Ok(ActorBudgetPolicy {
                max_executions_per_hour: r.try_get("max_executions_per_hour")?,
                max_executions_total: r.try_get("max_executions_total")?,
                max_fuel_per_execution: r.try_get("max_fuel_per_execution")?,
                max_fuel_per_hour: r.try_get("max_fuel_per_hour")?,
                max_outbound_requests_per_hour: r.try_get("max_outbound_requests_per_hour")?,
                max_workflow_count: r.try_get("max_workflow_count")?,
                max_workflows_per_minute: r.try_get("max_workflows_per_minute")?,
                max_compilations_per_hour: r.try_get("max_compilations_per_hour")?,
                on_budget_exceeded: r.try_get("on_budget_exceeded")?,
                max_llm_tokens_per_day: r.try_get("max_llm_tokens_per_day")?,
            })
        })
        .transpose()
    }

    // ── R2 token ledger ────────────────────────────────────────────────────

    /// Batch-insert one verified result's LLM usage into the `llm_usage`
    /// ledger (UNNEST, single round-trip).
    ///
    /// SECURITY (identity from controller records): when `execution_id` is
    /// present, `workflow_id` / `org_id` — and the `actor_id` / `user_id`
    /// fallbacks — come from the controller's own `workflow_executions` row
    /// via the join; the dispatch-context `actor_id` / `user_id` arguments
    /// are themselves controller-stamped. Nothing identity-bearing is taken
    /// from the worker's result (it contributes only provider/model/counts).
    /// With no `execution_id` (controller-side scaffolding calls) the row
    /// records the caller-resolved `user_id` and NULL workflow/org.
    pub async fn record_llm_usage(
        &self,
        execution_id: Option<Uuid>,
        actor_id: Option<Uuid>,
        user_id: Option<Uuid>,
        entries: &[LlmUsageInsert],
    ) -> Result<u64> {
        if entries.is_empty() {
            return Ok(0);
        }
        let providers: Vec<String> = entries.iter().map(|e| e.provider.clone()).collect();
        let models: Vec<String> = entries.iter().map(|e| e.model.clone()).collect();
        let prompts: Vec<i64> = entries.iter().map(|e| e.prompt_tokens).collect();
        let completions: Vec<i64> = entries.iter().map(|e| e.completion_tokens).collect();
        let calls: Vec<i32> = entries.iter().map(|e| e.calls).collect();

        let result = sqlx::query(
            "INSERT INTO llm_usage \
             (execution_id, workflow_id, actor_id, user_id, org_id, \
              provider, model, prompt_tokens, completion_tokens, calls) \
             SELECT $1, we.workflow_id, COALESCE(we.actor_id, $2), \
                    COALESCE(we.user_id, $3), we.org_id, \
                    u.provider, u.model, u.prompt_tokens, u.completion_tokens, u.calls \
             FROM UNNEST($4::text[], $5::text[], $6::bigint[], $7::bigint[], $8::int[]) \
                  AS u(provider, model, prompt_tokens, completion_tokens, calls) \
             LEFT JOIN workflow_executions we ON we.id = $1",
        )
        .bind(execution_id)
        .bind(actor_id)
        .bind(user_id)
        .bind(&providers)
        .bind(&models)
        .bind(&prompts)
        .bind(&completions)
        .bind(&calls)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected())
    }

    /// Total LLM tokens (prompt + completion) attributed to an actor over
    /// the trailing 24 hours — the read side of the
    /// `max_llm_tokens_per_day` budget ceiling.
    pub async fn sum_llm_tokens_last_24h(&self, actor_id: Uuid) -> Result<i64> {
        let total: i64 = sqlx::query_scalar(
            "SELECT COALESCE(SUM(prompt_tokens + completion_tokens), 0)::bigint \
             FROM llm_usage \
             WHERE actor_id = $1 AND recorded_at > now() - INTERVAL '24 hours'",
        )
        .bind(actor_id)
        .fetch_one(&self.db_pool)
        .await?;
        Ok(total)
    }

    /// Per-(provider, model) LLM usage rollup for a user over the trailing
    /// `days` window — feeds the weekly assistant report's cost section.
    /// `days` is clamped to 1..=90 (check 27: pg `make_interval` int arg is
    /// int4-only, hence the `::int` cast).
    pub async fn llm_usage_by_user_window(
        &self,
        user_id: Uuid,
        days: i32,
    ) -> Result<Vec<LlmUsageWindowRow>> {
        let days = days.clamp(1, 90);
        let rows = sqlx::query(
            "SELECT provider, model, \
                    COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens, \
                    COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens, \
                    COALESCE(SUM(calls), 0)::bigint AS calls \
             FROM llm_usage \
             WHERE user_id = $1 AND recorded_at > now() - make_interval(days => $2::int) \
             GROUP BY provider, model \
             ORDER BY (COALESCE(SUM(prompt_tokens), 0) + COALESCE(SUM(completion_tokens), 0)) DESC, provider, model",
        )
        .bind(user_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter()
            .map(|r| -> Result<LlmUsageWindowRow> {
                Ok(LlmUsageWindowRow {
                    provider: r.try_get("provider")?,
                    model: r.try_get("model")?,
                    prompt_tokens: r.try_get("prompt_tokens")?,
                    completion_tokens: r.try_get("completion_tokens")?,
                    calls: r.try_get("calls")?,
                })
            })
            .collect()
    }

    /// Per-(provider, model) LLM usage rollup for ONE actor over the
    /// trailing `days` window — the per-model/provider spend breakdown for
    /// the actor-detail token-spend panel (GraphQL `llmUsageSummary`).
    /// Index-backed by `idx_llm_usage_actor_recorded (actor_id,
    /// recorded_at)`. `days` clamps 1..=90 like the sibling per-user
    /// rollup (check 27: `make_interval`'s arg is int4-only, hence the
    /// `::int` cast). `LIMIT 100` bounds the row count defensively —
    /// (provider, model) cardinality for one actor is normally tiny, but
    /// nothing stops it from growing unboundedly over a long window.
    pub async fn llm_usage_by_actor_window(
        &self,
        actor_id: Uuid,
        days: i32,
    ) -> Result<Vec<LlmUsageWindowRow>> {
        let days = days.clamp(1, 90);
        let rows = sqlx::query(
            "SELECT provider, model, \
                    COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens, \
                    COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens, \
                    COALESCE(SUM(calls), 0)::bigint AS calls \
             FROM llm_usage \
             WHERE actor_id = $1 AND recorded_at > now() - make_interval(days => $2::int) \
             GROUP BY provider, model \
             ORDER BY (COALESCE(SUM(prompt_tokens), 0) + COALESCE(SUM(completion_tokens), 0)) DESC, provider, model \
             LIMIT 100",
        )
        .bind(actor_id)
        .bind(days)
        .fetch_all(&self.db_pool)
        .await?;

        rows.into_iter()
            .map(|r| -> Result<LlmUsageWindowRow> {
                Ok(LlmUsageWindowRow {
                    provider: r.try_get("provider")?,
                    model: r.try_get("model")?,
                    prompt_tokens: r.try_get("prompt_tokens")?,
                    completion_tokens: r.try_get("completion_tokens")?,
                    calls: r.try_get("calls")?,
                })
            })
            .collect()
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

        row.map(|r| -> Result<ActorBudgetSummary> {
            Ok(ActorBudgetSummary {
                max_executions_per_hour: r.try_get("max_executions_per_hour")?,
                max_workflow_count: r.try_get("max_workflow_count")?,
                on_budget_exceeded: r.try_get("on_budget_exceeded")?,
            })
        })
        .transpose()
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

    /// Look up an actor's full tenancy pair `(user_id, org_id)`. Returns
    /// `Ok(None)` when the actor doesn't exist. Used by the `__ops_alert__`
    /// node hook to stamp ownership on ingested alerts — same shape as
    /// [`Self::get_actor_owner_user_id`] plus the (nullable) org, in one
    /// round-trip instead of two.
    pub async fn get_actor_tenancy(&self, actor_id: Uuid) -> Result<Option<(Uuid, Option<Uuid>)>> {
        let row = sqlx::query("SELECT user_id, org_id FROM actors WHERE id = $1")
            .bind(actor_id)
            .fetch_optional(&self.db_pool)
            .await?;
        row.map(|r| -> Result<(Uuid, Option<Uuid>)> {
            Ok((r.try_get("user_id")?, r.try_get::<Option<_>, _>("org_id")?))
        })
        .transpose()
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
            .map(|r| -> Result<ActorExecStats> {
                Ok(ActorExecStats {
                    total: r.try_get("total")?,
                    last_24h: r.try_get("last_24h")?,
                    completed: r.try_get("completed")?,
                    failed: r.try_get("failed")?,
                })
            })
            .transpose()?
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

        rows.iter()
            .map(|r| -> Result<ApprovalPolicyRow> {
                Ok(ApprovalPolicyRow {
                    id: r.try_get("id")?,
                    trigger_condition: r.try_get("trigger_condition")?,
                    approval_mode: r.try_get("approval_mode")?,
                    approvers: r.try_get("approvers")?,
                    created_at: r.try_get("created_at")?,
                })
            })
            .collect::<Result<Vec<_>>>()
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

    // ── Scoped read surface (GraphQL actors resolvers) ────────────────────
    //
    // The methods below take the caller's `&mut PgConnection` instead of
    // routing through `self.db_pool`: the GraphQL resolvers run them on a
    // tenant-scoped tx / UnitOfWork (RFC 0004/0005) so the actors /
    // workflows / workflow_executions RLS policies backstop the app-layer
    // predicates. Do NOT add pool-routing variants for those paths — that
    // would silently drop the RLS backstop.

    /// Actor list for a user with workflow/execution counts, newest first.
    /// Run on a tenant-read-scoped tx (real org ids keep the RLS-enabled
    /// COUNT subqueries counting teammates' executions on org-shared
    /// workflows).
    pub async fn list_actor_summaries_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        user_id: Uuid,
    ) -> Result<Vec<ActorSummaryWithCountsRow>> {
        let rows = sqlx::query_as::<_, ActorSummaryWithCountsRow>(
            r#"SELECT
                a.id, a.name, a.description, a.status, a.max_capability_world,
                a.created_at, a.updated_at,
                (SELECT COUNT(*) FROM workflows w WHERE w.actor_id = a.id) as workflow_count,
                (SELECT COUNT(*) FROM workflow_executions we
                 JOIN workflows w ON w.id = we.workflow_id
                 WHERE w.actor_id = a.id) as execution_count
             FROM actors a
             WHERE a.user_id = $1
             ORDER BY a.created_at DESC"#,
        )
        .bind(user_id)
        .fetch_all(conn)
        .await?;
        Ok(rows)
    }

    /// Single-actor detail (ownership-gated) with counts + last-active.
    /// Same tenant-read-scoped executor contract as
    /// `list_actor_summaries_scoped`.
    pub async fn get_actor_details_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ActorDetailsRow>> {
        let row = sqlx::query_as::<_, ActorDetailsRow>(
            r#"SELECT
                a.id, a.name, a.description, a.status, a.max_capability_world, a.metadata,
                a.created_at, a.updated_at,
                (SELECT COUNT(*) FROM workflows w WHERE w.actor_id = a.id) as workflow_count,
                (SELECT COUNT(*) FROM workflow_executions we
                 WHERE we.actor_id = a.id) as execution_count,
                (SELECT MAX(we.started_at) FROM workflow_executions we
                 WHERE we.actor_id = a.id) as last_active_at
             FROM actors a
             WHERE a.id = $1 AND a.user_id = $2"#,
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_optional(conn)
        .await?;
        Ok(row)
    }

    /// True if the actor exists and belongs to `user_id`. Runs on the
    /// caller's scoped connection so the actors RLS policy backstops the
    /// ownership predicate within the same snapshot as the read it gates.
    pub async fn actor_owned_by_user_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM actors WHERE id = $1 AND user_id = $2)",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_one(conn)
        .await?;
        Ok(exists)
    }

    /// Execution status counts for an actor (`workflow_executions` RLS
    /// backstops via the caller's scoped connection).
    pub async fn get_actor_execution_counts_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
    ) -> Result<ActorExecutionCountsRow> {
        let row = sqlx::query_as::<_, ActorExecutionCountsRow>(
            "SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status = 'completed') AS successful,
                COUNT(*) FILTER (WHERE status = 'failed') AS failed,
                COUNT(*) FILTER (WHERE status IN ('pending', 'running')) AS active
             FROM workflow_executions WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_one(conn)
        .await?;
        Ok(row)
    }

    /// Workflow counts for an actor (`workflows` RLS backstops via the
    /// caller's scoped connection).
    pub async fn get_actor_workflow_counts_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
    ) -> Result<ActorWorkflowCountsRow> {
        let row = sqlx::query_as::<_, ActorWorkflowCountsRow>(
            "SELECT
                COUNT(*) AS total,
                COUNT(*) FILTER (WHERE status != 'archived' OR status IS NULL) AS active
             FROM workflows WHERE actor_id = $1",
        )
        .bind(actor_id)
        .fetch_one(conn)
        .await?;
        Ok(row)
    }

    /// Newest-first action-log page (no `details` payload — the GraphQL
    /// listing shape). Runs on the caller's scoped connection, sharing the
    /// snapshot with the ownership check that gates it.
    pub async fn list_action_log_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
        limit: i64,
    ) -> Result<Vec<ActionLogSummaryRow>> {
        let rows = sqlx::query_as::<_, ActionLogSummaryRow>(
            r#"SELECT id, action_type, summary, timestamp, workflow_id, execution_id
               FROM actor_action_log
               WHERE actor_id = $1
               ORDER BY timestamp DESC
               LIMIT $2"#,
        )
        .bind(actor_id)
        .bind(limit)
        .fetch_all(conn)
        .await?;
        Ok(rows)
    }

    /// Insert a new actor row (status 'active'). Takes the caller's
    /// connection: actors are ORG-pinned (RFC 0006 — the RLS WITH CHECK
    /// keys on `org_id = app.current_org_id`), so the GraphQL create /
    /// clone mutations run this on a `begin_org_scoped` tx opened for the
    /// owner's personal org. Do NOT route through `self.db_pool`; a
    /// bare-pool create only passes the org pin via its rollout-safe
    /// `unset → permit` clause (i.e. silently un-enforced — check 42).
    ///
    /// Errors are returned WITHOUT added context so callers can inspect
    /// the raw Postgres message (unique-violation detection).
    pub async fn insert_actor_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
        user_id: Uuid,
        name: &str,
        description: Option<&str>,
        max_capability_world: &str,
    ) -> Result<()> {
        sqlx::query(
            "INSERT INTO actors (id, user_id, name, description, max_capability_world, status) \
             VALUES ($1, $2, $3, $4, $5, 'active')",
        )
        .bind(actor_id)
        .bind(user_id)
        .bind(name)
        .bind(description)
        .bind(max_capability_world)
        .execute(conn)
        .await?;
        Ok(())
    }

    /// Set an actor's status (ownership-gated), refusing terminal-state
    /// rows — the `status NOT IN ('archived','terminated')` guard makes
    /// the IRREVERSIBLE contract on terminate/archive unconditional
    /// (MCP-645/647). Takes the caller's connection (per-user scoped tx;
    /// RFC 0005 S3 — USING doubles as WITH CHECK). Returns rows affected
    /// (0 = missing / not owned / terminal).
    pub async fn update_actor_status_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
        user_id: Uuid,
        status: &str,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE actors SET status = $1, updated_at = now() \
             WHERE id = $2 AND user_id = $3 \
             AND status NOT IN ('archived', 'terminated')",
        )
        .bind(status)
        .bind(actor_id)
        .bind(user_id)
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }

    /// Mark an actor terminated (ownership-gated, no terminal guard —
    /// terminating a terminated actor is a no-op rewrite of the same
    /// state). Takes the caller's connection (per-user scoped tx).
    /// Returns rows affected.
    pub async fn terminate_actor_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<u64> {
        let result = sqlx::query(
            "UPDATE actors SET status = 'terminated', updated_at = now() \
             WHERE id = $1 AND user_id = $2",
        )
        .bind(actor_id)
        .bind(user_id)
        .execute(conn)
        .await?;
        Ok(result.rows_affected())
    }

    /// Partial-update an actor's name / description / capability world
    /// (ownership-gated). At least one field must be Some — callers
    /// validate that upstream. Takes the caller's connection (per-user
    /// scoped tx). Returns rows affected.
    ///
    /// Errors are returned WITHOUT added context so callers can inspect
    /// the raw Postgres message (unique/duplicate-name detection).
    pub async fn update_actor_fields_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
        user_id: Uuid,
        name: Option<&str>,
        description: Option<&str>,
        max_capability_world: Option<&str>,
    ) -> Result<u64> {
        // Dynamic SET clause; param_count tracks bound parameters
        // separately from set_parts because "updated_at = NOW()" has no
        // bind (same shape as WorkflowRepository::update_workflow_metadata).
        let mut set_parts: Vec<String> = vec!["updated_at = NOW()".to_string()];
        let mut param_count = 0usize;
        if name.is_some() {
            param_count += 1;
            set_parts.push(format!("name = ${}", param_count));
        }
        if description.is_some() {
            param_count += 1;
            set_parts.push(format!("description = ${}", param_count));
        }
        if max_capability_world.is_some() {
            param_count += 1;
            set_parts.push(format!("max_capability_world = ${}", param_count));
        }
        let sql = format!(
            "UPDATE actors SET {} WHERE id = ${} AND user_id = ${}",
            set_parts.join(", "),
            param_count + 1,
            param_count + 2,
        );
        let mut q = sqlx::query(&sql);
        if let Some(n) = name {
            q = q.bind(n.trim());
        }
        if let Some(d) = description {
            q = q.bind(d);
        }
        if let Some(w) = max_capability_world {
            q = q.bind(w);
        }
        let result = q.bind(actor_id).bind(user_id).execute(conn).await?;
        Ok(result.rows_affected())
    }

    /// True if the actor exists, belongs to `user_id`, AND is not
    /// terminated. Ownership gate for writes that must refuse terminated
    /// actors (e.g. memory writes). Takes the caller's scoped connection.
    pub async fn actor_owned_active_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<bool> {
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM actors WHERE id = $1 AND user_id = $2 AND status != 'terminated')",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_one(conn)
        .await?;
        Ok(exists)
    }

    /// Clone-source fields for a non-terminated actor the user owns.
    /// Takes the caller's connection — the GraphQL clone mutation runs
    /// this ownership read and the clone INSERT in ONE org-scoped tx.
    pub async fn get_actor_clone_source_scoped(
        &self,
        conn: &mut sqlx::PgConnection,
        actor_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<ActorCloneSourceRow>> {
        let row = sqlx::query_as::<_, ActorCloneSourceRow>(
            "SELECT name, description, max_capability_world FROM actors \
             WHERE id = $1 AND user_id = $2 AND status != 'terminated'",
        )
        .bind(actor_id)
        .bind(user_id)
        .fetch_optional(conn)
        .await?;
        Ok(row)
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

        rows.iter()
            .map(|r| -> Result<ActionLogEntry> {
                Ok(ActionLogEntry {
                    id: r.try_get("id")?,
                    timestamp: r.try_get("timestamp")?,
                    action_type: r.try_get("action_type")?,
                    workflow_id: r.try_get("workflow_id")?,
                    execution_id: r.try_get("execution_id")?,
                    summary: r.try_get("summary")?,
                    details: r.try_get("details")?,
                })
            })
            .collect::<Result<Vec<_>>>()
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

        row.map(|r| -> Result<UserCapabilityGrant> {
            Ok(UserCapabilityGrant {
                max_capability_world: r.try_get("max_capability_world")?,
                granted_by: r.try_get("granted_by")?,
                granted_at: r.try_get("granted_at")?,
                notes: r.try_get("notes")?,
            })
        })
        .transpose()
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

    /// Resolve the LLM data-egress decision for an actor whose memory is
    /// about to be summarized by an LLM. This is the SINGLE canonical
    /// fail-closed tier gate shared by graph-RAG's entity-extraction path
    /// (`talos_graph_rag::ExtractionService`) AND the Phase-3b memory
    /// consolidation loop (`talos_memory_consolidation`) — do NOT reimplement
    /// the decision matrix; a security decision copy-pasted drifts.
    ///
    /// The matrix (both callers depend on this exact behaviour):
    ///   * `Tier2`  → [`LlmTierDecision::External`] (any backend permitted).
    ///   * `Tier1`  → [`LlmTierDecision::LocalOnly`] ONLY when BOTH the
    ///     operator has attested the Ollama backend is on-host
    ///     (`tier1_local_ok`) AND that backend is actually wired
    ///     (`ollama_available`); otherwise [`LlmTierDecision::Skip`]. The
    ///     attestation vouches for the backend's locality, not for
    ///     unattributable writes — it never widens the Skip cases below.
    ///   * `Ok(None)` (actor row missing) → [`LlmTierDecision::Skip`]. A
    ///     memory referencing a missing actor is unusual; fail closed rather
    ///     than leak privacy-sensitive content to an external provider.
    ///   * `Err(...)` (DB error) → [`LlmTierDecision::Skip`] (fail closed).
    ///   * Any future stricter-than-tier1 variant → [`LlmTierDecision::Skip`]
    ///     (`LlmTier` is non-exhaustive; a new stricter tier must not inherit
    ///     tier1's local-attestation carve-out).
    pub async fn resolve_llm_tier_decision(
        &self,
        actor_id: Uuid,
        tier1_local_ok: bool,
        ollama_available: bool,
    ) -> LlmTierDecision {
        let lookup = self.get_actor_max_llm_tier(actor_id).await;
        // Log the fail-closed cases here (async context) so operators can
        // correlate a Skip with the underlying cause; the pure decision
        // matrix itself lives in `decide_llm_tier` so it's unit-testable
        // without Postgres.
        match &lookup {
            Ok(None) => tracing::warn!(
                target: "talos_actor_repository",
                actor_id = %actor_id,
                "resolve_llm_tier_decision: actor not found — failing closed (Skip)"
            ),
            Err(e) => tracing::warn!(
                target: "talos_actor_repository",
                actor_id = %actor_id,
                error = %e,
                "resolve_llm_tier_decision: tier lookup failed — failing closed (Skip)"
            ),
            _ => {}
        }
        decide_llm_tier(lookup.map_err(|_| ()), tier1_local_ok, ollama_available)
    }

    /// Cross-tenant scan of active actors for the Phase-3b consolidation
    /// loop. Returns [`ConsolidationActor`] (`actor_id` + `max_llm_tier`) for up
    /// to `limit` active actors, ordered by `last_consolidated_at ASC NULLS
    /// FIRST, id` — a least-recently-swept rotation cursor for fair fleet
    /// coverage — in a single N+1-free query (the tier is carried on the row,
    /// so no per-actor tier lookup).
    ///
    /// This is a PLATFORM scan: the consolidation loop runs AS the platform
    /// background service, not on behalf of any single user, so no RLS tenant
    /// scope is applied here (same posture as `talos-ml`'s teacher-audit
    /// `scan_candidates`). The per-actor tier gate
    /// ([`llm_tier_decision_from_tier_str`] over the carried `max_llm_tier`) is
    /// what bounds where each actor's memory may go; the row's org is resolved
    /// inside the persist path, not carried here.
    pub async fn scan_actors_for_consolidation(
        &self,
        limit: i64,
    ) -> Result<Vec<ConsolidationActor>> {
        // Least-recently-swept first (rotation cursor): `last_consolidated_at
        // ASC NULLS FIRST` guarantees every active actor is eventually reached
        // even when the fleet exceeds `limit` — an `ORDER BY id` scan would
        // starve higher-id actors forever. `mark_actors_consolidated` advances
        // the cursor after each tick. `id` is the stable tiebreaker.
        let rows = sqlx::query(
            "SELECT id, max_llm_tier FROM actors \
             WHERE status = 'active' \
             ORDER BY last_consolidated_at ASC NULLS FIRST, id \
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            // Fail-loud reads (checks 52/55): schema drift errors instead of
            // silently defaulting. `id`/`max_llm_tier` are NOT NULL.
            let actor_id: Uuid = r.try_get::<Uuid, _>("id")?;
            // Fail CLOSED on the (unreachable — NOT NULL DEFAULT) NULL case:
            // an absent tier must not become tier2/External. "tier1" →
            // most-restrictive; `LlmTier::from_db_str` maps unknown → Tier1 too.
            let max_llm_tier: String = r
                .try_get::<Option<String>, _>("max_llm_tier")?
                .unwrap_or_else(|| "tier1".to_string());
            out.push(ConsolidationActor {
                actor_id,
                max_llm_tier,
            });
        }
        Ok(out)
    }

    /// Advance the consolidation rotation cursor for every actor a tick
    /// processed (consolidated OR skipped), so the next tick moves on to the
    /// least-recently-swept actors. Best-effort: a failure here only means the
    /// next tick may re-examine the same actors, never data loss. No-op on an
    /// empty slice.
    pub async fn mark_actors_consolidated(&self, actor_ids: &[Uuid]) -> Result<u64> {
        if actor_ids.is_empty() {
            return Ok(0);
        }
        let result =
            sqlx::query("UPDATE actors SET last_consolidated_at = now() WHERE id = ANY($1)")
                .bind(actor_ids)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected())
    }

    /// Batch scan for the autonomous memory-REFLECTION loop (Phase 3). Returns
    /// [`ConsolidationActor`] (`actor_id` + `max_llm_tier`) for up to `limit`
    /// active actors, ordered by `last_reflected_at ASC NULLS FIRST, id` — a
    /// least-recently-reflected rotation cursor for fair fleet coverage — in a
    /// single N+1-free query (the tier is carried on the row, so no per-actor
    /// tier lookup).
    ///
    /// Reflection uses its OWN cursor column (`last_reflected_at`), distinct
    /// from consolidation's `last_consolidated_at`, so the two independent-cadence
    /// loops never couple their rotation. Same PLATFORM-scan posture as
    /// [`scan_actors_for_consolidation`]: it runs AS the background service, not
    /// on behalf of any user, so no RLS tenant scope is applied; the per-actor
    /// tier gate ([`llm_tier_decision_from_tier_str`] over the carried
    /// `max_llm_tier`) is what bounds where each actor's memory may go.
    pub async fn scan_actors_for_reflection(&self, limit: i64) -> Result<Vec<ConsolidationActor>> {
        // Least-recently-reflected first (rotation cursor): `last_reflected_at
        // ASC NULLS FIRST` guarantees every active actor is eventually reached
        // even when the fleet exceeds `limit`. `mark_actors_reflected` advances
        // the cursor after each tick. `id` is the stable tiebreaker.
        let rows = sqlx::query(
            "SELECT id, max_llm_tier FROM actors \
             WHERE status = 'active' \
             ORDER BY last_reflected_at ASC NULLS FIRST, id \
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;

        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            // Fail-loud reads (checks 52/55): schema drift errors instead of
            // silently defaulting. `id`/`max_llm_tier` are NOT NULL.
            let actor_id: Uuid = r.try_get::<Uuid, _>("id")?;
            // Fail CLOSED on the (unreachable — NOT NULL DEFAULT) NULL case:
            // an absent tier must not become tier2/External. "tier1" →
            // most-restrictive; `LlmTier::from_db_str` maps unknown → Tier1 too.
            let max_llm_tier: String = r
                .try_get::<Option<String>, _>("max_llm_tier")?
                .unwrap_or_else(|| "tier1".to_string());
            out.push(ConsolidationActor {
                actor_id,
                max_llm_tier,
            });
        }
        Ok(out)
    }

    /// Advance the reflection rotation cursor for every actor a tick processed
    /// (reflected OR skipped), so the next tick moves on to the
    /// least-recently-reflected actors. Best-effort: a failure here only means
    /// the next tick may re-examine the same actors, never data loss. No-op on
    /// an empty slice.
    pub async fn mark_actors_reflected(&self, actor_ids: &[Uuid]) -> Result<u64> {
        if actor_ids.is_empty() {
            return Ok(0);
        }
        let result = sqlx::query("UPDATE actors SET last_reflected_at = now() WHERE id = ANY($1)")
            .bind(actor_ids)
            .execute(&self.db_pool)
            .await?;
        Ok(result.rows_affected())
    }

    // ── Adaptive per-actor memory ranking — Phase 2 (learned weights) ──────
    //
    // Learned per-actor fused-ranking weights are stored in the actor's
    // `metadata.rank_weights` JSONB slot. The three methods below are the
    // read (serving), write (training-fit), and scan (training rotation)
    // surfaces. Every one keys STRICTLY on `actor_id` — the per-actor tenancy
    // isolation invariant: one actor's fit can only ever read/write its OWN
    // row, so one actor's outcomes can never influence another's weights.
    // RLS on `actors` is a defence-in-depth backstop; the `WHERE id = $1`
    // predicate is the primary guarantee.

    /// Read the learned rank-weights blob (`actors.metadata->'rank_weights'`)
    /// for one actor. `Ok(None)` when the actor is missing OR has no learned
    /// weights yet (cold-start). Fail-loud read (`try_get::<Option<_>,_>()?`)
    /// so a projection/type drift errors instead of silently defaulting
    /// (checks 52/55). Keyed on `actor_id` only — pure per-actor isolation.
    pub async fn get_actor_rank_weights(
        &self,
        actor_id: Uuid,
    ) -> Result<Option<serde_json::Value>> {
        let row = sqlx::query(
            "SELECT metadata->'rank_weights' AS rank_weights FROM actors WHERE id = $1",
        )
        .bind(actor_id)
        .fetch_optional(&self.db_pool)
        .await?;
        match row {
            Some(r) => Ok(r.try_get::<Option<serde_json::Value>, _>("rank_weights")?),
            None => Ok(None),
        }
    }

    /// Persist the learned rank-weights blob into `actors.metadata.rank_weights`
    /// for one actor (the training-fit writer). Uses `jsonb_set` over a
    /// `COALESCE(metadata,'{}')` so a NULL-metadata actor is handled and every
    /// OTHER metadata key is preserved. Keyed STRICTLY on `actor_id` — a fit for
    /// one actor can only ever write that actor's row (per-actor isolation; RLS
    /// is the backstop). Returns true if a row was updated.
    pub async fn set_actor_rank_weights(
        &self,
        actor_id: Uuid,
        rank_weights: &serde_json::Value,
    ) -> Result<bool> {
        let result = sqlx::query(
            "UPDATE actors \
             SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{rank_weights}', $2), \
                 updated_at = NOW() \
             WHERE id = $1",
        )
        .bind(actor_id)
        .bind(rank_weights)
        .execute(&self.db_pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Cross-tenant scan of active actors for the Phase-2 rank-training loop.
    /// Returns up to `limit` active actor ids.
    ///
    /// This is a PLATFORM scan (same posture as `scan_actors_for_consolidation`
    /// and `talos-ml`'s teacher-audit): the training loop runs AS the platform
    /// background service, not on behalf of any single user, so no RLS tenant
    /// scope is applied. The subsequent fit + write is keyed per `actor_id`,
    /// which is where per-actor tenancy isolation lives.
    ///
    /// Rotation: ordered `ORDER BY id` (deterministic, stable). For a fleet
    /// SMALLER than `limit` (the common case — the training set is small and
    /// `ADAPTIVE_RANK_MAX_ACTORS_PER_TICK` defaults to 50) every actor is
    /// reached each tick, so no cursor is needed. If the active fleet grows
    /// beyond one tick's `limit`, a dedicated `last_rank_trained_at` rotation
    /// cursor (mirroring consolidation's `last_consolidated_at`) is the
    /// follow-up — deliberately deferred for v1 to avoid a migration, since
    /// a stale-but-present learned weight simply keeps serving the last fit.
    pub async fn scan_actors_for_rank_training(&self, limit: i64) -> Result<Vec<Uuid>> {
        // Least-recently-trained first (rotation cursor): never-trained actors
        // (`last_rank_trained_at IS NULL`) sort FIRST, so every active actor is
        // eventually fit even when the fleet exceeds one tick's `limit` — an
        // `ORDER BY id` scan would train only the lowest-id N forever and leave
        // the rest permanently on global weights. `mark_actors_rank_trained`
        // advances the cursor after each tick. `id` is the stable tiebreaker.
        let rows = sqlx::query(
            "SELECT id FROM actors WHERE status = 'active' \
             ORDER BY last_rank_trained_at ASC NULLS FIRST, id \
             LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.db_pool)
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for r in &rows {
            // Fail-loud read (checks 52/55): `id` is NOT NULL — a drift errors.
            out.push(r.try_get::<Uuid, _>("id")?);
        }
        Ok(out)
    }

    /// Advance the rank-training rotation cursor for every actor a tick examined
    /// (fit OR skipped for too-few examples), so the next tick moves on to the
    /// least-recently-trained actors. Best-effort — a failure only means a
    /// repeat next tick, never data loss. No-op on an empty slice.
    pub async fn mark_actors_rank_trained(&self, actor_ids: &[Uuid]) -> Result<u64> {
        if actor_ids.is_empty() {
            return Ok(0);
        }
        let result =
            sqlx::query("UPDATE actors SET last_rank_trained_at = now() WHERE id = ANY($1)")
                .bind(actor_ids)
                .execute(&self.db_pool)
                .await?;
        Ok(result.rows_affected())
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

    /// Fetch the data-mutation ceiling for an actor.
    /// Returns `Ok(Some(ceiling))` on success, `Ok(None)` when the actor
    /// doesn't exist, `Err` on DB failure. Never masks DB errors as
    /// `Write` — see `talos_engine::actor_binding::apply_actor_to_engine`
    /// for the fail-closed (`ReadOnly`) contract.
    pub async fn get_actor_max_write_ceiling(
        &self,
        actor_id: Uuid,
    ) -> Result<Option<talos_workflow_job_protocol::WriteCeiling>> {
        let row: Option<String> =
            sqlx::query_scalar("SELECT max_write_ceiling FROM actors WHERE id = $1")
                .bind(actor_id)
                .fetch_optional(&self.db_pool)
                .await?;
        Ok(row
            .as_deref()
            .map(talos_workflow_job_protocol::WriteCeiling::from_db_str))
    }

    /// Set an actor's data-mutation ceiling. Validates user ownership
    /// before mutating. Returns true if the row was updated, false if
    /// the actor doesn't exist or doesn't belong to the user.
    pub async fn set_actor_max_write_ceiling(
        &self,
        actor_id: Uuid,
        user_id: Uuid,
        ceiling: talos_workflow_job_protocol::WriteCeiling,
    ) -> Result<bool> {
        // The `actors_write_ceiling_grant_guard` trigger (migration
        // 20260709180000) blocks any `readonly -> write` escalation unless
        // the session opts in via this transaction-local GUC. This is the
        // ONLY sanctioned grant path, so it is the only place the GUC is set
        // — a bulk / migration-re-run `UPDATE actors SET
        // max_write_ceiling='write'` carries no GUC and is refused, which is
        // exactly the clobber we're guarding against. `set_config(..., true)`
        // scopes the setting to this transaction. Locking DOWN
        // (write -> readonly) doesn't strictly need the GUC, but setting it
        // unconditionally keeps this path simple and is harmless.
        let mut tx = self.db_pool.begin().await?;
        sqlx::query("SELECT set_config('talos.allow_ceiling_grant', 'on', true)")
            .execute(&mut *tx)
            .await?;
        let result =
            sqlx::query("UPDATE actors SET max_write_ceiling = $1 WHERE id = $2 AND user_id = $3")
                .bind(ceiling.as_signing_str())
                .bind(actor_id)
                .bind(user_id)
                .execute(&mut *tx)
                .await?;
        tx.commit().await?;
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

    /// Fetch a user's email by id (e.g. to display who granted a
    /// capability ceiling). No `is_active` filter — deactivated granters
    /// still resolve for audit display.
    pub async fn get_user_email(&self, user_id: Uuid) -> Result<Option<String>> {
        let email: Option<String> = sqlx::query_scalar("SELECT email FROM users WHERE id = $1")
            .bind(user_id)
            .fetch_optional(&self.db_pool)
            .await?;
        Ok(email)
    }

    /// The user's personal organization (id + name) — the org their
    /// MCP-created resources are stamped with. Used by `whoami` so an
    /// identity/tenancy mismatch (an MCP token authenticating as a
    /// different user/org than the UI login) is diagnosable in one call
    /// instead of an investigation.
    pub async fn get_user_org_summary(&self, user_id: Uuid) -> Result<Option<(Uuid, String)>> {
        let row: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT o.id, o.name FROM organizations o \
             JOIN organization_members om ON om.org_id = o.id \
             WHERE om.user_id = $1 AND o.is_personal = true \
             LIMIT 1",
        )
        .bind(user_id)
        .fetch_optional(&self.db_pool)
        .await?;
        Ok(row)
    }

    /// True if a user row exists for this id (any state — no `is_active`
    /// filter). Used as the target-exists gate before writing a
    /// capability grant.
    pub async fn user_exists(&self, user_id: Uuid) -> Result<bool> {
        let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)")
            .bind(user_id)
            .fetch_one(&self.db_pool)
            .await?;
        Ok(exists)
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

        rows.iter()
            .map(|r| -> Result<CapabilityGrantRow> {
                Ok(CapabilityGrantRow {
                    user_id: r.try_get("user_id")?,
                    email: r.try_get("email")?,
                    max_capability_world: r.try_get("max_capability_world")?,
                    granted_by: r.try_get("granted_by")?,
                    granted_at: r.try_get("granted_at")?,
                    notes: r.try_get("notes")?,
                })
            })
            .collect::<Result<Vec<_>>>()
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

        row.map(|r| -> Result<SourceActorCloneRow> {
            Ok(SourceActorCloneRow {
                max_capability_world: r.try_get("max_capability_world")?,
                description: r.try_get::<Option<_>, _>("description")?,
                secret_grants: r
                    .try_get::<Option<_>, _>("secret_grants")?
                    .unwrap_or_default(),
            })
        })
        .transpose()
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

        row.map(|r| -> Result<ActorBasicInfo> {
            Ok(ActorBasicInfo {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
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
            })
        })
        .transpose()
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
        rows.iter()
            .map(|r| -> Result<ActorBasicSummary> {
                Ok(ActorBasicSummary {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    description: r.try_get::<Option<_>, _>("description")?,
                    max_capability_world: r
                        .try_get::<Option<_>, _>("max_capability_world")?
                        .unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()
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
        rows.iter()
            .map(|r| -> Result<ActorMemorySimilarityRow> {
                Ok(ActorMemorySimilarityRow {
                    actor_id: r
                        .try_get::<Option<_>, _>("actor_id")?
                        .unwrap_or(Uuid::nil()),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    description: r.try_get::<Option<_>, _>("description")?,
                    max_capability_world: r
                        .try_get::<Option<_>, _>("max_capability_world")?
                        .unwrap_or_default(),
                    best_score: r.try_get::<Option<_>, _>("best_score")?.unwrap_or(0.0),
                    memory_count: r.try_get::<Option<_>, _>("memory_count")?.unwrap_or(0),
                })
            })
            .collect::<Result<Vec<_>>>()
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
                key: r.try_get::<Option<_>, _>("key")?.unwrap_or_default(),
                value,
                memory_type: r
                    .try_get::<Option<_>, _>("memory_type")?
                    .unwrap_or_default(),
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
                key: r.try_get::<Option<_>, _>("key")?.unwrap_or_default(),
                value,
                memory_type: r
                    .try_get::<Option<_>, _>("memory_type")?
                    .unwrap_or_default(),
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
        row.map(|r| -> Result<ActorCardInfo> {
            Ok(ActorCardInfo {
                name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                description: r
                    .try_get::<Option<String>, _>("description")
                    .unwrap_or(None),
                status: r.try_get::<Option<_>, _>("status")?.unwrap_or_default(),
                max_capability_world: r
                    .try_get::<Option<_>, _>("max_capability_world")?
                    .unwrap_or_default(),
            })
        })
        .transpose()
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
        rows.iter()
            .map(|r| -> Result<(Uuid, String)> {
                Ok((
                    r.try_get::<Option<Uuid>, _>("id")?.unwrap_or_default(),
                    r.try_get::<Option<String>, _>("name")?.unwrap_or_default(),
                ))
            })
            .collect::<Result<Vec<_>>>()
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
        rows.iter()
            .map(|r| -> Result<PublishedWorkflowRow> {
                Ok(PublishedWorkflowRow {
                    id: r.try_get::<Option<_>, _>("id")?.unwrap_or_default(),
                    name: r.try_get::<Option<_>, _>("name")?.unwrap_or_default(),
                    description: r.try_get::<Option<_>, _>("description")?,
                    capabilities: r
                        .try_get::<Option<_>, _>("capabilities")?
                        .unwrap_or_default(),
                })
            })
            .collect::<Result<Vec<_>>>()
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

/// Pure fail-closed tier-decision matrix, factored out of
/// [`ActorRepository::resolve_llm_tier_decision`] so every arm is unit-testable
/// without a real ActorRepository or Postgres. `lookup` is the resolved outcome
/// of `get_actor_max_llm_tier` with its error type erased to `()` (the caller
/// logs before erasing). Keep this in sync with the async method's doc-comment
/// contract — this IS the contract.
pub(crate) fn decide_llm_tier(
    lookup: Result<Option<talos_workflow_job_protocol::LlmTier>, ()>,
    tier1_local_ok: bool,
    ollama_available: bool,
) -> LlmTierDecision {
    match lookup {
        Ok(Some(talos_workflow_job_protocol::LlmTier::Tier2)) => LlmTierDecision::External,
        Ok(Some(talos_workflow_job_protocol::LlmTier::Tier1)) => {
            if tier1_local_ok && ollama_available {
                LlmTierDecision::LocalOnly
            } else {
                LlmTierDecision::Skip
            }
        }
        // `LlmTier` is non-exhaustive — a future stricter-than-tier1 variant
        // must not inherit tier1's local carve-out.
        #[allow(unreachable_patterns)]
        Ok(Some(_)) => LlmTierDecision::Skip,
        Ok(None) => LlmTierDecision::Skip, // actor missing — fail closed
        Err(()) => LlmTierDecision::Skip,  // DB error — fail closed
    }
}

/// Resolve the egress decision from an ALREADY-FETCHED `max_llm_tier` string
/// (e.g. the value carried on a [`ConsolidationActor`] from the batch scan),
/// avoiding a per-actor tier lookup (no N+1). The string is mapped through
/// `LlmTier::from_db_str`, which fail-closes an unknown/empty value to `Tier1`
/// — so a corrupt tier can never yield `External`. Shares the exact same
/// fail-closed matrix as the async [`ActorRepository::resolve_llm_tier_decision`]
/// (both call [`decide_llm_tier`]); the "actor missing" arm is not applicable
/// here since the actor came from the scan.
pub fn llm_tier_decision_from_tier_str(
    max_llm_tier: &str,
    tier1_local_ok: bool,
    ollama_available: bool,
) -> LlmTierDecision {
    let tier = talos_workflow_job_protocol::LlmTier::from_db_str(max_llm_tier);
    decide_llm_tier(Ok(Some(tier)), tier1_local_ok, ollama_available)
}

#[cfg(test)]
mod llm_tier_decision_tests {
    use super::{decide_llm_tier, LlmTierDecision};
    use talos_workflow_job_protocol::LlmTier;

    #[test]
    fn tier2_is_external() {
        assert_eq!(
            decide_llm_tier(Ok(Some(LlmTier::Tier2)), false, false),
            LlmTierDecision::External
        );
        // Tier2 is External regardless of attestation / ollama presence.
        assert_eq!(
            decide_llm_tier(Ok(Some(LlmTier::Tier2)), true, true),
            LlmTierDecision::External
        );
    }

    #[test]
    fn tier1_attested_with_ollama_is_local_only() {
        assert_eq!(
            decide_llm_tier(Ok(Some(LlmTier::Tier1)), true, true),
            LlmTierDecision::LocalOnly
        );
    }

    #[test]
    fn tier1_without_attestation_is_skip() {
        // Even with ollama wired, no operator attestation → Skip (never egress).
        assert_eq!(
            decide_llm_tier(Ok(Some(LlmTier::Tier1)), false, true),
            LlmTierDecision::Skip
        );
    }

    #[test]
    fn tier1_without_ollama_is_skip() {
        assert_eq!(
            decide_llm_tier(Ok(Some(LlmTier::Tier1)), true, false),
            LlmTierDecision::Skip
        );
    }

    #[test]
    fn missing_actor_is_skip() {
        assert_eq!(decide_llm_tier(Ok(None), true, true), LlmTierDecision::Skip);
    }

    #[test]
    fn db_error_is_skip() {
        assert_eq!(decide_llm_tier(Err(()), true, true), LlmTierDecision::Skip);
    }

    #[test]
    fn from_tier_str_maps_and_fails_closed() {
        use super::llm_tier_decision_from_tier_str as d;
        // Canonical strings.
        assert_eq!(d("tier2", true, true), LlmTierDecision::External);
        assert_eq!(d("tier1", true, true), LlmTierDecision::LocalOnly);
        assert_eq!(d("tier1", false, true), LlmTierDecision::Skip);
        // A corrupt / unknown tier string must NOT become External — from_db_str
        // fail-closes to Tier1, so it's Skip (or LocalOnly only when attested).
        assert_eq!(d("garbage", true, true), LlmTierDecision::LocalOnly);
        assert_eq!(d("garbage", false, false), LlmTierDecision::Skip);
        assert_eq!(d("", false, false), LlmTierDecision::Skip);
    }
}

#[cfg(test)]
mod default_actor_cache_tests {
    //! Exercises the REAL cache helpers (`default_actor_cache_get`/`_put`)
    //! per the no-shadow-copies testing convention. The cache is
    //! process-global, so each test uses fresh user UUIDs — tests can run
    //! concurrently without interfering.
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn miss_then_hit_roundtrip() {
        let user = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let now = Instant::now();
        assert_eq!(default_actor_cache_get(user, now), None);
        default_actor_cache_put(user, actor, now);
        assert_eq!(default_actor_cache_get(user, now), Some(actor));
    }

    #[test]
    fn entry_expires_after_ttl() {
        let user = Uuid::new_v4();
        let actor = Uuid::new_v4();
        let now = Instant::now();
        default_actor_cache_put(user, actor, now);
        // One nanosecond short of the TTL: still a hit.
        let almost = now + DEFAULT_ACTOR_CACHE_TTL - Duration::from_nanos(1);
        assert_eq!(default_actor_cache_get(user, almost), Some(actor));
        // At the TTL boundary: expired (strict `<` comparison).
        let expired = now + DEFAULT_ACTOR_CACHE_TTL;
        assert_eq!(default_actor_cache_get(user, expired), None);
    }

    #[test]
    fn put_overwrites_and_refreshes() {
        let user = Uuid::new_v4();
        let first = Uuid::new_v4();
        let second = Uuid::new_v4();
        let t0 = Instant::now();
        default_actor_cache_put(user, first, t0);
        let t1 = t0 + Duration::from_secs(200);
        default_actor_cache_put(user, second, t1);
        // The refreshed entry survives past the ORIGINAL entry's expiry.
        let t2 = t0 + DEFAULT_ACTOR_CACHE_TTL + Duration::from_secs(1);
        assert_eq!(default_actor_cache_get(user, t2), Some(second));
    }
}
