use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use talos_actor_policy_hook::PolicyPrePublishHook;
use talos_actor_types::PolicyVerdict;
use talos_workflow_repository::WorkflowRepository;
use talos_workflow_validation::{ValidationIssue, ValidationSeverity, WorkflowValidationService};

/// Outcome of a publish attempt. Added so we can surface a policy
/// `Blocked` verdict without shoehorning it into the existing
/// `(WorkflowVersion, Vec<ValidationIssue>)` return — publish didn't
/// happen when it's blocked, and the caller needs the gate details.
#[derive(Debug)]
pub enum PublishOutcome {
    /// Published successfully. Validation warnings (non-blocking) are
    /// carried alongside for the response.
    Published {
        version: WorkflowVersion,
        warnings: Vec<ValidationIssue>,
    },
    /// An actor policy blocked the publish. The underlying transaction
    /// was rolled back — no `workflow_versions` row exists, no active
    /// version changed. Caller surfaces the approval-gate URL so a
    /// human can resolve it and then retry publish_version.
    Blocked {
        policy_id: Uuid,
        gate_id: Uuid,
        approve_url: String,
        reject_url: String,
        trigger_label: String,
        approvers: Vec<String>,
        reason: String,
    },
}

/// A published, immutable snapshot of a workflow graph.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct WorkflowVersion {
    pub id: Uuid,
    pub workflow_id: Uuid,
    pub version_number: i32,
    pub graph_json: serde_json::Value,
    pub description: Option<String>,
    pub published_at: DateTime<Utc>,
    pub published_by: Uuid,
    pub is_active: bool,
    pub created_at: DateTime<Utc>,
}

/// Service for managing workflow versions.
pub struct WorkflowVersionService;

impl WorkflowVersionService {
    /// Get the latest version number for a workflow, or 0 if none exist.
    pub async fn get_latest_version_number(db_pool: &PgPool, workflow_id: Uuid) -> Result<i32> {
        let row = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT MAX(version_number) FROM workflow_versions WHERE workflow_id = $1",
        )
        .bind(workflow_id)
        .fetch_one(db_pool)
        .await
        .context("Failed to fetch latest version number")?;

        Ok(row.unwrap_or(0))
    }

    /// Publish the current draft graph_json as a new immutable version.
    ///
    /// Validates the workflow graph before publishing. If the graph has
    /// structural errors (missing modules, cycles, missing required config,
    /// vault permission violations), publication is blocked and the errors
    /// are returned.  Warnings (unreachable nodes, Phase 3 advisories) do
    /// not block publication.
    ///
    /// Pass `workflow_repo` as `None` to skip validation (internal/testing use
    /// only).  Production callers should always provide the repo.
    ///
    /// Backwards-compatible wrapper. New callers that want actor-policy
    /// enforcement should call [`publish_version_with_policy`] and
    /// handle the [`PublishOutcome::Blocked`] variant.
    pub async fn publish_version(
        db_pool: &PgPool,
        workflow_id: Uuid,
        user_id: Uuid,
        description: Option<String>,
        workflow_repo: Option<&WorkflowRepository>,
    ) -> Result<(WorkflowVersion, Vec<ValidationIssue>)> {
        match Self::publish_version_with_policy(
            db_pool,
            workflow_id,
            user_id,
            description,
            workflow_repo,
            None,
        )
        .await?
        {
            PublishOutcome::Published { version, warnings } => Ok((version, warnings)),
            // Without a policy hook this variant is unreachable. Kept
            // as an explicit anyhow::bail! so a future caller mis-using
            // this wrapper with a hook gets a loud runtime error rather
            // than a silent no-op publish.
            PublishOutcome::Blocked { reason, .. } => {
                anyhow::bail!(
                    "publish_version: unexpected policy block (no hook supplied): {reason}"
                )
            }
        }
    }

    /// Full-fidelity publish path. Same as [`publish_version`] plus:
    /// - Optional `policy_hook` evaluated inside the transaction *after*
    ///   ownership validation but *before* the version insert. On a
    ///   [`PolicyVerdict::Blocked`] verdict the transaction rolls back
    ///   and [`PublishOutcome::Blocked`] is returned — no `workflow_versions`
    ///   row is written and the active version is unchanged.
    /// - Actor id is resolved from the `workflows` row and passed to
    ///   the hook. If the workflow has no actor_id, the hook is
    ///   skipped entirely (there's nothing to gate against).
    pub async fn publish_version_with_policy(
        db_pool: &PgPool,
        workflow_id: Uuid,
        user_id: Uuid,
        description: Option<String>,
        workflow_repo: Option<&WorkflowRepository>,
        policy_hook: Option<&dyn PolicyPrePublishHook>,
    ) -> Result<PublishOutcome> {
        // ── Pre-publish validation gate ──────────────────────────────────
        let mut validation_warnings: Vec<ValidationIssue> = Vec::new();
        if let Some(repo) = workflow_repo {
            let validation: anyhow::Result<talos_workflow_validation::ValidationResult> =
                WorkflowValidationService::validate(repo, workflow_id, user_id).await;
            let validation = validation.context("Pre-publish validation failed")?;

            let errors: Vec<&ValidationIssue> = validation.errors();
            if !errors.is_empty() {
                let error_messages: Vec<String> =
                    errors.iter().map(|e| e.message.clone()).collect();
                return Err(anyhow::anyhow!(
                    "Workflow validation failed with {} error(s):\n  - {}",
                    error_messages.len(),
                    error_messages.join("\n  - ")
                ));
            }

            validation_warnings = validation
                .issues
                .into_iter()
                .filter(|i| i.severity == ValidationSeverity::Warning)
                .collect();
        }

        // Use a transaction to ensure atomicity
        let mut tx = db_pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // MCP-594 (2026-05-12): role-filter the org_ids for the
        // ownership check. publish_version is a write — Viewer-role
        // org members must not be able to publish org-owned workflow
        // versions. Sibling fix to rollback_to_version below; mirrors
        // the `user_writable_org_ids` helper in talos-api.
        //
        // MCP-515: pre-fix `unwrap_or_default()` silently zeroed this
        // list on any query error. The downstream ownership check then
        // evaluated `org_id = ANY([])` which matches no org-owned row,
        // so a transient DB failure (or migration drift on
        // `organization_members`) caused a legitimate org-owned
        // workflow operation to fail with "Workflow not found or
        // access denied". Same swallow-zero class as MCP-488 / MCP-489 /
        // MCP-503; propagate via `?` so the caller sees a structured
        // database error instead of a misleading access-denied.
        let org_ids: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
            "SELECT org_id FROM organization_members \
             WHERE user_id = $1 AND role IN ('member', 'admin', 'owner')",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .context("Failed to fetch user's writable org memberships")?;

        // 1. Snapshot current graph_json from the workflows table (verify ownership or org access).
        // Also pull actor_id for the policy hook — the hook runs inside
        // this same tx so any advisory locks the detectors take
        // release cleanly on commit OR rollback.
        let row: Option<(String, Option<Uuid>)> = sqlx::query_as(
            "SELECT graph_json, actor_id FROM workflows \
             WHERE id = $1 AND (user_id = $2 OR org_id = ANY($3))",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(&org_ids)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to fetch workflow graph")?;
        let (graph_json, actor_id_opt) =
            row.ok_or_else(|| anyhow::anyhow!("Workflow not found or access denied"))?;

        // Parse graph_json string into JSONB value
        let graph_jsonb: serde_json::Value =
            serde_json::from_str(&graph_json).context("Failed to parse workflow graph_json")?;

        // 1a. Actor-policy enforcement. Only runs when the workflow
        // has an actor AND the caller supplied a hook. Evaluated
        // inside the tx so detector advisory locks release with the
        // tx; rolling back on Blocked leaves no partial state.
        if let (Some(actor_id), Some(hook)) = (actor_id_opt, policy_hook) {
            let verdict = hook.check(&mut tx, actor_id, workflow_id, user_id).await?;
            if let PolicyVerdict::Blocked {
                policy_id,
                gate_id,
                approve_url,
                reject_url,
                trigger_label,
                approvers,
                reason,
                ..
            } = verdict
            {
                // Rollback explicit; the caller should not see any
                // partial state from the version insert. The approval
                // gate row itself was created *outside* this tx (via
                // advanced_repo's own pool), so it survives the
                // rollback correctly.
                //
                // NOTE: the current `create_approval_gate` impl uses
                // `self.db_pool` directly (not this tx), which is
                // what we want here — the gate must persist even
                // when the publish tx rolls back.
                tx.rollback()
                    .await
                    .context("Failed to roll back tx after policy block")?;
                tracing::info!(
                    target: "actor_policies",
                    workflow_id = %workflow_id,
                    actor_id = %actor_id,
                    policy_id = %policy_id,
                    gate_id = %gate_id,
                    "publish_version blocked by actor policy",
                );
                return Ok(PublishOutcome::Blocked {
                    policy_id,
                    gate_id,
                    approve_url,
                    reject_url,
                    trigger_label,
                    approvers,
                    reason,
                });
            }
        }

        // 2. Get next version number
        let latest = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT MAX(version_number) FROM workflow_versions WHERE workflow_id = $1",
        )
        .bind(workflow_id)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to fetch latest version number")?;

        let next_version = latest.unwrap_or(0) + 1;

        // 3. Deactivate the current active version (if any)
        sqlx::query(
            "UPDATE workflow_versions SET is_active = false WHERE workflow_id = $1 AND is_active = true",
        )
        .bind(workflow_id)
        .execute(&mut *tx)
        .await
        .context("Failed to deactivate previous active version")?;

        // 4. Insert the new version as active
        let version = sqlx::query_as::<_, WorkflowVersion>(
            r#"
            INSERT INTO workflow_versions (workflow_id, version_number, graph_json, description, published_by, is_active)
            VALUES ($1, $2, $3, $4, $5, true)
            RETURNING id, workflow_id, version_number, graph_json, description, published_at, published_by, is_active, created_at
            "#,
        )
        .bind(workflow_id)
        .bind(next_version)
        .bind(&graph_jsonb)
        .bind(description.as_deref())
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to insert workflow version")?;

        tx.commit().await.context("Failed to commit transaction")?;

        tracing::info!(
            workflow_id = %workflow_id,
            version = next_version,
            "Published workflow version"
        );

        Ok(PublishOutcome::Published {
            version,
            warnings: validation_warnings,
        })
    }

    /// Get the currently active published version for a workflow.
    pub async fn get_active_version(
        db_pool: &PgPool,
        workflow_id: Uuid,
    ) -> Result<Option<WorkflowVersion>> {
        let mut conn = db_pool
            .acquire()
            .await
            .context("acquire connection for get_active_version")?;
        Self::get_active_version_on_conn(&mut conn, workflow_id).await
    }

    /// `get_active_version` against a caller-supplied connection — RFC 0005
    /// S3 executor-threading convention. Lets the call compose into a
    /// request-scoped `talos_db::UnitOfWork` (`uow.conn()`) so it shares
    /// the request's tenant scope + transaction instead of taking its own
    /// pooled connection. The `&PgPool` method above delegates here, so
    /// there is one source of query logic.
    pub async fn get_active_version_on_conn(
        conn: &mut sqlx::PgConnection,
        workflow_id: Uuid,
    ) -> Result<Option<WorkflowVersion>> {
        let version = sqlx::query_as::<_, WorkflowVersion>(
            r#"
            SELECT id, workflow_id, version_number, graph_json, description, published_at, published_by, is_active, created_at
            FROM workflow_versions
            WHERE workflow_id = $1 AND is_active = true
            "#,
        )
        .bind(workflow_id)
        .fetch_optional(conn)
        .await
        .context("Failed to fetch active workflow version")?;

        Ok(version)
    }

    /// Active published version's `graph_json` as text, against a
    /// caller-supplied connection (RFC 0005 S3 executor threading — the
    /// GraphQL version-diff resolver runs this inside its request-scoped
    /// UnitOfWork so the draft + published reads share one snapshot).
    pub async fn get_active_graph_json_on_conn(
        conn: &mut sqlx::PgConnection,
        workflow_id: Uuid,
    ) -> Result<Option<String>> {
        let graph_json: Option<String> = sqlx::query_scalar(
            "SELECT graph_json::text FROM workflow_versions WHERE workflow_id = $1 AND is_active = true",
        )
        .bind(workflow_id)
        .fetch_optional(conn)
        .await
        .context("Failed to fetch active version graph_json")?;
        Ok(graph_json)
    }

    /// Get a version by id, gated on the PARENT workflow's ownership OR
    /// org access (workflow_versions has no RLS policy of its own — the
    /// JOIN through `workflows` is the only tenant protection a version
    /// read gets, plus the workflows RLS backstop when run on the
    /// caller's tenant-scoped tx). Takes the caller's connection; do NOT
    /// add a bare-pool variant for the GraphQL path.
    pub async fn get_version_for_accessor_on_conn(
        conn: &mut sqlx::PgConnection,
        version_id: Uuid,
        user_id: Uuid,
        accessible_org_ids: &[Uuid],
    ) -> Result<Option<WorkflowVersion>> {
        let version = sqlx::query_as::<_, WorkflowVersion>(
            "SELECT wv.* FROM workflow_versions wv \
             JOIN workflows w ON wv.workflow_id = w.id \
             WHERE wv.id = $1 AND (w.user_id = $2 OR w.org_id = ANY($3))",
        )
        .bind(version_id)
        .bind(user_id)
        .bind(accessible_org_ids)
        .fetch_optional(conn)
        .await
        .context("Failed to fetch workflow version")?;
        Ok(version)
    }

    /// Get a specific version by its ID.
    pub async fn get_version(
        db_pool: &PgPool,
        version_id: Uuid,
    ) -> Result<Option<WorkflowVersion>> {
        let version = sqlx::query_as::<_, WorkflowVersion>(
            r#"
            SELECT id, workflow_id, version_number, graph_json, description, published_at, published_by, is_active, created_at
            FROM workflow_versions
            WHERE id = $1
            "#,
        )
        .bind(version_id)
        .fetch_optional(db_pool)
        .await
        .context("Failed to fetch workflow version")?;

        Ok(version)
    }

    /// List all versions for a workflow, ordered by version number descending.
    pub async fn list_versions(
        db_pool: &PgPool,
        workflow_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WorkflowVersion>> {
        let mut conn = db_pool
            .acquire()
            .await
            .context("acquire connection for list_versions")?;
        Self::list_versions_on_conn(&mut conn, workflow_id, limit, offset).await
    }

    /// `list_versions` against a caller-supplied connection — RFC 0005 S3
    /// executor-threading convention (composes into a `UnitOfWork`; the
    /// `&PgPool` method delegates here, single source of query logic).
    pub async fn list_versions_on_conn(
        conn: &mut sqlx::PgConnection,
        workflow_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<WorkflowVersion>> {
        let versions = sqlx::query_as::<_, WorkflowVersion>(
            r#"
            SELECT id, workflow_id, version_number, graph_json, description, published_at, published_by, is_active, created_at
            FROM workflow_versions
            WHERE workflow_id = $1
            ORDER BY version_number DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(workflow_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(conn)
        .await
        .context("Failed to list workflow versions")?;

        Ok(versions)
    }

    /// Rollback to a previous version by setting it as active.
    ///
    /// Creates a *new* version that copies the graph_json from the target version,
    /// so version history remains append-only. The new version is marked active.
    pub async fn rollback_to_version(
        db_pool: &PgPool,
        workflow_id: Uuid,
        version_id: Uuid,
        user_id: Uuid,
    ) -> Result<WorkflowVersion> {
        let mut tx = db_pool
            .begin()
            .await
            .context("Failed to begin transaction")?;

        // MCP-594 (2026-05-12): role-filter the org_ids for the
        // ownership check. Pre-fix this SELECT pulled EVERY org
        // membership regardless of role, and the downstream
        // `org_id = ANY($3)` predicate let a Viewer-role member of an
        // org rollback org-owned workflows. Rollback is a write —
        // Viewer roles must be excluded. Mirrors the
        // `user_writable_org_ids` helper in `talos-api/src/schema/mod.rs`
        // (and the secret-create cross-org check) which already filters
        // `role IN ('member', 'admin', 'owner')` at the DB layer.
        //
        // MCP-515: pre-fix `unwrap_or_default()` silently zeroed this
        // list on any query error. The downstream ownership check then
        // evaluated `org_id = ANY([])` which matches no org-owned row,
        // so a transient DB failure (or migration drift on
        // `organization_members`) caused a legitimate org-owned
        // workflow operation to fail with "Workflow not found or
        // access denied". Same swallow-zero class as MCP-488 / MCP-489 /
        // MCP-503; propagate via `?` so the caller sees a structured
        // database error instead of a misleading access-denied.
        let org_ids: Vec<Uuid> = sqlx::query_scalar::<_, Uuid>(
            "SELECT org_id FROM organization_members \
             WHERE user_id = $1 AND role IN ('member', 'admin', 'owner')",
        )
        .bind(user_id)
        .fetch_all(&mut *tx)
        .await
        .context("Failed to fetch user's writable org memberships")?;

        // 1. Verify the user owns this workflow or has org access
        let owns = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM workflows WHERE id = $1 AND (user_id = $2 OR org_id = ANY($3)))",
        )
        .bind(workflow_id)
        .bind(user_id)
        .bind(&org_ids)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to check workflow ownership")?;

        if !owns {
            anyhow::bail!("Workflow not found or access denied");
        }

        // 2. Fetch the target version (must belong to this workflow)
        let target = sqlx::query_as::<_, WorkflowVersion>(
            r#"
            SELECT id, workflow_id, version_number, graph_json, description, published_at, published_by, is_active, created_at
            FROM workflow_versions
            WHERE id = $1 AND workflow_id = $2
            "#,
        )
        .bind(version_id)
        .bind(workflow_id)
        .fetch_optional(&mut *tx)
        .await
        .context("Failed to fetch target version")?
        .ok_or_else(|| anyhow::anyhow!("Version not found or does not belong to this workflow"))?;

        // 3. Deactivate current active version
        sqlx::query(
            "UPDATE workflow_versions SET is_active = false WHERE workflow_id = $1 AND is_active = true",
        )
        .bind(workflow_id)
        .execute(&mut *tx)
        .await
        .context("Failed to deactivate current active version")?;

        // 4. Get next version number
        let latest = sqlx::query_scalar::<_, Option<i32>>(
            "SELECT MAX(version_number) FROM workflow_versions WHERE workflow_id = $1",
        )
        .bind(workflow_id)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to fetch latest version number")?;

        let next_version = latest.unwrap_or(0) + 1;

        // 5. Create a new version with the target's graph_json
        let description = format!("Rollback to version {}", target.version_number);

        let new_version = sqlx::query_as::<_, WorkflowVersion>(
            r#"
            INSERT INTO workflow_versions (workflow_id, version_number, graph_json, description, published_by, is_active)
            VALUES ($1, $2, $3, $4, $5, true)
            RETURNING id, workflow_id, version_number, graph_json, description, published_at, published_by, is_active, created_at
            "#,
        )
        .bind(workflow_id)
        .bind(next_version)
        .bind(&target.graph_json)
        .bind(&description)
        .bind(user_id)
        .fetch_one(&mut *tx)
        .await
        .context("Failed to create rollback version")?;

        tx.commit().await.context("Failed to commit transaction")?;

        tracing::info!(
            workflow_id = %workflow_id,
            from_version = target.version_number,
            new_version = next_version,
            "Rolled back workflow version"
        );

        Ok(new_version)
    }
}
