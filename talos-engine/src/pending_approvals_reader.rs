//! Postgres impl of [`talos_workflow_engine_core::PendingApprovalsReader`]
//! — the read port behind the `pending_approvals` system node.
//!
//! Thin adapter over [`talos_execution_repository::ExecutionRepository`]
//! (all SQL stays in the domain crate). It composes the exact same two
//! surfaces the `list_pending_approvals` MCP reader does:
//! `list_pending_approvals_for_user` (the pending set) and
//! `approval_links::mint_approval_urls` (one-click approve/reject
//! capability URLs, best-effort + timeout-bounded).
//!
//! Tenancy: every query is scoped by the `user_id` the engine passes in,
//! which comes from the execution's resolved identity — node config
//! carries no identity.
//!
//! SECURITY: the minted URLs are capability secrets. They MUST transit
//! node output (that is the point of the node — a downstream compose
//! node embeds them into an approval-notification email that is only
//! sent after the execution has actually paused), but they are NEVER
//! logged here or by the caller. A mint that fails or times out degrades
//! that entry to `null` URLs rather than dropping the approval or
//! failing the read.

use async_trait::async_trait;
use serde_json::{json, Value as JsonValue};
use sqlx::PgPool;
use talos_execution_repository::ExecutionRepository;
use uuid::Uuid;

pub struct PostgresPendingApprovalsReader {
    repo: ExecutionRepository,
}

impl PostgresPendingApprovalsReader {
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self {
            repo: ExecutionRepository::new(pool),
        }
    }
}

#[async_trait]
impl talos_workflow_engine_core::PendingApprovalsReader for PostgresPendingApprovalsReader {
    async fn pending(
        &self,
        user_id: Uuid,
        limit: u32,
    ) -> Result<JsonValue, talos_workflow_engine_core::BoxError> {
        // Defensive re-clamp: the parser clamps 1..=25, but the port
        // contract says impls must clamp again (never trust the caller).
        let limit = limit.clamp(1, 25);
        let rows = self
            .repo
            .list_pending_approvals_for_user(user_id, i64::from(limit))
            .await?;

        // Mint one-click approve/reject capability links per pending
        // approval so a notify-after-pause delivery surface can embed
        // them. Best-effort and timeout-bounded — a slow/failed mint
        // degrades to link-less items, never an error (mirrors the
        // ops-alerts digest reader that mints correction URLs, and the
        // `list_pending_approvals` MCP reader). Tokens are hash-only at
        // rest.
        let base_url = talos_public_url::public_base_url_or(talos_config::get_base_url);
        let execution_ids: Vec<Uuid> = rows.iter().map(|r| r.execution_id).collect();
        let approval_urls = talos_execution_repository::approval_links::mint_approval_urls(
            &self.repo,
            user_id,
            &execution_ids,
            &base_url,
        )
        .await;

        let approvals: Vec<JsonValue> = rows
            .iter()
            .zip(approval_urls.iter())
            .map(|(r, urls)| {
                let waiting_seconds = r
                    .requested_at
                    .map(|t| (chrono::Utc::now() - t).num_seconds())
                    .unwrap_or(0);
                json!({
                    "execution_id": r.execution_id.to_string(),
                    "workflow_id": r.workflow_id.map(|id| id.to_string()),
                    "workflow_name": r.workflow_name,
                    "node_id": r.node_id.to_string(),
                    "required_for": r.required_for,
                    "requested_at": r.requested_at.map(|t| t.to_rfc3339()),
                    "waiting_seconds": waiting_seconds,
                    "approve_url": urls.as_ref().map(|u| u.approve_url.clone()),
                    "reject_url": urls.as_ref().map(|u| u.reject_url.clone()),
                })
            })
            .collect();

        Ok(json!({
            "count": approvals.len(),
            "approvals": approvals,
        }))
    }
}
