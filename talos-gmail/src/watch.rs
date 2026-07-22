//! Gmail watch-channel lifecycle, backed by the `integration_state`
//! primitive.
//!
//! # Before editing this file or adding a third integration
//!
//! Read `docs/integration-pattern.md`. This module is one of two
//! reference implementations of the canonical push-integration
//! pattern (the other is `google_calendar::watch`). Drift between
//! the two should be deliberate and captured in the doc; accidental
//! drift is how integration-3 ends up paying for bugs we already
//! fixed here.
//!
//! Specifically: the `create_watch` / `create_fresh_watch_locked`
//! split is not optional — see the `docs/integration-pattern.md`
//! section on the "Renewal zero-channel bug (e43430b)" for what
//! happens when renewal reuses the public fast-path.
//!
//! # Storage model
//!
//! Each watch is one row in `integration_state`:
//!
//! | column            | value                                         |
//! |-------------------|-----------------------------------------------|
//! | integration_name  | `"gmail"`                                     |
//! | user_id           | owning user                                   |
//! | key               | `"watch/{internal_uuid}"`                     |
//! | value             | JSON — full watch-row shape (see below)       |
//! | expires_at        | 14 days past Google's expiration (grace)      |
//! | idx_str_1         | `email_address` (for Pub/Sub webhook lookup)  |
//! | idx_str_2         | `topic_name` (reserved, observability)        |
//! | idx_ts_1          | Google `expiration` (renewal filter)          |
//! | idx_int_1         | unused                                        |
//!
//! # Differences from gcal
//!
//! * **One watch per mailbox.** Gmail has no calendar-list analogue;
//!   the lock is keyed by `(user_id, integration_id)` — a coarser
//!   grain than gcal's `(user, integration, calendar)`.
//! * **No verification token per watch.** Authenticity on the
//!   delivery side is a Pub/Sub JWT (see `pubsub_jwt.rs`), not an
//!   opaque token we mint at create time.
//! * **`history_id` is the sync cursor.** Unlike gcal's
//!   `sync_token` (opaque), Gmail's `history_id` is a monotonic
//!   integer. Renewal does NOT update it — we only advance as
//!   pushed messages are processed.
//!
//! Scheduler, audit log shape, failure-enrichment queries, and the
//! concurrent-create lock pattern are the same as gcal's.

use super::api::GmailWatchApiClient;
use super::GmailIntegrationService;
use anyhow::{anyhow, Context, Result};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use talos_integration_helpers::audit::{
    insert_channel_audit, truncate_and_redact_error, ChannelAuditEvent,
};
use talos_integration_helpers::state_store::{ttl_with_grace, ChannelStore, CreateLockMap};
use talos_integration_state::execute_op;
use talos_memory::integration_state_rpc::{
    IndexedSlots, IntegrationOp, IntegrationOpResult, ListFilter, StoredEntry,
};
use uuid::Uuid;

pub(crate) const GMAIL_INTEGRATION_NAME: &str = "gmail";

/// Row stored in `integration_state.value`. Separate from any API-
/// facing struct so controller-private fields never leak through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GmailWatchRow {
    pub id: Uuid,
    pub integration_id: Uuid,
    pub email_address: String,
    /// Fully-qualified Pub/Sub topic, e.g. `projects/p/topics/t`.
    pub topic_name: String,
    /// The last `historyId` we've fully processed. Pub/Sub pushes
    /// arrive with a current historyId; we call history.list from
    /// stored → current, advance the cursor once each page's
    /// messages are dispatched.
    pub history_id: u64,
    /// Label filter. Empty vec = every message triggers.
    #[serde(default)]
    pub label_ids: Vec<String>,
    pub expiration_ms: i64,
    /// Optional bound WASM module — one inbound message → one dispatched
    /// module job. Mutually informative with `workflow_id`: when both
    /// are set, `workflow_id` WINS (see `dispatch::select_dispatch_target`).
    pub module_id: Option<Uuid>,
    /// Optional bound WORKFLOW — an inbound push triggers one full
    /// workflow execution (the workflow re-fetches its own mail).
    /// Takes precedence over `module_id` when both are set.
    /// `#[serde(default)]` so pre-existing watch rows (serialized before
    /// this field existed) decode to `None`.
    #[serde(default)]
    pub workflow_id: Option<Uuid>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

fn decode_row(entry: &StoredEntry) -> Result<GmailWatchRow> {
    serde_json::from_str(&entry.value).context("decode gmail watch row")
}

/// Service handle. Owns config (topic name, service account), the
/// integration service (OAuth token access), and the in-memory
/// concurrency-lock map.
pub struct GmailWatchService {
    pub(crate) pool: sqlx::PgPool,
    pub(crate) integrations: Arc<GmailIntegrationService>,
    /// Fully-qualified Pub/Sub topic name configured by the operator
    /// (`GMAIL_PUBSUB_TOPIC`). Gmail's watch API rejects watch
    /// requests where we don't own the topic, so this is
    /// pre-validated at startup.
    pub(crate) topic_name: String,
    /// Default label filter for new watches. If empty, every
    /// message triggers. Most users want `["INBOX"]`.
    pub(crate) default_label_ids: Vec<String>,
    /// Serializes `create_watch` per `(user_id, integration_id)` so
    /// two concurrent callers can't register with Google twice.
    create_locks: CreateLockMap<(Uuid, Uuid)>,
    /// API client — cheap to clone (reqwest internally Arcs).
    pub(crate) api: GmailWatchApiClient,
}

impl GmailWatchService {
    pub fn new(
        pool: sqlx::PgPool,
        integrations: Arc<GmailIntegrationService>,
        topic_name: String,
        default_label_ids: Vec<String>,
    ) -> Self {
        Self {
            pool,
            integrations,
            topic_name,
            default_label_ids,
            create_locks: CreateLockMap::new(),
            api: GmailWatchApiClient::new(),
        }
    }

    /// User-scoped handle over `integration_state` for gmail watch
    /// rows. Cheap to construct per call (`PgPool` is `Arc`-backed).
    fn store(&self) -> ChannelStore {
        ChannelStore::new(self.pool.clone(), GMAIL_INTEGRATION_NAME, "watch/")
    }

    /// Evict idle create-locks. Paired with the webhook rate-limiter
    /// sweep in main.rs for consistency with gcal.
    pub fn cleanup_create_locks(&self) {
        self.create_locks.cleanup();
    }

    // ------------------------------------------------------------------
    // Public lifecycle ops — all user-scoped, authz automatic through
    // integration_state row scoping.
    // ------------------------------------------------------------------

    /// Create a new watch, or re-point an existing one at a different
    /// module. Exactly one watch exists per mailbox at any time.
    pub(crate) async fn create_watch(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
        module_id: Option<Uuid>,
        workflow_id: Option<Uuid>,
        label_ids: Option<Vec<String>>,
    ) -> Result<GmailWatchRow> {
        let _guard = self.acquire_lock(user_id, integration_id).await;

        // Fast path: if there's already a row for this (user,
        // integration), update module_id (and optionally labels) on
        // the existing Google-side watch. Gmail's watch is stateless
        // on our side — calling users.watch again with new label_ids
        // replaces the filter; we don't want to do that implicitly,
        // so fast-path skips the Google call entirely and only flips
        // our bookkeeping.
        if let Some(mut existing) = self
            .find_single_for_integration(user_id, integration_id)
            .await?
        {
            if let Some(ref labels) = label_ids {
                if *labels != existing.label_ids {
                    tracing::info!(
                        channel_uuid = %existing.id,
                        "gmail create_watch: label_ids changed; call stop+create to rotate the subscription"
                    );
                }
            }
            existing.module_id = module_id;
            existing.workflow_id = workflow_id;
            existing.updated_at_ms = Utc::now().timestamp_millis();
            self.upsert_row(user_id, &existing).await?;
            return Ok(existing);
        }

        self.create_fresh_watch_locked(
            user_id,
            integration_id,
            module_id,
            workflow_id,
            label_ids.unwrap_or_else(|| self.default_label_ids.clone()),
        )
        .await
    }

    /// Delete the old row BEFORE creating fresh, same pattern as gcal —
    /// prevents the fast-path from incorrectly returning the about-to-
    /// be-deleted row.
    pub(crate) async fn renew_watch(
        &self,
        user_id: Uuid,
        channel_uuid: Uuid,
    ) -> Result<GmailWatchRow> {
        let old = self.find_by_id(user_id, channel_uuid).await?;

        let _guard = self.acquire_lock(user_id, old.integration_id).await;

        // Gmail's users.stop is optional on renewal — users.watch
        // again effectively replaces the subscription. But calling
        // stop explicitly makes the intent clear on the Google side,
        // matching gcal's stop-then-create pattern.
        let integration = self
            .integrations
            .get_integration(user_id, old.integration_id)
            .await
            .context("fetch integration for renew")?
            .ok_or_else(|| anyhow!("integration {} not found", old.integration_id))?;
        let access_token = self
            .integrations
            .get_access_token(user_id, &integration.email_address)
            .await?;
        if let Err(e) = self.api.users_stop(&access_token).await {
            tracing::warn!(error = %e, "users.stop during renew failed; continuing with re-create");
        }

        // Preserve history_id and label_ids + module_id + workflow_id
        // across the rotation.
        let history_id = old.history_id;
        let label_ids = old.label_ids.clone();
        let module_id = old.module_id;
        let workflow_id = old.workflow_id;
        let integration_id = old.integration_id;
        let old_id = old.id;

        self.delete_row(user_id, old_id).await?;

        // Create fresh under the same lock; manually preserve the
        // cursor so we don't re-fire old pushes. Google's users.watch
        // returns a NEW historyId (current tip) which we deliberately
        // ignore — our stored cursor is the authority.
        let mut new_row = self
            .create_fresh_watch_locked(user_id, integration_id, module_id, workflow_id, label_ids)
            .await
            .context("create_fresh during renew")?;
        if new_row.history_id < history_id {
            new_row.history_id = history_id;
            self.upsert_row(user_id, &new_row).await?;
        }

        // Regression guard against the gcal "zero-channel" bug: a
        // successful renew MUST produce a different channel_uuid.
        debug_assert_ne!(new_row.id, old_id);
        Ok(new_row)
    }

    /// Stop + delete. Idempotent: missing rows succeed silently.
    pub async fn stop_watch(&self, user_id: Uuid, channel_uuid: Uuid) -> Result<()> {
        let row = match self.find_by_id(user_id, channel_uuid).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };
        let integration_opt = self
            .integrations
            .get_integration(user_id, row.integration_id)
            .await
            .ok()
            .flatten();

        let mut google_err: Option<String> = None;
        if let Some(integration) = integration_opt {
            if let Ok(token) = self
                .integrations
                .get_access_token(user_id, &integration.email_address)
                .await
            {
                if let Err(e) = self.api.users_stop(&token).await {
                    tracing::warn!(error = %e, "users.stop failed; deleting row anyway");
                    google_err = Some(e.to_string());
                }
            }
        }

        self.delete_row(user_id, row.id).await?;

        // Audit — mirrors gcal's channel_stopped event. Failures here
        // are non-fatal (visibility loss, not correctness).
        let success = google_err.is_none();
        // MCP-980 (2026-05-15) + MCP-1181 (2026-05-17): the Google API
        // error string is truncated at 1 KiB FIRST, then DLP-redacted
        // before bind — stop-watch failures can echo refresh_token /
        // access_token via Google's error_description field on
        // token-related rejections. Both steps live in the canonical
        // `truncate_and_redact_error` helper.
        let redacted_google_err = google_err.as_deref().map(truncate_and_redact_error);
        if let Err(e) = insert_channel_audit(
            &self.pool,
            ChannelAuditEvent {
                integration_id: Some(row.integration_id),
                user_id,
                event_type: "gmail_channel_stopped",
                target: Some(&row.email_address),
                success,
                error_message: redacted_google_err.as_deref(),
                metadata: serde_json::json!({
                    "channel_uuid": row.id.to_string(),
                    "topic_name": row.topic_name,
                }),
            },
        )
        .await
        {
            tracing::warn!(error = %e, "gmail channel_stopped audit log insert failed");
        }
        Ok(())
    }

    /// Hot-path webhook lookup: given a Pub/Sub push's `emailAddress`,
    /// find the matching (user, watch row). Used by the Pub/Sub
    /// handler in commit 3.
    pub(crate) async fn find_by_email(&self, email: &str) -> Result<Option<(Uuid, GmailWatchRow)>> {
        // Resolve email → owning user(s) via gmail_integrations. IMPORTANT: the
        // table is UNIQUE(user_id, email_address), NOT unique on email alone — the
        // SAME mailbox can be connected by multiple Talos users. A bare `LIMIT 1`
        // with no tiebreaker would dispatch the push to a Postgres-arbitrary user
        // (their module / token / history), a cross-tenant confusion. Enumerate
        // all active owners deterministically, warn on the ambiguous case, and
        // return the first owner that actually has a watch row for this mailbox
        // (an owner with no active watch can't be the push's target). A fuller fix
        // would resolve by the watch's channel/topic identity rather than email.
        let user_ids: Vec<Uuid> = sqlx::query_scalar(
            "SELECT user_id FROM gmail_integrations \
             WHERE email_address = $1 AND is_active = true ORDER BY user_id",
        )
        .bind(email)
        .fetch_all(&self.pool)
        .await?;

        if user_ids.len() > 1 {
            // owner_count only — never log the email (PII).
            tracing::warn!(
                owner_count = user_ids.len(),
                "gmail push mailbox connected by multiple Talos users; dispatching to \
                 the first owner with an active watch (deterministic by user_id)"
            );
        }

        for user_id in user_ids {
            let filter = ListFilter {
                idx_str_1_eq: Some(email.to_string()),
                ..Default::default()
            };
            // Errors are deliberately ignored (pre-extraction `if let
            // Ok(...)` behavior): a failing user is skipped, the next
            // owner is tried.
            if let Ok(entries) = self.store().list_entries(user_id, filter, 1).await {
                if let Some(entry) = entries.into_iter().next() {
                    let row = decode_row(&entry)?;
                    return Ok(Some((user_id, row)));
                }
            }
        }
        Ok(None)
    }

    /// Advance the stored cursor + updated_at after successful
    /// dispatch of history items. Called from the push handler after
    /// the last page is processed.
    pub async fn advance_history_id(
        &self,
        user_id: Uuid,
        channel_uuid: Uuid,
        new_history_id: u64,
    ) -> Result<()> {
        let mut row = self.find_by_id(user_id, channel_uuid).await?;
        // Monotonic: never regress. If a later push arrived first
        // (unlikely but technically possible under retry pressure),
        // we keep the higher cursor.
        if new_history_id > row.history_id {
            row.history_id = new_history_id;
            row.updated_at_ms = Utc::now().timestamp_millis();
            self.upsert_row(user_id, &row).await?;
        }
        Ok(())
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    pub(crate) async fn create_fresh_watch_locked(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
        module_id: Option<Uuid>,
        workflow_id: Option<Uuid>,
        label_ids: Vec<String>,
    ) -> Result<GmailWatchRow> {
        let integration = self
            .integrations
            .get_integration(user_id, integration_id)
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "integration {} not found for user {}",
                    integration_id,
                    user_id
                )
            })?;
        let access_token = self
            .integrations
            .get_access_token(user_id, &integration.email_address)
            .await?;

        let watch_resp = self
            .api
            .users_watch(&access_token, &self.topic_name, &label_ids)
            .await
            .context("users.watch failed")?;

        let now_ms = Utc::now().timestamp_millis();
        let row = GmailWatchRow {
            id: Uuid::new_v4(),
            integration_id,
            email_address: integration.email_address.clone(),
            topic_name: self.topic_name.clone(),
            history_id: watch_resp.history_id,
            label_ids,
            expiration_ms: watch_resp.expiration_ms as i64,
            module_id,
            workflow_id,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };

        // Orphan-stop pattern: if persist fails, tell Google to
        // forget about us so we don't leave a subscription ticking.
        if let Err(e) = self.upsert_row(user_id, &row).await {
            tracing::error!(error = %e, "gmail watch persist failed; stopping orphan Google subscription");
            // Arc-backed reqwest client — `clone()` is a refcount bump,
            // not a fresh TLS stack.
            let token = access_token.clone();
            let api = self.api.clone();
            tokio::spawn(async move {
                // MCP-804 (2026-05-14): log users_stop failures. This is
                // the orphan-stop path — we already failed to persist
                // the row, so the goal is to tell Google to forget the
                // subscription. If users_stop ALSO fails, Google keeps
                // the subscription ticking but we have no row, leaving
                // a real orphan that the renewal loop won't reach
                // (renewal walks integration_state rows, which we
                // don't have here). Operator visibility on this path
                // matters because the orphan silently incurs Google
                // API quota cost until it expires (~7 days). Same
                // operator-visibility class as MCP-733..780.
                if let Err(e) = api.users_stop(&token).await {
                    tracing::warn!(
                        target: "talos_audit",
                        error = %e,
                        "gmail watch orphan-stop failed: Google subscription will continue until ~7d TTL expires; check Google API quota and consider manual stop"
                    );
                }
            });
            return Err(e);
        }

        // DLP: `channel_uuid` is the pseudonymous identifier; the connected
        // account's email (PII) is redundant in operational logs. Parity with
        // the gmail-push-handler redaction + MCP-1011/1012.
        tracing::info!(
            channel_uuid = %row.id,
            topic = %row.topic_name,
            history_id = %row.history_id,
            "✅ Created gmail watch"
        );

        // Audit — same table as gcal, distinct event_type.
        if let Err(e) = insert_channel_audit(
            &self.pool,
            ChannelAuditEvent {
                integration_id: Some(row.integration_id),
                user_id,
                event_type: "gmail_channel_created",
                target: Some(&row.email_address),
                success: true,
                error_message: None,
                metadata: serde_json::json!({
                    "channel_uuid": row.id.to_string(),
                    "topic_name": row.topic_name,
                    "history_id": row.history_id,
                    "expiration": row.expiration_ms,
                    "module_id": row.module_id,
                    "workflow_id": row.workflow_id,
                    "label_ids": row.label_ids,
                }),
            },
        )
        .await
        {
            tracing::warn!(error = %e, "gmail channel_created audit log insert failed");
        }
        Ok(row)
    }

    async fn upsert_row(&self, user_id: Uuid, row: &GmailWatchRow) -> Result<()> {
        let value = serde_json::to_value(row).context("encode gmail row")?;
        // Same 14-day grace as gcal so a streak of renewal failures
        // doesn't sweep the row out of the scheduler's view — the
        // grace rule lives in `talos_integration_helpers::state_store`.
        let ttl_seconds = ttl_with_grace(row.expiration_ms);

        self.store()
            .set(
                user_id,
                row.id,
                value,
                ttl_seconds,
                IndexedSlots {
                    idx_str_1: Some(row.email_address.clone()),
                    idx_str_2: Some(row.topic_name.clone()),
                    idx_ts_1_ms: Some(row.expiration_ms),
                    idx_int_1: None,
                },
            )
            .await
    }

    async fn delete_row(&self, user_id: Uuid, channel_uuid: Uuid) -> Result<()> {
        self.store().delete(user_id, channel_uuid).await
    }

    pub(crate) async fn find_by_id(
        &self,
        user_id: Uuid,
        channel_uuid: Uuid,
    ) -> Result<GmailWatchRow> {
        match self.store().get_entry(user_id, channel_uuid).await? {
            Some(entry) => decode_row(&entry),
            None => Err(anyhow!(
                "gmail watch {} not found for user {}",
                channel_uuid,
                user_id
            )),
        }
    }

    async fn find_single_for_integration(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
    ) -> Result<Option<GmailWatchRow>> {
        // The lock guarantees there's at most one row per
        // (user, integration), but we still iterate the list to
        // defend against any bypass + to support a future
        // multi-label-filter shape.
        let entries = self
            .store()
            .list_entries(user_id, ListFilter::default(), 50)
            .await?;
        for entry in entries {
            let row = decode_row(&entry)?;
            if row.integration_id == integration_id {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    /// List every gmail watch row this user owns. Scheduler uses this
    /// enumerated per-user via `get_watches_needing_renewal`.
    pub(crate) async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<GmailWatchRow>> {
        let entries = self
            .store()
            .list_entries(user_id, ListFilter::default(), 500)
            .await?;
        let mut out = Vec::with_capacity(entries.len());
        for entry in entries {
            match decode_row(&entry) {
                Ok(row) => out.push(row),
                Err(e) => tracing::warn!(
                    key = %entry.key,
                    error = %e,
                    "skipping malformed gmail watch row"
                ),
            }
        }
        Ok(out)
    }

    /// List `(user_id, row)` pairs needing renewal in the next 24h.
    /// Iterates every user with an active Gmail integration — the
    /// same pattern gcal uses.
    ///
    /// Deliberately kept on raw `execute_op` (not `ChannelStore`):
    /// the per-user error arm carries the bespoke MCP-993 DLP
    /// redaction over the RAW `IntegrationStateError` Debug output,
    /// which the store's anyhow wrapping would alter.
    pub(crate) async fn get_watches_needing_renewal(&self) -> Result<Vec<(Uuid, GmailWatchRow)>> {
        let threshold_ms = (Utc::now() + Duration::hours(24)).timestamp_millis();
        let users: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT user_id FROM gmail_integrations WHERE is_active = true",
        )
        .fetch_all(&self.pool)
        .await
        .context("enumerate gmail integration owners")?;
        let mut out = Vec::new();
        for user_id in users {
            let filter = ListFilter {
                idx_ts_1_lt_ms: Some(threshold_ms),
                ..Default::default()
            };
            match execute_op(
                &self.pool,
                GMAIL_INTEGRATION_NAME,
                user_id,
                IntegrationOp::List { filter, limit: 500 },
            )
            .await
            {
                Ok(IntegrationOpResult::Entries { entries }) => {
                    if entries.len() == 500 {
                        tracing::warn!(%user_id, "gmail renewal query hit 500-row cap");
                    }
                    for entry in entries {
                        match decode_row(&entry) {
                            Ok(row) => out.push((user_id, row)),
                            Err(e) => tracing::error!(
                                key = %entry.key,
                                error = %e,
                                "skipping malformed gmail row"
                            ),
                        }
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    // MCP-993 (2026-05-15): DLP-redact the error in the
                    // operator-log surface. integration_state errors
                    // wrap downstream sqlx / RPC failures whose anyhow
                    // chain can include caller-supplied content
                    // (vault paths, channel UUIDs, upstream API body
                    // text). Defense-in-depth — sibling MCP-989/990
                    // operator-log redaction class.
                    let redacted = talos_dlp_provider::redact_str(&format!("{:?}", e));
                    tracing::error!(
                        %user_id,
                        error = %redacted,
                        "gmail list failed"
                    );
                }
            }
        }
        Ok(out)
    }

    async fn acquire_lock(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.create_locks.acquire((user_id, integration_id)).await
    }
}
