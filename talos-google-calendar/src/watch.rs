//! Google Calendar watch-channel management, backed by the
//! `integration_state` primitive.
//!
//! # Before editing this file or adding a third integration
//!
//! Read `docs/integration-pattern.md`. This module + its gmail
//! sibling are the two reference implementations of the canonical
//! push-integration pattern. Drift should be deliberate.
//!
//! The pattern's most-learned lesson — the `create_watch_channel`
//! / `create_fresh_watch_channel_locked` split — originated here in
//! commit `e43430b` (the zero-channel bug).
//!
//! # Storage model
//!
//! Each watch channel is one row in `integration_state`:
//!
//! | column            | value                                   |
//! |-------------------|-----------------------------------------|
//! | integration_name  | `"gcal"`                                |
//! | user_id           | owning user                             |
//! | key               | `"channel/{internal_uuid}"`             |
//! | value             | JSON — full `WatchChannel` shape        |
//! | expires_at        | ~5 min past Google's expiration         |
//! | idx_str_1         | Google channel_id (webhook lookup)      |
//! | idx_str_2         | calendar_id (per-calendar dedup)        |
//! | idx_ts_1          | Google expiration (renewal filter)      |
//! | idx_int_1         | (unused)                                |
//!
//! The webhook handler recovers `user_id` from the signed channel
//! token (see `webhook_token.rs`) and then performs an O(1) lookup
//! on `idx_str_1`.

use super::{GoogleCalendarService, WatchChannel};
use crate::api::GoogleCalendarApiClient;
use crate::webhook_token;
use anyhow::{anyhow, Context, Result};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use talos_integration_helpers::audit::{
    insert_channel_audit, truncate_and_redact_error, ChannelAuditEvent,
};
use talos_integration_helpers::state_store::{ttl_with_grace, ChannelStore};
use talos_integration_state::execute_op;
use talos_memory::integration_state_rpc::{
    IndexedSlots, IntegrationOp, IntegrationOpResult, ListFilter, StoredEntry,
};
use uuid::Uuid;

pub(crate) const GCAL_INTEGRATION_NAME: &str = "gcal";

/// Serialized form of a `WatchChannel` stored in
/// `integration_state.value`. Kept separate from the `WatchChannel`
/// struct so adding ephemeral controller-side fields to `WatchChannel`
/// doesn't silently break row compatibility with deployed rows.
///
/// ANY change to this struct is a storage-format change — existing
/// rows will have the old shape. Prefer adding new fields with
/// `#[serde(default)]` over renaming or removing existing ones.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct WatchChannelRow {
    pub(crate) id: Uuid,
    pub(crate) integration_id: Uuid,
    pub(crate) calendar_id: String,
    pub(crate) channel_id: String,
    pub(crate) resource_id: String,
    pub(crate) webhook_url: String,
    pub(crate) expiration_ms: i64,
    #[serde(default)]
    pub(crate) sync_token: Option<String>,
    #[serde(default)]
    pub(crate) module_id: Option<Uuid>,
    #[serde(default)]
    pub(crate) last_message_number: i64,
    pub(crate) created_at_ms: i64,
    pub(crate) updated_at_ms: i64,
}

impl WatchChannelRow {
    fn to_watch_channel(&self, user_id: Uuid) -> WatchChannel {
        WatchChannel {
            id: self.id,
            integration_id: self.integration_id,
            calendar_id: self.calendar_id.clone(),
            channel_id: self.channel_id.clone(),
            resource_id: self.resource_id.clone(),
            webhook_url: self.webhook_url.clone(),
            expiration: DateTime::<Utc>::from_timestamp_millis(self.expiration_ms)
                .unwrap_or_else(Utc::now),
            sync_token: self.sync_token.clone(),
            // `verification_token` is no longer a per-channel random; the
            // integration-level HMAC (see webhook_token.rs) replaces it.
            // Surface the bound user_id here for any caller that still
            // inspects the field — it's enough to correlate with logs.
            verification_token: user_id.to_string(),
            is_active: true, // rows in integration_state are live by definition
            module_id: self.module_id,
            created_at: DateTime::<Utc>::from_timestamp_millis(self.created_at_ms)
                .unwrap_or_else(Utc::now),
            updated_at: DateTime::<Utc>::from_timestamp_millis(self.updated_at_ms)
                .unwrap_or_else(Utc::now),
        }
    }
}

/// Decode a `StoredEntry` from integration_state into a `WatchChannelRow`.
/// `KeyNotFound` is the only error the caller should pattern-match on
/// upstream; everything else is logged as a decode failure.
fn decode_row(entry: &StoredEntry) -> Result<WatchChannelRow> {
    serde_json::from_str(&entry.value)
        .context("failed to decode gcal watch channel JSON from integration_state")
}

/// Resolve `(integration_id) -> user_id` once up-front. Every gcal
/// integration row has exactly one owning user; we need that user
/// before we can write to integration_state.
async fn user_id_for_integration(pool: &sqlx::PgPool, integration_id: Uuid) -> Result<Uuid> {
    let user_id: Uuid = sqlx::query_scalar(
        "SELECT user_id FROM google_calendar_integrations WHERE id = $1 AND is_active = true",
    )
    .bind(integration_id)
    .fetch_one(pool)
    .await
    .context("Integration not found or inactive")?;
    Ok(user_id)
}

impl GoogleCalendarService {
    /// User-scoped handle over `integration_state` for gcal watch
    /// rows. Cheap to construct per call (`PgPool` is `Arc`-backed).
    fn store(&self) -> ChannelStore {
        ChannelStore::new(self.db_pool.clone(), GCAL_INTEGRATION_NAME, "channel/")
    }

    /// Create a new watch channel, or re-point an existing one at a
    /// different module. Creates a Google-side watch iff no active
    /// `(integration_id, calendar_id)` row exists in integration_state.
    pub async fn create_watch_channel(
        &self,
        integration_id: Uuid,
        calendar_id: &str,
        webhook_url: &str,
        module_id: Option<Uuid>, // WASM module to execute when webhook arrives
    ) -> Result<WatchChannel> {
        // Google requires publicly-reachable HTTPS webhook URLs. Catch
        // the common dev-mode failure (forgot to start ngrok / BASE_URL
        // still pointing at localhost) BEFORE we burn a Google API
        // call — the API would reject with a generic 400, and our
        // caller would see "Failed to ..." with no hint about the
        // fix. A precise message here saves hours of head-scratching.
        if !webhook_url.starts_with("https://")
            || webhook_url.contains("localhost")
            || webhook_url.contains("127.0.0.1")
        {
            anyhow::bail!(
                "Webhook URL must be a publicly-reachable HTTPS endpoint \
                 (got: {}). In dev: run `make ngrok` to start a tunnel, \
                 which will restart the controller with BASE_URL pointing \
                 at the ngrok URL. Google rejects http:// and localhost URLs.",
                webhook_url
            );
        }

        let user_id = user_id_for_integration(&self.db_pool, integration_id).await?;

        // Serialize creation per (user, integration, calendar) so two
        // concurrent callers can't both pass the "no existing channel"
        // check and both create orphan Google channels.
        let _guard = self
            .acquire_create_channel_lock(user_id, integration_id, calendar_id)
            .await;

        // Fast path: if this (integration_id, calendar_id) already has a
        // live channel, update its module_id without touching Google's
        // API. Looked up via `idx_str_2 = calendar_id` + value filter.
        if let Some(mut existing) = self
            .find_channel_by_integration_and_calendar(user_id, integration_id, calendar_id)
            .await?
        {
            existing.module_id = module_id;
            existing.updated_at_ms = Utc::now().timestamp_millis();
            self.upsert_channel_row(user_id, &existing).await?;
            tracing::info!(
                channel_uuid = %existing.id,
                calendar = %calendar_id,
                "♻️  Reusing existing gcal watch channel (module_id updated)"
            );
            return Ok(existing.to_watch_channel(user_id));
        }

        // Slow path: call Google to create a fresh channel and persist.
        self.create_fresh_watch_channel_locked(
            user_id,
            integration_id,
            calendar_id,
            webhook_url,
            module_id,
            None,
        )
        .await
    }

    /// Unconditionally create a new Google-side channel and persist a
    /// new integration_state row. Assumes the caller already holds the
    /// `(user_id, integration_id, calendar_id)` create lock.
    ///
    /// Does NOT consult the fast path — when called from renewal the
    /// old row is still in integration_state, and the fast path would
    /// incorrectly short-circuit into returning the row that's about
    /// to be deleted. See the renewal path comment for details.
    async fn create_fresh_watch_channel_locked(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
        calendar_id: &str,
        webhook_url: &str,
        module_id: Option<Uuid>,
        preserved_sync_token: Option<String>,
    ) -> Result<WatchChannel> {
        let shared_key = self
            .worker_shared_key()
            .context("WORKER_SHARED_KEY not configured; webhook tokens cannot be signed")?;

        // Fetch a fresh access token for the Google API call.
        let integration_obj = self
            .get_integration(user_id, integration_id)
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "Integration {} not found for user {}",
                    integration_id,
                    user_id
                )
            })?;
        let access_token = self.get_access_token(&integration_obj).await?;

        // Pre-generate the UUID that will become the `X-Goog-Channel-ID`
        // on the Google side. Sign it BEFORE the API call so a network
        // failure mid-create doesn't leave a signed row without a live
        // Google channel (or vice versa).
        let channel_uuid = Uuid::new_v4();
        let google_channel_id = channel_uuid.to_string();
        let verification_token =
            webhook_token::sign_channel_token(user_id, &google_channel_id, shared_key);

        // Create the watch on Google's side.
        let api_client = GoogleCalendarApiClient::new();
        let watch_response = api_client
            .create_watch(
                &access_token,
                calendar_id,
                &google_channel_id,
                webhook_url,
                Some(&verification_token),
            )
            .await
            .context("Failed to create watch channel on Google API")?;

        let expiration_ms = watch_response
            .expiration
            .parse::<i64>()
            .context("Invalid expiration timestamp returned by Google")?;

        let now_ms = Utc::now().timestamp_millis();
        let row = WatchChannelRow {
            id: channel_uuid,
            integration_id,
            calendar_id: calendar_id.to_string(),
            channel_id: google_channel_id,
            resource_id: watch_response.resource_id,
            webhook_url: webhook_url.to_string(),
            expiration_ms,
            sync_token: preserved_sync_token.clone(),
            module_id,
            last_message_number: 0,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };

        self.upsert_channel_row(user_id, &row).await.map_err(|e| {
            // If we persisted the Google-side channel but failed to
            // persist to integration_state, we have an orphaned
            // Google channel. Best-effort stop so it doesn't keep
            // firing webhooks we can't resolve.
            tracing::error!(
                error = %e,
                channel = %row.channel_id,
                "❌ Failed to persist gcal watch row to integration_state; stopping orphaned Google channel"
            );
            let access_token_clone = access_token.clone();
            let channel_id_clone = row.channel_id.clone();
            let resource_id_clone = row.resource_id.clone();
            tokio::spawn(async move {
                let api = GoogleCalendarApiClient::new();
                let _ = api
                    .stop_watch(&access_token_clone, &channel_id_clone, &resource_id_clone)
                    .await;
            });
            e
        })?;

        tracing::info!(
            channel_uuid = %row.id,
            google_channel = %row.channel_id,
            calendar = %calendar_id,
            "✅ Created gcal watch channel"
        );

        // Audit-log the creation so post-hoc "who / when / which module"
        // queries don't require scraping tracing output. resource_id
        // is captured because Google's stop API requires both
        // channel_id AND resource_id; if the integration_state row
        // ever goes missing but the Google-side channel persists,
        // this audit row is the ONLY place resource_id can be
        // recovered from (Google doesn't expose a list-my-channels
        // API). Errors here are non-fatal — the watch was
        // successfully created, losing the audit row is a
        // visibility regression, not a correctness one.
        if let Err(e) = insert_channel_audit(
            &self.db_pool,
            ChannelAuditEvent {
                integration_id: Some(integration_id),
                user_id,
                event_type: "channel_created",
                target: Some(calendar_id),
                success: true,
                error_message: None,
                metadata: serde_json::json!({
                    "channel_uuid": row.id.to_string(),
                    "google_channel_id": row.channel_id,
                    "resource_id": row.resource_id,
                    "expiration": row.expiration_ms,
                    "module_id": row.module_id,
                    "preserved_sync_token": preserved_sync_token.is_some(),
                }),
            },
        )
        .await
        {
            tracing::warn!(error = %e, "gcal channel_created audit log insert failed");
        }

        Ok(row.to_watch_channel(user_id))
    }

    /// Renew a watch channel before it expires. Stops the old Google
    /// channel, deletes the old integration_state row, then creates a
    /// new fresh channel with the old sync_token preserved.
    ///
    /// # Ordering
    ///
    /// We delete the old row BEFORE creating the new Google-side
    /// channel. If create fails, we'll have no channel for this
    /// calendar — the scheduler will log the error and the user's
    /// webhooks pause until the next successful run. That's worse
    /// than a transparent success, BUT the alternative (calling the
    /// public `create_watch_channel`) would hit its fast-path check,
    /// find the old row, and return it unchanged — we'd delete the
    /// old row after "renewal" and end up with ZERO channels for the
    /// calendar. The loud-failure path is strictly better.
    ///
    /// `user_id` is the owning user — required because integration_state
    /// is scoped per-user. If you only have the channel uuid, resolve
    /// the user via `get_channels_needing_renewal` which returns
    /// `(user_id, channel)` pairs.
    pub async fn renew_watch_channel(
        &self,
        user_id: Uuid,
        channel_id: Uuid,
    ) -> Result<WatchChannel> {
        let old_row = self
            .find_channel_by_id_raw(user_id, channel_id)
            .await
            .with_context(|| {
                format!(
                    "Watch channel {} not found in integration_state for user {}",
                    channel_id, user_id
                )
            })?;

        let integration_obj = self
            .get_integration(user_id, old_row.integration_id)
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "Integration {} not found for user {}",
                    old_row.integration_id,
                    user_id
                )
            })?;
        let access_token = self.get_access_token(&integration_obj).await?;

        // Hold the create lock across the whole rotation so no other
        // caller can slip in with a concurrent create on the same
        // calendar.
        let _guard = self
            .acquire_create_channel_lock(user_id, old_row.integration_id, &old_row.calendar_id)
            .await;

        // Best-effort stop of the old Google channel. 404/410 means
        // already expired — ignore.
        let api_client = GoogleCalendarApiClient::new();
        let _ = api_client
            .stop_watch(&access_token, &old_row.channel_id, &old_row.resource_id)
            .await;

        // Preserve data we need before deleting the row, then delete
        // so the fast-path check in create can't find it.
        let integration_id = old_row.integration_id;
        let calendar_id = old_row.calendar_id.clone();
        let webhook_url = old_row.webhook_url.clone();
        let module_id = old_row.module_id;
        let sync_token = old_row.sync_token.clone();
        let old_google_channel_id = old_row.channel_id.clone();
        self.delete_channel_row(user_id, old_row.id).await?;

        // Create the replacement via the locked internal path. The
        // fast path would be wrong here — we JUST deleted the row,
        // but its index entries may linger for a moment.
        let new = self
            .create_fresh_watch_channel_locked(
                user_id,
                integration_id,
                &calendar_id,
                &webhook_url,
                module_id,
                sync_token,
            )
            .await?;

        // REGRESSION GUARD for commit e43430b — the zero-channel bug.
        // If the new channel's google_channel_id matches the old one,
        // it means create_fresh_watch_channel_locked is somehow returning
        // the existing row (e.g., someone "refactored" it to reuse
        // create_watch_channel's fast path). That would silently leave
        // us with zero watch channels for this calendar after the
        // subsequent delete of the old row. debug_assert fires in
        // dev/test builds and in CI; release builds compile it out.
        debug_assert_ne!(
            new.channel_id, old_google_channel_id,
            "gcal renewal produced a channel with the same google_channel_id \
             as the old one — the zero-channel bug has regressed. renew must \
             call create_fresh_watch_channel_locked, NOT create_watch_channel."
        );

        Ok(new)
    }

    /// Take the per-(user, integration, calendar) mutex that serializes
    /// watch-channel creation. The returned guard must be held until
    /// the Google API call + integration_state write are complete.
    async fn acquire_create_channel_lock(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
        calendar_id: &str,
    ) -> tokio::sync::OwnedMutexGuard<()> {
        self.create_channel_locks
            .acquire((user_id, integration_id, calendar_id.to_string()))
            .await
    }

    /// List channels that expire within the next 24 hours. Uses the
    /// indexed `idx_ts_1` slot so this is fast even with many channels
    /// per user.
    ///
    /// Iterates every known gcal-owning user (the outer DISTINCT query).
    /// If cardinality ever grows past ~10k users this should move to a
    /// paginated per-user iterator — for now a one-shot per user is
    /// acceptable.
    ///
    /// Deliberately kept on raw `execute_op` (not `ChannelStore`): the
    /// per-user tri-arm handling (unexpected-variant error line + raw
    /// `IntegrationStateError` Debug in the failure log) predates the
    /// store and must stay byte-for-byte.
    pub async fn get_channels_needing_renewal(&self) -> Result<Vec<(Uuid, WatchChannel)>> {
        let threshold_ms = (Utc::now() + Duration::hours(24)).timestamp_millis();

        // Find every user that owns at least one active gcal integration.
        let users: Vec<Uuid> = sqlx::query_scalar(
            "SELECT DISTINCT user_id FROM google_calendar_integrations WHERE is_active = true",
        )
        .fetch_all(&self.db_pool)
        .await
        .context("Failed to enumerate gcal integration owners")?;

        let mut out = Vec::new();
        for user_id in users {
            let filter = ListFilter {
                idx_ts_1_lt_ms: Some(threshold_ms),
                ..Default::default()
            };
            match execute_op(
                &self.db_pool,
                GCAL_INTEGRATION_NAME,
                user_id,
                IntegrationOp::List {
                    filter,
                    // 500 is the RPC hard cap; few users will exceed that
                    // in practice (channels are per-calendar, not per-event).
                    limit: 500,
                },
            )
            .await
            {
                Ok(IntegrationOpResult::Entries { entries }) => {
                    if entries.len() == 500 {
                        tracing::warn!(
                            %user_id,
                            "gcal renewal query hit 500-row cap — some channels may be missed this cycle"
                        );
                    }
                    for entry in entries {
                        match decode_row(&entry) {
                            Ok(row) => out.push((user_id, row.to_watch_channel(user_id))),
                            Err(e) => tracing::error!(
                                key = %entry.key,
                                error = %e,
                                "Skipping malformed gcal row"
                            ),
                        }
                    }
                }
                Ok(_) => tracing::error!("Unexpected op result for gcal list"),
                Err(e) => tracing::error!(
                    user_id = %user_id,
                    error = ?e,
                    "Failed to list gcal channels for renewal"
                ),
            }
        }

        Ok(out)
    }

    /// Sync events for a watch channel and update the stored sync_token.
    /// `user_id` is the owning user; callers get this from the signed
    /// webhook token or from a prior channel lookup.
    pub async fn sync_channel_events(
        &self,
        user_id: Uuid,
        channel_id: Uuid,
    ) -> Result<Vec<JsonValue>> {
        let row = self.find_channel_by_id_raw(user_id, channel_id).await?;

        let integration_obj = self
            .get_integration(user_id, row.integration_id)
            .await?
            .ok_or_else(|| {
                anyhow!(
                    "Integration {} not found for user {}",
                    row.integration_id,
                    user_id
                )
            })?;
        let access_token = self.get_access_token(&integration_obj).await?;

        let api_client = GoogleCalendarApiClient::new();
        let (events, new_sync_token) = api_client
            .sync_events(&access_token, &row.calendar_id, row.sync_token.as_deref())
            .await
            .context("Failed to sync events from Google Calendar API")?;

        self.update_channel_sync_token(user_id, channel_id, &new_sync_token)
            .await?;

        Ok(events
            .into_iter()
            .map(|e| serde_json::to_value(e).unwrap_or(serde_json::json!({})))
            .collect())
    }

    /// Stop a watch channel on Google's side, then remove the row.
    /// Idempotent — already-deleted rows succeed silently.
    /// `user_id` is the owning user.
    pub async fn stop_watch_channel(&self, user_id: Uuid, channel_id: Uuid) -> Result<()> {
        let row = match self.find_channel_by_id_raw(user_id, channel_id).await {
            Ok(r) => r,
            Err(_) => return Ok(()), // already gone; idempotent
        };

        let integration_obj = self.get_integration(user_id, row.integration_id).await?;
        let mut google_stop_error: Option<String> = None;
        if let Some(integration) = integration_obj {
            let access_token = self.get_access_token(&integration).await?;
            let api_client = GoogleCalendarApiClient::new();
            if let Err(e) = api_client
                .stop_watch(&access_token, &row.channel_id, &row.resource_id)
                .await
            {
                tracing::warn!(
                    channel = %row.channel_id,
                    error = %e,
                    "Failed to stop Google channel; continuing with local delete"
                );
                google_stop_error = Some(e.to_string());
            }
        }

        self.delete_channel_row(user_id, row.id).await?;

        // Audit-log the stop. Records both success AND partial-failure
        // (Google side refused). Non-fatal on insert failure.
        let success = google_stop_error.is_none();
        // MCP-980 + MCP-1181: the Google stop-watch error is truncated
        // at 1 KiB FIRST, then DLP-redacted before bind — sibling to
        // the gmail/watch.rs google_err redaction. Both steps live in
        // the canonical `truncate_and_redact_error` helper.
        let redacted_stop_err = google_stop_error.as_deref().map(truncate_and_redact_error);
        if let Err(e) = insert_channel_audit(
            &self.db_pool,
            ChannelAuditEvent {
                integration_id: Some(row.integration_id),
                user_id,
                event_type: "channel_stopped",
                target: Some(&row.calendar_id),
                success,
                error_message: redacted_stop_err.as_deref(),
                metadata: serde_json::json!({
                    "channel_uuid": row.id.to_string(),
                    "google_channel_id": row.channel_id,
                }),
            },
        )
        .await
        {
            tracing::warn!(error = %e, "gcal channel_stopped audit log insert failed");
        }

        Ok(())
    }

    // -----------------------------------------------------------------
    // Webhook-path helper: look up a channel by its Google-supplied
    // channel_id, scoped to a user recovered from the signed token.
    // -----------------------------------------------------------------

    /// Look up a watch channel by its internal UUID, scoped to the
    /// owning user. Used by paths where we already have the uuid from
    /// an earlier lookup — no slot index needed.
    pub(crate) async fn find_channel_by_id_raw(
        &self,
        user_id: Uuid,
        channel_uuid: Uuid,
    ) -> Result<WatchChannelRow> {
        match self.store().get_entry(user_id, channel_uuid).await? {
            Some(entry) => decode_row(&entry),
            None => Err(anyhow!(
                "channel {} not found for user {}",
                channel_uuid,
                user_id
            )),
        }
    }

    /// Look up a watch channel by `(user_id, google_channel_id)`.
    /// `Ok(None)` if the channel is unknown (caller treats this as a
    /// stale webhook to be silently ignored).
    pub(crate) async fn find_channel_by_google_id(
        &self,
        user_id: Uuid,
        google_channel_id: &str,
    ) -> Result<Option<WatchChannel>> {
        let filter = ListFilter {
            idx_str_1_eq: Some(google_channel_id.to_string()),
            ..Default::default()
        };
        if let Some(entry) = self
            .store()
            .list_entries(user_id, filter, 1)
            .await?
            .into_iter()
            .next()
        {
            let row = decode_row(&entry)?;
            Ok(Some(row.to_watch_channel(user_id)))
        } else {
            Ok(None)
        }
    }

    /// Advance the `last_message_number` on a channel. Used by the
    /// webhook dedup path to skip message-number replays.
    ///
    /// Returns `Ok(true)` if the row was updated (msg is newer) and
    /// `Ok(false)` if it was skipped (duplicate / out-of-order).
    /// `Err` means the channel was unreachable (decode error, DB
    /// outage) — the caller treats these as INTERNAL_SERVER_ERROR.
    ///
    /// **Race note:** integration_state has no per-row conditional
    /// UPDATE, so this is a read-modify-write. Two concurrent webhooks
    /// with msg N and N+1 can both read the same `last_message_number`
    /// and both return `Ok(true)`, overwriting each other. The
    /// resulting row has whichever write landed last; dedup for the
    /// LOSING write is defeated. Event-level Redis deduplication
    /// downstream (`deduplicate_events`) covers this: even if
    /// `advance_message_number` misses a duplicate, the event-payload
    /// dedup prevents duplicate job dispatch. If Redis is unavailable,
    /// this degrades gracefully (worst case: duplicate execution of
    /// one event).
    pub(crate) async fn advance_message_number(
        &self,
        user_id: Uuid,
        channel_uuid: Uuid,
        msg_num: i64,
    ) -> Result<bool> {
        let entry = match self.store().get_entry(user_id, channel_uuid).await? {
            Some(entry) => entry,
            None => {
                return Err(anyhow!(
                    "channel {} not found during msg-num advance",
                    channel_uuid
                ))
            }
        };
        let mut row = decode_row(&entry)?;
        if msg_num <= row.last_message_number {
            return Ok(false);
        }
        row.last_message_number = msg_num;
        row.updated_at_ms = Utc::now().timestamp_millis();
        self.upsert_channel_row(user_id, &row).await?;
        Ok(true)
    }

    // -----------------------------------------------------------------
    // Internal plumbing
    // -----------------------------------------------------------------

    /// Upsert a channel row. Every slot is populated so the indexed
    /// lookups for webhook/renewal work consistently.
    async fn upsert_channel_row(&self, user_id: Uuid, row: &WatchChannelRow) -> Result<()> {
        let value = serde_json::to_value(row).context("encode gcal watch row")?;
        // Keep the row visible well past Google's advertised
        // expiration so a run of renewal failures doesn't cause the
        // row to vanish between scheduler ticks — the 14-day grace
        // rule (and the 1-hour floor for already-past expirations)
        // lives in `talos_integration_helpers::state_store`.
        //
        // Happy-path rows are deleted explicitly by `renew_watch_
        // channel` / `stop_watch_channel` / `deactivate_integration`,
        // so this TTL only fires for truly abandoned rows.
        let ttl_seconds = ttl_with_grace(row.expiration_ms);

        self.store()
            .set(
                user_id,
                row.id,
                value,
                ttl_seconds,
                IndexedSlots {
                    idx_str_1: Some(row.channel_id.clone()),
                    idx_str_2: Some(row.calendar_id.clone()),
                    idx_ts_1_ms: Some(row.expiration_ms),
                    idx_int_1: None,
                },
            )
            .await
    }

    async fn delete_channel_row(&self, user_id: Uuid, channel_uuid: Uuid) -> Result<()> {
        self.store().delete(user_id, channel_uuid).await
    }

    async fn update_channel_sync_token(
        &self,
        user_id: Uuid,
        channel_uuid: Uuid,
        sync_token: &str,
    ) -> Result<()> {
        let entry = match self.store().get_entry(user_id, channel_uuid).await? {
            Some(entry) => entry,
            None => anyhow::bail!("channel {} not found", channel_uuid),
        };
        let mut row = decode_row(&entry)?;
        row.sync_token = Some(sync_token.to_string());
        row.updated_at_ms = Utc::now().timestamp_millis();
        self.upsert_channel_row(user_id, &row).await
    }

    async fn find_channel_by_integration_and_calendar(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
        calendar_id: &str,
    ) -> Result<Option<WatchChannelRow>> {
        let filter = ListFilter {
            idx_str_2_eq: Some(calendar_id.to_string()),
            ..Default::default()
        };
        let entries = self.store().list_entries(user_id, filter, 50).await?;
        for entry in entries {
            let row = decode_row(&entry)?;
            if row.integration_id == integration_id {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    /// Accessor for the HMAC key used to sign webhook tokens. Held by
    /// the service as an optional because tests may construct one
    /// without a key; production construction always sets it.
    fn worker_shared_key(&self) -> Option<&[u8]> {
        self.shared_key.get().map(|k| k.as_slice())
    }
}
