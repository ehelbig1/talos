//! Google Cloud watch-channel lifecycle, backed by the
//! `integration_state` primitive.
//!
//! # Before editing this file
//!
//! Read `docs/integration-pattern.md`. This is the THIRD consumer of
//! the canonical push-integration pattern (after `google_calendar` and
//! `gmail`). Where it diverges from those two, the divergence is
//! deliberate and driven by the upstream:
//!
//! * **No renewal / scheduler.** Unlike Gmail/GCal watches (which WE
//!   create against Google's watch API and must renew every 7 days),
//!   the Google Cloud push subscription is created and owned by the
//!   USER via `gcloud` against a Pub/Sub topic that points at our push
//!   endpoint. Nothing on our side expires, so there is no renewal
//!   loop and the row carries **no TTL** (`expires_at = None`).
//! * **No upstream API call at create.** `create_watch` only mints a
//!   local push token + persists a row; the user wires the Pub/Sub
//!   subscription to `.../api/gcp/pubsub/{token}` themselves.
//! * **Per-watch service account.** Each watch stores its OWN
//!   `expected_sa_email`; the push-JWT service-account check is
//!   per-row, not a single operator-configured value (Gmail's model).
//!
//! # Storage model
//!
//! Each watch is one row in `integration_state`:
//!
//! | column            | value                                          |
//! |-------------------|------------------------------------------------|
//! | integration_name  | `"google_cloud"`                              |
//! | user_id           | owning user                                    |
//! | key               | `"watch/{internal_uuid}"`                      |
//! | value             | JSON — full watch-row shape (AEAD at rest)     |
//! | expires_at        | NULL — the user owns the upstream subscription |
//! | idx_str_1         | `sha256_hex(push_token)` (webhook lookup)      |
//! | idx_str_2         | `expected_sa_email` (observability / dedup)    |
//! | idx_ts_1          | `last_push_received_ms` (liveness)             |
//! | idx_int_1         | unused                                         |
//!
//! The raw `push_token` lives ONLY inside the (AEAD-encrypted) row
//! value. The webhook hot path looks up by `sha256_hex(push_token)` on
//! `idx_str_1` — the raw secret is never indexed or logged (lint 41,
//! same discipline as `talos-webhooks/src/approval.rs:200`).

use super::integration::GoogleCloudIntegrationService;
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::Utc;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use talos_integration_helpers::audit::{insert_channel_audit, ChannelAuditEvent};
use talos_integration_helpers::state_store::{ChannelStore, CreateLockMap};
use talos_memory::integration_state_rpc::{IndexedSlots, ListFilter, StoredEntry};
use uuid::Uuid;

pub(crate) const GOOGLE_CLOUD_INTEGRATION_NAME: &str = "google_cloud";
const WATCH_KEY_PREFIX: &str = "watch/";

/// Max accepted length of a raw push token BEFORE hashing, on the
/// webhook hot path. Our tokens are 32 bytes base64url (43 chars); a
/// 128-char ceiling is generous and closes a trivial pre-hash DoS
/// lever (an attacker POSTing a multi-MB `{token}` path segment).
const MAX_PUSH_TOKEN_LEN: usize = 128;

/// Only persist a fresh `last_push_received_ms` when the previous value
/// is at least this old. Push volume can be high; a write per push
/// would hammer `integration_state` for a liveness field that's only
/// read by the summary UI.
const PUSH_RECEIVED_THROTTLE_MS: i64 = 60_000;

/// Row stored in `integration_state.value`. Separate from any API-
/// facing struct so controller-private fields (the raw `push_token`)
/// never leak through a summary projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct GcpWatchRow {
    pub id: Uuid,
    pub integration_id: Uuid,
    pub display_name: String,
    /// The Google service-account email the push JWT must be issued by
    /// (`--push-auth-service-account=...`). Validated at create time.
    pub expected_sa_email: String,
    /// Raw push token embedded in the push endpoint URL. Stored ONLY
    /// here (the row value is AEAD-encrypted at rest by
    /// integration_state); the webhook lookup keys on its sha256 in
    /// `idx_str_1`, never the raw value.
    pub push_token: String,
    pub module_id: Option<Uuid>,
    /// Epoch ms of the most recent verified push. `None` until the
    /// first push lands.
    pub last_push_received_ms: Option<i64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

fn decode_row(entry: &StoredEntry) -> Result<GcpWatchRow> {
    serde_json::from_str(&entry.value).context("decode google_cloud watch row")
}

/// Validate a Google service-account email. Accepts user-/project-
/// managed SAs (`*@*.iam.gserviceaccount.com`) AND Google-managed
/// system SAs (`*@*.gserviceaccount.com`, e.g. the Monitoring
/// notification SA). Rejects anything else so a typo doesn't create a
/// watch that can never authenticate a push.
pub fn is_valid_sa_email(email: &str) -> bool {
    if email.is_empty() || email.len() > 320 {
        return false;
    }
    let (local, domain) = match email.rsplit_once('@') {
        Some((l, d)) => (l, d),
        None => return false,
    };
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    // ".iam.gserviceaccount.com" is a subset of ".gserviceaccount.com"
    // with a leading label, but the plan enumerates both for clarity;
    // the domain suffix check (with its leading dot requiring a label
    // before it) covers both `*@*.iam.gserviceaccount.com` and the
    // broader `*@*.gserviceaccount.com`.
    email.ends_with(".iam.gserviceaccount.com") || domain.ends_with(".gserviceaccount.com")
}

/// Service handle. Owns the DB pool, the integration service (OAuth
/// token access for the read-only test probe), and the create-lock map.
pub struct GcpWatchService {
    pub(crate) pool: sqlx::PgPool,
    pub(crate) integrations: Arc<GoogleCloudIntegrationService>,
    /// Serializes `create_watch` per `(user_id, integration_id)` so two
    /// concurrent callers can't race the same create.
    create_locks: CreateLockMap<(Uuid, Uuid)>,
}

impl GcpWatchService {
    pub fn new(pool: sqlx::PgPool, integrations: Arc<GoogleCloudIntegrationService>) -> Self {
        Self {
            pool,
            integrations,
            create_locks: CreateLockMap::new(),
        }
    }

    /// User-scoped handle over `integration_state`. Cheap per call
    /// (`PgPool` is `Arc`-backed).
    fn store(&self) -> ChannelStore {
        ChannelStore::new(
            self.pool.clone(),
            GOOGLE_CLOUD_INTEGRATION_NAME,
            WATCH_KEY_PREFIX,
        )
    }

    /// Evict idle create-locks. Wired into the hourly sweep in main.rs.
    pub fn cleanup_create_locks(&self) {
        self.create_locks.cleanup();
    }

    // ------------------------------------------------------------------
    // Public lifecycle ops — all user-scoped, authz automatic through
    // integration_state row scoping.
    // ------------------------------------------------------------------

    /// Create a new watch. Mints a fresh push token, persists the row,
    /// and audits. Unlike Gmail/GCal there is NO upstream API call and
    /// NO fast-path "update existing" — a user may run multiple Cloud
    /// Monitoring channels (different service accounts / modules)
    /// against one integration, each an independent watch.
    pub(crate) async fn create_watch(
        &self,
        user_id: Uuid,
        integration_id: Uuid,
        expected_sa_email: String,
        display_name: Option<String>,
        module_id: Option<Uuid>,
    ) -> Result<GcpWatchRow> {
        if !is_valid_sa_email(&expected_sa_email) {
            return Err(anyhow!(
                "expected_sa_email must be a Google service account \
                 (e.g. talos-gcp-pusher@<project>.iam.gserviceaccount.com)"
            ));
        }

        let _guard = self.create_locks.acquire((user_id, integration_id)).await;

        // Ownership gate: the integration must exist AND belong to the
        // caller. `get_integration` filters `WHERE user_id = $2`.
        let _integration = self
            .integrations
            .get_integration(integration_id, user_id)
            .await
            .context("fetch integration for watch create")?
            .ok_or_else(|| anyhow!("integration {} not found", integration_id))?;

        let push_token = mint_push_token();
        let now_ms = Utc::now().timestamp_millis();
        let row = GcpWatchRow {
            id: Uuid::new_v4(),
            integration_id,
            display_name: display_name.unwrap_or_else(|| "GCP Monitoring".to_string()),
            expected_sa_email,
            push_token,
            module_id,
            last_push_received_ms: None,
            created_at_ms: now_ms,
            updated_at_ms: now_ms,
        };

        self.upsert_row(user_id, &row).await?;

        // DLP: the raw token is NEVER logged or placed in an index/audit
        // row — the pseudonymous `channel_uuid` is the log identifier.
        tracing::info!(
            channel_uuid = %row.id,
            integration_id = %row.integration_id,
            "✅ Created google_cloud watch"
        );

        // Audit — shared channel-lifecycle log. `target` is the SA
        // email; metadata carries the channel uuid + integration id but
        // NEVER the push token.
        if let Err(e) = insert_channel_audit(
            &self.pool,
            ChannelAuditEvent {
                integration_id: Some(row.integration_id),
                user_id,
                event_type: "gcp_channel_created",
                target: Some(&row.expected_sa_email),
                success: true,
                error_message: None,
                metadata: serde_json::json!({
                    "channel_uuid": row.id.to_string(),
                    "integration_id": row.integration_id.to_string(),
                }),
            },
        )
        .await
        {
            tracing::warn!(error = %e, "gcp channel_created audit log insert failed");
        }

        Ok(row)
    }

    /// Stop + delete. Idempotent: a missing row succeeds silently. There
    /// is no upstream call — the user deletes the Pub/Sub subscription
    /// on their side; deleting our row makes any further push a
    /// no-active-watch ack.
    pub async fn stop_watch(&self, user_id: Uuid, channel_uuid: Uuid) -> Result<()> {
        let row = match self.find_by_id(user_id, channel_uuid).await {
            Ok(r) => r,
            Err(_) => return Ok(()),
        };

        self.store().delete(user_id, row.id).await?;

        if let Err(e) = insert_channel_audit(
            &self.pool,
            ChannelAuditEvent {
                integration_id: Some(row.integration_id),
                user_id,
                event_type: "gcp_channel_stopped",
                target: Some(&row.expected_sa_email),
                success: true,
                error_message: None,
                metadata: serde_json::json!({
                    "channel_uuid": row.id.to_string(),
                    "integration_id": row.integration_id.to_string(),
                }),
            },
        )
        .await
        {
            tracing::warn!(error = %e, "gcp channel_stopped audit log insert failed");
        }
        Ok(())
    }

    /// Hot-path webhook lookup: given a raw push token from the push
    /// URL, resolve the owning `(user_id, watch row)`.
    ///
    /// Lint 41: the token is a secret, so the indexed lookup keys on
    /// `sha256_hex(token)` in `idx_str_1` (served O(1) by the global
    /// `integration_state_str1_idx` on `(integration_name, idx_str_1)`),
    /// never a raw-token equality. Once the owning `(user_id, key)` is
    /// found, the value is read back through `ChannelStore::get_entry`
    /// so decryption goes through the canonical AEAD path — mirrors the
    /// `token_hash`-then-fetch discipline in
    /// `talos-webhooks/src/approval.rs:200`.
    pub(crate) async fn find_by_push_token(
        &self,
        raw_token: &str,
    ) -> Result<Option<(Uuid, GcpWatchRow)>> {
        // Reject implausibly long / empty tokens BEFORE hashing (DoS
        // lever + can never be one of our 43-char tokens).
        if !is_lookupable_token(raw_token) {
            return Ok(None);
        }
        let token_hash = talos_text_util::sha256_hex(raw_token);

        // Read ONLY (user_id, key) here — the value stays encrypted and
        // is read back via the canonical path below. LIMIT 2 so we can
        // detect (and warn on) the impossible hash-collision case
        // without an unbounded scan.
        let rows: Vec<(Uuid, String)> = sqlx::query_as(
            "SELECT user_id, key FROM integration_state \
             WHERE integration_name = 'google_cloud' AND idx_str_1 = $1 \
             LIMIT 2",
        )
        .bind(&token_hash)
        .fetch_all(&self.pool)
        .await
        .context("google_cloud push-token lookup")?;

        if rows.len() > 1 {
            // A sha256 collision across two watch rows is astronomically
            // unlikely — log the anomaly (uuids only, never the token)
            // and take the first deterministically.
            tracing::warn!(
                match_count = rows.len(),
                "google_cloud push-token hash matched >1 watch row; using the first"
            );
        }

        let (user_id, key) = match rows.into_iter().next() {
            Some(pair) => pair,
            None => return Ok(None),
        };

        // Parse the internal uuid out of the `watch/{uuid}` key so we
        // can read back through the canonical (decrypting) path.
        let channel_uuid = match key
            .strip_prefix(WATCH_KEY_PREFIX)
            .and_then(|s| Uuid::parse_str(s).ok())
        {
            Some(id) => id,
            None => {
                tracing::warn!(%key, "google_cloud watch key not in watch/<uuid> form; skipping");
                return Ok(None);
            }
        };

        match self.store().get_entry(user_id, channel_uuid).await? {
            Some(entry) => {
                let row = decode_row(&entry)?;
                Ok(Some((user_id, row)))
            }
            None => Ok(None),
        }
    }

    /// Stamp the most-recent-push timestamp. Throttled: only writes when
    /// the previous value is at least [`PUSH_RECEIVED_THROTTLE_MS`] old
    /// (or unset), so a burst of pushes doesn't hammer integration_state
    /// for a liveness field.
    pub async fn record_push_received(&self, user_id: Uuid, channel_uuid: Uuid) -> Result<()> {
        let mut row = self.find_by_id(user_id, channel_uuid).await?;
        let now_ms = Utc::now().timestamp_millis();
        let should_write = match row.last_push_received_ms {
            Some(prev) => now_ms.saturating_sub(prev) >= PUSH_RECEIVED_THROTTLE_MS,
            None => true,
        };
        if should_write {
            row.last_push_received_ms = Some(now_ms);
            row.updated_at_ms = now_ms;
            self.upsert_row(user_id, &row).await?;
        }
        Ok(())
    }

    /// Load one watch row by internal uuid (ownership via the
    /// user-scoped store).
    pub(crate) async fn find_by_id(
        &self,
        user_id: Uuid,
        channel_uuid: Uuid,
    ) -> Result<GcpWatchRow> {
        match self.store().get_entry(user_id, channel_uuid).await? {
            Some(entry) => decode_row(&entry),
            None => Err(anyhow!(
                "google_cloud watch {} not found for user {}",
                channel_uuid,
                user_id
            )),
        }
    }

    /// List every google_cloud watch row this user owns.
    pub(crate) async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<GcpWatchRow>> {
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
                    "skipping malformed google_cloud watch row"
                ),
            }
        }
        Ok(out)
    }

    // ------------------------------------------------------------------
    // Internals
    // ------------------------------------------------------------------

    async fn upsert_row(&self, user_id: Uuid, row: &GcpWatchRow) -> Result<()> {
        let value = serde_json::to_value(row).context("encode google_cloud watch row")?;
        self.store()
            .set(
                user_id,
                row.id,
                value,
                // No TTL: the user owns the upstream subscription, so
                // there is nothing on our side to expire or renew.
                None,
                IndexedSlots {
                    idx_str_1: Some(talos_text_util::sha256_hex(&row.push_token)),
                    idx_str_2: Some(row.expected_sa_email.clone()),
                    idx_ts_1_ms: row.last_push_received_ms,
                    idx_int_1: None,
                },
            )
            .await
    }
}

/// Whether a raw push token from the URL is even worth a DB lookup:
/// non-empty and within the pre-hash length cap. Pulled out as a pure
/// predicate so the DoS-lever guard is unit-testable without a DB.
fn is_lookupable_token(raw: &str) -> bool {
    !raw.is_empty() && raw.len() <= MAX_PUSH_TOKEN_LEN
}

/// Mint a 32-byte push token, base64url-encoded (no padding, URL-safe
/// so it can ride in the push endpoint path segment). 256 bits of
/// CSPRNG entropy — the sole authenticator binding a Pub/Sub push to a
/// watch row.
fn mint_push_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn minted_token_length_and_charset() {
        let t = mint_push_token();
        // 32 bytes → 43 base64url chars (no padding).
        assert_eq!(t.len(), 43, "unexpected token length: {t}");
        assert!(
            t.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
            "token has non-url-safe chars: {t}"
        );
    }

    #[test]
    fn minted_tokens_are_unique() {
        let mut seen = HashSet::new();
        for _ in 0..1000 {
            assert!(seen.insert(mint_push_token()), "token collision");
        }
    }

    #[test]
    fn row_encode_decode_round_trip() {
        let row = GcpWatchRow {
            id: Uuid::new_v4(),
            integration_id: Uuid::new_v4(),
            display_name: "prod alerts".into(),
            expected_sa_email: "talos-gcp-pusher@my-proj.iam.gserviceaccount.com".into(),
            push_token: mint_push_token(),
            module_id: Some(Uuid::new_v4()),
            last_push_received_ms: Some(1_700_000_000_000),
            created_at_ms: 1_699_000_000_000,
            updated_at_ms: 1_700_000_000_000,
        };
        let value = serde_json::to_string(&row).unwrap();
        let entry = StoredEntry {
            key: format!("{WATCH_KEY_PREFIX}{}", row.id),
            value,
            updated_at_ms: row.updated_at_ms,
            expires_at_ms: None,
            slots: IndexedSlots::default(),
        };
        let decoded = decode_row(&entry).unwrap();
        assert_eq!(decoded.id, row.id);
        assert_eq!(decoded.push_token, row.push_token);
        assert_eq!(decoded.expected_sa_email, row.expected_sa_email);
        assert_eq!(decoded.last_push_received_ms, row.last_push_received_ms);
    }

    #[test]
    fn push_token_length_cap_rejection() {
        assert!(!is_lookupable_token(""));
        assert!(!is_lookupable_token(&"x".repeat(MAX_PUSH_TOKEN_LEN + 1)));
        // A real minted token (43 chars) and the boundary both pass.
        assert!(is_lookupable_token(&mint_push_token()));
        assert!(is_lookupable_token(&"x".repeat(MAX_PUSH_TOKEN_LEN)));
    }

    #[test]
    fn sa_email_validation() {
        // Valid — project/user-managed SA.
        assert!(is_valid_sa_email(
            "talos-gcp-pusher@my-project.iam.gserviceaccount.com"
        ));
        // Valid — Google-managed system SA (Monitoring notification).
        assert!(is_valid_sa_email(
            "service-123@gcp-sa-monitoring-notification.iam.gserviceaccount.com"
        ));
        assert!(is_valid_sa_email("push@my-proj.gserviceaccount.com"));
        // Invalid.
        assert!(!is_valid_sa_email(""));
        assert!(!is_valid_sa_email("alice@gmail.com"));
        assert!(!is_valid_sa_email("no-at-sign.iam.gserviceaccount.com"));
        assert!(!is_valid_sa_email("@my-proj.iam.gserviceaccount.com"));
        assert!(!is_valid_sa_email("push@gserviceaccount.com")); // no label before suffix
        assert!(!is_valid_sa_email(
            "evil@my-proj.iam.gserviceaccount.com.attacker.com"
        ));
    }
}
