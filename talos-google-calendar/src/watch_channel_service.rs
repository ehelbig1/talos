//! User-scoped watch-channel queries used by the REST handlers.
//!
//! Extraction rationale: the list handler was doing non-trivial work
//! (integration_state enumeration, row decode, batched module-name
//! resolution with defense-in-depth user filter, projection to the
//! public `WatchChannelSummary` shape). Keeping that in the HTTP
//! handler couples request parsing with data-shape logic; lifting it
//! here lets both tests and any future non-HTTP caller (GraphQL,
//! MCP tool, CLI) reach the same projection through one seam.
//!
//! Every method here is user-scoped by construction — the integration
//! _state layer is too, so authz is automatic. The SQL JOIN for
//! module names filters by `user_id IS NULL OR user_id = $me` as a
//! defense-in-depth belt on the suspender that the integration_state
//! scoping already provides.

use super::GoogleCalendarService;
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::Value as JsonValue;
use std::collections::HashMap;
use talos_integration_state::execute_op;
use talos_memory::integration_state_rpc::{IntegrationOp, IntegrationOpResult, ListFilter};
use uuid::Uuid;

/// Public API shape — distinct from the internal `WatchChannelRow`.
/// Adding controller-private fields to the internal row must NOT
/// automatically leak through this boundary.
#[derive(Serialize, Debug, Clone)]
pub struct WatchChannelSummary {
    pub channel_uuid: Uuid,
    pub integration_id: Uuid,
    pub calendar_id: String,
    pub google_channel_id: String,
    pub webhook_url: String,
    pub expiration: DateTime<Utc>,
    pub has_sync_token: bool,
    pub module_id: Option<Uuid>,
    pub module_name: Option<String>,
    pub last_message_number: i64,
    pub updated_at: DateTime<Utc>,
    /// Populated when the most recent renewal attempt for this
    /// channel failed. `None` means either the channel has never
    /// failed or its most recent event was a success. Callers
    /// display a warning badge + the error message to surface
    /// stuck channels (typically dead OAuth credentials).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recent_failure: Option<RenewalFailure>,
}

// `RenewalFailure` and `looks_like_oauth_failure` were lifted to the
// `talos-integration-helpers` crate so `talos-gmail` can depend on
// them without taking a dep on `talos-google-calendar`. Re-exported
// here for back-compat with the historical
// `crate::watch_channel_service::*` import path.
pub use talos_integration_helpers::{looks_like_oauth_failure, RenewalFailure};

pub struct WatchChannelService<'a> {
    service: &'a GoogleCalendarService,
}

impl<'a> WatchChannelService<'a> {
    pub fn new(service: &'a GoogleCalendarService) -> Self {
        Self { service }
    }

    /// List every active watch channel the user owns. Two DB round-
    /// trips total (one integration_state list + one batched module-
    /// name UNION), independent of channel count.
    pub async fn list_for_user(&self, user_id: Uuid) -> Result<Vec<WatchChannelSummary>> {
        let entries = match execute_op(
            &self.service.db_pool,
            super::watch::GCAL_INTEGRATION_NAME,
            user_id,
            IntegrationOp::List {
                filter: ListFilter::default(),
                limit: 500,
            },
        )
        .await
        {
            Ok(IntegrationOpResult::Entries { entries }) => entries,
            Ok(_) => vec![],
            Err(e) => {
                tracing::error!(
                    %user_id,
                    error = ?e,
                    "watch-channel list: integration_state list failed"
                );
                anyhow::bail!("failed to list watch channels");
            }
        };

        // Decode pass. Collect module_ids we'll need for the name
        // batch; log + skip malformed rows so an operator sees them
        // rather than silently losing data.
        let mut decoded: Vec<JsonValue> = Vec::with_capacity(entries.len());
        let mut module_ids: Vec<Uuid> = Vec::new();
        for entry in &entries {
            match serde_json::from_str::<JsonValue>(&entry.value) {
                Ok(v) => {
                    if let Some(mid) = v
                        .get("module_id")
                        .and_then(|m| m.as_str())
                        .and_then(|s| Uuid::parse_str(s).ok())
                    {
                        module_ids.push(mid);
                    }
                    decoded.push(v);
                }
                Err(e) => tracing::warn!(
                    key = %entry.key,
                    %user_id,
                    error = %e,
                    "skipping malformed gcal integration_state row in list"
                ),
            }
        }

        let module_name_by_id = self.resolve_module_names(user_id, &module_ids).await;

        let mut summaries = Vec::with_capacity(decoded.len());
        for v in decoded {
            if let Some(s) = project_row(&v, &module_name_by_id) {
                summaries.push(s);
            }
        }

        // Enrichment: attach the most recent renewal failure (if any)
        // to each row. One batched query regardless of row count,
        // filtered by user_id + channel_uuid set so we never scan
        // another user's audit entries.
        self.attach_recent_failures(user_id, &mut summaries).await;
        Ok(summaries)
    }

    /// For each summary, look up the most recent renewal audit entry
    /// for that channel_uuid. Attach a `RenewalFailure` iff that most
    /// recent entry was a failure — a successful event newer than any
    /// prior failure means the channel self-healed, so we don't
    /// display a stale warning.
    async fn attach_recent_failures(&self, user_id: Uuid, summaries: &mut [WatchChannelSummary]) {
        if summaries.is_empty() {
            return;
        }
        let channel_uuids: Vec<String> = summaries
            .iter()
            .map(|s| s.channel_uuid.to_string())
            .collect();

        // DISTINCT ON + ORDER BY gives us "the newest audit row per
        // channel_uuid in one pass". We restrict to recent history
        // (last 25 h = one scheduler cycle + margin) so an ancient
        // failure doesn't keep flagging a channel that's been working
        // for weeks.
        let rows: Vec<(String, String, bool, Option<String>, DateTime<Utc>)> = sqlx::query_as(
            "SELECT DISTINCT ON (metadata->>'channel_uuid') \
                    metadata->>'channel_uuid' AS channel_uuid, \
                    event_type, \
                    success, \
                    error_message, \
                    created_at \
             FROM google_calendar_audit_log \
             WHERE user_id = $1 \
               AND event_type IN ('channel_renewed', 'channel_renewal_failed') \
               AND metadata->>'channel_uuid' = ANY($2) \
               AND created_at > now() - interval '25 hours' \
             ORDER BY metadata->>'channel_uuid', created_at DESC",
        )
        .bind(user_id)
        .bind(&channel_uuids)
        .fetch_all(&self.service.db_pool)
        .await
        .unwrap_or_default();

        // Map channel_uuid_str → latest outcome. We only populate
        // `recent_failure` when the LATEST event is a failure; a
        // newer success wipes any prior failure badge.
        let mut latest: std::collections::HashMap<String, RenewalFailure> =
            std::collections::HashMap::new();
        for (cu, _event_type, success, error_message, at) in rows {
            if !success {
                let err = error_message.unwrap_or_else(|| "unknown error".into());
                let likely_oauth_failure = looks_like_oauth_failure(&err);
                latest.insert(
                    cu,
                    RenewalFailure {
                        error_message: truncate_error(&err, 300),
                        failed_at: at,
                        likely_oauth_failure,
                    },
                );
            }
            // success rows are implicitly ignored — DISTINCT ON gave us
            // the NEWEST row per channel, so if this row is success
            // we know there's no active failure for this channel.
        }

        for s in summaries.iter_mut() {
            if let Some(failure) = latest.remove(&s.channel_uuid.to_string()) {
                s.recent_failure = Some(failure);
            }
        }
    }

    /// Batched module-name resolution. Returns empty when `module_ids`
    /// is empty (never issues an empty `ANY` query). DB errors fall
    /// back to an empty map rather than propagating — name resolution
    /// is best-effort, the channel row itself is the authoritative
    /// data.
    async fn resolve_module_names(
        &self,
        user_id: Uuid,
        module_ids: &[Uuid],
    ) -> HashMap<Uuid, String> {
        let mut out = HashMap::new();
        if module_ids.is_empty() {
            return out;
        }
        // Defense-in-depth: filter by the caller's user_id AND NULL
        // (catalog templates). A compromised integration_state row
        // referencing another user's private module won't leak its
        // name. Phase 5.1: query the unified `modules` table by canonical id.
        #[derive(sqlx::FromRow)]
        struct Row {
            id: Uuid,
            name: String,
        }
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT id, name \
               FROM modules \
              WHERE id = ANY($1) \
                AND (user_id IS NULL OR user_id = $2)",
        )
        .bind(module_ids)
        .bind(user_id)
        .fetch_all(&self.service.db_pool)
        .await
        .unwrap_or_default();
        for row in rows {
            out.insert(row.id, row.name);
        }
        out
    }
}

/// Pure projection from the stored JSON row to the API shape. Kept
/// free-function so unit tests can exercise it without a service
/// instance.
fn project_row(
    v: &JsonValue,
    module_name_by_id: &HashMap<Uuid, String>,
) -> Option<WatchChannelSummary> {
    let channel_uuid = v
        .get("id")
        .and_then(|x| x.as_str())
        .and_then(|s| Uuid::parse_str(s).ok())?;
    let module_id = v
        .get("module_id")
        .and_then(|m| m.as_str())
        .and_then(|s| Uuid::parse_str(s).ok());
    Some(WatchChannelSummary {
        channel_uuid,
        integration_id: v
            .get("integration_id")
            .and_then(|x| x.as_str())
            .and_then(|s| Uuid::parse_str(s).ok())
            .unwrap_or_default(),
        calendar_id: v
            .get("calendar_id")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        google_channel_id: v
            .get("channel_id")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        webhook_url: v
            .get("webhook_url")
            .and_then(|x| x.as_str())
            .unwrap_or_default()
            .to_string(),
        expiration: DateTime::<Utc>::from_timestamp_millis(
            v.get("expiration_ms").and_then(|x| x.as_i64()).unwrap_or(0),
        )
        .unwrap_or_else(Utc::now),
        // Empty string counts as "no token" alongside missing / null.
        has_sync_token: v
            .get("sync_token")
            .map(|st| !st.is_null() && st.as_str().map(|s| !s.is_empty()).unwrap_or(false))
            .unwrap_or(false),
        module_id,
        module_name: module_id.and_then(|id| module_name_by_id.get(&id).cloned()),
        last_message_number: v
            .get("last_message_number")
            .and_then(|x| x.as_i64())
            .unwrap_or(0),
        updated_at: DateTime::<Utc>::from_timestamp_millis(
            v.get("updated_at_ms").and_then(|x| x.as_i64()).unwrap_or(0),
        )
        .unwrap_or_else(Utc::now),
        recent_failure: None,
    })
}

/// Cap error text so a misbehaving downstream can't flood the
/// response + UI with a megabyte of formatted garbage.
fn truncate_error(s: &str, cap: usize) -> String {
    if s.len() <= cap {
        s.to_string()
    } else {
        let mut out = s.chars().take(cap).collect::<String>();
        out.push('…');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn row(id: &str, ch: &str, exp_ms: i64, module: Option<&str>) -> JsonValue {
        let mut v = json!({
            "id": id,
            "integration_id": "00000000-0000-0000-0000-000000000001",
            "calendar_id": "primary",
            "channel_id": ch,
            "webhook_url": "https://example/webhook",
            "expiration_ms": exp_ms,
            "updated_at_ms": exp_ms,
            "last_message_number": 0,
        });
        if let Some(m) = module {
            v["module_id"] = json!(m);
        }
        v
    }

    #[test]
    fn project_row_basic_shape() {
        let uuid_a = Uuid::new_v4();
        let uuid_ch = "goog-ch-abc";
        let v = row(&uuid_a.to_string(), uuid_ch, 1_700_000_000_000, None);
        let s = project_row(&v, &HashMap::new()).unwrap();
        assert_eq!(s.channel_uuid, uuid_a);
        assert_eq!(s.calendar_id, "primary");
        assert_eq!(s.google_channel_id, uuid_ch);
        assert_eq!(s.last_message_number, 0);
        assert!(!s.has_sync_token);
        assert!(s.module_id.is_none());
        assert!(s.module_name.is_none());
    }

    #[test]
    fn project_row_resolves_module_name_when_present() {
        let module_id = Uuid::new_v4();
        let v = row(
            &Uuid::new_v4().to_string(),
            "ch",
            0,
            Some(&module_id.to_string()),
        );
        let mut names = HashMap::new();
        names.insert(module_id, "my-gcal-handler".to_string());
        let s = project_row(&v, &names).unwrap();
        assert_eq!(s.module_id, Some(module_id));
        assert_eq!(s.module_name.as_deref(), Some("my-gcal-handler"));
    }

    #[test]
    fn project_row_missing_module_name_stays_none() {
        let module_id = Uuid::new_v4();
        let v = row(
            &Uuid::new_v4().to_string(),
            "ch",
            0,
            Some(&module_id.to_string()),
        );
        // Empty name map — e.g. module deleted after row write.
        let s = project_row(&v, &HashMap::new()).unwrap();
        assert_eq!(s.module_id, Some(module_id));
        assert!(
            s.module_name.is_none(),
            "missing name must not fall back to empty string"
        );
    }

    #[test]
    fn has_sync_token_distinguishes_empty_missing_null() {
        let base = row(&Uuid::new_v4().to_string(), "ch", 0, None);

        // Field absent.
        assert!(!project_row(&base, &HashMap::new()).unwrap().has_sync_token);

        // Field present but null.
        let mut v = base.clone();
        v["sync_token"] = JsonValue::Null;
        assert!(!project_row(&v, &HashMap::new()).unwrap().has_sync_token);

        // Field present but empty string.
        v["sync_token"] = json!("");
        assert!(!project_row(&v, &HashMap::new()).unwrap().has_sync_token);

        // Field present with a real token.
        v["sync_token"] = json!("CAESBA...");
        assert!(project_row(&v, &HashMap::new()).unwrap().has_sync_token);
    }

    #[test]
    fn project_row_rejects_invalid_uuid() {
        let mut v = row("not-a-uuid", "ch", 0, None);
        assert!(project_row(&v, &HashMap::new()).is_none());
        v["id"] = json!(Uuid::new_v4().to_string());
        assert!(project_row(&v, &HashMap::new()).is_some());
    }

    #[test]
    fn project_row_has_no_recent_failure_by_default() {
        let v = row(&Uuid::new_v4().to_string(), "ch", 0, None);
        let s = project_row(&v, &HashMap::new()).unwrap();
        assert!(s.recent_failure.is_none());
    }

    #[test]
    fn looks_like_oauth_failure_matches_real_error_shapes() {
        // Real messages observed from Google's OAuth + our own
        // "reconnect" hint text. Every one MUST match.
        for msg in [
            "invalid_grant: Token has been expired or revoked.",
            "HTTP 401 Unauthorized",
            "Calendar access token not found at vault path oauth/google_calendar/…. Reconnect the Google Calendar integration.",
            "INVALID_TOKEN",
            "refresh token failed",
            "oauth request returned 401",
        ] {
            assert!(
                looks_like_oauth_failure(msg),
                "should flag as OAuth failure: {msg}"
            );
        }
    }

    #[test]
    fn looks_like_oauth_failure_false_negative_on_transient_errors() {
        // Transient network / rate-limit errors MUST NOT trip the
        // banner — they're not a "reconnect" fix.
        for msg in [
            "network error: connection reset",
            "dns resolution failed",
            "timeout after 30s",
            "rate limit exceeded",
            "HTTP 503 Service Unavailable",
            "Internal Server Error",
        ] {
            assert!(
                !looks_like_oauth_failure(msg),
                "must NOT flag as OAuth failure: {msg}"
            );
        }
    }

    #[test]
    fn truncate_error_caps_long_strings() {
        let s = "x".repeat(1000);
        let t = truncate_error(&s, 100);
        assert!(t.chars().count() == 101, "cap + ellipsis");
        assert!(t.ends_with('…'));
        // Short strings pass through unchanged.
        assert_eq!(truncate_error("short", 100), "short");
    }
}
