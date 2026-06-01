//! Minimal Gmail API client for the push-notification path.
//!
//! Covers only the endpoints the watch-channel lifecycle needs:
//!
//!   * `POST users.me/watch`    — register a push subscription
//!   * `POST users.me/stop`     — cancel it
//!   * `GET  users.me/history`  — fetch changes since a historyId
//!   * `GET  users.me/messages/:id` (metadata) — resolve history items
//!
//! OAuth flow + token refresh live in `integration.rs` and the
//! shared `OAuthCredentialService`. Callers pass in the resolved
//! access token.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const GMAIL_BASE: &str = "https://gmail.googleapis.com/gmail/v1";

/// reqwest::Client is Arc-backed, so `Clone` is cheap (bumps the
/// refcount). The orphan-stop path on `watch.rs` uses this to hand
/// an API client into a detached tokio::spawn without rebuilding
/// the TLS stack.
#[derive(Clone)]
pub struct GmailWatchApiClient {
    client: reqwest::Client,
    base_url: String,
}

/// Response from POST users.me/watch. Google returns expiration as
/// a string of milliseconds — parse to i64 once at the boundary so
/// downstream code never juggles string/number.
#[derive(Debug, Clone, Deserialize)]
pub struct WatchResponse {
    /// Most recent historyId Gmail knows about for this mailbox at
    /// the moment the watch was registered. Use as the starting
    /// point for `users.history.list` on first boot; ignore on
    /// renewal (we keep our stored cursor which is almost certainly
    /// older — i.e. we haven't caught up yet).
    #[serde(
        rename = "historyId",
        deserialize_with = "deserialize_string_or_u64_api"
    )]
    pub history_id: u64,
    /// Absolute epoch ms at which Google will stop publishing to our
    /// topic for this user. Always 7 days out by Gmail policy.
    #[serde(
        rename = "expiration",
        deserialize_with = "deserialize_string_or_u64_api"
    )]
    pub expiration_ms: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HistoryListResponse {
    #[serde(default)]
    pub history: Vec<HistoryEntry>,
    /// Gmail's current tip-of-log historyId. Persist this as the
    /// starting point for the NEXT call so we never re-process.
    #[serde(
        rename = "historyId",
        default,
        deserialize_with = "deserialize_optional_string_or_u64_api"
    )]
    pub next_history_id: Option<u64>,
    #[serde(default, rename = "nextPageToken")]
    pub next_page_token: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HistoryEntry {
    /// Set when messages were added to the mailbox in this history
    /// step. We dispatch one WASM job per new message; other history
    /// kinds (messagesDeleted, labelsAdded, labelsRemoved) are
    /// ignored for now.
    #[serde(default, rename = "messagesAdded")]
    pub messages_added: Vec<HistoryMessageAdded>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct HistoryMessageAdded {
    pub message: HistoryMessageRef,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct HistoryMessageRef {
    pub id: String,
    #[serde(default, rename = "threadId")]
    pub thread_id: Option<String>,
    #[serde(default, rename = "labelIds")]
    pub label_ids: Vec<String>,
}

/// Body for POST users.me/watch. `label_filter_behavior` picks
/// "INCLUDE" (default, only these labels notify) vs "EXCLUDE"
/// (everything except these); we hard-code INCLUDE since it's what
/// callers almost always want.
#[derive(Debug, Serialize)]
struct WatchRequest<'a> {
    #[serde(rename = "topicName")]
    topic_name: &'a str,
    #[serde(rename = "labelIds", skip_serializing_if = "<[String]>::is_empty")]
    label_ids: &'a [String],
    #[serde(rename = "labelFilterBehavior")]
    label_filter_behavior: &'static str,
}

impl Default for GmailWatchApiClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GmailWatchApiClient {
    pub fn new() -> Self {
        // MCP-534: same Mode-B hardening as GmailApiClient — Bearer
        // token on every users.watch / users.stop / history.list call.
        Self {
            client: reqwest::Client::builder()
                .timeout(super::GMAIL_HTTP_TIMEOUT)
                .connect_timeout(super::GMAIL_CONNECT_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("GmailWatchApiClient: failed to build hardened reqwest client"),
            base_url: GMAIL_BASE.to_string(),
        }
    }

    /// Register a push subscription for the user's mailbox. `labels`
    /// is the optional filter (`[]` = deliver everything).
    pub async fn users_watch(
        &self,
        access_token: &str,
        topic_name: &str,
        labels: &[String],
    ) -> Result<WatchResponse> {
        let url = format!("{}/users/me/watch", self.base_url);
        let body = WatchRequest {
            topic_name,
            label_ids: labels,
            label_filter_behavior: "INCLUDE",
        };
        let resp = self
            .client
            .post(&url)
            .bearer_auth(access_token)
            .json(&body)
            .send()
            .await
            .context("users.watch request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            // MCP-529: DLP-scrub the body preview AND route through the
            // codepoint-aware truncator. The local `truncate` helper
            // uses raw byte slicing `&s[..n]` which panics when `n`
            // lands mid-codepoint (same class as MCP-477/478/479);
            // Google API error responses can contain Unicode in
            // localised error messages. DLP scrubbing closes the
            // log-aggregator-leak path opened in MCP-527 / MCP-528 in
            // case Google ever echoes back token / email content.
            let text = talos_http_body::read_error_text_capped(resp).await;
            let preview = talos_text_util::truncate_at_char_boundary(&text, 500);
            let redacted = talos_dlp_provider::redact_str(preview);
            tracing::warn!(%status, body = %redacted, "users.watch returned error");
            bail!("users.watch returned {}", status);
        }
        talos_http_body::read_json_capped::<WatchResponse>(resp)
            .await
            .context("decode users.watch response")
    }

    /// Cancel the push subscription. Idempotent on Google's side —
    /// calling stop when no watch is active is harmless.
    pub async fn users_stop(&self, access_token: &str) -> Result<()> {
        let url = format!("{}/users/me/stop", self.base_url);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("users.stop request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            // MCP-529: same fix as users.watch above.
            let text = talos_http_body::read_error_text_capped(resp).await;
            let preview = talos_text_util::truncate_at_char_boundary(&text, 500);
            let redacted = talos_dlp_provider::redact_str(preview);
            tracing::warn!(%status, body = %redacted, "users.stop returned error");
            bail!("users.stop returned {}", status);
        }
        Ok(())
    }

    /// Fetch history since `start_history_id`. One page; callers
    /// iterate `next_page_token` if set.
    pub async fn users_history_list(
        &self,
        access_token: &str,
        start_history_id: u64,
        label_id: Option<&str>,
        page_token: Option<&str>,
    ) -> Result<HistoryListResponse> {
        let mut url = reqwest::Url::parse(&format!("{}/users/me/history", self.base_url))
            .context("parse history URL")?;
        {
            let mut q = url.query_pairs_mut();
            q.append_pair("startHistoryId", &start_history_id.to_string());
            q.append_pair("historyTypes", "messageAdded");
            if let Some(l) = label_id {
                q.append_pair("labelId", l);
            }
            if let Some(p) = page_token {
                q.append_pair("pageToken", p);
            }
            q.append_pair("maxResults", "500");
        }
        let resp = self
            .client
            .get(url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("history.list request failed")?;
        if !resp.status().is_success() {
            let status = resp.status();
            // MCP-529: same fix as users.watch above.
            let text = talos_http_body::read_error_text_capped(resp).await;
            let preview = talos_text_util::truncate_at_char_boundary(&text, 500);
            let redacted = talos_dlp_provider::redact_str(preview);
            tracing::warn!(%status, body = %redacted, "history.list returned error");
            bail!("history.list returned {}", status);
        }
        talos_http_body::read_json_capped::<HistoryListResponse>(resp)
            .await
            .context("decode history.list response")
    }
}

// MCP-529: the local `truncate` helper was removed — every call site
// now uses `talos_text_util::truncate_at_char_boundary` which is
// codepoint-safe (the bare `&s[..n]` slice in the old helper panicked
// when `n` landed mid-codepoint on a Unicode response, e.g. localised
// Google API error messages).

fn deserialize_string_or_u64_api<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    use serde::de::Error;
    let v = serde_json::Value::deserialize(d)?;
    match v {
        serde_json::Value::String(s) => s.parse::<u64>().map_err(D::Error::custom),
        serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| D::Error::custom("not u64")),
        _ => Err(D::Error::custom("expected string or number")),
    }
}

fn deserialize_optional_string_or_u64_api<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<u64>, D::Error> {
    use serde::de::Error;
    let v = Option::<serde_json::Value>::deserialize(d)?;
    match v {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::String(s)) => s.parse::<u64>().map(Some).map_err(D::Error::custom),
        Some(serde_json::Value::Number(n)) => Ok(n.as_u64()),
        _ => Err(D::Error::custom("expected string, number, or null")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // MCP-556: `truncate` lives in `watch_channel_service` (the sole
    // production caller); the orphan tests below were missing this
    // import, which made `cargo test --workspace --lib` fail in
    // `talos-gmail` with E0425.
    use crate::watch_channel_service::truncate;
    use serde_json::json;

    #[test]
    fn watch_response_decodes_string_fields() {
        // Google documents both `historyId` and `expiration` as
        // 64-bit integers returned as strings. Our deserializer
        // accepts either.
        let raw = json!({ "historyId": "12345", "expiration": "1700000000000" });
        let r: WatchResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(r.history_id, 12345);
        assert_eq!(r.expiration_ms, 1_700_000_000_000);
    }

    #[test]
    fn watch_response_decodes_number_fields() {
        let raw = json!({ "historyId": 42, "expiration": 1_700_000_000_000u64 });
        let r: WatchResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(r.history_id, 42);
        assert_eq!(r.expiration_ms, 1_700_000_000_000);
    }

    #[test]
    fn history_list_handles_missing_history_id() {
        // When the current historyId is unchanged, Google may return
        // no historyId at the top level — treat as None.
        let raw = json!({ "history": [] });
        let r: HistoryListResponse = serde_json::from_value(raw).unwrap();
        assert!(r.history.is_empty());
        assert_eq!(r.next_history_id, None);
    }

    #[test]
    fn history_entry_messages_added() {
        let raw = json!({
            "history": [{
                "messagesAdded": [
                    { "message": { "id": "m1", "threadId": "t1", "labelIds": ["INBOX"] } },
                    { "message": { "id": "m2" } }
                ]
            }],
            "historyId": "999"
        });
        let r: HistoryListResponse = serde_json::from_value(raw).unwrap();
        assert_eq!(r.next_history_id, Some(999));
        assert_eq!(r.history.len(), 1);
        assert_eq!(r.history[0].messages_added.len(), 2);
        assert_eq!(r.history[0].messages_added[0].message.id, "m1");
        assert_eq!(
            r.history[0].messages_added[0].message.label_ids,
            vec!["INBOX".to_string()]
        );
        // m2 has no label_ids / thread_id — both should default.
        assert_eq!(
            r.history[0].messages_added[1].message.label_ids,
            Vec::<String>::new()
        );
        assert!(r.history[0].messages_added[1].message.thread_id.is_none());
    }

    #[test]
    fn truncate_returns_short_string_unchanged() {
        assert_eq!(truncate("hello", 10), "hello");
    }

    #[test]
    fn truncate_caps_with_ellipsis() {
        let t = truncate(&"x".repeat(1000), 50);
        assert_eq!(t.chars().count(), 51);
        assert!(t.ends_with('…'));
    }
}
