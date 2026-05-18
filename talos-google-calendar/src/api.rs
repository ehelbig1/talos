use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Google Calendar API client
pub struct GoogleCalendarApiClient {
    client: reqwest::Client,
    base_url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CalendarListEntry {
    pub id: String,
    pub summary: String,
    pub description: Option<String>,
    #[serde(rename = "timeZone")]
    pub time_zone: Option<String>,
    #[serde(rename = "accessRole")]
    pub access_role: String,
    pub primary: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Event {
    pub id: String,
    pub status: String,
    pub html_link: Option<String>,
    pub summary: Option<String>,
    pub description: Option<String>,
    pub start: Option<EventDateTime>,
    pub end: Option<EventDateTime>,
    pub organizer: Option<Organizer>,
    pub attendees: Option<Vec<Attendee>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EventDateTime {
    pub date: Option<String>,
    #[serde(rename = "dateTime")]
    pub date_time: Option<String>,
    #[serde(rename = "timeZone")]
    pub time_zone: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Organizer {
    pub email: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Attendee {
    pub email: String,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(rename = "responseStatus")]
    pub response_status: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct WatchRequest {
    pub id: String,
    #[serde(rename = "type")]
    pub channel_type: String,
    pub address: String,
    pub token: Option<String>,
    pub expiration: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct WatchResponse {
    pub id: String,
    #[serde(rename = "resourceId")]
    pub resource_id: String,
    #[serde(rename = "resourceUri")]
    pub resource_uri: String,
    pub expiration: String,
}

impl GoogleCalendarApiClient {
    pub fn new() -> Self {
        // MCP-534: same Mode-B hardening as the Gmail / Slack /
        // Atlassian / OAuth clients fixed in MCP-533. Every Calendar
        // API call attaches `Bearer <access_token>`; disable redirects
        // so a stray 302 can't replay the credential to a redirect
        // target, and replace the `unwrap_or_else(Client::new)`
        // silent-downgrade footgun with a loud `.expect()`.
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .connect_timeout(std::time::Duration::from_secs(5))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("GoogleCalendarApiClient: failed to build hardened reqwest client");
        Self {
            client,
            base_url: "https://www.googleapis.com/calendar/v3".to_string(),
        }
    }

    /// List user's calendars
    pub async fn list_calendars(&self, access_token: &str) -> Result<Vec<CalendarListEntry>> {
        let url = format!("{}/users/me/calendarList", self.base_url);

        tracing::debug!("Fetching calendar list");

        let response = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("Failed to list calendars")?;

        let status = response.status();
        tracing::debug!("Google Calendar API response status: {}", status);

        if !status.is_success() {
            let error_text = response.text().await?;
            tracing::warn!(
                "Google Calendar API error listing calendars: {}",
                error_text
            );
            anyhow::bail!("Calendar list failed: {}", error_text);
        }

        let data: Value = response.json().await?;

        let calendars: Vec<CalendarListEntry> = data["items"]
            .as_array()
            .context("Missing items in calendar list")?
            .iter()
            .filter_map(|item| {
                let result: Result<CalendarListEntry, _> = serde_json::from_value(item.clone());
                if let Err(ref e) = result {
                    tracing::warn!("Failed to parse calendar entry: {}", e);
                }
                result.ok()
            })
            .collect();

        tracing::debug!("Parsed {} calendars", calendars.len());

        Ok(calendars)
    }

    /// Get events from a calendar (with optional sync token for incremental sync)
    pub async fn list_events(
        &self,
        access_token: &str,
        calendar_id: &str,
        sync_token: Option<&str>,
        page_token: Option<&str>,
    ) -> Result<(Vec<Event>, Option<String>, Option<String>)> {
        let url = format!("{}/calendars/{}/events", self.base_url, calendar_id);

        let mut request = self.client.get(&url).bearer_auth(access_token);

        // Add sync token for incremental sync
        if let Some(token) = sync_token {
            request = request.query(&[("syncToken", token)]);
        } else {
            // Full sync - get all events
            request = request.query(&[("singleEvents", "true")]);
        }

        // Add page token for pagination
        if let Some(token) = page_token {
            request = request.query(&[("pageToken", token)]);
        }

        let response = request.send().await.context("Failed to list events")?;

        // Handle 410 Gone - sync token expired
        if response.status() == 410 {
            anyhow::bail!("Sync token expired - full sync required");
        }

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Event list failed: {}", error_text);
        }

        let data: Value = response.json().await?;

        let events = data["items"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|item| serde_json::from_value(item.clone()).ok())
            .collect();

        let next_page_token = data["nextPageToken"].as_str().map(|s| s.to_string());
        let next_sync_token = data["nextSyncToken"].as_str().map(|s| s.to_string());

        Ok((events, next_page_token, next_sync_token))
    }

    /// Get a specific event
    pub async fn get_event(
        &self,
        access_token: &str,
        calendar_id: &str,
        event_id: &str,
    ) -> Result<Event> {
        let url = format!(
            "{}/calendars/{}/events/{}",
            self.base_url, calendar_id, event_id
        );

        let response = self
            .client
            .get(&url)
            .bearer_auth(access_token)
            .send()
            .await
            .context("Failed to get event")?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Get event failed: {}", error_text);
        }

        let event: Event = response.json().await?;
        Ok(event)
    }

    /// Create a watch channel for a calendar
    pub async fn create_watch(
        &self,
        access_token: &str,
        calendar_id: &str,
        channel_id: &str,
        webhook_url: &str,
        token: Option<&str>,
    ) -> Result<WatchResponse> {
        let url = format!("{}/calendars/{}/events/watch", self.base_url, calendar_id);

        // Set expiration to 7 days from now (max allowed)
        let expiration = chrono::Utc::now().timestamp_millis() + (7 * 24 * 60 * 60 * 1000);

        let watch_request = WatchRequest {
            id: channel_id.to_string(),
            channel_type: "web_hook".to_string(),
            address: webhook_url.to_string(),
            token: token.map(|s| s.to_string()),
            expiration: Some(expiration),
        };

        let response = self
            .client
            .post(&url)
            .bearer_auth(access_token)
            .json(&watch_request)
            .send()
            .await
            .context("Failed to create watch channel")?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Watch creation failed: {}", error_text);
        }

        let watch_response: WatchResponse = response.json().await?;
        Ok(watch_response)
    }

    /// Stop a watch channel
    pub async fn stop_watch(
        &self,
        access_token: &str,
        channel_id: &str,
        resource_id: &str,
    ) -> Result<()> {
        let url = format!("{}/channels/stop", self.base_url);

        let stop_request = serde_json::json!({
            "id": channel_id,
            "resourceId": resource_id,
        });

        let response = self
            .client
            .post(&url)
            .bearer_auth(access_token)
            .json(&stop_request)
            .send()
            .await
            .context("Failed to stop watch channel")?;

        if !response.status().is_success() {
            let error_text = response.text().await?;
            anyhow::bail!("Stop watch failed: {}", error_text);
        }

        Ok(())
    }

    /// Perform incremental sync with automatic pagination
    pub async fn sync_events(
        &self,
        access_token: &str,
        calendar_id: &str,
        sync_token: Option<&str>,
    ) -> Result<(Vec<Event>, String)> {
        // MCP-982: Bound pagination defensively. Google's events.list
        // normally terminates when `nextSyncToken` is returned (final
        // page), but if the API misbehaves we'd loop forever
        // accumulating into `all_events`. 100 pages × ~250 entries/page
        // = ~25 000 event changes — large enough to cover an active
        // calendar's first sync, small enough to bound a runaway loop.
        // Without a sync_token we cannot commit progress, so error out
        // rather than break silently; the next webhook push re-triggers
        // sync from the old sync_token (Google webhook notifications
        // are idempotent — they just say "something changed", not
        // what).
        const MAX_SYNC_PAGES: usize = 100;
        let mut all_events = Vec::new();
        let mut page_token: Option<String> = None;
        let mut new_sync_token: Option<String> = None;
        let mut pages_processed: usize = 0;

        loop {
            pages_processed += 1;
            if pages_processed > MAX_SYNC_PAGES {
                anyhow::bail!(
                    "gcal sync hit MAX_SYNC_PAGES cap ({}); next webhook will retry from old sync_token",
                    MAX_SYNC_PAGES
                );
            }
            let (events, next_page, next_sync) = self
                .list_events(access_token, calendar_id, sync_token, page_token.as_deref())
                .await?;

            all_events.extend(events);

            if let Some(sync) = next_sync {
                new_sync_token = Some(sync);
                break;
            }

            if let Some(next) = next_page {
                page_token = Some(next);
            } else {
                break;
            }
        }

        let final_sync_token =
            new_sync_token.context("No sync token returned - this should not happen")?;

        Ok((all_events, final_sync_token))
    }
}

impl Default for GoogleCalendarApiClient {
    fn default() -> Self {
        Self::new()
    }
}
