// Canonical catalog module: list Google Calendar events in a time window.
// Uses vault:// header resolution for auth — no direct secrets::get_secret calls.

use talos_sdk_macros::talos_module;
use serde::Deserialize;
use chrono::{Utc, Duration};

const HARD_CAP: usize = 50;
const MAX_HOURS: u64 = 168;

#[derive(Deserialize)]
struct ListResp {
    items: Option<Vec<Event>>,
}

#[derive(Deserialize)]
struct Event {
    id: Option<String>,
    summary: Option<String>,
    description: Option<String>,
    location: Option<String>,
    start: Option<EventTime>,
    end: Option<EventTime>,
    #[serde(rename = "hangoutLink")]
    hangout_link: Option<String>,
    attendees: Option<Vec<Attendee>>,
}

#[derive(Deserialize)]
struct EventTime {
    #[serde(rename = "dateTime")]
    date_time: Option<String>,
    date: Option<String>,
}

#[derive(Deserialize)]
struct Attendee {
    email: Option<String>,
    #[serde(rename = "responseStatus")]
    response_status: Option<String>,
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let auth = config["AUTH_HEADER"]
        .as_str()
        .ok_or("Missing AUTH_HEADER config (expected 'Bearer vault://oauth/google_calendar/{user_id}/{account}/access_token')")?;
    let calendar_id = config["CALENDAR_ID"].as_str().unwrap_or("primary");
    let hours_ahead: u64 = config["HOURS_AHEAD"].as_u64().unwrap_or(24).clamp(1, MAX_HOURS);
    let max_results: usize = config["MAX_RESULTS"]
        .as_u64()
        .map(|v| v as usize)
        .unwrap_or(20)
        .min(HARD_CAP);

    let now = Utc::now();
    let time_min = now.to_rfc3339();
    let time_max = (now + Duration::hours(hours_ahead as i64)).to_rfc3339();

    let query_string = format!(
        "timeMin={}&timeMax={}&singleEvents=true&orderBy=startTime&maxResults={}",
        pct(&time_min),
        pct(&time_max),
        max_results
    );
    let list_url = format!(
        "https://www.googleapis.com/calendar/v3/calendars/{}/events?{}",
        pct(calendar_id),
        query_string
    );
    let req = talos::core::http::Request {
        method: talos::core::http::Method::Get,
        url: list_url,
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ],
        body: vec![],
        timeout_ms: Some(10000),
    };
    let resp = talos::core::http::fetch(&req).map_err(|e| format!("calendar fetch: {:?}", e))?;
    if resp.status == 401 {
        return Err("Calendar 401: access_token invalid or expired. Call refresh_oauth_token to force a refresh.".to_string());
    }
    if resp.status >= 400 {
        let body = String::from_utf8(resp.body).unwrap_or_default();
        return Err(format!(
            "Calendar HTTP {}: {}",
            resp.status,
            &body[..body.len().min(200)]
        ));
    }
    let body_str = String::from_utf8(resp.body).map_err(|_| "calendar invalid utf8")?;
    let list: ListResp = serde_json::from_str(&body_str).map_err(|e| format!("calendar parse: {}", e))?;
    let items = list.items.unwrap_or_default();

    let mut out = Vec::with_capacity(items.len());
    for ev in items.into_iter().take(max_results) {
        let (start_val, is_all_day) = match &ev.start {
            Some(t) => {
                if let Some(dt) = t.date_time.clone() {
                    (dt, false)
                } else if let Some(d) = t.date.clone() {
                    (d, true)
                } else {
                    (String::new(), false)
                }
            }
            None => (String::new(), false),
        };
        let end_val = match &ev.end {
            Some(t) => t.date_time.clone().or_else(|| t.date.clone()).unwrap_or_default(),
            None => String::new(),
        };
        let mut attendees: Vec<serde_json::Value> = Vec::new();
        if let Some(a) = ev.attendees {
            for x in a.into_iter().take(12) {
                attendees.push(serde_json::json!({
                    "email": x.email.unwrap_or_default(),
                    "response_status": x.response_status.unwrap_or_default(),
                }));
            }
        }
        out.push(serde_json::json!({
            "id": ev.id.unwrap_or_default(),
            "summary": ev.summary.unwrap_or_default(),
            "description": ev.description.unwrap_or_default(),
            "location": ev.location.unwrap_or_default(),
            "start": start_val,
            "end": end_val,
            "all_day": is_all_day,
            "hangout_link": ev.hangout_link.unwrap_or_default(),
            "attendees": attendees,
        }));
    }

    let result = serde_json::json!({
        "count": out.len(),
        "events": out,
        "window_hours": hours_ahead,
    });
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        let c = b as char;
        if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
            out.push(c);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}
