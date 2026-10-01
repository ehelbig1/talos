// Canonical catalog module: list Google Calendar events in a time window.
// Uses vault:// header resolution for auth — no direct secrets::get_secret calls.
//
// Each event carries what a reader needs to plan around it, not only to
// display it: whether it holds the time (`busy`), what kind of entry it is
// (`event_type`), the owner's own answer (`response`), and the invitation's
// id (`uid`), which is the same on every calendar the invitation sits on.

use chrono::{Duration, Utc};
use serde::Deserialize;
use talos_sdk_macros::talos_module;

/// Most events returned in one run.
const HARD_CAP: usize = 250;
/// Largest window, in hours (14 days).
const MAX_HOURS: u64 = 336;
/// Events asked for per request, and the most requests one run makes.
const PAGE_SIZE: usize = 250;
const MAX_PAGES: usize = 3;
/// Characters of a provider error body quoted in an error.
const ERROR_BODY_CHARS: usize = 200;
/// Only what this module reads: a full event carries conference data,
/// reminders and extended properties that would be parsed and thrown away.
const FIELDS: &str = "timeZone,nextPageToken,items(id,iCalUID,status,summary,description,location,hangoutLink,transparency,eventType,recurringEventId,start,end,organizer(self),attendees(email,self,responseStatus,resource))";

#[derive(Deserialize, Default)]
struct ListResp {
    #[serde(default)]
    items: Vec<Event>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
    #[serde(rename = "timeZone", default)]
    time_zone: String,
}

#[derive(Deserialize, Default)]
struct Event {
    id: Option<String>,
    #[serde(rename = "iCalUID")]
    ical_uid: Option<String>,
    status: Option<String>,
    summary: Option<String>,
    description: Option<String>,
    location: Option<String>,
    start: Option<EventTime>,
    end: Option<EventTime>,
    #[serde(rename = "hangoutLink")]
    hangout_link: Option<String>,
    transparency: Option<String>,
    #[serde(rename = "eventType")]
    event_type: Option<String>,
    #[serde(rename = "recurringEventId")]
    recurring_event_id: Option<String>,
    organizer: Option<Organizer>,
    attendees: Option<Vec<Attendee>>,
}

#[derive(Deserialize)]
struct EventTime {
    #[serde(rename = "dateTime")]
    date_time: Option<String>,
    date: Option<String>,
}

#[derive(Deserialize)]
struct Organizer {
    #[serde(rename = "self", default)]
    is_self: bool,
}

#[derive(Deserialize)]
struct Attendee {
    email: Option<String>,
    #[serde(rename = "responseStatus")]
    response_status: Option<String>,
    #[serde(rename = "self", default)]
    is_self: bool,
    #[serde(default)]
    resource: bool,
}

/// A valid IANA zone name is letters, digits, `/`, `_`, `+`, `-`. Anything
/// else is refused rather than sent on in a URL.
fn valid_zone(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 64
        && zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'+' | b'-'))
}

/// The first `max` characters of `s`, cut on a character boundary.
fn clip_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn page_url(
    calendar_id: &str,
    time_min: &str,
    time_max: &str,
    page_size: usize,
    time_zone: Option<&str>,
    page_token: Option<&str>,
) -> String {
    let mut url = format!(
        "https://www.googleapis.com/calendar/v3/calendars/{}/events?timeMin={}&timeMax={}&singleEvents=true&orderBy=startTime&maxResults={}&fields={}",
        pct(calendar_id),
        pct(time_min),
        pct(time_max),
        page_size,
        pct(FIELDS)
    );
    if let Some(zone) = time_zone {
        url.push_str("&timeZone=");
        url.push_str(&pct(zone));
    }
    if let Some(token) = page_token {
        url.push_str("&pageToken=");
        url.push_str(&pct(token));
    }
    url
}

/// One calendar entry as this module reports it; `None` for a cancelled one.
fn event_json(ev: Event) -> Option<serde_json::Value> {
    if ev.status.as_deref() == Some("cancelled") {
        return None;
    }
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
    let all = ev.attendees.unwrap_or_default();
    // The calendar owner's own answer: accepted | declined | tentative |
    // needsAction, or "" for an entry with no guest list (the owner's own).
    let response = all
        .iter()
        .find(|a| a.is_self)
        .and_then(|a| a.response_status.clone())
        .unwrap_or_default();
    // Other people invited: not the owner, not a room.
    let guests = all
        .iter()
        .filter(|a| !a.is_self && !a.resource && a.email.is_some())
        .count();
    let attendees: Vec<serde_json::Value> = all
        .into_iter()
        .take(12)
        .map(|x| {
            serde_json::json!({
                "email": x.email.unwrap_or_default(),
                "response_status": x.response_status.unwrap_or_default(),
            })
        })
        .collect();
    Some(serde_json::json!({
        "id": ev.id.unwrap_or_default(),
        "uid": ev.ical_uid.unwrap_or_default(),
        "summary": ev.summary.unwrap_or_default(),
        "description": ev.description.unwrap_or_default(),
        "location": ev.location.unwrap_or_default(),
        "start": start_val,
        "end": end_val,
        "all_day": is_all_day,
        "busy": ev.transparency.as_deref() != Some("transparent"),
        "event_type": ev.event_type.unwrap_or_else(|| "default".to_string()),
        "response": response,
        "guests": guests,
        "organizer_self": ev.organizer.map(|o| o.is_self).unwrap_or(false),
        "recurring": ev.recurring_event_id.is_some(),
        "hangout_link": ev.hangout_link.unwrap_or_default(),
        "attendees": attendees,
    }))
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
        .clamp(1, HARD_CAP);
    let time_zone = match config["TIME_ZONE"].as_str().map(str::trim).filter(|z| !z.is_empty()) {
        Some(zone) if valid_zone(zone) => Some(zone),
        Some(_) => return Err("TIME_ZONE must be an IANA zone name such as America/New_York".to_string()),
        None => None,
    };

    let now = Utc::now();
    let time_min = now.to_rfc3339();
    let time_max = (now + Duration::hours(hours_ahead as i64)).to_rfc3339();

    let mut out: Vec<serde_json::Value> = Vec::new();
    let mut calendar_zone = String::new();
    let mut page_token: Option<String> = None;
    // True when the calendar holds more events in the window than were returned.
    let mut truncated = false;
    for page in 0..MAX_PAGES {
        let page_size = PAGE_SIZE.min(max_results - out.len()).max(1);
        let req = talos::core::http::Request {
            method: talos::core::http::Method::Get,
            url: page_url(calendar_id, &time_min, &time_max, page_size, time_zone, page_token.as_deref()),
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
            let body = String::from_utf8_lossy(&resp.body);
            return Err(format!("Calendar HTTP {}: {}", resp.status, clip_chars(&body, ERROR_BODY_CHARS)));
        }
        let list: ListResp = serde_json::from_slice(&resp.body).map_err(|e| format!("calendar parse: {}", e))?;
        if page == 0 {
            calendar_zone = list.time_zone;
        }
        for ev in list.items {
            if out.len() >= max_results {
                truncated = true;
                break;
            }
            if let Some(event) = event_json(ev) {
                out.push(event);
            }
        }
        match list.next_page_token {
            Some(_) if out.len() >= max_results => {
                truncated = true;
                break;
            }
            Some(token) if page + 1 < MAX_PAGES => page_token = Some(token),
            Some(_) => {
                truncated = true;
                break;
            }
            None => break,
        }
    }

    let result = serde_json::json!({
        "count": out.len(),
        "events": out,
        "window_hours": hours_ahead,
        "truncated": truncated,
        "time_zone": time_zone.map(str::to_string).unwrap_or(calendar_zone),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event(v: serde_json::Value) -> Event {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn an_invitation_reports_what_a_planner_needs() {
        let e = event_json(event(json!({
            "id": "abc", "iCalUID": "uid-1@google.com", "status": "confirmed", "summary": "Design review",
            "start": {"dateTime": "2026-10-06T10:30:00-04:00"}, "end": {"dateTime": "2026-10-06T11:30:00-04:00"},
            "hangoutLink": "https://meet.example/x", "recurringEventId": "r1", "organizer": {"self": false},
            "attendees": [
                {"email": "me@corp.example", "self": true, "responseStatus": "tentative"},
                {"email": "pat@corp.example", "responseStatus": "accepted"},
                {"email": "room@resource.calendar.google.com", "resource": true, "responseStatus": "accepted"}
            ]
        })))
        .unwrap();
        assert_eq!(e["uid"], "uid-1@google.com");
        assert_eq!(e["busy"], true);
        assert_eq!(e["event_type"], "default");
        assert_eq!(e["response"], "tentative", "the owner's own answer, not a guest's");
        assert_eq!(e["guests"], 1, "the owner and the room are not guests");
        assert_eq!((e["organizer_self"].as_bool(), e["recurring"].as_bool(), e["all_day"].as_bool()), (Some(false), Some(true), Some(false)));
        // The fields the template has always returned are unchanged.
        assert_eq!(e["id"], "abc");
        assert_eq!(e["summary"], "Design review");
        assert_eq!(e["start"], "2026-10-06T10:30:00-04:00");
        assert_eq!(e["hangout_link"], "https://meet.example/x");
        assert_eq!(e["attendees"].as_array().unwrap().len(), 3);
        assert_eq!(e["attendees"][0], json!({"email": "me@corp.example", "response_status": "tentative"}));
    }

    #[test]
    fn free_all_day_own_and_special_entries_are_told_apart() {
        let free = event_json(event(json!({"summary": "Conference", "transparency": "transparent", "start": {"date": "2026-10-07"}, "end": {"date": "2026-10-09"}}))).unwrap();
        assert_eq!((free["busy"].as_bool(), free["all_day"].as_bool(), free["start"].as_str(), free["end"].as_str()), (Some(false), Some(true), Some("2026-10-07"), Some("2026-10-09")));
        let own = event_json(event(json!({"summary": "Dentist", "organizer": {"self": true}, "start": {"dateTime": "2026-10-06T10:00:00-04:00"}}))).unwrap();
        assert_eq!((own["response"].as_str(), own["guests"].as_u64(), own["organizer_self"].as_bool(), own["busy"].as_bool()), (Some(""), Some(0), Some(true), Some(true)));
        let focus = event_json(event(json!({"summary": "Focus", "eventType": "focusTime", "start": {"dateTime": "2026-10-06T13:00:00-04:00"}}))).unwrap();
        assert_eq!(focus["event_type"], "focusTime");
        assert!(event_json(event(json!({"summary": "Gone", "status": "cancelled"}))).is_none());
        // An entry with nothing set still renders, as before.
        let bare = event_json(event(json!({}))).unwrap();
        assert_eq!((bare["start"].as_str(), bare["all_day"].as_bool(), bare["uid"].as_str()), (Some(""), Some(false), Some("")));
    }

    #[test]
    fn the_request_names_only_what_is_read_and_encodes_its_parts() {
        let url = page_url("primary", "2026-10-04T22:00:00+00:00", "2026-10-11T22:00:00+00:00", 250, Some("America/New_York"), Some("tok/en+1"));
        assert!(url.starts_with("https://www.googleapis.com/calendar/v3/calendars/primary/events?"));
        assert!(url.contains("timeMin=2026-10-04T22%3A00%3A00%2B00%3A00"));
        assert!(url.contains("singleEvents=true") && url.contains("orderBy=startTime") && url.contains("maxResults=250"));
        assert!(url.contains("&timeZone=America%2FNew_York") && url.contains("&pageToken=tok%2Fen%2B1"));
        let fields = url.split("fields=").nth(1).unwrap().split('&').next().unwrap();
        assert!(!fields.contains('(') && !fields.contains(','), "the fields list is percent-encoded");
        let bare = page_url("team@example.com", "a", "b", 20, None, None);
        assert!(bare.contains("/calendars/team%40example.com/events?") && !bare.contains("&timeZone=") && !bare.contains("&pageToken="));
        // Every field the event struct reads is asked for.
        for name in ["id", "iCalUID", "status", "summary", "description", "location", "hangoutLink", "transparency", "eventType", "recurringEventId", "start", "end", "organizer(self)", "attendees(email,self,responseStatus,resource)", "nextPageToken", "timeZone"] {
            assert!(FIELDS.contains(name), "{name}");
        }
    }

    #[test]
    fn a_zone_is_checked_before_it_reaches_a_url() {
        for ok in ["UTC", "America/New_York", "Etc/GMT+5", "America/Argentina/Buenos_Aires"] {
            assert!(valid_zone(ok), "{ok}");
        }
        for bad in ["", "America/New York", "UTC&maxResults=9999", "a?b", "Europe/Paris\n"] {
            assert!(!valid_zone(bad), "{bad:?}");
        }
        let err = run(json!({"config": {"AUTH_HEADER": "Bearer x", "TIME_ZONE": "bad zone"}}).to_string()).unwrap_err();
        assert!(err.starts_with("TIME_ZONE must be"));
        assert!(run(json!({"config": {}}).to_string()).unwrap_err().starts_with("Missing AUTH_HEADER"));
    }

    #[test]
    fn an_error_body_is_quoted_on_a_character_boundary() {
        // 199 ASCII characters then a two-byte one straddling byte 200: slicing
        // the bytes at 200 would panic.
        let body = format!("{}é and more", "x".repeat(199));
        assert_eq!(clip_chars(&body, 200), format!("{}é", "x".repeat(199)));
        assert_eq!(clip_chars("short", 200), "short");
        assert_eq!(clip_chars("", 200), "");
        assert_eq!(clip_chars("ééé", 2), "éé");
    }
}
