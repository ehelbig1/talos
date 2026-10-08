// Canonical catalog module: list Outlook (Microsoft 365) calendar events in a
// time window, through Microsoft Graph's calendarView.
// Uses vault:// header resolution for auth — no direct secrets::get_secret calls.
//
// The output mirrors google-calendar-list-events, so a workflow can swap one
// calendar for the other: the same top-level keys (`count`, `events`,
// `window_hours`, `truncated`, `time_zone`) and, per event, the same keys with
// Google's vocabulary — `busy`, `response` (accepted | declined | tentative |
// needsAction | ""), `guests`, `uid`, `recurring`, `all_day`, `event_type`,
// `organizer_self`, `hangout_link` (the online meeting's join URL here) and
// `attendees` [{email, response_status}]. Times are RFC 3339 with the zone's
// UTC offset (`2026-10-06T10:30:00-04:00`); an all-day entry's are dates.
// A cancelled meeting still on the calendar is left out, as Google's are.
//
// Graph is asked to convert times into TIME_ZONE (`Prefer: outlook.timezone`)
// and answers with a wall-clock time and no offset; the offset is attached
// here from the host's time-zone database. Without TIME_ZONE Graph answers in
// UTC, which is what `time_zone` then says.
//
// Paging follows `@odata.nextLink`, and only a link on
// https://graph.microsoft.com/v1.0/ — the bearer token is never sent anywhere
// else, whatever a response says.

use chrono::{DateTime, Datelike, Duration, NaiveDate, NaiveDateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use talos::core::datetime;
use talos_sdk_macros::talos_module;

const API: &str = "https://graph.microsoft.com/v1.0";
/// The only prefix a followed `@odata.nextLink` may have.
const NEXT_LINK_PREFIX: &str = "https://graph.microsoft.com/v1.0/";
/// Longest `@odata.nextLink` followed.
const MAX_NEXT_LINK_CHARS: usize = 4096;
/// Most events returned in one run.
const HARD_CAP: usize = 250;
/// Largest window, in hours (14 days).
const MAX_HOURS: u64 = 336;
/// Events asked for per request (`$top`), and the most requests one run makes:
/// enough to reach HARD_CAP with a page to spare for cancelled entries.
const PAGE_SIZE: usize = 50;
const MAX_PAGES: usize = 6;
/// Characters of a provider error body quoted in an error.
const ERROR_BODY_CHARS: usize = 200;
/// Attendees listed per event (all of them are counted in `guests`).
const MAX_ATTENDEES: usize = 12;
/// Longest calendar id accepted.
const MAX_CALENDAR_ID_CHARS: usize = 512;
/// Only what this module reads.
const SELECT: &str = "id,subject,start,end,location,attendees,organizer,isAllDay,showAs,responseStatus,iCalUId,seriesMasterId,isCancelled,isOrganizer,webLink,onlineMeeting";

// ------------------------------------------------------------ wire shapes

#[derive(Deserialize, Default)]
struct Page {
    #[serde(default)]
    value: Vec<Event>,
    #[serde(rename = "@odata.nextLink")]
    next_link: Option<String>,
}

#[derive(Deserialize, Default)]
struct Event {
    id: Option<String>,
    subject: Option<String>,
    start: Option<GraphTime>,
    end: Option<GraphTime>,
    location: Option<Location>,
    attendees: Option<Vec<Attendee>>,
    organizer: Option<Recipient>,
    #[serde(rename = "isAllDay")]
    is_all_day: Option<bool>,
    #[serde(rename = "showAs")]
    show_as: Option<String>,
    #[serde(rename = "responseStatus")]
    response_status: Option<Status>,
    #[serde(rename = "iCalUId")]
    ical_uid: Option<String>,
    #[serde(rename = "seriesMasterId")]
    series_master_id: Option<String>,
    #[serde(rename = "isCancelled")]
    is_cancelled: Option<bool>,
    #[serde(rename = "isOrganizer")]
    is_organizer: Option<bool>,
    #[serde(rename = "webLink")]
    web_link: Option<String>,
    #[serde(rename = "onlineMeeting")]
    online_meeting: Option<OnlineMeeting>,
}

#[derive(Deserialize)]
struct GraphTime {
    #[serde(rename = "dateTime")]
    date_time: Option<String>,
    #[serde(rename = "timeZone")]
    time_zone: Option<String>,
}

#[derive(Deserialize)]
struct Location {
    #[serde(rename = "displayName")]
    display_name: Option<String>,
}

#[derive(Deserialize)]
struct Recipient {
    #[serde(rename = "emailAddress")]
    email_address: Option<EmailAddress>,
}

#[derive(Deserialize)]
struct EmailAddress {
    address: Option<String>,
}

#[derive(Deserialize)]
struct Attendee {
    #[serde(rename = "emailAddress")]
    email_address: Option<EmailAddress>,
    status: Option<Status>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[derive(Deserialize)]
struct Status {
    response: Option<String>,
}

#[derive(Deserialize)]
struct OnlineMeeting {
    #[serde(rename = "joinUrl")]
    join_url: Option<String>,
}

// ----------------------------------------------------------------- helpers

/// A valid IANA zone name is letters, digits, `/`, `_`, `+`, `-`. Anything
/// else is refused rather than sent on in a header: a quote or a line break
/// could otherwise end the `Prefer` value or add a header.
fn valid_zone(zone: &str) -> bool {
    !zone.is_empty()
        && zone.len() <= 64
        && zone
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'+' | b'-'))
}

/// A Graph calendar id (base64-like: letters, digits, `-`, `_`, `=`, `+`, `/`).
/// It goes into the URL path, so anything else — `?`, `#`, `%`, `.`, a
/// space — is refused, and what is accepted is percent-encoded.
fn valid_calendar_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_CALENDAR_ID_CHARS
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'=' | b'+' | b'/'))
}

/// The first `max` characters of `s`, cut on a character boundary.
fn clip_chars(s: &str, max: usize) -> &str {
    match s.char_indices().nth(max) {
        Some((i, _)) => &s[..i],
        None => s,
    }
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A whole number from config: a JSON integer or a string holding one.
/// Absent (or null) is `default`; anything else outside `lo..=hi` is refused.
fn int_config(config: &serde_json::Value, key: &str, default: u64, lo: u64, hi: u64) -> Result<u64, String> {
    let v = &config[key];
    let n = if v.is_null() {
        Some(default)
    } else if let Some(n) = v.as_u64() {
        Some(n)
    } else {
        v.as_str().and_then(|s| s.trim().parse::<u64>().ok())
    };
    match n {
        Some(n) if (lo..=hi).contains(&n) => Ok(n),
        _ => Err(format!("{key} must be a whole number from {lo} to {hi}")),
    }
}

/// The first calendarView request. Later pages follow `@odata.nextLink`.
fn first_url(calendar_id: Option<&str>, start: &str, end: &str, top: usize) -> String {
    let base = match calendar_id {
        None => format!("{API}/me/calendarView"),
        Some(id) => format!("{API}/me/calendars/{}/calendarView", pct(id)),
    };
    format!(
        "{base}?startDateTime={}&endDateTime={}&$top={top}&$select={SELECT}&$orderby=start/dateTime",
        pct(start),
        pct(end)
    )
}

/// A next-page link that may be followed: on Graph v1.0, printable ASCII
/// with no space, and not absurdly long. `None` refuses it.
fn followable(link: &str) -> Option<&str> {
    (link.starts_with(NEXT_LINK_PREFIX)
        && link.len() <= MAX_NEXT_LINK_CHARS
        && link.bytes().all(|b| b.is_ascii_graphic()))
    .then_some(link)
}

/// Seconds `zone` is ahead of UTC at the instant `unix`.
fn offset_at(zone: &str, unix: i64) -> Option<i64> {
    let at = u64::try_from(unix).ok()?;
    datetime::local_offset_seconds(zone, at).ok().map(i64::from)
}

/// The offset in force in `zone` at a wall-clock time there. Two readings
/// settle it outside a daylight-saving change; in the repeated hour the
/// earlier reading wins, in the skipped hour the offset before the change.
fn offset_for_local(zone: &str, local: NaiveDateTime) -> Option<i64> {
    let naive = local.and_utc().timestamp();
    let first = offset_at(zone, naive)?;
    let second = offset_at(zone, naive - first)?;
    if second == first || offset_at(zone, naive - second) == Some(second) {
        Some(second)
    } else {
        Some(first)
    }
}

fn with_offset(local: NaiveDateTime, offset: i64) -> String {
    let sign = if offset < 0 { '-' } else { '+' };
    let abs = offset.unsigned_abs();
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}{sign}{:02}:{:02}",
        local.year(),
        local.month(),
        local.day(),
        local.hour(),
        local.minute(),
        local.second(),
        abs / 3600,
        (abs % 3600) / 60
    )
}

/// Graph's `2026-10-06T10:30:00.0000000`: a wall-clock time, no offset. Read
/// by position (a chrono format string costs more fuel per call than the
/// rest of an event); a fraction of a second is dropped.
fn graph_wall_clock(raw: &str) -> Option<NaiveDateTime> {
    let b = raw.as_bytes();
    if b.len() < 19 || b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if b.len() > 19 && (b[19] != b'.' || !b[20..].iter().all(u8::is_ascii_digit)) {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<u32> {
        let d = &b[r];
        d.iter().all(u8::is_ascii_digit).then(|| d.iter().fold(0u32, |n, c| n * 10 + u32::from(c - b'0')))
    };
    let date = NaiveDate::from_ymd_opt(i32::try_from(num(0..4)?).ok()?, num(5..7)?, num(8..10)?)?;
    date.and_hms_opt(num(11..13)?, num(14..16)?, num(17..19)?)
}

/// One of Graph's times as this module reports it. `zone` is the zone the
/// output is in (TIME_ZONE, or UTC). Graph labels each time with its zone:
/// the asked-for zone (the usual case), or UTC, which is converted here. A
/// time in any other zone, or one that cannot be read, is passed on as Graph
/// wrote it rather than given an offset that might be wrong.
fn render_time(t: Option<&GraphTime>, zone: &str, all_day: bool) -> String {
    let Some(t) = t else { return String::new() };
    let raw = t.date_time.as_deref().unwrap_or("").trim();
    let Some(naive) = graph_wall_clock(raw) else {
        return raw.to_string();
    };
    if all_day {
        // An all-day entry is a date (its end the day after, as Google's).
        return format!("{:04}-{:02}-{:02}", naive.year(), naive.month(), naive.day());
    }
    let label = t.time_zone.as_deref().unwrap_or("UTC");
    if label == zone {
        if zone == "UTC" {
            return with_offset(naive, 0);
        }
        return match offset_for_local(zone, naive) {
            Some(off) => with_offset(naive, off),
            None => raw.to_string(),
        };
    }
    if label == "UTC" {
        let utc = naive.and_utc().timestamp();
        return match offset_at(zone, utc) {
            Some(off) => with_offset(naive + Duration::seconds(off), off),
            None => raw.to_string(),
        };
    }
    raw.to_string()
}

/// Graph's answer in Google's vocabulary. For the calendar owner (`owner`)
/// a reply of `none` is "" — an entry with no invitation, as Google reports
/// an entry with no guest list — and for a guest it is `needsAction`.
fn response_word(graph: &str, owner: bool) -> String {
    match graph {
        "accepted" | "organizer" => "accepted".to_string(),
        "declined" => "declined".to_string(),
        "tentativelyAccepted" => "tentative".to_string(),
        "notResponded" => "needsAction".to_string(),
        "none" | "" if owner => String::new(),
        "none" | "" => "needsAction".to_string(),
        other => clip_chars(other, 40).to_string(),
    }
}

/// An https link, or "" (a link a renderer might follow is never another scheme).
fn https_or_empty(link: Option<String>) -> String {
    link.filter(|l| l.starts_with("https://")).unwrap_or_default()
}

/// One calendar entry as this module reports it. Typed rather than built as a
/// `serde_json::Value`: building and serialising a map per event cost more
/// fuel than parsing Graph's reply (measured 2026-10-08 on the recording).
#[derive(Serialize)]
struct OutEvent {
    id: String,
    uid: String,
    summary: String,
    location: String,
    start: String,
    end: String,
    all_day: bool,
    /// Holds the time unless it is marked free (Google: not "transparent").
    busy: bool,
    show_as: String,
    event_type: &'static str,
    response: String,
    guests: usize,
    organizer_self: bool,
    recurring: bool,
    hangout_link: String,
    web_link: String,
    attendees: Vec<OutAttendee>,
}

#[derive(Serialize)]
struct OutAttendee {
    email: String,
    response_status: String,
}

#[derive(Serialize)]
struct Output<'a> {
    count: usize,
    events: Vec<OutEvent>,
    window_hours: u64,
    truncated: bool,
    time_zone: &'a str,
}

/// One calendar entry as this module reports it; `None` for a cancelled one.
fn event_json(ev: Event, zone: &str) -> Option<OutEvent> {
    if ev.is_cancelled == Some(true) {
        return None;
    }
    let all_day = ev.is_all_day == Some(true);
    let own_reply = ev.response_status.and_then(|s| s.response).unwrap_or_default();
    // isOrganizer when Graph sends it; else a reply of "organizer" says so.
    let organizer_self = ev.is_organizer.unwrap_or(own_reply == "organizer");
    let organizer_address = ev
        .organizer
        .and_then(|o| o.email_address)
        .and_then(|e| e.address)
        .map(|a| a.trim().to_ascii_lowercase())
        .unwrap_or_default();
    let all = ev.attendees.unwrap_or_default();
    // The owner's own answer: Google's "" for their own entry with nobody
    // invited, "accepted" for one they organise with guests.
    let response = if own_reply == "organizer" && all.is_empty() {
        String::new()
    } else {
        response_word(&own_reply, true)
    };
    // Other people invited, rooms and equipment not counted. Graph lists the
    // invitees but not the organizer: when the owner organised, everyone
    // listed is someone else; when they were invited, the owner is among the
    // listed and the organizer is not, so the organizer takes their place.
    let mut people: Vec<String> = all
        .iter()
        .filter(|a| a.kind.as_deref() != Some("resource"))
        .filter_map(|a| a.email_address.as_ref()?.address.as_deref())
        .map(|a| a.trim().to_ascii_lowercase())
        .filter(|a| !a.is_empty())
        .collect();
    people.sort();
    people.dedup();
    let guests = if organizer_self {
        people.iter().filter(|a| **a != organizer_address).count()
    } else {
        if !organizer_address.is_empty() && !people.contains(&organizer_address) {
            people.push(organizer_address);
        }
        people.len().saturating_sub(1)
    };
    let attendees = all
        .into_iter()
        .take(MAX_ATTENDEES)
        .map(|a| OutAttendee {
            email: a.email_address.and_then(|e| e.address).unwrap_or_default(),
            response_status: response_word(a.status.and_then(|s| s.response).as_deref().unwrap_or(""), false),
        })
        .collect();
    let show_as = ev.show_as.unwrap_or_default();
    Some(OutEvent {
        id: ev.id.unwrap_or_default(),
        uid: ev.ical_uid.unwrap_or_default(),
        summary: ev.subject.unwrap_or_default(),
        location: ev.location.and_then(|l| l.display_name).unwrap_or_default(),
        start: render_time(ev.start.as_ref(), zone, all_day),
        end: render_time(ev.end.as_ref(), zone, all_day),
        all_day,
        busy: show_as != "free",
        event_type: if show_as == "oof" { "outOfOffice" } else { "default" },
        show_as,
        response,
        guests,
        organizer_self,
        recurring: ev.series_master_id.is_some_and(|s| !s.is_empty()),
        hangout_link: https_or_empty(ev.online_meeting.and_then(|m| m.join_url)),
        web_link: https_or_empty(ev.web_link),
        attendees,
    })
}

// ------------------------------------------------------------------- run

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let auth = config["AUTH_HEADER"]
        .as_str()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .ok_or("Missing AUTH_HEADER config (expected 'Bearer vault://oauth/microsoft_365/{user_id}/{account_id}/access_token')")?;
    let calendar_id = match config["CALENDAR_ID"].as_str().map(str::trim) {
        None | Some("") => None,
        // Google's name for the default calendar means the same here.
        Some(id) if id.eq_ignore_ascii_case("primary") => None,
        Some(id) if valid_calendar_id(id) => Some(id),
        Some(_) => {
            return Err("CALENDAR_ID must be a Graph calendar id (letters, digits, '-', '_', '=', '+', '/'), or empty for the default calendar".to_string())
        }
    };
    if !config["CALENDAR_ID"].is_null() && !config["CALENDAR_ID"].is_string() {
        return Err("CALENDAR_ID must be a string".to_string());
    }
    let hours_ahead = int_config(config, "HOURS_AHEAD", 24, 1, MAX_HOURS)?;
    let max_results = int_config(config, "MAX_RESULTS", 20, 1, HARD_CAP as u64)? as usize;
    let time_zone = match config["TIME_ZONE"].as_str().map(str::trim).filter(|z| !z.is_empty()) {
        Some(zone) if valid_zone(zone) => Some(zone),
        Some(_) => return Err("TIME_ZONE must be an IANA zone name such as America/New_York".to_string()),
        None => None,
    };

    let now_unix = datetime::now_unix();
    let now = i64::try_from(now_unix)
        .ok()
        .and_then(|s| DateTime::<Utc>::from_timestamp(s, 0))
        .ok_or("the clock cannot be read")?;
    if let Some(zone) = time_zone {
        // Checked against the host's zone database before anything is sent:
        // a name Graph does not know would silently come back as UTC.
        datetime::local_offset_seconds(zone, now_unix).map_err(|_| {
            format!("TIME_ZONE '{zone}' is not a time zone the host knows; use an IANA name such as America/New_York (case-sensitive)")
        })?;
    }
    let zone = time_zone.unwrap_or("UTC");
    let start = now.format("%Y-%m-%dT%H:%M:%SZ").to_string();
    let end = (now + Duration::hours(hours_ahead as i64)).format("%Y-%m-%dT%H:%M:%SZ").to_string();

    let mut headers = vec![
        ("Authorization".to_string(), auth.to_string()),
        ("Accept".to_string(), "application/json".to_string()),
    ];
    if let Some(zone) = time_zone {
        headers.push(("Prefer".to_string(), format!("outlook.timezone=\"{zone}\"")));
    }

    let mut out: Vec<OutEvent> = Vec::new();
    let mut url = first_url(calendar_id, &start, &end, PAGE_SIZE.min(max_results));
    // True when the calendar holds more events in the window than were returned.
    let mut truncated = false;
    for page in 0..MAX_PAGES {
        let req = talos::core::http::Request {
            method: talos::core::http::Method::Get,
            url: url.clone(),
            headers: headers.clone(),
            body: vec![],
            timeout_ms: Some(10000),
        };
        let resp = talos::core::http::fetch(&req).map_err(|e| format!("Graph fetch: {:?}", e))?;
        if resp.status == 401 {
            return Err("Microsoft 365 401: access_token invalid or expired. Call refresh_oauth_token to force a refresh.".to_string());
        }
        if !(200..300).contains(&resp.status) {
            let body = String::from_utf8_lossy(&resp.body);
            return Err(format!("Graph HTTP {}: {}", resp.status, clip_chars(&body, ERROR_BODY_CHARS)));
        }
        let list: Page = serde_json::from_slice(&resp.body).map_err(|e| format!("Graph parse: {}", e))?;
        for ev in list.value {
            if out.len() >= max_results {
                truncated = true;
                break;
            }
            if let Some(event) = event_json(ev, zone) {
                out.push(event);
            }
        }
        match list.next_link.filter(|l| !l.is_empty()) {
            Some(_) if out.len() >= max_results => {
                truncated = true;
                break;
            }
            Some(link) if page + 1 < MAX_PAGES => match followable(&link) {
                Some(next) => url = next.to_string(),
                None => {
                    return Err(format!(
                        "Graph returned an @odata.nextLink outside {NEXT_LINK_PREFIX}; refusing to send the token there"
                    ))
                }
            },
            Some(_) => {
                truncated = true;
                break;
            }
            None => break,
        }
    }

    let result = Output { count: out.len(), events: out, window_hours: hours_ahead, truncated, time_zone: zone };
    serde_json::to_string(&result).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use talos_module_testkit::host;
    use talos_module_testkit::host::clock::set_unix;
    use talos_module_testkit::host::http::respond_with;

    /// 2026-10-06T14:00:00Z.
    const NOW: u64 = 1_791_295_200;
    const AUTH: &str = "Bearer vault://oauth/microsoft_365/made-up-user/made-up-account/access_token";

    fn read(config: Value) -> Result<Value, String> {
        run(json!({ "config": config }).to_string()).map(|s| serde_json::from_str(&s).unwrap())
    }
    fn page(events: Vec<Value>, next: Option<&str>) -> String {
        let mut p = json!({ "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users('made-up')/calendarView", "value": events });
        if let Some(n) = next {
            p["@odata.nextLink"] = json!(n);
        }
        p.to_string()
    }
    /// A made-up meeting at `start`..`end` (wall-clock, in `tz`).
    fn meeting(n: usize, start: &str, end: &str, tz: &str) -> Value {
        json!({
            "id": format!("AAMkMadeUp{n}="), "subject": format!("Meeting {n}"),
            "start": {"dateTime": format!("{start}.0000000"), "timeZone": tz},
            "end": {"dateTime": format!("{end}.0000000"), "timeZone": tz},
            "location": {"displayName": "Room 4"}, "isAllDay": false, "showAs": "busy",
            "responseStatus": {"response": "accepted", "time": "2026-10-01T09:00:00Z"},
            "iCalUId": format!("040000008200E00074C5B7101A82E0080000000000{n:04}"),
            "seriesMasterId": null, "isCancelled": false, "isOrganizer": false,
            "webLink": "https://outlook.office365.com/owa/?itemid=AAMkMadeUp&exvsurl=1&path=/calendar/item",
            "onlineMeeting": null,
            "organizer": {"emailAddress": {"name": "Pat Example", "address": "pat@example.com"}},
            "attendees": [
                {"type": "required", "status": {"response": "accepted"}, "emailAddress": {"name": "Me", "address": "me@example.com"}}
            ]
        })
    }
    fn event(v: Value) -> Event {
        serde_json::from_value(v).unwrap()
    }
    /// The module's own `event_json`, read back as JSON.
    fn event_json(ev: Event, zone: &str) -> Option<Value> {
        super::event_json(ev, zone).map(|e| serde_json::to_value(e).unwrap())
    }

    #[test]
    fn the_first_request_is_built_as_expected() {
        set_unix(NOW);
        respond_with(|_| Ok(host::http::response(200, page(vec![], None))));
        let v = read(json!({"AUTH_HEADER": AUTH, "HOURS_AHEAD": 48, "MAX_RESULTS": 20, "TIME_ZONE": "America/New_York"})).unwrap();
        assert_eq!((v["count"].as_u64(), v["truncated"].as_bool(), v["window_hours"].as_u64()), (Some(0), Some(false), Some(48)));
        assert_eq!(v["time_zone"], "America/New_York");
        let sent = host::http::requests();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].url,
            format!("https://graph.microsoft.com/v1.0/me/calendarView?startDateTime=2026-10-06T14%3A00%3A00Z&endDateTime=2026-10-08T14%3A00%3A00Z&$top=20&$select={SELECT}&$orderby=start/dateTime")
        );
        assert_eq!(sent[0].method, talos::core::http::Method::Get);
        let header = |name: &str| sent[0].headers.iter().find(|(k, _)| k == name).map(|(_, v)| v.clone());
        assert_eq!(header("Authorization").as_deref(), Some(AUTH));
        assert_eq!(header("Prefer").as_deref(), Some("outlook.timezone=\"America/New_York\""));
        // Every field the event struct reads is asked for.
        for name in ["id", "subject", "start", "end", "location", "attendees", "organizer", "isAllDay", "showAs", "responseStatus", "iCalUId", "seriesMasterId", "isCancelled", "isOrganizer", "webLink", "onlineMeeting"] {
            assert!(SELECT.split(',').any(|f| f == name), "{name}");
        }
    }

    #[test]
    fn defaults_a_named_calendar_and_no_zone() {
        set_unix(NOW);
        respond_with(|_| Ok(host::http::response(200, page(vec![], None))));
        let v = read(json!({"AUTH_HEADER": AUTH})).unwrap();
        assert_eq!(v["time_zone"], "UTC", "without TIME_ZONE Graph answers in UTC");
        assert_eq!(v["window_hours"], 24);
        let sent = host::http::requests();
        assert!(sent[0].url.contains("&endDateTime=2026-10-07T14%3A00%3A00Z&$top=20&"), "{}", sent[0].url);
        assert!(!sent[0].headers.iter().any(|(k, _)| k == "Prefer"));
        // A calendar id goes into the path, percent-encoded; "primary" is the default calendar.
        respond_with(|_| Ok(host::http::response(200, page(vec![], None))));
        read(json!({"AUTH_HEADER": AUTH, "CALENDAR_ID": "AAMkAD+made/up==", "MAX_RESULTS": 250})).unwrap();
        respond_with(|_| Ok(host::http::response(200, page(vec![], None))));
        read(json!({"AUTH_HEADER": AUTH, "CALENDAR_ID": "primary"})).unwrap();
        let sent = host::http::requests();
        assert!(sent[1].url.starts_with("https://graph.microsoft.com/v1.0/me/calendars/AAMkAD%2Bmade%2Fup%3D%3D/calendarView?"), "{}", sent[1].url);
        assert!(sent[1].url.contains("&$top=50&"), "a page is at most 50");
        assert!(sent[2].url.starts_with("https://graph.microsoft.com/v1.0/me/calendarView?"));
    }

    #[test]
    fn config_is_validated_before_anything_is_sent() {
        set_unix(NOW);
        respond_with(|_| Ok(host::http::response(200, page(vec![], None))));
        assert!(read(json!({})).unwrap_err().starts_with("Missing AUTH_HEADER"));
        assert!(read(json!({"AUTH_HEADER": "  "})).unwrap_err().starts_with("Missing AUTH_HEADER"));
        for (key, bad) in [("HOURS_AHEAD", json!(0)), ("HOURS_AHEAD", json!(337)), ("HOURS_AHEAD", json!("soon")), ("HOURS_AHEAD", json!(-1)),
                           ("MAX_RESULTS", json!(0)), ("MAX_RESULTS", json!(251)), ("MAX_RESULTS", json!(2.5))] {
            let mut c = json!({"AUTH_HEADER": AUTH});
            c[key] = bad.clone();
            let err = read(c).unwrap_err();
            assert!(err.starts_with(&format!("{key} must be a whole number")), "{key}={bad}: {err}");
        }
        // A number written as a string is read.
        assert_eq!(read(json!({"AUTH_HEADER": AUTH, "HOURS_AHEAD": "336"})).unwrap()["window_hours"], 336);
        for bad in ["America/New York", "UTC\"; x=\"y", "Europe/Paris\r\nX-Evil: 1", "a?b", "Europe/P\u{0}aris"] {
            let err = read(json!({"AUTH_HEADER": AUTH, "TIME_ZONE": bad})).unwrap_err();
            assert!(err.starts_with("TIME_ZONE must be"), "{bad:?}: {err}");
        }
        assert!(read(json!({"AUTH_HEADER": AUTH, "TIME_ZONE": "Mars/Olympus_Mons"})).unwrap_err().contains("not a time zone the host knows"));
        for bad in ["../me", "abc?x=1", "id#frag", "a b", "a%2Fb", "made.up", &"A".repeat(513)] {
            let err = read(json!({"AUTH_HEADER": AUTH, "CALENDAR_ID": bad})).unwrap_err();
            assert!(err.starts_with("CALENDAR_ID must be"), "{bad:?}: {err}");
        }
        assert!(read(json!({"AUTH_HEADER": AUTH, "CALENDAR_ID": 7})).is_err());
        // Surrounding whitespace is trimmed off, never sent in the header.
        assert_eq!(read(json!({"AUTH_HEADER": AUTH, "TIME_ZONE": "Europe/Paris\n"})).unwrap()["time_zone"], "Europe/Paris");
        let sent = host::http::requests();
        assert!(sent[1].headers.iter().any(|(k, v)| k == "Prefer" && v == "outlook.timezone=\"Europe/Paris\""));
        // Only the two accepted configs above made a request.
        assert_eq!(sent.len(), 2);
    }

    #[test]
    fn a_refused_token_says_what_to_do() {
        set_unix(NOW);
        respond_with(|_| Ok(host::http::response(401, r#"{"error":{"code":"InvalidAuthenticationToken"}}"#)));
        let err = read(json!({"AUTH_HEADER": AUTH})).unwrap_err();
        assert_eq!(err, "Microsoft 365 401: access_token invalid or expired. Call refresh_oauth_token to force a refresh.");
    }

    #[test]
    fn graph_errors_are_quoted_and_clipped_on_a_character_boundary() {
        set_unix(NOW);
        let body = r#"{"error":{"code":"MailboxNotEnabledForRESTAPI","message":"The mailbox is either inactive, soft-deleted, or is hosted on-premise."}}"#;
        respond_with(move |_| Ok(host::http::response(404, body)));
        let err = read(json!({"AUTH_HEADER": AUTH})).unwrap_err();
        assert_eq!(err, format!("Graph HTTP 404: {body}"));
        // 199 ASCII characters then a two-byte one straddling byte 200: slicing
        // the bytes at 200 would panic.
        let long = format!("{}é and more", "x".repeat(199));
        let b = long.clone();
        respond_with(move |_| Ok(host::http::response(503, b.clone())));
        assert_eq!(read(json!({"AUTH_HEADER": AUTH})).unwrap_err(), format!("Graph HTTP 503: {}é", "x".repeat(199)));
        assert_eq!(clip_chars("ééé", 2), "éé");
        assert_eq!(clip_chars("short", 200), "short");
        respond_with(|_| Err(talos::core::http::Error::Timeout));
        assert!(read(json!({"AUTH_HEADER": AUTH})).unwrap_err().starts_with("Graph fetch:"));
        respond_with(|_| Ok(host::http::response(200, "<html>")));
        assert!(read(json!({"AUTH_HEADER": AUTH})).unwrap_err().starts_with("Graph parse:"));
    }

    const NEXT: &str = "https://graph.microsoft.com/v1.0/me/calendarView?startDateTime=2026-10-06T14%3a00%3a00Z&endDateTime=2026-10-07T14%3a00%3a00Z&%24top=2&%24skip=2";

    #[test]
    fn pages_are_followed_and_combined() {
        set_unix(NOW);
        respond_with(|req| {
            let body = if req.url == NEXT {
                page(vec![meeting(3, "2026-10-06T15:00:00", "2026-10-06T16:00:00", "UTC")], None)
            } else {
                page(vec![meeting(1, "2026-10-06T14:00:00", "2026-10-06T14:30:00", "UTC"), meeting(2, "2026-10-06T14:30:00", "2026-10-06T15:00:00", "UTC")], Some(NEXT))
            };
            Ok(host::http::response(200, body))
        });
        let v = read(json!({"AUTH_HEADER": AUTH, "MAX_RESULTS": 10})).unwrap();
        assert_eq!((v["count"].as_u64(), v["truncated"].as_bool()), (Some(3), Some(false)));
        assert_eq!(v["events"][2]["summary"], "Meeting 3");
        let sent = host::http::requests();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[1].url, NEXT, "the link is followed as Graph wrote it");
        assert!(sent[1].headers.iter().any(|(k, v)| k == "Authorization" && v == AUTH));
    }

    #[test]
    fn a_cut_list_says_truncated_and_stops_asking() {
        set_unix(NOW);
        // MAX_RESULTS reached inside a page.
        respond_with(|_| Ok(host::http::response(200, page((1..=3).map(|n| meeting(n, "2026-10-06T15:00:00", "2026-10-06T16:00:00", "UTC")).collect(), None))));
        let v = read(json!({"AUTH_HEADER": AUTH, "MAX_RESULTS": 2})).unwrap();
        assert_eq!((v["count"].as_u64(), v["truncated"].as_bool()), (Some(2), Some(true)));
        // MAX_RESULTS reached at a page's end with more to come: the next page is not asked for.
        respond_with(|_| Ok(host::http::response(200, page((1..=2).map(|n| meeting(n, "2026-10-06T15:00:00", "2026-10-06T16:00:00", "UTC")).collect(), Some(NEXT)))));
        let v = read(json!({"AUTH_HEADER": AUTH, "MAX_RESULTS": 2})).unwrap();
        assert_eq!((v["count"].as_u64(), v["truncated"].as_bool()), (Some(2), Some(true)));
        assert_eq!(host::http::requests().len(), 2, "one request per run");
        // A calendar that keeps paging stops at MAX_PAGES, and says so.
        respond_with(|_| Ok(host::http::response(200, page(vec![meeting(1, "2026-10-06T15:00:00", "2026-10-06T16:00:00", "UTC")], Some(NEXT)))));
        let v = read(json!({"AUTH_HEADER": AUTH, "MAX_RESULTS": 250})).unwrap();
        assert_eq!((v["count"].as_u64(), v["truncated"].as_bool()), (Some(MAX_PAGES as u64), Some(true)));
        assert_eq!(host::http::requests().len(), 2 + MAX_PAGES);
        // Cancelled entries are not counted toward MAX_RESULTS.
        let mut gone = meeting(9, "2026-10-06T15:00:00", "2026-10-06T16:00:00", "UTC");
        gone["isCancelled"] = json!(true);
        let events = vec![gone, meeting(1, "2026-10-06T15:00:00", "2026-10-06T16:00:00", "UTC")];
        respond_with(move |_| Ok(host::http::response(200, page(events.clone(), None))));
        let v = read(json!({"AUTH_HEADER": AUTH, "MAX_RESULTS": 1})).unwrap();
        assert_eq!((v["count"].as_u64(), v["truncated"].as_bool(), v["events"][0]["summary"].as_str()), (Some(1), Some(false), Some("Meeting 1")));
    }

    #[test]
    fn a_next_link_off_graph_is_never_followed() {
        set_unix(NOW);
        for link in [
            "https://evil.example.com/v1.0/me/calendarView?$skip=2",
            "http://graph.microsoft.com/v1.0/me/calendarView?$skip=2",
            "https://graph.microsoft.com.evil.example.com/v1.0/x",
            "https://graph.microsoft.com/beta/me/calendarView",
            "https://graph.microsoft.com/v1.0/me/calendarView?$skip=2 x",
        ] {
            let body = page(vec![meeting(1, "2026-10-06T15:00:00", "2026-10-06T16:00:00", "UTC")], Some(link));
            respond_with(move |_| Ok(host::http::response(200, body.clone())));
            let err = read(json!({"AUTH_HEADER": AUTH, "MAX_RESULTS": 10})).unwrap_err();
            assert!(err.contains("refusing to send the token there"), "{link}: {err}");
        }
        assert_eq!(host::http::requests().len(), 5, "only the first page of each run was asked for");
        assert_eq!(followable(NEXT), Some(NEXT));
    }

    #[test]
    fn an_invitation_reports_what_a_planner_needs() {
        set_unix(NOW);
        let e = event_json(event(json!({
            "id": "abc", "iCalUId": "uid-1", "subject": "Design review", "isAllDay": false, "showAs": "tentative",
            "start": {"dateTime": "2026-10-06T10:30:00.0000000", "timeZone": "America/New_York"},
            "end": {"dateTime": "2026-10-06T11:30:00.0000000", "timeZone": "America/New_York"},
            "location": {"displayName": "Room 4"}, "seriesMasterId": "AAMkSeries=", "isCancelled": false, "isOrganizer": false,
            "responseStatus": {"response": "tentativelyAccepted"},
            "onlineMeeting": {"joinUrl": "https://teams.microsoft.com/l/meetup-join/made-up"},
            "webLink": "https://outlook.office365.com/owa/?itemid=made-up",
            "organizer": {"emailAddress": {"name": "Pat", "address": "Pat@example.com"}},
            "attendees": [
                {"type": "required", "status": {"response": "tentativelyAccepted"}, "emailAddress": {"address": "me@example.com"}},
                {"type": "optional", "status": {"response": "none"}, "emailAddress": {"address": "sam@example.com"}},
                {"type": "resource", "status": {"response": "accepted"}, "emailAddress": {"address": "room4@example.com"}}
            ]
        })), "America/New_York")
        .unwrap();
        assert_eq!((e["uid"].as_str(), e["summary"].as_str(), e["location"].as_str()), (Some("uid-1"), Some("Design review"), Some("Room 4")));
        assert_eq!((e["start"].as_str(), e["end"].as_str()), (Some("2026-10-06T10:30:00-04:00"), Some("2026-10-06T11:30:00-04:00")));
        assert_eq!(e["busy"], true, "tentative still holds the time");
        assert_eq!(e["response"], "tentative", "the owner's own answer, in Google's words");
        // The owner and the room are not guests; the organizer, not listed by Graph, is.
        assert_eq!(e["guests"], 2);
        assert_eq!((e["recurring"].as_bool(), e["all_day"].as_bool(), e["organizer_self"].as_bool()), (Some(true), Some(false), Some(false)));
        assert_eq!(e["hangout_link"], "https://teams.microsoft.com/l/meetup-join/made-up");
        assert_eq!(e["event_type"], "default");
        assert_eq!(e["attendees"].as_array().unwrap().len(), 3);
        assert_eq!(e["attendees"][1], json!({"email": "sam@example.com", "response_status": "needsAction"}));
    }

    #[test]
    fn free_all_day_own_and_out_of_office_entries_are_told_apart() {
        set_unix(NOW);
        let free = event_json(event(json!({"subject": "Conference", "showAs": "free", "isAllDay": true,
            "start": {"dateTime": "2026-10-07T00:00:00.0000000", "timeZone": "UTC"}, "end": {"dateTime": "2026-10-09T00:00:00.0000000", "timeZone": "UTC"}})), "UTC").unwrap();
        assert_eq!((free["busy"].as_bool(), free["all_day"].as_bool(), free["start"].as_str(), free["end"].as_str()), (Some(false), Some(true), Some("2026-10-07"), Some("2026-10-09")));
        // The owner's own appointment, nobody invited.
        let own = event_json(event(json!({"subject": "Dentist", "showAs": "busy", "isOrganizer": true, "responseStatus": {"response": "organizer"}, "attendees": []})), "UTC").unwrap();
        assert_eq!((own["response"].as_str(), own["guests"].as_u64(), own["organizer_self"].as_bool(), own["busy"].as_bool()), (Some(""), Some(0), Some(true), Some(true)));
        // A meeting the owner organised: everyone listed is a guest.
        let hosted = event_json(event(json!({"isOrganizer": true, "responseStatus": {"response": "organizer"},
            "organizer": {"emailAddress": {"address": "me@example.com"}},
            "attendees": [{"type": "required", "emailAddress": {"address": "a@example.com"}}, {"type": "required", "emailAddress": {"address": "b@example.com"}}]})), "UTC").unwrap();
        assert_eq!((hosted["response"].as_str(), hosted["guests"].as_u64()), (Some("accepted"), Some(2)));
        let oof = event_json(event(json!({"subject": "Away", "showAs": "oof"})), "UTC").unwrap();
        assert_eq!((oof["event_type"].as_str(), oof["busy"].as_bool()), (Some("outOfOffice"), Some(true)));
        let elsewhere = event_json(event(json!({"showAs": "workingElsewhere", "responseStatus": {"response": "declined"}})), "UTC").unwrap();
        assert_eq!((elsewhere["busy"].as_bool(), elsewhere["response"].as_str()), (Some(true), Some("declined")));
        assert!(event_json(event(json!({"subject": "Canceled: Sync", "isCancelled": true})), "UTC").is_none());
        // An entry with nothing set still renders.
        let bare = event_json(event(json!({})), "UTC").unwrap();
        assert_eq!((bare["start"].as_str(), bare["all_day"].as_bool(), bare["uid"].as_str(), bare["recurring"].as_bool()), (Some(""), Some(false), Some(""), Some(false)));
        // A link in another scheme is dropped.
        let odd = event_json(event(json!({"webLink": "javascript:alert(1)", "onlineMeeting": {"joinUrl": "http://x.example.com"}})), "UTC").unwrap();
        assert_eq!((odd["web_link"].as_str(), odd["hangout_link"].as_str()), (Some(""), Some("")));
    }

    #[test]
    fn times_carry_the_offset_in_force_on_their_own_date() {
        set_unix(NOW);
        let t = |dt: &str, tz: &str| GraphTime { date_time: Some(dt.to_string()), time_zone: Some(tz.to_string()) };
        let ny = "America/New_York";
        // Before and after the change back to standard time (2026-11-01).
        assert_eq!(render_time(Some(&t("2026-10-31T09:00:00.0000000", ny)), ny, false), "2026-10-31T09:00:00-04:00");
        assert_eq!(render_time(Some(&t("2026-11-02T09:00:00.0000000", ny)), ny, false), "2026-11-02T09:00:00-05:00");
        // A time Graph left in UTC is converted into the zone.
        assert_eq!(render_time(Some(&t("2026-11-02T14:00:00.0000000", "UTC")), ny, false), "2026-11-02T09:00:00-05:00");
        assert_eq!(render_time(Some(&t("2026-10-06T14:00:00.0000000", "UTC")), "UTC", false), "2026-10-06T14:00:00+00:00");
        assert_eq!(render_time(Some(&t("2026-10-06T14:00:00.0000000", "Asia/Kolkata")), "Asia/Kolkata", false), "2026-10-06T14:00:00+05:30");
        // A zone this module did not ask for, or an unreadable time, passes through.
        assert_eq!(render_time(Some(&t("2026-10-06T14:00:00.0000000", "Pacific Standard Time")), ny, false), "2026-10-06T14:00:00.0000000");
        assert_eq!(render_time(Some(&t("soon", ny)), ny, false), "soon");
        assert_eq!(render_time(None, ny, false), "");
        assert_eq!(render_time(Some(&t("2026-10-06T14:00:00", "UTC")), "UTC", false), "2026-10-06T14:00:00+00:00");
        for bad in ["2026-13-06T14:00:00.0000000", "2026-10-06 14:00:00", "2026-10-06T14:00:00Z", "2026-10-06T14:00:00.00x", "2026-02-30T14:00:00", "２０２６-10-06T14:00:00"] {
            assert!(graph_wall_clock(bad).is_none(), "{bad}");
        }
    }
}
