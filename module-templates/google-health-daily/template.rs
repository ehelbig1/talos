// Canonical catalog module: last night's sleep, yesterday's steps and the
// resting heart rate from the Google Health API (Pixel Watch and Fitbit
// devices). Read-only: three GET requests, nothing is written anywhere.
//
// Uses vault:// header resolution for auth — the module never holds the token.
//
// Each of the three readings is independent. One that cannot be read is
// reported under `unavailable` and the others are still returned; a reading
// the API answered with NO data is `null`, which is a different statement
// ("nothing was recorded") from "could not be read".

use chrono::{DateTime, Duration, NaiveDate, Utc};
use serde::{Deserialize, Deserializer};
use talos::core::datetime;
use talos_sdk_macros::talos_module;

const API: &str = "https://health.googleapis.com/v4/users/me/dataTypes";
/// Sleep sessions asked for (the API's own maximum for this type).
const SLEEP_PAGE: usize = 25;
/// Step intervals asked for per request: a day holds at most 1,440 of them.
const STEPS_PAGE: usize = 2000;
/// The most requests one day's steps may take.
const STEPS_MAX_PAGES: usize = 3;
/// Days of resting heart rate read for the average.
const RESTING_DAYS: i64 = 7;
/// Characters of a provider error body quoted in an error.
const ERROR_BODY_CHARS: usize = 200;

// ------------------------------------------------------------ wire shapes

/// An int64 the API sends as a JSON string ("403"); a plain number is taken too.
fn int64<'de, D: Deserializer<'de>>(d: D) -> Result<Option<i64>, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Raw {
        Text(String),
        Number(f64),
    }
    Ok(match Option::<Raw>::deserialize(d)? {
        Some(Raw::Text(s)) => s.trim().parse::<i64>().ok(),
        Some(Raw::Number(n)) if n.is_finite() => Some(n as i64),
        _ => None,
    })
}

#[derive(Deserialize, Default)]
struct Page {
    #[serde(rename = "dataPoints", default)]
    data_points: Vec<Point>,
    #[serde(rename = "nextPageToken")]
    next_page_token: Option<String>,
}
#[derive(Deserialize, Default)]
struct Point {
    sleep: Option<Sleep>,
    steps: Option<Steps>,
    #[serde(rename = "dailyRestingHeartRate")]
    resting: Option<Resting>,
}
#[derive(Deserialize, Default)]
struct Sleep {
    #[serde(default)]
    interval: Interval,
    #[serde(default)]
    metadata: SleepMetadata,
    #[serde(default)]
    summary: SleepSummary,
}
#[derive(Deserialize, Default)]
struct Interval {
    #[serde(rename = "startTime")]
    start_time: Option<String>,
    #[serde(rename = "startUtcOffset")]
    start_utc_offset: Option<String>,
    #[serde(rename = "endTime")]
    end_time: Option<String>,
    #[serde(rename = "endUtcOffset")]
    end_utc_offset: Option<String>,
}
#[derive(Deserialize, Default)]
struct SleepMetadata {
    #[serde(default)]
    nap: bool,
    #[serde(rename = "mainSleep", default)]
    main_sleep: bool,
}
#[derive(Deserialize, Default)]
struct SleepSummary {
    #[serde(rename = "minutesAsleep", default, deserialize_with = "int64")]
    minutes_asleep: Option<i64>,
    #[serde(rename = "minutesAwake", default, deserialize_with = "int64")]
    minutes_awake: Option<i64>,
    #[serde(rename = "minutesInSleepPeriod", default, deserialize_with = "int64")]
    minutes_in_period: Option<i64>,
    #[serde(rename = "stagesSummary", default)]
    stages: Vec<StageSummary>,
}
#[derive(Deserialize, Default)]
struct StageSummary {
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default, deserialize_with = "int64")]
    minutes: Option<i64>,
}
#[derive(Deserialize, Default)]
struct Steps {
    #[serde(default, deserialize_with = "int64")]
    count: Option<i64>,
}
#[derive(Deserialize, Default)]
struct Resting {
    date: Option<CivilDate>,
    #[serde(rename = "beatsPerMinute", default, deserialize_with = "int64")]
    bpm: Option<i64>,
}
#[derive(Deserialize, Default)]
struct CivilDate {
    #[serde(default)]
    year: i32,
    #[serde(default)]
    month: u32,
    #[serde(default)]
    day: u32,
}

// ----------------------------------------------------------------- helpers

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

/// A string cut to `max` characters on a character boundary.
fn clip_chars(s: &str, max: usize) -> String {
    s.chars().take(max).collect()
}

/// An IANA zone name is letters, digits, `/`, `_`, `+`, `-`.
fn valid_zone(z: &str) -> bool {
    !z.is_empty() && z.len() <= 64 && z.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'/' | b'_' | b'+' | b'-'))
}

/// Seconds in a UTC offset such as "-14400s" or "3600.5s". An offset beyond
/// eighteen hours either way is not one: it is dropped (the configured zone's
/// offset is used) rather than added to a timestamp.
fn offset_seconds(s: &str) -> Option<i64> {
    s.trim()
        .strip_suffix('s')?
        .parse::<f64>()
        .ok()
        .filter(|v| v.is_finite() && v.abs() <= 18.0 * 3600.0)
        .map(|v| v as i64)
}

/// The wall-clock time of an instant where it was recorded: the instant plus
/// its own UTC offset, or plus `fallback` (the configured zone's offset now)
/// when the reading carries none.
fn local(stamp: Option<&str>, offset: Option<&str>, fallback: i64) -> Option<chrono::NaiveDateTime> {
    let at = DateTime::parse_from_rfc3339(stamp?.trim()).ok()?.with_timezone(&Utc);
    let secs = offset.and_then(offset_seconds).unwrap_or(fallback);
    Some((at + Duration::seconds(secs)).naive_utc())
}

/// Which data sources a request reads. `None` leaves the API's own default
/// (every source).
fn source_param(source: Option<&str>) -> Result<String, String> {
    match source.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(String::new()),
        Some(s @ ("all-sources" | "google-wearables" | "google-sources" | "self-sources")) => {
            Ok(format!("&dataSourceFamily={}", pct(&format!("users/me/dataSourceFamilies/{s}"))))
        }
        Some(_) => Err("DATA_SOURCE must be one of all-sources, google-wearables, google-sources, self-sources".to_string()),
    }
}

fn sleep_url(from: NaiveDate, source: &str) -> String {
    let filter = format!("sleep.interval.civil_end_time >= \"{}\"", from.format("%Y-%m-%d"));
    format!("{API}/sleep/dataPoints?pageSize={SLEEP_PAGE}&filter={}{source}", pct(&filter))
}
fn resting_url(from: NaiveDate, source: &str) -> String {
    let filter = format!("dailyRestingHeartRate.date >= \"{}\"", from.format("%Y-%m-%d"));
    format!("{API}/daily-resting-heart-rate/dataPoints?pageSize=31&filter={}{source}", pct(&filter))
}
fn steps_url(day: NaiveDate, source: &str, page_token: Option<&str>) -> String {
    let filter = format!(
        "steps.interval.civil_start_time >= \"{}\" AND steps.interval.civil_start_time < \"{}\"",
        day.format("%Y-%m-%d"),
        (day + Duration::days(1)).format("%Y-%m-%d")
    );
    let mut url = format!("{API}/steps/dataPoints?pageSize={STEPS_PAGE}&filter={}{source}", pct(&filter));
    if let Some(t) = page_token {
        url.push_str("&pageToken=");
        url.push_str(&pct(t));
    }
    url
}

// ------------------------------------------------------- the three readings

/// Last night: the main sleep (or, failing a flag, the longest non-nap
/// session) that ended today or yesterday, the most recent first. `None`
/// when no such session was recorded.
fn sleep_reading(page: &Page, today: NaiveDate, fallback_offset: i64) -> Option<serde_json::Value> {
    let mut best: Option<(chrono::NaiveDateTime, i64, &Sleep)> = None;
    let mut naps = 0usize;
    for s in page.data_points.iter().filter_map(|p| p.sleep.as_ref()) {
        let Some(end) = local(s.interval.end_time.as_deref(), s.interval.end_utc_offset.as_deref(), fallback_offset) else {
            continue;
        };
        if end.date() != today && end.date() != today - Duration::days(1) {
            continue;
        }
        if s.metadata.nap {
            naps += usize::from(end.date() == today);
            continue;
        }
        let asleep = s.summary.minutes_asleep.or(s.summary.minutes_in_period).unwrap_or(0);
        // The latest night wins; within one night the flagged main sleep, then the longest.
        let rank = |e: chrono::NaiveDateTime, main: bool, mins: i64| (e.date(), main, mins);
        if best.is_none_or(|(be, bm, b)| rank(end, s.metadata.main_sleep, asleep) > rank(be, b.metadata.main_sleep, bm)) {
            best = Some((end, asleep, s));
        }
    }
    let (end, _, s) = best?;
    let start = local(s.interval.start_time.as_deref(), s.interval.start_utc_offset.as_deref(), fallback_offset);
    let stage = |name: &str| s.summary.stages.iter().find(|x| x.kind.eq_ignore_ascii_case(name)).and_then(|x| x.minutes);
    Some(serde_json::json!({
        "ended_on": end.date().to_string(),
        "last_night": end.date() == today,
        "start": start.map(|t| t.format("%H:%M").to_string()),
        "end": end.format("%H:%M").to_string(),
        "minutes_asleep": s.summary.minutes_asleep,
        "minutes_awake": s.summary.minutes_awake,
        "minutes_in_bed": s.summary.minutes_in_period,
        "stages": { "deep": stage("DEEP"), "rem": stage("REM"), "light": stage("LIGHT"), "awake": stage("AWAKE") },
        "naps_today": naps,
    }))
}

/// The latest resting heart rate and the mean over the days read. `None`
/// when no day carried one.
fn resting_reading(page: &Page) -> Option<serde_json::Value> {
    let mut days: Vec<(NaiveDate, i64)> = page
        .data_points
        .iter()
        .filter_map(|p| p.resting.as_ref())
        .filter_map(|r| {
            let d = r.date.as_ref()?;
            Some((NaiveDate::from_ymd_opt(d.year, d.month, d.day)?, r.bpm.filter(|b| (20..=250).contains(b))?))
        })
        .collect();
    days.sort();
    days.dedup_by_key(|(d, _)| *d);
    let (latest_date, latest) = *days.last()?;
    let mean = days.iter().map(|(_, b)| *b as f64).sum::<f64>() / days.len() as f64;
    Some(serde_json::json!({
        "latest": latest,
        "latest_date": latest_date.to_string(),
        "average": (mean * 10.0).round() / 10.0,
        "days": days.len(),
    }))
}

// ------------------------------------------------------------------- run

struct Clock {
    today: NaiveDate,
    /// The configured zone's offset from UTC now, in seconds.
    offset: i64,
}

/// One GET: the status and the body.
type Get<'a> = dyn FnMut(&str) -> Result<(u16, Vec<u8>), String> + 'a;

/// Why one reading could not be had, or the parsed page.
fn page(get: &mut Get<'_>, url: &str, what: &str, unavailable: &mut Vec<serde_json::Value>) -> Result<Option<Page>, String> {
    let (status, body) = match get(url) {
        Ok(r) => r,
        Err(e) => {
            unavailable.push(serde_json::json!({ "what": what, "reason": clip_chars(&e, ERROR_BODY_CHARS) }));
            return Ok(None);
        }
    };
    if status == 401 {
        // The token itself is refused: nothing else will work either.
        return Err("Google Health 401: the access token is invalid or expired. Call refresh_oauth_token to force a refresh.".to_string());
    }
    if !(200..300).contains(&status) {
        let text = String::from_utf8_lossy(&body);
        unavailable.push(serde_json::json!({ "what": what, "status": status, "reason": clip_chars(&text, ERROR_BODY_CHARS) }));
        return Ok(None);
    }
    match serde_json::from_slice::<Page>(&body) {
        Ok(p) => Ok(Some(p)),
        Err(e) => {
            unavailable.push(serde_json::json!({ "what": what, "reason": format!("response could not be read: {e}") }));
            Ok(None)
        }
    }
}

fn gather(clock: &Clock, source: &str, zone: &str, get: &mut Get<'_>) -> Result<String, String> {
    let (today, yesterday) = (clock.today, clock.today - Duration::days(1));
    let mut unavailable: Vec<serde_json::Value> = Vec::new();

    let sleep = page(get, &sleep_url(yesterday, source), "sleep", &mut unavailable)?
        .and_then(|p| sleep_reading(&p, today, clock.offset));
    let resting = page(get, &resting_url(today - Duration::days(RESTING_DAYS - 1), source), "resting_heart_rate", &mut unavailable)?
        .and_then(|p| resting_reading(&p));

    // Yesterday's steps: every interval that began on that civil day, summed.
    // A page that cannot be read makes the whole reading unavailable: a sum
    // over the pages that did arrive would be presented as the day's total.
    let (mut total, mut intervals, mut truncated, mut read_steps) = (0i64, 0usize, false, false);
    let mut token: Option<String> = None;
    for n in 0..STEPS_MAX_PAGES {
        let Some(p) = page(get, &steps_url(yesterday, source, token.as_deref()), "steps", &mut unavailable)? else {
            read_steps = false;
            break;
        };
        read_steps = true;
        for s in p.data_points.iter().filter_map(|d| d.steps.as_ref()) {
            total = total.saturating_add(s.count.filter(|c| *c >= 0).unwrap_or(0));
            intervals += 1;
        }
        match p.next_page_token.filter(|t| !t.is_empty()) {
            Some(t) if n + 1 < STEPS_MAX_PAGES => token = Some(t),
            Some(_) => {
                truncated = true;
                break;
            }
            None => break,
        }
    }
    let steps = (read_steps && intervals > 0).then(|| {
        serde_json::json!({ "date": yesterday.to_string(), "count": total, "intervals": intervals, "truncated": truncated })
    });

    let failed = |what: &str| unavailable.iter().any(|u| u["what"] == what);
    if failed("sleep") && failed("resting_heart_rate") && failed("steps") {
        return Err(format!("none of the three readings could be read: {}", serde_json::Value::Array(unavailable)));
    }
    // "Nothing recorded" is a statement about the device (not worn, or not
    // synced), so it is made only when EVERY reading was answered and every
    // answer was empty. With a reading unavailable, what was recorded is not
    // known, and `unavailable` says which.
    let recorded = sleep.is_some() || resting.is_some() || steps.is_some();
    let nothing_recorded = !recorded && unavailable.is_empty();
    serde_json::to_string(&serde_json::json!({
        "kind": "health",
        "date": today.to_string(),
        "time_zone": zone,
        "sleep": sleep,
        "resting_heart_rate": resting,
        "steps": steps,
        "nothing_recorded": nothing_recorded,
        "unavailable": unavailable,
    }))
    .map_err(|e| e.to_string())
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let data: serde_json::Value = serde_json::from_str(&input).map_err(|e| e.to_string())?;
    let config = data.get("config").unwrap_or(&serde_json::Value::Null);
    let auth = config["AUTH_HEADER"]
        .as_str()
        .ok_or("Missing AUTH_HEADER config (expected 'Bearer vault://oauth/google_health/{user_id}/{account}/access_token')")?
        .to_string();
    let zone = config["TIME_ZONE"].as_str().map(str::trim).filter(|z| !z.is_empty()).unwrap_or("UTC");
    if !valid_zone(zone) {
        return Err("TIME_ZONE must be an IANA zone name such as America/New_York".to_string());
    }
    let source = source_param(config["DATA_SOURCE"].as_str())?;

    let now = Utc::now();
    let at = u64::try_from(now.timestamp()).map_err(|_| "the clock reads a time before 1970".to_string())?;
    let offset = datetime::local_offset_seconds(zone, at).map(i64::from).map_err(|_| {
        format!("TIME_ZONE '{}' is not a time zone the host knows; use an IANA name such as America/New_York (case-sensitive)", clip_chars(zone, 64))
    })?;
    let clock = Clock { today: (now + Duration::seconds(offset)).date_naive(), offset };

    let mut get = |url: &str| -> Result<(u16, Vec<u8>), String> {
        let req = talos::core::http::Request {
            method: talos::core::http::Method::Get,
            url: url.to_string(),
            headers: vec![
                ("Authorization".to_string(), auth.clone()),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            body: vec![],
            timeout_ms: Some(10000),
        };
        talos::core::http::fetch(&req).map(|r| (r.status, r.body)).map_err(|e| format!("{e:?}"))
    };
    gather(&clock, &source, zone, &mut get)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn d(s: &str) -> NaiveDate {
        NaiveDate::parse_from_str(s, "%Y-%m-%d").unwrap()
    }
    fn clock() -> Clock {
        Clock { today: d("2026-10-06"), offset: -4 * 3600 }
    }
    /// Answers each request by the data type in its path. Step pages are
    /// keyed by the page token the request carries ("" for the first), so a
    /// reader that does not send the token back gets the first page again.
    fn answer(sleep: (u16, Value), resting: (u16, Value), steps: Vec<(&'static str, (u16, Value))>) -> impl FnMut(&str) -> Result<(u16, Vec<u8>), String> {
        move |url: &str| {
            let (status, body) = if url.contains("/sleep/") {
                sleep.clone()
            } else if url.contains("/daily-resting-heart-rate/") {
                resting.clone()
            } else if url.contains("/steps/") {
                let token = url.split("&pageToken=").nth(1).unwrap_or("");
                steps.iter().find(|(t, _)| *t == token).map(|(_, a)| a.clone()).ok_or(format!("no step page for token '{token}'"))?
            } else {
                return Err(format!("unexpected request {url}"));
            };
            Ok((status, body.to_string().into_bytes()))
        }
    }
    fn out(r: Result<String, String>) -> Value {
        serde_json::from_str(&r.unwrap()).unwrap()
    }
    fn night() -> Value {
        json!({"dataPoints": [
            {"sleep": {"interval": {"startTime": "2026-10-06T03:41:00Z", "startUtcOffset": "-14400s", "endTime": "2026-10-06T10:52:00Z", "endUtcOffset": "-14400s"},
                       "metadata": {"mainSleep": true}, "summary": {"minutesAsleep": "403", "minutesAwake": "28", "minutesInSleepPeriod": "431",
                       "stagesSummary": [{"type": "DEEP", "minutes": "62"}, {"type": "REM", "minutes": "88"}, {"type": "LIGHT", "minutes": 253}, {"type": "AWAKE", "minutes": "28"}]}}},
            {"sleep": {"interval": {"endTime": "2026-10-06T18:30:00Z", "endUtcOffset": "-14400s"}, "metadata": {"nap": true}, "summary": {"minutesAsleep": "25"}}},
            {"sleep": {"interval": {"endTime": "2026-10-05T10:40:00Z", "endUtcOffset": "-14400s"}, "metadata": {"mainSleep": true}, "summary": {"minutesAsleep": "380"}}}
        ]})
    }
    fn resting() -> Value {
        json!({"dataPoints": [
            {"dailyRestingHeartRate": {"date": {"year": 2026, "month": 10, "day": 4}, "beatsPerMinute": "57"}},
            {"dailyRestingHeartRate": {"date": {"year": 2026, "month": 10, "day": 6}, "beatsPerMinute": "60"}},
            {"dailyRestingHeartRate": {"date": {"year": 2026, "month": 10, "day": 5}, "beatsPerMinute": 58}},
            {"dailyRestingHeartRate": {"date": {"year": 2026, "month": 13, "day": 1}, "beatsPerMinute": "40"}},
            {"dailyRestingHeartRate": {"date": {"year": 2026, "month": 10, "day": 3}, "beatsPerMinute": "0"}}
        ]})
    }

    #[test]
    fn the_three_readings_are_reduced_to_what_a_morning_message_needs() {
        let steps = vec![
            ("", (200, json!({"dataPoints": [{"steps": {"count": "4000"}}, {"steps": {"count": 421}}], "nextPageToken": "p2"}))),
            ("p2", (200, json!({"dataPoints": [{"steps": {"count": "4000"}}, {"steps": {"count": "-5"}}, {"heartRate": {}}]}))),
        ];
        let o = out(gather(&clock(), "", "America/New_York", &mut answer((200, night()), (200, resting()), steps)));
        assert_eq!(o["kind"], "health");
        assert_eq!(o["date"], "2026-10-06");
        // The night that ended this morning, in local time, with its stages.
        assert_eq!(o["sleep"], json!({"ended_on": "2026-10-06", "last_night": true, "start": "23:41", "end": "06:52",
            "minutes_asleep": 403, "minutes_awake": 28, "minutes_in_bed": 431,
            "stages": {"deep": 62, "rem": 88, "light": 253, "awake": 28}, "naps_today": 1}));
        // Latest day and the mean over the days that carried a plausible value.
        assert_eq!(o["resting_heart_rate"], json!({"latest": 60, "latest_date": "2026-10-06", "average": 58.3, "days": 3}));
        // Yesterday's intervals summed across pages; a negative count adds nothing.
        assert_eq!(o["steps"], json!({"date": "2026-10-05", "count": 8421, "intervals": 4, "truncated": false}));
        assert_eq!((o["nothing_recorded"].as_bool(), o["unavailable"].as_array().map(Vec::len)), (Some(false), Some(0)));
    }

    #[test]
    fn nothing_recorded_is_said_and_is_not_the_same_as_unreadable() {
        // The API answered all three with no data: the watch was not worn.
        let empty = || (200, json!({}));
        let o = out(gather(&clock(), "", "UTC", &mut answer(empty(), empty(), vec![("", empty())])));
        assert_eq!((o["sleep"].is_null(), o["resting_heart_rate"].is_null(), o["steps"].is_null()), (true, true, true));
        assert_eq!((o["nothing_recorded"].as_bool(), o["unavailable"].as_array().map(Vec::len)), (Some(true), Some(0)));
        // One reading refused (a scope not granted): named, and the others still read.
        let refused = || (403, json!({"error": {"message": "insufficient scope"}}));
        let o = out(gather(&clock(), "", "UTC", &mut answer((200, night()), refused(), vec![("", empty())])));
        assert_eq!(o["unavailable"][0]["what"], "resting_heart_rate");
        assert_eq!(o["unavailable"][0]["status"], 403);
        assert_eq!((o["sleep"]["minutes_asleep"].as_i64(), o["nothing_recorded"].as_bool()), (Some(403), Some(false)));
        // Two readings refused and the third empty: what was recorded is NOT
        // known, so it is not reported as a watch that was not worn.
        let o = out(gather(&clock(), "", "UTC", &mut answer(refused(), refused(), vec![("", empty())])));
        assert_eq!((o["nothing_recorded"].as_bool(), o["unavailable"].as_array().map(Vec::len)), (Some(false), Some(2)), "{o}");
        // A body that is not the expected JSON is unreadable, not empty.
        let mut bad = |url: &str| -> Result<(u16, Vec<u8>), String> {
            Ok((200, if url.contains("/sleep/") { b"<html>".to_vec() } else { b"{}".to_vec() }))
        };
        let o = out(gather(&clock(), "", "UTC", &mut bad));
        assert_eq!(o["unavailable"][0]["what"], "sleep");
        // All three unreadable is an error, and so is a refused token.
        let mut down = |_: &str| -> Result<(u16, Vec<u8>), String> { Ok((503, b"unavailable".to_vec())) };
        assert!(gather(&clock(), "", "UTC", &mut down).is_err_and(|e| e.contains("none of the three")));
        let mut denied = |_: &str| -> Result<(u16, Vec<u8>), String> { Ok((401, vec![])) };
        assert!(gather(&clock(), "", "UTC", &mut denied).is_err_and(|e| e.contains("401")));
    }

    #[test]
    fn last_night_is_the_latest_main_sleep_and_an_older_night_is_labelled_as_one() {
        // Only the night before last was recorded.
        let older = json!({"dataPoints": [{"sleep": {"interval": {"endTime": "2026-10-05T10:40:00Z", "endUtcOffset": "-14400s"}, "metadata": {"mainSleep": true}, "summary": {"minutesAsleep": "380"}}}]});
        let p: Page = serde_json::from_value(older).unwrap();
        let s = sleep_reading(&p, d("2026-10-06"), 0).unwrap();
        assert_eq!((s["ended_on"].as_str(), s["last_night"].as_bool()), (Some("2026-10-05"), Some(false)));
        // Two sessions the same morning, neither flagged: the longer one.
        let two = json!({"dataPoints": [
            {"sleep": {"interval": {"endTime": "2026-10-06T07:00:00Z"}, "summary": {"minutesAsleep": "90"}}},
            {"sleep": {"interval": {"endTime": "2026-10-06T11:00:00Z"}, "summary": {"minutesAsleep": "300"}}}]});
        let p: Page = serde_json::from_value(two).unwrap();
        // No offset on the reading: the configured zone's offset decides the local day and time.
        let s = sleep_reading(&p, d("2026-10-06"), -4 * 3600).unwrap();
        assert_eq!((s["minutes_asleep"].as_i64(), s["end"].as_str()), (Some(300), Some("07:00")));
        // A session from three days ago is not "last night".
        let stale = json!({"dataPoints": [{"sleep": {"interval": {"endTime": "2026-10-03T10:00:00Z"}, "summary": {"minutesAsleep": "400"}}}]});
        assert!(sleep_reading(&serde_json::from_value(stale).unwrap(), d("2026-10-06"), 0).is_none());
    }

    #[test]
    fn steps_stop_at_the_page_cap_and_say_so() {
        let page = |count: &str, next: &str| (200, json!({"dataPoints": [{"steps": {"count": count}}], "nextPageToken": next}));
        let pages = vec![("", page("100", "b")), ("b", page("20", "c")), ("c", page("3", "d")), ("d", page("4000", "e"))];
        let o = out(gather(&clock(), "", "UTC", &mut answer((200, json!({})), (200, json!({})), pages)));
        // Each page is asked for with the token the one before returned, and the fourth is never asked for.
        assert_eq!(o["steps"], json!({"date": "2026-10-05", "count": 123, "intervals": 3, "truncated": true}));
    }

    #[test]
    fn a_step_page_that_cannot_be_read_makes_the_reading_unavailable_not_smaller() {
        let pages = vec![
            ("", (200, json!({"dataPoints": [{"steps": {"count": "5000"}}], "nextPageToken": "b"}))),
            ("b", (500, json!({"error": "backend"}))),
        ];
        let o = out(gather(&clock(), "", "UTC", &mut answer((200, night()), (200, resting()), pages)));
        assert!(o["steps"].is_null(), "5,000 of the day's steps is not the day's steps: {o}");
        assert_eq!(o["unavailable"][0]["what"], "steps");
        assert_eq!(o["sleep"]["minutes_asleep"], 403);
        // With the other two also unreadable, it is "none of the three" — the
        // page that did arrive does not count as a reading.
        let pages = vec![
            ("", (200, json!({"dataPoints": [{"steps": {"count": "5000"}}], "nextPageToken": "b"}))),
            ("b", (500, json!({}))),
        ];
        let down = || (503, json!({}));
        assert!(gather(&clock(), "", "UTC", &mut answer(down(), down(), pages)).is_err_and(|e| e.contains("none of the three")));
    }

    #[test]
    fn requests_are_encoded_and_bounded() {
        let u = sleep_url(d("2026-10-05"), "");
        assert_eq!(u, "https://health.googleapis.com/v4/users/me/dataTypes/sleep/dataPoints?pageSize=25&filter=sleep.interval.civil_end_time%20%3E%3D%20%222026-10-05%22");
        let u = steps_url(d("2026-10-05"), &source_param(Some("google-wearables")).unwrap(), Some("a b&c"));
        assert!(u.contains("steps.interval.civil_start_time%20%3E%3D%20%222026-10-05%22%20AND%20steps.interval.civil_start_time%20%3C%20%222026-10-06%22"), "{u}");
        assert!(u.ends_with("&dataSourceFamily=users%2Fme%2FdataSourceFamilies%2Fgoogle-wearables&pageToken=a%20b%26c"), "{u}");
        assert!(resting_url(d("2026-09-30"), "").contains("/daily-resting-heart-rate/dataPoints?pageSize=31&filter=dailyRestingHeartRate.date%20%3E%3D%20%222026-09-30%22"));
        assert!(source_param(Some("everything&x=1")).is_err());
        assert_eq!(source_param(None).unwrap(), "");
        assert!(valid_zone("America/New_York") && !valid_zone("America/New York") && !valid_zone(""));
        assert_eq!((offset_seconds("-14400s"), offset_seconds("3600.5s"), offset_seconds("soon")), (Some(-14400), Some(3600), None));
        // An absurd offset is not applied (adding it to a timestamp would overflow).
        assert_eq!((offset_seconds("1e300s"), offset_seconds("-99999999s"), offset_seconds("64800s")), (None, None, Some(64800)));
        let far = json!({"dataPoints": [{"sleep": {"interval": {"endTime": "2026-10-06T10:00:00Z", "endUtcOffset": "9e18s"}, "summary": {"minutesAsleep": "400"}}}]});
        let s = sleep_reading(&serde_json::from_value(far).unwrap(), d("2026-10-06"), -4 * 3600).unwrap();
        assert_eq!(s["end"], "06:00", "the configured zone's offset is used instead");
    }
}
