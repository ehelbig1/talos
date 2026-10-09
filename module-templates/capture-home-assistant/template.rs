// Capture adapter: Home Assistant (a phone notification's reply box).
//
// One of the `capture-*` adapters. Each reads lines the owner typed somewhere
// other than mail and returns them in the SAME neutral `captured` shape, so
// what keeps the lines (a list, a journal) never learns which service they
// came from. docs/capture-contract.md.
//
// How the lines get here: with REPLY_TITLE set, `notify-home-assistant` puts a
// reply box under a notification. The companion app raises
// `mobile_app_notification_action` (action REPLY, `reply_text`) inside Home
// Assistant, and an automation there keeps each reply in one text helper as
// "<epoch ms>|<text>" (docs/capture-contract.md has the automation). This
// module reads that helper's history for the last day with ONE GET. The last
// day's history is every reply since, so nothing is lost while the platform
// is off; the number is the line's identity, so a reply read on two runs is
// the same line. A reply older than WINDOW_MS is not returned: the helper's
// CURRENT value is always in the history however old it is, and would
// otherwise come back on every run forever.
//
// It never changes anything in Home Assistant. An error names the status,
// never the response body.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

// ── capture contract ────────────────────────────────────────────────────────
// This block is IDENTICAL in every `capture-*` adapter, byte for byte, and
// `talos-catalog-tests/tests/capture_contract.rs` fails if two copies differ.
// docs/capture-contract.md.
//
// Output: { kind: "captured", source, captured: [{ id, text }], count, ignored }
// * `id` is "<source>:<key>"; the key is the line's identity at the service,
//   so the same line read on two runs has the same id.
// * `text` is one line: control characters become spaces, runs of whitespace
//   collapse, cut at CAPTURE_MAX_TEXT_CHARS characters on a character
//   boundary. An empty line is not returned.
// * Oldest first. At most CAPTURE_MAX_LINES, the newest kept.
// * `ignored` counts what was left out: lines with no key or no text,
//   duplicates, lines over the cap, and whatever the adapter itself did not
//   count as a line.

/// Most lines one run returns.
const CAPTURE_MAX_LINES: usize = 20;
/// A line is cut here.
const CAPTURE_MAX_TEXT_CHARS: usize = 240;

/// One line as the adapter read it: where it sits in time (smaller is older),
/// its identity at the service, and what was typed.
struct RawLine {
    order: u64,
    key: String,
    text: String,
}

fn capture_text(raw: &str) -> String {
    let flat: String = raw.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    flat.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(CAPTURE_MAX_TEXT_CHARS)
        .collect()
}

/// The contract's output for `source` (lowercase letters and '-') from the
/// lines an adapter read and the count it already set aside.
fn captured_output(source: &str, lines: Vec<RawLine>, ignored: usize) -> Result<String, String> {
    if source.is_empty() || !source.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
        return Err("a capture source is lowercase letters and '-'".to_string());
    }
    let mut ignored = ignored;
    let mut kept: Vec<(u64, String, String)> = Vec::new();
    for line in lines {
        let text = capture_text(&line.text);
        let key = line.key.trim().to_string();
        if text.is_empty() || key.is_empty() || kept.iter().any(|(_, k, _)| *k == key) {
            ignored += 1;
            continue;
        }
        kept.push((line.order, key, text));
    }
    kept.sort_by_key(|(order, _, _)| *order);
    if kept.len() > CAPTURE_MAX_LINES {
        let cut = kept.len() - CAPTURE_MAX_LINES;
        kept.drain(..cut);
        ignored += cut;
    }
    let captured: Vec<serde_json::Value> = kept
        .iter()
        .map(|(_, key, text)| serde_json::json!({ "id": format!("{source}:{key}"), "text": text }))
        .collect();
    serde_json::to_string(&serde_json::json!({
        "kind": "captured",
        "source": source,
        "count": captured.len(),
        "captured": captured,
        "ignored": ignored,
    }))
    .map_err(|e| format!("could not build the output: {e}"))
}
// ── end capture contract ────────────────────────────────────────────────────

/// Every line this adapter returns comes from a phone.
const SOURCE: &str = "phone";
/// A reply older than this is not returned (see the header).
const WINDOW_MS: u64 = 26 * 60 * 60 * 1000;

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
}

/// The node's config. Every key is optional here and checked in `run`, so a
/// missing one is reported by name instead of as a parse error.
#[derive(Deserialize, Default)]
struct Config {
    /// Home Assistant's external https:// address, with no path.
    #[serde(rename = "BASE_URL")]
    base_url: Option<String>,
    /// `Bearer vault://…`: the host replaces the reference when it sends.
    #[serde(rename = "AUTH_HEADER")]
    auth_header: Option<String>,
    /// The text helper the automation writes, e.g. `input_text.talos_capture`.
    #[serde(rename = "ENTITY")]
    entity: Option<String>,
    /// The clock, in epoch milliseconds, for a rehearsal or a test.
    #[serde(rename = "NOW_MS")]
    now_ms: Option<u64>,
}

/// One state of the helper. Everything else in the row is skipped.
#[derive(Deserialize)]
struct State {
    #[serde(default)]
    state: String,
}

fn base_of(raw: &str) -> Result<String, String> {
    let base = raw.trim().trim_end_matches('/');
    let host = base.strip_prefix("https://").ok_or("BASE_URL must start with https://")?;
    if host.is_empty() || host.contains(|c: char| c == '/' || c == '?' || c == '#' || c == '@' || c.is_whitespace()) {
        return Err("BASE_URL must be https://<host> with no path, query or credentials".to_string());
    }
    Ok(base.to_string())
}

fn entity_of(raw: &str) -> Result<&str, String> {
    let e = raw.trim();
    let name = e
        .strip_prefix("input_text.")
        .ok_or("ENTITY must be an input_text helper, e.g. input_text.talos_capture")?;
    if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_') {
        return Err("ENTITY must be input_text.<lowercase letters, digits and '_'>".to_string());
    }
    Ok(e)
}

/// "<epoch ms>|<text>" as the automation writes it; anything else is not a reply.
fn reply_of(state: &str) -> Option<RawLine> {
    let (stamp, text) = state.split_once('|')?;
    if !(12..=14).contains(&stamp.len()) || !stamp.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let order: u64 = stamp.parse().ok()?;
    Some(RawLine { order, key: stamp.to_string(), text: text.to_string() })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    use talos::core::http::{self, Method, Request};
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    let cfg = envelope.config;
    let base = base_of(cfg.base_url.as_deref().ok_or("Missing BASE_URL config")?)?;
    let auth = cfg
        .auth_header
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .ok_or("Missing AUTH_HEADER config")?;
    let entity = entity_of(cfg.entity.as_deref().ok_or("Missing ENTITY config")?)?;
    let now = cfg.now_ms.unwrap_or_else(now_ms);

    // No start time: the history API then answers for the last day.
    let req = Request {
        method: Method::Get,
        url: format!("{base}/api/history/period?filter_entity_id={entity}&minimal_response&no_attributes"),
        headers: vec![("Authorization".to_string(), auth.to_string())],
        body: Vec::new(),
        timeout_ms: Some(10_000),
    };
    let resp = http::fetch(&req).map_err(|e| format!("the phone replies could not be fetched: {e:?}"))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("Home Assistant answered {} for the reply history", resp.status));
    }
    let rows: Vec<Vec<State>> = serde_json::from_slice(&resp.body)
        .map_err(|e| format!("the reply history was not the expected shape: {e}"))?;

    let mut lines = Vec::new();
    let mut ignored = 0usize;
    for s in rows.iter().flatten() {
        match reply_of(&s.state) {
            Some(line) if line.order.saturating_add(WINDOW_MS) < now => ignored += 1,
            Some(line) => lines.push(line),
            None => ignored += 1,
        }
    }
    captured_output(SOURCE, lines, ignored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use talos_module_testkit::host;

    const NOW: u64 = 1_791_560_000_000;

    fn cfg() -> Value {
        json!({"BASE_URL": "https://home.example.test/", "AUTH_HEADER": "Bearer vault://homeassistant/token", "ENTITY": "input_text.made_up_capture", "NOW_MS": NOW})
    }
    fn run_with(config: Value) -> Result<Value, String> {
        run(json!({ "config": config }).to_string()).map(|out| serde_json::from_str(&out).unwrap())
    }
    fn history(states: &[String]) -> String {
        let rows: Vec<Value> = states.iter().map(|s| json!({"state": s, "last_changed": "2026-10-09T14:48:12+00:00"})).collect();
        json!([rows]).to_string()
    }
    fn at(minutes_ago: u64, text: &str) -> String {
        format!("{}|{text}", NOW - minutes_ago * 60_000)
    }

    #[test]
    fn replies_come_back_oldest_first_once_each_and_only_from_the_last_day() {
        host::http::respond(200, history(&[
            "unknown".to_string(),                        // the helper's first value
            at(27 * 60, "older than the window"),         // the carry-in, a day and more old
            at(90, "  book the\tcar \u{7} service  "),
            at(30, "want: an hour at the lake"),
            at(90, "book the car service"),               // the same reply read twice
            "hand edit with no stamp".to_string(),
            "123|too short to be a stamp".to_string(),
            format!("{}|", NOW - 1000),                   // a stamp and nothing typed
        ]));
        let out = run_with(cfg()).unwrap();
        assert_eq!((out["kind"].as_str(), out["source"].as_str(), out["count"].as_u64()), (Some("captured"), Some("phone"), Some(2)), "{out}");
        assert_eq!(out["captured"], json!([
            {"id": format!("phone:{}", NOW - 90 * 60_000), "text": "book the car service"},
            {"id": format!("phone:{}", NOW - 30 * 60_000), "text": "want: an hour at the lake"}]));
        // The helper's first value, the day-old carry-in, the hand edit, the short
    // stamp, the empty reply and the duplicate.
    assert_eq!(out["ignored"], 6, "{out}");

        // One GET, to the history of that one helper, with the reference and not a token.
        let reqs = host::http::requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, "https://home.example.test/api/history/period?filter_entity_id=input_text.made_up_capture&minimal_response&no_attributes");
        assert!(matches!(reqs[0].method, talos::core::http::Method::Get) && reqs[0].body.is_empty());
        assert_eq!(reqs[0].headers, vec![("Authorization".to_string(), "Bearer vault://homeassistant/token".to_string())]);
    }

    #[test]
    fn nothing_typed_is_an_empty_answer_and_a_long_day_keeps_the_newest() {
        host::http::respond(200, "[]");
        assert_eq!(run_with(cfg()).unwrap()["count"], 0);
        host::http::respond(200, history(&["unknown".to_string()]));
        let quiet = run_with(cfg()).unwrap();
        assert_eq!((quiet["count"].as_u64(), quiet["ignored"].as_u64()), (Some(0), Some(1)));

        let many: Vec<String> = (0..25).map(|i| at(100 - i, &format!("line {i}"))).collect();
        host::http::respond(200, history(&many));
        let out = run_with(cfg()).unwrap();
        assert_eq!((out["count"].as_u64(), out["ignored"].as_u64()), (Some(20), Some(5)));
        assert_eq!(out["captured"][0]["text"], "line 5");
        assert_eq!(out["captured"][19]["text"], "line 24");
        // A line is cut at 240 characters, on a character boundary.
        host::http::respond(200, history(&[at(5, &"é".repeat(250))]));
        assert_eq!(run_with(cfg()).unwrap()["captured"][0]["text"].as_str().unwrap().chars().count(), 240);
    }

    #[test]
    fn a_refusal_or_an_unexpected_answer_is_an_error_that_carries_no_body() {
        host::http::respond(401, r#"{"message": "secret detail"}"#);
        let err = run_with(cfg()).unwrap_err();
        assert!(err.contains("401") && !err.contains("secret detail"), "{err}");
        host::http::respond(200, r#"{"not": "a history"}"#);
        assert!(run_with(cfg()).unwrap_err().contains("not the expected shape"));
    }

    #[test]
    fn the_config_is_checked_before_anything_is_sent() {
        let mut c = cfg();
        for (key, value, want) in [
            ("BASE_URL", json!(null), "Missing BASE_URL"),
            ("BASE_URL", json!("http://home.example.test"), "must start with https://"),
            ("BASE_URL", json!("https://home.example.test/api"), "no path"),
            ("BASE_URL", json!("https://user@home.example.test"), "no path"),
            ("AUTH_HEADER", json!("  "), "Missing AUTH_HEADER"),
            ("ENTITY", json!(null), "Missing ENTITY"),
            ("ENTITY", json!("light.kitchen"), "must be an input_text helper"),
            ("ENTITY", json!("input_text.x&filter_entity_id=lock.front"), "lowercase letters"),
        ] {
            let kept = c[key].clone();
            c[key] = value;
            let err = run_with(c.clone()).unwrap_err();
            assert!(err.contains(want), "{key}: {err}");
            c[key] = kept;
        }
        assert!(host::http::requests().is_empty());
    }
}
