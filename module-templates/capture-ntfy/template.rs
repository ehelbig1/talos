// Capture adapter: ntfy (lines published to an inbox topic).
//
// One of the `capture-*` adapters. Each reads lines the owner typed somewhere
// other than mail and returns them in the SAME neutral `captured` shape, so
// what keeps the lines (a list, a journal) never learns which service they
// came from. docs/capture-contract.md.
//
// How the lines get here: the owner opens an inbox topic in the ntfy app and
// types a line, or shares text to it from any app. This module reads what the
// topic holds for the last WINDOW_SECS with ONE GET
// (`/<topic>/json?poll=1&since=<unix seconds>`, newline-delimited JSON). The
// server's message id is the line's identity, so a line read on two runs is
// the same line. The server must keep messages at least that long
// (`cache-duration`; ntfy's default is 12 h, so set 48h on your server).
//
// A token is REQUIRED. A capture topic anyone can publish to is a way for
// anyone to put lines on your list, so this adapter refuses to read one
// without AUTH_HEADER, and the server should deny anonymous access.
//
// It never publishes or deletes anything. An error names the status, never
// the response body.

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

/// Every line this adapter returns was typed on a phone.
const SOURCE: &str = "phone";
/// How far back each run reads.
const WINDOW_SECS: u64 = 26 * 60 * 60;

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
}

/// The node's config. Every key is optional here and checked in `run`, so a
/// missing one is reported by name instead of as a parse error.
#[derive(Deserialize, Default)]
struct Config {
    /// The ntfy server's https:// address, with no path.
    #[serde(rename = "SERVER_URL")]
    server_url: Option<String>,
    /// The inbox topic: 1 to 64 letters, digits, '_' or '-'.
    #[serde(rename = "TOPIC")]
    topic: Option<String>,
    /// `Bearer vault://ntfy/token`: the host replaces the reference when it sends.
    #[serde(rename = "AUTH_HEADER")]
    auth_header: Option<String>,
    /// The clock, in epoch milliseconds, for a rehearsal or a test.
    #[serde(rename = "NOW_MS")]
    now_ms: Option<u64>,
}

/// One line of the poll answer. Everything else in it is skipped.
#[derive(Deserialize)]
struct Event {
    #[serde(default)]
    event: String,
    #[serde(default)]
    id: String,
    #[serde(default)]
    time: u64,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    title: Option<String>,
}

fn server_of(raw: &str) -> Result<String, String> {
    let base = raw.trim().trim_end_matches('/');
    let host = base.strip_prefix("https://").ok_or("SERVER_URL must start with https://")?;
    if host.is_empty() || host.contains(|c: char| c == '/' || c == '?' || c == '#' || c == '@' || c.is_whitespace()) {
        return Err("SERVER_URL must be https://<host> with no path, query or credentials".to_string());
    }
    Ok(base.to_string())
}

fn topic_of(raw: &str) -> Result<&str, String> {
    let t = raw.trim();
    if t.is_empty() || t.len() > 64 || !t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-') {
        return Err("TOPIC must be 1 to 64 letters, digits, '_' or '-'".to_string());
    }
    Ok(t)
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
    let server = server_of(cfg.server_url.as_deref().ok_or("Missing SERVER_URL config")?)?;
    let topic = topic_of(cfg.topic.as_deref().ok_or("Missing TOPIC config")?)?;
    let auth = cfg
        .auth_header
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
        .ok_or("Missing AUTH_HEADER config: a capture topic is read with a token, never open")?;
    let since = (cfg.now_ms.unwrap_or_else(now_ms) / 1000).saturating_sub(WINDOW_SECS);

    let req = Request {
        method: Method::Get,
        url: format!("{server}/{topic}/json?poll=1&since={since}"),
        headers: vec![("Authorization".to_string(), auth.to_string())],
        body: Vec::new(),
        timeout_ms: Some(10_000),
    };
    let resp = http::fetch(&req).map_err(|e| format!("the inbox could not be fetched: {e:?}"))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("the ntfy server answered {} for the inbox", resp.status));
    }
    let body = std::str::from_utf8(&resp.body).map_err(|_| "the inbox answer was not text".to_string())?;

    let mut lines = Vec::new();
    let mut ignored = 0usize;
    for raw in body.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let e: Event = serde_json::from_str(raw).map_err(|e| format!("the inbox answer was not the expected shape: {e}"))?;
        if e.event != "message" || e.time < since {
            ignored += 1;
            continue;
        }
        let text = e.message.filter(|m| !m.trim().is_empty()).or(e.title).unwrap_or_default();
        lines.push(RawLine { order: e.time, key: e.id, text });
    }
    captured_output(SOURCE, lines, ignored)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use talos_module_testkit::host;

    const NOW: u64 = 1_791_560_000_000;
    const NOW_S: u64 = NOW / 1000;

    fn cfg() -> Value {
        json!({"SERVER_URL": "https://ntfy.example.test/", "TOPIC": "made-up-inbox", "AUTH_HEADER": "Bearer vault://ntfy/token", "NOW_MS": NOW})
    }
    fn run_with(config: Value) -> Result<Value, String> {
        run(json!({ "config": config }).to_string()).map(|out| serde_json::from_str(&out).unwrap())
    }
    fn msg(id: &str, ago_s: u64, text: &str) -> String {
        json!({"id": id, "time": NOW_S - ago_s, "event": "message", "topic": "made-up-inbox", "message": text}).to_string()
    }

    #[test]
    fn lines_come_back_oldest_first_once_each_and_only_from_the_window() {
        let body = [
            msg("aaaaaaaaaaa2", 600, "  call the\tdentist \u{7} "),
            msg("aaaaaaaaaaa1", 3600, "want: an hour at the lake"),
            json!({"id": "kkkkkkkkkkkk", "time": NOW_S, "event": "keepalive", "topic": "made-up-inbox"}).to_string(),
            msg("aaaaaaaaaaa2", 600, "call the dentist"),
            msg("aaaaaaaaaaa3", 27 * 3600, "older than the window"),
            json!({"id": "aaaaaaaaaaa4", "time": NOW_S - 60, "event": "message", "title": "only a title"}).to_string(),
            msg("aaaaaaaaaaa5", 30, "   "),
        ]
        .join("\n");
        host::http::respond(200, body);
        let out = run_with(cfg()).unwrap();
        assert_eq!(
            out["captured"],
            json!([
                {"id": "phone:aaaaaaaaaaa1", "text": "want: an hour at the lake"},
                {"id": "phone:aaaaaaaaaaa2", "text": "call the dentist"},
                {"id": "phone:aaaaaaaaaaa4", "text": "only a title"},
            ]),
            "{out}"
        );
        // The keepalive, the line older than the window, the duplicate and the blank one.
        assert_eq!((out["count"].clone(), out["ignored"].clone()), (json!(3), json!(4)), "{out}");

        // One GET for the topic's last day, with the reference and not a token.
        let reqs = host::http::requests();
        assert_eq!(reqs.len(), 1);
        assert_eq!(reqs[0].url, format!("https://ntfy.example.test/made-up-inbox/json?poll=1&since={}", NOW_S - WINDOW_SECS));
        assert!(matches!(reqs[0].method, talos::core::http::Method::Get) && reqs[0].body.is_empty());
        assert_eq!(reqs[0].headers, vec![("Authorization".to_string(), "Bearer vault://ntfy/token".to_string())]);
    }

    #[test]
    fn an_empty_inbox_is_an_empty_answer() {
        host::http::respond(200, "");
        let out = run_with(cfg()).unwrap();
        assert_eq!((out["count"].clone(), out["captured"].clone(), out["ignored"].clone()), (json!(0), json!([]), json!(0)));
    }

    #[test]
    fn a_refusal_or_a_broken_answer_is_an_error_that_carries_no_body() {
        host::http::respond(403, r#"{"code":40301,"error":"forbidden secret detail"}"#);
        let err = run_with(cfg()).unwrap_err();
        assert!(err.contains("403") && !err.contains("secret detail"), "{err}");
        // A corrupt line is an error, not a quietly shorter list.
        host::http::respond(200, format!("{}\n{{not json", msg("aaaaaaaaaaa1", 60, "x")));
        assert!(run_with(cfg()).unwrap_err().contains("not the expected shape"));
    }

    #[test]
    fn the_config_is_checked_before_anything_is_sent_and_a_token_is_required() {
        let mut c = cfg();
        for (key, value, want) in [
            ("SERVER_URL", json!(null), "Missing SERVER_URL"),
            ("SERVER_URL", json!("http://ntfy.example.test"), "must start with https://"),
            ("SERVER_URL", json!("https://ntfy.example.test/made-up-inbox"), "no path"),
            ("SERVER_URL", json!("https://user@ntfy.example.test"), "no path"),
            ("TOPIC", json!(null), "Missing TOPIC"),
            ("TOPIC", json!("inbox/../admin"), "TOPIC must be"),
            ("TOPIC", json!("x".repeat(65)), "TOPIC must be"),
            ("AUTH_HEADER", json!(null), "never open"),
            ("AUTH_HEADER", json!("  "), "never open"),
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
