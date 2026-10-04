// Notification adapter: ntfy (https://ntfy.sh, or a server you run).
//
// One of the `notify-*` adapters. Each reads the SAME `notification` object
// from the node before it and delivers it through one service; switching
// service is swapping this module on the send node and setting that
// service's config. Nothing upstream changes. docs/notification-contract.md.
//
// What ntfy does with the contract:
//   title, body      -> title, message
//   priority         -> 2 (low) / 3 (normal) / 4 (high)
//   link             -> click
//   actions          -> "view" (opens the link), or "http" with POST for an
//                       action marked one_tap: the phone POSTs to the link in
//                       the background, so a Talos action link acts on one tap
//   tag              -> not sent (this adapter does not replace an earlier
//                       message)
//
// DLP: logs counts only. An error names the host and the status, never the
// response body and never the topic.

use serde::{Deserialize, Serialize};
use talos_sdk_macros::talos_module;

// ── notification contract ───────────────────────────────────────────────────
// This block is IDENTICAL in every `notify-*` adapter, byte for byte, and
// `talos-catalog-tests/tests/notification_contract.rs` fails if two copies
// differ. It is what makes the adapters interchangeable: a workflow composes
// a `notification` once, and which service delivers it is the send node's
// module and config, nothing upstream. See docs/notification-contract.md.

const MAX_TITLE_CHARS: usize = 120;
const MAX_BODY_CHARS: usize = 1500;
const MAX_ACTIONS: usize = 3;
const MAX_ACTION_TITLE_CHARS: usize = 40;
const MAX_URL_BYTES: usize = 2000;
const MAX_TAG_BYTES: usize = 64;

#[derive(Deserialize)]
struct RawNotification {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    body: Option<String>,
    #[serde(default)]
    priority: Option<String>,
    #[serde(default)]
    tag: Option<String>,
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    actions: Vec<RawAction>,
}

#[derive(Deserialize)]
struct RawAction {
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    link: Option<String>,
    #[serde(default)]
    one_tap: bool,
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Priority {
    Low,
    Normal,
    High,
}

struct Action {
    title: String,
    link: String,
    /// The phone may act on this without opening a browser, where the
    /// service can. The link must then be one that acts on a POST.
    one_tap: bool,
}

struct Notification {
    title: String,
    body: String,
    priority: Priority,
    tag: Option<String>,
    link: Option<String>,
    actions: Vec<Action>,
    /// Actions asked for and not sent: no title, a link that is not https,
    /// or past the limit.
    actions_dropped: usize,
    /// A top-level link was given and was not usable.
    link_dropped: bool,
}

/// One line: control characters become spaces, runs of whitespace collapse.
fn clean_line(s: &str, max_chars: usize) -> String {
    let flat: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    cut(&flat.split_whitespace().collect::<Vec<_>>().join(" "), max_chars)
}

/// Text that keeps its line breaks and loses every other control character.
fn clean_text(s: &str, max_chars: usize) -> String {
    let kept: String = s
        .chars()
        .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
        .collect();
    cut(kept.trim(), max_chars)
}

fn cut(s: &str, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max_chars.saturating_sub(1)).collect();
    out.push('\u{2026}');
    out
}

/// A link a phone may open or POST to: https, bounded, and one token of
/// printable ASCII. Anything else is not sent — a link is where a
/// single-use capability travels, and plain http would carry it in the clear.
fn usable_link(s: &str) -> Option<String> {
    let s = s.trim();
    (s.len() > "https://".len()
        && s.len() <= MAX_URL_BYTES
        && s.starts_with("https://")
        && s.bytes().all(|b| b.is_ascii_graphic()))
    .then(|| s.to_string())
}

fn usable_tag(s: &str) -> Option<String> {
    (!s.is_empty()
        && s.len() <= MAX_TAG_BYTES
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.'))
    .then(|| s.to_string())
}

/// Read the upstream node's `notification`. `Ok(None)` is "nothing to send"
/// (`skip: true`). A missing notification, an empty body or an unknown
/// priority is an error: sending something other than what was composed is
/// worse than sending nothing and saying so.
fn check_notification(
    raw: Option<RawNotification>,
    skip: Option<bool>,
) -> Result<Option<Notification>, String> {
    if skip == Some(true) {
        return Ok(None);
    }
    let raw = raw.ok_or(
        "No notification to send: the upstream node's output has no `notification` object (docs/notification-contract.md)",
    )?;
    let body = clean_text(raw.body.as_deref().unwrap_or(""), MAX_BODY_CHARS);
    if body.is_empty() {
        return Err("The notification has no `body`".to_string());
    }
    let priority = match raw.priority.as_deref() {
        None | Some("normal") => Priority::Normal,
        Some("low") => Priority::Low,
        Some("high") => Priority::High,
        Some(other) => {
            return Err(format!(
                "The notification's `priority` must be low, normal or high; got '{}'",
                clean_line(other, 20)
            ))
        }
    };
    let asked = raw.actions.len();
    let actions: Vec<Action> = raw
        .actions
        .into_iter()
        .filter_map(|a| {
            let title = clean_line(a.title.as_deref().unwrap_or(""), MAX_ACTION_TITLE_CHARS);
            let link = usable_link(a.link.as_deref().unwrap_or(""))?;
            (!title.is_empty()).then_some(Action {
                title,
                link,
                one_tap: a.one_tap,
            })
        })
        .take(MAX_ACTIONS)
        .collect();
    let link = raw.link.as_deref().and_then(usable_link);
    Ok(Some(Notification {
        title: clean_line(raw.title.as_deref().unwrap_or(""), MAX_TITLE_CHARS),
        body,
        priority,
        tag: raw.tag.as_deref().and_then(usable_tag),
        link_dropped: raw.link.is_some() && link.is_none(),
        link,
        actions_dropped: asked - actions.len(),
        actions,
    }))
}

/// What every adapter returns, in the same words, so a workflow that reads
/// the result does not change when the service does.
#[derive(Serialize)]
struct Verdict {
    provider: &'static str,
    sent: bool,
    skipped: bool,
    dry_run: bool,
    /// The service's HTTP status; absent when nothing was sent.
    status: Option<u16>,
    actions_sent: usize,
    actions_dropped: usize,
    /// Actions delivered as a background POST rather than a link to open.
    one_tap_actions: usize,
    link_sent: bool,
    link_dropped: bool,
    tag_sent: bool,
}

/// An https base address with no query or fragment, without its trailing `/`.
fn usable_base(s: &str, name: &str) -> Result<String, String> {
    let link = usable_link(s)
        .filter(|l| !l.contains('?') && !l.contains('#'))
        .ok_or_else(|| format!("{name} must be an https:// address with no query"))?;
    Ok(link.trim_end_matches('/').to_string())
}

/// The host of an https address, for an error that names where and not what.
fn host_of(base: &str) -> &str {
    base.trim_start_matches("https://")
        .split('/')
        .next()
        .unwrap_or("")
}
// ── end notification contract ───────────────────────────────────────────────

const PROVIDER: &str = "ntfy";

#[derive(Deserialize, Default)]
struct Cfg {
    #[serde(rename = "SERVER_URL", default)]
    server_url: Option<String>,
    #[serde(rename = "TOPIC", default)]
    topic: Option<String>,
    #[serde(rename = "AUTH_HEADER", default)]
    auth_header: Option<String>,
    #[serde(rename = "DRY_RUN", default)]
    dry_run: Option<bool>,
    #[serde(rename = "TIMEOUT_MS", default)]
    timeout_ms: Option<u32>,
}

#[derive(Deserialize)]
struct Incoming {
    #[serde(default)]
    config: Cfg,
    #[serde(default)]
    notification: Option<RawNotification>,
    #[serde(default)]
    skip: Option<bool>,
}

#[derive(Serialize)]
struct NtfyAction<'a> {
    action: &'static str,
    label: &'a str,
    url: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'static str>,
    clear: bool,
}

#[derive(Serialize)]
struct NtfyMessage<'a> {
    topic: &'a str,
    message: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    title: &'a str,
    priority: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    click: Option<&'a str>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    actions: Vec<NtfyAction<'a>>,
}

fn usable_topic(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn ntfy_body(topic: &str, n: &Notification) -> Result<Vec<u8>, String> {
    let message = NtfyMessage {
        topic,
        message: &n.body,
        title: &n.title,
        priority: match n.priority {
            Priority::Low => 2,
            Priority::Normal => 3,
            Priority::High => 4,
        },
        click: n.link.as_deref(),
        actions: n
            .actions
            .iter()
            .map(|a| NtfyAction {
                action: if a.one_tap { "http" } else { "view" },
                label: &a.title,
                url: &a.link,
                method: a.one_tap.then_some("POST"),
                clear: true,
            })
            .collect(),
    };
    serde_json::to_vec(&message).map_err(|e| format!("could not build the message: {e}"))
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    use talos::core::logging::{self, Level};

    let incoming: Incoming = serde_json::from_str(&input)
        .map_err(|e| format!("could not read the node input: {e}"))?;
    let cfg = incoming.config;
    let base = usable_base(
        cfg.server_url.as_deref().ok_or("Missing SERVER_URL config (the ntfy server's https:// address)")?,
        "SERVER_URL",
    )?;
    let topic = cfg.topic.as_deref().ok_or("Missing TOPIC config")?;
    if !usable_topic(topic) {
        return Err("TOPIC must be 1 to 64 letters, digits, '_' or '-'".to_string());
    }
    let dry_run = cfg.dry_run.unwrap_or(false);

    let mut verdict = Verdict {
        provider: PROVIDER,
        sent: false,
        skipped: false,
        dry_run,
        status: None,
        actions_sent: 0,
        actions_dropped: 0,
        one_tap_actions: 0,
        link_sent: false,
        link_dropped: false,
        tag_sent: false,
    };
    let Some(n) = check_notification(incoming.notification, incoming.skip)? else {
        verdict.skipped = true;
        return serde_json::to_string(&verdict).map_err(|e| e.to_string());
    };
    verdict.actions_sent = n.actions.len();
    verdict.actions_dropped = n.actions_dropped;
    verdict.one_tap_actions = n.actions.iter().filter(|a| a.one_tap).count();
    verdict.link_sent = n.link.is_some();
    verdict.link_dropped = n.link_dropped;

    logging::log(
        Level::Info,
        &format!(
            "notify-ntfy: {} action(s), {} dropped, dry_run={}",
            verdict.actions_sent, verdict.actions_dropped, dry_run
        ),
    );
    if dry_run {
        return serde_json::to_string(&verdict).map_err(|e| e.to_string());
    }

    let mut headers = vec![("Content-Type".to_string(), "application/json".to_string())];
    if let Some(auth) = cfg.auth_header.as_deref().filter(|a| !a.trim().is_empty()) {
        headers.push(("Authorization".to_string(), auth.to_string()));
    }
    let req = talos::core::http::Request {
        method: talos::core::http::Method::Post,
        url: format!("{base}/"),
        headers,
        body: ntfy_body(topic, &n)?,
        timeout_ms: Some(cfg.timeout_ms.unwrap_or(10_000).clamp(1_000, 30_000)),
    };
    let resp = talos::core::http::fetch(&req)
        .map_err(|_| format!("ntfy: {} could not be reached", host_of(&base)))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("ntfy: {} answered {}", host_of(&base), resp.status));
    }
    verdict.sent = true;
    verdict.status = Some(resp.status);
    serde_json::to_string(&verdict).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use talos_module_testkit::host;

    fn config() -> Value {
        json!({ "SERVER_URL": "https://ntfy.example.test/", "TOPIC": "made-up-topic", "AUTH_HEADER": "Bearer vault://ntfy/token" })
    }
    fn note() -> Value {
        json!({
            "title": "Morning", "body": "Three things today.\nFirst: call the dentist.", "priority": "high",
            "tag": "morning", "link": "https://talos.example.test/today",
            "actions": [
                { "title": "Done", "link": "https://talos.example.test/action-links/aaaa", "one_tap": true },
                { "title": "Open list", "link": "https://talos.example.test/list" },
            ],
        })
    }
    fn send(config: Value, upstream: Value) -> Result<Value, String> {
        let mut input = upstream;
        input["config"] = config;
        run(input.to_string()).map(|s| serde_json::from_str(&s).unwrap())
    }
    fn sent_body() -> Value {
        let requests = host::http::requests();
        assert_eq!(requests.len(), 1, "one request");
        serde_json::from_slice(&requests[0].body).unwrap()
    }

    #[test]
    fn the_notification_is_sent_as_ntfy_expects_it() {
        host::http::respond(200, "{}");
        let v = send(config(), json!({ "notification": note() })).unwrap();
        assert_eq!(v["sent"], json!(true));
        assert_eq!((v["provider"].clone(), v["status"].clone()), (json!("ntfy"), json!(200)));
        assert_eq!((v["actions_sent"].clone(), v["one_tap_actions"].clone()), (json!(2), json!(1)));
        assert_eq!(v["tag_sent"], json!(false), "ntfy does not replace by tag");

        let request = &host::http::requests()[0];
        assert_eq!(request.url, "https://ntfy.example.test/");
        assert!(request
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer vault://ntfy/token"));
        let body = sent_body();
        assert_eq!(body["topic"], json!("made-up-topic"));
        assert_eq!(body["title"], json!("Morning"));
        assert_eq!(body["message"], json!("Three things today.\nFirst: call the dentist."));
        assert_eq!(body["priority"], json!(4));
        assert_eq!(body["click"], json!("https://talos.example.test/today"));
        // One tap: the phone POSTs. Otherwise the link is opened.
        assert_eq!(
            body["actions"][0],
            json!({ "action": "http", "label": "Done", "url": "https://talos.example.test/action-links/aaaa", "method": "POST", "clear": true })
        );
        assert_eq!(
            body["actions"][1],
            json!({ "action": "view", "label": "Open list", "url": "https://talos.example.test/list", "clear": true })
        );
    }

    #[test]
    fn a_link_that_is_not_https_is_never_sent() {
        host::http::respond(200, "{}");
        let mut n = note();
        n["link"] = json!("http://talos.example.test/today");
        n["actions"] = json!([
            { "title": "Dead", "link": "#" },
            { "title": "Mail", "link": "mailto:me@example.com" },
            { "title": "", "link": "https://talos.example.test/x" },
            { "title": "Kept", "link": "https://talos.example.test/kept" },
        ]);
        let v = send(config(), json!({ "notification": n })).unwrap();
        assert_eq!((v["actions_sent"].clone(), v["actions_dropped"].clone()), (json!(1), json!(3)));
        assert_eq!((v["link_sent"].clone(), v["link_dropped"].clone()), (json!(false), json!(true)));
        let body = sent_body();
        assert!(body.get("click").is_none(), "{body}");
        assert_eq!(body["actions"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn nothing_is_sent_for_skip_or_a_dry_run_and_a_missing_notification_is_an_error() {
        let v = send(config(), json!({ "skip": true, "notification": note() })).unwrap();
        assert_eq!((v["skipped"].clone(), v["sent"].clone()), (json!(true), json!(false)));
        let mut dry = config();
        dry["DRY_RUN"] = json!(true);
        let v = send(dry, json!({ "notification": note() })).unwrap();
        assert_eq!((v["dry_run"].clone(), v["sent"].clone(), v["actions_sent"].clone()), (json!(true), json!(false), json!(2)));
        assert!(host::http::requests().is_empty());

        assert!(send(config(), json!({})).unwrap_err().contains("no `notification` object"));
        assert!(send(config(), json!({ "notification": { "title": "t", "body": "  " } }))
            .unwrap_err()
            .contains("no `body`"));
        assert!(send(config(), json!({ "notification": { "body": "b", "priority": "urgent" } }))
            .unwrap_err()
            .contains("low, normal or high"));
        assert!(host::http::requests().is_empty());
    }

    #[test]
    fn a_refusal_names_the_host_and_the_status_and_nothing_else() {
        host::http::respond(403, r#"{"error":"topic made-up-topic forbidden for token tk_secret"}"#);
        let e = send(config(), json!({ "notification": note() })).unwrap_err();
        assert_eq!(e, "ntfy: ntfy.example.test answered 403");
    }

    #[test]
    fn config_that_cannot_work_is_refused_before_anything_is_sent() {
        for (patch, why) in [
            (json!({ "SERVER_URL": null }), "Missing SERVER_URL"),
            (json!({ "SERVER_URL": "http://ntfy.example.test" }), "https://"),
            (json!({ "SERVER_URL": "https://ntfy.example.test/?x=1" }), "no query"),
            (json!({ "TOPIC": null }), "Missing TOPIC"),
            (json!({ "TOPIC": "bad topic" }), "TOPIC must be"),
        ] {
            let mut c = config();
            for (k, v) in patch.as_object().unwrap() {
                c[k] = v.clone();
            }
            let e = send(c, json!({ "notification": note() })).unwrap_err();
            assert!(e.contains(why), "{patch}: {e}");
        }
        assert!(host::http::requests().is_empty());
    }

    #[test]
    fn long_text_is_cut_and_extra_actions_are_counted() {
        host::http::respond(200, "{}");
        let actions: Vec<Value> = (0..5)
            .map(|i| json!({ "title": format!("A{i}"), "link": format!("https://talos.example.test/{i}") }))
            .collect();
        let v = send(
            config(),
            json!({ "notification": { "title": "t".repeat(300), "body": "é".repeat(4000), "actions": actions } }),
        )
        .unwrap();
        assert_eq!((v["actions_sent"].clone(), v["actions_dropped"].clone()), (json!(3), json!(2)));
        let body = sent_body();
        assert_eq!(body["title"].as_str().unwrap().chars().count(), 120);
        assert_eq!(body["message"].as_str().unwrap().chars().count(), 1500);
    }
}
