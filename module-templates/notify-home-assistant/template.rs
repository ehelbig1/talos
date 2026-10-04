// Notification adapter: Home Assistant companion app.
//
// One of the `notify-*` adapters. Each reads the SAME `notification` object
// from the node before it and delivers it through one service; switching
// service is swapping this module on the send node and setting that
// service's config. Nothing upstream changes. docs/notification-contract.md.
//
// What this adapter does with the contract (the companion app's documented
// notification format; written from that format and NOT exercised against a
// live server):
//   title, body      -> title, message
//   priority         -> high: data.priority "high" with data.ttl 0
//   link             -> data.clickAction (Android) and data.url (iOS)
//   actions          -> data.actions, each {action: "URI", title, uri}: the
//                       link is OPENED. one_tap is not available here — a
//                       background POST needs an automation inside Home
//                       Assistant — so one_tap_actions is always 0
//   tag              -> data.tag: a later message with the same tag replaces
//                       the earlier one
//
// DLP: logs counts only. An error names the host and the status, never the
// response body and never the notify service.

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

const PROVIDER: &str = "home-assistant";

#[derive(Deserialize, Default)]
struct Cfg {
    #[serde(rename = "BASE_URL", default)]
    base_url: Option<String>,
    #[serde(rename = "NOTIFY_SERVICE", default)]
    notify_service: Option<String>,
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
struct HaAction<'a> {
    action: &'static str,
    title: &'a str,
    uri: &'a str,
}

#[derive(Serialize)]
struct HaData<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    tag: Option<&'a str>,
    #[serde(rename = "clickAction", skip_serializing_if = "Option::is_none")]
    click_action: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    actions: Vec<HaAction<'a>>,
}

#[derive(Serialize)]
struct HaMessage<'a> {
    message: &'a str,
    #[serde(skip_serializing_if = "str::is_empty")]
    title: &'a str,
    data: HaData<'a>,
}

/// A notify service name as Home Assistant spells one (`mobile_app_pixel`).
/// It becomes a path segment, so nothing else is let through.
fn usable_service(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 80
        && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn ha_body(n: &Notification) -> Result<Vec<u8>, String> {
    let high = n.priority == Priority::High;
    let message = HaMessage {
        message: &n.body,
        title: &n.title,
        data: HaData {
            tag: n.tag.as_deref(),
            click_action: n.link.as_deref(),
            url: n.link.as_deref(),
            priority: high.then_some("high"),
            ttl: high.then_some(0),
            actions: n
                .actions
                .iter()
                .map(|a| HaAction {
                    action: "URI",
                    title: &a.title,
                    uri: &a.link,
                })
                .collect(),
        },
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
        cfg.base_url.as_deref().ok_or("Missing BASE_URL config (Home Assistant's external https:// address)")?,
        "BASE_URL",
    )?;
    let service = cfg
        .notify_service
        .as_deref()
        .ok_or("Missing NOTIFY_SERVICE config (for example mobile_app_<device>)")?;
    if !usable_service(service) {
        return Err("NOTIFY_SERVICE must be lowercase letters, digits and '_' (the part after 'notify.')".to_string());
    }
    let auth = cfg
        .auth_header
        .as_deref()
        .filter(|a| !a.trim().is_empty())
        .ok_or("Missing AUTH_HEADER config (expected 'Bearer vault://homeassistant/token')")?;
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
    verdict.link_sent = n.link.is_some();
    verdict.link_dropped = n.link_dropped;
    verdict.tag_sent = n.tag.is_some();

    logging::log(
        Level::Info,
        &format!(
            "notify-home-assistant: {} action(s), {} dropped, dry_run={}",
            verdict.actions_sent, verdict.actions_dropped, dry_run
        ),
    );
    if dry_run {
        return serde_json::to_string(&verdict).map_err(|e| e.to_string());
    }

    let req = talos::core::http::Request {
        method: talos::core::http::Method::Post,
        url: format!("{base}/api/services/notify/{service}"),
        headers: vec![
            ("Authorization".to_string(), auth.to_string()),
            ("Content-Type".to_string(), "application/json".to_string()),
        ],
        body: ha_body(&n)?,
        timeout_ms: Some(cfg.timeout_ms.unwrap_or(10_000).clamp(1_000, 30_000)),
    };
    let resp = talos::core::http::fetch(&req)
        .map_err(|_| format!("home-assistant: {} could not be reached", host_of(&base)))?;
    if !(200..300).contains(&resp.status) {
        return Err(format!("home-assistant: {} answered {}", host_of(&base), resp.status));
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
        json!({ "BASE_URL": "https://home.example.test", "NOTIFY_SERVICE": "mobile_app_made_up_phone", "AUTH_HEADER": "Bearer vault://homeassistant/token" })
    }
    fn note() -> Value {
        json!({
            "title": "Morning", "body": "Three things today.", "priority": "high",
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

    #[test]
    fn the_notification_is_sent_as_the_companion_app_expects_it() {
        host::http::respond(200, "[]");
        let v = send(config(), json!({ "notification": note() })).unwrap();
        assert_eq!((v["sent"].clone(), v["provider"].clone()), (json!(true), json!("home-assistant")));
        // The link is opened; this service has no background POST.
        assert_eq!((v["actions_sent"].clone(), v["one_tap_actions"].clone()), (json!(2), json!(0)));
        assert_eq!(v["tag_sent"], json!(true));

        let requests = host::http::requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].url,
            "https://home.example.test/api/services/notify/mobile_app_made_up_phone"
        );
        assert!(requests[0]
            .headers
            .iter()
            .any(|(k, v)| k == "Authorization" && v == "Bearer vault://homeassistant/token"));
        let body: Value = serde_json::from_slice(&requests[0].body).unwrap();
        assert_eq!(
            body,
            json!({
                "message": "Three things today.",
                "title": "Morning",
                "data": {
                    "tag": "morning",
                    "clickAction": "https://talos.example.test/today",
                    "url": "https://talos.example.test/today",
                    "priority": "high",
                    "ttl": 0,
                    "actions": [
                        { "action": "URI", "title": "Done", "uri": "https://talos.example.test/action-links/aaaa" },
                        { "action": "URI", "title": "Open list", "uri": "https://talos.example.test/list" },
                    ],
                },
            })
        );
    }

    #[test]
    fn a_plain_notification_carries_no_empty_fields() {
        host::http::respond(200, "[]");
        send(config(), json!({ "notification": { "body": "Just this." } })).unwrap();
        let body: Value = serde_json::from_slice(&host::http::requests()[0].body).unwrap();
        assert_eq!(body, json!({ "message": "Just this.", "data": {} }));
    }

    #[test]
    fn config_that_cannot_work_is_refused_before_anything_is_sent() {
        for (patch, why) in [
            (json!({ "BASE_URL": null }), "Missing BASE_URL"),
            (json!({ "BASE_URL": "http://192.168.1.50:8123" }), "https://"),
            (json!({ "NOTIFY_SERVICE": null }), "Missing NOTIFY_SERVICE"),
            (json!({ "NOTIFY_SERVICE": "mobile_app/../../config" }), "NOTIFY_SERVICE must be"),
            (json!({ "NOTIFY_SERVICE": "notify.mobile_app_phone" }), "NOTIFY_SERVICE must be"),
            (json!({ "AUTH_HEADER": null }), "Missing AUTH_HEADER"),
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
    fn a_refusal_names_the_host_and_the_status_and_nothing_else() {
        host::http::respond(401, r#"{"message":"token eyJ-made-up rejected"}"#);
        let e = send(config(), json!({ "notification": note() })).unwrap_err();
        assert_eq!(e, "home-assistant: home.example.test answered 401");
    }
}
