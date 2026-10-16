// gcp-alerting-evidence: reads, from ONE Google Cloud project, the facts the
// security alerting check needs:
//   * the project's Cloud Monitoring notification channels, each with its
//     type, whether it is enabled, its verification status, and, for an email
//     channel, a fingerprint of the address it sends to;
//   * the project's alerting policies, each with whether the node's selector
//     picks it out and, for one it picks, whether it is enabled and which
//     channels it names.
// It reads; every request is a GET, and the module is granted no other verb,
// so it cannot change the project whatever it is given.
//
// It judges nothing. It hands on evidence in the neutral shape
// `security-alerting-check` reads (`kind: "security_alerting_evidence"`), and
// a part it could not read is left out and named in `unread`, never handed on
// as empty: an empty list of channels means the project has none, and an
// empty list of policies that it has no alerting policy.
//
// Requests (GET):
//   monitoring.googleapis.com   the project's notification channels, page by page
//   monitoring.googleapis.com   the project's alerting policies, page by page
//
// `GET https://monitoring.googleapis.com/v3/projects/<project>/notificationChannels`
// (REST Resource: projects.notificationChannels, method list, read
// 2026-10-15): the answer's `notificationChannels` are "The notification
// channels defined for the specified project", and a non-empty
// `nextPageToken` means more may follow; it is given back as `pageToken`.
// An email channel's address is its `email_address` label ("Create and manage
// notification channels by API", "List the types of notification channels").
// A channel that does not say `enabled` is read as enabled: "Channels are
// enabled by default" (the same page, "Create a notification channel").
//
// `GET https://monitoring.googleapis.com/v3/projects/<project>/alertPolicies`
// (method list, read 2026-10-15) pages the same way. Of each policy
// (REST Resource: projects.alertPolicies, "Resource: AlertPolicy") only this
// is read: its name, its `displayName`, its `userLabels`, `enabled`, and
// `notificationChannels`, whose entries are
// "projects/[PROJECT_ID_OR_NUMBER]/notificationChannels/[CHANNEL_ID]" and each
// "corresponds to the name field" of a channel the channel listing returns.
// Its conditions, filters and documentation are never read: which policies
// are security alerts is the selector's to say, not this reader's.
// Of `enabled` the page says that on read "clients should not make any
// assumption about the state if it has not been populated", so a policy that
// does not say is handed on with `enabled: null`, for the check to leave
// undecided. A channel a policy names is handed on by its id; an entry not in
// that form is handed on as "", for the check to leave undecided too.
//
// The selector is the node's config, ALERT_POLICY_SELECTOR, one of
//   {"label": "<key>=<value>"}            a policy carrying that user label
//   {"display_name_prefix": "<prefix>"}   a policy whose display name starts so
// The label is written as the page says labels are: lower-case letters,
// numerals, underscores and dashes, a key beginning with a letter, each at
// most 63 characters. Without a selector, or with one that is not of this
// shape, no policy can be picked out: the policies are unread, and named so.
// A policy the selector does not pick is handed on by its id alone.
//
// No address is handed on. The security group's address (the node's config,
// SECURITY_GROUP_EMAIL) and each email channel's address are handed on as a
// fingerprint, `sha256:` and the SHA-256 of the address with the spaces round
// it removed and in lower case, so the evidence names nobody's mailbox and the
// check can still tell which channels send to the group. A fingerprint hides
// an address only from someone who does not already know it.
//
// What it hands on is bounded: at most 300 channels and 300 policies, each
// policy naming at most 50 channels, and at most 300,000 bytes as written (a
// third of the platform's 1,000,000-byte node input, since a shadow run's
// first node is given its trigger three times over). The parts are counted in
// the order they are read (channels, then policies), and one that would take
// the evidence over the bound is left out and named in `unread`, saying how
// large it is. More than the counts allow is the part unread: never cut.
//
// The token is a short-lived one for a read-only service account, named in
// the node's config as a vault reference; this module never sees it. The
// module is granted no token path until the owner names the account. It
// needs: monitoring.notificationChannels.list and monitoring.alertPolicies.list
// (both in roles/monitoring.viewer).

use serde::Deserialize;
use std::collections::BTreeMap;
use talos_sdk_macros::talos_module;

const MONITORING: &str = "https://monitoring.googleapis.com/v3";
/// More than these and the part is not read: a reader that cut them short would hand on half.
const MAX_CHANNELS: usize = 300;
const MAX_POLICIES: usize = 300;
const MAX_POLICY_CHANNELS: usize = 50;
const MAX_PAGES: usize = 4;
const PAGE_SIZE: usize = 100;
/// The most evidence this reader hands on, in bytes as written: a third of the platform's
/// 1,000,000-byte node input, since a workflow's first node is given its trigger three times.
const MAX_EVIDENCE_BYTES: usize = 300_000;
/// What the evidence holds besides its parts (kind, project, the group's fingerprint, the
/// selector, unread, errors), set aside before any part is counted. The tests measure the most it can be.
const ENVELOPE_BYTES: usize = 4_000;

/// What the evidence takes so far, in bytes as written, against `MAX_EVIDENCE_BYTES`.
struct Budget {
    used: usize,
}
impl Budget {
    fn new() -> Self {
        Budget { used: ENVELOPE_BYTES }
    }
    /// A part, counted, when it fits in what is left; otherwise nothing is counted and the error says how large it is.
    fn take(&mut self, subject: &str, part: serde_json::Value) -> Result<serde_json::Value, String> {
        let size = part.to_string().len();
        if self.used + size > MAX_EVIDENCE_BYTES {
            return Err(format!("{subject} too large to hand on ({size} bytes as written; the evidence is at most {MAX_EVIDENCE_BYTES} bytes in all)"));
        }
        self.used += size;
        Ok(part)
    }
}

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
}
#[derive(Deserialize, Default)]
struct Config {
    /// "Bearer " and a vault reference to the reader account's access token.
    #[serde(rename = "AUTH_HEADER")]
    auth_header: Option<String>,
    /// The project to read, by id.
    #[serde(rename = "PROJECT")]
    project: Option<String>,
    /// The security group's email address. Handed on only as its fingerprint.
    #[serde(rename = "SECURITY_GROUP_EMAIL")]
    security_group: Option<String>,
    /// Which alerting policies are the security alerts: read by `selector`, never by serde, so a
    /// selector of the wrong shape is a reason the policies are unread, not a failed run.
    #[serde(rename = "ALERT_POLICY_SELECTOR")]
    selector: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
struct Channels {
    #[serde(default, rename = "notificationChannels")]
    channels: Vec<Channel>,
    #[serde(default, rename = "nextPageToken")]
    next: String,
}
#[derive(Deserialize)]
struct Channel {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "type")]
    kind: String,
    #[serde(default)]
    labels: BTreeMap<String, String>,
    /// Unset is enabled: "Channels are enabled by default."
    enabled: Option<bool>,
    #[serde(default, rename = "verificationStatus")]
    verification: String,
}

#[derive(Deserialize, Default)]
struct Policies {
    #[serde(default, rename = "alertPolicies")]
    policies: Vec<Policy>,
    #[serde(default, rename = "nextPageToken")]
    next: String,
}
#[derive(Deserialize)]
struct Policy {
    #[serde(default)]
    name: String,
    #[serde(default, rename = "displayName")]
    display: String,
    #[serde(default, rename = "userLabels")]
    labels: BTreeMap<String, String>,
    /// Unset is unknown: "clients should not make any assumption about the state if it has not been populated".
    enabled: Option<bool>,
    #[serde(default, rename = "notificationChannels")]
    channels: Vec<String>,
}

/// Which policies are the security alerts, as the node's config says.
#[derive(Debug, PartialEq)]
enum Selector {
    Label(String, String),
    Prefix(String),
}
impl Selector {
    fn picks(&self, p: &Policy) -> bool {
        match self {
            Selector::Label(key, value) => p.labels.get(key) == Some(value),
            Selector::Prefix(prefix) => p.display.starts_with(prefix.as_str()),
        }
    }
    /// How the evidence says which selector picked the policies.
    fn described(&self) -> serde_json::Value {
        match self {
            Selector::Label(key, value) => serde_json::json!({ "label": format!("{key}={value}") }),
            Selector::Prefix(prefix) => serde_json::json!({ "display_name_prefix": prefix }),
        }
    }
}
/// A label key or value as the page says they are written: lower-case letters, numerals,
/// underscores and dashes, at most 63 characters; a key begins with a letter.
fn label_part_ok(s: &str, key: bool) -> bool {
    s.len() <= 63 && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-') && (!key || s.as_bytes().first().is_some_and(u8::is_ascii_lowercase))
}
/// The selector in the node's config, or why there is none to use.
fn selector(given: Option<&serde_json::Value>) -> Result<Selector, String> {
    const SHAPE: &str = "ALERT_POLICY_SELECTOR must be {\"label\": \"<key>=<value>\"} or {\"display_name_prefix\": \"<prefix>\"}";
    let given = given.ok_or("no ALERT_POLICY_SELECTOR in the node's config, so no alerting policy is picked out")?;
    let one = given.as_object().filter(|o| o.len() == 1).ok_or(SHAPE)?;
    match one.iter().next() {
        Some((k, serde_json::Value::String(label))) if k == "label" => match label.split_once('=') {
            Some((key, value)) if label_part_ok(key, true) && label_part_ok(value, false) => Ok(Selector::Label(key.to_string(), value.to_string())),
            _ => Err(SHAPE.to_string()),
        },
        Some((k, serde_json::Value::String(prefix))) if k == "display_name_prefix" && !prefix.trim().is_empty() && prefix.chars().count() <= 100 && !prefix.chars().any(char::is_control) => Ok(Selector::Prefix(prefix.clone())),
        _ => Err(SHAPE.to_string()),
    }
}

/// A project id as Google writes one: it goes into request paths.
fn project_ok(s: &str) -> bool {
    (6..=30).contains(&s.len()) && s.as_bytes()[0].is_ascii_lowercase() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
/// An email address plainly written: one `@`, something on each side, a dot in the domain, no space.
fn address_ok(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else { return false };
    (3..=254).contains(&s.len()) && !local.is_empty() && domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.') && !domain.contains('@') && s.chars().all(|c| c.is_ascii_graphic())
}
/// How an address is handed on and compared: `sha256:` and the SHA-256, in hex, of the
/// address with the spaces round it removed and in lower case.
fn address_hash(address: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(address.trim().to_lowercase().as_bytes());
    format!("sha256:{}", digest.iter().map(|b| format!("{b:02x}")).collect::<String>())
}
fn shown(s: &str, max: usize) -> String {
    s.chars().filter(|c| !c.is_control()).take(max).collect()
}
/// The last part of a resource name, when it is a plain id.
fn last(name: &str) -> Option<&str> {
    name.rsplit('/').next().filter(|s| !s.is_empty() && s.len() <= 100 && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b)))
}
/// The id of the channel a policy names, when the entry is in the form the page gives:
/// projects/[PROJECT_ID_OR_NUMBER]/notificationChannels/[CHANNEL_ID]. "" otherwise.
fn named_channel(entry: &str) -> &str {
    match entry.split('/').collect::<Vec<_>>().as_slice() {
        ["projects", project, "notificationChannels", id] if !project.is_empty() && last(id) == Some(*id) => id,
        _ => "",
    }
}
/// A page token goes back into a query: only what Google issues.
fn token_ok(t: &str) -> bool {
    t.len() <= 2000 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_=+/.".contains(&b))
}
fn pct(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// One GET. The status and the kind of failure are kept; no body of an error is.
fn get(auth: &str, url: &str) -> Result<Vec<u8>, String> {
    use talos::core::http::{self, Method, Request};
    let req = Request { method: Method::Get, url: url.to_string(), headers: vec![("Authorization".to_string(), auth.to_string()), ("Accept".to_string(), "application/json".to_string())], body: Vec::new(), timeout_ms: Some(20_000) };
    let resp = http::fetch(&req).map_err(|e| format!("could not be reached ({e:?})"))?;
    match resp.status {
        200..=299 => Ok(resp.body),
        other => Err(format!("answered HTTP {other}")),
    }
}

/// Every page of a listing, as far as `MAX_PAGES`; `each` takes a page's rows and says
/// whether there are too many. A listing longer than that is an error: half a listing is not the listing.
fn pages<T: for<'de> Deserialize<'de>>(auth: &str, base: &str, what: &str, next: fn(&T) -> &str, mut each: impl FnMut(&T) -> Result<(), String>) -> Result<(), String> {
    let mut token = String::new();
    for page in 0.. {
        if page == MAX_PAGES {
            return Err(format!("{what} runs to more than {MAX_PAGES} pages; this reader would be cutting it short"));
        }
        let query = if token.is_empty() { String::new() } else { format!("&pageToken={}", pct(&token)) };
        let listed: T = serde_json::from_slice(&get(auth, &format!("{base}?pageSize={PAGE_SIZE}{query}")).map_err(|e| format!("{what} {e}"))?).map_err(|_| format!("{what} answered with something that could not be read"))?;
        each(&listed)?;
        let following = next(&listed);
        if following.is_empty() {
            break;
        }
        if !token_ok(following) {
            return Err(format!("{what} gave a page token that could not be used"));
        }
        token = following.to_string();
    }
    Ok(())
}

/// Every notification channel of the project, page by page, in the shape the check reads.
fn read_channels(auth: &str, project: &str) -> Result<Vec<serde_json::Value>, String> {
    let what = "the notification channel listing";
    let mut rows: Vec<serde_json::Value> = Vec::new();
    pages::<Channels>(auth, &format!("{MONITORING}/projects/{project}/notificationChannels"), what, |l| &l.next, |listed| {
        for c in &listed.channels {
            let id = last(&c.name).ok_or_else(|| format!("{what} gave a channel whose name could not be read"))?;
            let mut row = serde_json::json!({ "id": id, "type": shown(&c.kind, 60), "enabled": c.enabled.unwrap_or(true), "verification": shown(&c.verification, 40) });
            // Only an email channel's address is looked at, and only its fingerprint is handed on.
            if c.kind == "email" {
                row["address"] = c.labels.get("email_address").map(|a| a.trim()).filter(|a| !a.is_empty()).map(address_hash).unwrap_or_default().into();
            }
            rows.push(row);
        }
        if rows.len() > MAX_CHANNELS {
            return Err(format!("the project has more than {MAX_CHANNELS} notification channels; this reader would be cutting them short"));
        }
        Ok(())
    })?;
    Ok(rows)
}

/// Every alerting policy of the project, page by page, in the shape the check reads: a policy
/// the selector picks with what the check needs of it, any other by its id alone.
fn read_policies(auth: &str, project: &str, selector: &Selector) -> Result<Vec<serde_json::Value>, String> {
    let what = "the alerting policy listing";
    let mut rows: Vec<serde_json::Value> = Vec::new();
    pages::<Policies>(auth, &format!("{MONITORING}/projects/{project}/alertPolicies"), what, |l| &l.next, |listed| {
        for p in &listed.policies {
            let id = last(&p.name).ok_or_else(|| format!("{what} gave a policy whose name could not be read"))?;
            if !selector.picks(p) {
                rows.push(serde_json::json!({ "id": id, "selected": false }));
                continue;
            }
            if p.channels.len() > MAX_POLICY_CHANNELS {
                return Err(format!("an alerting policy names more than {MAX_POLICY_CHANNELS} notification channels; this reader would be cutting them short"));
            }
            let display: String = p.display.chars().filter(|c| c.is_alphanumeric() || " -_.:/()".contains(*c)).take(100).collect();
            rows.push(serde_json::json!({ "id": id, "selected": true, "name": display, "enabled": p.enabled, "channels": p.channels.iter().map(|c| named_channel(c)).collect::<Vec<_>>() }));
        }
        if rows.len() > MAX_POLICIES {
            return Err(format!("the project has more than {MAX_POLICIES} alerting policies; this reader would be cutting them short"));
        }
        Ok(())
    })?;
    Ok(rows)
}

/// The evidence, from what each read gave. A part that could not be read, or that would take the
/// evidence over `MAX_EVIDENCE_BYTES`, is left out and named in `unread`.
fn evidence(project: &str, security_group: &str, selector: Option<&Selector>, channels: Result<Vec<serde_json::Value>, String>, policies: Result<Vec<serde_json::Value>, String>) -> serde_json::Value {
    let mut out = serde_json::json!({ "kind": "security_alerting_evidence", "project": project, "security_group": address_hash(security_group) });
    if let Some(s) = selector {
        out["alert_selector"] = s.described();
    }
    let mut unread: Vec<&str> = Vec::new();
    let mut errors = serde_json::Map::new();
    let mut budget = Budget::new();
    for (part, subject, read) in [("channels", "the notification channels are", channels), ("policies", "the alerting policies are", policies)] {
        match read.and_then(|rows| budget.take(subject, rows.into())) {
            Ok(rows) => out[part] = rows,
            Err(e) => {
                unread.push(part);
                errors.insert(part.to_string(), e.into());
            }
        }
    }
    out["unread"] = unread.into();
    out["errors"] = errors.into();
    out
}

#[talos_module(world = "http-node")]
pub fn run(input: String) -> Result<String, String> {
    let cfg = serde_json::from_str::<Envelope>(&input).map_err(|e| format!("Input parse error: {e}"))?.config;
    let auth = cfg.auth_header.filter(|a| !a.trim().is_empty()).ok_or("Missing AUTH_HEADER config")?;
    let project = cfg.project.as_deref().map(str::trim).filter(|p| project_ok(p)).ok_or("PROJECT must be a project id (lower-case letters, digits and dashes)")?.to_string();
    let group = cfg.security_group.as_deref().map(str::trim).filter(|a| address_ok(a)).ok_or("SECURITY_GROUP_EMAIL must be the security group's email address")?.to_string();
    let chosen = selector(cfg.selector.as_ref());
    let channels = read_channels(&auth, &project);
    // Without a selector no policy can be picked out, so none is asked for.
    let policies = chosen.as_ref().map_err(String::clone).and_then(|s| read_policies(&auth, &project, s));
    serde_json::to_string(&evidence(&project, &group, chosen.as_ref().ok(), channels, policies)).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};
use talos::core::http::Method;
use talos_module_testkit::host;

const P: &str = "example-np";
const GROUP: &str = "security-team@example.com";

fn config() -> Value {
    json!({"AUTH_HEADER": "Bearer vault://gcp/impersonated/reader@example-np.iam.gserviceaccount.com/access_token", "PROJECT": P, "SECURITY_GROUP_EMAIL": GROUP, "ALERT_POLICY_SELECTOR": {"label": "security-control=true"}})
}
fn read() -> Result<Value, String> {
    run(json!({"config": config()}).to_string()).map(|o| serde_json::from_str(&o).unwrap())
}
/// Four channels: the group's email channel, another person's (disabled), a Slack channel, and an
/// email channel whose address is written in another letter case with spaces round it.
fn channels() -> Value {
    json!({"notificationChannels": [
        {"type": "email", "name": "projects/example-np/notificationChannels/1111", "displayName": "Security", "labels": {"email_address": "security-team@example.com"}, "enabled": true, "verificationStatus": "VERIFICATION_STATUS_UNSPECIFIED"},
        {"type": "email", "name": "projects/example-np/notificationChannels/2222", "displayName": "On call", "labels": {"email_address": "oncall@example.com"}, "enabled": false},
        {"type": "slack", "name": "projects/example-np/notificationChannels/3333", "labels": {"channel_name": "#alerts"}, "verificationStatus": "VERIFIED"},
        {"type": "email", "name": "projects/example-np/notificationChannels/4444", "labels": {"email_address": " Security-Team@Example.COM "}}
    ], "totalSize": 4})
}
/// The channel listing answered with `body`; the alerting policy listing with none.
fn cloud(status: u16, body: Value) {
    channels_by(move |_| (status, body.clone()));
}
/// The channel listing answered by `answer`; the alerting policy listing with none.
fn channels_by(answer: impl Fn(&str) -> (u16, Value) + 'static) {
    host::http::respond_with(move |req| {
        let (status, body) = if req.url.contains("/alertPolicies") { (200, json!({})) } else { answer(&req.url) };
        Ok(host::http::response(status, body.to_string()))
    });
}
/// The channel listing answered with `channels()`; the alerting policy listing by `answer`.
fn policies_by(answer: impl Fn(&str) -> (u16, Value) + 'static) {
    host::http::respond_with(move |req| {
        let (status, body) = if req.url.contains("/alertPolicies") { answer(&req.url) } else { (200, channels()) };
        Ok(host::http::response(status, body.to_string()))
    });
}
fn channel_requests() -> usize {
    host::http::requests().iter().filter(|r| r.url.contains("/notificationChannels")).count()
}
/// Three alerting policies: two security alerts (one labelled, one in name only), and another.
fn policies() -> Value {
    json!({"alertPolicies": [
        {"name": "projects/example-np/alertPolicies/7001", "displayName": "Security: IAM policy changed <b>", "userLabels": {"security-control": "true", "team": "platform"}, "enabled": true,
         "notificationChannels": ["projects/example-np/notificationChannels/1111", "projects/123456789012/notificationChannels/3333", "not a channel"],
         "documentation": {"content": "Page the on-call person at oncall@example.com"}, "conditions": [{"displayName": "IAM change", "conditionMatchedLog": {"filter": "protoPayload.methodName=\"SetIamPolicy\""}}]},
        {"name": "projects/example-np/alertPolicies/7002", "displayName": "Security: firewall changed", "userLabels": {"security-control": "false"}, "enabled": false, "notificationChannels": ["projects/example-np/notificationChannels/2222"]},
        {"name": "projects/example-np/alertPolicies/7003", "displayName": "CPU high", "userLabels": {"security-control": "true"}, "notificationChannels": []}
    ], "totalSize": 3})
}
fn hash(address: &str) -> String {
    address_hash(address)
}

#[test]
fn the_channels_are_read_with_a_get_in_the_shape_the_check_reads_and_no_address_is_handed_on() {
    cloud(200, channels());
    let out = read().unwrap();
    assert_eq!((out["kind"].as_str(), out["project"].as_str(), out["unread"].clone(), out["errors"].clone()), (Some("security_alerting_evidence"), Some(P), json!([]), json!({})));
    assert_eq!(out["security_group"], json!(hash(GROUP)));
    assert_eq!(out["channels"], json!([
        {"id": "1111", "type": "email", "enabled": true, "verification": "VERIFICATION_STATUS_UNSPECIFIED", "address": hash(GROUP)},
        {"id": "2222", "type": "email", "enabled": false, "verification": "", "address": hash("oncall@example.com")},
        // Not an email channel: no address of any kind is looked at.
        {"id": "3333", "type": "slack", "enabled": true, "verification": "VERIFIED"},
        // Letter case and spaces round an address do not make it another address.
        {"id": "4444", "type": "email", "enabled": true, "verification": "", "address": hash(GROUP)},
    ]));
    let text = out.to_string();
    for name in ["security-team", "oncall", "example.com", "#alerts", "Security", "On call"] {
        assert!(!text.contains(name), "{name} was handed on");
    }
    let seen = host::http::requests();
    assert_eq!(seen.len(), 2);
    assert!(seen.iter().all(|r| r.method == Method::Get));
    assert_eq!(seen[0].url, format!("https://monitoring.googleapis.com/v3/projects/{P}/notificationChannels?pageSize=100"));
    assert_eq!(seen[1].url, format!("https://monitoring.googleapis.com/v3/projects/{P}/alertPolicies?pageSize=100"));
}

#[test]
fn the_fingerprint_is_the_sha256_of_the_trimmed_lower_case_address() {
    // printf 'security-team@example.com' | shasum -a 256
    assert_eq!(address_hash("security-team@example.com"), "sha256:48ddc227211d8cacd2496f5ab2bb796ed1173a434d5ddb4d818ec1918113bb90");
    assert_eq!(address_hash(" Security-Team@EXAMPLE.com\n"), address_hash("security-team@example.com"));
    assert_ne!(address_hash("security-team@example.com"), address_hash("security-team@example.org"));
    let h = address_hash("a@b.example");
    assert!(h.starts_with("sha256:") && h.len() == 7 + 64 && h[7..].bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)), "{h}");
}

#[test]
fn a_listing_that_could_not_be_read_is_left_out_and_named_and_no_error_body_is_kept() {
    cloud(403, json!({"error": {"message": "secret-looking detail"}}));
    let out = read().unwrap();
    assert!(out.get("channels").is_none(), "{out}");
    assert_eq!((out["unread"].clone(), out["errors"]["channels"].clone()), (json!(["channels"]), json!("the notification channel listing answered HTTP 403")));
    assert!(!out.to_string().contains("secret-looking"));
    // The group's fingerprint is handed on all the same: it is the node's config, not something read.
    assert_eq!(out["security_group"], json!(hash(GROUP)));
}

#[test]
fn a_network_failure_keeps_its_kind() {
    // No responder: every request fails as a network error would.
    let out = read().unwrap();
    let why = out["errors"]["channels"].as_str().unwrap();
    assert!(why.starts_with("the notification channel listing could not be reached (") && why.to_lowercase().contains("network"), "{why}");
}

#[test]
fn an_empty_listing_is_a_fact_and_an_unreadable_one_is_unread() {
    for empty in [json!({}), json!({"notificationChannels": [], "nextPageToken": ""})] {
        cloud(200, empty);
        let out = read().unwrap();
        assert_eq!((out["channels"].clone(), out["unread"].clone()), (json!([]), json!([])));
    }
    for bad in [json!("not an object"), json!({"notificationChannels": [{"name": 7}]}), json!({"notificationChannels": [{"name": "projects/p/notificationChannels/1", "labels": {"email_address": 7}}]}), json!({"notificationChannels": [{"name": "projects/p/notificationChannels/1", "enabled": "yes"}]}), json!({"notificationChannels": [], "nextPageToken": 3})] {
        cloud(200, bad.clone());
        let out = read().unwrap();
        assert_eq!((out["unread"].clone(), out["errors"]["channels"].clone()), (json!(["channels"]), json!("the notification channel listing answered with something that could not be read")), "{bad}");
    }
    host::http::respond_with(|_| Ok(host::http::response(200, "not json")));
    assert_eq!(read().unwrap()["unread"], json!(["channels", "policies"]));
}

#[test]
fn a_channel_whose_name_cannot_be_read_makes_the_listing_unread() {
    for name in ["", "projects/example-np/notificationChannels/", "projects/example-np/notificationChannels/1 2"] {
        cloud(200, json!({"notificationChannels": [{"type": "email", "name": name, "labels": {"email_address": GROUP}}]}));
        let out = read().unwrap();
        assert_eq!((out["unread"].clone(), out["errors"]["channels"].clone()), (json!(["channels"]), json!("the notification channel listing gave a channel whose name could not be read")), "{name:?}");
    }
}

#[test]
fn an_email_channel_without_an_address_is_handed_on_saying_none() {
    cloud(200, json!({"notificationChannels": [{"type": "email", "name": "projects/example-np/notificationChannels/9", "labels": {}}, {"type": "email", "name": "projects/example-np/notificationChannels/8", "labels": {"email_address": "  "}}]}));
    let out = read().unwrap();
    assert_eq!(out["channels"], json!([
        {"id": "9", "type": "email", "enabled": true, "verification": "", "address": ""},
        {"id": "8", "type": "email", "enabled": true, "verification": "", "address": ""},
    ]));
}

fn page(start: usize, n: usize, token: &str) -> Value {
    json!({"notificationChannels": (start..start + n).map(|i| json!({"type": "email", "name": format!("projects/example-np/notificationChannels/{i}"), "labels": {"email_address": format!("person{i}@example.com")}})).collect::<Vec<_>>(), "nextPageToken": token})
}

#[test]
fn the_channels_are_read_page_by_page_and_a_listing_too_long_to_hand_on_whole_is_unread() {
    channels_by(|url| (200, if url.ends_with("&pageToken=tok%2Fen%3D1") { page(2, 1, "") } else { page(0, 2, "tok/en=1") }));
    let out = read().unwrap();
    assert_eq!(out["channels"].as_array().unwrap().iter().map(|c| c["id"].as_str().unwrap()).collect::<Vec<_>>(), ["0", "1", "2"]);
    assert_eq!(host::http::requests()[1].url, format!("https://monitoring.googleapis.com/v3/projects/{P}/notificationChannels?pageSize=100&pageToken=tok%2Fen%3D1"));
    // A listing that never ends is cut off at its last page and handed on as unread.
    channels_by(|_| (200, json!({"notificationChannels": [], "nextPageToken": "more"})));
    let before = channel_requests();
    let out = read().unwrap();
    assert_eq!(out["unread"], json!(["channels"]));
    assert_eq!(out["errors"]["channels"], json!("the notification channel listing runs to more than 4 pages; this reader would be cutting it short"));
    assert_eq!(channel_requests() - before, MAX_PAGES);
    // Exactly as many pages as are read is the whole listing.
    let asked = std::rc::Rc::new(std::cell::Cell::new(0usize));
    let counter = asked.clone();
    channels_by(move |_| {
        counter.set(counter.get() + 1);
        (200, json!({"notificationChannels": [], "nextPageToken": if counter.get() < MAX_PAGES { "more" } else { "" }}))
    });
    assert_eq!(read().unwrap()["channels"], json!([]));
    // A page token that is not one Google issues is not sent back.
    cloud(200, json!({"notificationChannels": [], "nextPageToken": "a b"}));
    let out = read().unwrap();
    assert_eq!(out["errors"]["channels"], json!("the notification channel listing gave a page token that could not be used"));
}

#[test]
fn more_channels_than_can_be_handed_on_are_unread_and_as_many_are_handed_on() {
    cloud(200, page(0, MAX_CHANNELS + 1, ""));
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["errors"]["channels"].clone()), (json!(["channels"]), json!("the project has more than 300 notification channels; this reader would be cutting them short")));
    cloud(200, page(0, MAX_CHANNELS, ""));
    assert_eq!(read().unwrap()["channels"].as_array().unwrap().len(), MAX_CHANNELS);
}

#[test]
fn the_most_it_can_hand_on_fits_in_what_a_node_is_given_three_times() {
    // As many channels as are handed on, each with its longest id, type and status, an address, and the longest project.
    let wide = "😀";
    let rows: Vec<Value> = (0..MAX_CHANNELS).map(|i| json!({"type": "email", "name": format!("projects/p/notificationChannels/{i:03}{}", "9".repeat(97)), "labels": {"email_address": "x@example.com"}, "enabled": false, "verificationStatus": wide.repeat(40)})).collect();
    let mut long_type = rows.clone();
    for r in long_type.iter_mut() {
        r["type"] = json!(wide.repeat(60));
    }
    for rows in [rows, long_type] {
        cloud(200, json!({"notificationChannels": rows}));
        let out = run(json!({"config": {"AUTH_HEADER": "Bearer x", "PROJECT": "a".repeat(30), "SECURITY_GROUP_EMAIL": GROUP, "ALERT_POLICY_SELECTOR": {"label": "security-control=true"}}}).to_string()).unwrap();
        assert!(out.len() <= MAX_EVIDENCE_BYTES, "{} bytes", out.len());
        assert_eq!(serde_json::from_str::<Value>(&out).unwrap()["unread"], json!([]));
    }
}

#[test]
fn the_config_must_name_a_token_a_plain_project_and_the_groups_address() {
    let with = |config: Value| run(json!({"config": config}).to_string()).unwrap_err();
    assert_eq!(with(json!({"PROJECT": P, "SECURITY_GROUP_EMAIL": GROUP})), "Missing AUTH_HEADER config");
    assert_eq!(with(json!({"AUTH_HEADER": " ", "PROJECT": P, "SECURITY_GROUP_EMAIL": GROUP})), "Missing AUTH_HEADER config");
    for project in ["", "Example-NP", "example-np/../other", "ex"] {
        assert_eq!(with(json!({"AUTH_HEADER": "Bearer x", "PROJECT": project, "SECURITY_GROUP_EMAIL": GROUP})), "PROJECT must be a project id (lower-case letters, digits and dashes)", "{project}");
    }
    for address in [json!(null), json!(""), json!("security-team"), json!("security team@example.com"), json!("@example.com"), json!("security-team@example"), json!("security-team@.example.com"), json!("a@b@example.com")] {
        let mut c = config();
        c["SECURITY_GROUP_EMAIL"] = address.clone();
        assert_eq!(with(c), "SECURITY_GROUP_EMAIL must be the security group's email address", "{address}");
    }
    assert!(host::http::requests().is_empty());
    // An address with spaces round it is the address.
    let mut c = config();
    c["SECURITY_GROUP_EMAIL"] = json!("  security-team@example.com ");
    cloud(200, channels());
    let out: Value = serde_json::from_str(&run(json!({"config": c}).to_string()).unwrap()).unwrap();
    assert_eq!(out["security_group"], json!(hash(GROUP)));
}

#[test]
fn what_it_hands_on_is_judged_by_the_check() {
    // The two modules in a row: the group has two email channels here (1111 and 4444), so the check finds a duplicate.
    // The security alert names 1111 and 3333, and an entry that is not a channel: whether it reaches a dead one is undecided.
    policies_by(|_| (200, policies()));
    let out = read().unwrap();
    let judged: Value = serde_json::from_str(&crate::security_alerting_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    let found: Vec<&str> = judged["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap()).collect();
    assert_eq!(found, ["security-group-channel-duplicated"], "{judged}");
    assert_eq!(judged["not_assessed"], json!(["alert-misses-security-group", "alert-names-undelivering-channel"]));
    // With that entry gone, and the label off the policy that does not say whether it is enabled, the alert names
    // the group's channel and a working one: both alert rules pass.
    let mut readable = policies();
    readable["alertPolicies"][0]["notificationChannels"].as_array_mut().unwrap().pop();
    readable["alertPolicies"][2]["userLabels"] = json!({});
    policies_by(move |_| (200, readable.clone()));
    let out = read().unwrap();
    let judged: Value = serde_json::from_str(&crate::security_alerting_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!(judged["not_assessed"], json!([]), "{judged}");
    assert!(judged["passed"].as_array().unwrap().contains(&json!("alert-misses-security-group")) && judged["passed"].as_array().unwrap().contains(&json!("alert-names-undelivering-channel")), "{judged}");
    // An unread listing leaves every rule not assessed: never a pass.
    cloud(500, json!({}));
    let out = read().unwrap();
    let judged: Value = serde_json::from_str(&crate::security_alerting_check::run(json!({"input": out}).to_string()).unwrap()).unwrap();
    assert_eq!((judged["clean"].clone(), judged["passed"].clone(), judged["not_assessed"].as_array().unwrap().len()), (json!(false), json!([]), 5));
}

// ------------------------------------------------------------- the alerting policies

#[test]
fn the_policies_are_read_with_a_get_and_only_what_the_rules_need_is_handed_on() {
    policies_by(|_| (200, policies()));
    let out = read().unwrap();
    assert_eq!((out["unread"].clone(), out["alert_selector"].clone()), (json!([]), json!({"label": "security-control=true"})));
    assert_eq!(out["policies"], json!([
        // Picked by its label: its id, its name in plain characters, whether it is enabled, the ids of the channels it names
        // ("" for an entry that is not one); the project in an entry is not kept.
        {"id": "7001", "selected": true, "name": "Security: IAM policy changed b", "enabled": true, "channels": ["1111", "3333", ""]},
        // Not picked: its id alone.
        {"id": "7002", "selected": false},
        // Picked, and the API did not say whether it is enabled: handed on as not said.
        {"id": "7003", "selected": true, "name": "CPU high", "enabled": null, "channels": []},
    ]));
    let text = out.to_string();
    for never in ["oncall", "SetIamPolicy", "IAM change", "documentation", "conditions", "platform", "firewall"] {
        assert!(!text.contains(never), "{never} was handed on");
    }
}

#[test]
fn a_display_name_prefix_picks_the_policies_whose_name_starts_with_it() {
    let mut c = config();
    c["ALERT_POLICY_SELECTOR"] = json!({"display_name_prefix": "Security: "});
    policies_by(|_| (200, policies()));
    let out: Value = serde_json::from_str(&run(json!({"config": c}).to_string()).unwrap()).unwrap();
    let picked: Vec<(&str, bool)> = out["policies"].as_array().unwrap().iter().map(|p| (p["id"].as_str().unwrap(), p["selected"].as_bool().unwrap())).collect();
    assert_eq!(picked, [("7001", true), ("7002", true), ("7003", false)]);
    assert_eq!(out["alert_selector"], json!({"display_name_prefix": "Security: "}));
    // A name that has the prefix inside it, not at its start, is not picked.
    let mut c = config();
    c["ALERT_POLICY_SELECTOR"] = json!({"display_name_prefix": "Security: "});
    policies_by(|_| (200, json!({"alertPolicies": [{"name": "projects/p/alertPolicies/7004", "displayName": "Old Security: login alert"}]})));
    let out: Value = serde_json::from_str(&run(json!({"config": c}).to_string()).unwrap()).unwrap();
    assert_eq!(out["policies"], json!([{"id": "7004", "selected": false}]));
    policies_by(|_| (200, policies()));
    // The prefix is compared as written: letter case counts.
    let mut c = config();
    c["ALERT_POLICY_SELECTOR"] = json!({"display_name_prefix": "security: "});
    let out: Value = serde_json::from_str(&run(json!({"config": c}).to_string()).unwrap()).unwrap();
    assert!(out["policies"].as_array().unwrap().iter().all(|p| p["selected"] == json!(false)));
}

#[test]
fn without_a_usable_selector_no_policy_is_asked_for_and_the_policies_are_unread() {
    for (selector, why) in [
        (Value::Null, "no ALERT_POLICY_SELECTOR in the node's config, so no alerting policy is picked out"),
        (json!("security-control=true"), "ALERT_POLICY_SELECTOR must be {\"label\": \"<key>=<value>\"} or {\"display_name_prefix\": \"<prefix>\"}"),
        (json!({}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"label": "security-control"}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"label": "Security=true"}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"label": "1security=true"}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"label": "security=True"}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"label": format!("{}=x", "k".repeat(64))}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"label": format!("k={}", "v".repeat(64))}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"label": "=true"}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"label": 7}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"display_name_prefix": "  "}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"display_name_prefix": "x".repeat(101)}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"display_name_prefix": "Sec\nurity"}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"label": "a=b", "display_name_prefix": "x"}), "ALERT_POLICY_SELECTOR must be"),
        (json!({"labels": "a=b"}), "ALERT_POLICY_SELECTOR must be"),
    ] {
        let mut c = config();
        if selector.is_null() {
            c.as_object_mut().unwrap().remove("ALERT_POLICY_SELECTOR");
        } else {
            c["ALERT_POLICY_SELECTOR"] = selector.clone();
        }
        policies_by(|_| (200, policies()));
        let before = host::http::requests().len();
        let out: Value = serde_json::from_str(&run(json!({"config": c}).to_string()).unwrap()).unwrap();
        assert_eq!((out["unread"].clone(), out.get("policies"), out.get("alert_selector")), (json!(["policies"]), None, None), "{selector}");
        assert!(out["errors"]["policies"].as_str().unwrap().starts_with(why), "{selector}: {}", out["errors"]);
        // The channels are read all the same; the policies are not asked for.
        assert_eq!(out["channels"].as_array().unwrap().len(), 4);
        assert!(host::http::requests()[before..].iter().all(|r| !r.url.contains("/alertPolicies")), "{selector}");
    }
    // The longest of each form is taken, and an empty label value is a value.
    for selector in [json!({"label": format!("k{}={}", "k".repeat(62), "v".repeat(63))}), json!({"label": "security-control="}), json!({"display_name_prefix": "x".repeat(100)}), json!({"label": "sec_ctl-2=on_1"})] {
        let mut c = config();
        c["ALERT_POLICY_SELECTOR"] = selector.clone();
        let out: Value = serde_json::from_str(&run(json!({"config": c}).to_string()).unwrap()).unwrap();
        assert_eq!(out["unread"], json!([]), "{selector}");
    }
}

#[test]
fn a_policy_listing_that_could_not_be_read_is_unread_and_no_error_body_is_kept() {
    policies_by(|_| (403, json!({"error": {"message": "secret-looking detail"}})));
    let out = read().unwrap();
    assert!(out.get("policies").is_none());
    assert_eq!((out["unread"].clone(), out["errors"]["policies"].clone()), (json!(["policies"]), json!("the alerting policy listing answered HTTP 403")));
    assert!(!out.to_string().contains("secret-looking"));
    assert_eq!(out["channels"].as_array().unwrap().len(), 4);
    for bad in [json!("x"), json!({"alertPolicies": [{"name": 7}]}), json!({"alertPolicies": [{"name": "projects/p/alertPolicies/1", "enabled": "yes"}]}), json!({"alertPolicies": [{"name": "projects/p/alertPolicies/1", "userLabels": {"security-control": true}}]}), json!({"alertPolicies": [{"name": "projects/p/alertPolicies/1", "notificationChannels": [7]}]}), json!({"alertPolicies": null})] {
        policies_by(move |_| (200, bad.clone()));
        let out = read().unwrap();
        assert_eq!((out["unread"].clone(), out["errors"]["policies"].clone()), (json!(["policies"]), json!("the alerting policy listing answered with something that could not be read")));
    }
    for name in ["", "projects/p/alertPolicies/", "projects/p/alertPolicies/7 1"] {
        policies_by(move |_| (200, json!({"alertPolicies": [{"name": name, "userLabels": {"security-control": "true"}}]})));
        assert_eq!(read().unwrap()["errors"]["policies"], json!("the alerting policy listing gave a policy whose name could not be read"), "{name:?}");
    }
    // An empty listing is a fact.
    policies_by(|_| (200, json!({})));
    assert_eq!((read().unwrap()["policies"].clone(), read().unwrap()["unread"].clone()), (json!([]), json!([])));
}

fn policy_page(start: usize, n: usize, token: &str) -> Value {
    json!({"alertPolicies": (start..start + n).map(|i| json!({"name": format!("projects/example-np/alertPolicies/{i}"), "userLabels": {"security-control": "true"}, "enabled": true, "notificationChannels": ["projects/example-np/notificationChannels/1111"]})).collect::<Vec<_>>(), "nextPageToken": token})
}

#[test]
fn the_policies_are_read_page_by_page_and_more_than_can_be_handed_on_is_unread() {
    policies_by(|url| (200, if url.ends_with("&pageToken=next%2F1") { policy_page(2, 1, "") } else { policy_page(0, 2, "next/1") }));
    let out = read().unwrap();
    assert_eq!(out["policies"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap()).collect::<Vec<_>>(), ["0", "1", "2"]);
    assert_eq!(host::http::requests().last().unwrap().url, format!("https://monitoring.googleapis.com/v3/projects/{P}/alertPolicies?pageSize=100&pageToken=next%2F1"));
    policies_by(|_| (200, json!({"alertPolicies": [], "nextPageToken": "more"})));
    assert_eq!(read().unwrap()["errors"]["policies"], json!("the alerting policy listing runs to more than 4 pages; this reader would be cutting it short"));
    policies_by(|_| (200, json!({"alertPolicies": [], "nextPageToken": "a b"})));
    assert_eq!(read().unwrap()["errors"]["policies"], json!("the alerting policy listing gave a page token that could not be used"));
    policies_by(|_| (200, policy_page(0, MAX_POLICIES + 1, "")));
    assert_eq!(read().unwrap()["errors"]["policies"], json!("the project has more than 300 alerting policies; this reader would be cutting them short"));
    policies_by(|_| (200, policy_page(0, MAX_POLICIES, "")));
    assert_eq!(read().unwrap()["policies"].as_array().unwrap().len(), MAX_POLICIES);
    // A policy naming more channels than are handed on is the listing unread; as many is handed on.
    let naming = |n: usize| json!({"alertPolicies": [{"name": "projects/p/alertPolicies/1", "userLabels": {"security-control": "true"}, "notificationChannels": (0..n).map(|i| format!("projects/p/notificationChannels/{i}")).collect::<Vec<_>>()}]});
    policies_by(move |_| (200, naming(MAX_POLICY_CHANNELS + 1)));
    assert_eq!(read().unwrap()["errors"]["policies"], json!("an alerting policy names more than 50 notification channels; this reader would be cutting them short"));
    policies_by(move |_| (200, naming(MAX_POLICY_CHANNELS)));
    assert_eq!(read().unwrap()["policies"][0]["channels"].as_array().unwrap().len(), MAX_POLICY_CHANNELS);
    // A policy the selector does not pick is not counted against what it names.
    policies_by(move |_| {
        let mut many = naming(MAX_POLICY_CHANNELS + 1);
        many["alertPolicies"][0]["userLabels"] = json!({});
        (200, many)
    });
    assert_eq!(read().unwrap()["policies"], json!([{"id": "1", "selected": false}]));
}

#[test]
fn a_channel_entry_is_read_only_in_the_form_the_page_gives() {
    assert_eq!(named_channel("projects/example-np/notificationChannels/1111"), "1111");
    assert_eq!(named_channel("projects/123456789012/notificationChannels/1111"), "1111");
    for odd in ["1111", "notificationChannels/1111", "projects//notificationChannels/1111", "projects/p/notificationChannels/", "projects/p/notificationChannels/11 11", "projects/p/alertPolicies/1111", "projects/p/notificationChannels/1111/x", "x/projects/p/notificationChannels/1111"] {
        assert_eq!(named_channel(odd), "", "{odd}");
    }
}

#[test]
fn the_policies_are_counted_after_the_channels_and_a_part_too_large_is_left_out_never_cut() {
    // As many policies as are read, each naming as many channels as it may, each id as long as it may be.
    let wide = |i: usize| json!({"name": format!("projects/p/alertPolicies/{i:03}{}", "9".repeat(97)), "displayName": "😀".repeat(200), "userLabels": {"security-control": "true"}, "enabled": true,
                               "notificationChannels": (0..MAX_POLICY_CHANNELS).map(|c| format!("projects/p/notificationChannels/{c:02}{}", "8".repeat(98))).collect::<Vec<_>>()});
    policies_by(move |_| (200, json!({"alertPolicies": (0..MAX_POLICIES).map(wide).collect::<Vec<_>>()})));
    let out = run(json!({"config": config()}).to_string()).unwrap();
    assert!(out.len() <= MAX_EVIDENCE_BYTES, "{} bytes", out.len());
    let out: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(out["unread"], json!(["policies"]));
    assert!(out["errors"]["policies"].as_str().unwrap().starts_with("the alerting policies are too large to hand on ("), "{}", out["errors"]);
    assert_eq!(out["channels"].as_array().unwrap().len(), 4);
    // Exactly the room left takes the part; a byte less does not.
    let mut b = Budget::new();
    let part = json!(["x".repeat(MAX_EVIDENCE_BYTES - ENVELOPE_BYTES - 4)]);
    assert_eq!(part.to_string().len(), MAX_EVIDENCE_BYTES - ENVELOPE_BYTES);
    assert!(b.take("it is", part).is_ok());
    assert!(b.take("it is", json!(0)).is_err());
    // What the evidence holds besides its parts, with both unread and the longest errors and selector, fits in what is set aside.
    let envelope = json!({"kind": "security_alerting_evidence", "project": "a".repeat(30), "security_group": hash(GROUP), "alert_selector": {"display_name_prefix": "😀".repeat(100)},
                          "unread": ["channels", "policies"], "errors": {"channels": "😀".repeat(200), "policies": "😀".repeat(200)}});
    assert!(envelope.to_string().len() <= ENVELOPE_BYTES, "{}", envelope.to_string().len());
}
}
