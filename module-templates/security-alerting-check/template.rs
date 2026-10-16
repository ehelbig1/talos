// security-alerting-check: judges ONE Google Cloud project's security
// alerting from evidence a reader collected, by fixed rules. One project is
// one environment: each environment's project is judged by a run of its own.
// It reads its input and calls nothing: no cloud, no network, no model.
//
// What it judges: that the project has exactly one email notification
// channel for the security group, and that the channel delivers (it is
// enabled, and not waiting to be verified); and that every enabled alerting
// policy the node's selector picks out as a security alert names the group's
// channel, and names no channel that is missing from the project, disabled or
// unverified. A policy may name other channels as well as the group's, never
// instead of it. Which policies are security alerts is the selector's to say
// (a label on the policy, else a prefix of its display name, set in the
// reader's config); a policy's conditions are never read, and whether the
// right changes are watched is not judged. Nor can a check show that an email
// arrives: a test alert after a change shows that. This check sends nothing.
//
// Each rule says where it comes from: the published page and the heading it
// rests on, read on 2026-10-15. A heading's anchor is given only where the
// page itself showed one; otherwise the source names the page alone. A rule
// that is this module's own judgement says `basis: "local judgement"`.
//
// The module also carries its CATALOGUE (`CATALOGUE_ONLY: true`): every rule
// with its task, remedy and limits, and the practices of the same guidance it
// does not judge, with the reason.
//
// Evidence (`kind: "security_alerting_evidence"`), whatever collected it:
//   { project,
//     security_group: "sha256:<hex>",      the security group's address, as a fingerprint
//     channels: [{ id, type, enabled, verification, address }],
//     alert_selector: { label: "<key>=<value>" } | { display_name_prefix },
//     policies: [{ id, selected, name, enabled, channels: [channel id] }],
//     unread:   ["channels" | "policies"] }
//
//   address        an email channel's address, as a fingerprint: `sha256:`
//                  and the SHA-256, in hex, of the address with the spaces
//                  round it removed and in lower case; "" when the channel
//                  says none. Only an email channel has one. No address is
//                  ever in the evidence, so none is ever in a finding.
//   verification   VERIFICATION_STATUS_UNSPECIFIED (or "") | VERIFIED | UNVERIFIED
//   selected       whether the selector picked the policy out; a policy it did
//                  not pick carries nothing else, and is not judged
//   enabled        of a policy: true, false, or null when the API did not say
//                  (it says not to assume either then)
//   channels       the ids of the channels a policy names; "" for an entry the
//                  reader could not read as one
//
// Fail-closed, the same way as the other checks:
//   * no evidence is an error, not a clean result; nor is evidence that does
//     not say which address is the security group's;
//   * a part that is missing, or named in `unread`, makes every rule that
//     needs it "not assessed", and what they found is dropped;
//   * a part that was read but whose rows do not say what a rule needs (an
//     email channel with no address, a channel with no type or no id, a
//     verification status this check does not know, a policy that does not
//     say whether it was picked or is enabled, a channel entry that could not
//     be read) makes that rule not assessed too, with the reason in `undecided`;
//   * a selector that picked no enabled policy leaves the alert rules not
//     assessed: there was nothing to judge, which is never a pass;
//   * "clean" means no rule matched and every rule was assessed.
//
// A finding the owner has decided to live with is named in the node's config
// (`ACCEPTED: ["rule:severity:subject"]`), exactly, and is then reported as
// accepted instead of found.

use serde::Deserialize;
use talos_sdk_macros::talos_module;

const CHECK: &str = "security-alerting";
const TITLE: &str = "Security alerting check";
const PARTS: [&str; 2] = ["channels", "policies"];
/// The keeper remembers at most two hundred. More than this is refused, never cut.
const MAX_FINDINGS: usize = 180;
/// A channel's verification status, as the Monitoring API writes it.
const VERIFICATION: [&str; 4] = ["", "VERIFICATION_STATUS_UNSPECIFIED", "VERIFIED", "UNVERIFIED"];
const MISSING: &str = "security-group-channel-missing";
const DUPLICATED: &str = "security-group-channel-duplicated";
const NOT_DELIVERING: &str = "security-group-channel-not-delivering";
const MISSES_GROUP: &str = "alert-misses-security-group";
const DEAD_CHANNEL: &str = "alert-names-undelivering-channel";

// ------------------------------------------------------------ the sources

struct Doc {
    id: &'static str,
    publisher: &'static str,
    title: &'static str,
    url: &'static str,
}
const CHANNELS: Doc = Doc { id: "google-monitoring-notification-channels", publisher: "Google Cloud", title: "Create and manage notification channels", url: "https://docs.cloud.google.com/monitoring/support/notification-options" };
const CHANNELS_API: Doc = Doc { id: "google-monitoring-notification-channels-api", publisher: "Google Cloud", title: "Create and manage notification channels by API", url: "https://docs.cloud.google.com/monitoring/alerts/using-channels-api" };
const CHANNEL_RESOURCE: Doc = Doc { id: "google-monitoring-notification-channel-resource", publisher: "Google Cloud", title: "REST Resource: projects.notificationChannels", url: "https://docs.cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.notificationChannels" };
const ALERT_RESOURCE: Doc = Doc { id: "google-monitoring-alert-policy-resource", publisher: "Google Cloud", title: "REST Resource: projects.alertPolicies", url: "https://docs.cloud.google.com/monitoring/api/ref_v3/rest/v3/projects.alertPolicies" };
const DOCS: [&Doc; 4] = [&CHANNELS, &CHANNELS_API, &CHANNEL_RESOURCE, &ALERT_RESOURCE];

/// A heading of a document. `anchor` is the fragment the page showed for it,
/// or "" when it showed none: a source then names the page alone.
struct Cite {
    doc: &'static Doc,
    anchor: &'static str,
    heading: &'static str,
}
struct Rule {
    id: &'static str,
    needs: &'static [&'static str],
    sources: &'static [Cite],
    /// The title of a ticket that would put a finding of this rule right:
    /// what to do, verb first, naming no project.
    task: &'static str,
    remedy: &'static str,
}
const RULES: [Rule; 5] = [
    // An email channel is one address: "Enter a single email address and a description." And of a group's
    // address: "If you use a group email address as the notification channel for an alerting policy, then
    // configure the group to accept mail from alerting-noreply@google.com".
    Rule { id: MISSING, needs: &["channels"], task: "Create an email notification channel for the security group",
           remedy: "Create one Cloud Monitoring email notification channel with the security group's address in the project, and have the group accept mail from alerting-noreply@google.com.",
           sources: &[Cite { doc: &CHANNELS, anchor: "", heading: "Email" }] },
    // Neither page says how many channels one address should have. That two for one address is a fault is this
    // check's reading of the requirement ("exactly one"): an alert may name either, and each sends the group its own copy.
    Rule { id: DUPLICATED, needs: &["channels"], task: "Keep one email notification channel for the security group",
           remedy: "Point every alerting policy that names an extra channel for the security group at the one that remains, then delete the extras.",
           sources: &[] },
    // enabled: "Whether notifications are forwarded to the described channel"; "Disabling a channel prevents delivery of
    // notifications to the channel." UNVERIFIED: "The channel has yet to be verified and requires verification to function."
    Rule { id: NOT_DELIVERING, needs: &["channels"], task: "Make the security group's notification channel deliver",
           remedy: "Enable the channel, so that notifications are forwarded to it, and if it is waiting to be verified, verify it.",
           sources: &[
               Cite { doc: &CHANNEL_RESOURCE, anchor: "", heading: "Resource: NotificationChannel" },
               Cite { doc: &CHANNEL_RESOURCE, anchor: "", heading: "VerificationStatus" },
               Cite { doc: &CHANNELS_API, anchor: "", heading: "Modify a notification channel" },
           ] },
    // notificationChannels: "Identifies the notification channels to which notifications should be sent when incidents
    // are opened or closed or when new violations occur on an already opened incident." A policy that does not name the
    // group's channel sends the group nothing.
    Rule { id: MISSES_GROUP, needs: &["channels", "policies"], task: "Send every security alert to the security group",
           remedy: "Add the security group's email notification channel to the alerting policy's notification channels; the channels it already names may stay.",
           sources: &[Cite { doc: &ALERT_RESOURCE, anchor: "", heading: "Resource: AlertPolicy" }] },
    // Each entry of notificationChannels "corresponds to the name field in each of the NotificationChannel objects that are
    // returned from the notificationChannels.list method": one that the listing does not return is a channel that is not
    // there. A disabled channel: "Disabling a channel prevents delivery of notifications to the channel"; an UNVERIFIED one
    // "requires verification to function".
    Rule { id: DEAD_CHANNEL, needs: &["channels", "policies"], task: "Remove or repair notification channels that security alerts cannot reach",
           remedy: "Point the alerting policy at channels that exist in the project and work: remove the entry for a deleted channel, and enable or verify one that is disabled or waiting to be verified.",
           sources: &[
               Cite { doc: &ALERT_RESOURCE, anchor: "", heading: "Resource: AlertPolicy" },
               Cite { doc: &CHANNEL_RESOURCE, anchor: "", heading: "VerificationStatus" },
               Cite { doc: &CHANNELS_API, anchor: "", heading: "Modify a notification channel" },
           ] },
];

/// What a rule does not judge of what it is about, in its catalogue entry,
/// so that "there is a rule for it" is never read as "all of it is checked".
const LIMITS: [(&str, &[&str]); 5] = [
    (MISSING, &[
        "only an email channel counts: a security group reached through Slack, PagerDuty, Pub/Sub, a webhook or the mobile app is not recognised",
        "the address is compared whole, ignoring letter case and the spaces round it: an alias of the group, or an address that forwards to it, is not recognised",
        "whether the group accepts mail from alerting-noreply@google.com, as the page asks of a group address, is a setting of the group and is not read",
        "whether any alerting policy sends to the channel, and which changes those alerts watch, is not judged",
        "only the one project the evidence is of: each environment's project is judged by a run of its own",
    ]),
    (DUPLICATED, &["a channel of another type for the security group, beside its email channel, is not counted"]),
    (NOT_DELIVERING, &[
        "whether a notification sent to the channel arrived (its delivery logs, or a test notification) is not read",
        "a channel waiting to be verified is a finding; one that says no status, as an email channel usually does, is taken to work, as the API says",
    ]),
    (MISSES_GROUP, &[
        "which policies are security alerts is the selector's choice (a label on the policy, else a prefix of its display name, in the reader's config): a policy it does not pick is not judged, and whether the right changes are watched at all is not judged",
        "a disabled policy the selector picks is not judged; when it picks no enabled policy at all, the alert rules are not assessed, never passed",
        "whether an email actually reaches the group is not shown by any setting: a test alert after the change shows it, and this check sends nothing",
        "only the policies of the one project the evidence is of: each environment's project is judged by a run of its own",
    ]),
    (DEAD_CHANNEL, &[
        "a channel a policy names is matched by its id; the project written in the policy's entry is not compared",
        "whether a notification sent to a working channel arrived is not read: a test alert shows it",
    ]),
];

/// What the check hands on besides its findings, in its own words.
const PRODUCTS: [(&str, &str); 2] = [
    ("security-group-channels", "The project's email notification channels for the security group, by channel id: whether each is enabled and its verification status"),
    ("security-alert-policies", "The alerting policies the selector picked out as security alerts, by id and name: whether each is enabled and whether it names the security group's channel"),
];

/// Practices of the same guidance this check does not judge, and why. The
/// id is this module's (a fragment is not guessed), so the address is the page's.
const NOT_JUDGED: [(&Doc, &str, &str, &str); 5] = [
    (&CHANNELS, "decide-which-channels", "Decide which notification channels to create", "a second channel of another type for redundancy is the page's advice; the requirement judged here is the security group's email channel only"),
    (&CHANNELS, "test-a-channel", "Test a notification channel", "whether a test notification reached the group is not in this evidence"),
    (&CHANNELS, "channel-logs", "View notification channel logs", "delivery failures are in the channel's logs, which are not read"),
    (&ALERT_RESOURCE, "condition", "Condition", "what a policy watches is not read: which policies are security alerts is the selector's to say, and whether the right changes are monitored is not this check's question"),
    (&ALERT_RESOURCE, "notification-rate-limit", "NotificationRateLimit", "a log-based alert's rate limit can hold notifications back; it is not read"),
];

fn cite_json(c: &Cite) -> serde_json::Value {
    let url = if c.anchor.is_empty() { c.doc.url.to_string() } else { format!("{}#{}", c.doc.url, c.anchor) };
    serde_json::json!({ "document": c.doc.id, "publisher": c.doc.publisher, "title": c.doc.title, "heading": c.heading, "anchor": c.anchor, "url": url })
}
fn sources_of(rule: &str) -> Vec<serde_json::Value> {
    RULES.iter().find(|r| r.id == rule).map(|r| r.sources.iter().map(cite_json).collect()).unwrap_or_default()
}
fn basis(sources: &[serde_json::Value]) -> &'static str {
    if sources.is_empty() {
        "local judgement"
    } else {
        "published guidance"
    }
}

fn catalogue() -> serde_json::Value {
    serde_json::json!({
        "documents": DOCS.iter().map(|d| serde_json::json!({ "id": d.id, "publisher": d.publisher, "title": d.title, "url": d.url, "every_heading_accounted_for": false })).collect::<Vec<_>>(),
        "products": PRODUCTS.iter().map(|(id, says)| serde_json::json!({ "id": id, "says": says })).collect::<Vec<_>>(),
        "rules": RULES.iter().map(|r| {
            let sources: Vec<serde_json::Value> = r.sources.iter().map(cite_json).collect();
            serde_json::json!({
                "rule": r.id,
                "basis": basis(&sources),
                "task": r.task,
                "remedy": r.remedy,
                "limits": LIMITS.iter().find(|(rule, _)| *rule == r.id).map(|(_, limits)| limits.to_vec()).unwrap_or_default(),
                "sources": sources,
            })
        }).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.iter().map(|(doc, id, heading, why)| serde_json::json!({ "document": doc.id, "publisher": doc.publisher, "title": doc.title, "heading": heading, "anchor": id, "url": doc.url, "why": why })).collect::<Vec<_>>(),
    })
}

// ----------------------------------------------------------- the evidence

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    config: Config,
    #[serde(default)]
    input: Option<EvidenceIn>,
}
#[derive(Deserialize, Default)]
struct Config {
    /// Findings decided to be acceptable, each as "rule:severity:subject", exactly as reported.
    #[serde(rename = "ACCEPTED")]
    accepted: Option<Vec<String>>,
    /// Return the catalogue of rules and judge nothing.
    #[serde(rename = "CATALOGUE_ONLY")]
    catalogue_only: Option<bool>,
}
#[derive(Deserialize, Default)]
struct EvidenceIn {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    project: String,
    #[serde(default)]
    security_group: String,
    channels: Option<Vec<Channel>>,
    /// Which selector picked the policies, as the reader says it. Only shown, and only needed to be there.
    alert_selector: Option<serde_json::Value>,
    policies: Option<Vec<AlertPolicy>>,
    #[serde(default)]
    unread: Vec<String>,
}
#[derive(Deserialize)]
struct AlertPolicy {
    #[serde(default)]
    id: String,
    /// Absent is not "not picked": evidence that does not say is undecided.
    selected: Option<bool>,
    #[serde(default)]
    name: String,
    /// Absent (or null) is unknown, as the API says it is.
    enabled: Option<bool>,
    #[serde(default)]
    channels: Vec<String>,
}
#[derive(Deserialize)]
struct Channel {
    #[serde(default)]
    id: String,
    #[serde(default, rename = "type")]
    kind: String,
    /// Absent is not "on": evidence that does not say is undecided.
    enabled: Option<bool>,
    #[serde(default)]
    verification: String,
    /// An email channel's address, as a fingerprint. Absent on a channel of another type.
    #[serde(default)]
    address: String,
}

struct Finding {
    rule: &'static str,
    severity: &'static str,
    subject: String,
    says: String,
}

/// A name from evidence, as it may be shown: plain characters, cut to a length.
fn name(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_alphanumeric() || "-_.".contains(*c)).take(100).collect()
}
/// A project id as Google writes one.
fn project_ok(s: &str) -> bool {
    (6..=30).contains(&s.len()) && s.as_bytes()[0].is_ascii_lowercase() && s.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
/// An address's fingerprint as the reader writes one: `sha256:` and 64 lower-case hex digits.
fn fingerprint_ok(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
}
fn is_email(c: &Channel) -> bool {
    c.kind == "email"
}
/// A policy's display name, as it may be shown.
fn title(s: &str) -> String {
    s.chars().filter(|c| c.is_alphanumeric() || " -_.:/()".contains(*c)).take(100).collect()
}
/// A selector as the reader describes one: exactly one of the two forms, as text.
fn selector_said(s: Option<&serde_json::Value>) -> Option<String> {
    let o = s?.as_object().filter(|o| o.len() == 1)?;
    match o.iter().next()? {
        (k, serde_json::Value::String(v)) if k == "label" && v.contains('=') => Some(format!("the label {}", v.chars().filter(|c| c.is_ascii_alphanumeric() || "-_=".contains(*c)).take(130).collect::<String>())),
        (k, serde_json::Value::String(v)) if k == "display_name_prefix" && !v.trim().is_empty() => Some(format!("the display-name prefix \"{}\"", title(v))),
        _ => None,
    }
}
/// The policies the selector picked and that are enabled: the ones the alert rules judge.
fn live(policies: &[AlertPolicy]) -> Vec<&AlertPolicy> {
    policies.iter().filter(|p| p.selected == Some(true) && p.enabled == Some(true)).collect()
}

/// Rules whose part was read but whose rows do not say what the rule needs,
/// each with the reason. The caller reports such a rule as not assessed and
/// drops what it found on the rows that did say.
fn undecided(group: &str, channels: &[Channel], policies: Option<&[AlertPolicy]>, selector: Option<&str>) -> Vec<(&'static str, String)> {
    let mut open: Vec<(&'static str, String)> = Vec::new();
    // A channel that may be the group's and cannot be told apart from another: every rule's count is in doubt.
    let unknown = channels.iter().filter(|c| c.kind.trim().is_empty() || name(&c.id).is_empty() || name(&c.id) != c.id || (is_email(c) && !fingerprint_ok(&c.address))).count();
    if unknown > 0 {
        let why = format!("{unknown} of {} notification channels do not say what this rule needs: a type, a plain id, and for an email channel the fingerprint of its address", channels.len());
        for rule in [MISSING, DUPLICATED, NOT_DELIVERING, MISSES_GROUP, DEAD_CHANNEL] {
            open.push((rule, why.clone()));
        }
    }
    let ours: Vec<&Channel> = channels.iter().filter(|c| is_email(c) && c.address == group).collect();
    let unsaid = ours.iter().filter(|c| c.enabled.is_none() || !VERIFICATION.contains(&c.verification.as_str())).count();
    if unsaid > 0 {
        open.push((NOT_DELIVERING, format!("{unsaid} of the security group's {} email channels do not say whether they are enabled, or have a verification status this check does not know", ours.len())));
    }
    if let Some(ps) = policies {
        let both = |open: &mut Vec<(&'static str, String)>, why: String| {
            open.push((MISSES_GROUP, why.clone()));
            open.push((DEAD_CHANNEL, why));
        };
        let picked: Vec<&AlertPolicy> = ps.iter().filter(|p| p.selected == Some(true)).collect();
        let unclear = ps.iter().filter(|p| p.selected.is_none() || name(&p.id).is_empty() || name(&p.id) != p.id).count();
        let unsaid = picked.iter().filter(|p| p.enabled.is_none()).count();
        let unread_entries = live(ps).iter().filter(|p| p.channels.iter().any(|c| name(c).is_empty() || name(c) != *c)).count();
        match selector {
            None => both(&mut open, "the evidence does not say which selector picked the alerting policies out".to_string()),
            Some(_) if unclear > 0 => both(&mut open, format!("{unclear} of {} alerting policies do not say whether the selector picked them, or have no plain id", ps.len())),
            Some(_) if unsaid > 0 => both(&mut open, format!("{unsaid} of the {} alerting policies the selector picked do not say whether they are enabled, and the API says not to assume either", picked.len())),
            Some(s) if picked.is_empty() => both(&mut open, format!("the selector ({s}) picked no alerting policy of the {} in the project, so there was nothing to judge", ps.len())),
            Some(s) if live(ps).is_empty() => both(&mut open, format!("the selector ({s}) picked {} alerting policies and none of them is enabled, so there was nothing to judge", picked.len())),
            Some(_) if unread_entries > 0 => both(&mut open, format!("{unread_entries} of the enabled alerting policies the selector picked name a channel in a form this check cannot read")),
            Some(_) => {}
        }
        // A channel a policy names that does not say whether it delivers.
        let named_unsaid = live(ps).iter().flat_map(|p| p.channels.iter()).filter(|id| channels.iter().any(|c| c.id == **id && (c.enabled.is_none() || !VERIFICATION.contains(&c.verification.as_str())))).count();
        if named_unsaid > 0 {
            open.push((DEAD_CHANNEL, format!("{named_unsaid} channels named by the alerting policies the selector picked do not say whether they are enabled, or have a verification status this check does not know")));
        }
    }
    // One reason per rule: the first.
    let mut seen: Vec<&str> = Vec::new();
    open.retain(|(rule, _)| if seen.contains(rule) { false } else { seen.push(rule); true });
    open
}

/// Every rule that matched. Which rules could not be assessed is decided by
/// the caller, from what was unread and from `undecided`.
fn check(group: &str, channels: &[Channel], policies: &[AlertPolicy]) -> Vec<Finding> {
    let mut findings: Vec<Finding> = Vec::new();
    let ours: Vec<&Channel> = channels.iter().filter(|c| is_email(c) && c.address == group).collect();
    if ours.is_empty() {
        findings.push(Finding { rule: MISSING, severity: "high", subject: "security group email channel".to_string(), says: "the project has no email notification channel for the security group, so no alert of this environment can be sent to the group by email".to_string() });
    }
    if ours.len() > 1 {
        let ids: Vec<String> = ours.iter().map(|c| name(&c.id)).collect();
        findings.push(Finding { rule: DUPLICATED, severity: "low", subject: "security group email channel".to_string(), says: format!("the project has {} email notification channels for the security group ({}); there should be one, so that every alert names the same channel and the group is sent each alert once", ours.len(), ids.join(", ")) });
    }
    for c in &ours {
        let why = if c.enabled == Some(false) {
            "is disabled: no notification is delivered to it"
        } else if c.verification == "UNVERIFIED" {
            "is waiting to be verified, and does not work until it is"
        } else {
            continue;
        };
        findings.push(Finding { rule: NOT_DELIVERING, severity: "high", subject: format!("channel {}", name(&c.id)), says: format!("the security group's email channel {why}") });
    }
    for p in live(policies) {
        let called = if p.name.trim().is_empty() { String::new() } else { format!(" ({})", title(&p.name)) };
        if !p.channels.iter().any(|named| ours.iter().any(|c| c.id == *named)) {
            findings.push(Finding { rule: MISSES_GROUP, severity: "high", subject: format!("alert policy {}", name(&p.id)), says: format!("the security alert{called} does not name the security group's email channel, so an incident it opens is not sent to the group") });
        }
        let mut named: Vec<&String> = p.channels.iter().collect();
        named.sort();
        named.dedup();
        for id in named {
            let why = match channels.iter().find(|c| c.id == **id) {
                None => "is not in the project: the alert is sent nowhere through it",
                Some(c) if c.enabled == Some(false) => "is disabled: no notification is delivered to it",
                Some(c) if c.verification == "UNVERIFIED" => "is waiting to be verified, and does not work until it is",
                Some(_) => continue,
            };
            findings.push(Finding { rule: DEAD_CHANNEL, severity: "medium", subject: format!("alert policy {} channel {}", name(&p.id), name(id)), says: format!("the security alert{called} names notification channel {}, which {why}", name(id)) });
        }
    }
    findings
}

#[talos_module(world = "minimal-node")]
pub fn run(input: String) -> Result<String, String> {
    let envelope: Envelope = serde_json::from_str(&input).map_err(|e| format!("Input parse error: {e}"))?;
    if envelope.config.catalogue_only.unwrap_or(false) {
        return serde_json::to_string(&serde_json::json!({ "kind": "security_catalogue", "check": CHECK, "title": TITLE, "catalogue": catalogue() })).map_err(|e| e.to_string());
    }
    // No evidence is a failure, never a clean result.
    let arrived = envelope.input.filter(|e| e.kind == "security_alerting_evidence").ok_or("the evidence did not arrive")?;
    if arrived.unread.iter().any(|part| !PARTS.contains(&part.as_str())) {
        return Err("the evidence names a part this check does not know".to_string());
    }
    // A result is kept and reported by its project: one that cannot be named plainly is not judged.
    if !project_ok(&arrived.project) {
        return Err("the evidence does not name its project plainly".to_string());
    }
    // Without the group's address no channel can be told to be the group's.
    if !fingerprint_ok(&arrived.security_group) {
        return Err("the evidence does not say which address is the security group's".to_string());
    }
    let accepted_list = match envelope.config.accepted {
        None => Vec::new(),
        Some(list) if list.len() <= 20 && list.iter().all(|a| a.len() <= 300) => list,
        Some(_) => return Err("ACCEPTED holds at most twenty findings".to_string()),
    };
    // A part that did not arrive was not read, whatever `unread` says.
    let mut unread: Vec<String> = arrived.unread.clone();
    if arrived.channels.is_none() && !unread.iter().any(|u| u == "channels") {
        unread.push("channels".to_string());
    }
    if arrived.policies.is_none() && !unread.iter().any(|u| u == "policies") {
        unread.push("policies".to_string());
    }
    let read = |part: &str| !unread.iter().any(|u| u == part);
    let channels = if read("channels") { arrived.channels.unwrap_or_default() } else { Vec::new() };
    let policies = if read("policies") { arrived.policies.unwrap_or_default() } else { Vec::new() };
    let selector = selector_said(arrived.alert_selector.as_ref());
    let group = arrived.security_group.as_str();
    let undecided: Vec<(&str, String)> = if read("channels") { undecided(group, &channels, read("policies").then_some(policies.as_slice()), selector.as_deref()) } else { Vec::new() };
    let not_assessed: Vec<&str> = RULES.iter().filter(|r| r.needs.iter().any(|n| !read(n)) || undecided.iter().any(|(rule, _)| *rule == r.id)).map(|r| r.id).collect();
    let all: Vec<Finding> = check(group, &channels, &policies).into_iter().filter(|f| !not_assessed.contains(&f.rule)).collect();
    if all.len() > MAX_FINDINGS {
        return Err(format!("the check found more than {MAX_FINDINGS} things; reporting some of them would hide the rest"));
    }
    let passed: Vec<&str> = RULES.iter().map(|r| r.id).filter(|id| !not_assessed.contains(id) && !all.iter().any(|f| f.rule == *id)).collect();
    // Accepted only by an exact match on what was reported.
    let (accepted, findings): (Vec<Finding>, Vec<Finding>) = all.into_iter().partition(|f| accepted_list.iter().any(|a| *a == format!("{}:{}:{}", f.rule, f.severity, f.subject)));
    let worst = ["critical", "high", "medium", "low"].iter().find(|s| findings.iter().any(|f| f.severity == **s)).copied();
    let listed = |list: &[Finding]| -> Vec<serde_json::Value> {
        list.iter()
            .map(|f| {
                let sources = sources_of(f.rule);
                serde_json::json!({ "rule": f.rule, "severity": f.severity, "subject": f.subject, "says": f.says, "basis": basis(&sources), "sources": sources })
            })
            .collect()
    };
    let ours: Vec<&Channel> = channels.iter().filter(|c| is_email(c) && c.address == group).collect();
    serde_json::to_string(&serde_json::json!({
        "kind": "security_check", "check": CHECK, "title": TITLE, "project": arrived.project,
        // Clean only when no rule matched and every rule was assessed.
        "clean": findings.is_empty() && not_assessed.is_empty(),
        "worst": worst,
        "findings": listed(&findings), "accepted": listed(&accepted), "passed": passed, "not_assessed": not_assessed,
        // Why a rule is not assessed although its part was read.
        "undecided": undecided.iter().map(|(rule, why)| serde_json::json!({ "rule": rule, "why": why })).collect::<Vec<_>>(),
        "not_judged": NOT_JUDGED.len(),
        // Drawn only when the channels were read; otherwise absent, never partial.
        "security_group_channels": if read("channels") { serde_json::json!(ours.iter().map(|c| serde_json::json!({ "channel": name(&c.id), "enabled": c.enabled, "verification": name(&c.verification) })).collect::<Vec<_>>()) } else { serde_json::Value::Null },
        // Drawn only when both parts were read; otherwise absent, never partial.
        "security_alert_policies": if read("channels") && read("policies") { serde_json::json!(policies.iter().filter(|p| p.selected == Some(true)).map(|p| serde_json::json!({ "policy": name(&p.id), "name": title(&p.name), "enabled": p.enabled, "names_security_group": p.channels.iter().any(|named| ours.iter().any(|c| c.id == *named)) })).collect::<Vec<_>>()) } else { serde_json::Value::Null },
        "alert_selector": selector,
        "counted": { "channels": channels.len(), "email_channels": channels.iter().filter(|c| is_email(c)).count(), "security_group_channels": ours.len(), "policies": policies.len(), "selected_policies": policies.iter().filter(|p| p.selected == Some(true)).count() },
        "unread": unread,
    }))
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
use super::*;
use serde_json::{json, Value};

const G: &str = "sha256:48ddc227211d8cacd2496f5ab2bb796ed1173a434d5ddb4d818ec1918113bb90";
const OTHER: &str = "sha256:d876c66bad34ef8c60ff07a371204c781a9b9d76fcdee661579a9e69d33b0c85";

fn group_channel(id: &str) -> Value {
    json!({"id": id, "type": "email", "enabled": true, "verification": "VERIFICATION_STATUS_UNSPECIFIED", "address": G})
}
/// The group's channel, someone else's disabled email channel, and a Slack channel; one security
/// alert the selector picked, naming the group's channel and the Slack one, and one it did not pick.
fn evidence() -> Value {
    json!({"kind": "security_alerting_evidence", "project": "example-np", "security_group": G, "channels": [
        group_channel("1111"),
        {"id": "2222", "type": "email", "enabled": false, "verification": "", "address": OTHER},
        {"id": "3333", "type": "slack", "enabled": true, "verification": "VERIFIED"},
    ], "alert_selector": {"label": "security-control=true"}, "policies": [
        {"id": "7001", "selected": true, "name": "Security: IAM policy changed", "enabled": true, "channels": ["1111", "3333"]},
        {"id": "7002", "selected": false},
    ], "unread": []})
}
/// Other channels, with the security alert naming exactly the group's email channels among them.
fn with_channels(channels: Value) -> Value {
    let mut e = evidence();
    let ours: Vec<Value> = channels.as_array().unwrap().iter().filter(|c| c["type"] == "email" && c["address"] == G).map(|c| c["id"].clone()).collect();
    e["channels"] = channels;
    e["policies"][0]["channels"] = json!(ours);
    e
}
fn with_policies(policies: Value) -> Value {
    let mut e = evidence();
    e["policies"] = policies;
    e
}
fn alert(id: &str, channels: Value) -> Value {
    json!({"id": id, "selected": true, "name": format!("Security alert {id}"), "enabled": true, "channels": channels})
}
fn judge(evidence: Value) -> Value {
    judge_with(evidence, json!({}))
}
fn judge_with(evidence: Value, config: Value) -> Value {
    serde_json::from_str(&run(json!({"config": config, "input": evidence}).to_string()).unwrap()).unwrap()
}
fn found(out: &Value) -> Vec<String> {
    out["findings"].as_array().unwrap().iter().map(|f| f["rule"].as_str().unwrap().to_string()).collect()
}
fn strings(v: &Value) -> Vec<String> {
    v.as_array().unwrap().iter().map(|x| x.as_str().unwrap().to_string()).collect()
}

#[test]
fn one_enabled_channel_for_the_group_is_clean() {
    let out = judge(evidence());
    assert_eq!((out["kind"].clone(), out["check"].clone(), out["project"].clone(), out["clean"].clone()), (json!("security_check"), json!("security-alerting"), json!("example-np"), json!(true)), "{out}");
    assert_eq!(strings(&out["passed"]), [MISSING, DUPLICATED, NOT_DELIVERING, MISSES_GROUP, DEAD_CHANNEL]);
    assert_eq!((out["not_assessed"].clone(), out["undecided"].clone(), out["worst"].clone()), (json!([]), json!([]), Value::Null));
    assert_eq!(out["counted"], json!({"channels": 3, "email_channels": 2, "security_group_channels": 1, "policies": 2, "selected_policies": 1}));
    assert_eq!(out["security_alert_policies"], json!([{"policy": "7001", "name": "Security: IAM policy changed", "enabled": true, "names_security_group": true}]));
    assert_eq!(out["alert_selector"], json!("the label security-control=true"));
    assert_eq!(out["security_group_channels"], json!([{"channel": "1111", "enabled": true, "verification": "VERIFICATION_STATUS_UNSPECIFIED"}]));
    // A verified channel works as well as one that needs no verification.
    let mut verified = group_channel("1111");
    verified["verification"] = json!("VERIFIED");
    assert_eq!(judge(with_channels(json!([verified])))["clean"], json!(true));
    let mut unsaid = group_channel("1111");
    unsaid["verification"] = json!("");
    assert_eq!(judge(with_channels(json!([unsaid])))["clean"], json!(true));
}

#[test]
fn no_channel_for_the_group_is_a_finding() {
    let out = judge(with_channels(json!([{"id": "2222", "type": "email", "enabled": true, "verification": "", "address": OTHER}])));
    // With no channel for the group, no security alert can name one either.
    assert_eq!(found(&out), [MISSING, MISSES_GROUP]);
    let f = &out["findings"][0];
    assert_eq!((f["severity"].clone(), f["subject"].clone(), f["basis"].clone()), (json!("high"), json!("security group email channel"), json!("published guidance")));
    assert_eq!(f["sources"][0]["heading"], json!("Email"));
    assert_eq!(strings(&out["passed"]), [DUPLICATED, NOT_DELIVERING, DEAD_CHANNEL]);
    assert_eq!((out["clean"].clone(), out["worst"].clone()), (json!(false), json!("high")));
    // A project with no channel at all: the group has none either.
    assert_eq!(found(&judge(with_channels(json!([])))), [MISSING, MISSES_GROUP]);
}

#[test]
fn only_an_email_channel_with_the_groups_address_is_the_groups() {
    // The group's fingerprint on a channel that is not an email channel is not an email channel for the group.
    let mut e = with_channels(json!([{"id": "3333", "type": "slack", "enabled": true, "verification": "VERIFIED", "address": G}, {"id": "2222", "type": "email", "enabled": true, "verification": "", "address": OTHER}]));
    e["policies"][0]["channels"] = json!(["3333"]);
    assert_eq!(found(&judge(e)), [MISSING, MISSES_GROUP]);
}

#[test]
fn two_channels_for_the_group_are_a_finding_naming_both() {
    let out = judge(with_channels(json!([group_channel("1111"), group_channel("4444")])));
    assert_eq!(found(&out), [DUPLICATED]);
    let f = &out["findings"][0];
    assert_eq!((f["severity"].clone(), f["basis"].clone(), f["sources"].clone()), (json!("low"), json!("local judgement"), json!([])));
    assert!(f["says"].as_str().unwrap().contains("2 email notification channels for the security group (1111, 4444)"), "{f}");
    assert_eq!(strings(&out["passed"]), [MISSING, NOT_DELIVERING, MISSES_GROUP, DEAD_CHANNEL]);
    // A disabled duplicate is still a duplicate, and does not deliver; the alert that names it names a dead channel.
    let mut off = group_channel("4444");
    off["enabled"] = json!(false);
    assert_eq!(found(&judge(with_channels(json!([group_channel("1111"), off])))), [DUPLICATED, NOT_DELIVERING, DEAD_CHANNEL]);
}

#[test]
fn a_channel_for_the_group_that_is_disabled_or_unverified_does_not_deliver() {
    let mut off = group_channel("1111");
    off["enabled"] = json!(false);
    let out = judge(with_channels(json!([off])));
    assert_eq!(found(&out), [NOT_DELIVERING, DEAD_CHANNEL]);
    let f = &out["findings"][0];
    assert_eq!((f["severity"].clone(), f["subject"].clone()), (json!("high"), json!("channel 1111")));
    assert!(f["says"].as_str().unwrap().contains("is disabled"), "{f}");
    assert_eq!(f["sources"].as_array().unwrap().iter().map(|s| s["heading"].as_str().unwrap()).collect::<Vec<_>>(), ["Resource: NotificationChannel", "VerificationStatus", "Modify a notification channel"]);
    let mut waiting = group_channel("1111");
    waiting["verification"] = json!("UNVERIFIED");
    let out = judge(with_channels(json!([waiting])));
    assert_eq!(found(&out), [NOT_DELIVERING, DEAD_CHANNEL]);
    assert!(out["findings"][0]["says"].as_str().unwrap().contains("waiting to be verified"));
    // Another person's disabled channel is not the group's.
    assert_eq!(found(&judge(evidence())), Vec::<String>::new());
}

#[test]
fn a_channel_that_does_not_say_what_a_rule_needs_leaves_every_rule_undecided() {
    for odd in [
        json!({"id": "9", "type": "email", "enabled": true, "verification": "", "address": ""}),
        json!({"id": "9", "type": "email", "enabled": true, "verification": ""}),
        json!({"id": "9", "type": "email", "enabled": true, "verification": "", "address": format!("sha256:{}", G[7..].to_uppercase())}),
        json!({"id": "9", "type": "email", "enabled": true, "verification": "", "address": "sha256:abc"}),
        json!({"id": "9", "type": "", "enabled": true, "verification": ""}),
        json!({"id": "9", "type": " ", "enabled": true, "verification": ""}),
        json!({"id": "", "type": "slack", "enabled": true, "verification": ""}),
        json!({"id": "9 9", "type": "slack", "enabled": true, "verification": ""}),
    ] {
        // Here the group's channel is missing too: what the rule would find on the rest is dropped.
        let out = judge(with_channels(json!([odd.clone()])));
        assert_eq!(strings(&out["not_assessed"]), [MISSING, DUPLICATED, NOT_DELIVERING, MISSES_GROUP, DEAD_CHANNEL], "{odd}");
        assert_eq!((found(&out), out["passed"].clone(), out["clean"].clone()), (Vec::<String>::new(), json!([]), json!(false)), "{odd}");
        assert_eq!(out["undecided"].as_array().unwrap().len(), 5, "{odd}");
        assert!(out["undecided"][0]["why"].as_str().unwrap().starts_with("1 of 1 notification channels do not say"), "{}", out["undecided"]);
    }
    // A channel of another type needs no address.
    assert_eq!(judge(with_channels(json!([group_channel("1111"), {"id": "3333", "type": "pubsub", "enabled": true, "verification": ""}])))["clean"], json!(true));
}

#[test]
fn a_group_channel_that_does_not_say_whether_it_delivers_leaves_that_rule_undecided() {
    for (key, value) in [("enabled", Value::Null), ("verification", json!("PENDING"))] {
        let mut odd = group_channel("1111");
        if value.is_null() {
            odd.as_object_mut().unwrap().remove(key);
        } else {
            odd[key] = value;
        }
        let mut off = group_channel("4444");
        off["enabled"] = json!(false);
        let out = judge(with_channels(json!([odd, off])));
        // The alert names both, so whether it names a dead channel is in doubt too.
        assert_eq!(strings(&out["not_assessed"]), [NOT_DELIVERING, DEAD_CHANNEL], "{key}");
        // The count is still known; what the delivery rule found on the channel that did say is dropped.
        assert_eq!(found(&out), [DUPLICATED], "{key}");
        assert_eq!(out["undecided"][0]["rule"], json!(NOT_DELIVERING));
        assert!(out["undecided"][0]["why"].as_str().unwrap().starts_with("1 of the security group's 2 email channels"), "{}", out["undecided"]);
    }
    // Another person's channel that does not say whether it is enabled does not matter.
    let mut e = evidence();
    e["channels"][1].as_object_mut().unwrap().remove("enabled");
    assert_eq!(judge(e)["clean"], json!(true));
}

#[test]
fn channels_that_were_not_read_are_not_assessed_never_passed() {
    let mut e = evidence();
    e["unread"] = json!(["channels"]);
    let out = judge(e);
    assert_eq!((strings(&out["not_assessed"]), out["passed"].clone(), out["clean"].clone(), out["findings"].clone()), (vec![MISSING.to_string(), DUPLICATED.to_string(), NOT_DELIVERING.to_string(), MISSES_GROUP.to_string(), DEAD_CHANNEL.to_string()], json!([]), json!(false), json!([])));
    assert_eq!((out["security_group_channels"].clone(), out["counted"]["channels"].clone()), (Value::Null, json!(0)));
    // A part that did not arrive was not read, whatever `unread` says: an absent list is not "no channels".
    let mut e = evidence();
    e.as_object_mut().unwrap().remove("channels");
    let out = judge(e);
    assert_eq!((strings(&out["not_assessed"]).len(), strings(&out["unread"]), out["clean"].clone()), (5, vec!["channels".to_string()], json!(false)));
    assert!(found(&out).is_empty());
}

#[test]
fn evidence_that_is_not_there_or_not_plain_is_refused() {
    let err = |input: Value| run(json!({"input": input}).to_string()).unwrap_err();
    assert_eq!(run(json!({}).to_string()).unwrap_err(), "the evidence did not arrive");
    let mut e = evidence();
    e["kind"] = json!("wif_evidence");
    assert_eq!(err(e), "the evidence did not arrive");
    let mut e = evidence();
    e["unread"] = json!(["alerts"]);
    assert_eq!(err(e), "the evidence names a part this check does not know");
    for project in ["", "Example-NP", "example-np/../x"] {
        let mut e = evidence();
        e["project"] = json!(project);
        assert_eq!(err(e), "the evidence does not name its project plainly");
    }
    for group in [json!(null), json!(""), json!("security-team@example.com"), json!(G.to_uppercase()), json!(format!("sha256:{}", G[7..].to_uppercase())), json!(&G[..70])] {
        let mut e = evidence();
        if group.is_null() {
            e.as_object_mut().unwrap().remove("security_group");
        } else {
            e["security_group"] = group.clone();
        }
        assert_eq!(err(e), "the evidence does not say which address is the security group's", "{group}");
    }
}

#[test]
fn a_finding_is_accepted_only_by_an_exact_match() {
    let mut missing = with_channels(json!([]));
    missing["policies"] = json!([alert("7001", json!(["3333"]))]);
    missing["channels"] = json!([{"id": "3333", "type": "slack", "enabled": true, "verification": "VERIFIED"}]);
    let out = judge_with(missing.clone(), json!({"ACCEPTED": ["security-group-channel-missing:high:security group email channel", "alert-misses-security-group:high:alert policy 7001"]}));
    assert_eq!((found(&out), out["accepted"].as_array().unwrap().len(), out["clean"].clone()), (Vec::<String>::new(), 2, json!(true)));
    for near in ["security-group-channel-missing:low:security group email channel", "security-group-channel-missing:high:security group"] {
        assert_eq!(found(&judge_with(missing.clone(), json!({"ACCEPTED": [near, "alert-misses-security-group:high:alert policy 7001"]}))), [MISSING], "{near}");
    }
    let many: Vec<String> = (0..21).map(|i| format!("x:{i}")).collect();
    assert_eq!(run(json!({"config": {"ACCEPTED": many}, "input": missing}).to_string()).unwrap_err(), "ACCEPTED holds at most twenty findings");
    assert_eq!(run(json!({"config": {"ACCEPTED": ["x".repeat(301)]}, "input": with_channels(json!([]))}).to_string()).unwrap_err(), "ACCEPTED holds at most twenty findings");
    assert!(run(json!({"config": {"ACCEPTED": ["x".repeat(300)]}, "input": with_channels(json!([]))}).to_string()).is_ok());
}

#[test]
fn more_findings_than_can_be_carried_are_an_error_not_a_cut() {
    let off = |i: usize| json!({"id": format!("{i}"), "type": "email", "enabled": false, "verification": "", "address": G});
    // One duplicate finding and one per disabled channel.
    // No security alert here: the alert rules are not assessed, and find nothing.
    let quiet = |channels: Vec<Value>| {
        let mut e = with_channels(json!(channels));
        e["policies"] = json!([]);
        e
    };
    assert_eq!(run(json!({"input": quiet((0..MAX_FINDINGS).map(off).collect())}).to_string()).unwrap_err(), "the check found more than 180 things; reporting some of them would hide the rest");
    assert_eq!(found(&judge(quiet((0..MAX_FINDINGS - 1).map(off).collect()))).len(), MAX_FINDINGS);
}

#[test]
fn the_catalogue_names_every_rule_with_its_task_remedy_limits_and_sources() {
    let out: Value = serde_json::from_str(&run(json!({"config": {"CATALOGUE_ONLY": true}}).to_string()).unwrap()).unwrap();
    assert_eq!((out["kind"].clone(), out["check"].clone()), (json!("security_catalogue"), json!("security-alerting")));
    let c = &out["catalogue"];
    let rules: Vec<&str> = c["rules"].as_array().unwrap().iter().map(|r| r["rule"].as_str().unwrap()).collect();
    assert_eq!(rules, [MISSING, DUPLICATED, NOT_DELIVERING, MISSES_GROUP, DEAD_CHANNEL]);
    for r in c["rules"].as_array().unwrap() {
        assert!(!r["task"].as_str().unwrap().is_empty() && !r["remedy"].as_str().unwrap().is_empty() && !r["limits"].as_array().unwrap().is_empty(), "{r}");
        assert_eq!(r["basis"], json!(if r["sources"].as_array().unwrap().is_empty() { "local judgement" } else { "published guidance" }));
        for s in r["sources"].as_array().unwrap() {
            assert!(s["url"].as_str().unwrap().starts_with("https://docs.cloud.google.com/monitoring/"), "{s}");
        }
    }
    // A heading is cited by a rule or listed as not judged, never both.
    let cited: Vec<(String, String)> = c["rules"].as_array().unwrap().iter().flat_map(|r| r["sources"].as_array().unwrap().iter().map(|s| (s["document"].as_str().unwrap().to_string(), s["heading"].as_str().unwrap().to_string()))).collect();
    let skipped = c["not_judged"].as_array().unwrap();
    assert_eq!(skipped.len(), 5);
    for n in skipped {
        assert!(!cited.contains(&(n["document"].as_str().unwrap().to_string(), n["heading"].as_str().unwrap().to_string())), "{n}");
        assert!(!n["why"].as_str().unwrap().is_empty());
    }
    assert_eq!(c["products"].as_array().unwrap().iter().map(|p| p["id"].as_str().unwrap()).collect::<Vec<_>>(), ["security-group-channels", "security-alert-policies"]);
    assert_eq!(c["documents"].as_array().unwrap().len(), 4);
    // Delivery itself is not something a setting shows: the limits say so.
    let misses = c["rules"].as_array().unwrap().iter().find(|r| r["rule"] == MISSES_GROUP).unwrap();
    assert!(strings(&misses["limits"]).iter().any(|l| l.contains("test alert") && l.contains("sends nothing")), "{misses}");
    assert_eq!(misses["sources"][0]["heading"], json!("Resource: AlertPolicy"));
}

#[test]
fn no_address_or_display_name_reaches_a_finding() {
    // The evidence carries only fingerprints; what is shown is a channel id cut to plain characters.
    let mut off = group_channel("1111<script>");
    off["enabled"] = json!(false);
    let out = judge(with_channels(json!([off])));
    assert!(strings(&out["not_assessed"]).contains(&NOT_DELIVERING.to_string()));
    let out = judge(with_channels(json!([group_channel("1111"), group_channel("4444")])));
    assert!(!out.to_string().contains("sha256:"), "{out}");
}

// ------------------------------------------------------------- the alerts

#[test]
fn a_security_alert_that_does_not_name_the_groups_channel_is_a_finding() {
    let out = judge(with_policies(json!([alert("7001", json!(["3333"])), {"id": "7002", "selected": false}])));
    assert_eq!(found(&out), [MISSES_GROUP]);
    let f = &out["findings"][0];
    assert_eq!((f["severity"].clone(), f["subject"].clone(), f["basis"].clone()), (json!("high"), json!("alert policy 7001"), json!("published guidance")));
    assert!(f["says"].as_str().unwrap().contains("(Security alert 7001) does not name the security group's email channel"), "{f}");
    assert_eq!(strings(&out["passed"]), [MISSING, DUPLICATED, NOT_DELIVERING, DEAD_CHANNEL]);
    assert_eq!(out["security_alert_policies"][0]["names_security_group"], json!(false));
    // A policy naming no channel at all sends the group nothing either.
    assert_eq!(found(&judge(with_policies(json!([alert("7001", json!([]))])))), [MISSES_GROUP]);
    // Naming the group's channel as well as others is what is asked; every picked policy is judged.
    assert_eq!(found(&judge(with_policies(json!([alert("7001", json!(["3333", "1111"])), alert("7003", json!(["3333"]))])))), [MISSES_GROUP]);
    assert_eq!(judge(with_policies(json!([alert("7001", json!(["3333", "1111"])), alert("7003", json!(["1111"]))])))["clean"], json!(true));
}

#[test]
fn a_policy_the_selector_did_not_pick_or_that_is_disabled_is_not_judged() {
    let mut off = alert("7003", json!(["9999"]));
    off["enabled"] = json!(false);
    // A policy the selector did not pick is not judged, even one that says it is enabled and names a channel that is gone.
    let out = judge(with_policies(json!([alert("7001", json!(["1111"])), {"id": "7002", "selected": false, "enabled": true, "channels": ["9999"]}, off])));
    assert_eq!((out["clean"].clone(), found(&out)), (json!(true), Vec::<String>::new()), "{out}");
}

#[test]
fn a_selector_that_picks_no_enabled_policy_leaves_the_alert_rules_not_assessed() {
    let mut off = alert("7003", json!(["1111"]));
    off["enabled"] = json!(false);
    for (policies, why) in [
        (json!([{"id": "7002", "selected": false}]), "the selector (the label security-control=true) picked no alerting policy of the 1 in the project"),
        (json!([]), "the selector (the label security-control=true) picked no alerting policy of the 0 in the project"),
        (json!([off]), "the selector (the label security-control=true) picked 1 alerting policies and none of them is enabled"),
    ] {
        let out = judge(with_policies(policies.clone()));
        assert_eq!(strings(&out["not_assessed"]), [MISSES_GROUP, DEAD_CHANNEL], "{policies}");
        assert_eq!((out["clean"].clone(), strings(&out["passed"])), (json!(false), vec![MISSING.to_string(), DUPLICATED.to_string(), NOT_DELIVERING.to_string()]), "{policies}");
        assert!(out["undecided"][0]["why"].as_str().unwrap().starts_with(why), "{}", out["undecided"]);
    }
    // A prefix selector is named as such.
    let mut e = with_policies(json!([]));
    e["alert_selector"] = json!({"display_name_prefix": "Security: "});
    assert!(judge(e)["undecided"][0]["why"].as_str().unwrap().starts_with("the selector (the display-name prefix \"Security: \") picked no alerting policy"));
}

#[test]
fn a_security_alert_naming_a_channel_that_cannot_deliver_is_a_finding() {
    let mut waiting = json!({"id": "4444", "type": "webhook_tokenauth", "enabled": true, "verification": "UNVERIFIED"});
    let mut e = with_policies(json!([alert("7001", json!(["1111", "2222", "8888", "4444", "8888"]))]));
    e["channels"].as_array_mut().unwrap().push(waiting.take());
    let out = judge(e);
    assert_eq!(found(&out), [DEAD_CHANNEL, DEAD_CHANNEL, DEAD_CHANNEL], "{out}");
    let says: Vec<(String, String)> = out["findings"].as_array().unwrap().iter().map(|f| (f["subject"].as_str().unwrap().to_string(), f["says"].as_str().unwrap().to_string())).collect();
    // Each channel once, in order of its id, however often the policy names it.
    assert_eq!(says.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(), ["alert policy 7001 channel 2222", "alert policy 7001 channel 4444", "alert policy 7001 channel 8888"]);
    assert!(says[0].1.ends_with("which is disabled: no notification is delivered to it"), "{says:?}");
    assert!(says[1].1.ends_with("which is waiting to be verified, and does not work until it is"), "{says:?}");
    assert!(says[2].1.ends_with("which is not in the project: the alert is sent nowhere through it"), "{says:?}");
    assert_eq!(out["findings"][0]["severity"], json!("medium"));
    assert_eq!(out["findings"][0]["sources"].as_array().unwrap().iter().map(|s| s["heading"].as_str().unwrap()).collect::<Vec<_>>(), ["Resource: AlertPolicy", "VerificationStatus", "Modify a notification channel"]);
    // The group's channel is named, so the group is reached: the other rule passes.
    assert!(strings(&out["passed"]).contains(&MISSES_GROUP.to_string()));
}

#[test]
fn a_policy_that_does_not_say_what_the_alert_rules_need_leaves_them_undecided() {
    let both = [MISSES_GROUP, DEAD_CHANNEL];
    let mut unsaid = alert("7001", json!(["9999"]));
    unsaid.as_object_mut().unwrap().remove("enabled");
    let mut null = alert("7001", json!(["9999"]));
    null["enabled"] = Value::Null;
    let mut unpicked = alert("7001", json!(["9999"]));
    unpicked.as_object_mut().unwrap().remove("selected");
    for (policy, why) in [
        (unsaid, "1 of the 1 alerting policies the selector picked do not say whether they are enabled"),
        (null, "1 of the 1 alerting policies the selector picked do not say whether they are enabled"),
        (unpicked, "1 of 1 alerting policies do not say whether the selector picked them"),
        (alert("", json!(["9999"])), "1 of 1 alerting policies do not say whether the selector picked them, or have no plain id"),
        (alert("70 01", json!(["9999"])), "1 of 1 alerting policies do not say whether the selector picked them, or have no plain id"),
        (alert("7001", json!(["9999", ""])), "1 of the enabled alerting policies the selector picked name a channel in a form this check cannot read"),
        (alert("7001", json!(["99 99"])), "1 of the enabled alerting policies the selector picked name a channel in a form this check cannot read"),
    ] {
        let out = judge(with_policies(json!([policy.clone()])));
        assert_eq!(strings(&out["not_assessed"]), both, "{policy}");
        // What the rules would have found on the rest (9999 is not in the project) is dropped.
        assert!(found(&out).is_empty(), "{policy}");
        assert!(out["undecided"][0]["why"].as_str().unwrap().starts_with(why), "{policy}: {}", out["undecided"]);
    }
    // The evidence must say which selector picked the policies.
    for selector in [Value::Null, json!("security-control=true"), json!({}), json!({"label": "security-control"}), json!({"display_name_prefix": " "}), json!({"label": "a=b", "display_name_prefix": "x"})] {
        let mut e = evidence();
        if selector.is_null() {
            e.as_object_mut().unwrap().remove("alert_selector");
        } else {
            e["alert_selector"] = selector.clone();
        }
        let out = judge(e);
        assert_eq!(strings(&out["not_assessed"]), both, "{selector}");
        assert_eq!(out["undecided"][0]["why"], json!("the evidence does not say which selector picked the alerting policies out"), "{selector}");
    }
}

#[test]
fn a_named_channel_that_does_not_say_whether_it_delivers_leaves_the_dead_channel_rule_undecided() {
    let mut e = evidence();
    e["channels"][2].as_object_mut().unwrap().remove("enabled");
    let out = judge(e);
    assert_eq!(strings(&out["not_assessed"]), [DEAD_CHANNEL]);
    assert!(out["undecided"][0]["why"].as_str().unwrap().starts_with("1 channels named by the alerting policies the selector picked do not say"), "{}", out["undecided"]);
    let mut e = evidence();
    e["channels"][2]["verification"] = json!("PENDING");
    assert_eq!(strings(&judge(e)["not_assessed"]), [DEAD_CHANNEL]);
}

#[test]
fn policies_that_were_not_read_leave_the_alert_rules_not_assessed_and_the_channel_rules_judged() {
    let mut e = evidence();
    e["unread"] = json!(["policies"]);
    let out = judge(e);
    assert_eq!((strings(&out["not_assessed"]), strings(&out["passed"]), out["clean"].clone()), (vec![MISSES_GROUP.to_string(), DEAD_CHANNEL.to_string()], vec![MISSING.to_string(), DUPLICATED.to_string(), NOT_DELIVERING.to_string()], json!(false)));
    assert_eq!((out["security_alert_policies"].clone(), out["undecided"].clone()), (Value::Null, json!([])));
    // Evidence from a reader that does not read policies: absent is unread, never "no policies".
    let mut e = with_policies(json!([alert("7001", json!(["3333"]))]));
    e.as_object_mut().unwrap().remove("policies");
    let out = judge(e);
    assert_eq!((strings(&out["not_assessed"]), strings(&out["unread"])), (vec![MISSES_GROUP.to_string(), DEAD_CHANNEL.to_string()], vec!["policies".to_string()]));
    assert!(found(&out).is_empty());
}
}
