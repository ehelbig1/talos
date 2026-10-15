//! The receiver for Jira webhook deliveries: `POST /api/atlassian/webhook`.
//!
//! Public, and the URL is one fixed address for the whole deployment, so
//! nothing about the request is believed until its token verifies, and the
//! owner of a delivery is whoever REGISTERED the webhook it names — never
//! anything the request says about itself.
//!
//! Order, cheapest first. Nothing touches the database, and the body is not
//! read, before step 2 has passed:
//!
//! 1. `Authorization: Bearer` is present and of a sane length.
//! 2. The token verifies under the app's client secret ([`crate::push_jwt`]),
//!    and has not been used before ([`crate::push_replay`]): a token is
//!    single-use, remembered by its hash until it can no longer verify. A
//!    delivery answered with a 5xx releases its token, so Atlassian's retry
//!    is not refused as a replay.
//! 3. The body (at most 1 MiB) is read and parsed for four things only:
//!    `matchedWebhookIds`, `webhookEvent`, `issue.key`, and the HOST (or, on
//!    the API gateway, the cloud id) of `issue.self`. Everything else in it —
//!    the ticket — is skipped by the parser and never held, logged or stored.
//! 4. The matched webhook ids are mapped to the registrations that own them.
//!    A lookup that did not answer is a 503 (Atlassian retries); no row is a
//!    200 (nothing to retry toward). A registration acts on a delivery only
//!    when the delivery's `issue.self` is on the registration's OWN site:
//!    a Jira webhook id is unique only within one site, so an id match alone
//!    could start one user's workflow for another site's event (security
//!    review 2026-10-14, F-1). A delivery with no `issue.self`, or from
//!    another site, starts nothing (202) and is recorded. Among registrations
//!    on the delivery's site, a webhook id registered on more than one site is
//!    still ambiguous and starts nothing.
//! 4b. Each registration acts on at most [`DELIVERIES_PER_REGISTRATION_PER_MINUTE`]
//!    deliveries a minute (per replica), and holds at most
//!    [`DEDUP_ROWS_PER_REGISTRATION`] remembered deliveries (F-4).
//! 5. The execution pause is consulted, BEFORE the delivery is recorded as
//!    handled: a 503 after that record would be retried by Atlassian and then
//!    skipped as a duplicate, which is a drop.
//! 6. `X-Atlassian-Webhook-Identifier` (stable across Atlassian's retries) is
//!    recorded per registration; a delivery already recorded starts nothing.
//! 7. Each registration bound to a workflow starts it once, as the
//!    registration's own user, through the trigger service, with identifiers
//!    only. The 200 is sent first; the starts run in a task.

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::Extension;
use serde::de::{IgnoredAny, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use std::sync::Arc;
use talos_execution_orchestration::{
    ExecutionOrchestrationService, TriggerInput, TriggerOutcome, PUSH_REFUSAL_TRIGGER_FAILED,
    PUSH_REFUSAL_TRIGGER_SERVICE_NOT_WIRED,
};
use talos_integration_helpers::audit::{insert_channel_audit, ChannelAuditEvent};
use uuid::Uuid;

use crate::integration::AtlassianIntegrationService;
use crate::push_jwt::{self, JwtRefusal};

/// Largest delivery body read. An issue with long text fields and a full
/// changelog is tens of kilobytes; Atlassian documents no limit. The router's
/// body-limit layer uses this same constant.
pub const JIRA_WEBHOOK_MAX_BODY_BYTES: usize = 1024 * 1024;

/// Most webhook ids taken from one delivery. A user may hold five webhooks
/// per site; a delivery naming more than this is not asked about in full.
const MAX_MATCHED_WEBHOOK_IDS: usize = 64;

/// Most registrations one delivery is mapped to. One more than this is asked
/// for, so that "there were more" is known rather than cut off: a webhook id's
/// second site hidden by a row limit would make an ambiguous id look like an
/// unambiguous one.
const MAX_MATCHED_REGISTRATIONS: usize = 256;

/// Longest `X-Atlassian-Webhook-Identifier` recorded.
const MAX_DELIVERY_ID_LEN: usize = 128;

/// The reason recorded for a start withheld because the webhook id is
/// registered on more than one site.
pub const REFUSAL_AMBIGUOUS_WEBHOOK_ID: &str = "ambiguous_webhook_id";

/// The reason recorded for a start withheld because the delivery's
/// `issue.self` is not on the registration's site (or is absent).
pub const REFUSAL_SITE_MISMATCH: &str = "site_mismatch";

/// The reason recorded for a start withheld because the registration already
/// holds [`DEDUP_ROWS_PER_REGISTRATION`] remembered deliveries.
pub const REFUSAL_DEDUP_CAP: &str = "dedup_cap";

/// Most deliveries one registration acts on per minute, per replica. A Jira
/// user's assigned issues change far less often; this bounds what a flood of
/// verified deliveries can start and insert.
pub const DELIVERIES_PER_REGISTRATION_PER_MINUTE: u32 = 60;

/// Most remembered (unswept) deliveries one registration holds. The hourly
/// sweep deletes rows older than seven days; a registration at this count has
/// received over a thousand deliveries a day for a week, which is a flood.
/// Above it a delivery inserts nothing and starts nothing (`DLQ_MAX_PENDING`'s
/// refuse-and-record shape).
pub const DEDUP_ROWS_PER_REGISTRATION: i64 = 10_000;

/// Most refusal records (site mismatch, dedup cap) written per registration
/// per hour: a refusal is recorded so its owner can find it, but a flood of
/// refusals must not become a flood of rows.
const REFUSAL_RECORDS_PER_REGISTRATION_PER_HOUR: u32 = 10;

/// Longest `issue.self` read.
const MAX_SELF_URL_LEN: usize = 512;

/// What the receiver made of a delivery, as a closed set. The handler turns
/// it into a status; a test reads it to know WHY a status was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReceiptNote {
    /// No `Authorization: Bearer` header (or one too long to be a token).
    MissingBearer,
    /// The app's client secret is not configured, so nothing can be verified.
    NotConfigured,
    /// The token did not verify.
    Refused(JwtRefusal),
    /// The token verified but was already used (here or, with a shared
    /// replay guard, on another replica). Nothing is read.
    Replayed,
    /// The replay memory could not answer (full, or the shared guard is
    /// down and the deployment fails closed); Atlassian is asked to retry.
    ReplayUnavailable,
    /// Every registration the delivery matched is on another site than the
    /// delivery's `issue.self` (or the delivery has none). Nothing started.
    SiteMismatch {
        /// Registrations the delivery's webhook ids matched.
        matched: usize,
    },
    /// The body was longer than [`JIRA_WEBHOOK_MAX_BODY_BYTES`] (or the
    /// connection ended before it was all read).
    BodyTooLarge,
    /// The body could not be read, or is not the JSON a delivery is.
    BodyMalformed,
    /// The registrations could not be read; Atlassian is asked to retry.
    LookupFailed,
    /// The execution pause is set; Atlassian is asked to retry.
    Deferred,
    /// The delivery could not be recorded as handled; Atlassian is asked to
    /// retry, and nothing was started.
    DedupFailed,
    /// The delivery's webhook ids matched more registrations than are read.
    /// Nothing is started: acting on a partial read could hide an ambiguous
    /// webhook id. Answered 200, since a retry would match the same rows.
    TooManyRegistrations,
    /// Authenticated and handled.
    Accepted {
        /// Registrations the delivery's webhook ids matched.
        matched: usize,
        /// Of those, how many were withheld because the delivery is from
        /// another site.
        off_site: usize,
        /// Of the rest, how many were withheld as ambiguous.
        ambiguous: usize,
        /// Of the rest, how many were over their per-minute budget.
        rate_limited: usize,
        /// Of the rest, how many were at their remembered-delivery cap.
        capped: usize,
        /// Of the rest, how many had already seen this delivery.
        duplicates: usize,
    },
}

impl ReceiptNote {
    /// The status Atlassian is answered with. 5xx is retried by Atlassian (up
    /// to five times); 2xx and 4xx are not.
    #[must_use]
    pub fn status(self) -> StatusCode {
        match self {
            Self::MissingBearer | Self::Refused(_) => StatusCode::UNAUTHORIZED,
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::BodyMalformed => StatusCode::BAD_REQUEST,
            Self::NotConfigured
            | Self::LookupFailed
            | Self::Deferred
            | Self::DedupFailed
            | Self::ReplayUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::SiteMismatch { .. } => StatusCode::ACCEPTED,
            Self::TooManyRegistrations | Self::Replayed | Self::Accepted { .. } => StatusCode::OK,
        }
    }
}

/// One workflow start a delivery calls for. Identifiers only: this is also
/// everything the workflow's trigger input is built from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedStart {
    pub registration_id: Uuid,
    /// The registration's owner. The start is made AS this user.
    pub user_id: Uuid,
    pub workflow_id: Uuid,
    pub cloud_id: String,
    pub webhook_id: i64,
    pub event: Option<String>,
    pub issue_key: Option<String>,
}

/// The receiver's answer: a status, why, and the starts still to run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushReceipt {
    pub note: ReceiptNote,
    pub starts: Vec<PlannedStart>,
}

impl PushReceipt {
    fn just(note: ReceiptNote) -> Self {
        Self {
            note,
            starts: Vec::new(),
        }
    }

    #[must_use]
    pub fn status(&self) -> StatusCode {
        self.note.status()
    }
}

/// `matchedWebhookIds`, read without ever holding more than
/// [`MAX_MATCHED_WEBHOOK_IDS`] of them.
#[derive(Debug, Default)]
struct MatchedIds {
    ids: Vec<i64>,
    truncated: bool,
}

impl<'de> Deserialize<'de> for MatchedIds {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Ids;
        impl<'de> Visitor<'de> for Ids {
            type Value = MatchedIds;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("an array of webhook ids")
            }
            fn visit_unit<E>(self) -> Result<MatchedIds, E> {
                Ok(MatchedIds::default())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<MatchedIds, A::Error> {
                let mut out = MatchedIds::default();
                while let Some(id) = seq.next_element::<i64>()? {
                    if out.ids.len() < MAX_MATCHED_WEBHOOK_IDS {
                        if !out.ids.contains(&id) {
                            out.ids.push(id);
                        }
                    } else {
                        out.truncated = true;
                    }
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(Ids)
    }
}

/// A short string, or nothing. Any other JSON value in its place is skipped
/// rather than being an error or being held: a field this receiver does not
/// need must not be able to make a delivery unreadable.
fn short_string_or_nothing<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    string_up_to_or_nothing(deserializer, 128)
}

/// `issue.self`, up to [`MAX_SELF_URL_LEN`]: only its site is ever used.
fn self_url_or_nothing<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    string_up_to_or_nothing(deserializer, MAX_SELF_URL_LEN)
}

fn string_up_to_or_nothing<'de, D: Deserializer<'de>>(
    deserializer: D,
    max: usize,
) -> Result<Option<String>, D::Error> {
    struct Short(usize);
    impl<'de> Visitor<'de> for Short {
        type Value = Option<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_str<E>(self, v: &str) -> Result<Option<String>, E> {
            Ok((v.len() <= self.0).then(|| v.to_string()))
        }
        fn visit_unit<E>(self) -> Result<Option<String>, E> {
            Ok(None)
        }
        fn visit_bool<E>(self, _: bool) -> Result<Option<String>, E> {
            Ok(None)
        }
        fn visit_i64<E>(self, _: i64) -> Result<Option<String>, E> {
            Ok(None)
        }
        fn visit_u64<E>(self, _: u64) -> Result<Option<String>, E> {
            Ok(None)
        }
        fn visit_f64<E>(self, _: f64) -> Result<Option<String>, E> {
            Ok(None)
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Option<String>, A::Error> {
            while seq.next_element::<IgnoredAny>()?.is_some() {}
            Ok(None)
        }
        fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Option<String>, A::Error> {
            while map.next_entry::<IgnoredAny, IgnoredAny>()?.is_some() {}
            Ok(None)
        }
    }
    deserializer.deserialize_any(Short(max))
}

/// The issue, of which only the key and the site of `self` are read.
#[derive(Debug, Default)]
struct IssueRef {
    key: Option<String>,
    /// `issue.self`, held only until its site is taken from it.
    self_url: Option<String>,
}

impl<'de> Deserialize<'de> for IssueRef {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Issue;
        impl<'de> Visitor<'de> for Issue {
            type Value = IssueRef;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("any JSON value")
            }
            fn visit_unit<E>(self) -> Result<IssueRef, E> {
                Ok(IssueRef::default())
            }
            fn visit_bool<E>(self, _: bool) -> Result<IssueRef, E> {
                Ok(IssueRef::default())
            }
            fn visit_i64<E>(self, _: i64) -> Result<IssueRef, E> {
                Ok(IssueRef::default())
            }
            fn visit_u64<E>(self, _: u64) -> Result<IssueRef, E> {
                Ok(IssueRef::default())
            }
            fn visit_f64<E>(self, _: f64) -> Result<IssueRef, E> {
                Ok(IssueRef::default())
            }
            fn visit_str<E>(self, _: &str) -> Result<IssueRef, E> {
                Ok(IssueRef::default())
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<IssueRef, A::Error> {
                while seq.next_element::<IgnoredAny>()?.is_some() {}
                Ok(IssueRef::default())
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<IssueRef, A::Error> {
                #[derive(Deserialize)]
                #[serde(transparent)]
                struct Key(#[serde(deserialize_with = "short_string_or_nothing")] Option<String>);
                #[derive(Deserialize)]
                #[serde(transparent)]
                struct SelfUrl(#[serde(deserialize_with = "self_url_or_nothing")] Option<String>);
                let mut out = IssueRef::default();
                while let Some(name) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    if name == "key" {
                        out.key = map.next_value::<Key>()?.0;
                    } else if name == "self" {
                        out.self_url = map.next_value::<SelfUrl>()?.0;
                    } else {
                        map.next_value::<IgnoredAny>()?;
                    }
                }
                Ok(out)
            }
        }
        deserializer.deserialize_any(Issue)
    }
}

/// The things read from a delivery. No other field of the body is named
/// here, so no other field can be held.
#[derive(Debug, Deserialize)]
struct DeliveryBody {
    #[serde(rename = "matchedWebhookIds", default)]
    matched_webhook_ids: MatchedIds,
    #[serde(
        rename = "webhookEvent",
        default,
        deserialize_with = "short_string_or_nothing"
    )]
    webhook_event: Option<String>,
    #[serde(default)]
    issue: IssueRef,
}

/// A Jira issue key as it is passed on: `PROJ-123`. A project key is an
/// uppercase letter followed by up to 19 uppercase letters, digits or `_`;
/// the number is 1 to 10 digits. Anything else is left out — the key may end
/// up in a request path downstream.
#[must_use]
pub fn plain_issue_key(key: &str) -> Option<&str> {
    let (project, number) = key.split_once('-')?;
    let mut project_bytes = project.bytes();
    let first_ok = project_bytes.next().is_some_and(|b| b.is_ascii_uppercase());
    let rest_ok = project_bytes.all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_');
    let project_ok = first_ok && rest_ok && project.len() <= 20;
    let number_ok = (1..=10).contains(&number.len()) && number.bytes().all(|b| b.is_ascii_digit());
    (project_ok && number_ok).then_some(key)
}

/// An event name as it is passed on: `jira:issue_updated`. Lowercase letters,
/// `_` and `:`, at most 64 characters; anything else is left out.
#[must_use]
pub fn plain_event_name(event: &str) -> Option<&str> {
    let ok = (1..=64).contains(&event.len())
        && event
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b == b'_' || b == b':');
    ok.then_some(event)
}

/// What a workflow bound to a Jira registration is started with: that
/// something changed, on which site, through which webhook, and — when it is
/// a plain key — which issue.
///
/// No summary, description, status, assignee, comment or user name travels in
/// the trigger. A trigger input is stored with its execution and shown
/// wherever an execution is; the workflow reads Jira itself with its own
/// grants, which is also what makes it safe to start the same workflow from a
/// schedule (no push, no key) as a catch-up.
#[must_use]
pub fn jira_push_trigger_input(start: &PlannedStart) -> serde_json::Value {
    let mut push = serde_json::Map::new();
    push.insert("cloud_id".into(), serde_json::json!(start.cloud_id));
    push.insert("webhook_id".into(), serde_json::json!(start.webhook_id));
    if let Some(event) = start.event.as_deref().and_then(plain_event_name) {
        push.insert("event".into(), serde_json::json!(event));
    }
    if let Some(key) = start.issue_key.as_deref().and_then(plain_issue_key) {
        push.insert("issue_key".into(), serde_json::json!(key));
    }
    serde_json::json!({ "jira_push": push })
}

/// A registration a delivery's webhook id matched.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct Owner {
    pub id: Uuid,
    pub user_id: Uuid,
    pub cloud_id: String,
    pub webhook_id: i64,
    pub workflow_id: Option<Uuid>,
    /// The site URL of the registration's own Jira connection
    /// (`atlassian_integrations.site_url` for its user and cloud id). `None`
    /// when the connection is gone: such a registration acts on nothing.
    pub site_url: Option<String>,
}

/// Which Jira site a delivery is about, taken from its `issue.self`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliverySite {
    /// `https://<host>/…` — a site address (`example.atlassian.net`, or a
    /// custom domain). Lowercased.
    Host(String),
    /// `https://api.atlassian.com/ex/jira/<cloud id>/…` — the API gateway,
    /// which names the site by its cloud id.
    Cloud(String),
}

/// A site's host as both sides of the site comparison spell it: the parsed
/// URL's host (lowercased, IDNA-normalised by the parser) without a trailing
/// root dot. ONE spelling, so `Example.atlassian.net.` in one place and
/// `example.atlassian.net` in another name the same site (security review
/// 2026-10-15, F2-6).
fn site_host(url: &reqwest::Url) -> Option<String> {
    let host = url.host_str()?.to_ascii_lowercase();
    let host = host.strip_suffix('.').unwrap_or(&host).to_string();
    (!host.is_empty()).then_some(host)
}

/// The site an `issue.self` URL names, or `None` when it is not an `https`
/// URL with a host. Pure; only the host (or the gateway's cloud id) is kept.
#[must_use]
pub fn delivery_site(self_url: &str) -> Option<DeliverySite> {
    let url = reqwest::Url::parse(self_url).ok()?;
    if url.scheme() != "https" {
        return None;
    }
    let host = site_host(&url)?;
    if host == "api.atlassian.com" {
        let mut segments = url.path_segments()?;
        return match (segments.next(), segments.next(), segments.next()) {
            (Some("ex"), Some("jira"), Some(cloud)) if !cloud.is_empty() => {
                Some(DeliverySite::Cloud(cloud.to_string()))
            }
            _ => None,
        };
    }
    Some(DeliverySite::Host(host))
}

/// Why a delivery is not about a registration's site — the word the audit
/// line carries, so a site Atlassian names differently from the connection's
/// `site_url` (a custom domain on one side, `<site>.atlassian.net` on the
/// other) is told apart from another site's delivery (F2-6). Never a host.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OffSite {
    /// The delivery's `issue.self` names no site.
    DeliveryNamesNoSite,
    /// The registration's connection is gone, or its `site_url` is no URL.
    ConnectionHasNoSite,
    /// The gateway form names another cloud id.
    CloudIdDiffers,
    /// Two `*.atlassian.net` hosts, or two custom domains, that differ.
    HostDiffers,
    /// One host is `*.atlassian.net` and the other is not: possibly the same
    /// site under a custom domain. Still withheld — nothing proves it is.
    HostDiffersCustomDomain,
}

impl OffSite {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::DeliveryNamesNoSite => "delivery_names_no_site",
            Self::ConnectionHasNoSite => "connection_has_no_site",
            Self::CloudIdDiffers => "cloud_id_differs",
            Self::HostDiffers => "host_differs",
            Self::HostDiffersCustomDomain => "host_differs_custom_domain",
        }
    }
}

/// Whether a registration may act on a delivery from `site`, and why not.
/// `None` is "on this site". Fail closed: no site on either side is off it.
pub(crate) fn why_off_site(owner: &Owner, site: Option<&DeliverySite>) -> Option<OffSite> {
    match site {
        None => Some(OffSite::DeliveryNamesNoSite),
        Some(DeliverySite::Cloud(cloud)) => {
            (*cloud != owner.cloud_id).then_some(OffSite::CloudIdDiffers)
        }
        Some(DeliverySite::Host(host)) => {
            let Some(own) = owner
                .site_url
                .as_deref()
                .and_then(|u| reqwest::Url::parse(u).ok())
                .as_ref()
                .and_then(site_host)
            else {
                return Some(OffSite::ConnectionHasNoSite);
            };
            if own == *host {
                return None;
            }
            let atlassian = |h: &str| h.ends_with(".atlassian.net");
            Some(if atlassian(&own) == atlassian(host) {
                OffSite::HostDiffers
            } else {
                OffSite::HostDiffersCustomDomain
            })
        }
    }
}

/// Whether a registration may act on a delivery from `site`: the delivery is
/// about the registration's own site.
#[must_use]
pub(crate) fn owner_is_on_site(owner: &Owner, site: Option<&DeliverySite>) -> bool {
    why_off_site(owner, site).is_none()
}

/// Split matched registrations into those on the delivery's site and the
/// rest. Pure.
pub(crate) fn split_by_site(
    owners: Vec<Owner>,
    site: Option<&DeliverySite>,
) -> (Vec<Owner>, Vec<Owner>) {
    owners
        .into_iter()
        .partition(|owner| owner_is_on_site(owner, site))
}

/// A fixed-window counter per registration, bounded: when it holds more than
/// [`Self::MAX_KEYS`] registrations it drops every window that has ended.
pub(crate) struct RegistrationBudget {
    max: u32,
    window: std::time::Duration,
    windows: dashmap::DashMap<Uuid, (u32, std::time::Instant)>,
}

impl RegistrationBudget {
    const MAX_KEYS: usize = 4096;

    pub(crate) fn new(max: u32, window: std::time::Duration) -> Self {
        Self {
            max,
            window,
            windows: dashmap::DashMap::new(),
        }
    }

    /// Spend one unit of `registration`'s budget; `false` when it is spent.
    pub(crate) fn allow(&self, registration: Uuid) -> bool {
        let now = std::time::Instant::now();
        if self.windows.len() > Self::MAX_KEYS {
            let window = self.window;
            self.windows
                .retain(|_, (_, started)| now.duration_since(*started) < window);
        }
        let mut entry = self.windows.entry(registration).or_insert((0, now));
        let (count, started) = entry.value_mut();
        if now.duration_since(*started) >= self.window {
            *count = 1;
            *started = now;
            true
        } else if *count < self.max {
            *count += 1;
            true
        } else {
            false
        }
    }
}

/// The per-registration budgets the receiver holds (per replica).
pub struct DeliveryBudgets {
    pub(crate) deliveries: RegistrationBudget,
    pub(crate) refusal_records: RegistrationBudget,
}

impl Default for DeliveryBudgets {
    fn default() -> Self {
        Self {
            deliveries: RegistrationBudget::new(
                DELIVERIES_PER_REGISTRATION_PER_MINUTE,
                std::time::Duration::from_secs(60),
            ),
            refusal_records: RegistrationBudget::new(
                REFUSAL_RECORDS_PER_REGISTRATION_PER_HOUR,
                std::time::Duration::from_secs(3600),
            ),
        }
    }
}

/// Split matched registrations into those a delivery may act on and those it
/// may not. Pure.
///
/// A webhook id that names registrations on more than one site is AMBIGUOUS:
/// the delivery does not say which site sent it, so acting on any of them
/// could start one user's workflow for another site's ticket (and hand it
/// that ticket's key). All of them are withheld.
pub(crate) fn split_ambiguous(owners: Vec<Owner>) -> (Vec<Owner>, Vec<Owner>) {
    let mut sites_per_webhook: std::collections::HashMap<i64, Vec<&str>> =
        std::collections::HashMap::new();
    for owner in &owners {
        let sites = sites_per_webhook.entry(owner.webhook_id).or_default();
        if !sites.contains(&owner.cloud_id.as_str()) {
            sites.push(&owner.cloud_id);
        }
    }
    let ambiguous_ids: Vec<i64> = sites_per_webhook
        .iter()
        .filter(|(_, sites)| sites.len() > 1)
        .map(|(id, _)| *id)
        .collect();
    owners
        .into_iter()
        .partition(|owner| !ambiguous_ids.contains(&owner.webhook_id))
}

/// The bearer token of a request, when there is one of a plausible length.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer")
        && !token.is_empty()
        && token.len() <= push_jwt::MAX_JWT_BYTES)
        .then_some(token)
}

/// `X-Atlassian-Webhook-Identifier`, when it is something that can be a key.
fn delivery_id(headers: &HeaderMap) -> Option<&str> {
    let id = headers
        .get("x-atlassian-webhook-identifier")?
        .to_str()
        .ok()?
        .trim();
    ((1..=MAX_DELIVERY_ID_LEN).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_graphic()))
        .then_some(id)
}

impl AtlassianIntegrationService {
    /// Authenticate one delivery, decide what it starts, and record it as
    /// handled. Starts nothing itself: the starts are returned for
    /// [`run_planned_starts`], so the caller can answer Atlassian first.
    pub async fn receive_push(&self, headers: &HeaderMap, body: Body) -> PushReceipt {
        // 1. Presence. No crypto, no body, no database.
        let Some(token) = bearer_token(headers) else {
            return PushReceipt::just(ReceiptNote::MissingBearer);
        };

        // 2. The signature, under the app's client secret.
        let Some(secret) = self
            .client_secret()
            .filter(|s| s.len() >= push_jwt::MIN_CLIENT_SECRET_BYTES)
        else {
            tracing::error!(
                "Jira webhook delivery received but ATLASSIAN_CLIENT_SECRET is unset or too \
                 short to verify with; answering 503"
            );
            return PushReceipt::just(ReceiptNote::NotConfigured);
        };
        let verified = match push_jwt::verify_delivery_jwt(token, secret.as_bytes()) {
            Ok(verified) => verified,
            Err(refusal) => {
                tracing::warn!(
                    target: "talos_audit",
                    event_kind = "jira_webhook_refused",
                    reason = refusal.as_str(),
                    "Jira webhook delivery refused: its token did not verify"
                );
                return PushReceipt::just(ReceiptNote::Refused(refusal));
            }
        };
        push_jwt::log_shape_once(&verified);

        // 2b. Single use. Before the body and before any database read.
        let token_hash = crate::push_replay::token_hash(token);
        match self
            .delivery_replay
            .admit(token_hash, verified.expires_at)
            .await
        {
            crate::push_replay::ReplayVerdict::Fresh => {}
            crate::push_replay::ReplayVerdict::Replayed => {
                tracing::warn!(
                    target: "talos_audit",
                    event_kind = "jira_webhook_replayed",
                    "Jira webhook delivery refused: its token was already used"
                );
                return PushReceipt::just(ReceiptNote::Replayed);
            }
            crate::push_replay::ReplayVerdict::Unavailable => {
                return PushReceipt::just(ReceiptNote::ReplayUnavailable);
            }
        }

        let receipt = self.receive_verified_delivery(headers, body).await;
        // A 5xx asks Atlassian to retry, perhaps with this same token; the
        // retry must not be refused as a replay of a delivery that did nothing.
        if receipt.status().is_server_error() {
            self.delivery_replay.release_everywhere(&token_hash).await;
        }
        receipt
    }

    /// Steps 3 onward, for a delivery whose token verified and was fresh.
    async fn receive_verified_delivery(&self, headers: &HeaderMap, body: Body) -> PushReceipt {
        // 3. The body, bounded, and only four things out of it.
        let declared_too_large = headers
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .is_some_and(|len| len > JIRA_WEBHOOK_MAX_BODY_BYTES);
        if declared_too_large {
            return PushReceipt::just(ReceiptNote::BodyTooLarge);
        }
        let Ok(bytes) = axum::body::to_bytes(body, JIRA_WEBHOOK_MAX_BODY_BYTES).await else {
            return PushReceipt::just(ReceiptNote::BodyTooLarge);
        };
        let Ok(delivery) = serde_json::from_slice::<DeliveryBody>(&bytes) else {
            tracing::warn!(
                body_len = bytes.len(),
                "authenticated Jira webhook delivery is not the JSON a delivery is"
            );
            return PushReceipt::just(ReceiptNote::BodyMalformed);
        };
        drop(bytes);
        if delivery.matched_webhook_ids.truncated {
            tracing::warn!(
                kept = MAX_MATCHED_WEBHOOK_IDS,
                "Jira webhook delivery named more webhook ids than are looked up"
            );
        }
        // The site the delivery is about; the URL itself is not kept.
        let site = delivery.issue.self_url.as_deref().and_then(delivery_site);
        if delivery.matched_webhook_ids.ids.is_empty() {
            return PushReceipt::just(ReceiptNote::Accepted {
                matched: 0,
                off_site: 0,
                ambiguous: 0,
                rate_limited: 0,
                capped: 0,
                duplicates: 0,
            });
        }

        // 4. Whose webhooks these are: asked of the registrations, by the id
        //    Atlassian issued, with each registration's own site. Nothing
        //    else in the request is consulted.
        let owners: Vec<Owner> = match sqlx::query_as(
            "SELECT r.id, r.user_id, r.cloud_id, r.webhook_id, r.workflow_id, i.site_url \
             FROM atlassian_webhook_registrations r \
             LEFT JOIN atlassian_integrations i \
               ON i.user_id = r.user_id AND i.cloud_id = r.cloud_id \
             WHERE r.webhook_id = ANY($1) \
             ORDER BY r.webhook_id, r.cloud_id LIMIT $2",
        )
        .bind(&delivery.matched_webhook_ids.ids)
        .bind(MAX_MATCHED_REGISTRATIONS as i64 + 1)
        .fetch_all(&self.db_pool)
        .await
        {
            Ok(owners) if owners.len() > MAX_MATCHED_REGISTRATIONS => {
                tracing::error!(
                    target: "talos_audit",
                    event_kind = "jira_push_too_many_registrations",
                    limit = MAX_MATCHED_REGISTRATIONS,
                    "Jira webhook delivery matched more registrations than are read; nothing \
                     is started, because a partial read could hide an ambiguous webhook id"
                );
                return PushReceipt::just(ReceiptNote::TooManyRegistrations);
            }
            Ok(owners) => owners,
            Err(e) => {
                // Not "no such webhook": the read did not answer. Atlassian
                // retries a 5xx, and a 200 here would drop the delivery.
                tracing::error!(error = %e, "Jira webhook delivery: registrations could not be read; answering 503");
                return PushReceipt::just(ReceiptNote::LookupFailed);
            }
        };
        let matched = owners.len();
        // A webhook id is unique only within one Jira site: a registration
        // acts only on a delivery about its own site.
        let (on_site, off_site) = split_by_site(owners, site.as_ref());
        let (deliverable, ambiguous) = split_ambiguous(on_site);

        // 5. The execution pause, before anything records this delivery.
        let pause = talos_execution_pause::push_admission(
            &self.db_pool,
            deliverable.iter().any(|o| o.workflow_id.is_some()),
            talos_execution_pause::PauseGatePath::JiraPush,
        )
        .await;
        if pause.defers() {
            tracing::info!(admission = ?pause, "Jira webhook delivery deferred by the execution pause (503)");
            return PushReceipt::just(ReceiptNote::Deferred);
        }

        for owner in &off_site {
            let why = why_off_site(owner, site.as_ref()).unwrap_or(OffSite::HostDiffers);
            self.record_off_site(owner, why).await;
        }
        for owner in &ambiguous {
            self.record_ambiguous(owner).await;
        }
        if deliverable.is_empty() && ambiguous.is_empty() && !off_site.is_empty() {
            return PushReceipt::just(ReceiptNote::SiteMismatch { matched });
        }

        // 5b. Each registration's per-minute budget (per replica).
        let (deliverable, over_budget): (Vec<Owner>, Vec<Owner>) = deliverable
            .into_iter()
            .partition(|owner| self.delivery_budgets.deliveries.allow(owner.id));
        for owner in &over_budget {
            tracing::warn!(
                target: "talos_audit",
                event_kind = "jira_push_rate_limited",
                registration = %owner.id,
                limit_per_minute = DELIVERIES_PER_REGISTRATION_PER_MINUTE,
                "Jira webhook delivery dropped: this registration is over its per-minute budget"
            );
        }

        // 6. Each registration handles a delivery once, and remembers at most
        //    DEDUP_ROWS_PER_REGISTRATION deliveries.
        let candidate_ids: Vec<Uuid> = deliverable.iter().map(|o| o.id).collect();
        let (fresh_ids, capped_ids): (Vec<Uuid>, Vec<Uuid>) = match delivery_id(headers) {
            Some(delivery_id) if !candidate_ids.is_empty() => {
                match sqlx::query_as::<_, (Uuid, bool, bool)>(
                    "WITH cand AS ( \
                         SELECT r AS registration_id, \
                                (SELECT count(*) FROM atlassian_webhook_deliveries d \
                                  WHERE d.registration_id = r) AS held \
                         FROM unnest($1::uuid[]) AS r), \
                     ins AS ( \
                         INSERT INTO atlassian_webhook_deliveries (registration_id, delivery_id) \
                         SELECT registration_id, $2 FROM cand WHERE held < $3 \
                         ON CONFLICT DO NOTHING RETURNING registration_id) \
                     SELECT c.registration_id, (c.held >= $3), (i.registration_id IS NOT NULL) \
                     FROM cand c LEFT JOIN ins i USING (registration_id)",
                )
                .bind(&candidate_ids)
                .bind(delivery_id)
                .bind(DEDUP_ROWS_PER_REGISTRATION)
                .fetch_all(&self.db_pool)
                .await
                {
                    Ok(rows) => (
                        rows.iter().filter(|r| r.2).map(|r| r.0).collect(),
                        rows.iter().filter(|r| r.1).map(|r| r.0).collect(),
                    ),
                    Err(e) => {
                        tracing::error!(error = %e, "Jira webhook delivery could not be recorded as handled; answering 503");
                        return PushReceipt::just(ReceiptNote::DedupFailed);
                    }
                }
            }
            // No identifier to recognise a retry by: handled as new. The
            // token is single-use (step 2b), so a resend of this delivery
            // under the same token is refused there; the workflow a delivery
            // starts is one that is safe to run twice.
            _ => (candidate_ids.clone(), Vec::new()),
        };
        for owner in deliverable.iter().filter(|o| capped_ids.contains(&o.id)) {
            self.record_refusal(owner, REFUSAL_DEDUP_CAP).await;
        }
        let duplicates = candidate_ids.len() - fresh_ids.len() - capped_ids.len();

        if !fresh_ids.is_empty() {
            if let Err(e) = sqlx::query(
                "UPDATE atlassian_webhook_registrations SET last_delivery_at = now() \
                 WHERE id = ANY($1)",
            )
            .bind(&fresh_ids)
            .execute(&self.db_pool)
            .await
            {
                tracing::warn!(error = %e, "Jira webhook delivery: last_delivery_at was not recorded");
            }
        }

        // 7. What to start, and as whom: the registration's own user and
        //    the workflow that user bound to it.
        let event = delivery.webhook_event;
        let issue_key = delivery.issue.key;
        let starts = deliverable
            .into_iter()
            .filter(|owner| fresh_ids.contains(&owner.id))
            .filter_map(|owner| {
                Some(PlannedStart {
                    registration_id: owner.id,
                    user_id: owner.user_id,
                    workflow_id: owner.workflow_id?,
                    cloud_id: owner.cloud_id,
                    webhook_id: owner.webhook_id,
                    event: event
                        .as_deref()
                        .and_then(plain_event_name)
                        .map(String::from),
                    issue_key: issue_key
                        .as_deref()
                        .and_then(plain_issue_key)
                        .map(String::from),
                })
            })
            .collect();

        PushReceipt {
            note: ReceiptNote::Accepted {
                matched,
                off_site: off_site.len(),
                ambiguous: ambiguous.len(),
                rate_limited: over_budget.len(),
                capped: capped_ids.len(),
                duplicates,
            },
            starts,
        }
    }

    /// A delivery withheld from a registration because it is about another
    /// site (or names none): said in the audit stream, and — when the
    /// registration would have started a workflow, within the refusal-record
    /// budget — as a row its owner can find.
    async fn record_off_site(&self, owner: &Owner, why: OffSite) {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "jira_push_site_mismatch",
            registration = %owner.id,
            user_id = %owner.user_id,
            webhook_id = owner.webhook_id,
            mismatch = why.as_str(),
            "Jira webhook delivery withheld: it is not about this registration's site, so its \
             webhook id may be another site's"
        );
        self.record_refusal(owner, REFUSAL_SITE_MISMATCH).await;
    }

    /// [`record_not_started`] for a registration with a bound workflow, within
    /// its refusal-record budget.
    async fn record_refusal(&self, owner: &Owner, reason: &'static str) {
        let Some(workflow_id) = owner.workflow_id else {
            return;
        };
        if !self.delivery_budgets.refusal_records.allow(owner.id) {
            return;
        }
        record_not_started(
            &self.db_pool,
            owner.user_id,
            owner.id,
            &owner.cloud_id,
            owner.webhook_id,
            workflow_id,
            reason,
        )
        .await;
    }

    /// A delivery withheld because its webhook id is registered on more than
    /// one site: said in the audit stream, and — when the registration would
    /// have started a workflow, within the refusal-record budget — as a row
    /// its owner can find.
    async fn record_ambiguous(&self, owner: &Owner) {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "jira_push_ambiguous_webhook_id",
            registration = %owner.id,
            user_id = %owner.user_id,
            webhook_id = owner.webhook_id,
            "Jira webhook delivery withheld: this webhook id is registered on more than one \
             site, and a delivery does not say which site sent it. Delete and re-create the \
             channel."
        );
        // Within the same refusal-record budget as the other refusals
        // (security review 2026-10-15, F2-2).
        self.record_refusal(owner, REFUSAL_AMBIGUOUS_WEBHOOK_ID)
            .await;
    }
}

/// The durable record of a start that did not happen: one row in the shared
/// integration-events log, with a reason from a closed set.
async fn record_not_started(
    pool: &sqlx::PgPool,
    user_id: Uuid,
    registration_id: Uuid,
    cloud_id: &str,
    webhook_id: i64,
    workflow_id: Uuid,
    reason: &'static str,
) {
    if let Err(e) = insert_channel_audit(
        pool,
        ChannelAuditEvent {
            integration_id: None,
            user_id,
            event_type: "jira_workflow_not_started",
            target: Some(cloud_id),
            success: false,
            error_message: Some(reason),
            metadata: serde_json::json!({
                "registration_id": registration_id,
                "webhook_id": webhook_id,
                "workflow_id": workflow_id,
            }),
        },
    )
    .await
    {
        tracing::warn!(registration = %registration_id, error = %e, "jira_workflow_not_started audit log insert failed");
    }
}

/// Start each workflow a delivery called for, once.
///
/// Through [`ExecutionOrchestrationService::trigger`], as the registration's
/// own user — the platform pause, the workflow's ownership and liveness, its
/// actor's budget and ceilings, its input schema and its concurrency limit
/// all apply, exactly as for `trigger_workflow`. Ownership is therefore
/// checked again here: a registration naming a workflow that is no longer
/// its user's starts nothing.
///
/// A start that is refused is NOT retried: the delivery has been answered and
/// recorded. It is written down — a WARN under `talos_audit` and a row in the
/// shared integration-events log, with a reason from the trigger service's
/// closed set — because a binding that silently starts nothing is the failure
/// nobody would otherwise see.
pub async fn run_planned_starts(
    pool: &sqlx::PgPool,
    orchestration: Option<&Arc<ExecutionOrchestrationService>>,
    starts: &[PlannedStart],
) {
    for start in starts {
        let outcome = match orchestration {
            None => Err(PUSH_REFUSAL_TRIGGER_SERVICE_NOT_WIRED),
            Some(service) => match service
                .trigger(TriggerInput {
                    workflow_id: start.workflow_id,
                    user_id: start.user_id,
                    trigger_input: jira_push_trigger_input(start),
                    trigger_agent_id: None,
                    inject_memory_context: false,
                    // What started the run: this registration's push.
                    origin: talos_execution_orchestration::ExecutionOrigin::PushChannel {
                        integration: crate::push::INTEGRATION_NAME,
                        channel_id: start.registration_id,
                    },
                    validate_only: false,
                    dry_run: false,
                    wait_ms: None,
                })
                .await
            {
                Ok(TriggerOutcome::Dispatched(started)) => Ok(started.execution_id),
                // Not reachable with `validate_only: false`; named so it is never read as a start.
                Ok(TriggerOutcome::ValidatedOnly(_)) => Err(PUSH_REFUSAL_TRIGGER_FAILED),
                Err(e) => {
                    tracing::warn!(
                        registration = %start.registration_id,
                        workflow_id = %start.workflow_id,
                        user_id = %start.user_id,
                        error = %e,
                        "Jira push: the bound workflow was not started"
                    );
                    Err(e.push_refusal_reason())
                }
            },
        };
        match outcome {
            Ok(execution_id) => tracing::info!(
                event_kind = "jira_push_started_workflow",
                registration = %start.registration_id,
                workflow_id = %start.workflow_id,
                %execution_id,
                "Jira push started its bound workflow"
            ),
            Err(reason) => {
                tracing::warn!(
                    target: "talos_audit",
                    event_kind = "jira_push_workflow_not_started",
                    registration = %start.registration_id,
                    workflow_id = %start.workflow_id,
                    user_id = %start.user_id,
                    reason,
                    "Jira push: bound workflow not started; this delivery will not start it again"
                );
                record_not_started(
                    pool,
                    start.user_id,
                    start.registration_id,
                    &start.cloud_id,
                    start.webhook_id,
                    start.workflow_id,
                    reason,
                )
                .await;
            }
        }
    }
}

/// `POST /api/atlassian/webhook`. Answers as soon as the delivery is
/// authenticated, mapped and recorded; the starts run after the answer.
pub async fn webhook_handler(
    State(service): State<Arc<AtlassianIntegrationService>>,
    // The shared trigger service, layered on the app: a delivery starts its
    // workflow through the same gates as any other trigger.
    Extension(orchestration): Extension<Option<Arc<ExecutionOrchestrationService>>>,
    request: Request,
) -> StatusCode {
    let (parts, body) = request.into_parts();
    let receipt = service.receive_push(&parts.headers, body).await;
    let status = receipt.status();
    if !receipt.starts.is_empty() {
        let pool = service.pool().clone();
        tokio::spawn(async move {
            run_planned_starts(&pool, orchestration.as_ref(), &receipt.starts).await;
        });
    }
    status
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    const SECRET: &str = "test-client-secret-of-enough-length";

    /// A pool that can never connect: any database read in a test that uses
    /// it fails, so a receipt that is NOT a database failure proves no read
    /// was attempted.
    fn unreachable_pool() -> sqlx::PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(std::time::Duration::from_millis(250))
            .connect_lazy("postgres://talos:talos@127.0.0.1:1/talos_unreachable")
            .expect("lazy pool construction should not fail")
    }

    fn service() -> AtlassianIntegrationService {
        AtlassianIntegrationService::with_client_for_tests(
            unreachable_pool(),
            "test-client-id",
            SECRET,
            "https://talos.example.com/api/atlassian/callback",
        )
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn token(alg: Algorithm, secret: &str, claims: &serde_json::Value) -> String {
        encode(
            &Header::new(alg),
            claims,
            &EncodingKey::from_secret(secret.as_bytes()),
        )
        .expect("sign")
    }

    /// A fresh token each call: a token is single-use (`push_replay`), and
    /// Atlassian's carry a `jti`.
    fn valid_token() -> String {
        token(
            Algorithm::HS256,
            SECRET,
            &serde_json::json!({"exp": now() + 120, "jti": Uuid::new_v4().to_string()}),
        )
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        headers
    }

    fn delivery() -> Body {
        Body::from(
            serde_json::json!({
                "webhookEvent": "jira:issue_updated",
                "matchedWebhookIds": [1000],
                "issue": {"key": "PROJ-7", "fields": {"summary": "Quarterly numbers"}},
            })
            .to_string(),
        )
    }

    fn hand_built(alg: &str) -> String {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        format!(
            "{}.{}.{}",
            URL_SAFE_NO_PAD.encode(serde_json::json!({"alg": alg, "typ": "JWT"}).to_string()),
            URL_SAFE_NO_PAD.encode(serde_json::json!({"exp": now() + 120}).to_string()),
            "AAAA"
        )
    }

    /// The control for every test below: with a token that verifies, the
    /// receiver DOES go to the database — and, the pool being unreachable,
    /// says so. So a receipt other than `LookupFailed` in the tests that
    /// follow means the database was never asked.
    #[tokio::test]
    async fn a_verified_delivery_reaches_the_database() {
        let receipt = service()
            .receive_push(&bearer(&valid_token()), delivery())
            .await;
        assert_eq!(receipt.note, ReceiptNote::LookupFailed);
        assert_eq!(receipt.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(receipt.starts.is_empty());
    }

    #[tokio::test]
    async fn a_delivery_with_no_bearer_token_is_refused_before_any_database_read() {
        let svc = service();
        let mut basic = HeaderMap::new();
        basic.insert(header::AUTHORIZATION, "Basic dXNlcjpwYXNz".parse().unwrap());
        let mut empty = HeaderMap::new();
        empty.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        let mut long = HeaderMap::new();
        long.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", "a".repeat(push_jwt::MAX_JWT_BYTES + 1))
                .parse()
                .unwrap(),
        );
        for headers in [HeaderMap::new(), basic, empty, long] {
            let receipt = svc.receive_push(&headers, delivery()).await;
            assert_eq!(receipt.note, ReceiptNote::MissingBearer);
            assert_eq!(receipt.status(), StatusCode::UNAUTHORIZED);
            assert!(receipt.starts.is_empty());
        }
    }

    #[tokio::test]
    async fn a_delivery_whose_signature_does_not_verify_is_refused_before_any_database_read() {
        let forged = token(
            Algorithm::HS256,
            "another-secret-of-enough-length-",
            &serde_json::json!({"exp": now() + 120}),
        );
        let receipt = service().receive_push(&bearer(&forged), delivery()).await;
        assert_eq!(receipt.note, ReceiptNote::Refused(JwtRefusal::BadSignature));
        assert_eq!(receipt.status(), StatusCode::UNAUTHORIZED);
        assert!(receipt.starts.is_empty());
    }

    #[tokio::test]
    async fn a_delivery_naming_none_or_rs256_is_refused_before_any_database_read() {
        let svc = service();
        for alg in ["none", "RS256", "ES256", "PS256", "EdDSA"] {
            let receipt = svc
                .receive_push(&bearer(&hand_built(alg)), delivery())
                .await;
            assert_eq!(
                receipt.note,
                ReceiptNote::Refused(JwtRefusal::AlgorithmNotAccepted),
                "{alg}"
            );
            assert_eq!(receipt.status(), StatusCode::UNAUTHORIZED);
        }
        // `none` with no signature at all, the form the attack is named for.
        let unsigned = hand_built("none");
        let unsigned = format!("{}.", unsigned.rsplit_once('.').unwrap().0);
        let receipt = svc.receive_push(&bearer(&unsigned), delivery()).await;
        assert_eq!(
            receipt.note,
            ReceiptNote::Refused(JwtRefusal::AlgorithmNotAccepted)
        );
    }

    #[tokio::test]
    async fn an_expired_delivery_is_refused_before_any_database_read() {
        let expired = token(
            Algorithm::HS256,
            SECRET,
            &serde_json::json!({"exp": now() - 600}),
        );
        let receipt = service().receive_push(&bearer(&expired), delivery()).await;
        assert_eq!(receipt.note, ReceiptNote::Refused(JwtRefusal::Expired));
        assert_eq!(receipt.status(), StatusCode::UNAUTHORIZED);
    }

    /// A deployment with no client secret (or one too short to be a key)
    /// verifies nothing and admits nothing.
    #[tokio::test]
    async fn without_a_usable_client_secret_nothing_is_verified_or_admitted() {
        for secret in ["", "short"] {
            let svc = AtlassianIntegrationService::with_client_for_tests(
                unreachable_pool(),
                "test-client-id",
                secret,
                "https://talos.example.com/api/atlassian/callback",
            );
            // Signed with that very secret: it would verify, if verifying
            // with it were allowed.
            let signed = token(
                Algorithm::HS256,
                secret,
                &serde_json::json!({"exp": now() + 120}),
            );
            let receipt = svc.receive_push(&bearer(&signed), delivery()).await;
            assert_eq!(receipt.note, ReceiptNote::NotConfigured, "{secret:?}");
            assert_eq!(receipt.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
    }

    #[tokio::test]
    async fn a_body_that_is_too_large_or_not_a_delivery_is_refused_without_a_database_read() {
        let svc = service();

        let big = Body::from(vec![b' '; JIRA_WEBHOOK_MAX_BODY_BYTES + 1]);
        assert_eq!(
            svc.receive_push(&bearer(&valid_token()), big).await.note,
            ReceiptNote::BodyTooLarge
        );
        let mut declared = bearer(&valid_token());
        declared.insert(
            header::CONTENT_LENGTH,
            (JIRA_WEBHOOK_MAX_BODY_BYTES + 1)
                .to_string()
                .parse()
                .unwrap(),
        );
        assert_eq!(
            svc.receive_push(&declared, Body::empty()).await.note,
            ReceiptNote::BodyTooLarge
        );

        for junk in ["", "not json", "[1,2,3]", r#"{"matchedWebhookIds":["a"]}"#] {
            let receipt = svc
                .receive_push(&bearer(&valid_token()), Body::from(junk))
                .await;
            assert_eq!(receipt.note, ReceiptNote::BodyMalformed, "{junk}");
            assert_eq!(receipt.status(), StatusCode::BAD_REQUEST);
        }

        // A delivery that matched nothing asks the database nothing.
        for body in [
            r#"{}"#,
            r#"{"matchedWebhookIds":[]}"#,
            r#"{"matchedWebhookIds":null}"#,
        ] {
            let receipt = svc
                .receive_push(&bearer(&valid_token()), Body::from(body))
                .await;
            assert_eq!(
                receipt.note,
                ReceiptNote::Accepted {
                    matched: 0,
                    off_site: 0,
                    ambiguous: 0,
                    rate_limited: 0,
                    capped: 0,
                    duplicates: 0
                },
                "{body}"
            );
            assert_eq!(receipt.status(), StatusCode::OK);
        }
    }

    /// Only the three named things are read, whatever else the body holds
    /// and whatever shape the rest takes.
    #[test]
    fn only_the_webhook_ids_the_event_and_the_issue_key_are_read() {
        let body = serde_json::json!({
            "timestamp": 1_760_000_000_000_i64,
            "webhookEvent": "jira:issue_updated",
            "matchedWebhookIds": [1000, 1001, 1000],
            "user": {"displayName": "Someone Example", "accountId": "abc"},
            "issue": {
                "id": "10001",
                "self": "https://example.atlassian.net/rest/api/3/issue/10001",
                "key": "PROJ-7",
                "fields": {"summary": "Quarterly numbers", "description": {"type": "doc"}},
            },
            "changelog": {"items": [{"field": "status", "toString": "Done"}]},
        });
        let parsed: DeliveryBody = serde_json::from_value(body).unwrap();
        assert_eq!(parsed.matched_webhook_ids.ids, [1000, 1001]);
        assert!(!parsed.matched_webhook_ids.truncated);
        assert_eq!(parsed.webhook_event.as_deref(), Some("jira:issue_updated"));
        assert_eq!(parsed.issue.key.as_deref(), Some("PROJ-7"));

        // Fields of an unexpected shape are skipped, not errors.
        for odd in [
            serde_json::json!({"matchedWebhookIds": [1], "issue": "PROJ-7", "webhookEvent": 5}),
            serde_json::json!({"matchedWebhookIds": [1], "issue": {"key": {"nested": true}}}),
            serde_json::json!({"matchedWebhookIds": [1], "issue": [1, 2], "webhookEvent": null}),
            serde_json::json!({"matchedWebhookIds": [1], "issue": {"key": "K".repeat(500)}}),
        ] {
            let parsed: DeliveryBody = serde_json::from_value(odd.clone()).expect("readable");
            assert_eq!(parsed.matched_webhook_ids.ids, [1], "{odd}");
            assert_eq!(parsed.issue.key, None, "{odd}");
            assert_eq!(parsed.webhook_event, None, "{odd}");
        }

        // More ids than are looked up: the first are kept and it is said.
        let many: Vec<i64> = (0..500).collect();
        let parsed: DeliveryBody =
            serde_json::from_value(serde_json::json!({"matchedWebhookIds": many})).unwrap();
        assert_eq!(
            parsed.matched_webhook_ids.ids.len(),
            MAX_MATCHED_WEBHOOK_IDS
        );
        assert!(parsed.matched_webhook_ids.truncated);
    }

    #[test]
    fn an_issue_key_is_passed_on_only_when_it_is_a_plain_key() {
        for good in [
            "PROJ-7",
            "A-1",
            "AB_C2-1234567890",
            "ABCDEFGHIJKLMNOPQRST-1",
        ] {
            assert_eq!(plain_issue_key(good), Some(good));
        }
        for bad in [
            "",
            "PROJ",
            "PROJ-",
            "-7",
            "proj-7",
            "PROJ-7a",
            "PROJ-12345678901",
            "ABCDEFGHIJKLMNOPQRSTU-1",
            "1PROJ-7",
            "PROJ-7/../../x",
            "PROJ-7?expand=all",
            "PROJ 7",
            "PROJ-7\n",
            "PR-OJ-7",
        ] {
            assert_eq!(plain_issue_key(bad), None, "{bad:?}");
        }
    }

    fn start(event: Option<&str>, issue_key: Option<&str>) -> PlannedStart {
        PlannedStart {
            registration_id: Uuid::nil(),
            user_id: Uuid::nil(),
            workflow_id: Uuid::nil(),
            cloud_id: "11111111-2222-3333-4444-555555555555".into(),
            webhook_id: 1000,
            event: event.map(String::from),
            issue_key: issue_key.map(String::from),
        }
    }

    /// The trigger names what changed by identifier and carries nothing a
    /// ticket says.
    #[test]
    fn the_trigger_carries_identifiers_only() {
        assert_eq!(
            jira_push_trigger_input(&start(Some("jira:issue_updated"), Some("PROJ-7"))),
            serde_json::json!({
                "jira_push": {
                    "cloud_id": "11111111-2222-3333-4444-555555555555",
                    "webhook_id": 1000,
                    "event": "jira:issue_updated",
                    "issue_key": "PROJ-7",
                }
            })
        );
        // Anything that is not a plain key or a plain event name is left out,
        // even if a caller built the start by hand.
        let odd = jira_push_trigger_input(&start(
            Some("Quarterly numbers"),
            Some("PROJ-7 Quarterly numbers"),
        ));
        assert_eq!(
            odd,
            serde_json::json!({
                "jira_push": {
                    "cloud_id": "11111111-2222-3333-4444-555555555555",
                    "webhook_id": 1000,
                }
            })
        );
        let keys: Vec<&String> = odd["jira_push"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["cloud_id", "webhook_id"]);
    }

    fn owner(webhook_id: i64, cloud_id: &str) -> Owner {
        Owner {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            cloud_id: cloud_id.to_string(),
            webhook_id,
            workflow_id: Some(Uuid::new_v4()),
            site_url: Some(format!("https://{cloud_id}.example.test")),
        }
    }

    /// A token is single-use, refused the second time before the body or
    /// the database is read (security review 2026-10-14, F-2 / F-10).
    #[tokio::test]
    async fn a_replayed_token_is_refused_before_any_database_read() {
        let svc = service();
        let headers = bearer(&valid_token());
        // Matches nothing, so the first use reads no database either.
        let first = svc
            .receive_push(&headers, Body::from(r#"{"matchedWebhookIds":[]}"#))
            .await;
        assert!(matches!(first.note, ReceiptNote::Accepted { .. }));
        // The replay names a webhook id: were the body or the database read,
        // the unreachable pool would answer LookupFailed.
        let replay = svc.receive_push(&headers, delivery()).await;
        assert_eq!(replay.note, ReceiptNote::Replayed);
        assert!(replay.starts.is_empty());
        // Without the identifier header too: the token is the key, not a
        // header the sender chooses.
        assert_eq!(
            svc.receive_push(&headers, delivery()).await.note,
            ReceiptNote::Replayed
        );
    }

    /// A delivery answered with a 5xx is retried by Atlassian, perhaps with
    /// the same token; that retry must be read again, not refused.
    #[tokio::test]
    async fn a_token_whose_delivery_was_answered_with_a_5xx_can_be_retried() {
        let svc = service();
        let headers = bearer(&valid_token());
        let first = svc.receive_push(&headers, delivery()).await;
        assert_eq!(first.note, ReceiptNote::LookupFailed);
        assert_eq!(first.status(), StatusCode::SERVICE_UNAVAILABLE);
        let retry = svc.receive_push(&headers, delivery()).await;
        assert_eq!(
            retry.note,
            ReceiptNote::LookupFailed,
            "not refused as a replay"
        );
    }

    #[test]
    fn a_delivery_site_is_the_host_of_issue_self_or_the_gateways_cloud_id() {
        assert_eq!(
            delivery_site("https://Example.atlassian.net/rest/api/3/issue/10001"),
            Some(DeliverySite::Host("example.atlassian.net".into()))
        );
        assert_eq!(
            delivery_site(
                "https://api.atlassian.com/ex/jira/11111111-2222-3333-4444-555555555555/rest/api/3/issue/1"
            ),
            Some(DeliverySite::Cloud(
                "11111111-2222-3333-4444-555555555555".into()
            ))
        );
        for not_a_site in [
            "http://example.atlassian.net/rest/api/3/issue/1",
            "https://api.atlassian.com/rest/api/3/issue/1",
            "not a url",
            "",
        ] {
            assert_eq!(delivery_site(not_a_site), None, "{not_a_site}");
        }
    }

    #[test]
    fn a_registration_acts_only_on_a_delivery_about_its_own_site() {
        let mine = owner(1000, "site-a");
        let theirs = owner(1000, "site-b");
        let host = DeliverySite::Host("site-a.example.test".into());
        let (on, off) = split_by_site(vec![mine.clone(), theirs.clone()], Some(&host));
        assert_eq!(on, vec![mine.clone()]);
        assert_eq!(off, vec![theirs.clone()]);
        // On the gateway the cloud id decides.
        let cloud = DeliverySite::Cloud("site-b".into());
        let (on, _) = split_by_site(vec![mine.clone(), theirs.clone()], Some(&cloud));
        assert_eq!(on, vec![theirs]);
        // No site named: nothing acts. A registration whose connection is
        // gone acts on nothing either.
        let (on, _) = split_by_site(vec![mine.clone()], None);
        assert!(on.is_empty());
        let orphan = Owner {
            site_url: None,
            ..mine
        };
        assert!(!owner_is_on_site(&orphan, Some(&host)));
    }

    /// One spelling of a site on both sides (F2-6): case and a trailing root
    /// dot do not make a delivery another site's. A difference is named by
    /// its class, so a custom domain is told apart from another site.
    #[test]
    fn a_site_is_compared_in_one_spelling_and_a_mismatch_says_which_kind() {
        let mut mine = owner(1000, "site-a");
        mine.site_url = Some("https://Site-A.atlassian.net./".into());
        let delivered = delivery_site("https://site-a.ATLASSIAN.net/rest/api/3/issue/1");
        assert_eq!(why_off_site(&mine, delivered.as_ref()), None);
        let trailing = delivery_site("https://site-a.atlassian.net./rest/api/3/issue/1");
        assert_eq!(why_off_site(&mine, trailing.as_ref()), None);

        let other = delivery_site("https://site-b.atlassian.net/rest/api/3/issue/1");
        assert_eq!(
            why_off_site(&mine, other.as_ref()),
            Some(OffSite::HostDiffers)
        );
        let custom = delivery_site("https://jira.example.test/rest/api/3/issue/1");
        assert_eq!(
            why_off_site(&mine, custom.as_ref()),
            Some(OffSite::HostDiffersCustomDomain)
        );
        let gateway = DeliverySite::Cloud("site-b".into());
        assert_eq!(
            why_off_site(&mine, Some(&gateway)),
            Some(OffSite::CloudIdDiffers)
        );
        assert_eq!(
            why_off_site(&mine, None),
            Some(OffSite::DeliveryNamesNoSite)
        );
        mine.site_url = Some("not a url".into());
        let delivered = delivery_site("https://site-a.atlassian.net/rest/api/3/issue/1");
        assert_eq!(
            why_off_site(&mine, delivered.as_ref()),
            Some(OffSite::ConnectionHasNoSite)
        );
    }

    #[test]
    fn a_registration_budget_refuses_past_its_window_count() {
        let budget = RegistrationBudget::new(2, std::time::Duration::from_secs(60));
        let (a, b) = (Uuid::new_v4(), Uuid::new_v4());
        assert!(budget.allow(a));
        assert!(budget.allow(a));
        assert!(!budget.allow(a));
        assert!(
            budget.allow(b),
            "one registration's flood does not spend another's"
        );
    }

    /// A webhook id on two sites is withheld on both; one on a single site is
    /// not affected by its neighbour's ambiguity.
    #[test]
    fn a_webhook_id_registered_on_two_sites_is_withheld_on_both() {
        let (a, b, c) = (
            owner(1000, "site-a"),
            owner(1000, "site-b"),
            owner(2000, "site-a"),
        );
        let (deliverable, ambiguous) = split_ambiguous(vec![a.clone(), b.clone(), c.clone()]);
        assert_eq!(deliverable, std::slice::from_ref(&c));
        assert_eq!(ambiguous, [a, b]);

        let (deliverable, ambiguous) = split_ambiguous(vec![c.clone()]);
        assert_eq!((deliverable, ambiguous), (vec![c], vec![]));
        assert_eq!(split_ambiguous(vec![]), (vec![], vec![]));
    }

    #[test]
    fn a_delivery_identifier_is_used_only_when_it_can_be_a_key() {
        let with = |value: &str| {
            let mut headers = HeaderMap::new();
            headers.insert("X-Atlassian-Webhook-Identifier", value.parse().unwrap());
            headers
        };
        assert_eq!(delivery_id(&with("abc-123")), Some("abc-123"));
        assert_eq!(delivery_id(&with("  abc-123  ")), Some("abc-123"));
        assert_eq!(delivery_id(&with("has space")), None);
        assert_eq!(delivery_id(&with(&"a".repeat(129))), None);
        assert_eq!(delivery_id(&HeaderMap::new()), None);
    }

    #[test]
    fn each_note_answers_atlassian_with_the_status_that_gets_the_right_retry() {
        use ReceiptNote as N;
        // Retried by Atlassian (5xx): the delivery is not lost.
        for note in [
            N::NotConfigured,
            N::LookupFailed,
            N::Deferred,
            N::DedupFailed,
        ] {
            assert_eq!(note.status(), StatusCode::SERVICE_UNAVAILABLE, "{note:?}");
        }
        // Not retried: repeating it would change nothing.
        assert_eq!(N::MissingBearer.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            N::Refused(JwtRefusal::BadSignature).status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(N::BodyTooLarge.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(N::BodyMalformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            N::Accepted {
                matched: 1,
                off_site: 0,
                ambiguous: 0,
                rate_limited: 0,
                capped: 0,
                duplicates: 1
            }
            .status(),
            StatusCode::OK
        );
        assert_eq!(N::TooManyRegistrations.status(), StatusCode::OK);
        assert_eq!(N::Replayed.status(), StatusCode::OK);
        assert_eq!(
            N::ReplayUnavailable.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
        // A delivery about another site is refused, and not retried.
        assert_eq!(
            N::SiteMismatch { matched: 1 }.status(),
            StatusCode::ACCEPTED
        );
    }
}
