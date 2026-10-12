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
//! 2. The token verifies under the app's client secret ([`crate::push_jwt`]).
//! 3. The body (at most 1 MiB) is read and parsed for three things only:
//!    `matchedWebhookIds`, `webhookEvent`, `issue.key`. Everything else in it
//!    — the ticket — is skipped by the parser and never held, logged or
//!    stored.
//! 4. The matched webhook ids are mapped to the registrations that own them.
//!    A lookup that did not answer is a 503 (Atlassian retries); no row is a
//!    200 (nothing to retry toward). A webhook id registered on more than one
//!    site is ambiguous — the delivery does not say which site it came from —
//!    and starts nothing.
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
        /// Of those, how many were withheld as ambiguous.
        ambiguous: usize,
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
            Self::NotConfigured | Self::LookupFailed | Self::Deferred | Self::DedupFailed => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            Self::TooManyRegistrations | Self::Accepted { .. } => StatusCode::OK,
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
    struct Short;
    impl<'de> Visitor<'de> for Short {
        type Value = Option<String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("any JSON value")
        }
        fn visit_str<E>(self, v: &str) -> Result<Option<String>, E> {
            Ok((v.len() <= 128).then(|| v.to_string()))
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
    deserializer.deserialize_any(Short)
}

/// The issue, of which only the key is read.
#[derive(Debug, Default)]
struct IssueRef {
    key: Option<String>,
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
                let mut out = IssueRef::default();
                while let Some(name) = map.next_key::<std::borrow::Cow<'de, str>>()? {
                    if name == "key" {
                        out.key = map.next_value::<Key>()?.0;
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

/// The three things read from a delivery. No other field of the body is
/// named here, so no other field can be held.
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

        // 3. The body, bounded, and only three things out of it.
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
        if delivery.matched_webhook_ids.ids.is_empty() {
            return PushReceipt::just(ReceiptNote::Accepted {
                matched: 0,
                ambiguous: 0,
                duplicates: 0,
            });
        }

        // 4. Whose webhooks these are: asked of the registrations, by the id
        //    Atlassian issued. Nothing else in the request is consulted.
        let owners: Vec<Owner> = match sqlx::query_as(
            "SELECT id, user_id, cloud_id, webhook_id, workflow_id \
             FROM atlassian_webhook_registrations WHERE webhook_id = ANY($1) \
             ORDER BY webhook_id, cloud_id LIMIT $2",
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
        let (deliverable, ambiguous) = split_ambiguous(owners);

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

        for owner in &ambiguous {
            self.record_ambiguous(owner).await;
        }

        // 6. Each registration handles a delivery once.
        let candidate_ids: Vec<Uuid> = deliverable.iter().map(|o| o.id).collect();
        let fresh_ids: Vec<Uuid> = match delivery_id(headers) {
            Some(delivery_id) if !candidate_ids.is_empty() => match sqlx::query_scalar(
                "INSERT INTO atlassian_webhook_deliveries (registration_id, delivery_id) \
                 SELECT unnest($1::uuid[]), $2 ON CONFLICT DO NOTHING RETURNING registration_id",
            )
            .bind(&candidate_ids)
            .bind(delivery_id)
            .fetch_all(&self.db_pool)
            .await
            {
                Ok(fresh) => fresh,
                Err(e) => {
                    tracing::error!(error = %e, "Jira webhook delivery could not be recorded as handled; answering 503");
                    return PushReceipt::just(ReceiptNote::DedupFailed);
                }
            },
            // No identifier to recognise a retry by: handled as new. The
            // workflow a delivery starts is one that is safe to run twice.
            _ => candidate_ids.clone(),
        };
        let duplicates = candidate_ids.len() - fresh_ids.len();

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
                ambiguous: ambiguous.len(),
                duplicates,
            },
            starts,
        }
    }

    /// A delivery withheld because its webhook id is registered on more than
    /// one site: said in the audit stream, and — when the registration would
    /// have started a workflow — as a row its owner can find.
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
        let Some(workflow_id) = owner.workflow_id else {
            return;
        };
        record_not_started(
            &self.db_pool,
            owner.user_id,
            owner.id,
            &owner.cloud_id,
            owner.webhook_id,
            workflow_id,
            REFUSAL_AMBIGUOUS_WEBHOOK_ID,
        )
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

    fn valid_token() -> String {
        token(
            Algorithm::HS256,
            SECRET,
            &serde_json::json!({"exp": now() + 120}),
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
        let headers = bearer(&valid_token());

        let big = Body::from(vec![b' '; JIRA_WEBHOOK_MAX_BODY_BYTES + 1]);
        assert_eq!(
            svc.receive_push(&headers, big).await.note,
            ReceiptNote::BodyTooLarge
        );
        let mut declared = headers.clone();
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
            let receipt = svc.receive_push(&headers, Body::from(junk)).await;
            assert_eq!(receipt.note, ReceiptNote::BodyMalformed, "{junk}");
            assert_eq!(receipt.status(), StatusCode::BAD_REQUEST);
        }

        // A delivery that matched nothing asks the database nothing.
        for body in [
            r#"{}"#,
            r#"{"matchedWebhookIds":[]}"#,
            r#"{"matchedWebhookIds":null}"#,
        ] {
            let receipt = svc.receive_push(&headers, Body::from(body)).await;
            assert_eq!(
                receipt.note,
                ReceiptNote::Accepted {
                    matched: 0,
                    ambiguous: 0,
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
        }
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
                ambiguous: 0,
                duplicates: 1
            }
            .status(),
            StatusCode::OK
        );
        assert_eq!(N::TooManyRegistrations.status(), StatusCode::OK);
    }
}
