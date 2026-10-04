//! Action links — capability URLs that start ONE named workflow with ONE
//! fixed payload when their owner confirms them.
//!
//! A message the platform composes (the morning email, a bill reminder)
//! can carry "done", "keep", "hold this time" as links. The approval link
//! ([`crate::approval_links`]) can only resume a suspended execution; this
//! is the general form: `/action-links/{token}`.
//!
//! Security model — the approval-link model, with two additions:
//!
//! * **256-bit `OsRng` tokens, hash-only at rest**, looked up by hash and
//!   re-compared in constant time. A read of the table yields nothing
//!   clickable.
//! * **GET is side-effect free.** The HTTP layer renders a confirmation
//!   page that names the workflow and the action; only the POST starts
//!   anything, so a mail scanner or link prefetcher cannot.
//! * **Tenancy rides the token row.** `user_id` is captured at mint from
//!   the run that minted it; the request supplies nothing but the token.
//! * **The target is the graph author's choice.** A token is minted only
//!   for a workflow the minting node's configuration names AND the minting
//!   user owns (the ownership JOIN in [`ExecutionRepository::mint_action_tokens`]).
//!   A module's output picks among those targets; it cannot name another.
//! * **Single use, claimed before the start** (addition one). The apply
//!   path claims `used_at` in one conditional UPDATE and only then starts
//!   the workflow, so a link starts its workflow at most once however many
//!   times it is submitted. A start that fails before an execution exists
//!   releases the claim so the owner can try again.
//! * **Bounded** (addition two): a payload is a JSON object of at most
//!   [`MAX_PAYLOAD_BYTES`], a label at most [`MAX_LABEL_CHARS`], a mint at
//!   most [`MAX_LINKS_PER_MINT`] links, a lifetime at most
//!   [`MAX_TTL_HOURS`].
//!
//! Known exposure (the same one approval links document): minted URLs
//! travel in the minting node's output to the node that sends them, so raw
//! tokens also sit in the persisted execution output, readable by the
//! owning user — who could start the same workflow directly. "Hash-only" is
//! a claim about this table.

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::Row;
use subtle::ConstantTimeEq;
use uuid::Uuid;

use crate::approval_links::{new_raw_token, token_shape_valid};
use crate::ExecutionRepository;

/// Default link lifetime: the read window of a daily message, with slack.
pub const DEFAULT_TTL_HOURS: i64 = 72;
/// Longest lifetime a node may ask for (a weekly message read a week late).
pub const MAX_TTL_HOURS: i64 = 336;
/// Most links one mint call stores.
pub const MAX_LINKS_PER_MINT: usize = 64;
/// Largest payload, as compact JSON text. Matches the table's CHECK.
pub const MAX_PAYLOAD_BYTES: usize = 8192;
/// Longest label, in characters. Matches the table's CHECK.
pub const MAX_LABEL_CHARS: usize = 160;

/// One link to mint.
#[derive(Debug, Clone)]
pub struct ActionLinkRequest {
    /// The workflow the link starts. Must be owned by the minting user.
    pub workflow_id: Uuid,
    /// What the confirmation page says the link does ("Done: call the dentist").
    pub label: String,
    /// The trigger input the workflow receives. A JSON object.
    pub payload: serde_json::Value,
}

/// Why a requested link was not minted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MintRefusal {
    /// The payload is not a JSON object.
    PayloadNotAnObject,
    /// The payload is larger than [`MAX_PAYLOAD_BYTES`].
    PayloadTooLarge,
    /// The label is empty once trimmed.
    LabelEmpty,
    /// The workflow does not exist or is not the minting user's.
    WorkflowNotOwned,
    /// More than [`MAX_LINKS_PER_MINT`] links were requested; this one is
    /// past the cap.
    TooManyLinks,
}

impl MintRefusal {
    /// The report spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PayloadNotAnObject => "payload_not_an_object",
            Self::PayloadTooLarge => "payload_too_large",
            Self::LabelEmpty => "label_empty",
            Self::WorkflowNotOwned => "workflow_not_owned",
            Self::TooManyLinks => "too_many_links",
        }
    }
}

/// Everything the HTTP layer needs to render the confirmation page and to
/// start the workflow.
#[derive(Debug, Clone)]
pub struct ActionTokenContext {
    pub id: Uuid,
    pub user_id: Uuid,
    pub workflow_id: Uuid,
    pub workflow_name: String,
    pub label: String,
    pub payload: serde_json::Value,
    /// The link has already been used.
    pub used: bool,
    pub expires_at: DateTime<Utc>,
}

/// What claiming a token found.
#[derive(Debug, Clone)]
pub enum ActionClaim {
    /// This call claimed the link; the caller must now start the workflow
    /// (and release the claim if no execution comes of it).
    Claimed(ActionTokenContext),
    /// The link exists and was used before.
    AlreadyUsed,
    /// Unknown, malformed or expired — one answer for all three.
    Invalid,
}

/// A label as stored: control characters and runs of whitespace become one
/// space, the ends are trimmed, and the result is cut to
/// [`MAX_LABEL_CHARS`] on a character boundary. `None` when nothing is left.
#[must_use]
pub fn stored_label(raw: &str) -> Option<String> {
    let spaced: String = raw
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    let cleaned: String = spaced
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_LABEL_CHARS)
        .collect();
    (!cleaned.is_empty()).then_some(cleaned)
}

/// A lifetime as stored: the default when none is asked for, never below
/// one hour, never above [`MAX_TTL_HOURS`].
#[must_use]
pub fn stored_ttl_hours(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_TTL_HOURS)
        .clamp(1, MAX_TTL_HOURS)
}

/// Check one request's own shape (everything but ownership, which only the
/// database can answer). Returns the label and the payload text to store.
fn validated(request: &ActionLinkRequest) -> std::result::Result<(String, String), MintRefusal> {
    if !request.payload.is_object() {
        return Err(MintRefusal::PayloadNotAnObject);
    }
    let payload = request.payload.to_string();
    if payload.len() > MAX_PAYLOAD_BYTES {
        return Err(MintRefusal::PayloadTooLarge);
    }
    let label = stored_label(&request.label).ok_or(MintRefusal::LabelEmpty)?;
    Ok((label, payload))
}

impl ExecutionRepository {
    /// Mint one token per request, order-aligned with `requests`:
    /// `Ok(raw token)` for a link that was stored, `Err(why)` for one that
    /// was not.
    ///
    /// One statement: the expired-token sweep (an indexed range scan) is a
    /// CTE of the batched insert, and the ownership JOIN drops any request
    /// naming a workflow that is not `user_id`'s — RETURNING reports which
    /// rows landed, so a link is rendered only for a token that exists.
    pub async fn mint_action_tokens(
        &self,
        user_id: Uuid,
        source_execution_id: Option<Uuid>,
        source_node: Option<&str>,
        ttl_hours: Option<i64>,
        requests: &[ActionLinkRequest],
    ) -> Result<Vec<std::result::Result<String, MintRefusal>>> {
        let mut out: Vec<std::result::Result<String, MintRefusal>> =
            Vec::with_capacity(requests.len());
        let mut workflow_ids: Vec<Uuid> = Vec::new();
        let mut hashes: Vec<String> = Vec::new();
        let mut labels: Vec<String> = Vec::new();
        let mut payloads: Vec<String> = Vec::new();
        for request in requests {
            if hashes.len() >= MAX_LINKS_PER_MINT {
                out.push(Err(MintRefusal::TooManyLinks));
                continue;
            }
            match validated(request) {
                Ok((label, payload)) => {
                    let raw = new_raw_token();
                    workflow_ids.push(request.workflow_id);
                    hashes.push(talos_text_util::sha256_hex(&raw));
                    labels.push(label);
                    payloads.push(payload);
                    out.push(Ok(raw));
                }
                Err(refusal) => out.push(Err(refusal)),
            }
        }
        if hashes.is_empty() {
            return Ok(out);
        }

        let stored: std::collections::HashSet<String> = sqlx::query_scalar(
            "WITH gc AS ( \
                 DELETE FROM workflow_action_tokens WHERE expires_at < NOW() \
             ) \
             INSERT INTO workflow_action_tokens \
                 (user_id, workflow_id, token_hash, label, payload, \
                  source_execution_id, source_node, expires_at) \
             SELECT $1, w.id, x.token_hash, x.label, x.payload::jsonb, $6, $7, \
                    NOW() + make_interval(hours => $8::int) \
             FROM UNNEST($2::uuid[], $3::text[], $4::text[], $5::text[]) \
                  AS x(workflow_id, token_hash, label, payload) \
             JOIN workflows w ON w.id = x.workflow_id AND w.user_id = $1 \
             RETURNING token_hash",
        )
        .bind(user_id)
        .bind(&workflow_ids)
        .bind(&hashes)
        .bind(&labels)
        .bind(&payloads)
        .bind(source_execution_id)
        .bind(source_node)
        .bind(i32::try_from(stored_ttl_hours(ttl_hours)).unwrap_or(i32::MAX))
        .fetch_all(&self.db_pool)
        .await?
        .into_iter()
        .collect();

        // A validated request whose row did not land named a workflow the
        // user does not own (or one deleted since the node resolved it).
        let mut hash_iter = hashes.iter();
        for slot in &mut out {
            if slot.is_ok() {
                let hash = hash_iter.next().expect("one hash per validated request");
                if !stored.contains(hash) {
                    *slot = Err(MintRefusal::WorkflowNotOwned);
                }
            }
        }
        Ok(out)
    }

    /// Resolve a token for the confirmation page. `None` for unknown,
    /// malformed or expired — the HTTP layer shows one page for all three.
    /// A USED token still resolves (with `used: true`) so the page can say
    /// the action already happened rather than that the link never existed.
    pub async fn lookup_action_token(&self, provided: &str) -> Result<Option<ActionTokenContext>> {
        if !token_shape_valid(provided) {
            return Ok(None);
        }
        let provided_hash = talos_text_util::sha256_hex(provided);
        let Some(row) = sqlx::query(
            "SELECT t.id, t.token_hash, t.user_id, t.workflow_id, w.name, t.label, t.payload, \
                    t.used_at IS NOT NULL AS used, t.expires_at \
             FROM workflow_action_tokens t \
             JOIN workflows w ON w.id = t.workflow_id AND w.user_id = t.user_id \
             WHERE t.token_hash = $1 AND t.expires_at > NOW()",
        )
        .bind(&provided_hash)
        .fetch_optional(&self.db_pool)
        .await?
        else {
            return Ok(None);
        };
        let stored: String = row.try_get("token_hash")?;
        if !bool::from(stored.as_bytes().ct_eq(provided_hash.as_bytes())) {
            return Ok(None);
        }
        Ok(Some(ActionTokenContext {
            id: row.try_get("id")?,
            user_id: row.try_get("user_id")?,
            workflow_id: row.try_get("workflow_id")?,
            workflow_name: row.try_get("name")?,
            label: row.try_get("label")?,
            payload: row.try_get("payload")?,
            used: row.try_get("used")?,
            expires_at: row.try_get("expires_at")?,
        }))
    }

    /// Claim a token for use. The conditional UPDATE is the single-use
    /// guarantee: of any number of concurrent submissions exactly one gets
    /// [`ActionClaim::Claimed`].
    pub async fn claim_action_token(&self, provided: &str) -> Result<ActionClaim> {
        let Some(context) = self.lookup_action_token(provided).await? else {
            return Ok(ActionClaim::Invalid);
        };
        if context.used {
            return Ok(ActionClaim::AlreadyUsed);
        }
        let claimed = sqlx::query(
            "UPDATE workflow_action_tokens SET used_at = NOW() \
             WHERE id = $1 AND used_at IS NULL AND expires_at > NOW()",
        )
        .bind(context.id)
        .execute(&self.db_pool)
        .await?
        .rows_affected();
        Ok(if claimed == 1 {
            ActionClaim::Claimed(context)
        } else {
            // Lost the race to another submission, or expired in between.
            ActionClaim::AlreadyUsed
        })
    }

    /// Give a claim back: the workflow did not start, so the link has not
    /// done its one thing. Refuses to release a token that already names an
    /// execution.
    pub async fn release_action_token(&self, id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_action_tokens SET used_at = NULL \
             WHERE id = $1 AND triggered_execution_id IS NULL",
        )
        .bind(id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }

    /// Record the execution a claimed link started.
    pub async fn record_action_execution(&self, id: Uuid, execution_id: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE workflow_action_tokens SET triggered_execution_id = $2 \
             WHERE id = $1 AND used_at IS NOT NULL",
        )
        .bind(id)
        .bind(execution_id)
        .execute(&self.db_pool)
        .await?;
        Ok(())
    }
}

/// The URL for one raw token. Pure so it is unit-testable.
#[must_use]
pub fn action_url(base_url: &str, raw_token: &str) -> String {
    format!(
        "{}/action-links/{raw_token}",
        base_url.trim_end_matches('/')
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_label_is_trimmed_cleaned_and_cut_on_a_character_boundary() {
        assert_eq!(
            stored_label("  Done: call\tthe dentist \n").as_deref(),
            Some("Done: call the dentist")
        );
        assert_eq!(stored_label(" \n\t "), None);
        let long = "é".repeat(MAX_LABEL_CHARS + 40);
        assert_eq!(
            stored_label(&long).unwrap().chars().count(),
            MAX_LABEL_CHARS
        );
    }

    #[test]
    fn a_lifetime_is_held_between_an_hour_and_the_ceiling() {
        assert_eq!(stored_ttl_hours(None), DEFAULT_TTL_HOURS);
        assert_eq!(stored_ttl_hours(Some(0)), 1);
        assert_eq!(stored_ttl_hours(Some(-5)), 1);
        assert_eq!(stored_ttl_hours(Some(24)), 24);
        assert_eq!(stored_ttl_hours(Some(100_000)), MAX_TTL_HOURS);
    }

    #[test]
    fn a_request_is_refused_for_its_own_shape_before_the_database_is_asked() {
        let request = |label: &str, payload: serde_json::Value| ActionLinkRequest {
            workflow_id: Uuid::nil(),
            label: label.to_string(),
            payload,
        };
        assert!(validated(&request(
            "Done",
            serde_json::json!({"op": "done", "item": 12})
        ))
        .is_ok());
        assert_eq!(
            validated(&request("Done", serde_json::json!(["done", 12]))),
            Err(MintRefusal::PayloadNotAnObject)
        );
        assert_eq!(
            validated(&request("Done", serde_json::json!("done 12"))),
            Err(MintRefusal::PayloadNotAnObject)
        );
        assert_eq!(
            validated(&request("   ", serde_json::json!({}))),
            Err(MintRefusal::LabelEmpty)
        );
        let big = serde_json::json!({ "note": "x".repeat(MAX_PAYLOAD_BYTES) });
        assert_eq!(
            validated(&request("Done", big)),
            Err(MintRefusal::PayloadTooLarge)
        );
    }

    #[test]
    fn the_url_is_the_base_and_the_token() {
        let token = "a".repeat(64);
        assert_eq!(
            action_url("https://x.example/", &token),
            format!("https://x.example/action-links/{token}")
        );
        assert_eq!(
            action_url("https://x.example", &token),
            format!("https://x.example/action-links/{token}")
        );
    }
}
