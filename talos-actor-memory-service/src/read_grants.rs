//! Memory read grants: a bearer token that reads ONE key of ONE actor's
//! memory, and nothing else.
//!
//! The narrow credential for "hand one approved document to a session".
//! Before this the only thing such a session could be given was MCP access,
//! which reads every key of every actor the user owns and can write and
//! change as well, so "may read only this" was an instruction and not a
//! fact.
//!
//! Security model, the one the approval and action links use:
//!
//! * **The scope is the row.** `actor_id` and the exact `memory_key` are
//!   fixed when the owner mints the grant. A read supplies the token and
//!   nothing else, so nothing a holder sends can widen it.
//! * **256 random bits, hash-only at rest**, looked up by hash and compared
//!   in constant time. The raw token is returned once, by [`mint`].
//! * **Read-only.** There is no write through a grant.
//! * **Bounded**: a lifetime that is always set ([`DEFAULT_TTL_HOURS`],
//!   at most [`MAX_TTL_HOURS`]), an optional number of reads, and revocation.
//! * **One enforcement point.** [`claim_read`] is a single conditional
//!   UPDATE: live, not revoked, reads left, and the actor still the minting
//!   user's. It counts the read in the same statement, so the limit holds
//!   under concurrent reads and every read is recorded on the row.
//! * **One answer.** Unknown, malformed, expired, revoked, used up, and a
//!   key with nothing stored under it are all `None` here and one `404` at
//!   the HTTP layer. A holder learns nothing about what else exists.
//! * **Audited.** Minting and revoking are operator acts and are written to
//!   `admin_event_log` in the transaction that makes the change, with the
//!   scope. Reads are `read_count` / `last_read_at` on the grant.
//!
//! What a grant does NOT do: redact. The document is returned as the owner's
//! own `actor_recall` returns it. A grant is the owner deciding that this
//! document may leave, including for an actor whose model tier keeps its
//! data on the host; that decision is the mint, and it is recorded.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::{Pool, Postgres, Row};
use subtle::ConstantTimeEq;
use uuid::Uuid;

/// Lifetime when the owner names none.
pub const DEFAULT_TTL_HOURS: i64 = 24;
/// Longest lifetime a grant may have.
pub const MAX_TTL_HOURS: i64 = 168;
/// Largest `max_reads`. Matches the table's CHECK.
pub const MAX_READS_LIMIT: i32 = 1000;
/// Longest label, in characters. Matches the table's CHECK.
pub const MAX_LABEL_CHARS: usize = 160;
/// Most live (unexpired, unrevoked) grants one user may hold.
pub const MAX_LIVE_GRANTS_PER_USER: i64 = 50;
/// Most grants one listing returns.
pub const LIST_LIMIT: i64 = 100;
/// How long an expired grant's row is kept, so its owner can still see
/// whether it was used.
const KEEP_EXPIRED_DAYS: i32 = 30;

/// What the owner asks for.
#[derive(Debug, Clone)]
pub struct GrantRequest<'a> {
    pub actor_id: Uuid,
    pub memory_key: &'a str,
    /// What the grant is for, in the owner's words.
    pub label: &'a str,
    pub ttl_hours: Option<i64>,
    pub max_reads: Option<i32>,
}

/// A grant that was made. `raw_token` exists only here.
#[derive(Debug, Clone)]
pub struct MintedGrant {
    pub id: Uuid,
    pub raw_token: String,
    pub memory_key: String,
    pub expires_at: DateTime<Utc>,
    pub max_reads: Option<i32>,
}

/// Why a grant was not made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantRefusal {
    /// The key is not a usable memory key.
    Key(&'static str),
    /// The label is empty once cleaned.
    LabelEmpty,
    /// `max_reads` is outside 1..=[`MAX_READS_LIMIT`].
    MaxReads,
    /// The actor does not exist or is not the user's. One answer for both.
    ActorNotAccessible,
    /// The user already holds [`MAX_LIVE_GRANTS_PER_USER`] live grants.
    TooManyLiveGrants,
}

impl std::fmt::Display for GrantRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Key(why) => write!(f, "{why}"),
            Self::LabelEmpty => write!(f, "label must say what the grant is for"),
            Self::MaxReads => write!(f, "max_reads must be between 1 and {MAX_READS_LIMIT}"),
            Self::ActorNotAccessible => write!(f, "Actor not found or not accessible"),
            Self::TooManyLiveGrants => write!(
                f,
                "You already hold {MAX_LIVE_GRANTS_PER_USER} live read grants. Revoke one \
                 (revoke_memory_read_grant) or let one expire."
            ),
        }
    }
}

/// The scope a valid token carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantScope {
    pub grant_id: Uuid,
    pub user_id: Uuid,
    pub actor_id: Uuid,
    pub memory_key: String,
}

/// The document a grant reads.
#[derive(Debug, Clone)]
pub struct GrantedDocument {
    pub grant_id: Uuid,
    pub key: String,
    pub value: serde_json::Value,
    pub memory_type: String,
    pub updated_at: DateTime<Utc>,
}

/// One grant as its owner sees it. Never the token, never its hash.
#[derive(Debug, Clone)]
pub struct GrantSummary {
    pub id: Uuid,
    pub actor_id: Uuid,
    pub memory_key: String,
    pub label: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub max_reads: Option<i32>,
    pub read_count: i32,
    pub last_read_at: Option<DateTime<Utc>>,
}

impl GrantSummary {
    /// `live`, `revoked`, `expired` or `used_up`, as of `now`.
    #[must_use]
    pub fn state(&self, now: DateTime<Utc>) -> &'static str {
        if self.revoked_at.is_some() {
            "revoked"
        } else if self.expires_at <= now {
            "expired"
        } else if self.max_reads.is_some_and(|max| self.read_count >= max) {
            "used_up"
        } else {
            "live"
        }
    }
}

/// A lifetime as stored: the default when none is asked for, never below one
/// hour, never above [`MAX_TTL_HOURS`].
#[must_use]
pub fn stored_ttl_hours(requested: Option<i64>) -> i64 {
    requested
        .unwrap_or(DEFAULT_TTL_HOURS)
        .clamp(1, MAX_TTL_HOURS)
}

/// A label as stored: control characters and runs of whitespace become one
/// space, the ends are trimmed, cut to [`MAX_LABEL_CHARS`]. `None` when
/// nothing is left.
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

/// Whether `token` has the shape of a grant token: 64 hex characters.
/// Checked before any database work.
#[must_use]
pub fn token_shape_valid(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}

/// The token a request carries: `Authorization: Bearer <token>`, and only
/// that. A token is never read from a URL, where proxies, tunnels and
/// access logs record it.
#[must_use]
pub fn bearer_token(authorization: Option<&str>) -> Option<&str> {
    let value = authorization?.trim();
    let (scheme, token) = value.split_once(' ')?;
    let token = token.trim();
    (scheme.eq_ignore_ascii_case("bearer") && token_shape_valid(token)).then_some(token)
}

fn new_raw_token() -> String {
    hex::encode(talos_random::bytes::<32>())
}

/// Make a grant for `user_id`. The actor must be theirs; that is asked in
/// the INSERT itself, so a grant row exists only for an actor its owner
/// holds.
///
/// # Errors
/// When the database cannot be read or written. A refusal is the inner
/// `Err`.
pub async fn mint(
    pool: &Pool<Postgres>,
    user_id: Uuid,
    request: GrantRequest<'_>,
) -> Result<std::result::Result<MintedGrant, GrantRefusal>> {
    let key = match talos_memory::validate_memory_key(request.memory_key) {
        Ok(key) => key,
        Err(why) => return Ok(Err(GrantRefusal::Key(why))),
    };
    let Some(label) = stored_label(request.label) else {
        return Ok(Err(GrantRefusal::LabelEmpty));
    };
    if request
        .max_reads
        .is_some_and(|max| !(1..=MAX_READS_LIMIT).contains(&max))
    {
        return Ok(Err(GrantRefusal::MaxReads));
    }
    let ttl_hours = i32::try_from(stored_ttl_hours(request.ttl_hours)).unwrap_or(24);

    // The sweep removes EVERY user's long-expired grants, so it is a system
    // statement on the pool, never part of this user's scoped transaction:
    // inside it, a row-security policy on the table would silently narrow it
    // to one user (security review 2026-10-14, D-1 / D-10).
    sqlx::query(
        "DELETE FROM memory_read_grants \
         WHERE expires_at < NOW() - make_interval(days => $1::int)",
    )
    .bind(KEEP_EXPIRED_DAYS)
    .execute(pool)
    .await
    .context("sweep expired read grants")?;

    let mut tx = talos_db::begin_user_scoped(pool, user_id).await?;

    let live: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM memory_read_grants \
         WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .bind(user_id)
    .fetch_one(&mut *tx)
    .await
    .context("count live read grants")?;
    if live >= MAX_LIVE_GRANTS_PER_USER {
        return Ok(Err(GrantRefusal::TooManyLiveGrants));
    }

    let raw_token = new_raw_token();
    let Some(row) = sqlx::query(
        "INSERT INTO memory_read_grants \
             (user_id, actor_id, memory_key, token_hash, label, max_reads, expires_at) \
         SELECT $1, a.id, $3, $4, $5, $6, NOW() + make_interval(hours => $7::int) \
         FROM actors a WHERE a.id = $2 AND a.user_id = $1 \
         RETURNING id, expires_at",
    )
    .bind(user_id)
    .bind(request.actor_id)
    .bind(key)
    .bind(talos_text_util::sha256_hex(&raw_token))
    .bind(&label)
    .bind(request.max_reads)
    .bind(ttl_hours)
    .fetch_optional(&mut *tx)
    .await
    .context("insert read grant")?
    else {
        return Ok(Err(GrantRefusal::ActorNotAccessible));
    };
    let id: Uuid = row.try_get("id")?;
    let expires_at: DateTime<Utc> = row.try_get("expires_at")?;

    // The operator act, with its scope, in the transaction that made it.
    talos_admin_event_log::insert_on_conn(
        &mut tx,
        Some(user_id),
        "memory_read_grant_created",
        "actor",
        Some(request.actor_id),
        &format!(
            "Read grant created for one memory key of actor {}",
            request.actor_id
        ),
        Some(&serde_json::json!({
            "grant_id": id,
            "memory_key": key,
            "label": label,
            "expires_at": expires_at,
            "max_reads": request.max_reads,
        })),
    )
    .await?;
    tx.commit().await?;

    Ok(Ok(MintedGrant {
        id,
        raw_token,
        memory_key: key.to_string(),
        expires_at,
        max_reads: request.max_reads,
    }))
}

/// Use a grant once: the ONE place its scope is enforced.
///
/// `None` for a token that is unknown, malformed, expired, revoked, out of
/// reads, or whose actor is no longer the minting user's. The read is
/// counted by the statement that admits it.
///
/// # Errors
/// When the database cannot be reached.
pub async fn claim_read(pool: &Pool<Postgres>, provided: &str) -> Result<Option<GrantScope>> {
    if !token_shape_valid(provided) {
        return Ok(None);
    }
    let provided_hash = talos_text_util::sha256_hex(provided);
    let Some(row) = sqlx::query(
        "UPDATE memory_read_grants g \
         SET read_count = g.read_count + 1, last_read_at = NOW() \
         FROM actors a \
         WHERE g.token_hash = $1 \
           AND g.revoked_at IS NULL \
           AND g.expires_at > NOW() \
           AND (g.max_reads IS NULL OR g.read_count < g.max_reads) \
           AND a.id = g.actor_id AND a.user_id = g.user_id \
         RETURNING g.id, g.token_hash, g.user_id, g.actor_id, g.memory_key",
    )
    .bind(&provided_hash)
    .fetch_optional(pool)
    .await
    .context("claim read grant")?
    else {
        return Ok(None);
    };
    let stored: String = row.try_get("token_hash")?;
    if !bool::from(stored.as_bytes().ct_eq(provided_hash.as_bytes())) {
        return Ok(None);
    }
    Ok(Some(GrantScope {
        grant_id: row.try_get("id")?,
        user_id: row.try_get("user_id")?,
        actor_id: row.try_get("actor_id")?,
        memory_key: row.try_get("memory_key")?,
    }))
}

/// Read the one document a token grants. `None` for every reason there is
/// nothing to return (see [`claim_read`]), including a key with nothing
/// stored under it.
///
/// The memory is read through `talos_memory`, like every other read of it.
///
/// # Errors
/// When the database or the decryption cannot be reached.
pub async fn read_granted_document(
    pool: &Pool<Postgres>,
    provided: &str,
) -> Result<Option<GrantedDocument>> {
    let Some(scope) = claim_read(pool, provided).await? else {
        return Ok(None);
    };
    let found = talos_memory::recall_exact(pool, scope.actor_id, &scope.memory_key).await?;
    tracing::info!(
        target: "talos_audit",
        event_kind = "memory_read_grant_used",
        grant_id = %scope.grant_id,
        actor_id = %scope.actor_id,
        found = found.is_some(),
        "memory read grant used"
    );
    Ok(found.map(|row| GrantedDocument {
        grant_id: scope.grant_id,
        key: row.key,
        value: row.value,
        memory_type: row.memory_type,
        updated_at: row.updated_at,
    }))
}

/// The user's grants, newest first, at most [`LIST_LIMIT`].
///
/// # Errors
/// When the database cannot be read.
pub async fn list(pool: &Pool<Postgres>, user_id: Uuid) -> Result<Vec<GrantSummary>> {
    let rows = sqlx::query(
        "SELECT id, actor_id, memory_key, label, created_at, expires_at, revoked_at, \
                max_reads, read_count, last_read_at \
         FROM memory_read_grants WHERE user_id = $1 \
         ORDER BY created_at DESC, id DESC LIMIT $2",
    )
    .bind(user_id)
    .bind(LIST_LIMIT)
    .fetch_all(pool)
    .await
    .context("list read grants")?;
    rows.into_iter()
        .map(|r| -> Result<GrantSummary> {
            Ok(GrantSummary {
                id: r.try_get("id")?,
                actor_id: r.try_get("actor_id")?,
                memory_key: r.try_get("memory_key")?,
                label: r.try_get("label")?,
                created_at: r.try_get("created_at")?,
                expires_at: r.try_get("expires_at")?,
                revoked_at: r.try_get("revoked_at")?,
                max_reads: r.try_get("max_reads")?,
                read_count: r.try_get("read_count")?,
                last_read_at: r.try_get("last_read_at")?,
            })
        })
        .collect()
}

/// End one of the user's grants now. `false` when there is no such live
/// grant of theirs (unknown, another user's, or already revoked: one answer).
///
/// # Errors
/// When the database cannot be written.
pub async fn revoke(pool: &Pool<Postgres>, user_id: Uuid, grant_id: Uuid) -> Result<bool> {
    let mut tx = talos_db::begin_user_scoped(pool, user_id).await?;
    let Some(actor_id) = sqlx::query_scalar::<_, Uuid>(
        "UPDATE memory_read_grants SET revoked_at = NOW() \
         WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL \
         RETURNING actor_id",
    )
    .bind(grant_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .context("revoke read grant")?
    else {
        return Ok(false);
    };
    talos_admin_event_log::insert_on_conn(
        &mut tx,
        Some(user_id),
        "memory_read_grant_revoked",
        "actor",
        Some(actor_id),
        &format!("Read grant {grant_id} revoked"),
        Some(&serde_json::json!({ "grant_id": grant_id })),
    )
    .await?;
    tx.commit().await?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_token_is_read_from_the_authorization_header_and_nowhere_else() {
        let token = "a".repeat(64);
        assert_eq!(
            bearer_token(Some(&format!("Bearer {token}"))),
            Some(token.as_str())
        );
        assert_eq!(
            bearer_token(Some(&format!("bearer  {token} "))),
            Some(token.as_str())
        );
        for not_a_token in [
            None,
            Some(String::new()),
            Some(token.clone()),
            Some(format!("Basic {token}")),
            Some(format!("Bearer {}", "a".repeat(63))),
            Some(format!("Bearer {}", "a".repeat(65))),
            Some(format!("Bearer {}", "g".repeat(64))),
            Some(format!("Bearer {token} extra")),
            Some("Bearer".to_string()),
        ] {
            assert_eq!(
                bearer_token(not_a_token.as_deref()),
                None,
                "{not_a_token:?}"
            );
        }
    }

    #[test]
    fn a_minted_token_has_the_shape_that_is_accepted_and_no_two_are_alike() {
        let (a, b) = (new_raw_token(), new_raw_token());
        assert!(token_shape_valid(&a) && token_shape_valid(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn a_lifetime_is_always_set_and_never_past_a_week() {
        assert_eq!(stored_ttl_hours(None), 24);
        assert_eq!(stored_ttl_hours(Some(1)), 1);
        assert_eq!(stored_ttl_hours(Some(0)), 1);
        assert_eq!(stored_ttl_hours(Some(-5)), 1);
        assert_eq!(stored_ttl_hours(Some(168)), 168);
        assert_eq!(stored_ttl_hours(Some(10_000)), 168);
    }

    #[test]
    fn a_label_is_cleaned_and_bounded() {
        assert_eq!(
            stored_label("  brief\tfor\nthe  build "),
            Some("brief for the build".to_string())
        );
        assert_eq!(stored_label(" \n\t "), None);
        assert_eq!(
            stored_label(&"x".repeat(400)).unwrap().chars().count(),
            MAX_LABEL_CHARS
        );
    }

    #[test]
    fn a_grants_state_is_read_off_its_row() {
        let now = Utc::now();
        let base = GrantSummary {
            id: Uuid::nil(),
            actor_id: Uuid::nil(),
            memory_key: "k".into(),
            label: "l".into(),
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            revoked_at: None,
            max_reads: Some(2),
            read_count: 1,
            last_read_at: None,
        };
        assert_eq!(base.state(now), "live");
        assert_eq!(
            GrantSummary {
                read_count: 2,
                ..base.clone()
            }
            .state(now),
            "used_up"
        );
        assert_eq!(
            GrantSummary {
                expires_at: now,
                ..base.clone()
            }
            .state(now),
            "expired"
        );
        // Revoked wins: it is what the owner did.
        assert_eq!(
            GrantSummary {
                revoked_at: Some(now),
                expires_at: now,
                ..base
            }
            .state(now),
            "revoked"
        );
    }
}
