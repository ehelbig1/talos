//! Controller-internal service for `integration_state` reads/writes.
//!
//! This is the single source of truth for the data-plane operations
//! behind the `integration_state` primitive. It is called from three
//! surfaces:
//!
//! 1. `rpc_subscribers::spawn_integration_state_subscriber` — handles
//!    requests from workers arriving over NATS.
//! 2. The platform-internal integrations (e.g. `google_calendar`) that
//!    manage their own state rows without a NATS round-trip. A same-
//!    process NATS hop would be wasteful and add a failure mode.
//! 3. Tests — can exercise the function directly against a live pool.
//!
//! Extracting a single function lets both paths share the validator,
//! the DB error-redaction, and the canonical SQL, so a fix in one
//! applies to the other. If we later grow a third RPC surface (HTTP,
//! SDK, etc.) it imports from here too.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use talos_memory::integration_state_rpc::{
    IndexedSlots, IntegrationOp, IntegrationOpResult, IntegrationStateError, ListFilter,
    StoredEntry, MAX_RESULT_LIMIT,
};
use uuid::Uuid;

// Utilities live in this module because the data-plane logic that
// uses them is here. The RPC subscriber calls into this module, so
// it picks them up through the same path.

/// Convert epoch ms to a chrono UTC DateTime, returning None if the
/// value is outside chrono's safe range (roughly years 0001..=9999).
pub fn ms_to_datetime(ms: i64) -> Option<chrono::DateTime<chrono::Utc>> {
    use chrono::TimeZone;
    chrono::Utc.timestamp_millis_opt(ms).single()
}

/// Escape SQL LIKE metacharacters (`%`, `_`, `\`) so a caller-supplied
/// prefix is matched literally. Compose the final pattern as
/// `format!("{}%", escape_like_pattern(prefix))`.
pub fn escape_like_pattern(s: &str) -> String {
    s.chars()
        .flat_map(|c| match c {
            '\\' | '%' | '_' => vec!['\\', c].into_iter(),
            other => vec![other].into_iter(),
        })
        .collect()
}

/// Per-(integration, user) row cap. Enforced in Rust rather than via
/// SQL CHECK to avoid a subquery on every insert. Matches the value
/// documented in `integration_state_rpc.rs`.
pub const MAX_ROWS_PER_INTEGRATION_USER: i64 = 10_000;

/// Derive a 64-bit Postgres advisory-lock key from
/// `(integration_name, user_id)`. Used by the SET path to serialise
/// the count-check + INSERT against the cap (MCP-717). Collisions
/// across distinct tuples are harmless — they cause incidental
/// serialisation across unrelated SETs but never violate correctness.
/// SHA-256 gives uniform distribution; the cryptographic strength is
/// incidental, not required.
pub fn integration_state_lock_key(integration_name: &str, user_id: Uuid) -> i64 {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(integration_name.as_bytes());
    hasher.update(user_id.as_bytes());
    let bytes = hasher.finalize();
    i64::from_be_bytes(
        bytes[..8]
            .try_into()
            .expect("SHA-256 always yields 32 bytes"),
    )
}

/// Thin convenience wrapper. Holds only the pool; methods are also
/// exposed as free functions so callers that already thread `&PgPool`
/// around don't need to construct the service.
#[derive(Clone)]
pub struct IntegrationStateService {
    pool: PgPool,
}

impl IntegrationStateService {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Look up a single row. Returns `KeyNotFound` if the row is absent
    /// OR expired — the caller should never observe an expired row.
    pub async fn get(
        &self,
        integration_name: &str,
        user_id: Uuid,
        key: &str,
    ) -> Result<StoredEntry, IntegrationStateError> {
        match execute_op(
            &self.pool,
            integration_name,
            user_id,
            IntegrationOp::Get {
                key: key.to_string(),
            },
        )
        .await?
        {
            IntegrationOpResult::Entry { entry } => Ok(entry),
            _ => Err(IntegrationStateError::Internal(
                "unexpected op result".into(),
            )),
        }
    }

    /// Upsert a row. `ttl_seconds` is applied against `now()` at insert.
    /// Any present slot values MUST already have passed the length /
    /// range validators in `integration_state_rpc::validate_op`; the
    /// controller-internal caller is responsible for the same checks
    /// the RPC boundary enforces (no deeper validation happens here).
    pub async fn set(
        &self,
        integration_name: &str,
        user_id: Uuid,
        entry: SetEntry,
    ) -> Result<(), IntegrationStateError> {
        match execute_op(
            &self.pool,
            integration_name,
            user_id,
            IntegrationOp::Set {
                key: entry.key,
                value: entry.value,
                ttl_seconds: entry.ttl_seconds,
                slots: entry.slots,
            },
        )
        .await?
        {
            IntegrationOpResult::Ok => Ok(()),
            _ => Err(IntegrationStateError::Internal(
                "unexpected op result".into(),
            )),
        }
    }

    pub async fn delete(
        &self,
        integration_name: &str,
        user_id: Uuid,
        key: &str,
    ) -> Result<(), IntegrationStateError> {
        match execute_op(
            &self.pool,
            integration_name,
            user_id,
            IntegrationOp::Delete {
                key: key.to_string(),
            },
        )
        .await?
        {
            IntegrationOpResult::Ok => Ok(()),
            _ => Err(IntegrationStateError::Internal(
                "unexpected op result".into(),
            )),
        }
    }

    /// List rows matching `filter`. `limit` is clamped server-side to
    /// `MAX_RESULT_LIMIT`. Rows are ordered by `updated_at DESC`.
    pub async fn list(
        &self,
        integration_name: &str,
        user_id: Uuid,
        filter: ListFilter,
        limit: u32,
    ) -> Result<Vec<StoredEntry>, IntegrationStateError> {
        match execute_op(
            &self.pool,
            integration_name,
            user_id,
            IntegrationOp::List { filter, limit },
        )
        .await?
        {
            IntegrationOpResult::Entries { entries } => Ok(entries),
            _ => Err(IntegrationStateError::Internal(
                "unexpected op result".into(),
            )),
        }
    }
}

/// Structured input for `set`. Mirrors the wire-level `IntegrationOp::Set`
/// but with slots exposed as a typed field so callers don't confuse
/// `idx_str_1` / `idx_str_2` / etc.
pub struct SetEntry {
    pub key: String,
    pub value: serde_json::Value,
    pub ttl_seconds: Option<u64>,
    pub slots: IndexedSlots,
}

/// Pure execution path — does the same thing the NATS subscriber does,
/// against the same pool, with the same SQL. Subscribers call this.
/// Platform-internal callers call this. Tests call this.
pub async fn execute_op(
    pool: &PgPool,
    integration_name: &str,
    user_id: Uuid,
    op: IntegrationOp,
) -> Result<IntegrationOpResult, IntegrationStateError> {
    match op {
        IntegrationOp::Get { key } => {
            let row_opt = sqlx::query(
                "SELECT key, value, \
                        (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint AS updated_at_ms, \
                        CASE WHEN expires_at IS NULL THEN NULL \
                             ELSE (EXTRACT(EPOCH FROM expires_at) * 1000)::bigint \
                        END AS expires_at_ms, \
                        idx_str_1, idx_str_2, \
                        CASE WHEN idx_ts_1 IS NULL THEN NULL \
                             ELSE (EXTRACT(EPOCH FROM idx_ts_1) * 1000)::bigint \
                        END AS idx_ts_1_ms, \
                        idx_int_1 \
                 FROM integration_state \
                 WHERE integration_name = $1 AND user_id = $2 AND key = $3 \
                   AND (expires_at IS NULL OR expires_at > now()) \
                 LIMIT 1",
            )
            .bind(integration_name)
            .bind(user_id)
            .bind(&key)
            .fetch_optional(pool)
            .await
            .map_err(db_err)?;
            let row = row_opt.ok_or(IntegrationStateError::KeyNotFound)?;
            let entry = row_to_entry(&row)?;
            Ok(IntegrationOpResult::Entry { entry })
        }
        IntegrationOp::Set {
            key,
            value,
            ttl_seconds,
            slots,
        } => {
            let value_str = value.to_string();
            if value_str.len() > 64 * 1024 {
                return Err(IntegrationStateError::InvalidInput(
                    "value exceeds 64 KiB cap".into(),
                ));
            }
            // MCP-717 (2026-05-13): TOCTOU-safe cap enforcement. Pre-fix
            // the existence + count + INSERT triple ran as three
            // independent statements against the pool — multiple
            // parallel new-key SETs (e.g. a fleet of webhooks for
            // distinct integration scopes firing simultaneously) could
            // each observe existing=None and row_count < MAX, then all
            // INSERT successfully, pushing the user past
            // MAX_ROWS_PER_INTEGRATION_USER by up to RPC-concurrency-cap
            // rows. Same per-user cap TOCTOU class as MCP-401/434/685
            // (clone_actor_memories / per-user actor cap). Fix shape:
            // begin transaction → pg_advisory_xact_lock keyed on
            // (integration_name, user_id) hash → run the existence +
            // count + INSERT atomically under the lock → commit.
            //
            // Cap check only fires on insert (not update) so updates to
            // existing rows always succeed even after the user has hit
            // the ceiling. Existence is a scalar SELECT — indexed by the
            // (integration_name, user_id, key) unique constraint.
            let lock_key = integration_state_lock_key(integration_name, user_id);
            let mut tx = pool.begin().await.map_err(db_err)?;
            sqlx::query("SELECT pg_advisory_xact_lock($1)")
                .bind(lock_key)
                .execute(&mut *tx)
                .await
                .map_err(db_err)?;
            let existing: Option<bool> = sqlx::query_scalar(
                "SELECT true FROM integration_state \
                 WHERE integration_name = $1 AND user_id = $2 AND key = $3 LIMIT 1",
            )
            .bind(integration_name)
            .bind(user_id)
            .bind(&key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(db_err)?;
            if existing.is_none() {
                let row_count: i64 = sqlx::query_scalar(
                    "SELECT count(*) FROM integration_state \
                     WHERE integration_name = $1 AND user_id = $2",
                )
                .bind(integration_name)
                .bind(user_id)
                .fetch_one(&mut *tx)
                .await
                .map_err(db_err)?;
                if row_count >= MAX_ROWS_PER_INTEGRATION_USER {
                    // Drop the transaction (releases the advisory lock
                    // automatically per `xact` semantics).
                    return Err(IntegrationStateError::StorageFull);
                }
            }
            let expires_at: Option<DateTime<Utc>> =
                ttl_seconds.map(|secs| Utc::now() + chrono::Duration::seconds(secs as i64));
            let idx_ts_1 = slots.idx_ts_1_ms.and_then(ms_to_datetime);
            sqlx::query(
                "INSERT INTO integration_state \
                     (integration_name, user_id, key, value, expires_at, \
                      idx_str_1, idx_str_2, idx_ts_1, idx_int_1) \
                 VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, $8, $9) \
                 ON CONFLICT (integration_name, user_id, key) DO UPDATE SET \
                     value      = EXCLUDED.value, \
                     expires_at = EXCLUDED.expires_at, \
                     idx_str_1  = EXCLUDED.idx_str_1, \
                     idx_str_2  = EXCLUDED.idx_str_2, \
                     idx_ts_1   = EXCLUDED.idx_ts_1, \
                     idx_int_1  = EXCLUDED.idx_int_1",
            )
            .bind(integration_name)
            .bind(user_id)
            .bind(&key)
            .bind(&value_str)
            .bind(expires_at)
            .bind(slots.idx_str_1)
            .bind(slots.idx_str_2)
            .bind(idx_ts_1)
            .bind(slots.idx_int_1)
            .execute(&mut *tx)
            .await
            .map_err(db_err)?;
            tx.commit().await.map_err(db_err)?;
            Ok(IntegrationOpResult::Ok)
        }
        IntegrationOp::Delete { key } => {
            sqlx::query(
                "DELETE FROM integration_state \
                 WHERE integration_name = $1 AND user_id = $2 AND key = $3",
            )
            .bind(integration_name)
            .bind(user_id)
            .bind(&key)
            .execute(pool)
            .await
            .map_err(db_err)?;
            Ok(IntegrationOpResult::Ok)
        }
        IntegrationOp::List { filter, limit } => {
            let capped_limit = limit.clamp(1, MAX_RESULT_LIMIT) as i64;
            // Dynamic query building — every value is bound via
            // parameters (never string-interpolated) so there's no
            // SQL-injection surface.
            let mut sql = String::from(
                "SELECT key, value, \
                        (EXTRACT(EPOCH FROM updated_at) * 1000)::bigint AS updated_at_ms, \
                        CASE WHEN expires_at IS NULL THEN NULL \
                             ELSE (EXTRACT(EPOCH FROM expires_at) * 1000)::bigint \
                        END AS expires_at_ms, \
                        idx_str_1, idx_str_2, \
                        CASE WHEN idx_ts_1 IS NULL THEN NULL \
                             ELSE (EXTRACT(EPOCH FROM idx_ts_1) * 1000)::bigint \
                        END AS idx_ts_1_ms, \
                        idx_int_1 \
                 FROM integration_state \
                 WHERE integration_name = $1 AND user_id = $2 \
                   AND (expires_at IS NULL OR expires_at > now())",
            );
            let mut bind_idx: u32 = 3;
            if filter.key_prefix.is_some() {
                sql.push_str(&format!(" AND key LIKE ${}", bind_idx));
                bind_idx += 1;
            }
            if filter.idx_str_1_eq.is_some() {
                sql.push_str(&format!(" AND idx_str_1 = ${}", bind_idx));
                bind_idx += 1;
            }
            if filter.idx_str_2_eq.is_some() {
                sql.push_str(&format!(" AND idx_str_2 = ${}", bind_idx));
                bind_idx += 1;
            }
            if filter.idx_ts_1_gte_ms.is_some() {
                sql.push_str(&format!(" AND idx_ts_1 >= ${}", bind_idx));
                bind_idx += 1;
            }
            if filter.idx_ts_1_lt_ms.is_some() {
                sql.push_str(&format!(" AND idx_ts_1 < ${}", bind_idx));
                bind_idx += 1;
            }
            if filter.idx_int_1_eq.is_some() {
                sql.push_str(&format!(" AND idx_int_1 = ${}", bind_idx));
                bind_idx += 1;
            }
            sql.push_str(&format!(" ORDER BY updated_at DESC LIMIT ${}", bind_idx));

            let mut q = sqlx::query(&sql).bind(integration_name).bind(user_id);
            if let Some(ref p) = filter.key_prefix {
                // Escape LIKE metacharacters so a `%` or `_` in the
                // caller's prefix doesn't silently become a wildcard.
                q = q.bind(format!("{}%", escape_like_pattern(p)));
            }
            if let Some(s) = filter.idx_str_1_eq {
                q = q.bind(s);
            }
            if let Some(s) = filter.idx_str_2_eq {
                q = q.bind(s);
            }
            if let Some(ms) = filter.idx_ts_1_gte_ms {
                q = q.bind(ms_to_datetime(ms).ok_or_else(|| {
                    IntegrationStateError::InvalidInput("idx_ts_1_gte_ms out of range".into())
                })?);
            }
            if let Some(ms) = filter.idx_ts_1_lt_ms {
                q = q.bind(ms_to_datetime(ms).ok_or_else(|| {
                    IntegrationStateError::InvalidInput("idx_ts_1_lt_ms out of range".into())
                })?);
            }
            if let Some(n) = filter.idx_int_1_eq {
                q = q.bind(n);
            }
            q = q.bind(capped_limit);

            let rows = q.fetch_all(pool).await.map_err(db_err)?;
            let entries: Vec<_> = rows.iter().map(row_to_entry).collect::<Result<_, _>>()?;
            Ok(IntegrationOpResult::Entries { entries })
        }
    }
}

/// Constant error message for every DB failure. Raw Postgres text never
/// crosses this boundary — it's logged server-side so operators can
/// debug, but the caller only sees a fixed string. Critical when the
/// caller is WASM guest code (via the RPC subscriber).
fn db_err(e: sqlx::Error) -> IntegrationStateError {
    tracing::error!(error = %e, "integration_state db op failed");
    IntegrationStateError::Internal("database operation failed".into())
}

fn row_to_entry(row: &sqlx::postgres::PgRow) -> Result<StoredEntry, IntegrationStateError> {
    use sqlx::Row;
    let key: String = row.try_get("key").map_err(|e| {
        tracing::error!(error = %e, "integration_state row.key decode failed");
        IntegrationStateError::Internal("row decode failed".into())
    })?;
    let value_json: serde_json::Value = row.try_get("value").map_err(|e| {
        tracing::error!(error = %e, "integration_state row.value decode failed");
        IntegrationStateError::Internal("row decode failed".into())
    })?;
    let value = serde_json::to_string(&value_json).map_err(|e| {
        tracing::error!(error = %e, "integration_state row serialize failed");
        IntegrationStateError::Internal("row encode failed".into())
    })?;
    let updated_at_ms: i64 = row.try_get("updated_at_ms").unwrap_or(0);
    let expires_at_ms: Option<i64> = row.try_get("expires_at_ms").unwrap_or(None);
    let idx_str_1: Option<String> = row.try_get("idx_str_1").unwrap_or(None);
    let idx_str_2: Option<String> = row.try_get("idx_str_2").unwrap_or(None);
    let idx_ts_1_ms: Option<i64> = row.try_get("idx_ts_1_ms").unwrap_or(None);
    let idx_int_1: Option<i64> = row.try_get("idx_int_1").unwrap_or(None);
    Ok(StoredEntry {
        key,
        value,
        updated_at_ms,
        expires_at_ms,
        slots: IndexedSlots {
            idx_str_1,
            idx_str_2,
            idx_ts_1_ms,
            idx_int_1,
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_key_is_deterministic() {
        let uid = Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let a = integration_state_lock_key("gmail", uid);
        let b = integration_state_lock_key("gmail", uid);
        assert_eq!(a, b, "same input must produce same lock key");
    }

    #[test]
    fn lock_key_differs_for_different_integrations() {
        let uid = Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let a = integration_state_lock_key("gmail", uid);
        let b = integration_state_lock_key("gcal", uid);
        assert_ne!(
            a, b,
            "distinct integration_name must produce distinct keys (collision rate ~2^-64)"
        );
    }

    #[test]
    fn lock_key_differs_for_different_users() {
        let uid1 = Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let uid2 = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
        let a = integration_state_lock_key("gmail", uid1);
        let b = integration_state_lock_key("gmail", uid2);
        assert_ne!(
            a, b,
            "distinct user_id must produce distinct keys (collision rate ~2^-64)"
        );
    }

    #[test]
    fn lock_key_stable_across_versions() {
        // Pinning known-vector: this property guards against an
        // accidental refactor changing the hash function and
        // invalidating in-flight advisory locks across a rolling
        // deploy. A new derivation = a deliberate migration, not an
        // ABI change.
        let uid = Uuid::parse_str("f47ac10b-58cc-4372-a567-0e02b2c3d479").unwrap();
        let k = integration_state_lock_key("gmail", uid);
        // SHA-256("gmail" || uuid_bytes)[..8] as i64 BE — the only
        // value this function may emit for these inputs.
        let expected: i64 = i64::from_be_bytes({
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(b"gmail");
            hasher.update(uid.as_bytes());
            let bytes = hasher.finalize();
            bytes[..8].try_into().unwrap()
        });
        assert_eq!(k, expected);
    }
}
