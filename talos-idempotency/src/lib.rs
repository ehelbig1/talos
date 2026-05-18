//! Request deduplication and idempotency key support.
//!
//! Prevents duplicate processing of:
//! - Webhook deliveries
//! - API mutations (POST/PUT)
//! - Workflow executions
//! - Payment operations

use anyhow::{anyhow, Result};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

/// Idempotency key record
#[derive(Debug, Clone)]
pub struct IdempotencyRecord {
    pub key: String,
    pub request_hash: String,
    pub response_body: Option<String>,
    pub status_code: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Idempotency key service
pub struct IdempotencyService {
    redis: Arc<redis::Client>,
    default_ttl: Duration,
}

impl IdempotencyService {
    /// Create new service
    pub fn new(redis: Arc<redis::Client>, ttl: Duration) -> Self {
        Self {
            redis,
            default_ttl: ttl,
        }
    }

    /// Check if request is duplicate and return cached response.
    ///
    /// Returns `Ok(Some(record))` on a true cache hit (same key + same hash),
    /// `Ok(None)` on a miss, and `Err(...)` on a hash mismatch — the
    /// caller MUST treat the mismatch as a 4xx surface (someone is reusing
    /// an Idempotency-Key with a different body, intentionally or via
    /// client bug) and refuse to process, not silently fall through to a
    /// duplicate execution.
    ///
    /// MCP-487 return-shape fix: Lua tables keyed by strings only
    /// (e.g. `{status = ..., body = ...}`) RESP-encode as empty arrays —
    /// Redis's Lua-to-RESP conversion uses numeric indices and discards
    /// string keys. The previous script returned such a table on every
    /// hit AND mismatch, so the Rust positional decoder always errored
    /// out and the caller fell through to `Ok(None)` (= cache miss),
    /// silently re-processing every duplicate. Switching the Lua script
    /// to `cjson.encode(...)` of a structured outcome shape eliminates
    /// the conversion ambiguity entirely — the wire format is a single
    /// bulk string parsed by serde on the Rust side.
    pub async fn check(&self, key: &str, request_hash: &str) -> Result<Option<IdempotencyRecord>> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;

        let redis_key = format!("idempotency:{}", key);

        // Lua script: atomically GET + verify hash + extract TTL. Encodes
        // the outcome as JSON so the Rust side has a single, unambiguous
        // wire shape — see the doc-comment above for why string-keyed
        // Lua tables don't work.
        let script = r#"
            local key = KEYS[1]
            local request_hash = ARGV[1]
            local data = redis.call('GET', key)
            if not data then
                return nil
            end
            local record = cjson.decode(data)
            if record.request_hash ~= request_hash then
                return cjson.encode({tag = 'mismatch'})
            end
            local ttl = redis.call('TTL', key)
            return cjson.encode({
                tag = 'hit',
                status_code = record.status_code,
                response_body = record.response_body,
                created_at = record.created_at,
                ttl_seconds = ttl
            })
        "#;

        let result: Option<String> = redis::cmd("EVAL")
            .arg(script)
            .arg(1)
            .arg(&redis_key)
            .arg(request_hash)
            .query_async(&mut conn)
            .await?;

        let Some(json) = result else {
            return Ok(None); // genuine cache miss
        };

        let outcome: CheckOutcome = serde_json::from_str(&json)
            .map_err(|e| anyhow!("idempotency check returned malformed payload: {e}"))?;

        match outcome {
            CheckOutcome::Mismatch => {
                // Security signal: log AT WARN so operators can spot
                // intentional key-reuse attacks or buggy clients that
                // recycle keys across distinct request bodies. NEVER
                // return the original cached response in this case —
                // doing so would let an attacker who guesses a victim's
                // Idempotency-Key fish for that victim's response.
                tracing::warn!(
                    %key,
                    "idempotency key reused with different request hash; rejecting"
                );
                Err(anyhow!(
                    "Idempotency-Key reused with a different request body"
                ))
            }
            CheckOutcome::Hit {
                status_code,
                response_body,
                created_at,
                ttl_seconds,
            } => {
                let created = created_at
                    .as_deref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now);
                let expires =
                    Utc::now() + chrono::Duration::seconds(ttl_seconds.max(0));
                Ok(Some(IdempotencyRecord {
                    key: key.to_string(),
                    request_hash: request_hash.to_string(),
                    status_code,
                    response_body,
                    created_at: created,
                    expires_at: expires,
                }))
            }
        }
    }

    /// Store response for idempotency key.
    ///
    /// MCP-487: uses `SET ... NX EX` so only the FIRST writer wins. The
    /// crate today has no separate `begin/complete` reservation step
    /// (TOCTOU window between `check` and `store` is still open — two
    /// concurrent identical requests can both miss the cache and both
    /// proceed through their handler), but the NX guard at least ensures
    /// the canonical cached response is stable. Without it, request A's
    /// cached response could be overwritten by request B's non-identical
    /// response (different timestamps, non-deterministic ordering of
    /// child resources, etc.) and a subsequent `check` would return B's
    /// response instead of A's. The Idempotency-Key contract is "same
    /// key returns same response forever within TTL" — that requires
    /// pinning the FIRST writer.
    ///
    /// Returns `Ok(true)` if this call wrote the record, `Ok(false)` if a
    /// concurrent writer beat us — the caller can use this signal to
    /// decide whether to log a "TOCTOU lost the race, my response was
    /// discarded" warning. A future `begin/complete` API would close
    /// the window entirely.
    pub async fn store(
        &self,
        key: &str,
        request_hash: &str,
        status_code: i32,
        response_body: Option<&str>,
    ) -> Result<bool> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;

        let redis_key = format!("idempotency:{}", key);

        // Use `response_body` directly so Option round-trips as JSON
        // null vs string — previously `.unwrap_or("")` collapsed
        // None into "" and lost the distinction at retrieval.
        let record = serde_json::json!({
            "request_hash": request_hash,
            "status_code": status_code,
            "response_body": response_body,
            "created_at": Utc::now().to_rfc3339(),
        });

        let ttl_secs = self.default_ttl.as_secs() as usize;

        let outcome: Option<String> = redis::cmd("SET")
            .arg(&redis_key)
            .arg(record.to_string())
            .arg("NX")
            .arg("EX")
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await?;

        Ok(outcome.is_some())
    }

    /// Generate hash of request body for idempotency check.
    ///
    /// MCP-440: returns 32 hex chars (128 bits) rather than 16 (64 bits).
    /// With 64-bit truncation, a birthday-collision attack against the
    /// idempotency mismatch detection is feasible (~2^32 grind). An
    /// attacker who can predict a victim's request body can craft a
    /// distinct payload that hashes to the same 16-char value and
    /// suppress the victim's request as a "duplicate". 128 bits pushes
    /// collision-grinding to 2^64, which is not feasible.
    pub fn hash_request(body: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(body);
        hex::encode(hasher.finalize())[..32].to_string()
    }

}

/// Internal representation of the `check` Lua script's outcome payload.
#[derive(Debug, Deserialize)]
#[serde(tag = "tag")]
enum CheckOutcome {
    #[serde(rename = "hit")]
    Hit {
        status_code: i32,
        response_body: Option<String>,
        created_at: Option<String>,
        ttl_seconds: i64,
    },
    #[serde(rename = "mismatch")]
    Mismatch,
}

/// Webhook deduplication service
pub struct WebhookDeduplication {
    redis: Arc<redis::Client>,
    window: Duration,
}

impl WebhookDeduplication {
    pub fn new(redis: Arc<redis::Client>, window: Duration) -> Self {
        Self { redis, window }
    }

    /// Check if webhook was already processed
    pub async fn is_duplicate(&self, trigger_id: Uuid, event_id: &str) -> Result<bool> {
        let mut conn = self.redis.get_multiplexed_async_connection().await?;

        let key = format!("webhook:processed:{}:{}", trigger_id, event_id);

        // Try to set - if already exists, it's a duplicate
        let set: bool = redis::cmd("SET")
            .arg(&key)
            .arg("1")
            .arg("NX")
            .arg("EX")
            .arg(self.window.as_secs() as usize)
            .query_async(&mut conn)
            .await?;

        Ok(!set) // Not set = duplicate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_request() {
        let body = b"test request body";
        let hash1 = IdempotencyService::hash_request(body);
        let hash2 = IdempotencyService::hash_request(body);

        assert_eq!(hash1, hash2);
        // MCP-440: 32 hex chars = 128 bits → birthday collision 2^64,
        // not feasibly grindable. 16 hex (64 bits) was.
        assert_eq!(hash1.len(), 32);
    }

    #[test]
    fn test_hash_request_distinct_inputs_distinct_outputs() {
        // Forensic value: two different payloads must produce different
        // hashes. With 32 hex chars these never collide at any realistic
        // scale.
        let a = IdempotencyService::hash_request(b"payload-a");
        let b = IdempotencyService::hash_request(b"payload-b");
        assert_ne!(a, b);
    }

    #[test]
    fn test_check_outcome_hit_decodes() {
        // MCP-487: this is the wire shape the fixed Lua script returns
        // for a cache hit. Locking it in so a future Lua-script edit
        // can't silently regress to the string-keyed-table shape that
        // RESP-encodes as empty array.
        let json = r#"{
            "tag": "hit",
            "status_code": 201,
            "response_body": "{\"id\":42}",
            "created_at": "2026-05-11T12:00:00Z",
            "ttl_seconds": 3600
        }"#;
        let outcome: CheckOutcome = serde_json::from_str(json).unwrap();
        match outcome {
            CheckOutcome::Hit {
                status_code,
                response_body,
                ttl_seconds,
                ..
            } => {
                assert_eq!(status_code, 201);
                assert_eq!(response_body.as_deref(), Some("{\"id\":42}"));
                assert_eq!(ttl_seconds, 3600);
            }
            _ => panic!("expected Hit"),
        }
    }

    #[test]
    fn test_check_outcome_hit_with_null_body() {
        // None body must round-trip as JSON null, not "" — distinguishing
        // a 204 No Content cached response from a 200 with empty body.
        let json = r#"{
            "tag": "hit",
            "status_code": 204,
            "response_body": null,
            "created_at": null,
            "ttl_seconds": 60
        }"#;
        let outcome: CheckOutcome = serde_json::from_str(json).unwrap();
        match outcome {
            CheckOutcome::Hit {
                response_body,
                created_at,
                ..
            } => {
                assert!(response_body.is_none());
                assert!(created_at.is_none());
            }
            _ => panic!("expected Hit"),
        }
    }

    #[test]
    fn test_check_outcome_mismatch_decodes() {
        let json = r#"{"tag": "mismatch"}"#;
        let outcome: CheckOutcome = serde_json::from_str(json).unwrap();
        assert!(matches!(outcome, CheckOutcome::Mismatch));
    }

    #[test]
    fn test_check_outcome_unknown_tag_errors() {
        // Future-proofing — if the Lua script ever emits a new tag and
        // an old controller is still running, we want a structured
        // error not a silent fallthrough that re-processes the request.
        let json = r#"{"tag": "pending"}"#;
        let err = serde_json::from_str::<CheckOutcome>(json);
        assert!(err.is_err(), "unknown tag must error, got {:?}", err);
    }
}
