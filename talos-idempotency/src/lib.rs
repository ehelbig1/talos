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
    /// The original response's `Content-Type`, cached so a replayed response is
    /// faithful — without it a replayed JSON body arrives with no Content-Type
    /// and clients (e.g. GraphQL clients) mis-parse it.
    pub content_type: Option<String>,
    pub status_code: i32,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Outcome of [`IdempotencyService::begin`] — the atomic claim that closes the
/// TOCTOU window the legacy `check` + `store` pair left open.
#[derive(Debug, Clone)]
pub enum BeginOutcome {
    /// First arrival: THIS caller holds the reservation and MUST run the
    /// operation, then call [`IdempotencyService::complete`] with the
    /// response. The GET-and-claim was a single atomic Redis `EVAL`, so no
    /// other concurrent caller can also receive `Proceed` for this key.
    Proceed,
    /// A concurrent request with the SAME key + request hash is mid-flight
    /// (reserved but not yet completed). The caller should return `409
    /// Conflict` — the original is still running; retrying later may hit the
    /// cached response.
    InFlight,
    /// The operation already completed under this key + hash; return the
    /// cached response verbatim (do not re-execute).
    Hit(IdempotencyRecord),
    /// The key was used before with a DIFFERENT request hash. The caller MUST
    /// reject (4xx) and never return the other request's body — returning it
    /// would let an attacker who guesses a victim's key fish for the response.
    Mismatch,
}

/// Idempotency key service
pub struct IdempotencyService {
    redis: Arc<redis::Client>,
    default_ttl: Duration,
    /// M4 (2026-05-28 review): cached, auto-reconnecting multiplexed connection
    /// (see `conn`). Replaces a fresh TCP+TLS+AUTH connection per idempotent
    /// mutation.
    conn_mgr: tokio::sync::OnceCell<redis::aio::ConnectionManager>,
}

impl IdempotencyService {
    /// Create new service
    pub fn new(redis: Arc<redis::Client>, ttl: Duration) -> Self {
        Self {
            redis,
            default_ttl: ttl,
            conn_mgr: tokio::sync::OnceCell::new(),
        }
    }

    /// M4: hand out a clone of ONE cached, auto-reconnecting multiplexed
    /// connection instead of opening a fresh one per call. `get_or_try_init`
    /// does not cache an init failure, so a Redis outage at first use is retried.
    async fn conn(&self) -> Result<redis::aio::ConnectionManager> {
        let mgr = self
            .conn_mgr
            .get_or_try_init(|| async {
                redis::aio::ConnectionManager::new((*self.redis).clone()).await
            })
            .await?;
        Ok(mgr.clone())
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
        let mut conn = self.conn().await?;

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
                let expires = Utc::now() + chrono::Duration::seconds(ttl_seconds.max(0));
                Ok(Some(IdempotencyRecord {
                    key: key.to_string(),
                    request_hash: request_hash.to_string(),
                    status_code,
                    response_body,
                    // Legacy `check` predates content_type caching.
                    content_type: None,
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
        let mut conn = self.conn().await?;

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

    /// How long a reservation marker lives before it is treated as abandoned.
    /// MUST exceed the longest synchronous handler behind an idempotency key —
    /// if a reservation expires while its handler is still running, a retry
    /// could `begin` → `Proceed` and execute concurrently (the very
    /// double-execution this primitive prevents). Triggering a workflow only
    /// CREATES the execution (the run is async), so 120 s is comfortable; the
    /// completed-record TTL is the much-longer `default_ttl`.
    const RESERVATION_TTL_SECS: usize = 120;

    /// Atomically claim an idempotency key, or learn it is already
    /// in-flight/completed/conflicting. This is the TOCTOU-safe replacement
    /// for the `check` (GET) + `store` (SET NX) pair: the GET-and-claim is a
    /// single Redis `EVAL`, so exactly one concurrent caller receives
    /// [`BeginOutcome::Proceed`]. That caller runs the operation and MUST then
    /// call [`complete`](Self::complete); every other concurrent caller with
    /// the same key+hash gets [`BeginOutcome::InFlight`].
    ///
    /// MCP-487 lesson carried forward: the Lua script `cjson.encode`s a
    /// tagged outcome so the Rust side sees one unambiguous bulk-string shape
    /// (string-keyed Lua tables RESP-encode as empty arrays and silently
    /// decode-fail).
    pub async fn begin(&self, key: &str, request_hash: &str) -> Result<BeginOutcome> {
        let mut conn = self.conn().await?;
        let redis_key = format!("idempotency:{}", key);

        // Atomic GET-and-claim. On miss: write a `reserved` marker (short TTL)
        // and return `proceed`. On a `reserved`/completed record: return
        // `in_flight`/`hit`. On a hash mismatch: return `mismatch` and DO NOT
        // claim (the existing owner keeps the key).
        let script = r#"
            local key = KEYS[1]
            local request_hash = ARGV[1]
            local reservation_ttl = tonumber(ARGV[2])
            local now = ARGV[3]
            local data = redis.call('GET', key)
            if not data then
                redis.call('SET', key,
                    cjson.encode({tag='reserved', request_hash=request_hash, created_at=now}),
                    'EX', reservation_ttl)
                return cjson.encode({tag='proceed'})
            end
            local record = cjson.decode(data)
            if record.request_hash ~= request_hash then
                return cjson.encode({tag='mismatch'})
            end
            if record.tag == 'reserved' then
                return cjson.encode({tag='in_flight'})
            end
            local ttl = redis.call('TTL', key)
            return cjson.encode({
                tag = 'hit',
                status_code = record.status_code,
                response_body = record.response_body,
                content_type = record.content_type,
                created_at = record.created_at,
                ttl_seconds = ttl
            })
        "#;

        let now = Utc::now().to_rfc3339();
        let json: String = redis::cmd("EVAL")
            .arg(script)
            .arg(1)
            .arg(&redis_key)
            .arg(request_hash)
            .arg(Self::RESERVATION_TTL_SECS)
            .arg(&now)
            .query_async(&mut conn)
            .await?;

        let payload: BeginPayload = serde_json::from_str(&json)
            .map_err(|e| anyhow!("idempotency begin returned malformed payload: {e}"))?;
        Ok(payload.into_outcome(key, request_hash))
    }

    /// Persist the response for a key previously claimed via [`begin`](Self::begin),
    /// overwriting the reservation marker with the completed record at the full
    /// [`default_ttl`](Self#structfield.default_ttl). Idempotent and safe to
    /// retry. Refuses to clobber a key now owned by a DIFFERENT request hash
    /// (e.g. if the reservation expired and another request claimed it),
    /// returning `Ok(false)` in that case so the caller can log the lost race.
    pub async fn complete(
        &self,
        key: &str,
        request_hash: &str,
        status_code: i32,
        response_body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<bool> {
        let mut conn = self.conn().await?;
        let redis_key = format!("idempotency:{}", key);

        let record = serde_json::json!({
            "tag": "completed",
            "request_hash": request_hash,
            "status_code": status_code,
            "response_body": response_body,
            "content_type": content_type,
            "created_at": Utc::now().to_rfc3339(),
        });
        let ttl_secs = self.default_ttl.as_secs() as usize;

        // Only write if the current value is absent or still OURS (same hash) —
        // never overwrite a key a different request now owns.
        let script = r#"
            local key = KEYS[1]
            local request_hash = ARGV[1]
            local record = ARGV[2]
            local ttl = tonumber(ARGV[3])
            local data = redis.call('GET', key)
            if data then
                local cur = cjson.decode(data)
                if cur.request_hash ~= request_hash then
                    return 0
                end
            end
            redis.call('SET', key, record, 'EX', ttl)
            return 1
        "#;

        let wrote: i64 = redis::cmd("EVAL")
            .arg(script)
            .arg(1)
            .arg(&redis_key)
            .arg(request_hash)
            .arg(record.to_string())
            .arg(ttl_secs)
            .query_async(&mut conn)
            .await?;

        Ok(wrote == 1)
    }

    /// Release a reservation WITHOUT caching a response. Used when the
    /// operation failed transiently (5xx) so a retry can proceed fresh rather
    /// than being told `InFlight` until [`RESERVATION_TTL_SECS`](Self::RESERVATION_TTL_SECS)
    /// elapses. Only deletes a key still held as OUR reservation (same hash,
    /// still `reserved`) — never a completed record or one another request
    /// now owns.
    pub async fn release(&self, key: &str, request_hash: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        let redis_key = format!("idempotency:{}", key);
        let script = r#"
            local key = KEYS[1]
            local request_hash = ARGV[1]
            local data = redis.call('GET', key)
            if data then
                local cur = cjson.decode(data)
                if cur.request_hash == request_hash and cur.tag == 'reserved' then
                    redis.call('DEL', key)
                end
            end
            return 1
        "#;
        let _: i64 = redis::cmd("EVAL")
            .arg(script)
            .arg(1)
            .arg(&redis_key)
            .arg(request_hash)
            .query_async(&mut conn)
            .await?;
        Ok(())
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

/// HTTP header carrying the client-chosen idempotency key.
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";

/// Response header stamped on a replayed (cache-hit) response so clients and
/// operators can tell a replay from a fresh execution.
pub const IDEMPOTENT_REPLAYED_HEADER: &str = "idempotent-replayed";

/// Max accepted idempotency-key length (matches typical provider limits).
const MAX_IDEMPOTENCY_KEY_LEN: usize = 255;

/// Cap on the request body buffered to hash it — deliberately ABOVE the
/// largest route `DefaultBodyLimit` (GraphQL's 5 MiB) so the route's own limit,
/// not this one, rejects oversized bodies. This is only a backstop against
/// unbounded buffering on the idempotency path.
const MAX_IDEMPOTENT_REQUEST_BYTES: usize = 8 * 1024 * 1024;

/// Cap on a response body cached + replayed. A larger response can't be cached
/// (the buffered stream is consumed), so the idempotent request gets a 500 and
/// the reservation is released so a retry can proceed.
const MAX_IDEMPOTENT_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// True if `k` is a well-formed idempotency key: non-empty, ≤ 255 chars, and
/// all printable ASCII (so it's safe as a Redis key suffix + a header value).
pub fn valid_idempotency_key(k: &str) -> bool {
    !k.is_empty() && k.len() <= MAX_IDEMPOTENCY_KEY_LEN && k.bytes().all(|b| b.is_ascii_graphic())
}

/// Caller-identifying bytes used to NAMESPACE idempotency keys per caller.
///
/// SECURITY: without this, the Redis key is `idempotency:<client-key>` — a
/// GLOBAL namespace. Two callers choosing the same `Idempotency-Key` with the
/// same body would collide, so caller B's `begin` would replay caller A's
/// cached response (a created API key, a secret, …). Folding the caller's
/// credential into the key (`idempotency:<hash(creds)>.<client-key>`) gives
/// each caller an independent namespace. Uses whatever auth material the
/// request carries — `Authorization`, `X-API-Key`, and the `talos_access_token`
/// session cookie — so the scope is stable across a caller's retries but
/// differs between callers. Unauthenticated requests share the empty scope, but
/// their mutations are rejected downstream so nothing sensitive is cached.
fn caller_scope(headers: &axum::http::HeaderMap) -> Vec<u8> {
    let mut scope = Vec::new();
    if let Some(v) = headers.get(axum::http::header::AUTHORIZATION) {
        scope.extend_from_slice(b"a:");
        scope.extend_from_slice(v.as_bytes());
        scope.push(0);
    }
    if let Some(v) = headers.get("x-api-key") {
        scope.extend_from_slice(b"k:");
        scope.extend_from_slice(v.as_bytes());
        scope.push(0);
    }
    if let Some(cookie) = headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
    {
        for part in cookie.split(';') {
            if let Some(tok) = part.trim().strip_prefix("talos_access_token=") {
                scope.extend_from_slice(b"s:");
                scope.extend_from_slice(tok.as_bytes());
                scope.push(0);
            }
        }
    }
    scope
}

/// Opt-in idempotency middleware. Requests WITHOUT an `Idempotency-Key` header
/// take a zero-touch passthrough — so existing traffic (none sends the header)
/// is entirely unaffected. With the header:
///   * malformed key → 400.
///   * no Redis configured → passthrough (can't enforce; never block).
///   * the request body is buffered + hashed, then `begin()` decides:
///     - `Hit`      → replay the cached response (stamped `idempotent-replayed`).
///     - `InFlight` → 409 (a same-key+body request is mid-flight).
///     - `Mismatch` → 422 (key reused with a different body).
///     - `Proceed`  → run the handler; cache the response via `complete()` for
///       status < 500, or `release()` on 5xx so a retry isn't stuck `InFlight`.
///   * a Redis error during `begin` fails OPEN (run the handler un-deduped)
///     rather than blocking the request.
pub async fn idempotency_middleware(
    axum::extract::Extension(service): axum::extract::Extension<Option<Arc<IdempotencyService>>>,
    request: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use axum::response::{IntoResponse, Response};

    // Never intercept a protocol upgrade (e.g. WebSocket on /ws, which shares
    // this middleware's route group). Buffering a `101 Switching Protocols`
    // response would drop the `OnUpgrade` extension and break the handshake.
    // Clients don't send Idempotency-Key on WS, but this is the safe gate.
    if request.headers().contains_key(axum::http::header::UPGRADE) {
        return next.run(request).await;
    }

    // Opt-in gate: no header → unchanged path. MUST stay first so existing
    // traffic never touches the buffering/Redis path.
    let key = match request
        .headers()
        .get(IDEMPOTENCY_KEY_HEADER)
        .and_then(|v| v.to_str().ok())
    {
        Some(k) => k.to_string(),
        None => return next.run(request).await,
    };
    if !valid_idempotency_key(&key) {
        return (StatusCode::BAD_REQUEST, "Invalid Idempotency-Key header").into_response();
    }
    // Redis not configured → can't enforce; never block the request.
    let Some(service) = service else {
        return next.run(request).await;
    };

    // Namespace the key per caller so a key + body chosen by one caller can
    // never replay another caller's cached response (cross-user cache leak).
    let scope_hash = IdempotencyService::hash_request(&caller_scope(request.headers()));
    let scoped_key = format!("{scope_hash}.{key}");

    // Buffer the request body to hash it, then rebuild the request unchanged.
    let (parts, body) = request.into_parts();
    let body_bytes = match to_bytes(body, MAX_IDEMPOTENT_REQUEST_BYTES).await {
        Ok(b) => b,
        Err(_) => return (StatusCode::PAYLOAD_TOO_LARGE, "Request body too large").into_response(),
    };
    let request_hash = IdempotencyService::hash_request(&body_bytes);

    match service.begin(&scoped_key, &request_hash).await {
        Ok(BeginOutcome::Hit(rec)) => {
            let status = StatusCode::from_u16(rec.status_code as u16).unwrap_or(StatusCode::OK);
            let mut resp = Response::new(Body::from(rec.response_body.unwrap_or_default()));
            *resp.status_mut() = status;
            // Faithful replay: restore the cached Content-Type so the replayed
            // body parses like the original. Default to JSON (the content type
            // of the API routes this middleware fronts) if none was cached.
            let ct = rec.content_type.as_deref().unwrap_or("application/json");
            if let Ok(v) = ct.parse() {
                resp.headers_mut()
                    .insert(axum::http::header::CONTENT_TYPE, v);
            }
            if let Ok(v) = "true".parse() {
                resp.headers_mut().insert(IDEMPOTENT_REPLAYED_HEADER, v);
            }
            resp
        }
        Ok(BeginOutcome::InFlight) => (
            StatusCode::CONFLICT,
            "A request with this Idempotency-Key is already in progress",
        )
            .into_response(),
        Ok(BeginOutcome::Mismatch) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            "Idempotency-Key was already used with a different request body",
        )
            .into_response(),
        Ok(BeginOutcome::Proceed) => {
            let request = Request::from_parts(parts, Body::from(body_bytes));
            let response = next.run(request).await;
            let (resp_parts, resp_body) = response.into_parts();
            let status = resp_parts.status;
            let content_type = resp_parts
                .headers
                .get(axum::http::header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            // Never cache a response that establishes client state via
            // `Set-Cookie` (login/refresh set a session cookie). Two reasons:
            // (1) the replay path restores only status+body+Content-Type, so a
            //     replayed login would return "success" with NO session cookie
            //     — a broken, confusing auth state; and
            // (2) caching the Set-Cookie would store a live session token in
            //     Redis for the full TTL.
            // Such responses are returned to THIS caller intact (resp_parts
            // keeps Set-Cookie) but the reservation is released so a retry
            // re-executes and gets a fresh cookie.
            let sets_cookie = resp_parts
                .headers
                .contains_key(axum::http::header::SET_COOKIE);
            match to_bytes(resp_body, MAX_IDEMPOTENT_RESPONSE_BYTES).await {
                Ok(bytes) => {
                    if status.as_u16() < 500 && !sets_cookie {
                        let body_str = String::from_utf8_lossy(&bytes).into_owned();
                        if let Err(e) = service
                            .complete(
                                &scoped_key,
                                &request_hash,
                                status.as_u16() as i32,
                                Some(&body_str),
                                content_type.as_deref(),
                            )
                            .await
                        {
                            tracing::warn!(error = %e, "idempotency complete failed; response not cached");
                        }
                    } else if let Err(e) = service.release(&scoped_key, &request_hash).await {
                        tracing::warn!(error = %e, "idempotency release failed (5xx or Set-Cookie response)");
                    }
                    Response::from_parts(resp_parts, Body::from(bytes))
                }
                Err(_) => {
                    // Body exceeded the cache cap and is now consumed; release so
                    // a retry can proceed, and surface a clear error.
                    let _ = service.release(&scoped_key, &request_hash).await;
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Response too large for idempotent handling",
                    )
                        .into_response()
                }
            }
        }
        Err(e) => {
            // Fail open: a Redis hiccup must not block the request.
            tracing::warn!(error = %e, "idempotency begin failed; processing without idempotency");
            let request = Request::from_parts(parts, Body::from(body_bytes));
            next.run(request).await
        }
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

/// Internal representation of the `begin` Lua script's outcome payload.
#[derive(Debug, Deserialize)]
#[serde(tag = "tag")]
enum BeginPayload {
    #[serde(rename = "proceed")]
    Proceed,
    #[serde(rename = "in_flight")]
    InFlight,
    #[serde(rename = "mismatch")]
    Mismatch,
    #[serde(rename = "hit")]
    Hit {
        status_code: i32,
        // `default` so a record written before content_type existed (or any
        // partial record) decodes to None rather than failing the whole begin.
        #[serde(default)]
        response_body: Option<String>,
        #[serde(default)]
        content_type: Option<String>,
        #[serde(default)]
        created_at: Option<String>,
        ttl_seconds: i64,
    },
}

impl BeginPayload {
    fn into_outcome(self, key: &str, request_hash: &str) -> BeginOutcome {
        match self {
            BeginPayload::Proceed => BeginOutcome::Proceed,
            BeginPayload::InFlight => BeginOutcome::InFlight,
            BeginPayload::Mismatch => BeginOutcome::Mismatch,
            BeginPayload::Hit {
                status_code,
                response_body,
                content_type,
                created_at,
                ttl_seconds,
            } => {
                let created = created_at
                    .as_deref()
                    .and_then(|s| DateTime::parse_from_rfc3339(s).ok())
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(Utc::now);
                let expires = Utc::now() + chrono::Duration::seconds(ttl_seconds.max(0));
                BeginOutcome::Hit(IdempotencyRecord {
                    key: key.to_string(),
                    request_hash: request_hash.to_string(),
                    status_code,
                    response_body,
                    content_type,
                    created_at: created,
                    expires_at: expires,
                })
            }
        }
    }
}

/// Webhook deduplication service
pub struct WebhookDeduplication {
    redis: Arc<redis::Client>,
    window: Duration,
    /// M4 (2026-05-28 review): cached, auto-reconnecting multiplexed connection.
    conn_mgr: tokio::sync::OnceCell<redis::aio::ConnectionManager>,
}

impl WebhookDeduplication {
    pub fn new(redis: Arc<redis::Client>, window: Duration) -> Self {
        Self {
            redis,
            window,
            conn_mgr: tokio::sync::OnceCell::new(),
        }
    }

    /// M4: clone of one cached, auto-reconnecting multiplexed connection.
    async fn conn(&self) -> Result<redis::aio::ConnectionManager> {
        let mgr = self
            .conn_mgr
            .get_or_try_init(|| async {
                redis::aio::ConnectionManager::new((*self.redis).clone()).await
            })
            .await?;
        Ok(mgr.clone())
    }

    /// Check if webhook was already processed
    pub async fn is_duplicate(&self, trigger_id: Uuid, event_id: &str) -> Result<bool> {
        let mut conn = self.conn().await?;

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

    /// Release a dedup claim taken by [`Self::is_duplicate`] (begin/abandon
    /// pattern). `is_duplicate` atomically RECORDS the claim at arrival — which
    /// correctly prevents two *concurrent* deliveries of the same event from
    /// both processing — but if the caller then hits a TRANSIENT failure
    /// *before* the event is actually processed (e.g. a module/workflow load
    /// error returning a retryable 5xx), the claim must be released so the
    /// sender's redelivery isn't silently suppressed as a "duplicate" and the
    /// delivery lost for the whole window. Callers release ONLY on
    /// pre-processing failures; a claim for an event that actually ran stays
    /// recorded.
    ///
    /// DELs the same `webhook:processed:{trigger_id}:{event_id}` key. The value
    /// is a fixed sentinel (`"1"`), so an unconditional DEL is correct — there
    /// is no per-caller token to guard against (unlike the idempotency
    /// `reserved` records above), and the key is namespaced per (trigger,
    /// event), so a release can only affect this exact claim.
    pub async fn release(&self, trigger_id: Uuid, event_id: &str) -> Result<()> {
        let mut conn = self.conn().await?;
        let key = format!("webhook:processed:{}:{}", trigger_id, event_id);
        let _: i64 = redis::cmd("DEL").arg(&key).query_async(&mut conn).await?;
        Ok(())
    }
}

// ============================================================================
// In-memory, per-process idempotency dedup store (worker-side)
// ============================================================================
//
// The credential-free worker has NO Redis (all data-plane access is signed
// NATS-RPC to the controller), so [`IdempotencyService`] above — which is
// Redis-backed — is not usable there. This lightweight in-memory store is the
// worker's belt-and-suspenders layer ON TOP OF the `Idempotency-Key` HTTP
// header a mutating send already carries when the node declared
// `__idempotency_key__`:
//
// * The HEADER is the primary mechanism — it lets a *destination that honors
//   it* collapse a retried/duplicate send.
// * This STORE covers the case where the destination does NOT honor the header:
//   once a send under key `K` has COMPLETED SUCCESSFULLY in this process, a
//   subsequent send under the same `K` (a module firing twice, an in-worker
//   pipeline-step re-execution, or a controller re-dispatch that lands on the
//   same worker within the TTL) is short-circuited and returns the cached
//   response instead of re-firing.
//
// KNOWN GAP (documented, not a bug): a send that TIMES OUT after the
// destination already applied it is never recorded here (no success was
// observed), so a subsequent attempt still re-fires — closing that requires
// destination-side idempotency support (the header). This store only dedupes
// *observed* successes, which is the safe direction: a non-2xx response is NOT
// cached, so a genuinely-failed op stays retryable.

/// A neutral cached response for the in-memory dedup store. Deliberately
/// transport-agnostic (status + headers + body) so both the `http::fetch` and
/// `webhook::send` host paths can reconstruct their own response type from it
/// without this crate depending on the WIT bindings.
#[derive(Debug, Clone)]
pub struct DedupResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Outcome of [`InMemoryIdempotencyStore::check`].
#[derive(Debug, Clone)]
pub enum DedupCheck {
    /// No fresh completed record for this key — the caller MUST fire the send
    /// and, on a successful response, call [`InMemoryIdempotencyStore::complete`].
    Proceed,
    /// This key already completed successfully in this process within the TTL
    /// window — return this cached response verbatim instead of re-firing.
    Completed(DedupResponse),
}

struct DedupEntry {
    stored_at: std::time::Instant,
    response: DedupResponse,
}

/// Per-process, in-memory, TTL-bounded idempotency dedup store. Cheap: a single
/// `Mutex<HashMap>` guarded by short, await-free critical sections. Bounded by
/// both a TTL sweep (read- and write-path) and a hard entry cap, so memory can
/// never grow monotonically with distinct-keys-ever-seen.
pub struct InMemoryIdempotencyStore {
    inner: std::sync::Mutex<InMemoryInner>,
    ttl: Duration,
    max_entries: usize,
}

struct InMemoryInner {
    entries: std::collections::HashMap<String, DedupEntry>,
    last_sweep: std::time::Instant,
}

impl InMemoryIdempotencyStore {
    /// Create a store with the given completed-record TTL and hard entry cap.
    #[must_use]
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            inner: std::sync::Mutex::new(InMemoryInner {
                entries: std::collections::HashMap::new(),
                last_sweep: std::time::Instant::now(),
            }),
            ttl,
            max_entries: max_entries.max(1),
        }
    }

    /// Sweep expired entries. Called opportunistically from `check`/`complete`
    /// but rate-limited to at most once per `ttl` so hot paths don't pay an
    /// O(n) scan on every call. Caller holds the lock.
    fn maybe_sweep(&self, inner: &mut InMemoryInner, now: std::time::Instant) {
        if now.duration_since(inner.last_sweep) < self.ttl {
            return;
        }
        let ttl = self.ttl;
        inner
            .entries
            .retain(|_, e| now.duration_since(e.stored_at) < ttl);
        inner.last_sweep = now;
    }

    /// Check for a fresh completed record. Returns [`DedupCheck::Completed`]
    /// with the cached response when this key completed within the TTL, else
    /// [`DedupCheck::Proceed`]. A stale (expired) record is treated as a miss.
    #[must_use]
    pub fn check(&self, key: &str) -> DedupCheck {
        let now = std::time::Instant::now();
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            // Poisoned lock (a prior panic while holding it): fail OPEN — a
            // dedup store must never block a legitimate send. Proceed as if
            // there were no record.
            Err(_) => return DedupCheck::Proceed,
        };
        self.maybe_sweep(&mut inner, now);
        match inner.entries.get(key) {
            Some(e) if now.duration_since(e.stored_at) < self.ttl => {
                DedupCheck::Completed(e.response.clone())
            }
            _ => DedupCheck::Proceed,
        }
    }

    /// Record a SUCCESSFUL completion for `key`. Callers MUST only record
    /// responses that represent a genuine success (2xx) — a failed op must stay
    /// retryable, so non-success responses are not stored by convention. The
    /// hard entry cap is enforced here: when full, an expired-entry sweep runs
    /// first, and if the map is still at capacity the record is dropped
    /// (best-effort — the header remains the primary dedup mechanism).
    pub fn complete(&self, key: &str, response: DedupResponse) {
        let now = std::time::Instant::now();
        let mut inner = match self.inner.lock() {
            Ok(g) => g,
            Err(_) => return, // poisoned: skip recording, fail open
        };
        // Only force a sweep when we're at the cap; otherwise honor the
        // rate-limited cadence.
        if inner.entries.len() >= self.max_entries {
            let ttl = self.ttl;
            inner
                .entries
                .retain(|_, e| now.duration_since(e.stored_at) < ttl);
            inner.last_sweep = now;
        } else {
            self.maybe_sweep(&mut inner, now);
        }
        if inner.entries.len() >= self.max_entries && !inner.entries.contains_key(key) {
            // Still full after sweeping and this is a new key — drop it rather
            // than grow unbounded. Log once-ish at debug; the miss is benign.
            tracing::debug!(
                cap = self.max_entries,
                "in-memory idempotency store at capacity; dropping new dedup record"
            );
            return;
        }
        inner.entries.insert(
            key.to_string(),
            DedupEntry {
                stored_at: now,
                response,
            },
        );
    }

    /// Test/introspection helper: current number of retained entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().map(|g| g.entries.len()).unwrap_or(0)
    }

    /// Whether the store currently holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The `begin` Lua script returns one of four cjson-encoded tagged shapes.
    // The Redis-atomic GET-and-claim itself needs a live Redis (no test infra
    // in this crate), but the Rust-side decode + mapping to `BeginOutcome` is
    // pure and pinned here — a wire-shape drift (the MCP-487 class) would break
    // every idempotent request, so it must decode unambiguously.
    fn parse(json: &str) -> BeginOutcome {
        serde_json::from_str::<BeginPayload>(json)
            .expect("valid begin payload")
            .into_outcome("k", "h")
    }

    #[test]
    fn caller_scope_isolates_distinct_callers() {
        use axum::http::HeaderMap;
        let scope = |build: &dyn Fn(&mut HeaderMap)| {
            let mut h = HeaderMap::new();
            build(&mut h);
            super::caller_scope(&h)
        };
        let user_a = scope(&|h| {
            h.insert("authorization", "Bearer token-A".parse().unwrap());
        });
        let user_b = scope(&|h| {
            h.insert("authorization", "Bearer token-B".parse().unwrap());
        });
        let api_key = scope(&|h| {
            h.insert("x-api-key", "key-123".parse().unwrap());
        });
        let cookie_a = scope(&|h| {
            h.insert(
                "cookie",
                "csrf=z; talos_access_token=A; foo=bar".parse().unwrap(),
            );
        });
        let cookie_b = scope(&|h| {
            h.insert(
                "cookie",
                "csrf=z; talos_access_token=B; foo=bar".parse().unwrap(),
            );
        });
        let none = scope(&|_| {});

        // Distinct credentials → distinct scopes (no cross-caller cache hit).
        assert_ne!(user_a, user_b);
        assert_ne!(user_a, api_key);
        assert_ne!(
            cookie_a, cookie_b,
            "different session token → different scope"
        );
        // The empty (unauthenticated) scope is distinct from any credentialed one.
        assert!(none.is_empty());
        assert_ne!(none, user_a);
        // Same credential → same scope (a caller's own retry still hits cache).
        assert_eq!(
            user_a,
            scope(&|h| {
                h.insert("authorization", "Bearer token-A".parse().unwrap());
            })
        );
        // Only the session cookie matters, not unrelated cookies (csrf/foo here).
        assert_eq!(
            cookie_a,
            scope(&|h| {
                h.insert("cookie", "talos_access_token=A".parse().unwrap());
            })
        );
    }

    #[test]
    fn valid_idempotency_key_rules() {
        assert!(valid_idempotency_key("abc-123_XYZ.req:42"));
        assert!(!valid_idempotency_key("")); // empty
        assert!(!valid_idempotency_key("has space")); // whitespace
        assert!(!valid_idempotency_key("tab\there")); // control
        assert!(!valid_idempotency_key(&"a".repeat(256))); // too long
        assert!(valid_idempotency_key(&"a".repeat(255))); // at the cap
    }

    #[test]
    fn begin_payload_proceed_in_flight_mismatch() {
        assert!(matches!(
            parse(r#"{"tag":"proceed"}"#),
            BeginOutcome::Proceed
        ));
        assert!(matches!(
            parse(r#"{"tag":"in_flight"}"#),
            BeginOutcome::InFlight
        ));
        assert!(matches!(
            parse(r#"{"tag":"mismatch"}"#),
            BeginOutcome::Mismatch
        ));
    }

    #[test]
    fn begin_payload_hit_builds_record() {
        let out = parse(
            r#"{"tag":"hit","status_code":201,"response_body":"{\"ok\":true}","content_type":"application/json","created_at":"2026-06-01T00:00:00+00:00","ttl_seconds":3600}"#,
        );
        match out {
            BeginOutcome::Hit(rec) => {
                assert_eq!(rec.key, "k");
                assert_eq!(rec.request_hash, "h");
                assert_eq!(rec.status_code, 201);
                assert_eq!(rec.response_body.as_deref(), Some("{\"ok\":true}"));
                assert_eq!(rec.content_type.as_deref(), Some("application/json"));
                assert!(rec.expires_at > rec.created_at);
            }
            other => panic!("expected Hit, got {other:?}"),
        }
    }

    #[test]
    fn begin_payload_hit_missing_content_type_is_none() {
        // A record cached before content_type existed omits the field — it must
        // decode to None (not fail the whole begin), and the replay then falls
        // back to the default content type.
        let out = parse(
            r#"{"tag":"hit","status_code":200,"response_body":"x","created_at":null,"ttl_seconds":60}"#,
        );
        match out {
            BeginOutcome::Hit(rec) => assert!(rec.content_type.is_none()),
            other => panic!("expected Hit, got {other:?}"),
        }
    }

    #[test]
    fn begin_payload_hit_tolerates_null_body_and_negative_ttl() {
        // response_body may be JSON null (a cached 204-style empty body); a
        // negative TTL (key already expiring) must clamp to a non-negative
        // window rather than producing an expires_at in the past via overflow.
        let out = parse(
            r#"{"tag":"hit","status_code":204,"response_body":null,"created_at":null,"ttl_seconds":-1}"#,
        );
        match out {
            BeginOutcome::Hit(rec) => {
                assert_eq!(rec.status_code, 204);
                assert!(rec.response_body.is_none());
                assert!(rec.expires_at >= rec.created_at);
            }
            other => panic!("expected Hit, got {other:?}"),
        }
    }

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

#[cfg(test)]
mod middleware_tests {
    //! Pins the two safety-critical paths that DON'T need a live Redis: the
    //! opt-in passthrough (no header → handler runs, Redis never touched) and
    //! malformed-key rejection (400 before any Redis call). The begin/complete
    //! cache-hit/replay paths need Redis and are covered by manual/integration
    //! testing.
    use super::*;
    use axum::{
        body::Body,
        extract::Extension,
        http::{Request, StatusCode},
        middleware::from_fn,
        routing::post,
        Router,
    };
    use tower::ServiceExt;

    async fn ok_handler() -> &'static str {
        "handled"
    }

    /// A service whose Redis client points at a closed port — constructing it
    /// is lazy (no connection), and the tested paths must never reach Redis, so
    /// any accidental connection attempt would surface as a test failure/hang.
    fn never_connect_service() -> Option<Arc<IdempotencyService>> {
        let client = redis::Client::open("redis://127.0.0.1:1/").unwrap();
        Some(Arc::new(IdempotencyService::new(
            Arc::new(client),
            Duration::from_secs(60),
        )))
    }

    fn app(service: Option<Arc<IdempotencyService>>) -> Router {
        Router::new()
            .route("/", post(ok_handler))
            .layer(from_fn(idempotency_middleware))
            .layer(Extension(service))
    }

    #[tokio::test]
    async fn no_header_passes_through_untouched() {
        let resp = app(never_connect_service())
            .oneshot(Request::post("/").body(Body::from("payload")).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(IDEMPOTENT_REPLAYED_HEADER).is_none());
    }

    #[tokio::test]
    async fn upgrade_request_passes_through_even_with_key() {
        // A protocol upgrade (WebSocket) carrying an Idempotency-Key must NOT be
        // intercepted — the middleware would otherwise break the handshake. The
        // guard runs before any Redis touch, so the handler is reached.
        let resp = app(never_connect_service())
            .oneshot(
                Request::post("/")
                    .header(IDEMPOTENCY_KEY_HEADER, "valid-key-123")
                    .header(axum::http::header::UPGRADE, "websocket")
                    .body(Body::from("payload"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get(IDEMPOTENT_REPLAYED_HEADER).is_none());
    }

    #[tokio::test]
    async fn malformed_key_rejected_before_redis() {
        let resp = app(never_connect_service())
            .oneshot(
                Request::post("/")
                    .header(IDEMPOTENCY_KEY_HEADER, "bad key with spaces")
                    .body(Body::from("payload"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn no_service_configured_passes_through() {
        // Redis unconfigured (None) + a valid key → must NOT block the request.
        let resp = app(None)
            .oneshot(
                Request::post("/")
                    .header(IDEMPOTENCY_KEY_HEADER, "valid-key-123")
                    .body(Body::from("payload"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}

#[cfg(test)]
mod in_memory_dedup_tests {
    use super::{DedupCheck, DedupResponse, InMemoryIdempotencyStore};
    use std::time::Duration;

    fn resp(status: u16) -> DedupResponse {
        DedupResponse {
            status,
            headers: vec![("content-type".to_string(), "application/json".to_string())],
            body: b"{\"ok\":true}".to_vec(),
        }
    }

    #[test]
    fn miss_then_complete_then_hit_short_circuits() {
        let store = InMemoryIdempotencyStore::new(Duration::from_secs(60), 100);
        // First check: no record → Proceed.
        assert!(matches!(store.check("k1"), DedupCheck::Proceed));
        // Record a success.
        store.complete("k1", resp(200));
        // Second check: same key → Completed with the cached response.
        match store.check("k1") {
            DedupCheck::Completed(r) => {
                assert_eq!(r.status, 200);
                assert_eq!(r.body, b"{\"ok\":true}");
            }
            DedupCheck::Proceed => panic!("expected a completed short-circuit"),
        }
    }

    #[test]
    fn distinct_keys_are_independent() {
        let store = InMemoryIdempotencyStore::new(Duration::from_secs(60), 100);
        store.complete("a", resp(200));
        assert!(matches!(store.check("a"), DedupCheck::Completed(_)));
        // A DIFFERENT key (the non-declaring / different-send case) is
        // unaffected — no dedup, must Proceed.
        assert!(matches!(store.check("b"), DedupCheck::Proceed));
    }

    #[test]
    fn expired_record_is_a_miss() {
        // Zero TTL → any stored record is immediately stale.
        let store = InMemoryIdempotencyStore::new(Duration::from_millis(0), 100);
        store.complete("k", resp(200));
        // `now - stored_at < 0ms` is false → treated as a miss.
        assert!(matches!(store.check("k"), DedupCheck::Proceed));
    }

    #[test]
    fn entry_cap_is_bounded() {
        let store = InMemoryIdempotencyStore::new(Duration::from_secs(600), 4);
        for i in 0..50 {
            store.complete(&format!("k{i}"), resp(200));
        }
        assert!(
            store.len() <= 4,
            "store must stay within its hard entry cap (was {})",
            store.len()
        );
    }
}
