use axum::{
    extract::{ConnectInfo, State},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::{Arc, LazyLock, OnceLock};
use std::time::Instant;
use uuid::Uuid;

/// The canonical set of recognized MCP agent capability strings.
/// Any capability in `allowed_capabilities` not in this set will be logged as a warning.
///
/// MCP-1203 (2026-05-17): `secrets:write` was removed alongside the MCP
/// secret-write handlers (MCP-1201). The string survives in the
/// API-key scope vocabulary (`ApiKeyScope::SecretsWrite` in
/// talos-auth-types — gates GraphQL secret mutations) but the
/// MCP-agent vocabulary no longer recognises it. Migration
/// `20260517220000_drop_secrets_write_mcp_capability.sql` strips the
/// string from `agent_roles.allowed_capabilities` rows and the
/// table-level CHECK constraint.
const KNOWN_CAPABILITIES: &[&str] = &[
    "*",
    "admin",
    "minimal",
    "minimal-node",
    "automation",
    "automation-node",
    "network",
    "network-node",
    "secrets",
    "secrets-node",
    "filesystem",
    "filesystem-node",
    "messaging",
    "messaging-node",
    "database",
    "database-node",
    "cache",
    "cache-node",
    "governance",
    "governance-node",
    "agent",
    "agent-node",
    "http",
    "http-node",
    "llm-inference",
    "llm-inference-node",
    "trusted",
    "trusted-node",
];

#[derive(Clone, Debug)]
pub struct AgentIdentity {
    pub agent_id: Uuid,
    pub name: String,
    pub role_name: String,
    pub allowed_capabilities: Vec<String>,
    /// Optional user ID for scoping agent operations to a specific user.
    pub user_id: Option<Uuid>,
}

impl AgentIdentity {
    /// Returns true if the agent has admin or wildcard ("*") capability.
    /// This is the canonical way to check for admin — never string-compare inline.
    #[inline]
    pub fn is_admin(&self) -> bool {
        self.allowed_capabilities
            .iter()
            .any(|c| c == "*" || c == "admin")
    }

    /// Returns true if the agent has the given capability or admin/wildcard.
    #[inline]
    pub fn has_capability(&self, cap: &str) -> bool {
        self.is_admin() || self.allowed_capabilities.iter().any(|c| c == cap)
    }

    /// Validate capability strings and log warnings for unknown ones.
    /// Called at auth time so every request from a misconfigured agent is flagged.
    fn warn_unknown_capabilities(&self) {
        for cap in &self.allowed_capabilities {
            if !KNOWN_CAPABILITIES.contains(&cap.as_str()) {
                tracing::warn!(
                    agent_id = %self.agent_id,
                    agent_name = %self.name,
                    role = %self.role_name,
                    capability = cap.as_str(),
                    "Agent has unrecognized capability string — possible typo or misconfiguration. \
                     Known capabilities: {}",
                    KNOWN_CAPABILITIES.join(", ")
                );
            }
        }
    }
}

/// Per-IP rate-limit state for MCP auth.
struct McpAuthRateState {
    count: u32,
    window_start: Instant,
}

/// Maximum MCP auth requests per window per IP.
/// Configurable via MCP_AUTH_RATE_LIMIT env var (default: 60).
///
/// MCP-664 (2026-05-13): route through `positive_env_or_default` so
/// `MCP_AUTH_RATE_LIMIT=0` doesn't make the auth endpoint reject
/// every request (the comparison `entry.count > 0` fires on the
/// first request since `count` is incremented to 1 before the
/// check). Sibling fix to MCP-661 / MCP-663 — same `=0` footgun
/// class across rate-limit envs.
fn mcp_auth_max_requests() -> u32 {
    static CACHED: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| talos_config::positive_env_or_default("MCP_AUTH_RATE_LIMIT", 60u32))
}

/// Window duration for MCP auth rate limiting in seconds.
/// Configurable via MCP_AUTH_RATE_WINDOW env var (default: 60).
///
/// MCP-664: `MCP_AUTH_RATE_WINDOW=0` would silently DISABLE rate
/// limiting — every request's `now.duration_since(window_start)
/// >= 0` evaluates true, resetting the window with count=1 on every
/// call regardless of historical rate. Brute-force attackers could
/// hammer the auth endpoint with no throttling. Sibling failure
/// mode to the max_requests=0 case above; same fix shape.
fn mcp_auth_window_secs() -> u64 {
    static CACHED: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CACHED.get_or_init(|| talos_config::positive_env_or_default("MCP_AUTH_RATE_WINDOW", 60u64))
}

/// Global rate limiter for MCP auth (IP -> state).
static MCP_AUTH_RATE_LIMITER: OnceLock<DashMap<String, McpAuthRateState>> = OnceLock::new();

/// MCP-1146 (2026-05-16): defense-in-depth max-entries cap.
///
/// Pre-fix the rate limiter had a periodic cleanup at len > 1000 that
/// removed entries older than `2 * window`. In the pathological case
/// where 1000+ entries are ALL recent (within the cleanup window —
/// e.g., a botnet with 100K distinct source IPs hitting /mcp at a
/// sustained rate inside the same 60s window), the retain runs but
/// removes nothing, and the cache continues to grow. At ~80
/// bytes/entry, 1M entries = ~80 MB of attacker-influenced heap;
/// pathological cases of fake-X-Forwarded-For floods could push much
/// higher.
///
/// Sibling audit class to MCP-1093/1132/1137/1145: every TTL-bounded
/// in-memory cache needs read-path eviction, periodic sweep, AND a
/// max-entries cap. The CSRF grace cache (MCP-1145) and signed-RPC
/// nonce cache use the same 50_000 boundary; aligning here keeps the
/// operator mental model uniform.
///
/// Real deployments don't approach this — a single tenant's MCP
/// clients route through 1-10 IPs; multi-tenant deployments through
/// 100-1000. 50_000 is the DoS-defense boundary, not a normal-load
/// bound. Operators who see the structured WARN
/// `event_kind = "mcp_auth_rate_limiter_cap_hit"` should investigate
/// for spoofed-IP flood before raising the cap.
const MCP_AUTH_RATE_LIMITER_MAX_ENTRIES: usize = 50_000;

/// Maximum age of a cached bcrypt verification result before re-verification is required.
///
/// MCP-660 (2026-05-13): lowered from 60s to 10s. The cache bounds the
/// time window between `revoke_mcp_agent` (DELETE FROM mcp_agents…) and
/// observable token invalidation — without proactive cache invalidation
/// on revoke, a revoked token survives in this cache until the entry
/// expires. 60s was tolerable but generous for the threat model where
/// the user has detected a compromised token and explicitly revoked it.
/// 10s is a 6× improvement to the revocation grace.
///
/// CPU cost trade-off: a chatty client (10 req/s with the same token)
/// previously triggered ~1 bcrypt verify per minute; now ~6/min. bcrypt
/// at the default cost runs in ~100 ms inside `spawn_blocking`, so the
/// budget is ~0.6 CPU-sec/min/user — well inside normal load.
///
/// Future work: extract the cache to a shared crate and wire the
/// revoke handlers (`revoke_mcp_agent` in GraphQL + the MCP equivalent)
/// to call `BCRYPT_VERIFY_CACHE.remove(&token_lookup_hash)` directly,
/// closing the grace window entirely. Blocked today by the crate-
/// dependency direction: talos-api MUST NOT depend on talos-mcp-handlers.
const BCRYPT_CACHE_TTL_SECS: u64 = 10;
/// Maximum number of entries in the bcrypt verification cache before eviction runs.
const BCRYPT_CACHE_MAX_ENTRIES: usize = 1_000;

/// Background sweep interval for the bcrypt verification cache revocation
/// poller. MCP-991 (2026-05-15) — closes the residual revocation gap that
/// the per-entry TTL can't reach: when an agent is revoked via the GraphQL
/// `revoke_mcp_agent` mutation (`DELETE FROM mcp_agents …` in talos-api),
/// existing cache entries keyed on `token_lookup_hash` remain valid until
/// their TTL expires (up to BCRYPT_CACHE_TTL_SECS = 10 s). Cross-crate
/// proactive invalidation is "Future work" (see the `BCRYPT_CACHE_TTL_SECS`
/// comment) — the dep-direction rule blocks talos-api from calling into
/// talos-mcp-handlers. The sweep is the contained alternative: a single
/// background task here batches a `SELECT id FROM mcp_agents WHERE id =
/// ANY($1) AND is_active = true` against ALL cached agent_ids every
/// `SWEEP_INTERVAL_SECS` and evicts entries whose agents are no longer
/// active. Worst-case revocation window drops from 10 s (TTL only) to
/// 3 s. Single batched query so cost is one DB roundtrip per sweep,
/// independent of cache size.
const BCRYPT_CACHE_SWEEP_INTERVAL_SECS: u64 = 3;

/// Spawn the bcrypt cache revocation sweep task. Call once at controller
/// startup. Runs until `shutdown_rx` flips; logs failures via
/// `tracing::warn!` and continues on transient errors — a Postgres
/// blip is preferable to taking the auth path offline.
///
/// MCP-994 (2026-05-15): added `shutdown_rx` for graceful termination,
/// matching the sibling `LLM_KEYS_SWEEP` task pattern in
/// `controller/src/main.rs`. Pre-fix this loop ran forever and got
/// force-aborted on process shutdown (no clean drain, no shutdown
/// log line). The MCP-991 sweep emits structured audit-trail events
/// so a clean shutdown log helps operators correlate cache state
/// across restart boundaries.
pub fn spawn_bcrypt_cache_revocation_sweep(
    db_pool: PgPool,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    tokio::spawn(async move {
        let mut shutdown = shutdown_rx;
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(
            BCRYPT_CACHE_SWEEP_INTERVAL_SECS,
        ));
        // Skip the immediate tick — the cache is empty at startup.
        interval.tick().await;
        tracing::info!(
            target: "talos_audit",
            sweep_interval_secs = BCRYPT_CACHE_SWEEP_INTERVAL_SECS,
            "MCP-991: bcrypt cache revocation sweep started"
        );
        loop {
            tokio::select! {
                _ = interval.tick() => {
                    // MCP-1132 (2026-05-16): TTL-expired eviction.
                    // Sibling pattern to MCP-1093 (DEK cache sweep).
                    // Pre-fix the MCP-991 revocation sweep only evicted
                    // entries whose agents had been DB-deactivated; it
                    // ignored entries whose timestamp was older than
                    // `BCRYPT_CACHE_TTL_SECS`. Those entries are
                    // harmless on the hit path (the TTL check at the
                    // call site falls through to re-verification) but
                    // consume memory monotonically with every distinct
                    // token seen since startup — one-shot test agents,
                    // rotated tokens, and short-lived OAuth-derived
                    // agents all leave residue. The only existing
                    // expired-eviction path was the
                    // `BCRYPT_CACHE_MAX_ENTRIES = 1000` overflow
                    // `retain` at the insert site, which fires only
                    // under cache pressure.
                    //
                    // Run expired-eviction BEFORE the revocation query
                    // so the agent_ids slice we send to Postgres is
                    // already minus the expired set — smaller batch,
                    // less DB-side work.
                    let evict_now = Instant::now();
                    let before_expired_evict = BCRYPT_VERIFY_CACHE.len();
                    BCRYPT_VERIFY_CACHE.retain(|_, (cached_at, _)| {
                        evict_now.duration_since(*cached_at).as_secs() < BCRYPT_CACHE_TTL_SECS
                    });
                    let evicted_expired = before_expired_evict.saturating_sub(BCRYPT_VERIFY_CACHE.len());
                    if evicted_expired > 0 {
                        tracing::debug!(
                            target: "talos_audit",
                            evicted_expired,
                            cached_after = BCRYPT_VERIFY_CACHE.len(),
                            "MCP-1132: bcrypt cache sweep evicted TTL-expired entries"
                        );
                    }

                    let cached: Vec<(String, Uuid)> = BCRYPT_VERIFY_CACHE
                        .iter()
                        .map(|kv| (kv.key().clone(), kv.value().1.agent_id))
                        .collect();
                    if cached.is_empty() {
                        continue;
                    }
                    let agent_ids: Vec<Uuid> = cached.iter().map(|(_, id)| *id).collect();

                    // Route through the canonical repository helper —
                    // keeps raw SQL out of talos-mcp-handlers per the
                    // architectural mandate (lint check 6).
                    let sysrepo = talos_system_repo::SystemRepository::new(db_pool.clone());
                    let active: Vec<Uuid> = match sysrepo.list_active_agent_ids(&agent_ids).await {
                        Ok(rows) => rows,
                        Err(e) => {
                            tracing::warn!(
                                target: "talos_audit",
                                error = %e,
                                "bcrypt cache sweep: batch query failed — keeping existing cache (revocation visibility deferred to next tick)"
                            );
                            continue;
                        }
                    };
                    let active_set: std::collections::HashSet<Uuid> = active.into_iter().collect();

                    let mut evicted = 0usize;
                    for (token_hash, agent_id) in cached {
                        if !active_set.contains(&agent_id) {
                            BCRYPT_VERIFY_CACHE.remove(&token_hash);
                            evicted += 1;
                            tracing::info!(
                                target: "talos_audit",
                                %agent_id,
                                "bcrypt cache: evicted revoked agent"
                            );
                        }
                    }
                    if evicted > 0 {
                        tracing::info!(
                            target: "talos_audit",
                            evicted,
                            cached_after = BCRYPT_VERIFY_CACHE.len(),
                            "MCP-991: bcrypt cache sweep evicted revoked agents"
                        );
                    }
                }
                _ = shutdown.changed() => {
                    if *shutdown.borrow() {
                        tracing::info!(
                            target: "talos_audit",
                            "bcrypt cache revocation sweep received shutdown signal"
                        );
                        break;
                    }
                }
            }
        }
    });
}

/// In-memory cache of recent bcrypt verification results.
/// Key: `token_lookup_hash` — SHA-256 of the FULL token (hex-encoded).
/// Value: (timestamp of verification, verified AgentIdentity).
///
/// MCP-715 (2026-05-13): the previous comment said "SHA-256 of first 8 chars",
/// which is doc-drift — the actual computation at line ~242 is
/// `Sha256::digest(token.as_bytes())` over the WHOLE token, matching the
/// `mcp_agents.token_lookup_hash` column (created via
/// `talos-api/src/schema/actors/mutations.rs::register_mcp_agent` with the
/// same full-token SHA-256) and `talos-auth::generate_token_lookup_hash`.
/// A future contributor reading the stale doc and "fixing" the code to match
/// would weaken the cache key to a 32-bit (8-hex-char) prefix, dropping
/// the collision-resistance from ~2^128 to ~2^16 by birthday paradox. Doc-
/// drift is a latent footgun — keep the doc and the code in lockstep.
///
/// This avoids repeated expensive bcrypt CPU work for the same token within a
/// short window. Security note: the bcrypt verification still runs on first use;
/// the cache only skips re-verification for up to BCRYPT_CACHE_TTL_SECS seconds.
static BCRYPT_VERIFY_CACHE: LazyLock<DashMap<String, (Instant, AgentIdentity)>> =
    LazyLock::new(DashMap::new);

/// Check IP-based rate limit for MCP auth. Returns `Err(())` if rate limit exceeded.
fn check_mcp_auth_rate_limit(ip: &str) -> Result<(), ()> {
    let limiter = MCP_AUTH_RATE_LIMITER.get_or_init(DashMap::new);
    let now = Instant::now();

    // Periodic cleanup: remove expired entries when map grows large
    if limiter.len() > 1_000 {
        limiter.retain(|_, state| {
            now.duration_since(state.window_start).as_secs() < mcp_auth_window_secs() * 2
        });
    }

    // MCP-1146 (2026-05-16): fail-closed at the defense-in-depth cap.
    // The cleanup above only removes entries older than 2 * window —
    // when 50_000+ entries are ALL recent (spoofed-IP flood inside one
    // window), the retain is a no-op. Rather than let the cache grow
    // unbounded, refuse NEW IPs at the cap so the attacker doesn't
    // amplify their attack into heap exhaustion. Existing tracked IPs
    // continue to be rate-limited normally (the `entry()` path below
    // touches existing keys, not new ones). This is the same fail-
    // closed posture as the canonical nonce-cache cap-hit handling in
    // talos-memory and the MCP-1145 CSRF grace cache.
    //
    // `contains_key(ip)` is a cheap O(1) DashMap lookup; we only block
    // when the cap is reached AND the request is for an IP we haven't
    // seen recently. The check is intentionally outside the `entry()`
    // path so existing IPs (already being rate-limited) keep flowing
    // through their normal accounting.
    if limiter.len() >= MCP_AUTH_RATE_LIMITER_MAX_ENTRIES && !limiter.contains_key(ip) {
        tracing::warn!(
            target: "talos_audit",
            event_kind = "mcp_auth_rate_limiter_cap_hit",
            size = limiter.len(),
            cap = MCP_AUTH_RATE_LIMITER_MAX_ENTRIES,
            ip = %ip,
            "MCP auth rate-limiter at capacity; refusing new IP (investigate for spoofed-IP flood)"
        );
        return Err(());
    }

    let mut entry = limiter
        .entry(ip.to_string())
        .or_insert_with(|| McpAuthRateState {
            count: 0,
            window_start: now,
        });

    if now.duration_since(entry.window_start).as_secs() >= mcp_auth_window_secs() {
        // Reset the window
        entry.count = 1;
        entry.window_start = now;
        Ok(())
    } else {
        entry.count += 1;
        if entry.count > mcp_auth_max_requests() {
            Err(())
        } else {
            Ok(())
        }
    }
}

pub async fn mcp_auth_middleware(
    State(db_pool): State<PgPool>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    mut req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // MCP-1097 (2026-05-16): rate-limit bucket key must reflect the
    // REAL client IP, not the direct peer (the reverse proxy in any
    // production deployment with a load balancer / ingress). Pre-fix
    // `addr.ip().to_string()` collapsed every MCP agent into the
    // proxy's single IP bucket — the 60-req/min default became a
    // GLOBAL cap shared across all MCP traffic. A chatty client
    // exhausted the bucket and every other agent got 429. Sibling
    // pattern to `talos_rate_limit::extract_client_ip` which the main
    // app rate-limiter already uses correctly (RFC 7239 right-to-left
    // XFF walk skipping trusted-proxy entries). `mcp_router` is
    // merged AFTER the outer rate-limit layers so the existing
    // `Extension<Arc<TrustedProxies>>` doesn't propagate; build a
    // process-local handle from `TRUSTED_PROXY_CIDRS` once via
    // LazyLock so each request pays only a hashmap lookup.
    static TRUSTED_PROXIES: std::sync::LazyLock<talos_rate_limit::TrustedProxies> =
        std::sync::LazyLock::new(talos_rate_limit::TrustedProxies::from_env);
    let ip = talos_rate_limit::extract_client_ip(addr.ip(), req.headers(), &TRUSTED_PROXIES)
        .to_string();
    if check_mcp_auth_rate_limit(&ip).is_err() {
        tracing::warn!(ip = %ip, "MCP auth rate limit exceeded");
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    // 1. Extract Bearer Token from multiple sources:
    //    a) Authorization: Bearer <token> header (standard)
    //    b) ?token=<token> query parameter (for clients that can't set headers)
    let auth_header = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .filter(|s| s.starts_with("Bearer "))
        .map(|s| s[7..].trim().to_string());

    // Query-param token: supported for clients that cannot set HTTP headers
    // (e.g. SSE clients, browser EventSource).  The token value is extracted
    // here and NEVER written to any log — the raw URI (which would contain the
    // plaintext token) must not appear in access logs or tracing spans.
    let query_token = req.uri().query().and_then(|q| {
        q.split('&').find_map(|pair| {
            let mut parts = pair.splitn(2, '=');
            match (parts.next(), parts.next()) {
                (Some("token"), Some(v)) => Some(v.to_string()),
                _ => None,
            }
        })
    });

    let token = match auth_header.or(query_token) {
        Some(t) => t,
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // 2. Compute SHA-256 lookup hash for efficient DB query
    let token_lookup_hash = format!("{:x}", Sha256::digest(token.as_bytes()));

    // 2b. Check bcrypt verification cache — avoids expensive CPU work on repeat requests
    let now = Instant::now();
    if let Some(entry) = BCRYPT_VERIFY_CACHE.get(&token_lookup_hash) {
        let (cached_at, ref cached_identity) = *entry;
        if now.duration_since(cached_at).as_secs() < BCRYPT_CACHE_TTL_SECS {
            let agent = cached_identity.clone();
            drop(entry); // release DashMap read lock before proceeding
            tracing::trace!(agent_id = %agent.agent_id, "bcrypt verification cache hit");

            // MCP-716 (2026-05-13): skip `touch_agent_last_connected` on
            // cache hit. The uncached path below (line ~366) fires the
            // touch unconditionally when it inserts the cache entry, so
            // a cache hit means `last_connected_at` was updated less
            // than BCRYPT_CACHE_TTL_SECS (10 s) ago — re-updating on
            // every cached request added zero information but cost one
            // DB UPDATE per request. For a chatty MCP agent (e.g. 100
            // req/s) that's 100 redundant UPDATEs/s against the
            // `mcp_agents` row — at 1000 active agents the prior
            // implementation generated ~100k pointless UPDATEs/s of DB
            // pool pressure. `last_connected_at` UX granularity remains
            // bounded by the cache TTL (10 s freshness for "currently
            // online" displays), which is well within product
            // expectations and matches the equivalent JWT
            // `last_seen_at` patterns elsewhere in the codebase.

            req.extensions_mut().insert(Arc::new(agent));
            return Ok(next.run(req).await);
        }
    }

    // 3. Look up Agent in Database using the lookup hash
    //
    // MCP-873 (2026-05-14): log the underlying error before collapsing
    // to 500. Pre-fix a DB outage / connection pool exhaustion /
    // query timeout during MCP auth looked identical on the operator
    // side to an unspecified internal error — and silent auth-path
    // 500s are particularly painful to root-cause because the user-
    // facing surface is just "your tool call returned an error".
    let sysrepo = talos_system_repo::SystemRepository::new(db_pool.clone());
    let record = sysrepo
        .find_active_agent_by_token_lookup_hash(&token_lookup_hash)
        .await
        .map_err(|e| {
            tracing::error!(
                error = %e,
                "mcp_auth: agent lookup by token_lookup_hash failed"
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let agent = match record {
        Some(r) => {
            // 4. Verify bcrypt hash for security (lookup hash only narrows the search)
            let token_clone = token.clone();
            let bcrypt_hash = r.token_hash.clone();
            // MCP-873 (2026-05-14): log both failure paths distinctly.
            // JoinError → spawn_blocking thread panicked, real
            // operator-actionable failure (likely OOM or runtime bug).
            // bcrypt::verify Err → either invalid stored hash format
            // (DB corruption) or a malformed bcrypt input — also
            // operator-actionable. Pre-fix both collapsed to 500/401
            // with no telemetry.
            let is_valid =
                tokio::task::spawn_blocking(move || bcrypt::verify(&token_clone, &bcrypt_hash))
                    .await
                    .map_err(|e| {
                        tracing::error!(
                            error = %e,
                            "mcp_auth: bcrypt spawn_blocking JoinError"
                        );
                        StatusCode::INTERNAL_SERVER_ERROR
                    })?
                    .map_err(|e| {
                        tracing::error!(
                            error = %e,
                            "mcp_auth: bcrypt::verify failed (possibly malformed stored hash)"
                        );
                        StatusCode::UNAUTHORIZED
                    })?;

            if !is_valid {
                return Err(StatusCode::UNAUTHORIZED);
            }

            {
                let identity = AgentIdentity {
                    agent_id: r.id,
                    name: r.name,
                    role_name: r.role_name,
                    allowed_capabilities: r.allowed_capabilities,
                    user_id: r.user_id,
                };
                // Validate capabilities at auth time — unknown strings are logged as
                // warnings so operators catch typos before they cause silent access denials.
                identity.warn_unknown_capabilities();

                // Cache the verified identity to avoid repeated bcrypt work.
                //
                // MCP-1177 (2026-05-17): fail-CLOSED at cap. Pre-fix sequence
                // was `if len > MAX: retain non-expired; insert`. Under a
                // burst where all entries are fresh (< BCRYPT_CACHE_TTL_SECS
                // = 10 s), `retain` evicts zero entries and the unconditional
                // insert grows the cache beyond cap by 1 per call. Under
                // sustained burst, the cache can grow to N × (request rate ×
                // TTL window) entries — N=1 per insert, 10s window, 1000
                // req/s = 10_000 entries (10x the configured cap), each
                // holding an `AgentIdentity` with allowed_capabilities and
                // role_name strings. Sibling fail-CLOSED-at-cap pattern as
                // MCP-1145 (TOKEN_GRACE_CACHE), MCP-1146 (MCP_AUTH_RATE_LIMITER),
                // MCP-1147 (REFRESH_RATE_LIMITER). The cost of refusing to
                // cache when at cap is one extra bcrypt verify per
                // already-known-token request — bounded and operator-
                // recognisable (caches are perf optimisations; auth is
                // already correct without them).
                let already_cached = BCRYPT_VERIFY_CACHE.contains_key(&token_lookup_hash);
                let mut should_insert = true;
                if BCRYPT_VERIFY_CACHE.len() >= BCRYPT_CACHE_MAX_ENTRIES {
                    let evict_now = Instant::now();
                    BCRYPT_VERIFY_CACHE.retain(|_, (cached_at, _)| {
                        evict_now.duration_since(*cached_at).as_secs() < BCRYPT_CACHE_TTL_SECS
                    });
                    // After expired-eviction, if STILL at cap and this
                    // token isn't already cached, refuse the new insert.
                    // Auth succeeds; the next request from this token
                    // re-verifies via bcrypt (~50-100 ms cost) rather than
                    // the ~µs cache hit. Loud event so operators can
                    // correlate auth-rate spikes with cache pressure.
                    if !already_cached && BCRYPT_VERIFY_CACHE.len() >= BCRYPT_CACHE_MAX_ENTRIES {
                        tracing::warn!(
                            target: "talos_audit",
                            event_kind = "bcrypt_cache_at_cap",
                            cap = BCRYPT_CACHE_MAX_ENTRIES,
                            "BCRYPT_VERIFY_CACHE at cap after expired-eviction; \
                             skipping insert for this token (next request from this \
                             token will re-verify via bcrypt)"
                        );
                        should_insert = false;
                    }
                }
                if should_insert {
                    BCRYPT_VERIFY_CACHE.insert(
                        token_lookup_hash.clone(),
                        (Instant::now(), identity.clone()),
                    );
                }

                identity
            }
        }
        None => return Err(StatusCode::UNAUTHORIZED),
    };

    // 4b. Lazy user-row upsert — ensures FK-constrained writes succeed.
    //
    // On fresh deployments the mcp_agents.user_id UUID may not yet have a
    // corresponding row in the `users` table (e.g. when the identity was issued
    // by an external OAuth/SSO provider before the local DB row was written).
    // We insert a minimal stub with ON CONFLICT (id) DO NOTHING so existing
    // users are never touched, and the insert is a near-zero-cost PK lookup on
    // every subsequent request.
    //
    // This MUST be awaited (not spawned) so the row exists before the handler
    // attempts any FK-constrained INSERT.
    if let Some(uid) = agent.user_id {
        // Build a deterministic, globally-unique synthetic email.
        // Using the full UUID guarantees no collision with other MCP users.
        let synthetic_email = format!("mcp-{}@system.internal", uid);
        if let Err(e) = sysrepo
            .ensure_user_row_for_agent(uid, &synthetic_email)
            .await
        {
            // Warn but don't abort — the FK violation will surface in the handler
            // with a clear error message thanks to the mcp_error() fix.
            tracing::warn!(
                user_id = %uid,
                "mcp_auth: failed to ensure user row for FK-constrained writes: {:#}",
                e
            );
        }
    }

    // Update last connected async (fire and forget)
    let pool_clone = db_pool.clone();
    let agent_id = agent.agent_id;
    tokio::spawn(async move {
        let sysrepo = talos_system_repo::SystemRepository::new(pool_clone);
        if let Err(db_err) = sysrepo.touch_agent_last_connected(agent_id).await {
            tracing::error!("Database operation failed: {}", db_err);
        }
    });

    // 5. Inject AgentIdentity into Request extensions
    req.extensions_mut().insert(Arc::new(agent));

    Ok(next.run(req).await)
}

/// MCP-1146 (2026-05-16): tests for the rate-limiter max-entries cap.
#[cfg(test)]
mod mcp_auth_rate_limiter_cap_tests {
    use super::*;

    /// Process-global limiter — serialise tests that touch it so
    /// parallel runs don't race each other's `clear()` and pre-fill
    /// assertions. Same pattern as the GRACE_TEST_LOCK in talos-csrf
    /// (MCP-1145) and NONCE_TEST_LOCK in talos-memory.
    static LIMITER_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn limiter_test_lock() -> std::sync::MutexGuard<'static, ()> {
        LIMITER_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// At cap, NEW IPs are rejected; existing tracked IPs still flow
    /// through their normal rate-limit accounting (the cap doesn't
    /// punish IPs already under quota tracking).
    #[test]
    fn new_ip_rejected_at_cap_existing_ip_continues() {
        let _g = limiter_test_lock();
        let limiter = MCP_AUTH_RATE_LIMITER.get_or_init(DashMap::new);
        limiter.clear();

        // Wedge to exactly the cap. Sentinel keys so we don't depend
        // on real IP shapes.
        let now = Instant::now();
        for i in 0..MCP_AUTH_RATE_LIMITER_MAX_ENTRIES {
            limiter.insert(
                format!("wedge-{}", i),
                McpAuthRateState {
                    count: 1,
                    window_start: now,
                },
            );
        }
        assert_eq!(limiter.len(), MCP_AUTH_RATE_LIMITER_MAX_ENTRIES);

        // NEW IP at-cap: rejected.
        assert!(
            check_mcp_auth_rate_limit("203.0.113.42").is_err(),
            "new IP must be rejected when rate limiter at cap"
        );
        // Cache didn't grow — the gated path returned without inserting.
        assert_eq!(limiter.len(), MCP_AUTH_RATE_LIMITER_MAX_ENTRIES);

        // EXISTING IP at-cap: still flows through accounting (this
        // request is the 2nd, well under the 60-req default cap).
        assert!(
            check_mcp_auth_rate_limit("wedge-0").is_ok(),
            "existing IP must keep flowing through rate-limit accounting at cap"
        );
        // Still at cap (existing IP touched in-place, no new entry).
        assert_eq!(limiter.len(), MCP_AUTH_RATE_LIMITER_MAX_ENTRIES);

        limiter.clear();
    }

    /// Below cap, NEW IPs are admitted and tracked.
    #[test]
    fn new_ip_admitted_below_cap() {
        let _g = limiter_test_lock();
        let limiter = MCP_AUTH_RATE_LIMITER.get_or_init(DashMap::new);
        limiter.clear();

        let ip = "198.51.100.7";
        assert!(check_mcp_auth_rate_limit(ip).is_ok());
        assert!(limiter.contains_key(ip));

        limiter.clear();
    }
}
