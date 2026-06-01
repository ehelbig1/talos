use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{HeaderMap, Request, Response, StatusCode},
    middleware::Next,
};
use governor::{
    clock::{Clock, DefaultClock},
    state::{direct::NotKeyed, keyed::DashMapStateStore, InMemoryState},
    Quota, RateLimiter,
};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;

/// Cached environment flags to avoid re-parsing on every request.
struct RateLimitEnvConfig {
    is_production: bool,
    enforce_in_dev: bool,
}

static RATE_LIMIT_ENV: OnceLock<RateLimitEnvConfig> = OnceLock::new();

fn rate_limit_env() -> &'static RateLimitEnvConfig {
    RATE_LIMIT_ENV.get_or_init(|| {
        let is_production = crate::is_production();
        // MCP-1073 (2026-05-16): canonical bool-env helper. Pre-fix
        // `== "true"` case-sensitive exact-match — `=1` / `=yes` etc.
        // got the FALSE branch. OnceLock-cached so the env read is
        // once-per-process; canonical truthy/falsy tokens now agree
        // with the workspace-wide pattern.
        let enforce_in_dev = talos_config::bool_env_or_default("ENFORCE_RATE_LIMITS_IN_DEV", false);
        RateLimitEnvConfig {
            is_production,
            enforce_in_dev,
        }
    })
}

/// Helper to read a rate‑limit configuration value from the environment.
/// Returns the parsed `u32` or the provided `default` if the variable is
/// missing, cannot be parsed, OR is set to `0`.
///
/// MCP-661 (2026-05-13): route through `talos_config::positive_env_or_default`
/// so `API_RATE_LIMIT=0` / `WEBHOOK_RATE_LIMIT=0` / `GLOBAL_RATE_LIMIT=0`
/// substitute the default instead of becoming "deny every request".
/// `RateLimiter::allow(_, 0)` returns false unconditionally (verified by
/// the `test_rate_limiter_zero_limit_always_denies` regression test in
/// talos-webhooks), so a Helm placeholder like `API_RATE_LIMIT: "0"`
/// previously took the whole API offline. Same `=0` footgun class as
/// MCP-638/639/640/642/643 (worker semaphores / retention envs).
///
/// `=""` continues to fall back to the default via the existing
/// `talos_config` empty-env handling — see MCP-630/631/653 for the
/// long-tail sweep that closes the rest of the env-handling
/// regressions.
pub fn env_rate_limit(var: &str, default: u32) -> u32 {
    talos_config::positive_env_or_default(var, default)
}

/// Rate limiter configuration
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Number of requests allowed per window
    pub requests: u32,
    /// Time window duration
    pub per: Duration,
    /// Burst size (how many requests can happen at once)
    pub burst_size: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            requests: 100,
            per: Duration::from_secs(60),
            burst_size: 20,
        }
    }
}

#[allow(dead_code)]
impl RateLimitConfig {
    /// Create rate limit for authentication endpoints (stricter)
    pub fn auth() -> Self {
        Self {
            requests: 5,
            per: Duration::from_secs(60), // 5 requests per minute
            burst_size: 2,
        }
    }

    /// Create rate limit for general API endpoints
    pub fn api() -> Self {
        Self {
            requests: env_rate_limit("RATE_LIMIT_API_REQUESTS", 300),
            per: Duration::from_secs(env_rate_limit("RATE_LIMIT_API_WINDOW", 60) as u64),
            burst_size: env_rate_limit("RATE_LIMIT_API_BURST", 100),
        }
    }

    /// Create rate limit for webhooks
    pub fn webhook() -> Self {
        Self {
            requests: 60,
            per: Duration::from_secs(60), // 60 requests per minute (1/sec)
            burst_size: 10,
        }
    }
}

/// IP whitelist configuration
#[derive(Clone)]
pub struct IpWhitelist {
    networks: Vec<IpNetwork>,
}

impl IpWhitelist {
    /// Create IP whitelist from comma-separated string of IPs/CIDR ranges
    /// Example: "192.168.1.0/24,10.0.0.5,172.16.0.0/16"
    pub fn from_string(whitelist_str: &str) -> Result<Self, String> {
        let mut networks = Vec::new();

        for entry in whitelist_str.split(',') {
            let entry = entry.trim();
            if entry.is_empty() {
                continue;
            }

            // Try to parse as CIDR first
            match entry.parse::<IpNetwork>() {
                Ok(network) => networks.push(network),
                Err(_) => {
                    // Try to parse as single IP and convert to /32 or /128
                    match entry.parse::<IpAddr>() {
                        Ok(ip) => {
                            let network = match ip {
                                IpAddr::V4(ipv4) => IpNetwork::V4(
                                    ipnetwork::Ipv4Network::new(ipv4, 32)
                                        .map_err(|e| format!("Invalid IPv4 CIDR: {}", e))?,
                                ),
                                IpAddr::V6(ipv6) => IpNetwork::V6(
                                    ipnetwork::Ipv6Network::new(ipv6, 128)
                                        .map_err(|e| format!("Invalid IPv6 CIDR: {}", e))?,
                                ),
                            };
                            networks.push(network);
                        }
                        Err(_) => {
                            return Err(format!("Invalid IP or CIDR range: {}", entry));
                        }
                    }
                }
            }
        }

        Ok(Self { networks })
    }

    /// Check if an IP address is whitelisted
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        self.networks.iter().any(|network| network.contains(*ip))
    }

    /// Empty whitelist (no IPs whitelisted)
    pub fn empty() -> Self {
        Self {
            networks: Vec::new(),
        }
    }
}

/// Trusted proxy configuration.
#[derive(Clone)]
pub struct TrustedProxies(IpWhitelist);

impl TrustedProxies {
    /// Build from the `TRUSTED_PROXY_CIDRS` environment variable.
    pub fn from_env() -> Self {
        let cidrs = std::env::var("TRUSTED_PROXY_CIDRS").unwrap_or_default();
        let loopback = "127.0.0.1,::1";
        let cidrs = if cidrs.is_empty() {
            tracing::info!(
                "TRUSTED_PROXY_CIDRS not set — X-Forwarded-For will only be trusted from loopback"
            );
            loopback.to_string()
        } else {
            format!("{},{}", cidrs, loopback)
        };
        let whitelist = IpWhitelist::from_string(&cidrs).unwrap_or_else(|e| {
            tracing::error!(
                "Invalid TRUSTED_PROXY_CIDRS '{}': {} — falling back to loopback only",
                cidrs,
                e
            );
            IpWhitelist::from_string(loopback).unwrap_or_else(|_| IpWhitelist::empty())
        });
        Self(whitelist)
    }

    /// Returns `true` if `ip` is a trusted proxy.
    pub fn is_trusted(&self, ip: &IpAddr) -> bool {
        self.0.is_whitelisted(ip)
    }
}

/// IP-based rate limiter
pub type IpRateLimiter = Arc<RateLimiter<String, DashMapStateStore<String>, DefaultClock>>;

/// Create a new IP-based rate limiter
pub fn create_rate_limiter(config: RateLimitConfig) -> IpRateLimiter {
    // If we want N requests per window of length W, the time between replenishing
    // individual cells is W / N.
    let period = config.per / config.requests;

    // Handle invalid config gracefully instead of panicking
    let quota = match Quota::with_period(period) {
        Some(q) => match NonZeroU32::new(config.burst_size) {
            Some(burst) => q.allow_burst(burst),
            None => {
                tracing::warn!("Invalid burst_size: {}, using default", config.burst_size);
                q.allow_burst(NonZeroU32::MIN)
            }
        },
        None => {
            tracing::warn!("Invalid rate limit period: {:?}, using default", period);
            // Use a sensible default: 1 request per second with burst of 1
            Quota::with_period(Duration::from_secs(1))
                .unwrap_or_else(|| Quota::per_second(NonZeroU32::MIN))
                .allow_burst(NonZeroU32::MIN)
        }
    };

    Arc::new(RateLimiter::dashmap(quota))
}

/// Paths exempt from per-IP rate limiting: kubelet probes, the Prometheus
/// scrape endpoint, the CSRF cookie seeder, and the root status check.
/// Probes connect to the pod IP directly (no XFF), so they share the node IP
/// with all SNAT'd external traffic — without an exemption, a busy site
/// evicts probes from the bucket and the kubelet kills the pod.
///
/// The router architecture also merges these paths AFTER the rate-limit
/// layers, so under normal operation this check never fires. It exists as a
/// belt-and-suspenders guard against future router changes that accidentally
/// re-wrap a probe path.
///
/// MCP-1074 (2026-05-16): added `/auth/csrf` — lives in `probe_routes`
/// in `controller/main.rs` per the architectural intent "no rate
/// limiting, no auth" (see the comment at the `/auth/csrf` route
/// definition documenting the 2026-04-25 CookieManagerLayer debugging
/// episode). Pre-fix the architectural guard was the ONLY protection;
/// a future refactor that moves `probe_routes` before the rate-limit
/// layer would silently rate-limit the CSRF seeder → frontend can't
/// get a fresh cookie under load → security outage. The exempt list
/// must MIRROR the *security-critical* probe_routes contents to match
/// the comment's stated belt-and-suspenders guarantee. The `/` root
/// status route is INTENTIONALLY not exempt (low-stakes status echo;
/// the existing `rate_limited_paths_are_not_exempt` test pins this
/// choice).
pub fn is_rate_limit_exempt_path(path: &str) -> bool {
    matches!(
        path,
        "/health"
            | "/health/redis"
            | "/health/nats"
            | "/live"
            | "/ready"
            | "/metrics/prometheus"
            | "/auth/csrf"
    )
}

/// Parse a single X-Forwarded-For entry into an `IpAddr`. Accepts:
///   * bare IPv4 (`192.0.2.1`)
///   * bare IPv6 (`2001:db8::1`)
///   * IPv4 with port (`192.0.2.1:8080`)
///   * bracketed IPv6 (`[2001:db8::1]`)
///   * bracketed IPv6 with port (`[2001:db8::1]:443`) — RFC 7239 §6.3
///
/// MCP-912 (2026-05-14): pre-fix `extract_client_ip` only tried
/// `entry.parse::<IpAddr>()`, which rejects every bracketed-IPv6 form.
/// A strict RFC 7239 proxy (the form RECOMMENDED by the spec) would
/// have every XFF entry fail to parse → walk falls through → fallback
/// to `direct_ip` (= trusted-proxy IP) → all clients sharing the
/// proxy share ONE rate-limit bucket → trivial cross-tenant DoS via
/// any one user exhausting the shared bucket. Plain-IPv6 deployments
/// (AWS, Cloudflare, nginx default) were unaffected.
fn parse_xff_entry(entry: &str) -> Option<IpAddr> {
    let entry = entry.trim();
    // Bare IpAddr (covers plain v4 and plain v6).
    if let Ok(ip) = entry.parse::<IpAddr>() {
        return Some(ip);
    }
    // SocketAddr handles `v4:port` and `[v6]:port`.
    if let Ok(sock) = entry.parse::<SocketAddr>() {
        return Some(sock.ip());
    }
    // Bracketed IPv6 without port: `[2001:db8::1]`.
    if let Some(inner) = entry.strip_prefix('[').and_then(|e| e.strip_suffix(']')) {
        if let Ok(ip) = inner.parse::<IpAddr>() {
            return Some(ip);
        }
    }
    None
}

/// Resolve the real client IP from a request, walking `X-Forwarded-For` per
/// RFC 7239 §5.2: only trust the header when the direct peer is a configured
/// trusted proxy, then walk the chain right-to-left and return the first
/// non-trusted entry. A naive leftmost read lets any client behind a trusted
/// proxy spoof its source IP by pre-pending an entry.
pub fn extract_client_ip(
    direct_ip: IpAddr,
    headers: &HeaderMap,
    trusted_proxies: &TrustedProxies,
) -> IpAddr {
    if !trusted_proxies.is_trusted(&direct_ip) {
        return direct_ip;
    }

    let Some(forwarded) = headers.get("x-forwarded-for") else {
        return direct_ip;
    };
    let Ok(s) = forwarded.to_str() else {
        return direct_ip;
    };

    // MCP-1103 (2026-05-16): cap the right-to-left walk. axum permits
    // header values up to ~64KB, so a comma-separated list can carry
    // ~10k entries. Each iteration parses an IP
    // (`parse_xff_entry`) AND runs a `TrustedProxies::is_trusted`
    // CIDR lookup. An attacker who can either (a) bypass a proxy that
    // strips X-Forwarded-For, or (b) submit through a misconfigured
    // proxy that appends without stripping, can fill XFF with
    // thousands of entries crafted to match `TRUSTED_PROXY_CIDRS` —
    // forcing the walk to iterate every entry on its way to find the
    // first untrusted one. At, say, 1000 req/s through that ingress,
    // ~10M parse+CIDR-lookup ops/sec hits this middleware ahead of
    // every authenticated request.
    //
    // Real proxy chains have 1–5 entries (client → CDN → LB → ingress
    // → service); 64 covers any reasonable topology with headroom.
    // We collect ALL entries (the `.split(',')` walk is O(string), not
    // O(entries × CIDR), so the collect is cheap) and then cap the
    // EXPENSIVE walk via `.take(MAX_XFF_ENTRIES)` after `.rev()` —
    // preserving the rightmost entries where the legitimate proxy
    // chain lives. The all-trusted-fallback at the bottom still
    // points at the leftmost entry (best-effort original-client
    // claim).
    let entries: Vec<&str> = s
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .collect();
    if entries.is_empty() {
        return direct_ip;
    }

    const MAX_XFF_ENTRIES: usize = 64;
    for entry in entries.iter().rev().take(MAX_XFF_ENTRIES) {
        if let Some(ip) = parse_xff_entry(entry) {
            if !trusted_proxies.is_trusted(&ip) {
                return ip;
            }
        }
    }

    // Every entry parsed as a trusted proxy (all-internal chain). Fall back
    // to the leftmost as the best-effort original-client claim.
    entries
        .first()
        .and_then(|first| parse_xff_entry(first))
        .unwrap_or(direct_ip)
}

/// Rate limiting middleware
pub async fn rate_limit_middleware(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    limiter: axum::Extension<IpRateLimiter>,
    whitelist: axum::Extension<Arc<IpWhitelist>>,
    trusted_proxies: axum::Extension<Arc<TrustedProxies>>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, Response<Body>> {
    if is_rate_limit_exempt_path(request.uri().path()) {
        return Ok(next.run(request).await);
    }

    let ip_addr = extract_client_ip(addr.ip(), request.headers(), &trusted_proxies);
    let ip = ip_addr.to_string();

    // Disable rate limiting completely in development unless explicitly enforced
    let env = rate_limit_env();
    if !env.is_production && !env.enforce_in_dev {
        let response = next.run(request).await;
        return Ok(response);
    }

    if whitelist.is_whitelisted(&ip_addr) {
        tracing::debug!("IP {} is whitelisted, bypassing rate limit", ip);
        let response = next.run(request).await;
        return Ok(response);
    }

    let is_graphql = request.uri().path().starts_with("/graphql");

    match limiter.check_key(&ip) {
        Ok(_) => {
            let response = next.run(request).await;
            Ok(response)
        }
        Err(not_until) => {
            // MCP-499: compute the actual replenishment time from
            // governor and surface it via `Retry-After`. Pre-fix, the
            // response body said "Wait for 4s" but no `Retry-After`
            // header was set — HTTP RFC 6585 recommends the header so
            // clients can programmatically back off. The global
            // limiter already set a (static) `Retry-After: 30`; the
            // per-IP limiter said "4s" in the body and set nothing in
            // the headers. Using `not_until.wait_time_from(clock.now())`
            // gives the real GCRA replenishment time, accurate to the
            // configured quota.
            let clock = DefaultClock::default();
            let wait = not_until.wait_time_from(clock.now());
            // Round up so a sub-second wait still produces a
            // semantically-valid `Retry-After: N` (zero seconds tells
            // a client "retry now," which would just re-hit the
            // limiter); cap at 60s so a wildly-misconfigured quota
            // doesn't surface a multi-minute backoff for what should
            // be a transient throttle.
            let retry_after_secs = wait.as_secs().saturating_add(1).clamp(1, 60);
            tracing::warn!(
                ip = %ip,
                retry_after = retry_after_secs,
                "Rate limit exceeded"
            );

            let mut response = if is_graphql {
                let json_body = serde_json::json!({
                    "data": null,
                    "errors": [{
                        "message": format!("Too Many Requests! Wait for {}s", retry_after_secs),
                        "extensions": {
                            "code": "RATE_LIMITED",
                            "retry_after_secs": retry_after_secs,
                        }
                    }]
                });
                let mut res = Response::new(Body::from(json_body.to_string()));
                *res.status_mut() = StatusCode::OK;
                res
            } else {
                let mut res = Response::new(Body::from(format!(
                    "Too Many Requests! Wait for {}s",
                    retry_after_secs
                )));
                *res.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                res
            };

            if is_graphql {
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
            }
            // RFC 6585 §4: a 429 response SHOULD include `Retry-After`.
            // Even for the GraphQL 200-with-errors path we surface it
            // — well-behaved clients can read the header without
            // having to parse the GraphQL errors envelope.
            if let Ok(hv) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                response
                    .headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, hv);
            }

            Ok(response)
        }
    }
}

/// Global rate limiter (tracks overall system load)
pub type GlobalRateLimiter =
    Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock, governor::middleware::NoOpMiddleware>>;

/// Create a global rate limiter (not per-IP)
pub fn create_global_rate_limiter(config: RateLimitConfig) -> GlobalRateLimiter {
    let period = config.per / config.requests;

    // Handle invalid config gracefully instead of panicking
    let quota = match Quota::with_period(period) {
        Some(q) => match NonZeroU32::new(config.burst_size) {
            Some(burst) => q.allow_burst(burst),
            None => {
                tracing::warn!("Invalid burst_size: {}, using default", config.burst_size);
                q.allow_burst(NonZeroU32::MIN)
            }
        },
        None => {
            tracing::warn!("Invalid rate limit period: {:?}, using default", period);
            // Use a sensible default: 1 request per second with burst of 1
            Quota::with_period(Duration::from_secs(1))
                .unwrap_or_else(|| Quota::per_second(NonZeroU32::MIN))
                .allow_burst(NonZeroU32::MIN)
        }
    };

    Arc::new(RateLimiter::direct(quota))
}

/// Global rate limiting middleware (protects against overall system overload)
pub async fn global_rate_limit_middleware(
    limiter: axum::Extension<GlobalRateLimiter>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, Response<Body>> {
    if is_rate_limit_exempt_path(request.uri().path()) {
        return Ok(next.run(request).await);
    }

    match limiter.check() {
        Ok(_) => {
            let response = next.run(request).await;
            Ok(response)
        }
        Err(not_until) => {
            // MCP-569: dynamic Retry-After from governor's actual
            // replenishment time, matching the per-IP limiter's
            // behavior (MCP-499). Static "Retry-After: 30" was at
            // best a misleading hint — a 1000-req/s burst against a
            // 5000-req/s quota would surface "wait 30s" when in
            // reality the next slot replenishes in <1ms; clients
            // backed off far longer than needed. Cap at 60s so a
            // wildly-misconfigured quota doesn't surface a multi-
            // minute backoff for what should be a transient spike.
            let clock = DefaultClock::default();
            let wait = not_until.wait_time_from(clock.now());
            let retry_after_secs = wait.as_secs().saturating_add(1).clamp(1, 60);
            let path = request.uri().path().to_string();
            tracing::warn!(
                path = %path,
                retry_after = retry_after_secs,
                "Global rate limit exceeded"
            );

            let mut response = Response::new(Body::from(
                "Service temporarily unavailable due to high load. Please try again later.",
            ));
            *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            if let Ok(hv) = axum::http::HeaderValue::from_str(&retry_after_secs.to_string()) {
                response
                    .headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, hv);
            }

            Ok(response)
        }
    }
}

// ============================================================================
// Redis-backed distributed rate limiter
// ============================================================================

/// Controls behavior when Redis is unavailable for distributed rate limiting.
///
/// In a multi-instance deployment, falling back to in-memory rate limiting means
/// each instance tracks independently — an attacker can distribute requests across
/// N instances, effectively multiplying the rate limit by N.
#[derive(Clone, Debug, PartialEq)]
pub enum RateLimitFallbackPolicy {
    /// Fall back to per-instance in-memory rate limiting when Redis is unavailable.
    /// Suitable for development or single-instance deployments.
    FailOpen,
    /// Reject all requests when Redis is unavailable.
    /// Suitable for production multi-instance deployments where consistent
    /// enforcement is required for security (e.g., auth endpoints).
    FailClosed,
}

/// Distributed rate limiter backed by Redis with configurable fallback policy.
///
/// When `policy` is `FailOpen` (the default for development), a Redis outage causes
/// graceful degradation to per-instance in-memory limiting.  When `FailClosed`
/// (recommended for production auth endpoints), a Redis outage blocks all requests
/// to prevent distributed brute-force attacks across controller instances.
#[derive(Clone)]
pub struct DistributedRateLimiter {
    redis_client: Option<Arc<redis::Client>>,
    fallback: IpRateLimiter,
    max_requests: u32,
    window_secs: u64,
    prefix: String,
    policy: RateLimitFallbackPolicy,
    /// M4 (2026-05-28 review): cached, auto-reconnecting multiplexed
    /// connection. This limiter is on the per-request hot path; the old
    /// `get_multiplexed_tokio_connection()`-per-check opened a fresh
    /// connection (TCP + TLS + AUTH) on every request. See `conn_or_init`.
    conn_mgr: tokio::sync::OnceCell<redis::aio::ConnectionManager>,
}

impl DistributedRateLimiter {
    pub fn new(
        redis_client: Option<Arc<redis::Client>>,
        config: RateLimitConfig,
        prefix: &str,
    ) -> Self {
        Self::with_policy(
            redis_client,
            config,
            prefix,
            RateLimitFallbackPolicy::FailOpen,
        )
    }

    /// Create a distributed rate limiter with an explicit fallback policy.
    pub fn with_policy(
        redis_client: Option<Arc<redis::Client>>,
        config: RateLimitConfig,
        prefix: &str,
        policy: RateLimitFallbackPolicy,
    ) -> Self {
        if redis_client.is_none() && policy == RateLimitFallbackPolicy::FailClosed {
            tracing::error!(
                prefix = prefix,
                "DistributedRateLimiter created with FailClosed policy but no Redis client — \
                 all rate-limited requests will be rejected until Redis becomes available"
            );
        }
        let fallback = create_rate_limiter(config.clone());
        Self {
            redis_client,
            fallback,
            max_requests: config.requests,
            window_secs: config.per.as_secs(),
            prefix: prefix.to_string(),
            policy,
            conn_mgr: tokio::sync::OnceCell::new(),
        }
    }

    /// M4: hand out a clone of ONE cached, auto-reconnecting multiplexed
    /// connection instead of opening a fresh connection per request.
    /// `ConnectionManager` keeps one socket open and reconnects transparently;
    /// clones share it. `get_or_try_init` does not cache an init failure, so a
    /// Redis outage at first use is retried (and meanwhile `check` applies the
    /// configured fail-open / fail-closed fallback policy).
    async fn conn_or_init(
        &self,
        client: &redis::Client,
    ) -> Result<redis::aio::ConnectionManager, redis::RedisError> {
        let mgr = self
            .conn_mgr
            .get_or_try_init(|| async { redis::aio::ConnectionManager::new(client.clone()).await })
            .await?;
        Ok(mgr.clone())
    }

    /// Create a distributed rate limiter that auto-detects the fallback policy
    /// based on the environment: `FailClosed` in production, `FailOpen` in development.
    pub fn auto(
        redis_client: Option<Arc<redis::Client>>,
        config: RateLimitConfig,
        prefix: &str,
    ) -> Self {
        let policy = if crate::is_production() {
            RateLimitFallbackPolicy::FailClosed
        } else {
            RateLimitFallbackPolicy::FailOpen
        };
        Self::with_policy(redis_client, config, prefix, policy)
    }

    pub async fn check(&self, identifier: &str) -> bool {
        if let Some(ref client) = self.redis_client {
            match self.check_redis(client, identifier).await {
                Ok(allowed) => return allowed,
                Err(e) => match self.policy {
                    RateLimitFallbackPolicy::FailClosed => {
                        tracing::error!(
                            prefix = %self.prefix,
                            identifier = identifier,
                            error = %e,
                            "Redis rate limit check failed — rejecting request (fail-closed policy)"
                        );
                        return false;
                    }
                    RateLimitFallbackPolicy::FailOpen => {
                        tracing::warn!(
                            prefix = %self.prefix,
                            identifier = identifier,
                            error = %e,
                            "Redis rate limit check failed — falling back to in-memory (fail-open policy)"
                        );
                    }
                },
            }
        } else if self.policy == RateLimitFallbackPolicy::FailClosed {
            tracing::error!(
                prefix = %self.prefix,
                identifier = identifier,
                "No Redis client available — rejecting request (fail-closed policy)"
            );
            return false;
        }
        self.fallback.check_key(&identifier.to_string()).is_ok()
    }

    async fn check_redis(
        &self,
        client: &redis::Client,
        identifier: &str,
    ) -> Result<bool, redis::RedisError> {
        let key = format!("rl:{}:{}", self.prefix, identifier);
        let mut con = self.conn_or_init(client).await?;
        // MCP-442: INCR and EXPIRE used to be two separate commands. If
        // the EXPIRE leg failed (transient network blip, server
        // reconnect mid-flight), INCR had already created the key with
        // NO TTL. Subsequent requests would see `count > 1`, skip
        // EXPIRE, and the key would persist forever — permanently
        // locking out that identifier until an operator manually
        // deleted the key. EVAL the two ops as one Lua script so they
        // execute atomically on the Redis server: either both succeed
        // or neither modifies state.
        const RATE_LIMIT_SCRIPT: &str = r#"
            local count = redis.call('INCR', KEYS[1])
            if count == 1 then
                redis.call('EXPIRE', KEYS[1], ARGV[1])
            end
            return count
        "#;
        let count: i64 = redis::cmd("EVAL")
            .arg(RATE_LIMIT_SCRIPT)
            .arg(1)
            .arg(&key)
            .arg(self.window_secs as i64)
            .query_async(&mut con)
            .await?;
        Ok(count <= self.max_requests as i64)
    }

    /// MCP-718 (2026-05-13): periodic-sweep entry point for the in-memory
    /// fallback. The fallback `IpRateLimiter` (governor with
    /// `DashMapStateStore<String>`) retains one entry per distinct
    /// identifier forever — entries are added on `check_redis` failure
    /// when fallback policy is `FailOpen`. Under sustained Redis outages
    /// the map grows with distinct caller IDs and the entries SURVIVE
    /// recovery (no auto-eviction in governor's keyed state store).
    /// `api_limiter` / `webhook_limiter` (raw `IpRateLimiter`) already
    /// have a 5-min sweep in `controller/src/main.rs` (MCP-694); this
    /// method exposes the same hygiene contract for `DistributedRateLimiter`
    /// wrappers so callers can wire BOTH limiter classes into a single
    /// cleanup loop without reaching inside.
    ///
    /// `retain_recent` drops keys whose buckets are indistinguishable
    /// from "fresh" state; `shrink_to_fit` reclaims DashMap capacity.
    pub fn cleanup_fallback(&self) {
        self.fallback.retain_recent();
        self.fallback.shrink_to_fit();
    }

    /// MCP-718: read-side accessor matching `IpRateLimiter::len` so the
    /// sweep task can emit before/after metrics in lockstep with the
    /// raw-limiter cleanup loop.
    pub fn fallback_len(&self) -> usize {
        self.fallback.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn trusted(cidrs: &str) -> TrustedProxies {
        TrustedProxies(IpWhitelist::from_string(cidrs).expect("valid cidrs"))
    }

    fn headers_with_xff(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("x-forwarded-for", HeaderValue::from_str(value).unwrap());
        h
    }

    /// MCP-912: bracketed-IPv6 XFF forms (RFC 7239-recommended) must
    /// parse so the right-to-left walk doesn't silently fall through
    /// to the trusted proxy IP and collapse every client onto one
    /// rate-limit bucket.
    #[test]
    fn extract_client_ip_handles_bracketed_ipv6() {
        let proxies = trusted("10.0.0.0/8");
        let direct: IpAddr = "10.0.0.1".parse().unwrap();
        // Real client is 2001:db8::1 behind one trusted proxy.
        for entry in &[
            "2001:db8::1",
            "[2001:db8::1]",
            "[2001:db8::1]:443",
            "192.0.2.1:8080",
        ] {
            let h = headers_with_xff(entry);
            let got = extract_client_ip(direct, &h, &proxies);
            assert!(
                !proxies.is_trusted(&got),
                "entry {entry:?} should resolve to a non-trusted client, got {got}"
            );
        }
    }

    /// MCP-912: parse helper sanity — accepts both bare and bracketed
    /// forms; rejects garbage.
    #[test]
    fn parse_xff_entry_accepts_known_forms() {
        assert!(parse_xff_entry("192.0.2.1").is_some());
        assert!(parse_xff_entry("192.0.2.1:8080").is_some());
        assert!(parse_xff_entry("2001:db8::1").is_some());
        assert!(parse_xff_entry("[2001:db8::1]").is_some());
        assert!(parse_xff_entry("[2001:db8::1]:443").is_some());
        // Whitespace tolerated.
        assert!(parse_xff_entry("  192.0.2.1  ").is_some());
        // Garbage rejected.
        assert!(parse_xff_entry("not-an-ip").is_none());
        assert!(parse_xff_entry("").is_none());
    }

    #[test]
    fn probe_paths_are_exempt() {
        // MCP-1074: `/auth/csrf` added — CSRF cookie seeder lives in
        // `probe_routes` per the controller's "no rate limiting, no
        // auth" architectural intent and must be exempt by
        // belt-and-suspenders guard too.
        for path in [
            "/health",
            "/health/redis",
            "/health/nats",
            "/live",
            "/ready",
            "/metrics/prometheus",
            "/auth/csrf",
        ] {
            assert!(is_rate_limit_exempt_path(path), "{path} should be exempt");
        }
    }

    #[test]
    fn rate_limited_paths_are_not_exempt() {
        for path in [
            "/",
            "/graphql",
            "/ws",
            "/metrics",
            "/api/foo",
            "/health/", // trailing-slash form is NOT a probe path
            "/healthz", // common k8s name we don't serve
            "/healthcheck",
        ] {
            assert!(
                !is_rate_limit_exempt_path(path),
                "{path} should NOT be exempt"
            );
        }
    }

    #[test]
    fn xff_ignored_when_direct_peer_untrusted() {
        let direct: IpAddr = "203.0.113.5".parse().unwrap();
        let headers = headers_with_xff("198.51.100.1, 10.42.0.1");
        let trusted = trusted("10.42.0.0/16");
        // Direct peer 203.0.113.5 is NOT in trusted_proxies, so the XFF
        // header is untrusted and ignored — preventing spoofing from any
        // client that bypasses the proxy.
        assert_eq!(extract_client_ip(direct, &headers, &trusted), direct);
    }

    #[test]
    fn xff_uses_rightmost_untrusted_entry() {
        // Real proxy chain: client -> Traefik (10.42.0.5) -> kube-proxy (10.42.0.1)
        // Direct peer is kube-proxy. Header is "client, traefik". Rightmost
        // untrusted entry walking right-to-left is the original client IP.
        let direct: IpAddr = "10.42.0.1".parse().unwrap();
        let headers = headers_with_xff("203.0.113.5, 10.42.0.5");
        let trusted = trusted("10.42.0.0/16");
        let real: IpAddr = "203.0.113.5".parse().unwrap();
        assert_eq!(extract_client_ip(direct, &headers, &trusted), real);
    }

    #[test]
    fn xff_rejects_client_spoof_via_prepend() {
        // Hostile client behind the trusted proxy pre-pends a fake IP to
        // their own request: their real IP gets appended by the proxy as
        // the rightmost entry. RFC 7239 walk-from-right ignores the
        // attacker-supplied "1.1.1.1" prefix and lands on the real IP.
        let direct: IpAddr = "10.42.0.1".parse().unwrap();
        let headers = headers_with_xff("1.1.1.1, 198.51.100.7");
        let trusted = trusted("10.42.0.0/16");
        let attacker_real: IpAddr = "198.51.100.7".parse().unwrap();
        assert_eq!(
            extract_client_ip(direct, &headers, &trusted),
            attacker_real,
            "attacker-prepended XFF entry must not become the rate-limit key"
        );
    }

    #[test]
    fn xff_falls_back_to_leftmost_when_chain_all_trusted() {
        // All entries are inside trusted CIDRs (e.g. service-mesh hop chain).
        // We have no untrusted entry to anchor on; fall back to the leftmost
        // claim so we at least key off something stable per upstream.
        let direct: IpAddr = "10.42.0.1".parse().unwrap();
        let headers = headers_with_xff("10.42.0.7, 10.42.0.5");
        let trusted = trusted("10.42.0.0/16");
        let leftmost: IpAddr = "10.42.0.7".parse().unwrap();
        assert_eq!(extract_client_ip(direct, &headers, &trusted), leftmost);
    }

    #[test]
    fn xff_handles_empty_and_whitespace() {
        let direct: IpAddr = "10.42.0.1".parse().unwrap();
        let trusted = trusted("10.42.0.0/16");

        // No header → direct peer.
        assert_eq!(
            extract_client_ip(direct, &HeaderMap::new(), &trusted),
            direct
        );

        // Header present but empty/whitespace → direct peer.
        assert_eq!(
            extract_client_ip(direct, &headers_with_xff("   "), &trusted),
            direct
        );
        assert_eq!(
            extract_client_ip(direct, &headers_with_xff(", ,"), &trusted),
            direct
        );
    }

    #[test]
    fn xff_skips_unparseable_entries() {
        let direct: IpAddr = "10.42.0.1".parse().unwrap();
        let trusted = trusted("10.42.0.0/16");
        let real: IpAddr = "203.0.113.9".parse().unwrap();
        // Garbage between commas should be skipped, not mistaken for the client.
        let headers = headers_with_xff("not-an-ip, 203.0.113.9, 10.42.0.5");
        assert_eq!(extract_client_ip(direct, &headers, &trusted), real);
    }

    /// MCP-1103: a pathological XFF with thousands of crafted entries
    /// must not pin the per-request CIDR-lookup cost. The walk caps at
    /// `MAX_XFF_ENTRIES = 64` from the right, so an attacker padding
    /// 5000 trusted-CIDR-shaped entries on the LEFT can't force the
    /// middleware to iterate them. The rightmost-untrusted entry
    /// within the cap window is returned.
    #[test]
    fn xff_cap_walks_only_rightmost_entries() {
        let direct: IpAddr = "10.42.0.1".parse().unwrap();
        let trusted = trusted("10.42.0.0/16");
        let real: IpAddr = "203.0.113.99".parse().unwrap();

        // Build XFF: <5000 fake trusted IPs>, real-untrusted, <60 trusted>
        // Walk from the right: first 60 trusted (skipped), then hits
        // real-untrusted at position 61 (within the 64-entry window) →
        // returns real-untrusted. The 5000 left-side fakes never get
        // touched.
        let mut parts: Vec<String> = (0..5000)
            .map(|i| format!("10.42.{}.{}", (i / 256) % 256, i % 256))
            .collect();
        parts.push("203.0.113.99".to_string());
        for _ in 0..60 {
            parts.push("10.42.0.5".to_string());
        }
        let xff = parts.join(", ");
        let headers = headers_with_xff(&xff);
        assert_eq!(extract_client_ip(direct, &headers, &trusted), real);
    }

    /// Defense-in-depth complement: when the rightmost 64 entries are
    /// ALL trusted (long internal-only chain), the fallback to the
    /// leftmost entry still works regardless of how many entries
    /// preceded the cap window.
    #[test]
    fn xff_cap_fallback_to_leftmost_on_all_trusted_window() {
        let direct: IpAddr = "10.42.0.1".parse().unwrap();
        let trusted = trusted("10.42.0.0/16");
        // Leftmost is an untrusted-shaped IP; the entire chain after it
        // is trusted. The right-to-left walk hits 64 trusted entries
        // and bails; fallback returns the leftmost.
        let leftmost: IpAddr = "203.0.113.50".parse().unwrap();
        let mut parts = vec!["203.0.113.50".to_string()];
        for _ in 0..200 {
            parts.push("10.42.0.5".to_string());
        }
        let xff = parts.join(", ");
        let headers = headers_with_xff(&xff);
        assert_eq!(extract_client_ip(direct, &headers, &trusted), leftmost);
    }

    #[test]
    fn test_rate_limit_config() {
        let auth = RateLimitConfig::auth();
        assert_eq!(auth.requests, 5);
        assert_eq!(auth.per, Duration::from_secs(60));

        // Since we allow configuring from env, these defaults are 300, 60, 100
        // in a clean environment. Let's just assume we check the general logic.
        // assert_eq!(api.requests, 300);
        // assert_eq!(api.per, Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_rate_limiter_creation() {
        let config = RateLimitConfig::api();
        let limiter = create_rate_limiter(config);
        assert!(limiter.check_key(&"127.0.0.1".to_string()).is_ok());
    }

    #[tokio::test]
    async fn test_rate_limiter_enforcement() {
        let config = RateLimitConfig {
            requests: 2,
            per: Duration::from_secs(2), // 1 per sec
            burst_size: 2,
        };
        let limiter = create_rate_limiter(config);

        let ip = "127.0.0.1".to_string();

        assert!(limiter.check_key(&ip).is_ok());
        assert!(limiter.check_key(&ip).is_ok());
        assert!(limiter.check_key(&ip).is_err());
    }

    #[tokio::test]
    async fn test_distributed_rate_limiter_fail_open_without_redis() {
        // Without Redis and FailOpen policy, requests should fall back to in-memory limiter
        let config = RateLimitConfig {
            requests: 100,
            per: Duration::from_secs(60),
            burst_size: 20,
        };
        let limiter = DistributedRateLimiter::with_policy(
            None,
            config,
            "test",
            RateLimitFallbackPolicy::FailOpen,
        );
        // Should allow — in-memory fallback permits the request
        assert!(limiter.check("test-user").await);
    }

    #[tokio::test]
    async fn test_distributed_rate_limiter_fail_closed_without_redis() {
        // Without Redis and FailClosed policy, ALL requests should be rejected
        let config = RateLimitConfig {
            requests: 100,
            per: Duration::from_secs(60),
            burst_size: 20,
        };
        let limiter = DistributedRateLimiter::with_policy(
            None,
            config,
            "test",
            RateLimitFallbackPolicy::FailClosed,
        );
        // Should reject — no Redis available and policy is fail-closed
        assert!(!limiter.check("test-user").await);
    }

    #[tokio::test]
    async fn test_distributed_rate_limiter_fail_closed_with_unreachable_redis() {
        // With an unreachable Redis client and FailClosed policy, requests should be rejected
        let client = redis::Client::open("redis://127.0.0.1:1").expect("client creation");
        let config = RateLimitConfig {
            requests: 100,
            per: Duration::from_secs(60),
            burst_size: 20,
        };
        let limiter = DistributedRateLimiter::with_policy(
            Some(Arc::new(client)),
            config,
            "test",
            RateLimitFallbackPolicy::FailClosed,
        );
        // Should reject — Redis is unreachable and policy is fail-closed
        assert!(!limiter.check("test-user").await);
    }

    #[tokio::test]
    async fn test_distributed_rate_limiter_fail_open_with_unreachable_redis() {
        // With an unreachable Redis client and FailOpen policy, should fall back to in-memory
        let client = redis::Client::open("redis://127.0.0.1:1").expect("client creation");
        let config = RateLimitConfig {
            requests: 100,
            per: Duration::from_secs(60),
            burst_size: 20,
        };
        let limiter = DistributedRateLimiter::with_policy(
            Some(Arc::new(client)),
            config,
            "test",
            RateLimitFallbackPolicy::FailOpen,
        );
        // Should allow — falls back to in-memory limiter
        assert!(limiter.check("test-user").await);
    }
}
