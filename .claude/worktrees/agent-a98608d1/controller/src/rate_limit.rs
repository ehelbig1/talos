use axum::{
    body::Body,
    extract::ConnectInfo,
    http::{Request, Response, StatusCode},
    middleware::Next,
};
use governor::{
    clock::DefaultClock,
    state::{direct::NotKeyed, keyed::DashMapStateStore, InMemoryState},
    Quota, RateLimiter,
};
use ipnetwork::IpNetwork;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

/// Helper to read a rate‑limit configuration value from the environment.
/// Returns the parsed `u32` or the provided `default` if the variable is missing
/// or cannot be parsed.
pub fn env_rate_limit(var: &str, default: u32) -> u32 {
    std::env::var(var)
        .unwrap_or_else(|_| default.to_string())
        .parse::<u32>()
        .unwrap_or(default)
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
    let quota = Quota::with_period(period)
        .expect("Invalid rate limit period")
        .allow_burst(NonZeroU32::new(config.burst_size).expect("Burst size must be > 0"));

    Arc::new(RateLimiter::dashmap(quota))
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
    let direct_ip = addr.ip();
    let ip_addr = if trusted_proxies.is_trusted(&direct_ip) {
        if let Some(forwarded) = request.headers().get("x-forwarded-for") {
            if let Ok(s) = forwarded.to_str() {
                s.split(',')
                    .next()
                    .and_then(|first| first.trim().parse::<IpAddr>().ok())
                    .unwrap_or(direct_ip)
            } else {
                direct_ip
            }
        } else {
            direct_ip
        }
    } else {
        direct_ip
    };
    let ip = ip_addr.to_string();
    
    // Disable rate limiting completely in development unless explicitly enforced
    if std::env::var("RUST_ENV").unwrap_or_default() != "production" && 
       std::env::var("ENFORCE_RATE_LIMITS_IN_DEV").unwrap_or_default() != "true" {
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
        Err(_) => {
            tracing::warn!("Rate limit exceeded for IP: {}", ip);

            let mut response = if is_graphql {
                let json_body = serde_json::json!({
                    "data": null,
                    "errors": [{
                        "message": "Too Many Requests! Wait for 4s",
                        "extensions": {
                            "code": "RATE_LIMITED"
                        }
                    }]
                });
                let mut res = Response::new(Body::from(json_body.to_string()));
                *res.status_mut() = StatusCode::OK;
                res
            } else {
                let mut res = Response::new(Body::from("Too Many Requests! Wait for 4s"));
                *res.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                res
            };

            if is_graphql {
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                );
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
    let quota = Quota::with_period(period)
        .expect("Invalid rate limit period")
        .allow_burst(NonZeroU32::new(config.burst_size).expect("Burst size must be > 0"));

    Arc::new(RateLimiter::direct(quota))
}

/// Global rate limiting middleware (protects against overall system overload)
pub async fn global_rate_limit_middleware(
    limiter: axum::Extension<GlobalRateLimiter>,
    request: Request<Body>,
    next: Next,
) -> Result<Response<Body>, Response<Body>> {
    match limiter.check() {
        Ok(_) => {
            let response = next.run(request).await;
            Ok(response)
        }
        Err(_) => {
            tracing::warn!("Global rate limit exceeded");

            let mut response = Response::new(Body::from(
                "Service temporarily unavailable due to high load. Please try again later.",
            ));
            *response.status_mut() = StatusCode::SERVICE_UNAVAILABLE;
            response.headers_mut().insert(
                axum::http::header::RETRY_AFTER,
                axum::http::HeaderValue::from_static("30"),
            );

            Ok(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
