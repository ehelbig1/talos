//! A `tower_governor` key extractor that keys on the REAL client IP.
//!
//! `GovernorConfigBuilder::default()` is `PeerIpKeyExtractor`: the socket peer.
//! Behind the chart's nginx frontend (and any ingress) the peer is the proxy
//! pod for every request, so the production-only governor layer collapsed
//! every user onto ONE 10 req/s bucket — a platform-wide DoS any single user
//! could trip, and the exact defect `rate_limit_middleware` already avoided by
//! resolving the client through [`extract_client_ip`] (F4).
//!
//! This extractor reuses that ONE resolver — the RFC 7239 right-to-left
//! `X-Forwarded-For` walk that trusts the header only when the peer is a
//! configured trusted proxy — so the governor and the in-house limiters agree
//! on who a request is from. `SmartIpKeyExtractor` was deliberately NOT used:
//! it reads the LEFTMOST forwarded entry from any peer, which is the
//! attacker-controllable head of the chain (see the S4 note on
//! `extract_client_ip`).

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use axum::extract::ConnectInfo;
use axum::http::Request;
use tower_governor::key_extractor::KeyExtractor;
use tower_governor::GovernorError;

use crate::middleware::{extract_client_ip, TrustedProxies};

/// Keys the governor on the trusted-proxy-resolved client IP.
#[derive(Clone)]
pub struct TrustedProxyClientIpKeyExtractor {
    trusted_proxies: Arc<TrustedProxies>,
}

impl TrustedProxyClientIpKeyExtractor {
    /// Build from the SAME `TrustedProxies` the rate-limit middlewares use, so
    /// the two layers cannot disagree about which peers may set
    /// `X-Forwarded-For`.
    pub fn new(trusted_proxies: Arc<TrustedProxies>) -> Self {
        Self { trusted_proxies }
    }

    /// The pure core: peer + headers → key. Split out so it is testable
    /// without a `Request`.
    pub fn resolve(&self, peer: IpAddr, headers: &axum::http::HeaderMap) -> IpAddr {
        extract_client_ip(peer, headers, &self.trusted_proxies)
    }
}

impl KeyExtractor for TrustedProxyClientIpKeyExtractor {
    type Key = IpAddr;

    fn name(&self) -> &'static str {
        "client IP (RFC 7239 trusted-proxy walk)"
    }

    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, GovernorError> {
        // Same source the default `PeerIpKeyExtractor` reads: the
        // `ConnectInfo<SocketAddr>` axum inserts when the app is served with
        // `into_make_service_with_connect_info`. Absent ⇒ the request cannot
        // be attributed ⇒ governor's own "unable to extract key" response
        // (fail closed, as the default extractor does).
        let peer = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|ci| ci.0.ip())
            .ok_or(GovernorError::UnableToExtractKey)?;
        Ok(self.resolve(peer, req.headers()))
    }

    fn key_name(&self, key: &Self::Key) -> Option<String> {
        Some(key.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::IpWhitelist;
    use axum::http::HeaderValue;

    fn extractor(trusted_cidrs: &str) -> TrustedProxyClientIpKeyExtractor {
        let whitelist = IpWhitelist::from_string(trusted_cidrs).expect("valid cidrs");
        TrustedProxyClientIpKeyExtractor::new(Arc::new(TrustedProxies::from_whitelist(whitelist)))
    }

    fn req(peer: &str, xff: Option<&str>) -> Request<()> {
        let mut r = Request::builder().uri("/graphql").body(()).unwrap();
        if let Some(v) = xff {
            r.headers_mut()
                .insert("x-forwarded-for", HeaderValue::from_str(v).unwrap());
        }
        r.extensions_mut().insert(ConnectInfo::<SocketAddr>(
            format!("{peer}:4321").parse().unwrap(),
        ));
        r
    }

    /// The F4 reproducer: two users behind the trusted ingress must land in
    /// two buckets. Under `PeerIpKeyExtractor` both keys would be 10.0.0.1.
    #[test]
    fn two_clients_behind_the_trusted_proxy_get_two_keys() {
        let ex = extractor("10.0.0.0/8");
        let a = ex.extract(&req("10.0.0.1", Some("203.0.113.7"))).unwrap();
        let b = ex.extract(&req("10.0.0.1", Some("198.51.100.9"))).unwrap();
        assert_eq!(a, "203.0.113.7".parse::<IpAddr>().unwrap());
        assert_eq!(b, "198.51.100.9".parse::<IpAddr>().unwrap());
        assert_ne!(a, b);
    }

    /// An UNTRUSTED peer cannot pick its own bucket by forging the header —
    /// the whole reason `SmartIpKeyExtractor` was rejected.
    #[test]
    fn untrusted_peer_cannot_spoof_its_key() {
        let ex = extractor("10.0.0.0/8");
        let key = ex
            .extract(&req("203.0.113.7", Some("198.51.100.9, 10.0.0.1")))
            .unwrap();
        assert_eq!(key, "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    /// Behind a trusted proxy, the walk is right-to-left: a client that
    /// PREPENDS a forged entry is still keyed on its real address.
    #[test]
    fn prepended_forgery_behind_trusted_proxy_is_ignored() {
        let ex = extractor("10.0.0.0/8");
        let key = ex
            .extract(&req("10.0.0.1", Some("1.2.3.4, 203.0.113.7")))
            .unwrap();
        assert_eq!(key, "203.0.113.7".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn missing_connect_info_fails_closed() {
        let ex = extractor("10.0.0.0/8");
        let r = Request::builder().uri("/").body(()).unwrap();
        assert!(matches!(
            ex.extract(&r),
            Err(GovernorError::UnableToExtractKey)
        ));
    }
}
