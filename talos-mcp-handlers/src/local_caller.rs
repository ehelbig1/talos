//! Who the tokenless local MCP route answers: a caller on this machine.
//!
//! `/mcp/local` carries no token. Outside production it runs every tool as
//! the first user, which is the point of it: a development stack and its
//! scripts need no key. Until 2026-10-13 its only condition was the build
//! mode, so the route was as reachable as the controller's port. A
//! development stack with a public tunnel forwards every path to that port,
//! and a reverse proxy in front of a non-production build proxies `/mcp` by
//! prefix, so the route was served on those addresses too, to anyone.
//!
//! A request is answered only when nothing about it says it came from
//! somewhere else:
//!
//! * **No forwarding header.** A tunnel or a reverse proxy adds one
//!   (`X-Forwarded-For` and its family, `Forwarded`, `Via`), and the caller
//!   behind it cannot take it away again.
//! * **`Host` names this machine**: `localhost`, a `127.0.0.0/8` address or
//!   `[::1]`, with any port. A proxy that passes the public name through is
//!   refused here; so is a page whose name was re-pointed at `127.0.0.1`
//!   (DNS rebinding), which the browser still sends under its own name.
//! * **`Origin`, when a browser sent one, is a page served from this
//!   machine.**
//!
//! A refusal is a bare `404`, which is what a production build answers for
//! this path.
//!
//! # What this does not do
//!
//! It does not authenticate. A process on this machine, or one on the same
//! container network that sets `Host: localhost`, is still served as the
//! first user: the route is operator-equivalent to whoever can reach the
//! port. A caller that is not on this machine uses `/mcp` with an agent
//! token.

use axum::extract::Request;
use axum::http::{header, HeaderMap, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use std::net::{Ipv4Addr, Ipv6Addr};

/// What a proxy or tunnel adds to a request it forwards.
const FORWARDING_HEADERS: [&str; 6] = [
    "forwarded",
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "x-real-ip",
    "via",
];

/// Why a request is not answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NotLocal {
    /// A forwarding header is present.
    Forwarded,
    /// The request names no host, several, or one that is not this machine.
    Host,
    /// A browser sent it for a page that was not served from this machine.
    Origin,
}

impl NotLocal {
    /// The `reason` an audit line carries.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Forwarded => "forwarded",
            Self::Host => "host_not_local",
            Self::Origin => "origin_not_local",
        }
    }
}

/// Whether an authority (`host`, `host:port`, `[v6]`, `[v6]:port`) names
/// this machine.
fn authority_is_loopback(authority: &str) -> bool {
    fn port_ok(port: &str) -> bool {
        !port.is_empty() && port.len() <= 5 && port.bytes().all(|b| b.is_ascii_digit())
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let Some((address, after)) = rest.split_once(']') else {
            return false;
        };
        let port_part_ok = after.is_empty() || after.strip_prefix(':').is_some_and(port_ok);
        return port_part_ok && address.parse::<Ipv6Addr>().is_ok_and(|ip| ip.is_loopback());
    }
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port_ok(port) => host,
        Some(_) => return false,
        None => authority,
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    host.eq_ignore_ascii_case("localhost")
        || host.parse::<Ipv4Addr>().is_ok_and(|ip| ip.is_loopback())
}

/// Why this request is not from this machine, or `None` when nothing says
/// it is not.
pub(crate) fn not_local(headers: &HeaderMap, uri: &Uri) -> Option<NotLocal> {
    if FORWARDING_HEADERS
        .iter()
        .any(|name| headers.contains_key(*name))
    {
        return Some(NotLocal::Forwarded);
    }

    // Exactly one Host (HTTP/1.1), or the request target's authority
    // (HTTP/2, which carries no Host header).
    let mut hosts = headers.get_all(header::HOST).iter();
    let host_is_local = match (hosts.next(), hosts.next()) {
        (Some(one), None) => one.to_str().is_ok_and(authority_is_loopback),
        (None, _) => uri
            .authority()
            .is_some_and(|authority| authority_is_loopback(authority.as_str())),
        (Some(_), Some(_)) => false,
    };
    if !host_is_local {
        return Some(NotLocal::Host);
    }

    let origin_is_local = headers.get_all(header::ORIGIN).iter().all(|origin| {
        origin.to_str().is_ok_and(|origin| {
            origin
                .strip_prefix("http://")
                .or_else(|| origin.strip_prefix("https://"))
                .is_some_and(authority_is_loopback)
        })
    });
    if !origin_is_local {
        return Some(NotLocal::Origin);
    }
    None
}

/// The layer on the local route: serve a local caller, answer anyone else
/// as if the route were not there.
///
/// The refusal is counted (`talos_mcp_auth_total{outcome="local_route_refused"}`)
/// and logged with its reason only. No header value is logged: every one of
/// them is the caller's text.
pub(crate) async fn local_callers_only(request: Request, next: Next) -> Response {
    match not_local(request.headers(), request.uri()) {
        None => next.run(request).await,
        Some(why) => {
            talos_metrics::record_mcp_auth(talos_metrics::McpAuthOutcome::LocalRouteRefused);
            tracing::warn!(
                target: "talos_audit",
                event_kind = "mcp_local_refused",
                reason = why.as_str(),
                "MCP /local: a request that did not come from this machine was refused"
            );
            StatusCode::NOT_FOUND.into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
        map
    }

    fn verdict(pairs: &[(&str, &str)]) -> Option<NotLocal> {
        not_local(&headers(pairs), &Uri::from_static("/mcp/local"))
    }

    #[test]
    fn this_machine_by_any_of_its_names_is_local() {
        for host in [
            "localhost",
            "localhost:8000",
            "LocalHost:8000",
            "localhost.:8000",
            "127.0.0.1",
            "127.0.0.1:8000",
            "127.10.20.30:65535",
            "[::1]",
            "[::1]:8000",
        ] {
            assert_eq!(verdict(&[("host", host)]), None, "{host}");
        }
    }

    #[test]
    fn any_other_name_is_not() {
        for host in [
            "",
            "tunnel.example",
            "tunnel.example:443",
            "controller:8000",
            "host.docker.internal:8000",
            "localhost.tunnel.example",
            "127.0.0.1.tunnel.example",
            "notlocalhost",
            "localhost:",
            "localhost:80a",
            "localhost:123456",
            "user@localhost",
            "localhost@tunnel.example",
            "10.0.0.5:8000",
            "192.168.1.5",
            "0.0.0.0:8000",
            "[::]:8000",
            "[::ffff:127.0.0.1]:8000",
            "[::1",
            "[::1]x",
            "[::1]:",
            "::1",
        ] {
            assert_eq!(verdict(&[("host", host)]), Some(NotLocal::Host), "{host:?}");
        }
        // No Host at all, and no authority in the request target.
        assert_eq!(verdict(&[]), Some(NotLocal::Host));
        // Two Host headers: which one a proxy and this server each believe
        // is not something to guess at.
        assert_eq!(
            verdict(&[("host", "localhost:8000"), ("host", "tunnel.example")]),
            Some(NotLocal::Host)
        );
        assert_eq!(
            verdict(&[("host", "localhost:8000"), ("host", "localhost:8000")]),
            Some(NotLocal::Host)
        );
    }

    #[test]
    fn an_http2_request_is_judged_by_its_authority() {
        let local = Uri::from_static("http://localhost:8000/mcp/local");
        let remote = Uri::from_static("https://tunnel.example/mcp/local");
        assert_eq!(not_local(&HeaderMap::new(), &local), None);
        assert_eq!(not_local(&HeaderMap::new(), &remote), Some(NotLocal::Host));
        // A Host header, when there is one, is what is judged.
        assert_eq!(
            not_local(&headers(&[("host", "tunnel.example")]), &local),
            Some(NotLocal::Host)
        );
    }

    #[test]
    fn a_forwarding_header_marks_a_request_whatever_its_host_says() {
        for name in FORWARDING_HEADERS {
            assert_eq!(
                verdict(&[("host", "localhost:8000"), (name, "x")]),
                Some(NotLocal::Forwarded),
                "{name}"
            );
        }
        // Header names are case-insensitive on the wire.
        assert_eq!(
            verdict(&[
                ("host", "localhost:8000"),
                ("X-Forwarded-For", "203.0.113.7")
            ]),
            Some(NotLocal::Forwarded)
        );
        // An empty value is still the header.
        assert_eq!(
            verdict(&[("host", "localhost:8000"), ("x-forwarded-for", "")]),
            Some(NotLocal::Forwarded)
        );
    }

    #[test]
    fn a_browser_is_served_only_for_a_page_from_this_machine() {
        for origin in [
            "http://localhost:3002",
            "http://127.0.0.1:5173",
            "https://localhost",
            "http://[::1]:3002",
        ] {
            assert_eq!(
                verdict(&[("host", "localhost:8000"), ("origin", origin)]),
                None,
                "{origin}"
            );
        }
        for origin in [
            "null",
            "",
            "https://tunnel.example",
            "http://localhost.tunnel.example",
            "http://localhost:3002/path",
            "file://",
            "localhost:3002",
            "ftp://localhost",
        ] {
            assert_eq!(
                verdict(&[("host", "localhost:8000"), ("origin", origin)]),
                Some(NotLocal::Origin),
                "{origin:?}"
            );
        }
        // Every Origin must pass, not just the first.
        assert_eq!(
            verdict(&[
                ("host", "localhost:8000"),
                ("origin", "http://localhost:3002"),
                ("origin", "https://tunnel.example"),
            ]),
            Some(NotLocal::Origin)
        );
    }
}
