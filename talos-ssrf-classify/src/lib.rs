//! Single source of truth for SSRF private-IP classification.
//!
//! Both the controller (`talos-http-utils::ssrf`) and the WASM-host worker
//! gate outbound HTTP on this classifier at DNS-resolution time — the resolver
//! IS the connect, so a `Some(policy)` here is the only thing standing between
//! sandboxed guest code and an internal target (cloud-metadata IAM credentials
//! at `169.254.169.254`, loopback admin services, RFC1918 hosts, …).
//!
//! Historically this logic was duplicated byte-for-byte in two crates and kept
//! in sync by hand (the worker copy carried a "Mirrors talos_http_utils::ssrf"
//! comment). That manual mirror is exactly the drift hazard a shared crate
//! removes: a hardening fix now lands in one place for both gates.
//!
//! Dependency-free (std::net only) so it's cheap to pull into the worker
//! without dragging in a web framework.
//!
//! Coverage:
//! - IPv4: loopback (127/8), RFC1918, link-local incl. metadata (169.254/16),
//!   multicast, broadcast, the whole `0.0.0.0/8` (Linux routes it to loopback),
//!   and RFC 6598 CGNAT (100.64/10).
//! - IPv6: loopback (`::1`), multicast, unspecified (`::`), link-local
//!   (`fe80::/10`), unique-local (`fc00::/7`), deprecated site-local
//!   (`fec0::/10`), and every **IPv4-in-IPv6 transition form** —
//!   IPv4-mapped (`::ffff:a.b.c.d`), IPv4-compatible (`::a.b.c.d`),
//!   NAT64 well-known (`64:ff9b::/96`), and 6to4 (`2002::/16`) — canonicalized
//!   to their embedded IPv4 and re-checked, so the v4 rules can't be bypassed
//!   by spelling a private/loopback/metadata target in any IPv6 form.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Classify an IPv4 address. `Some(policy)` = refuse (SSRF target), `None` =
/// allow. The policy string is used by callers as the `record_capability_denied`
/// reason / structured-log field.
#[must_use]
pub fn classify_private_ipv4(addr: Ipv4Addr) -> Option<&'static str> {
    if addr.is_loopback()
        || addr.is_private()
        || addr.is_link_local()
        || addr.is_multicast()
        || addr.is_broadcast()
    {
        return Some("private-ip");
    }
    // Entire 0.0.0.0/8: on Linux connecting to 0.x routes to loopback, so the
    // whole /8 is an SSRF target — not just the exact `0.0.0.0` that
    // `is_unspecified()` matches (MCP-553 / MCP-1069).
    if addr.octets()[0] == 0 {
        return Some("private-ip-unspecified");
    }
    // RFC 6598 Carrier-Grade NAT (100.64.0.0/10): routable internally, not on
    // the public internet.
    if (u32::from(addr) >> 22) == (0x6440_0000u32 >> 22) {
        return Some("private-ip-cgnat");
    }
    None
}

/// Build an `Ipv4Addr` from two consecutive IPv6 segments (the low 32 bits of
/// a transition-form address).
fn v4_from_segs(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::new((hi >> 8) as u8, hi as u8, (lo >> 8) as u8, lo as u8)
}

/// If `addr` is an IPv4-in-IPv6 transition form, return its embedded IPv4 plus
/// the form's label. Covers IPv4-mapped, IPv4-compatible, NAT64 well-known, and
/// 6to4. `None` for any other IPv6 address.
fn embedded_ipv4(segs: [u16; 8]) -> Option<(Ipv4Addr, &'static str)> {
    let high_zero = segs[0] == 0 && segs[1] == 0 && segs[2] == 0 && segs[3] == 0;
    // IPv4-mapped `::ffff:a.b.c.d` — segs[4]==0, segs[5]==0xffff.
    if high_zero && segs[4] == 0 && segs[5] == 0xffff {
        return Some((v4_from_segs(segs[6], segs[7]), "ipv4-mapped-ipv6"));
    }
    // IPv4-compatible `::a.b.c.d` (deprecated) — the entire high 96 bits zero.
    // Callers handle `::`/`::1` before this, so the embedded v4 here is a real
    // target spelling (e.g. `::169.254.169.254`).
    if high_zero && segs[4] == 0 && segs[5] == 0 {
        return Some((v4_from_segs(segs[6], segs[7]), "ipv4-compat-ipv6"));
    }
    // NAT64 well-known prefix `64:ff9b::/96` (RFC 6052) — a NAT64 gateway
    // translates these to the embedded IPv4.
    if segs[0] == 0x0064
        && segs[1] == 0xff9b
        && segs[2] == 0
        && segs[3] == 0
        && segs[4] == 0
        && segs[5] == 0
    {
        return Some((v4_from_segs(segs[6], segs[7]), "nat64"));
    }
    // 6to4 `2002::/16` (RFC 3056) — the embedded IPv4 is the gateway address in
    // segs[1..3]; a 6to4 relay routes to it.
    if segs[0] == 0x2002 {
        return Some((v4_from_segs(segs[1], segs[2]), "6to4"));
    }
    None
}

/// Classify an IP (v4 or v6) for SSRF purposes: `Some(policy)` = refuse,
/// `None` = allow.
#[must_use]
pub fn classify_private_ip(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(addr) => classify_private_ipv4(addr),
        IpAddr::V6(addr) => classify_private_ipv6(addr),
    }
}

fn classify_private_ipv6(addr: Ipv6Addr) -> Option<&'static str> {
    // Direct IPv6 special addresses first, so they carry the precise policy
    // label rather than an embedded-v4 one.
    if addr.is_loopback() || addr.is_multicast() {
        return Some("private-ip");
    }
    if addr.is_unspecified() {
        return Some("private-ip-unspecified");
    }
    // Any IPv4-in-IPv6 transition form: canonicalize and re-check the v4 so a
    // private/loopback/metadata target can't be reached via an IPv6 spelling.
    let segs = addr.segments();
    if let Some((v4, form)) = embedded_ipv4(segs) {
        if let Some(reason) = classify_private_ipv4(v4) {
            return Some(match (reason, form) {
                // Preserve the historical strings for the IPv4-mapped path.
                ("private-ip-cgnat", "ipv4-mapped-ipv6") => "private-ip-cgnat-ipv4-mapped-ipv6",
                (_, "ipv4-mapped-ipv6") => "private-ip-ipv4-mapped-ipv6",
                ("private-ip-cgnat", "ipv4-compat-ipv6") => "private-ip-cgnat-ipv4-compat-ipv6",
                (_, "ipv4-compat-ipv6") => "private-ip-ipv4-compat-ipv6",
                ("private-ip-cgnat", "nat64") => "private-ip-cgnat-nat64",
                (_, "nat64") => "private-ip-nat64",
                ("private-ip-cgnat", "6to4") => "private-ip-cgnat-6to4",
                (_, "6to4") => "private-ip-6to4",
                _ => "private-ip-embedded-ipv4",
            });
        }
        // Embedded v4 is public → governed by the hostname allowlist like any
        // public destination; not an SSRF target on its own.
    }
    // IPv6 link-local (fe80::/10), unique-local (fc00::/7), and deprecated
    // site-local (fec0::/10).
    let first = segs[0];
    if (first & 0xffc0) == 0xfe80 || (first & 0xfe00) == 0xfc00 || (first & 0xffc0) == 0xfec0 {
        return Some("private-ip");
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn allows_public_v4_and_v6() {
        assert!(classify_private_ip(ip("8.8.8.8")).is_none());
        assert!(classify_private_ip(ip("1.1.1.1")).is_none());
        assert!(classify_private_ip(ip("2606:4700:4700::1111")).is_none());
        // IPv4-mapped public is allowed (real v4 connection to a public host).
        assert!(classify_private_ip(ip("::ffff:8.8.8.8")).is_none());
    }

    #[test]
    fn documentation_ranges_are_treated_as_public() {
        // RFC-5737 documentation ranges (192.0.2/24, 198.51.100/24,
        // 203.0.113/24) are reserved-UNASSIGNED, not internal/private — a
        // connection to one just fails to route, it can't reach an internal
        // service. So they are deliberately NOT SSRF targets, consistent with
        // talos_http_utils::ssrf and the WIT-http gate. (The worker's WASI
        // socket check used to block them as the lone divergence; consolidating
        // it onto this classifier removed that inconsistency — pin it here.)
        assert!(classify_private_ip(ip("192.0.2.1")).is_none());
        assert!(classify_private_ip(ip("198.51.100.42")).is_none());
        assert!(classify_private_ip(ip("203.0.113.5")).is_none());
    }

    #[test]
    fn rejects_v4_private_ranges() {
        for s in [
            "127.0.0.1",
            "10.0.0.5",
            "172.16.3.4",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "0.0.0.0",
            "0.1.2.3",    // 0.0.0.0/8
            "100.64.0.1", // CGNAT
            "224.0.0.1",  // multicast
            "255.255.255.255",
        ] {
            assert!(
                classify_private_ip(ip(s)).is_some(),
                "{s} should be blocked"
            );
        }
    }

    #[test]
    fn rejects_v6_special_ranges() {
        for s in [
            "::1",
            "fe80::1",
            "fc00::1",
            "fd00:ec2::254",
            "::",
            "ff02::1",
            "fec0::1",
        ] {
            assert!(
                classify_private_ip(ip(s)).is_some(),
                "{s} should be blocked"
            );
        }
    }

    #[test]
    fn preserves_historical_ipv4_mapped_policy_strings() {
        assert_eq!(
            classify_private_ip(ip("::ffff:127.0.0.1")),
            Some("private-ip-ipv4-mapped-ipv6")
        );
        assert_eq!(
            classify_private_ip(ip("::ffff:100.64.0.1")),
            Some("private-ip-cgnat-ipv4-mapped-ipv6")
        );
    }

    #[test]
    fn rejects_ipv4_compatible_embedding_private_v4() {
        // ::169.254.169.254 — metadata endpoint via the deprecated compat form.
        assert_eq!(
            classify_private_ip(ip("::169.254.169.254")),
            Some("private-ip-ipv4-compat-ipv6")
        );
        assert_eq!(
            classify_private_ip(ip("::127.0.0.1")),
            Some("private-ip-ipv4-compat-ipv6")
        );
    }

    #[test]
    fn rejects_nat64_embedding_private_v4() {
        // 64:ff9b::169.254.169.254 — metadata via a NAT64 gateway.
        assert_eq!(
            classify_private_ip(ip("64:ff9b::a9fe:a9fe")),
            Some("private-ip-nat64")
        );
        // public v4 behind NAT64 is allowed.
        assert!(classify_private_ip(ip("64:ff9b::8.8.8.8")).is_none());
    }

    #[test]
    fn rejects_6to4_embedding_private_v4() {
        // 2002:a9fe:a9fe:: — 6to4 wrapping 169.254.169.254.
        assert_eq!(
            classify_private_ip(ip("2002:a9fe:a9fe::")),
            Some("private-ip-6to4")
        );
        // 2002:0a00:0001:: — 6to4 wrapping 10.0.0.1.
        assert_eq!(
            classify_private_ip(ip("2002:a00:1::")),
            Some("private-ip-6to4")
        );
    }
}
