//! SSRF guard for outbound HTTP URLs.
//!
//! Used at any site where Talos fires an HTTP request to a URL that
//! originated from caller input (workflow webhooks, approval-gate
//! notifications, SLA alert webhooks, MCP `test_*_webhook` handlers).
//!
//! # What this rejects
//!
//! * Plaintext `http://` (HTTPS-only egress is a defense-in-depth rule).
//! * Loopback (`127.0.0.0/8`, `::1`, `localhost`).
//! * RFC-1918 private ranges (`10/8`, `172.16/12`, `192.168/16`).
//! * Link-local (`169.254/16`, `fe80::/10`).
//! * IPv6 ULA (`fc00::/7`).
//! * Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`).
//! * IPv4-mapped IPv6 (`::ffff:`-prefixed) addresses that resolve to any
//!   of the above.
//! * Non-canonical IPv4 encodings (octal `0177.0.0.1`, hex `0x7f.0.0.1`,
//!   single integer `2130706433`, zero-padded `127.000.000.001`) — these
//!   would slip past the literal-string blocklist while still resolving
//!   to private IPs through `getaddrinfo`.
//!
//! # What this does NOT defend against
//!
//! DNS rebinding (a hostname that resolves to a public IP at check time
//! and a private IP at connect time). Callers that need that guarantee
//! must resolve the hostname themselves and pin the connection to the
//! resolved IP via custom `reqwest` connector.
//!
//! For background-firing paths (webhooks stored at write-time then fired
//! later), call this AT FIRE TIME — write-time validation alone leaves a
//! gap when SSRF rules tighten between write and fire.

use std::str::FromStr;

/// Returns true if `s` looks like an attempt to encode an IPv4 address in a
/// non-canonical form that the OS resolver (`getaddrinfo`) would still
/// accept and normalise — octal (`0177.0.0.1`), hex (`0x7f.0.0.1`),
/// integer (`2130706433`), or zero-padded decimal (`127.000.000.001`).
///
/// Bypasses against the literal-string blocklist were the issue: an
/// attacker could pass `https://0177.0.0.1/` and the host-prefix checks
/// would let it through, but reqwest → getaddrinfo → connect ends up at
/// 127.0.0.1. We don't try to *interpret* these — we reject them.
/// MCP-196 (2026-05-08): RFC 3986 character whitelist. Returns true
/// for characters that may appear unencoded in a URL — alphanumeric
/// (unreserved without `-._~`, but `-` and `.` and `_` and `~` are
/// also unreserved), gen-delims (`:` `/` `?` `#` `[` `]` `@`),
/// sub-delims (`!` `$` `&` `'` `(` `)` `*` `+` `,` `;` `=`), and `%`
/// for percent-encoded sequences.
///
/// Caller responsible for the surrounding semantic checks (well-formed
/// percent triplets, scheme, host, etc.). This is a fast first gate
/// against the most common operator-typed garbage that today survives
/// the prefix check and persists as a never-firing webhook config.
fn is_valid_url_char(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '-' | '.'
                | '_'
                | '~'
                | ':'
                | '/'
                | '?'
                | '#'
                | '['
                | ']'
                | '@'
                | '!'
                | '$'
                | '&'
                | '\''
                | '('
                | ')'
                | '*'
                | '+'
                | ','
                | ';'
                | '='
                | '%'
        )
}

pub fn looks_like_obfuscated_ipv4(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    // Single integer encoding: a bare base-10 integer that's actually an IP.
    // 32-bit unsigned max is 4_294_967_295. Values that fit in u32 are
    // potential single-int IPv4 encodings; integer 32 alone shouldn't get
    // misclassified as a hostname.
    if s.chars().all(|c| c.is_ascii_digit()) && s.len() <= 10 {
        if let Ok(n) = s.parse::<u64>() {
            // Anything that fits in u32 is a valid getaddrinfo single-int IPv4.
            // Single digits are very unlikely to be real hostnames either.
            if n <= u32::MAX as u64 {
                return true;
            }
        }
    }
    // Hex octet form: `0x7f.0.0.1` or full hex `0x7f000001`.
    if s.contains("0x") || s.contains("0X") {
        return true;
    }
    // Dotted form with a non-canonical octet (leading zero, hex prefix,
    // out-of-range, or empty between dots). Strict canonical IPv4 always
    // parses cleanly via `Ipv4Addr::from_str`; if it doesn't and the string
    // is digits/dots only, it's an obfuscation attempt.
    let only_digits_and_dots = s.chars().all(|c| c.is_ascii_digit() || c == '.');
    if only_digits_and_dots && s.contains('.') {
        // 1) Strict-canonical parser succeeds → not obfuscated.
        if std::net::Ipv4Addr::from_str(s).is_ok() {
            return false;
        }
        // 2) Same shape but parser rejected (leading-zero octet, bad octet,
        //    too few/many dots). Treat as an attempt — reject.
        return true;
    }
    false
}

/// Validates that a URL is safe for outbound HTTP requests (SSRF protection).
///
/// Returns `Ok(())` if the URL is safe, `Err(reason)` if it should be rejected.
/// The returned reason string is safe to surface to callers.
///
/// See module docs for the full list of rejected destinations and the
/// DNS-rebinding caveat.
pub fn check_outbound_url_no_ssrf(url: &str) -> Result<(), &'static str> {
    if !url.starts_with("https://") {
        return Err(
            "URL must use https:// — plaintext HTTP is not permitted for outbound requests",
        );
    }

    // MCP-196 (2026-05-08): reject URLs containing characters outside
    // the RFC 3986 unreserved + reserved + percent-encoding sets.
    // Pre-fix this function only validated the host (SSRF + IP form);
    // a URL like `https://example.com/<>:bad{}` passed because the
    // host extraction grabbed `example.com` and the path was ignored.
    // Persisted webhook URLs with such characters then silently failed
    // to send when the alert/breach fired (URL parse error in reqwest).
    // Allowed: alphanumeric + `-._~:/?#[]@!$&'()*+,;=%`. Anything else
    // (spaces, control chars, `<>"{}|\^` backtick, non-ASCII without
    // percent-encoding) is rejected loudly at config time.
    if let Some(bad) = url.chars().find(|c| !is_valid_url_char(*c)) {
        // Specific message paths so the operator knows which character
        // class tripped the check.
        if bad.is_whitespace() || bad.is_control() {
            return Err("URL contains whitespace or control characters; percent-encode them or remove");
        }
        return Err(
            "URL contains characters disallowed by RFC 3986 (e.g. < > \" { } | \\ ^ backtick); \
             percent-encode them or remove",
        );
    }

    // IPv6 addresses in URLs use bracket notation (RFC 3986): https://[::1]/path
    //
    // MCP-505: extract the authority component (before path/query/fragment),
    // then strip the userinfo (everything before the LAST '@') BEFORE
    // matching against blocklist patterns. Pre-fix the host extraction
    // for non-bracketed URLs split on `[/, ?, #, :]` — which preserved
    // the userinfo as part of the matched "host" string. So
    // `https://example.com@127.0.0.1/path` extracted
    // `host = "example.com@127.0.0.1"`, which matches no blocklist
    // entry — but `url::Url` (used by reqwest internally) parses
    // `example.com` as userinfo and connects to `127.0.0.1`. Real
    // SSRF bypass via the userinfo trick (RFC 3986 §3.2.1).
    let after_scheme = url.trim_start_matches("https://");
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    // Last '@' in the authority is the userinfo terminator; everything
    // after it is host + optional :port (or bracketed-IPv6 + :port).
    let host_and_port: &str = match authority.rfind('@') {
        Some(at) => &authority[at + 1..],
        None => authority,
    };
    let host = if host_and_port.starts_with('[') {
        host_and_port
            .trim_start_matches('[')
            .split(']')
            .next()
            .unwrap_or("")
            .to_lowercase()
    } else {
        host_and_port
            .split(':')
            .next()
            .unwrap_or("")
            .to_lowercase()
    };

    if looks_like_obfuscated_ipv4(&host) {
        return Err(
            "URL host uses a non-canonical IPv4 encoding (octal, hex, integer, or zero-padded). \
             Use a hostname or canonical dotted-decimal form (e.g. 192.0.2.1).",
        );
    }

    let ipv4_is_blocked = |addr: &str| -> bool {
        addr == "127.0.0.1"
            || addr.starts_with("10.")
            || addr.starts_with("192.168.")
            || addr.starts_with("169.254.")
            || (addr.starts_with("172.") && {
                let oct: u8 = addr
                    .split('.')
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                (16..=31).contains(&oct)
            })
            // MCP-542: CGNAT (100.64.0.0/10, RFC 6598). Shared-address-
            // space for carrier-grade NAT; ALSO used by AWS PrivateLink,
            // GCP internal load balancers, and other cloud-internal
            // endpoints. The worker's `classify_private_ip` covers this
            // (and so does the worker error-sanitiser per MCP-530) but
            // this canonical SSRF guard didn't — leaving a gap for
            // background webhook fires that point at cloud-internal
            // 100.64.x.x services.
            || (addr.starts_with("100.") && {
                let oct: u8 = addr
                    .split('.')
                    .nth(1)
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0);
                (64..=127).contains(&oct)
            })
    };

    let ipv4_mapped_part: Option<String> = if let Some(rest) = host.strip_prefix("::ffff:") {
        Some(rest.to_string())
    } else {
        host.strip_prefix("0:0:0:0:0:ffff:")
            .map(|rest| rest.to_string())
    };

    // If the IPv4-mapped part itself is obfuscated (e.g. ::ffff:0177.0.0.1),
    // reject before passing it through the literal-prefix block check.
    if let Some(ref mapped) = ipv4_mapped_part {
        if looks_like_obfuscated_ipv4(mapped) {
            return Err(
                "URL host uses a non-canonical IPv4 encoding (octal, hex, integer, or zero-padded). \
                 Use a hostname or canonical dotted-decimal form (e.g. 192.0.2.1).",
            );
        }
    }

    let blocked = matches!(
        host.as_str(),
        "localhost" | "127.0.0.1" | "::1" | "0.0.0.0"
            | "0:0:0:0:0:0:0:1"
            | "169.254.169.254"   // AWS/GCP/Azure metadata
            | "metadata.google.internal"
    ) || host.starts_with("127.")  // entire 127.0.0.0/8 loopback range
        // MCP-1067 (2026-05-15): entire 0.0.0.0/8 IPv4 unspecified
        // range. Pre-fix only the literal `"0.0.0.0"` exact match
        // was caught; `0.0.0.1`, `0.0.0.42`, `0.255.255.255` slipped
        // through. On Linux the kernel routes `0.x.y.z` to
        // `127.0.0.1` so an attacker who supplies `http://0.0.0.1:8080`
        // gets loopback access. This is the talos-http-utils sibling
        // of the worker's MCP-553 fix (`classify_private_ipv4` uses
        // `addr.is_unspecified()` for the same coverage). Same
        // hostname false-positive trade-off as `host.starts_with("10.")`
        // / `host.starts_with("172.")` — defense-in-depth over a rare
        // legitimate hostname (`0.example.com`).
        || host.starts_with("0.")
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || (host.starts_with("172.") && {
            let oct: u8 = host
                .split('.')
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            (16..=31).contains(&oct)
        })
        // MCP-542: CGNAT 100.64.0.0/10. See `ipv4_is_blocked` for
        // rationale (cloud-internal services frequently live here).
        || (host.starts_with("100.") && {
            let oct: u8 = host
                .split('.')
                .nth(1)
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            (64..=127).contains(&oct)
        })
        // MCP-1071 (2026-05-15): IPv4 multicast (224.0.0.0/4).
        // Sibling-parity with the worker's `classify_private_ipv4`
        // (`addr.is_multicast()`) and the WASI socket gate
        // (`ip.is_multicast()`). Pre-fix ssrf.rs caught IPv6
        // multicast via the post-parse `v6.is_multicast()` arm but
        // had no IPv4 equivalent — a controller-side caller
        // (`talos-execution-orchestration::failure_webhook`,
        // `talos-engine::approval_gate`, `talos-audit-ledger`,
        // GraphQL config validation) submitting `http://224.0.0.1/`
        // (link-local multicast) passed the guard. Threat is bounded
        // (most VMs don't route multicast) but the three SSRF
        // surfaces should agree on what's blocked. First-octet
        // range 224..=239 matches the IANA multicast block.
        || {
            let oct: u8 = host
                .split('.')
                .next()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            (224..=239).contains(&oct)
        }
        || host.starts_with("169.254.")
        || host.starts_with("fc") // IPv6 ULA fc00::/7 (lower half)
        || host.starts_with("fd") // IPv6 ULA fc00::/7 (upper half)
        || host.starts_with("fe80") // IPv6 link-local
        || ipv4_mapped_part
            .as_deref()
            .map(ipv4_is_blocked)
            .unwrap_or(false)
        || host.is_empty();

    if blocked {
        return Err(
            "URL points to a blocked destination (localhost, private IP, or cloud metadata endpoint)",
        );
    }

    // MCP-458: parse the host as IPv6 and check `.to_ipv4_mapped()`
    // to catch the pure-hex IPv4-mapped IPv6 bypass. Pre-fix
    // `[::ffff:7f00:1]` slipped through every literal-prefix check —
    // the strip_prefix(`::ffff:`) above produced `7f00:1` which
    // doesn't match dotted-decimal patterns like `127.` — but the OS
    // resolves the whole IPv6 to 127.0.0.1 and reqwest connects to
    // loopback. Cases caught by this gate that string-prefix matches
    // can't see:
    //   * `::ffff:7f00:1`        (hex form of ::ffff:127.0.0.1)
    //   * `::ffff:a00:1`         (hex form of ::ffff:10.0.0.1)
    //   * `0:0:0:0:0:ffff:7f00:1` (expanded hex form)
    //   * any compressed-zero form (`0::ffff:7f00:1`, etc.)
    //
    // We also reject IPv6 loopback / unspecified / link-local / ULA
    // here for cases the literal-prefix check missed (e.g.
    // `[0:0:0:0:0:0:0:1]` vs `[::1]`).
    // IP-literal hosts skip the resolve-time SSRF gate (reqwest connects to a
    // literal directly, no DNS), so the canonical classifier is applied here on
    // the parsed address. This catches every IPv6 spelling of an internal
    // target — loopback/unspecified/link-local/ULA/site-local, IPv4-mapped
    // (`::ffff:7f00:1`), and the other IPv4-in-IPv6 transition forms
    // (IPv4-compatible, NAT64 `64:ff9b::/96`, 6to4 `2002::/16`) that the
    // string-prefix checks above can't see (MCP-458/542/1068 + the 2026-05-31
    // transition-form sweep, now in talos-ssrf-classify).
    if let Ok(v6) = std::net::Ipv6Addr::from_str(&host) {
        if classify_private_ip(std::net::IpAddr::V6(v6)).is_some() {
            return Err(
                "URL points to a blocked destination (localhost, private IP, or cloud metadata endpoint)",
            );
        }
    }

    // Finally: any host that parses as a strict-canonical Ipv4Addr but
    // wasn't caught above is a public IP we permit. Anything that looked
    // like dotted decimal but failed the strict parse was already rejected
    // by `looks_like_obfuscated_ipv4`. No additional canonical-IPv4 work
    // needed here — kept this comment so future maintainers don't try to
    // add a second parsing layer.
    let _ = std::net::Ipv4Addr::from_str(&host).ok();

    Ok(())
}

// The SSRF private-IP classifier is the single source of truth in
// `talos-ssrf-classify` (std-only, shared with the WASM-host worker so a
// hardening fix lands in one place for both gates). Re-exported here so the
// existing `talos_http_utils::ssrf::classify_private_ip` import path — used by
// this crate's connect-time DNS resolver and by talos-mcp-handlers — keeps
// resolving.
pub use talos_ssrf_classify::classify_private_ip;

#[cfg(test)]
mod classify_private_ip_tests {
    use super::classify_private_ip;
    use std::net::IpAddr;
    use std::str::FromStr;

    fn ip(s: &str) -> IpAddr {
        IpAddr::from_str(s).unwrap()
    }

    #[test]
    fn allows_public_ipv4_and_ipv6() {
        assert!(classify_private_ip(ip("8.8.8.8")).is_none());
        assert!(classify_private_ip(ip("1.1.1.1")).is_none());
        assert!(classify_private_ip(ip("2606:4700:4700::1111")).is_none());
    }

    #[test]
    fn rejects_loopback_private_linklocal_metadata() {
        assert!(classify_private_ip(ip("127.0.0.1")).is_some());
        assert!(classify_private_ip(ip("10.0.0.5")).is_some());
        assert!(classify_private_ip(ip("172.16.3.4")).is_some());
        assert!(classify_private_ip(ip("192.168.1.1")).is_some());
        assert!(classify_private_ip(ip("169.254.169.254")).is_some()); // cloud metadata
        assert!(classify_private_ip(ip("0.0.0.0")).is_some());
        assert!(classify_private_ip(ip("0.1.2.3")).is_some()); // 0.0.0.0/8
        assert!(classify_private_ip(ip("100.64.0.1")).is_some()); // CGNAT
    }

    #[test]
    fn rejects_ipv6_loopback_ula_linklocal_and_mapped_v4() {
        assert!(classify_private_ip(ip("::1")).is_some());
        assert!(classify_private_ip(ip("fe80::1")).is_some());
        assert!(classify_private_ip(ip("fc00::1")).is_some());
        assert!(classify_private_ip(ip("::")).is_some());
        // ::ffff:169.254.169.254 — metadata via IPv4-mapped IPv6.
        assert!(classify_private_ip(ip("::ffff:169.254.169.254")).is_some());
        // ::ffff:10.0.0.1 — RFC-1918 via mapped IPv6.
        assert!(classify_private_ip(ip("::ffff:10.0.0.1")).is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::check_outbound_url_no_ssrf;

    #[test]
    fn rejects_plaintext_http() {
        assert!(check_outbound_url_no_ssrf("http://example.com/").is_err());
    }

    /// MCP-196 (2026-05-08): URLs containing RFC-3986-disallowed
    /// characters silently passed pre-fix because the host extraction
    /// only looked at the prefix. Now they reject loudly.
    #[test]
    fn rejects_rfc3986_disallowed_chars() {
        for url in [
            "https://example.com/<>:bad-chars{}",
            "https://example.com/path|with|pipes",
            "https://example.com/path\\with\\backslash",
            "https://example.com/path\"with\"quotes",
            "https://example.com/path^with^caret",
            "https://example.com/path`with`backtick",
        ] {
            let err = check_outbound_url_no_ssrf(url).unwrap_err();
            assert!(
                err.contains("disallowed by RFC 3986"),
                "should reject {url}; got: {err}"
            );
        }
    }

    #[test]
    fn rejects_whitespace_and_control_chars() {
        for url in [
            "https://example.com/ space",
            "https://example.com/\tbad",
            "https://example.com/\nbad",
            "https://example.com/\rbad",
        ] {
            let err = check_outbound_url_no_ssrf(url).unwrap_err();
            assert!(
                err.contains("whitespace or control"),
                "should reject {url:?}; got: {err}"
            );
        }
    }

    #[test]
    fn accepts_well_formed_https_urls() {
        // Sanity check: legitimate URLs with all RFC-allowed characters
        // (gen-delims, sub-delims, percent-encoded sequences) still pass.
        for url in [
            "https://example.com/path",
            "https://example.com/path?query=1&other=2",
            "https://example.com/path#fragment",
            "https://example.com/path/with-dashes_and.dots",
            "https://example.com/percent-encoded%20space",
            "https://example.com:443/explicit-port",
            "https://user@example.com/with-userinfo",
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_ok(),
                "should accept {url}"
            );
        }
    }

    #[test]
    fn rejects_canonical_loopback_and_private_ranges() {
        for h in [
            "https://127.0.0.1/",
            "https://10.0.0.1/",
            "https://192.168.1.1/",
            "https://172.16.0.1/",
            "https://172.31.255.255/",
            "https://169.254.169.254/",
            "https://localhost/",
            "https://[::1]/",
        ] {
            assert!(check_outbound_url_no_ssrf(h).is_err(), "should reject {h}");
        }
    }

    #[test]
    fn rejects_octal_ipv4_loopback() {
        // 0177 (octal) = 127 — getaddrinfo accepts this as 127.0.0.1.
        assert!(check_outbound_url_no_ssrf("https://0177.0.0.1/").is_err());
    }

    #[test]
    fn rejects_hex_ipv4_loopback() {
        // 0x7f = 127.
        assert!(check_outbound_url_no_ssrf("https://0x7f.0.0.1/").is_err());
        // Full hex 0x7f000001.
        assert!(check_outbound_url_no_ssrf("https://0x7f000001/").is_err());
    }

    #[test]
    fn rejects_integer_ipv4_loopback() {
        // 2130706433 = 127.0.0.1 as a single integer.
        assert!(check_outbound_url_no_ssrf("https://2130706433/").is_err());
    }

    #[test]
    fn rejects_zero_padded_loopback() {
        // 127.000.000.001 — leading zeros, getaddrinfo still resolves.
        assert!(check_outbound_url_no_ssrf("https://127.000.000.001/").is_err());
    }

    #[test]
    fn rejects_loopback_subnet() {
        // 127.0.0.0/8 — even the non-".1" loopback range should be blocked.
        assert!(check_outbound_url_no_ssrf("https://127.42.42.42/").is_err());
    }

    /// MCP-1067: entire 0.0.0.0/8 unspecified range must reject. Pre-fix
    /// the exact-match `"0.0.0.0"` was caught but `0.0.0.1`,
    /// `0.42.42.42`, `0.255.255.255` slipped through. On Linux the
    /// kernel routes `0.x.y.z:PORT` to `127.0.0.1:PORT`.
    #[test]
    fn rejects_unspecified_ipv4_subnet() {
        for url in [
            "https://0.0.0.0/",
            "https://0.0.0.1/",
            "https://0.0.0.42/",
            "https://0.42.0.0/",
            "https://0.255.255.255/",
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "should reject {url}"
            );
        }
    }

    /// MCP-1071: IPv4 multicast 224.0.0.0/4 must reject. Pre-fix
    /// ssrf.rs blocked IPv6 multicast (`v6.is_multicast()`) but
    /// had no IPv4 equivalent — worker host_impl and WASI socket
    /// gate both block IPv4 multicast; ssrf.rs was the holdout.
    #[test]
    fn rejects_ipv4_multicast_range() {
        for url in [
            "https://224.0.0.1/",      // all-hosts link-local
            "https://224.0.0.251/",    // mDNS
            "https://239.255.255.250/", // SSDP
            "https://225.1.2.3/",
            "https://239.0.0.1/",
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "should reject multicast {url}"
            );
        }
    }

    /// MCP-1071: 240.0.0.0/4 (reserved, not multicast) and the boundary
    /// `223.255.255.255` and `240.0.0.1` should still PASS — the deny
    /// is strictly 224..=239 first-octet.
    #[test]
    fn accepts_addresses_adjacent_to_multicast_range() {
        for url in [
            "https://223.0.0.1/",
            "https://223.255.255.255/",
            "https://240.0.0.1/",
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_ok(),
                "should accept {url} (just outside multicast range)"
            );
        }
    }

    /// MCP-1068: IPv4-mapped IPv6 sibling of MCP-1067. Pre-fix
    /// `::ffff:0.0.0.1` had `v4.is_unspecified()` = false (only the
    /// exact zero address matches) and slipped through the v6 → v4
    /// mapping check. With `octets[0] == 0` added, the full /8 is
    /// blocked across both forms.
    #[test]
    fn rejects_unspecified_ipv4_mapped_ipv6() {
        for url in [
            "https://[::ffff:0.0.0.0]/",
            "https://[::ffff:0.0.0.1]/",
            "https://[::ffff:0.42.42.42]/",
            "https://[::ffff:0.255.255.255]/",
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "should reject {url}"
            );
        }
    }

    #[test]
    fn rejects_ipv4_mapped_v6_to_loopback() {
        assert!(check_outbound_url_no_ssrf("https://[::ffff:127.0.0.1]/").is_err());
        assert!(check_outbound_url_no_ssrf("https://[::ffff:0177.0.0.1]/").is_err());
    }

    /// MCP-458: pure-hex IPv4-mapped IPv6 forms must reject. Pre-fix
    /// the strip_prefix(`::ffff:`) check left `7f00:1` as the
    /// post-strip text, which doesn't match dotted-decimal patterns
    /// like `127.`. But the OS resolves the whole IPv6 to 127.0.0.1.
    #[test]
    fn rejects_pure_hex_ipv4_mapped_ipv6() {
        for url in [
            "https://[::ffff:7f00:1]/",                // ::ffff:127.0.0.1
            "https://[::ffff:a00:1]/",                 // ::ffff:10.0.0.1
            "https://[::ffff:c0a8:1]/",                // ::ffff:192.168.0.1
            "https://[::ffff:ac10:1]/",                // ::ffff:172.16.0.1
            "https://[0:0:0:0:0:ffff:7f00:1]/",        // expanded form
            "https://[::ffff:a9fe:a9fe]/",             // ::ffff:169.254.169.254 (cloud metadata)
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "MCP-458 regression: should reject pure-hex IPv4-mapped IPv6: {url}"
            );
        }
    }

    /// MCP-458: IPv6 loopback / link-local / ULA in expanded forms
    /// must reject. The literal-string `::1` is already caught; this
    /// pins the expanded-form variants that bypass the prefix match.
    #[test]
    fn rejects_ipv6_loopback_and_local_expanded_forms() {
        for url in [
            "https://[0:0:0:0:0:0:0:1]/",     // ::1 expanded
            "https://[fe80::1]/",             // link-local
            "https://[fc00::1]/",             // ULA
            "https://[fd00::1]/",             // ULA upper half
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "MCP-458 regression: should reject IPv6 special: {url}"
            );
        }
    }

    #[test]
    fn still_allows_legitimate_public_ipv6() {
        // 2606:4700:4700::1111 = Cloudflare DNS. Public IPv6 must continue to work.
        assert!(check_outbound_url_no_ssrf("https://[2606:4700:4700::1111]/").is_ok());
    }

    /// MCP-505: an attacker who controls a URL field can hide the real
    /// destination behind userinfo. RFC 3986 §3.2.1 says everything
    /// before the LAST '@' in the authority is userinfo — `url::Url`
    /// (used by reqwest internally) parses `example.com` here as
    /// userinfo and connects to `127.0.0.1`. Pre-fix the SSRF check
    /// extracted host as `"example.com@127.0.0.1"` which matched no
    /// blocklist entry and let the request through to loopback.
    #[test]
    fn rejects_ipv4_loopback_hidden_behind_userinfo() {
        for url in [
            "https://example.com@127.0.0.1/",
            "https://example.com@127.0.0.1:8080/path",
            "https://user:pass@10.0.0.1/admin",
            "https://anything@169.254.169.254/computeMetadata/v1/",
            "https://decoy.com@0177.0.0.1/", // userinfo + octal-loopback
            "https://decoy.com@0x7f.0.0.1/", // userinfo + hex-loopback
            "https://attacker@2130706433/", // userinfo + integer-loopback
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "MCP-505 regression: must reject userinfo-hidden loopback: {url}"
            );
        }
    }

    #[test]
    fn rejects_ipv6_loopback_hidden_behind_userinfo() {
        for url in [
            "https://example.com@[::1]/",
            "https://decoy@[::ffff:127.0.0.1]/",
            "https://attacker@[fe80::1]/",
            "https://anything@[fc00::1]/",
            "https://decoy@[::ffff:7f00:1]/", // pure-hex IPv4-mapped (MCP-458 surface)
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "MCP-505 regression: must reject userinfo-hidden IPv6 special: {url}"
            );
        }
    }

    #[test]
    fn userinfo_does_not_break_legitimate_public_hosts() {
        // Userinfo against a legitimate public host stays accepted.
        assert!(
            check_outbound_url_no_ssrf("https://user@example.com/path").is_ok(),
            "legitimate userinfo must still pass"
        );
        // Userinfo with @ in the password portion: only the LAST @
        // separates userinfo from host per RFC 3986.
        assert!(
            check_outbound_url_no_ssrf("https://user@example.com:pass@example.com/path").is_ok(),
            "multi-@ userinfo must use the LAST @ as the host separator"
        );
        // Same with multi-@ trick pointing to loopback — must still
        // reject (the LAST @ is the real authority boundary).
        assert!(
            check_outbound_url_no_ssrf("https://decoy@evil.com@127.0.0.1/").is_err(),
            "multi-@ userinfo pointing at loopback must reject"
        );
    }

    #[test]
    fn allows_canonical_public_ipv4() {
        // RFC-5737 documentation range, definitely public.
        assert!(check_outbound_url_no_ssrf("https://192.0.2.1/").is_ok());
    }

    /// MCP-542: CGNAT 100.64.0.0/10 (RFC 6598). Cloud-internal endpoints
    /// (AWS PrivateLink, GCP internal LBs) frequently live in this
    /// range. Pre-fix it slipped past the canonical guard while the
    /// worker's own classify_private_ip already covered it.
    #[test]
    fn rejects_cgnat_range() {
        for url in [
            "https://100.64.0.1/",      // lower boundary
            "https://100.64.255.255/",  // mid lower-byte
            "https://100.127.255.254/", // upper boundary
            "https://100.65.0.1/",      // typical AWS PrivateLink shape
            "https://100.100.100.100/", // round inside-range probe
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "MCP-542: must reject CGNAT host: {url}"
            );
        }
    }

    /// MCP-542: 100.0.0.0/8 boundary — only 100.64.0.0–100.127.255.255
    /// is CGNAT. 100.0–63.x and 100.128–255.x are public allocations.
    /// Tripwire so a future "block all 100.x" overreach can't sneak in.
    #[test]
    fn allows_non_cgnat_in_100_block() {
        for url in [
            "https://100.0.0.1/",      // public ARIN allocation
            "https://100.63.255.255/", // just below CGNAT
            "https://100.128.0.1/",    // just above CGNAT
            "https://100.255.255.255/",
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_ok(),
                "MCP-542: must NOT reject non-CGNAT public 100.x: {url}"
            );
        }
    }

    /// MCP-542: CGNAT via IPv4-mapped IPv6 hex form. Same surface as
    /// MCP-458's pure-hex 127.x bypass — `[::ffff:6440:1]` = 100.64.0.1.
    /// Goes through the `to_ipv4_mapped()` path, which uses
    /// `Ipv4Addr::is_private()` (RFC-1918 only, NOT CGNAT) — we added
    /// an explicit CGNAT check alongside `is_private`.
    #[test]
    fn rejects_cgnat_via_ipv4_mapped_ipv6() {
        for url in [
            "https://[::ffff:6440:1]/",          // ::ffff:100.64.0.1
            "https://[::ffff:100.64.0.1]/",      // dotted form, also CGNAT
            "https://[::ffff:100.127.255.254]/", // upper-end CGNAT
            "https://[::ffff:647f:fffe]/",       // hex form of 100.127.255.254
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "MCP-542: must reject CGNAT via IPv4-mapped IPv6: {url}"
            );
        }
    }

    /// MCP-542: userinfo + CGNAT — combines MCP-505 (userinfo-hidden
    /// loopback) and MCP-542 (CGNAT). An attacker who knows the gap
    /// exists could combine both tricks; lock both surfaces.
    #[test]
    fn rejects_cgnat_hidden_behind_userinfo() {
        for url in [
            "https://example.com@100.64.0.1/",
            "https://user:pass@100.100.100.100/admin",
            "https://decoy@[::ffff:100.64.0.1]/",
        ] {
            assert!(
                check_outbound_url_no_ssrf(url).is_err(),
                "MCP-542: must reject userinfo-hidden CGNAT: {url}"
            );
        }
    }

    #[test]
    fn allows_normal_hostname() {
        assert!(check_outbound_url_no_ssrf("https://example.com/").is_ok());
        assert!(check_outbound_url_no_ssrf("https://api.partner.io/v1/foo").is_ok());
    }
}
