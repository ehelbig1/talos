//! Error-message sanitization for operator/client-facing strings —
//! strips file paths, line numbers and internal IP addresses, and
//! truncates to a bounded length. Extracted verbatim from `main.rs`.

use std::sync::OnceLock;

// ============================================================================
// SECURITY: Static regex compilation — compiled exactly once at first use.
// Recompiling regexes on every call wastes CPU and can cause latency spikes.
// ============================================================================

static RE_UNIX_PATH: OnceLock<regex::Regex> = OnceLock::new();
static RE_WIN_PATH: OnceLock<regex::Regex> = OnceLock::new();
static RE_LINE_NUM: OnceLock<regex::Regex> = OnceLock::new();
static RE_INTERNAL_IP: OnceLock<regex::Regex> = OnceLock::new();

fn unix_path_re() -> &'static regex::Regex {
    RE_UNIX_PATH
        .get_or_init(|| regex::Regex::new(r"/[\w/.-]+\.(rs|toml|json)").expect("invalid regex"))
}

fn win_path_re() -> &'static regex::Regex {
    RE_WIN_PATH.get_or_init(|| {
        regex::Regex::new(r"[A-Z]:\\[\w\\.-]+\.(rs|toml|json)").expect("invalid regex")
    })
}

fn line_num_re() -> &'static regex::Regex {
    RE_LINE_NUM.get_or_init(|| regex::Regex::new(r":\d+:\d+").expect("invalid regex"))
}

fn internal_ip_re() -> &'static regex::Regex {
    // MCP-530: the original three alternatives missed every other
    // RFC-1918 / loopback / link-local range. Real error messages
    // commonly include:
    //   * 172.16.0.0/12 (RFC 1918) — covers Docker default bridge
    //     networks (`172.17.0.0/16`), most Kubernetes service
    //     CIDRs, AWS / GCP / Azure default VPC subnets.
    //   * 169.254.0.0/16 (RFC 3927 link-local) — includes
    //     169.254.169.254 (AWS / GCP / Azure / DO IMDS / metadata
    //     endpoint). Leaking this in an error message tells an
    //     attacker exactly which cloud the worker is running on.
    //   * 100.64.0.0/10 (RFC 6598 CGNAT) — used by some cloud
    //     load-balancer health-check origin IPs.
    //   * 127.0.0.0/8 (loopback) — only `127.0.0.1` was caught,
    //     so `127.0.0.53` (systemd-resolved), `127.0.1.1`
    //     (Ubuntu hostname), etc. leaked through.
    //
    // IPv6 deliberately omitted: matching it precisely in a regex
    // is verbose and the worker's error surfaces today only carry
    // IPv4. If a future production surface produces IPv6 internal
    // addresses, extend then.
    RE_INTERNAL_IP.get_or_init(|| {
        regex::Regex::new(
            r"(?x)
            10\.\d+\.\d+\.\d+
            |
            127\.\d+\.\d+\.\d+
            |
            169\.254\.\d+\.\d+
            |
            172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+
            |
            192\.168\.\d+\.\d+
            |
            100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d+\.\d+
            ",
        )
        .expect("invalid regex")
    })
}

// ============================================================================
// SECURITY: Error Message Sanitization
// Prevent information disclosure by removing file paths and sensitive data.
// ============================================================================

/// Sanitize error messages before sending to clients.
///
/// Removes: **secrets** (DLP), file paths, line numbers, internal IP addresses.
/// Truncates to 2000 characters (Unicode-safe).
///
/// # Why DLP runs here, and why it runs FIRST
///
/// This function is the shared truncator for the worker's error surfaces
/// (`worker/src/main.rs` job + pipeline failure paths,
/// [`crate::module_fetcher`], [`crate::reason_class::sanitized_transport_detail`]).
/// It historically performed no secret redaction whatsoever, so whether an
/// `sk-*` / `ghp_*` / `Bearer …` value echoed by an upstream API survived
/// depended entirely on whether the individual caller had remembered to wrap
/// its input — `sanitized_transport_detail` had, the two `main.rs` sites had
/// not.
///
/// Redaction is placed **before** the truncation for a specific reason:
/// truncating first can cut a token across the 2000-char bound so that no
/// pattern matches it any more, leaving an unredacted prefix in the output.
/// Order matters here even though both steps are individually correct.
///
/// Callers that already redact (`sanitized_transport_detail`) are unaffected —
/// redaction is idempotent.
pub fn sanitize_error_message(error: &str) -> String {
    // FIRST: secrets. See the doc comment above for why this cannot be moved
    // below the truncation.
    let mut sanitized = talos_dlp_provider::redact_str_failsafe(error).into_owned();

    sanitized = unix_path_re()
        .replace_all(&sanitized, "[FILE]")
        .into_owned();
    sanitized = win_path_re().replace_all(&sanitized, "[FILE]").into_owned();
    sanitized = line_num_re().replace_all(&sanitized, "").into_owned();
    sanitized = internal_ip_re()
        .replace_all(&sanitized, "[INTERNAL_IP]")
        .into_owned();

    // Unicode-safe truncation: count chars, not bytes.
    let char_count = sanitized.chars().count();
    if char_count > 2000 {
        let truncated: String = sanitized.chars().take(2000).collect();
        format!("{}... [truncated]", truncated)
    } else {
        sanitized
    }
}

#[cfg(test)]
mod sanitize_error_message_tests {
    //! MCP-530: pin the internal-IP coverage. Pre-fix only
    //! 192.168/16, 10/8, and the literal 127.0.0.1 were redacted.
    //! Every other RFC-1918 / loopback / link-local / CGNAT range
    //! leaked through. Cloud-metadata 169.254.169.254 is the
    //! highest-value redaction target — its presence in an error
    //! message would tell an attacker exactly which cloud the
    //! worker runs on.
    use super::sanitize_error_message;

    #[test]
    fn redacts_192_168_subnet() {
        let s = sanitize_error_message("error connecting to 192.168.1.42:5432");
        assert!(s.contains("[INTERNAL_IP]"));
        assert!(!s.contains("192.168.1.42"));
    }

    #[test]
    fn redacts_10_dot_subnet() {
        let s = sanitize_error_message("upstream 10.0.5.7 timeout");
        assert!(s.contains("[INTERNAL_IP]"));
        assert!(!s.contains("10.0.5.7"));
    }

    #[test]
    fn redacts_172_16_through_31_rfc1918() {
        // 172.16/12 — covers Docker default bridge (172.17/16) and
        // many cloud default subnets. Pre-MCP-530 these leaked.
        for ip in &[
            "172.16.0.1",
            "172.17.0.1", // docker0 default
            "172.20.5.10",
            "172.28.0.42",
            "172.31.255.254",
        ] {
            let s = sanitize_error_message(&format!("dial {} refused", ip));
            assert!(
                s.contains("[INTERNAL_IP]"),
                "RFC-1918 172/12 address must be redacted: {ip}"
            );
            assert!(!s.contains(ip), "raw {ip} must not leak");
        }
    }

    #[test]
    fn does_not_redact_172_outside_rfc1918() {
        // 172.15.x.x and 172.32.x.x are NOT RFC 1918 — they are
        // public address space. Must NOT be redacted (operators
        // debugging external upstream connectivity need them).
        for ip in &["172.15.0.1", "172.32.0.1", "172.100.0.1"] {
            let s = sanitize_error_message(&format!("dial {} refused", ip));
            assert!(
                !s.contains("[INTERNAL_IP]"),
                "{ip} is public 172/8 space; must NOT be redacted"
            );
        }
    }

    #[test]
    fn redacts_link_local_and_cloud_metadata() {
        // 169.254/16 — the cloud-metadata-server case
        // (169.254.169.254) is the highest-value redaction here.
        for ip in &["169.254.169.254", "169.254.0.1", "169.254.255.254"] {
            let s = sanitize_error_message(&format!("HTTP request to {} returned 401", ip));
            assert!(
                s.contains("[INTERNAL_IP]"),
                "link-local / IMDS {ip} must be redacted"
            );
            assert!(!s.contains(ip), "raw {ip} must not leak");
        }
    }

    #[test]
    fn redacts_cgnat_rfc6598() {
        // 100.64.0.0/10 (100.64.0.0 – 100.127.255.255)
        for ip in &["100.64.0.1", "100.100.5.7", "100.127.255.254"] {
            let s = sanitize_error_message(&format!("origin {} ", ip));
            assert!(s.contains("[INTERNAL_IP]"), "CGNAT {ip} must be redacted");
        }
        // Boundary: 100.63.x.x and 100.128.x.x are OUTSIDE CGNAT.
        for ip in &["100.63.0.1", "100.128.0.1"] {
            let s = sanitize_error_message(&format!("origin {}", ip));
            assert!(
                !s.contains("[INTERNAL_IP]"),
                "{ip} is outside CGNAT; must NOT be redacted"
            );
        }
    }

    #[test]
    fn redacts_full_127_loopback() {
        // Pre-MCP-530 only the literal 127.0.0.1 was caught.
        // 127.0.0.53 (systemd-resolved), 127.0.1.1 (Ubuntu
        // /etc/hosts hostname), 127.x.x.x in general are all
        // loopback.
        for ip in &["127.0.0.1", "127.0.0.53", "127.0.1.1", "127.255.255.254"] {
            let s = sanitize_error_message(&format!("connect {} refused", ip));
            assert!(s.contains("[INTERNAL_IP]"), "127/8 {ip} must be redacted");
        }
    }

    #[test]
    fn does_not_redact_public_ip() {
        for ip in &["1.1.1.1", "8.8.8.8", "203.0.113.5", "172.15.0.1"] {
            let s = sanitize_error_message(&format!("dial {} refused", ip));
            assert!(
                !s.contains("[INTERNAL_IP]"),
                "public {ip} must NOT be redacted"
            );
        }
    }

    // ====================================================================
    // Secret redaction, and its ORDER relative to truncation.
    // ====================================================================
    //
    // Before this, `sanitize_error_message` performed exactly four transforms
    // (unix path, windows path, line numbers, internal IP) and then truncated
    // — no secret redaction at any point. Its two `worker/src/main.rs` callers
    // pass WASM guest error text straight into it.

    /// Obviously-fake fixtures, one per relevant
    /// `talos_dlp_provider::PATTERN_SPECS` arm. `AKIAIOSFODNN7EXAMPLE` is AWS's
    /// own published documentation example.
    const SECRET_FIXTURES: &[(&str, &str)] = &[
        ("openai_style", "sk-TESTONLYabcdefghijklmnop"),
        ("github_pat", "ghp_TESTONLYabcdefghijklmnop"),
        ("bearer", "Bearer TESTONLYabcdefghijklmnop"),
        ("aws_access_key", "AKIAIOSFODNN7EXAMPLE"),
        (
            "jwt",
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJURVNUT05MWSJ9.c2lnVEVTVE9OTFk",
        ),
    ];

    fn secret_part(fixture: &str) -> &str {
        fixture.strip_prefix("Bearer ").unwrap_or(fixture)
    }

    #[test]
    fn redacts_every_secret_fixture() {
        for (name, fixture) in SECRET_FIXTURES {
            let out = sanitize_error_message(&format!(
                "execution failure: upstream returned 401 for {fixture}"
            ));
            assert!(
                !out.contains(secret_part(fixture)),
                "{name}: secret survived sanitization: {out}"
            );
            assert!(out.contains("[REDACTED"), "{name}: no redaction tag: {out}");
        }
    }

    #[test]
    fn redaction_runs_before_truncation() {
        // A token that STRADDLES the 2000-char truncation bound. If truncation
        // ran first, the cut would split the token, no pattern would match the
        // surviving prefix, and that prefix would be returned.
        //
        // The padding is separated by a space because the DLP API_KEY pattern
        // is `\b`-anchored: a token glued directly to a preceding word
        // character does not match it at all, which would make this test pass
        // for the wrong reason.
        // The AWS access-key pattern `\bA[KS]IA[0-9A-Z]{16}\b` needs the WHOLE
        // key, so a truncate-first implementation emits 15 of its 20
        // characters unredacted. A short-prefix fixture would not prove this:
        // `sk-TESTONLY…` was tried first and a truncate-first mutation
        // SURVIVED it, because `sk-` plus six characters already matches.
        let fixture = "AKIAIOSFODNN7EXAMPLE";
        let leaked_prefix = "AKIAIOSFODNN7EX";
        let pad = "p".repeat(2000 - 16);
        let out = sanitize_error_message(&format!("{pad} {fixture} trailing"));
        assert!(
            !out.contains(leaked_prefix),
            "an unredacted prefix survived the truncation bound: {out}"
        );
        assert!(!out.contains("AKIA"), "{out}");
        assert!(out.contains("[REDACTED"), "{out}");
    }

    #[test]
    fn still_strips_ips_and_paths_after_the_change() {
        // The pre-existing contract must be unchanged by adding DLP in front.
        let out =
            sanitize_error_message("panic at /app/src/runtime.rs:42:7 dialing 169.254.169.254");
        assert!(out.contains("[FILE]"), "{out}");
        assert!(out.contains("[INTERNAL_IP]"), "{out}");
        assert!(!out.contains("169.254.169.254"), "{out}");
    }

    #[test]
    fn clean_operator_text_is_left_alone() {
        for s in [
            "execution timed out after 30 seconds",
            "Signature verification failed",
            "WASM trap encountered",
        ] {
            assert_eq!(sanitize_error_message(s), s, "over-redacted: {s}");
        }
    }
}
