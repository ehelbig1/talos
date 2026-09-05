//! Unit tests for the verifying security audit.
//!
//! The tests that matter most are the PRESENT-BUT-BROKEN ones. Each converted
//! check has at least one: a configuration that every presence test in the
//! world grades green, and that the round trip catches.

use super::*;

// ───────────────────────────────────────────────────────────────────────────
// jwt_algorithm
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn jwt_verified_symmetric_passes_on_single_pod() {
    let c = check_jwt_algorithm(
        talos_auth::JwtSelfTest::Verified {
            algorithm: "HS256",
            asymmetric: false,
        },
        "single_pod",
    );
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.points, 10);
    assert_eq!(c.verification, Verification::RoundTrip);
    assert!(c.detail.contains("alg=HS256"));
}

#[test]
fn jwt_verified_symmetric_warns_on_microservices() {
    let c = check_jwt_algorithm(
        talos_auth::JwtSelfTest::Verified {
            algorithm: "HS256",
            asymmetric: false,
        },
        "microservices",
    );
    assert_eq!(c.status, Status::Warn);
    assert_eq!(c.points, 5, "the microservices deduction is unchanged");
}

#[test]
fn jwt_verified_asymmetric_passes_regardless_of_topology() {
    for topology in ["single_pod", "microservices"] {
        let c = check_jwt_algorithm(
            talos_auth::JwtSelfTest::Verified {
                algorithm: "RS256",
                asymmetric: true,
            },
            topology,
        );
        assert_eq!(c.status, Status::Pass);
        assert_eq!(c.points, 10);
    }
}

/// PRESENT BUT BROKEN. `JWT_ALGORITHM=RS256` with no PEM key material scored
/// the BEST possible outcome under the presence check — "asymmetric
/// (recommended)", full marks — while the process could not mint a token.
#[test]
fn jwt_broken_key_material_fails_and_never_reads_as_configured() {
    let c = check_jwt_algorithm(
        talos_auth::JwtSelfTest::Broken {
            stage: "key_material",
        },
        "single_pod",
    );
    assert_eq!(
        c.status,
        Status::Fail,
        "present-but-non-functional must not collapse into warn"
    );
    assert_eq!(c.points, 0);
    assert_eq!(c.verification, Verification::RoundTrip);
    assert!(c.detail.contains("NON-FUNCTIONAL"));
    assert!(
        !c.detail.contains("recommended"),
        "a broken control must never carry the language of a good one"
    );
}

#[test]
fn jwt_missing_secret_names_the_missing_variable() {
    let c = check_jwt_algorithm(
        talos_auth::JwtSelfTest::Broken { stage: "secret" },
        "single_pod",
    );
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("JWT_SECRET is not set"));
}

/// The underlying error never travels — key-parse errors can quote key bytes.
#[test]
fn jwt_broken_detail_carries_no_upstream_error_text() {
    for stage in ["key_material", "sign", "header", "verify"] {
        let c = check_jwt_algorithm(talos_auth::JwtSelfTest::Broken { stage }, "single_pod");
        assert!(
            c.detail.contains("event_kind=jwt_selftest_failed"),
            "the operator must be pointed at where the cause IS"
        );
    }
}

// ───────────────────────────────────────────────────────────────────────────
// master_encryption_key
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn kek_verified_passes_and_names_the_provider() {
    let c = check_master_encryption_key(Some(KekSelfTest::Verified {
        provider: "env".to_string(),
    }));
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.points, 15, "weight unchanged");
    assert_eq!(c.verification, Verification::RoundTrip);
    assert!(c.detail.contains("provider: env"));
}

/// PRESENT BUT BROKEN. The KEK is installed — so `TALOS_MASTER_KEY is
/// configured` was true and scored +15 — but nothing it wrapped can be
/// unwrapped.
#[test]
fn kek_failed_roundtrip_fails_with_zero_points() {
    for stage in ["wrap", "unwrap", "roundtrip"] {
        let c = check_master_encryption_key(Some(KekSelfTest::Failed {
            provider: "vault://transit/keys/talos-kek".to_string(),
            stage,
        }));
        assert_eq!(c.status, Status::Fail);
        assert_eq!(c.points, 0);
        assert_eq!(c.verification, Verification::RoundTrip);
        assert!(c.detail.contains("NON-FUNCTIONAL"));
        assert!(c.detail.contains(stage));
    }
}

/// A verification that could not run must be DISTINGUISHABLE from one that
/// ran and passed — the ⊘ SKIPPED lesson. A timeout is not a pass.
#[test]
fn kek_timeout_is_not_verified_and_is_not_a_pass() {
    let c = check_master_encryption_key(None);
    assert_eq!(c.verification, Verification::NotVerified);
    assert_ne!(c.status, Status::Pass);
    assert_eq!(c.points, 0);
    assert!(c.detail.starts_with("NOT VERIFIED"));
}

#[test]
fn kek_unavailable_is_not_verified() {
    let c = check_master_encryption_key(Some(KekSelfTest::Unavailable));
    assert_eq!(c.verification, Verification::NotVerified);
    assert_ne!(c.status, Status::Pass);
    assert!(c.detail.starts_with("NOT VERIFIED"));
}

// ───────────────────────────────────────────────────────────────────────────
// job_signing_key
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn job_signing_verified_passes() {
    let c = check_job_signing_key(JobSigningProbe::Verified);
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.points, 15, "weight unchanged");
    assert_eq!(c.verification, Verification::RoundTrip);
}

/// Control ABSENT keeps its historical `warn` — the operator was already told.
#[test]
fn job_signing_absent_keeps_its_historical_warn_and_wording() {
    let c = check_job_signing_key(JobSigningProbe::Absent);
    assert_eq!(c.status, Status::Warn);
    assert_eq!(
        c.detail, "WORKER_SHARED_KEY not set — job payloads are unsigned",
        "absent wording is byte-stable for existing dashboards"
    );
    assert_eq!(c.points, 0);
}

/// PRESENT BUT BROKEN outranks absent: `warn` for a missing key, `fail` for a
/// key that is set and cannot sign.
#[test]
fn job_signing_unusable_fails_harder_than_absent() {
    let absent = check_job_signing_key(JobSigningProbe::Absent);
    let unusable = check_job_signing_key(JobSigningProbe::Unusable);
    assert_eq!(absent.status, Status::Warn);
    assert_eq!(unusable.status, Status::Fail);
    assert_eq!(unusable.points, 0);
    assert!(unusable.detail.contains("SET but UNUSABLE"));
    // The hex parse error names a character of the key and its index.
    assert!(unusable.detail.contains("withheld"));
}

#[test]
fn job_signing_roundtrip_failure_fails() {
    let c = check_job_signing_key(JobSigningProbe::RoundTripFailed);
    assert_eq!(c.status, Status::Fail);
    assert_eq!(c.points, 0);
    assert_eq!(c.verification, Verification::RoundTrip);
}

/// The probe runs against the process's real `WORKER_SHARED_KEY` (absent in
/// the test environment) and must be repeatable — in particular it must not
/// consume a replay nonce, or the second run would fail.
#[test]
fn job_signing_probe_is_repeatable() {
    let first = probe_job_signing_key();
    let second = probe_job_signing_key();
    let third = probe_job_signing_key();
    assert_eq!(first, second);
    assert_eq!(second, third);
}

// ───────────────────────────────────────────────────────────────────────────
// aot_integrity_key
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn aot_valid_key_passes_but_says_it_was_not_exercised() {
    let c = check_aot_integrity_key(&"ab".repeat(32)); // 64 hex chars = 32 bytes
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.points, 10);
    assert_eq!(
        c.verification,
        Verification::ConfigPresence,
        "the enforcing key ring is the worker's; this cannot be a round trip"
    );
    assert!(c.detail.contains("Shape only"));
}

#[test]
fn aot_short_key_warns_with_the_decoded_length() {
    let c = check_aot_integrity_key(&"ab".repeat(16)); // 32 hex chars = 16 bytes
    assert_eq!(c.status, Status::Warn);
    assert_eq!(c.points, 0);
    assert!(c.detail.contains("16 bytes decoded"));
}

#[test]
fn aot_empty_key_is_info_not_fail() {
    let c = check_aot_integrity_key("");
    assert_eq!(c.status, Status::Info);
    assert_eq!(c.points, 0);
    assert!(c.detail.contains("ephemeral"));
}

/// Non-hex values are measured raw, matching the worker's `into_bytes()` path.
#[test]
fn aot_non_hex_key_is_measured_raw() {
    let c = check_aot_integrity_key(&"z".repeat(40));
    assert_eq!(c.status, Status::Pass);
    let short = check_aot_integrity_key(&"z".repeat(31));
    assert_eq!(short.status, Status::Warn);
}

// ───────────────────────────────────────────────────────────────────────────
// audit_event_signing
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn audit_signing_verified_passes() {
    let c = check_audit_event_signing(talos_audit_event::SigningSelfTest::Verified, true, true);
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.points, 10, "weight unchanged");
    assert_eq!(c.verification, Verification::RoundTrip);
}

#[test]
fn audit_signing_absent_keeps_its_historical_warn_and_wording() {
    let c = check_audit_event_signing(talos_audit_event::SigningSelfTest::NotSigned, false, false);
    assert_eq!(c.status, Status::Warn);
    assert_eq!(
        c.detail, "TALOS_AUDIT_SIGNING_KEY not set — audit events are unsigned",
        "absent wording is byte-stable for existing dashboards"
    );
    assert_eq!(c.points, 0);
}

/// THE case this whole change exists for. `TALOS_AUDIT_SIGNING_KEY` generated
/// with `openssl rand -hex 16` is present and non-empty, so the presence check
/// reported "Audit events are HMAC-signed for tamper detection" and awarded
/// +10 — while `audit_signing_key()` had rejected it at the 256-bit entropy
/// floor and every audit event went out unsigned.
#[test]
fn audit_signing_key_rejected_at_the_entropy_floor_fails_loudly() {
    let c = check_audit_event_signing(talos_audit_event::SigningSelfTest::NotSigned, true, false);
    assert_eq!(
        c.status,
        Status::Fail,
        "a key that is set and produces no signature is worse than no key"
    );
    assert_eq!(c.points, 0);
    assert_eq!(c.verification, Verification::RoundTrip);
    assert!(c.detail.contains("REJECTED at load"));
    assert!(
        !c.detail.contains("are HMAC-signed for tamper detection"),
        "must not reuse the wording of the passing case"
    );
}

#[test]
fn audit_signing_signer_verifier_disagreement_fails() {
    let c = check_audit_event_signing(
        talos_audit_event::SigningSelfTest::SignatureRejected,
        true,
        true,
    );
    assert_eq!(c.status, Status::Fail);
    assert_eq!(c.points, 0);
    assert!(c.detail.contains("verify_chain"));
}

// ───────────────────────────────────────────────────────────────────────────
// redis_tls
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn redis_probe_classifies_the_transports_the_client_will_use() {
    assert_eq!(probe_redis_transport(""), RedisTransport::NotConfigured);
    assert_eq!(
        probe_redis_transport("redis://127.0.0.1:6379"),
        RedisTransport::Plaintext
    );
    assert_eq!(
        probe_redis_transport("rediss://redis.example.com:6379"),
        RedisTransport::Tls
    );
    assert_eq!(
        probe_redis_transport("unix:///var/run/redis.sock"),
        RedisTransport::UnixSocket
    );
    assert_eq!(
        probe_redis_transport("not-a-redis-url"),
        RedisTransport::Unparseable
    );
}

/// PRESENT BUT BROKEN, and invisible to the prefix test: this URL starts with
/// `rediss://`, so `starts_with("rediss://")` reported "Redis using TLS
/// (rediss://)" and awarded +10 — for a connection that accepts ANY
/// certificate.
#[test]
fn redis_insecure_fragment_is_caught_although_the_prefix_says_tls() {
    const URL: &str = "rediss://redis.example.com:6379/#insecure";
    assert!(
        URL.starts_with("rediss://"),
        "the old prefix test passes this URL"
    );
    assert_eq!(probe_redis_transport(URL), RedisTransport::TlsInsecure);

    let c = check_redis_tls(RedisTransport::TlsInsecure, false);
    assert_eq!(c.status, Status::Fail);
    assert_eq!(c.points, 0);
    assert!(c.detail.contains("verification DISABLED"));
}

/// An unparseable URL also starts with a plausible scheme and would have
/// scored +10 in production under a prefix test.
#[test]
fn redis_unparseable_url_fails_and_never_echoes_the_url() {
    const URL: &str = "rediss://user:hunter2@@@:::/bad";
    let transport = probe_redis_transport(URL);
    let c = check_redis_tls(transport, true);
    assert_eq!(transport, RedisTransport::Unparseable);
    assert_eq!(c.status, Status::Fail);
    assert!(
        !c.detail.contains("hunter2"),
        "a Redis URL can embed a password; it must never be echoed"
    );
}

#[test]
fn redis_plaintext_grades_by_environment_as_before() {
    assert_eq!(
        check_redis_tls(RedisTransport::Plaintext, false).status,
        Status::Info
    );
    assert_eq!(
        check_redis_tls(RedisTransport::Plaintext, true).status,
        Status::Fail
    );
    assert_eq!(check_redis_tls(RedisTransport::Plaintext, true).points, 0);
}

#[test]
fn redis_tls_scores_ten_as_before() {
    let c = check_redis_tls(RedisTransport::Tls, true);
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.points, 10);
}

#[test]
fn redis_not_configured_scores_zero_and_stays_pass() {
    let c = check_redis_tls(RedisTransport::NotConfigured, false);
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.points, 0, "an unconfigured Redis earns nothing");
    assert_eq!(c.detail, "Redis not configured");
}

/// The probe must not open a socket — it is called from an interactive
/// handler. A URL pointing at a black-hole address returns immediately.
#[test]
fn redis_probe_does_no_network_io() {
    let start = std::time::Instant::now();
    // 198.51.100.0/24 is TEST-NET-2: guaranteed unroutable. A connecting
    // probe would block here until its connect timeout.
    let _ = probe_redis_transport("rediss://198.51.100.7:6379");
    assert!(
        start.elapsed() < std::time::Duration::from_millis(200),
        "probe_redis_transport must parse only; it took {:?}",
        start.elapsed()
    );
}

// ───────────────────────────────────────────────────────────────────────────
// audit_immutability_triggers
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn triggers_present_passes_with_the_historical_wording() {
    let c = check_audit_immutability_triggers(Some(4));
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.points, 10);
    assert_eq!(c.detail, "4 immutability trigger(s) active");
}

#[test]
fn triggers_absent_fails_with_the_historical_wording() {
    let c = check_audit_immutability_triggers(Some(0));
    assert_eq!(c.status, Status::Fail);
    assert_eq!(
        c.detail,
        "No audit immutability triggers found — run migrations"
    );
}

/// A failed query is "nobody looked", not "the triggers are missing". The old
/// `unwrap_or(0)` sent operators to re-run migrations over a database blip.
#[test]
fn triggers_query_failure_is_not_verified_and_does_not_blame_migrations() {
    let c = check_audit_immutability_triggers(None);
    assert_eq!(c.verification, Verification::NotVerified);
    assert_ne!(c.status, Status::Pass);
    assert_eq!(c.points, 0);
    assert!(c.detail.starts_with("NOT VERIFIED"));
    assert!(!c.detail.contains("run migrations"));
}

// ───────────────────────────────────────────────────────────────────────────
// cors_origins
// ───────────────────────────────────────────────────────────────────────────

#[test]
fn cors_explicit_list_passes_and_reports_the_parsed_count() {
    let parsed = Ok(vec![
        "https://a.example".to_string(),
        "https://b.example".to_string(),
    ]);
    let c = check_cors_origins(&parsed, true);
    assert_eq!(c.status, Status::Pass);
    assert_eq!(c.points, 10, "weight unchanged");
    assert_eq!(c.verification, Verification::Parsed);
    assert!(
        c.detail.contains("2 enforced origin(s)"),
        "the count is the finding: {}",
        c.detail
    );
}

/// PRESENT BUT BROKEN. `ALLOWED_ORIGIN=","` is non-empty, so the presence test
/// reported "ALLOWED_ORIGIN is explicitly configured" and awarded +10 — for an
/// allowlist that rejects every origin.
#[test]
fn cors_empty_parsed_list_fails_although_the_variable_is_set() {
    let parsed = talos_config::parse_allowed_origins(",", false);
    assert_eq!(
        parsed,
        Ok(vec![]),
        "the separator-only value has no origins"
    );

    let c = check_cors_origins(&parsed, true);
    assert_eq!(c.status, Status::Fail);
    assert_eq!(c.points, 0);
    assert!(c.detail.contains("ZERO origins"));
    assert!(
        !c.detail.contains("explicitly configured"),
        "must not reuse the wording of the passing case"
    );
}

#[test]
fn cors_dev_defaults_pass_without_scoring() {
    let parsed = talos_config::parse_allowed_origins(
        "http://localhost:3000,http://localhost:3001,http://localhost:3002",
        false,
    );
    let c = check_cors_origins(&parsed, false);
    assert_eq!(c.status, Status::Pass);
    assert_eq!(
        c.points, 0,
        "dev defaults earned nothing before, and do not now"
    );
    assert!(c.detail.contains("dev mode"));
    assert!(c.detail.contains("3 enforced origin(s)"));
}

#[test]
fn cors_production_validation_error_fails() {
    let parsed = talos_config::parse_allowed_origins("*", true);
    let c = check_cors_origins(&parsed, true);
    assert_eq!(c.status, Status::Fail);
    assert_eq!(c.points, 0);
    assert!(c.detail.contains("not permitted in production"));
}

// ───────────────────────────────────────────────────────────────────────────
// Scoring + report shape
// ───────────────────────────────────────────────────────────────────────────

/// The reachable maximum really is 100 — worth pinning, because the per-arm
/// point literals sum to more and read as an over-100 bug.
#[test]
fn a_fully_hardened_production_deployment_scores_exactly_max() {
    let checks = vec![
        check_production_mode(true),
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Verified {
                algorithm: "RS256",
                asymmetric: true,
            },
            "microservices",
        ),
        check_master_encryption_key(Some(KekSelfTest::Verified {
            provider: "vault://transit/keys/talos-kek".to_string(),
        })),
        check_job_signing_key(JobSigningProbe::Verified),
        check_aot_integrity_key(&"ab".repeat(32)),
        check_audit_event_signing(talos_audit_event::SigningSelfTest::Verified, true, true),
        check_redis_tls(RedisTransport::Tls, true),
        check_audit_immutability_triggers(Some(6)),
        check_cors_origins(&Ok(vec!["https://app.example.com".to_string()]), true),
    ];
    let report = render_report(&checks);
    assert_eq!(report["security_score"], 100);
    assert_eq!(report["max_score"], 100);
    assert_eq!(report["grade"], "A");
    assert_eq!(report["status_counts"]["fail"], 0);
    assert_eq!(report["verification_counts"]["not_verified"], 0);
}

/// Grade thresholds are untouched by this change.
#[test]
fn grade_thresholds_are_unchanged() {
    assert_eq!(grade_for(100), "A");
    assert_eq!(grade_for(90), "A");
    assert_eq!(grade_for(89), "B");
    assert_eq!(grade_for(75), "B");
    assert_eq!(grade_for(74), "C");
    assert_eq!(grade_for(60), "C");
    assert_eq!(grade_for(59), "D");
    assert_eq!(grade_for(40), "D");
    assert_eq!(grade_for(39), "F");
    assert_eq!(grade_for(0), "F");
}

/// Every check carries a `verification` field, and the response explains what
/// each value means — otherwise "pass" spans both "I exercised it" and "I read
/// an environment variable" exactly as before.
#[test]
fn every_check_reports_how_it_was_established() {
    let checks = vec![
        check_production_mode(false),
        check_master_encryption_key(None),
        check_aot_integrity_key(""),
    ];
    let report = render_report(&checks);
    for c in report["checks"].as_array().expect("checks array") {
        let v = c["verification"].as_str().expect("verification string");
        assert!(
            ["round_trip", "parsed", "config_presence", "not_verified"].contains(&v),
            "unknown verification value {v}"
        );
        assert!(
            report["verification_legend"][v].is_string(),
            "{v} must be documented in the legend"
        );
    }
    assert_eq!(report["verification_counts"]["not_verified"], 1);
}

/// The pre-existing response contract is preserved: same keys, same check
/// names, same status vocabulary.
#[test]
fn response_shape_is_backwards_compatible() {
    let checks = vec![check_production_mode(true)];
    let report = render_report(&checks);
    for key in [
        "security_score",
        "max_score",
        "grade",
        "grade_thresholds",
        "status_counts",
        "status_legend",
        "checks",
        "recommendation",
    ] {
        assert!(report.get(key).is_some(), "missing legacy key {key}");
    }
    let first = &report["checks"][0];
    assert_eq!(first["check"], "production_mode");
    assert!(first["status"].is_string());
    assert!(first["detail"].is_string());
}

/// The nine check names an operator's scripts key on.
#[test]
fn check_names_are_unchanged() {
    let names = vec![
        check_production_mode(false).name,
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Broken { stage: "secret" },
            "single_pod",
        )
        .name,
        check_master_encryption_key(None).name,
        check_job_signing_key(JobSigningProbe::Absent).name,
        check_aot_integrity_key("").name,
        check_audit_event_signing(talos_audit_event::SigningSelfTest::NotSigned, false, false).name,
        check_redis_tls(RedisTransport::NotConfigured, false).name,
        check_audit_immutability_triggers(Some(1)).name,
        check_cors_origins(&Ok(vec!["http://localhost:3000".to_string()]), false).name,
    ];
    assert_eq!(
        names,
        vec![
            "production_mode",
            "jwt_algorithm",
            "master_encryption_key",
            "job_signing_key",
            "aot_integrity_key",
            "audit_event_signing",
            "redis_tls",
            "audit_immutability_triggers",
            "cors_origins",
        ]
    );
}

/// No probe outcome may produce a `pass` alongside `not_verified`. A green
/// tick that means "I did not look" is the defect this whole line of work
/// keeps finding.
#[test]
fn nothing_that_was_not_verified_is_ever_reported_as_a_pass() {
    let unverified = vec![
        check_master_encryption_key(None),
        check_master_encryption_key(Some(KekSelfTest::Unavailable)),
        check_audit_immutability_triggers(None),
    ];
    for c in unverified {
        assert_eq!(c.verification, Verification::NotVerified, "{}", c.name);
        assert_ne!(c.status, Status::Pass, "{}", c.name);
        assert_eq!(c.points, 0, "{}", c.name);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Score honesty: the number must be reconstructible from the emitted fields,
// and the advice must name only conditions that exist
//
// The defect these pin was live and observable in one response: zero
// failures, zero warnings, a legend saying `info` is "not security-graded",
// a score of 70 — and the 30-point gap was exactly three info outcomes
// forfeiting ten points each. Nothing tested the legend against the
// arithmetic, or the advice against the counts, so both could say whatever
// they liked.
// ───────────────────────────────────────────────────────────────────────────

/// The nine checks a development stack with plaintext Redis, an ephemeral AOT
/// key and an explicit CORS list actually produces. Reproduced here rather
/// than asserted abstractly because the contradiction was only visible in a
/// whole report: each field was defensible alone.
fn dev_stack_checks() -> Vec<Check> {
    vec![
        check_production_mode(false),
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Verified {
                algorithm: "HS256",
                asymmetric: false,
            },
            "single_pod",
        ),
        check_master_encryption_key(Some(KekSelfTest::Verified {
            provider: "env".to_string(),
        })),
        check_job_signing_key(JobSigningProbe::Verified),
        check_aot_integrity_key(""),
        check_audit_event_signing(talos_audit_event::SigningSelfTest::Verified, true, true),
        check_redis_tls(RedisTransport::Plaintext, false),
        check_audit_immutability_triggers(Some(4)),
        check_cors_origins(&Ok(vec!["http://localhost:3000".to_string()]), true),
    ]
}

/// Sum the emitted `checks[]` and demand the emitted totals agree.
///
/// This is the guard for "why 70?": if a future change awards points from
/// anywhere other than a check's own `points`, or renders a denominator that
/// is not the sum of the emitted `max_points`, the response stops being
/// reconstructible and this fails.
fn assert_score_reconstructs(report: &serde_json::Value) {
    let checks = report["checks"].as_array().expect("checks array");
    let awarded: u64 = checks
        .iter()
        .map(|c| {
            c["points"]
                .as_u64()
                .expect("checks[].points must be emitted")
        })
        .sum();
    let max: u64 = checks
        .iter()
        .map(|c| {
            c["max_points"]
                .as_u64()
                .expect("checks[].max_points must be emitted")
        })
        .sum();

    assert_eq!(
        report["security_score"].as_u64(),
        Some(awarded),
        "security_score is no longer the sum of the emitted checks[].points — \
         an operator cannot reconstruct the score from the response"
    );
    assert_eq!(
        report["max_score"].as_u64(),
        Some(max),
        "max_score is no longer the sum of the emitted checks[].max_points"
    );

    let acct = &report["score_accounting"];
    assert_eq!(acct["awarded"].as_u64(), Some(awarded));
    assert_eq!(acct["max"].as_u64(), Some(max));
    assert_eq!(
        acct["forfeited"].as_u64(),
        Some(max - awarded),
        "score_accounting.forfeited must be max - awarded"
    );

    let shortfalls = acct["shortfalls"].as_array().expect("shortfalls array");
    let listed: u64 = shortfalls
        .iter()
        .map(|s| s["forfeited"].as_u64().expect("shortfall forfeited"))
        .sum();
    assert_eq!(
        listed,
        max - awarded,
        "score_accounting.shortfalls must account for EVERY point not awarded — \
         {} point(s) went missing with no entry naming them",
        (max - awarded) as i64 - listed as i64
    );

    let by_kind = &acct["forfeited_by_kind"];
    assert_eq!(
        by_kind["control"].as_u64().unwrap_or_default()
            + by_kind["deployment_posture"].as_u64().unwrap_or_default(),
        max - awarded,
        "forfeited_by_kind must partition the shortfall"
    );

    // Per-check sanity: nothing may award more than its own weight, or the
    // ratio the response prints is not a ratio.
    for c in checks {
        assert!(
            c["points"].as_u64().unwrap_or_default()
                <= c["max_points"].as_u64().unwrap_or_default(),
            "{} awarded more than its weight",
            c["check"]
        );
    }
}

#[test]
fn the_score_is_reconstructible_from_the_emitted_fields() {
    assert_score_reconstructs(&render_report(&dev_stack_checks()));
}

/// The same guard over deliberately awkward shapes, so it is not pinned to
/// one deployment: everything broken, everything unverified, everything full.
#[test]
fn the_score_reconstructs_on_failing_unverified_and_perfect_reports() {
    let all_broken = vec![
        check_production_mode(false),
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Broken { stage: "secret" },
            "single_pod",
        ),
        check_master_encryption_key(Some(KekSelfTest::Failed {
            provider: "env".to_string(),
            stage: "unwrap",
        })),
        check_job_signing_key(JobSigningProbe::Unusable),
        check_aot_integrity_key("abcd"),
        check_audit_event_signing(talos_audit_event::SigningSelfTest::NotSigned, true, false),
        check_redis_tls(RedisTransport::TlsInsecure, true),
        check_audit_immutability_triggers(Some(0)),
        check_cors_origins(&Ok(vec![]), true),
    ];
    let report = render_report(&all_broken);
    assert_score_reconstructs(&report);
    assert_eq!(report["security_score"], 0);
    assert_eq!(report["score_accounting"]["forfeited"], 100);

    let unverified = vec![
        check_master_encryption_key(None),
        check_audit_immutability_triggers(None),
    ];
    assert_score_reconstructs(&render_report(&unverified));

    // The all-green production report: no shortfall, so no shortfall entries.
    let perfect = render_report(&[
        check_production_mode(true),
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Verified {
                algorithm: "RS256",
                asymmetric: true,
            },
            "microservices",
        ),
        check_master_encryption_key(Some(KekSelfTest::Verified {
            provider: "vault".to_string(),
        })),
        check_job_signing_key(JobSigningProbe::Verified),
        check_aot_integrity_key(&"ab".repeat(32)),
        check_audit_event_signing(talos_audit_event::SigningSelfTest::Verified, true, true),
        check_redis_tls(RedisTransport::Tls, true),
        check_audit_immutability_triggers(Some(6)),
        check_cors_origins(&Ok(vec!["https://app.example.com".to_string()]), true),
    ]);
    assert_score_reconstructs(&perfect);
    assert_eq!(perfect["security_score"], 100);
    assert_eq!(
        perfect["score_accounting"]["shortfalls"]
            .as_array()
            .map(Vec::len),
        Some(0)
    );
}

/// The legend must not deny what the arithmetic does.
///
/// `info` outcomes forfeit points. The legend used to read "Configuration
/// noted; not security-graded", which is the exact opposite, and it was
/// printed in the same response as the 30-point gap those info outcomes
/// caused. This asserts the contradiction cannot come back: whenever a status
/// class forfeits points in a report, its legend may not claim to be ungraded,
/// and must point at where the points went.
#[test]
fn no_status_legend_denies_the_grading_it_receives() {
    let checks = dev_stack_checks();
    let report = render_report(&checks);

    // Precondition: this report really does forfeit points on `info`, or the
    // assertions below are vacuous.
    let info_forfeit: u32 = checks
        .iter()
        .filter(|c| c.status == Status::Info)
        .map(Check::forfeited)
        .sum();
    assert_eq!(
        info_forfeit, 30,
        "fixture drifted — three info outcomes forfeiting 10 each is the shape \
         that made the legend false"
    );

    for status in ["pass", "warn", "fail", "info"] {
        let forfeited: u32 = checks
            .iter()
            .filter(|c| c.status.as_str() == status)
            .map(Check::forfeited)
            .sum();
        if forfeited == 0 {
            continue;
        }
        let legend = report["status_legend"][status]
            .as_str()
            .expect("every status must be documented");
        let lowered = legend.to_lowercase();
        for denial in ["not security-graded", "not graded", "not scored"] {
            assert!(
                !lowered.contains(denial),
                "status_legend.{status} says {denial:?} while {status} outcomes \
                 forfeit {forfeited} point(s) in this very report"
            );
        }
        assert!(
            lowered.contains("score_accounting") || lowered.contains("points"),
            "status_legend.{status} forfeits points but does not tell the reader \
             where they went"
        );
    }
}

/// Advice may not name a class with zero members.
///
/// The replaced string was chosen by score band alone, so at 70 it emitted
/// "address failures before production" over `fail: 0`. Each clause is now
/// gated on its own class, and this drives every combination of present and
/// absent classes to prove the gating holds in both directions.
#[test]
fn recommendation_names_only_present_classes() {
    struct Case {
        label: &'static str,
        checks: Vec<Check>,
    }
    let cases = vec![
        Case {
            label: "clean dev stack (the live 70/C report)",
            checks: dev_stack_checks(),
        },
        Case {
            label: "a failure present",
            checks: vec![
                check_cors_origins(&Ok(vec![]), true),
                check_production_mode(true),
            ],
        },
        Case {
            label: "a warning that is not an unverified",
            checks: vec![check_job_signing_key(JobSigningProbe::Absent)],
        },
        Case {
            label: "an unverified check",
            checks: vec![check_master_encryption_key(None)],
        },
        Case {
            label: "full marks",
            checks: vec![check_production_mode(true)],
        },
    ];

    for Case { label, checks } in cases {
        let text = recommendation_for(&checks);
        // Drive the RENDERED report too, not only the helper. A mutation that
        // rewires `render_report` back to a score band leaves this helper
        // perfectly correct and unused — measured, that is exactly what
        // happened when this guard tested the helper alone.
        let rendered = render_report(&checks);
        assert_eq!(
            rendered["recommendation"].as_str(),
            Some(text.as_str()),
            "[{label}] render_report no longer emits recommendation_for's answer, \
             so the advice is being selected somewhere this test cannot see"
        );
        let lowered = text.to_lowercase();

        let has_fail = checks.iter().any(|c| c.status == Status::Fail);
        let has_unverified = checks
            .iter()
            .any(|c| c.verification == Verification::NotVerified);
        let has_warn = checks
            .iter()
            .any(|c| c.status == Status::Warn && c.verification != Verification::NotVerified);

        assert_eq!(
            lowered.contains("failing control"),
            has_fail,
            "[{label}] recommendation talks about failing controls but fail count \
             is {}: {text}",
            checks.iter().filter(|c| c.status == Status::Fail).count()
        );
        assert_eq!(
            lowered.contains("could not be verified"),
            has_unverified,
            "[{label}] unverified clause does not match the population: {text}"
        );
        assert_eq!(
            lowered.contains("harden"),
            has_warn,
            "[{label}] warning clause does not match the population: {text}"
        );

        // Every check the advice names must exist in the report it describes.
        for c in &checks {
            if c.status == Status::Fail || c.status == Status::Warn || c.forfeited() > 0 {
                continue;
            }
            assert!(
                !text.contains(c.name),
                "[{label}] recommendation names {}, which has nothing to report: {text}",
                c.name
            );
        }
    }
}

/// The specific sentence that was false, pinned as its own case.
#[test]
fn a_report_with_no_failures_never_tells_the_operator_to_address_failures() {
    let report = render_report(&dev_stack_checks());
    assert_eq!(report["status_counts"]["fail"], 0);
    assert_eq!(report["status_counts"]["warn"], 0);
    assert_eq!(report["security_score"], 70);
    assert_eq!(report["grade"], "C");

    let rec = report["recommendation"].as_str().expect("recommendation");
    for forbidden in ["failure", "failing control"] {
        assert!(
            !rec.to_lowercase().contains(forbidden),
            "a report with fail: 0 must not mention {forbidden:?}: {rec}"
        );
    }
    // And it must explain the gap rather than leaving it unaccounted.
    for named in ["production_mode", "aot_integrity_key", "redis_tls"] {
        assert!(
            rec.contains(named),
            "the 30-point gap is {named} among others, and the advice does not \
             name it: {rec}"
        );
    }
}

/// A dev stack tops out at exactly [`GRADE_A`], so grade A IS reachable
/// outside production — but only at perfection. Worth pinning: the natural
/// assumption is that A is unreachable in development, and acting on that
/// would justify re-weighting something that does not need it.
#[test]
fn grade_a_is_reachable_in_development_only_at_perfection() {
    let mut checks = dev_stack_checks();
    checks[4] = check_aot_integrity_key(&"ab".repeat(32));
    checks[6] = check_redis_tls(RedisTransport::Tls, false);
    let report = render_report(&checks);

    assert_eq!(report["security_score"], 90);
    assert_eq!(report["grade"], "A");
    // The whole remaining gap is posture, and the response says so.
    assert_eq!(report["score_accounting"]["forfeited"], 10);
    assert_eq!(
        report["score_accounting"]["forfeited_by_kind"]["deployment_posture"],
        10
    );
    assert_eq!(
        report["score_accounting"]["forfeited_by_kind"]["control"],
        0
    );

    // One missing control in dev drops to B, so there is no slack.
    checks[6] = check_redis_tls(RedisTransport::Plaintext, false);
    assert_eq!(render_report(&checks)["grade"], "B");
}

/// Weights live in exactly one table, and it agrees with [`MAX_SCORE`].
///
/// Without this the derived `max_score` and the constant the grade thresholds
/// were calibrated against could silently diverge — a tenth check would make
/// `GRADE_A` mean something other than 90%.
#[test]
fn weights_sum_to_max_score() {
    let sum: u32 = CHECK_WEIGHTS.iter().map(|(_, p, _)| *p).sum();
    assert_eq!(sum, MAX_SCORE, "CHECK_WEIGHTS no longer sums to MAX_SCORE");
    // Nine SCORED checks plus `write_ceiling_enforcement`, which is weighted 0
    // on purpose (see its CHECK_WEIGHTS entry). Ten entries, nine weights.
    assert_eq!(CHECK_WEIGHTS.len(), 10);
    assert_eq!(
        CHECK_WEIGHTS.iter().filter(|(_, p, _)| *p > 0).count(),
        9,
        "exactly one check is deliberately unweighted"
    );
}

/// An UNWEIGHTED check must cost nothing — not one point, in any arm.
///
/// This file has shipped the opposite before: a legend saying a class was
/// ungraded while that class quietly cost 30 points. `max_points()` falls back
/// to `self.points` for an unlisted name and `forfeited()` saturates, so an arm
/// that awarded points under a zero weight would inflate `security_score` past
/// `max_score` silently rather than failing anywhere. Drive every arm.
#[test]
fn unweighted_checks_cost_nothing() {
    use talos_worker_identity_repository::{summarize_write_ceiling_enforcement, WorkerBuildRow};
    fn row(enforced: Option<bool>) -> WorkerBuildRow {
        WorkerBuildRow {
            worker_id: "w".to_string(),
            build_version: None,
            supports_sealing: false,
            last_seen_at: chrono::Utc::now(),
            last_liveness_at: None,
            write_ceiling_enforced: enforced,
            write_ceiling_strict_egress: None,
        }
    }
    let arms = [
        check_write_ceiling_enforcement(None),
        check_write_ceiling_enforcement(Some(summarize_write_ceiling_enforcement(&[]))),
        check_write_ceiling_enforcement(Some(summarize_write_ceiling_enforcement(&[row(Some(
            true,
        ))]))),
        check_write_ceiling_enforcement(Some(summarize_write_ceiling_enforcement(&[
            row(Some(true)),
            row(Some(false)),
        ]))),
        check_write_ceiling_enforcement(Some(summarize_write_ceiling_enforcement(&[row(Some(
            false,
        ))]))),
        check_write_ceiling_enforcement(Some(summarize_write_ceiling_enforcement(&[row(None)]))),
    ];
    for c in &arms {
        assert_eq!(c.points, 0, "{} awarded points under a zero weight", c.name);
        assert_eq!(
            c.max_points(),
            0,
            "{} must contribute 0 to max_score",
            c.name
        );
        assert_eq!(c.forfeited(), 0, "{} must forfeit nothing", c.name);
    }
}

// ───────────────────────────────────────────────────────────────────────────
// write_ceiling_enforcement
// ───────────────────────────────────────────────────────────────────────────

mod write_ceiling {
    use super::*;
    use talos_worker_identity_repository::{summarize_write_ceiling_enforcement, WorkerBuildRow};

    fn row(enforced: Option<bool>) -> WorkerBuildRow {
        WorkerBuildRow {
            worker_id: "w".to_string(),
            build_version: None,
            supports_sealing: false,
            last_seen_at: chrono::Utc::now(),
            last_liveness_at: None,
            write_ceiling_enforced: enforced,
            write_ceiling_strict_egress: None,
        }
    }
    fn check(rows: &[WorkerBuildRow]) -> Check {
        check_write_ceiling_enforcement(Some(summarize_write_ceiling_enforcement(rows)))
    }

    /// THE DANGEROUS SURVIVOR. A check that passes when the fleet reports
    /// nothing is worse than no check: it converts "we never asked" into a
    /// green tick, which is the exact class this whole change exists to
    /// remove. An empty registry must be `NotVerified` — not `Pass`, and not
    /// even a `Warn` that claims to have measured something.
    #[test]
    fn an_empty_fleet_is_not_verified_never_a_pass() {
        let c = check(&[]);
        assert_ne!(c.status, Status::Pass, "silence must never read as a pass");
        assert_eq!(c.verification, Verification::NotVerified);
        assert_eq!(c.points, 0);
        assert!(c.detail.contains("UNKNOWN"));
    }

    /// Likewise when every row predates the feature: nobody reported, so
    /// nothing was established. `Unknown` is a refusal to answer, not an "all
    /// clear".
    #[test]
    fn an_all_unreported_fleet_is_not_verified() {
        let c = check(&[row(None), row(None)]);
        assert_ne!(c.status, Status::Pass);
        assert_eq!(c.verification, Verification::NotVerified);
    }

    /// A FAILED registry read is a database finding, not a ceiling finding —
    /// and must say so, so an operator does not go and change a ceiling in
    /// response to a Postgres outage.
    #[test]
    fn an_unreadable_registry_is_not_verified_and_blames_the_database() {
        let c = check_write_ceiling_enforcement(None);
        assert_ne!(c.status, Status::Pass);
        assert_eq!(c.verification, Verification::NotVerified);
        assert_eq!(c.points, 0);
        assert!(c.detail.contains("NOT VERIFIED"));
        assert!(
            c.detail.contains("database problem"),
            "must not read as a finding about the ceiling"
        );
    }

    /// The only passing shape: every registered worker reports enforcement.
    /// Still `ConfigPresence`, never higher — the controller read a value
    /// another process reported about its own env, unsigned, and exercised
    /// nothing. Same standing as `aot_integrity_key`, whose enforcing key ring
    /// also lives in the worker.
    #[test]
    fn a_fully_enforcing_fleet_passes_at_config_presence_only() {
        let c = check(&[row(Some(true)), row(Some(true))]);
        assert_eq!(c.status, Status::Pass);
        assert_eq!(c.verification, Verification::ConfigPresence);
        assert_ne!(
            c.verification,
            Verification::RoundTrip,
            "nothing was exercised from the controller"
        );
        assert!(c.detail.contains("UNSIGNED"));
        assert!(c.detail.contains("never an authorization input"));
    }

    /// A MIXED fleet must not pass. Nothing routes jobs by enforcement
    /// posture, so a readonly actor's job may land on the worker that does not
    /// enforce — and the detail has to say that, because "1 of 2 enforcing"
    /// reads reassuringly on its own.
    #[test]
    fn a_mixed_fleet_warns_and_names_the_routing_hazard() {
        let c = check(&[row(Some(true)), row(Some(false))]);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.verification, Verification::ConfigPresence);
        assert!(c.detail.contains("ADVISORY IN PART"));
        assert!(c.detail.contains("may"));
    }

    /// Every worker reporting OFF is a definite answer — Warn, but measured,
    /// so it is `ConfigPresence` rather than `NotVerified`. The distinction is
    /// the whole point of the verification axis: "it is off" and "we could not
    /// tell" are different jobs for the operator.
    #[test]
    fn a_fully_reporting_off_fleet_warns_but_is_measured() {
        let c = check(&[row(Some(false)), row(Some(false))]);
        assert_eq!(c.status, Status::Warn);
        assert_eq!(c.verification, Verification::ConfigPresence);
        assert_ne!(c.verification, Verification::NotVerified);
        assert!(c.detail.contains("ADVISORY"));
    }

    /// The check reaches the assembled report, and an unestablished one is
    /// named to the operator rather than being silently absent.
    #[test]
    fn it_reaches_the_report_and_the_recommendation() {
        let checks = vec![check_write_ceiling_enforcement(None)];
        let report = render_report(&checks);
        let names: Vec<&str> = report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c["check"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"write_ceiling_enforcement"));
        // Unweighted: it contributes to neither side of the score.
        assert_eq!(report["security_score"], 0);
        assert_eq!(report["max_score"], 0);
        assert_eq!(report["verification_counts"]["not_verified"], 1);
        assert!(
            report["recommendation"]
                .as_str()
                .unwrap()
                .contains("write_ceiling_enforcement"),
            "an unverified check must be named, not just counted"
        );
    }
}

/// Every arm of every check: its name is weighted, and it never awards more
/// than its weight. `max_points` is a property of the CHECK, so a warn arm
/// still reports the full weight and the shortfall shows up as forfeited.
#[test]
fn every_arm_is_weighted_and_within_its_weight() {
    let arms: Vec<Check> = vec![
        check_production_mode(true),
        check_production_mode(false),
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Verified {
                algorithm: "RS256",
                asymmetric: true,
            },
            "microservices",
        ),
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Verified {
                algorithm: "HS256",
                asymmetric: false,
            },
            "single_pod",
        ),
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Verified {
                algorithm: "HS256",
                asymmetric: false,
            },
            "microservices",
        ),
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Broken { stage: "secret" },
            "single_pod",
        ),
        check_jwt_algorithm(
            talos_auth::JwtSelfTest::Broken { stage: "mint" },
            "single_pod",
        ),
        check_master_encryption_key(Some(KekSelfTest::Verified {
            provider: "env".to_string(),
        })),
        check_master_encryption_key(Some(KekSelfTest::Failed {
            provider: "env".to_string(),
            stage: "wrap",
        })),
        check_master_encryption_key(Some(KekSelfTest::Unavailable)),
        check_master_encryption_key(None),
        check_write_ceiling_enforcement(None),
        check_job_signing_key(JobSigningProbe::Verified),
        check_job_signing_key(JobSigningProbe::Absent),
        check_job_signing_key(JobSigningProbe::Unusable),
        check_job_signing_key(JobSigningProbe::RoundTripFailed),
        check_aot_integrity_key(&"ab".repeat(32)),
        check_aot_integrity_key("abcd"),
        check_aot_integrity_key(""),
        check_audit_event_signing(talos_audit_event::SigningSelfTest::Verified, true, true),
        check_audit_event_signing(talos_audit_event::SigningSelfTest::NotSigned, false, false),
        check_audit_event_signing(talos_audit_event::SigningSelfTest::NotSigned, true, false),
        check_audit_event_signing(talos_audit_event::SigningSelfTest::NotSigned, true, true),
        check_redis_tls(RedisTransport::NotConfigured, false),
        check_redis_tls(RedisTransport::Tls, true),
        check_redis_tls(RedisTransport::TlsInsecure, true),
        check_redis_tls(RedisTransport::Plaintext, true),
        check_redis_tls(RedisTransport::Plaintext, false),
        check_redis_tls(RedisTransport::UnixSocket, false),
        check_redis_tls(RedisTransport::Unparseable, false),
        check_audit_immutability_triggers(Some(4)),
        check_audit_immutability_triggers(Some(0)),
        check_audit_immutability_triggers(None),
        check_cors_origins(&Ok(vec!["https://app.example.com".to_string()]), true),
        check_cors_origins(&Ok(vec!["http://localhost:3000".to_string()]), false),
        check_cors_origins(&Ok(vec![]), true),
        check_cors_origins(&Err("bad".to_string()), true),
    ];

    for arm in &arms {
        let weighted = CHECK_WEIGHTS.iter().find(|(n, _, _)| *n == arm.name);
        let (_, weight, _) =
            weighted.unwrap_or_else(|| panic!("check {} has no entry in CHECK_WEIGHTS", arm.name));
        assert_eq!(
            arm.max_points(),
            *weight,
            "{} must report its weight regardless of outcome",
            arm.name
        );
        assert!(
            arm.points <= *weight,
            "{} awarded {} against a weight of {weight}",
            arm.name,
            arm.points
        );
    }
}

/// Deployment posture is one check, deliberately. If a second one appears the
/// score has quietly become more about where it runs than about what is
/// configured, and that should be a decision, not a drift.
#[test]
fn only_production_mode_is_deployment_posture() {
    let posture: Vec<&str> = CHECK_WEIGHTS
        .iter()
        .filter(|(_, _, k)| *k == CheckKind::DeploymentPosture)
        .map(|(n, _, _)| *n)
        .collect();
    assert_eq!(posture, vec!["production_mode"]);
}

/// `verification` semantics are untouched by the scoring work: an unverified
/// check still never passes, and the shortfall entry for one must not read as
/// a verdict on the control.
#[test]
fn scoring_changes_did_not_disturb_verification_semantics() {
    let report = render_report(&[
        check_master_encryption_key(None),
        check_audit_immutability_triggers(None),
    ]);
    for c in report["checks"].as_array().expect("checks") {
        assert_eq!(c["verification"], "not_verified");
        assert_ne!(c["status"], "pass");
        assert_eq!(c["points"], 0);
    }
    let rec = report["recommendation"].as_str().expect("recommendation");
    assert!(rec.contains("could not be verified"));
    assert!(
        !rec.to_lowercase().contains("failing control"),
        "an unverified check is not a failure: {rec}"
    );
}
