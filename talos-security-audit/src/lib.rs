//! Verifying security audit.
//!
//! # Why this crate exists
//!
//! `security_audit` shipped nine checks, a score and a letter grade. Eight of
//! the nine asked whether a configuration value was *present*. Only
//! `audit_immutability_triggers` interrogated the system it was grading.
//!
//! That is the reason the empty-env-var defect class lived *inside the audit
//! handler itself* for over a year, through eleven repairs elsewhere: a
//! presence test cannot notice that the thing it asserts does not work. The
//! comment left behind by the MCP-625 fix says it exactly — "Operators saw a
//! green dashboard while critical security primitives were disabled."
//!
//! Every check here that CAN be exercised is exercised: the KEK wraps and
//! unwraps a probe DEK, the worker shared key signs and verifies a probe
//! message, the audit signing key signs and verifies a probe event, the JWT
//! key pair mints a probe token whose `alg` header is read back off the token.
//! Checks that cannot be exercised say so — [`Verification::NotVerified`] and
//! [`Verification::ConfigPresence`] exist so a green tick can never mean "I did
//! not look".
//!
//! # Two failure modes, deliberately not collapsed
//!
//! *Control absent* and *control present but non-functional* are different
//! findings and carry different statuses. Absent keeps whatever status it
//! historically had (`warn` for job signing, `warn` for audit signing, …).
//! Present-but-broken is always `fail`, because it is the worse of the two: a
//! missing key is a state the operator can see, while a key that is set and
//! does not work means something believes it is protected. The score weights
//! are untouched — a broken round trip simply earns the same zero as an absent
//! control.
//!
//! # Side effects
//!
//! None. Every probe operates on values minted inside the probe itself, and
//! nothing is persisted, published, cached or counted. See the per-probe notes
//! on [`SecretsManager::kek_selftest`], [`talos_audit_event::signing_selftest`]
//! and [`talos_auth::jwt_selftest`].
//!
//! [`SecretsManager::kek_selftest`]: talos_secrets_manager::SecretsManager::kek_selftest

use std::time::Duration;

use talos_secrets_manager::{KekSelfTest, SecretsManager};
use talos_system_repo::SystemRepository;

/// Upper bound on the KEK wrap→unwrap probe.
///
/// `EnvKekProvider` is local AES and finishes in microseconds, but a
/// `KEK_PROVIDER=vault` deployment makes two HTTP calls to Vault. This is an
/// interactive MCP handler, so an unreachable Vault must produce a *finding*
/// rather than a hung request — the timeout yields
/// [`Verification::NotVerified`], which is honestly "I could not tell", not a
/// pass and not a failure of the control.
const KEK_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Freshness window handed to the worker-shared-key probe's verify step. The
/// probe signs and verifies in the same expression, so any positive value
/// works; 60 s matches the dispatch path's own window.
const PROBE_FRESHNESS_SECS: u64 = 60;

/// Trigger-name pattern for the audit-immutability triggers.
const IMMUTABILITY_TRIGGER_PATTERN: &str = "trg_%_immutable";

// ───────────────────────────────────────────────────────────────────────────
// Vocabulary
// ───────────────────────────────────────────────────────────────────────────

/// The four operator-facing statuses. Unchanged from the pre-verification
/// audit so dashboards and scripts keep working.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Pass,
    Warn,
    Fail,
    Info,
}

impl Status {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Status::Pass => "pass",
            Status::Warn => "warn",
            Status::Fail => "fail",
            Status::Info => "info",
        }
    }
}

/// How a check's finding was established.
///
/// This axis is the whole point of the crate. Without it a reader cannot tell
/// a check that exercised the control from one that read an environment
/// variable, and "pass" silently spans both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verification {
    /// The control was exercised end to end during this run — a probe value
    /// was pushed through the real primitive and the result inspected.
    RoundTrip,
    /// The control's live configuration was read through the code that
    /// enforces it, but there is no operation to exercise (or the control is
    /// definitively absent, so there is nothing to exercise).
    Parsed,
    /// Only presence or shape was inspected. Nothing exercised the control;
    /// this check cannot detect a present-but-non-functional configuration.
    ConfigPresence,
    /// The verification could not run in this deployment. The status describes
    /// what was NOT learned — never "good".
    NotVerified,
}

impl Verification {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Verification::RoundTrip => "round_trip",
            Verification::Parsed => "parsed",
            Verification::ConfigPresence => "config_presence",
            Verification::NotVerified => "not_verified",
        }
    }
}

/// One rendered check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    pub verification: Verification,
    /// Points this outcome contributes to `security_score`.
    pub points: u32,
}

impl Check {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "check": self.name,
            "status": self.status.as_str(),
            "detail": self.detail,
            "verification": self.verification.as_str(),
        })
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 1 — production mode
// ───────────────────────────────────────────────────────────────────────────

#[must_use]
pub fn check_production_mode(is_prod: bool) -> Check {
    Check {
        name: "production_mode",
        status: if is_prod { Status::Pass } else { Status::Info },
        detail: if is_prod {
            "RUST_ENV=production".to_string()
        } else {
            "Development mode — some security features relaxed".to_string()
        },
        verification: Verification::Parsed,
        points: if is_prod { 10 } else { 0 },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 2 — JWT algorithm
// ───────────────────────────────────────────────────────────────────────────

/// Render the `jwt_algorithm` check from a self-test outcome.
///
/// `topology` is the raw `TALOS_DEPLOYMENT_TOPOLOGY` value; `single_pod`
/// (the default, and the canonical Talos deployment) keeps a symmetric
/// algorithm at `pass`, because HS256 has no asymmetric advantage to claim
/// when one process both signs and verifies. That grading is MCP-1209's and
/// is preserved verbatim.
#[must_use]
pub fn check_jwt_algorithm(outcome: talos_auth::JwtSelfTest, topology: &str) -> Check {
    let single_pod = topology == "single_pod";
    match outcome {
        talos_auth::JwtSelfTest::Verified {
            algorithm,
            asymmetric: true,
        } => Check {
            name: "jwt_algorithm",
            status: Status::Pass,
            detail: format!(
                "Minted and verified a probe token: alg={} — asymmetric (recommended)",
                algorithm
            ),
            verification: Verification::RoundTrip,
            points: 10,
        },
        talos_auth::JwtSelfTest::Verified {
            algorithm,
            asymmetric: false,
        } if single_pod => Check {
            name: "jwt_algorithm",
            status: Status::Pass,
            detail: format!(
                "Minted and verified a probe token: alg={} — symmetric (acceptable for \
                 single-pod deployment, topology={}). Move to RS256/ES256 only if splitting \
                 into a multi-controller / dedicated-verifier topology.",
                algorithm, topology
            ),
            verification: Verification::RoundTrip,
            points: 10,
        },
        talos_auth::JwtSelfTest::Verified { algorithm, .. } => Check {
            name: "jwt_algorithm",
            status: Status::Warn,
            detail: format!(
                "Minted and verified a probe token: alg={} — symmetric (upgrade to RS256/ES256 \
                 for microservice deployments, topology={})",
                algorithm, topology
            ),
            verification: Verification::RoundTrip,
            points: 5,
        },
        talos_auth::JwtSelfTest::Broken { stage: "secret" } => Check {
            name: "jwt_algorithm",
            status: Status::Fail,
            detail: "CRITICAL: JWT_SECRET is not set — this process cannot mint or verify \
                     access tokens."
                .to_string(),
            verification: Verification::RoundTrip,
            points: 0,
        },
        talos_auth::JwtSelfTest::Broken { stage } => Check {
            name: "jwt_algorithm",
            status: Status::Fail,
            detail: format!(
                "CRITICAL: JWT signing is CONFIGURED but NON-FUNCTIONAL — the mint/verify round \
                 trip failed at the '{}' stage, so this process cannot issue or accept access \
                 tokens. The cause is in the controller log under \
                 event_kind=jwt_selftest_failed (it is withheld here because key-parse errors \
                 can quote key material).",
                stage
            ),
            verification: Verification::RoundTrip,
            points: 0,
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 3 — master encryption key (KEK)
// ───────────────────────────────────────────────────────────────────────────

/// `None` means the probe exceeded [`KEK_PROBE_TIMEOUT`] — a distinct outcome
/// from any of the [`KekSelfTest`] arms, because nothing was learned.
#[must_use]
pub fn check_master_encryption_key(outcome: Option<KekSelfTest>) -> Check {
    match outcome {
        Some(KekSelfTest::Verified { provider }) => Check {
            name: "master_encryption_key",
            status: Status::Pass,
            detail: format!(
                "KEK wrap→unwrap round trip succeeded (provider: {}) — DEKs are recoverable, \
                 so encrypted secrets, memories and outputs can be read",
                provider
            ),
            verification: Verification::RoundTrip,
            points: 15,
        },
        Some(KekSelfTest::Failed { provider, stage }) => Check {
            name: "master_encryption_key",
            status: Status::Fail,
            detail: format!(
                "CRITICAL: the KEK is INSTALLED (provider: {}) but NON-FUNCTIONAL — its \
                 wrap→unwrap round trip failed at the '{}' stage. Every DEK in \
                 `encryption_keys` is unwrappable, so no encrypted secret can be read. The \
                 cause is in the controller log under event_kind=kek_selftest_failed.",
                provider, stage
            ),
            verification: Verification::RoundTrip,
            points: 0,
        },
        Some(KekSelfTest::Unavailable) => Check {
            name: "master_encryption_key",
            status: Status::Warn,
            detail: "NOT VERIFIED: the KEK provider could not be read (lock poisoned), so this \
                     run did not establish whether envelope encryption works."
                .to_string(),
            verification: Verification::NotVerified,
            points: 0,
        },
        None => Check {
            name: "master_encryption_key",
            status: Status::Warn,
            detail: format!(
                "NOT VERIFIED: the KEK wrap→unwrap probe did not finish within {} s. A \
                 KMS-backed KEK (KEK_PROVIDER=vault) may be slow or unreachable — this run did \
                 not establish whether envelope encryption works.",
                KEK_PROBE_TIMEOUT.as_secs()
            ),
            verification: Verification::NotVerified,
            points: 0,
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 4 — job signing key (WORKER_SHARED_KEY)
// ───────────────────────────────────────────────────────────────────────────

/// What the worker-shared-key probe learned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobSigningProbe {
    /// A probe message was signed and its HMAC verified.
    Verified,
    /// No key is configured at all.
    Absent,
    /// `WORKER_SHARED_KEY` is set but the loader rejected it (not hex, wrong
    /// length). Nothing can be signed.
    Unusable,
    /// The key loaded but the sign→verify round trip failed.
    RoundTripFailed,
}

/// Sign and verify a probe message with the live `WORKER_SHARED_KEY`.
///
/// **Side-effect free and idempotent.** [`WorkerHeartbeat`] is signed on the
/// stack and verified with `verify_no_replay`, the observer half of the
/// verify-once split (CLAUDE.md), so the process-local replay-nonce cache is
/// never touched — the probe cannot poison a nonce that a real message would
/// later need, and running the audit twice cannot make the second run fail.
/// The probe is never serialised, never published to NATS and never persisted.
///
/// [`WorkerHeartbeat`]: talos_workflow_job_protocol::WorkerHeartbeat
#[must_use]
pub fn probe_job_signing_key() -> JobSigningProbe {
    if !talos_config::env_var_is_set_nonempty("WORKER_SHARED_KEY")
        && !talos_config::env_var_is_set_nonempty("WORKER_SHARED_KEY_FILE")
    {
        return JobSigningProbe::Absent;
    }

    let key = match talos_workflow_job_protocol::load_worker_shared_key() {
        Ok(k) => k,
        Err(e) => {
            // The loader's message embeds `hex::FromHexError`, which names the
            // offending character AND its index — a byte of the key. It goes
            // to the log, never to the response.
            tracing::error!(
                target: "talos_security",
                event_kind = "job_signing_selftest_failed",
                stage = "load",
                error = %e,
                "WORKER_SHARED_KEY is set but could not be loaded"
            );
            return JobSigningProbe::Unusable;
        }
    };

    let mut probe = talos_workflow_job_protocol::WorkerHeartbeat {
        worker_id: "security-audit-probe".to_string(),
        capabilities: Vec::new(),
        cpu_usage_pct: 0.0,
        build_version: None,
        signature: Vec::new(),
        heartbeat_nonce: String::new(),
    };
    if let Err(e) = probe.sign(key.as_bytes()) {
        tracing::error!(
            target: "talos_security",
            event_kind = "job_signing_selftest_failed",
            stage = "sign",
            error = %e,
            "WORKER_SHARED_KEY loaded but could not sign a probe message"
        );
        return JobSigningProbe::RoundTripFailed;
    }
    match probe.verify_no_replay(key.as_bytes(), PROBE_FRESHNESS_SECS) {
        Ok(_) => JobSigningProbe::Verified,
        Err(e) => {
            tracing::error!(
                target: "talos_security",
                event_kind = "job_signing_selftest_failed",
                stage = "verify",
                error = %e,
                "WORKER_SHARED_KEY signed a probe message its own verifier rejects"
            );
            JobSigningProbe::RoundTripFailed
        }
    }
}

#[must_use]
pub fn check_job_signing_key(outcome: JobSigningProbe) -> Check {
    match outcome {
        JobSigningProbe::Verified => Check {
            name: "job_signing_key",
            status: Status::Pass,
            detail: "WORKER_SHARED_KEY verified by an HMAC sign→verify round trip — job \
                     payloads are signed"
                .to_string(),
            verification: Verification::RoundTrip,
            points: 15,
        },
        JobSigningProbe::Absent => Check {
            name: "job_signing_key",
            status: Status::Warn,
            detail: "WORKER_SHARED_KEY not set — job payloads are unsigned".to_string(),
            verification: Verification::Parsed,
            points: 0,
        },
        JobSigningProbe::Unusable => Check {
            name: "job_signing_key",
            status: Status::Fail,
            detail: "CRITICAL: WORKER_SHARED_KEY is SET but UNUSABLE — it is not a 32-byte \
                     (64-hex-char) key, so nothing can sign a job and every dispatch will be \
                     rejected by the worker. Regenerate with `openssl rand -hex 32`. (The \
                     parse error is withheld here: it names a character of the key.)"
                .to_string(),
            verification: Verification::RoundTrip,
            points: 0,
        },
        JobSigningProbe::RoundTripFailed => Check {
            name: "job_signing_key",
            status: Status::Fail,
            detail: "CRITICAL: WORKER_SHARED_KEY loaded but its own sign→verify round trip \
                     FAILED — job signatures will not validate. See the controller log under \
                     event_kind=job_signing_selftest_failed."
                .to_string(),
            verification: Verification::RoundTrip,
            points: 0,
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 5 — AOT integrity key
// ───────────────────────────────────────────────────────────────────────────

/// Minimum AOT key length, in bytes after hex decoding. Mirrors the worker's
/// own floor in `talos-worker-runtime::runtime::aot_key_ring`.
pub const MIN_AOT_KEY_BYTES: usize = 32;

/// Render `aot_integrity_key`.
///
/// **Deliberately still a presence-and-shape check, and labelled as one.** An
/// HMAC round trip here would be vacuous: `Hmac::<Sha256>::new_from_slice`
/// accepts a key of *any* length, so the round trip cannot fail for any
/// non-empty value and would prove nothing the length check does not already
/// prove. The control this key protects also does not live in this process —
/// the AOT cache and its key ring are the worker's, and the controller reads
/// `TALOS_AOT_HMAC_KEY` purely as an operator-attestation marker that the
/// bootstrap secret was populated (MCP-1210). So there is nothing here to
/// exercise, and the honest label is `config_presence`.
#[must_use]
pub fn check_aot_integrity_key(raw: &str) -> Check {
    // The worker accepts hex OR raw bytes; canonical form is hex. Measure the
    // decoded length when the value parses as hex, otherwise the raw length.
    let decoded_len = hex::decode(raw).map(|b| b.len()).unwrap_or(raw.len());

    if raw.is_empty() {
        return Check {
            name: "aot_integrity_key",
            status: Status::Info,
            detail: "Using ephemeral AOT key — blobs not cached across restarts. Generate a \
                     persistent key with `openssl rand -hex 32` and set it on \
                     `bootstrapSecret.data.TALOS_AOT_HMAC_KEY`."
                .to_string(),
            verification: Verification::ConfigPresence,
            points: 0,
        };
    }
    if decoded_len < MIN_AOT_KEY_BYTES {
        return Check {
            name: "aot_integrity_key",
            status: Status::Warn,
            detail: format!(
                "TALOS_AOT_HMAC_KEY is too short ({} bytes decoded; need ≥{}) — worker will \
                 panic at first WASM execution. Regenerate with `openssl rand -hex 32`.",
                decoded_len, MIN_AOT_KEY_BYTES
            ),
            verification: Verification::ConfigPresence,
            points: 0,
        };
    }
    Check {
        name: "aot_integrity_key",
        status: Status::Pass,
        detail: "TALOS_AOT_HMAC_KEY set (≥32 bytes) — AOT blobs are integrity-verified. Shape \
                 only: the enforcing key ring lives in the worker process, so the controller \
                 cannot exercise it from here."
            .to_string(),
        verification: Verification::ConfigPresence,
        points: 10,
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 6 — audit event signing
// ───────────────────────────────────────────────────────────────────────────

/// Render `audit_event_signing`.
///
/// `env_present` and `verify_keys_present` are what separate the three
/// non-passing outcomes. The nastiest of them is real and reachable today:
/// `audit_signing_key` REJECTS a key carrying under 256 bits of effective
/// entropy and returns `None`, so a `TALOS_AUDIT_SIGNING_KEY` generated with
/// `openssl rand -hex 16` leaves every audit event unsigned while the old
/// presence check reported "Audit events are HMAC-signed for tamper detection"
/// and awarded full marks.
#[must_use]
pub fn check_audit_event_signing(
    outcome: talos_audit_event::SigningSelfTest,
    env_present: bool,
    verify_keys_present: bool,
) -> Check {
    use talos_audit_event::SigningSelfTest;
    match (outcome, env_present, verify_keys_present) {
        (SigningSelfTest::Verified, _, _) => Check {
            name: "audit_event_signing",
            status: Status::Pass,
            detail: "Audit events are HMAC-signed for tamper detection — a probe event was \
                     signed and its signature verified"
                .to_string(),
            verification: Verification::RoundTrip,
            points: 10,
        },
        (_, false, _) => Check {
            name: "audit_event_signing",
            status: Status::Warn,
            detail: "TALOS_AUDIT_SIGNING_KEY not set — audit events are unsigned".to_string(),
            verification: Verification::Parsed,
            points: 0,
        },
        // Key configured, but nothing signs and nothing verifies: the loader
        // dropped it at the entropy floor.
        (_, true, false) => Check {
            name: "audit_event_signing",
            status: Status::Fail,
            detail: "CRITICAL: TALOS_AUDIT_SIGNING_KEY is SET but audit events are NOT being \
                     signed — the key was REJECTED at load for carrying under 256 bits of \
                     effective entropy (a hex key needs ≥64 characters; `openssl rand -hex 16` \
                     is half of that). There is no tamper detection on the audit log. \
                     Regenerate with `openssl rand -hex 32`."
                .to_string(),
            verification: Verification::RoundTrip,
            points: 0,
        },
        // Signing and verification are both configured and disagree.
        (_, true, true) => Check {
            name: "audit_event_signing",
            status: Status::Fail,
            detail: "CRITICAL: audit events are being signed, but NO configured verification \
                     key accepts the signature — `verify_chain` will report every event as \
                     forged. Check TALOS_AUDIT_SIGNING_KEY against \
                     TALOS_AUDIT_SIGNING_KEY_PREVIOUS."
                .to_string(),
            verification: Verification::RoundTrip,
            points: 0,
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 7 — Redis TLS
// ───────────────────────────────────────────────────────────────────────────

/// What the Redis URL resolves to through the redis client's own parser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedisTransport {
    NotConfigured,
    Tls,
    /// TLS with certificate verification disabled (`#insecure`).
    TlsInsecure,
    Plaintext,
    UnixSocket,
    /// `REDIS_URL` is set but the redis client cannot parse it, so there will
    /// be no Redis at all.
    Unparseable,
}

/// Resolve `REDIS_URL` through `redis::Client::open` — the same call
/// `init_redis` makes — and report the transport it selected.
///
/// **No I/O.** `Client::open` only parses the URL into a `ConnectionInfo`; the
/// connection is established lazily. That is deliberate: opening a socket
/// here would report a *down* Redis as a TLS failure, which is not a TLS
/// finding, and would put network latency inside an interactive handler. The
/// scheme is also what genuinely decides the transport, so parsing it with the
/// real client is a verification and not a proxy — it catches two things the
/// `starts_with("rediss://")` prefix test cannot: a `#insecure` fragment
/// (TLS with certificate verification switched off) and a URL the client
/// rejects outright.
#[must_use]
pub fn probe_redis_transport(redis_url: &str) -> RedisTransport {
    if redis_url.is_empty() {
        return RedisTransport::NotConfigured;
    }
    let Ok(client) = redis::Client::open(redis_url) else {
        return RedisTransport::Unparseable;
    };
    match client.get_connection_info().addr {
        redis::ConnectionAddr::TcpTls { insecure: true, .. } => RedisTransport::TlsInsecure,
        redis::ConnectionAddr::TcpTls { .. } => RedisTransport::Tls,
        redis::ConnectionAddr::Tcp(..) => RedisTransport::Plaintext,
        redis::ConnectionAddr::Unix(..) => RedisTransport::UnixSocket,
    }
}

#[must_use]
pub fn check_redis_tls(transport: RedisTransport, is_prod: bool) -> Check {
    match transport {
        RedisTransport::NotConfigured => Check {
            name: "redis_tls",
            status: Status::Pass,
            detail: "Redis not configured".to_string(),
            verification: Verification::Parsed,
            points: 0,
        },
        RedisTransport::Tls => Check {
            name: "redis_tls",
            status: Status::Pass,
            detail: "Redis using TLS (rediss://) — resolved through the redis client's own URL \
                     parser, with certificate verification enabled"
                .to_string(),
            verification: Verification::Parsed,
            points: 10,
        },
        RedisTransport::TlsInsecure => Check {
            name: "redis_tls",
            status: Status::Fail,
            detail: "CRITICAL: REDIS_URL requests TLS with certificate verification DISABLED \
                     (the `#insecure` fragment). The transport is encrypted but unauthenticated \
                     — any certificate is accepted, so the connection is trivially \
                     machine-in-the-middle-able. Remove the `#insecure` fragment."
                .to_string(),
            verification: Verification::Parsed,
            points: 0,
        },
        RedisTransport::Plaintext => Check {
            name: "redis_tls",
            status: if is_prod { Status::Fail } else { Status::Info },
            detail: "Redis using plaintext (redis://) — use rediss:// in production".to_string(),
            verification: Verification::Parsed,
            points: 0,
        },
        RedisTransport::UnixSocket => Check {
            name: "redis_tls",
            status: Status::Info,
            detail: "Redis is reached over a unix socket — transport TLS does not apply"
                .to_string(),
            verification: Verification::Parsed,
            points: 0,
        },
        RedisTransport::Unparseable => Check {
            name: "redis_tls",
            status: Status::Fail,
            detail: "CRITICAL: REDIS_URL is SET but the redis client cannot parse it, so there \
                     is no Redis connection at all — distributed rate limiting and the WASM \
                     cache are silently disabled. (The parse error is withheld here: a Redis \
                     URL can embed a password.)"
                .to_string(),
            verification: Verification::Parsed,
            points: 0,
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 8 — audit immutability triggers
// ───────────────────────────────────────────────────────────────────────────

/// `None` means the catalogue query failed — nobody looked, which is not the
/// same finding as "the triggers are not installed".
#[must_use]
pub fn check_audit_immutability_triggers(count: Option<i64>) -> Check {
    match count {
        Some(n) if n > 0 => Check {
            name: "audit_immutability_triggers",
            status: Status::Pass,
            detail: format!("{} immutability trigger(s) active", n),
            verification: Verification::RoundTrip,
            points: 10,
        },
        Some(_) => Check {
            name: "audit_immutability_triggers",
            status: Status::Fail,
            detail: "No audit immutability triggers found — run migrations".to_string(),
            verification: Verification::RoundTrip,
            points: 0,
        },
        None => Check {
            name: "audit_immutability_triggers",
            status: Status::Warn,
            detail: "NOT VERIFIED: the trigger-catalogue query failed, so this run did not \
                     establish whether audit immutability triggers are installed. This is a \
                     database problem, not a missing migration."
                .to_string(),
            verification: Verification::NotVerified,
            points: 0,
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 9 — CORS origins
// ───────────────────────────────────────────────────────────────────────────

/// Render `cors_origins` from the PARSED allowlist rather than from the
/// presence of `ALLOWED_ORIGIN`.
///
/// `parsed` is [`talos_config::check_allowed_origins`]'s result: the list
/// `is_origin_allowed` will enforce, produced by the same code that produces
/// it at runtime. `explicitly_set` distinguishes an operator-configured list
/// from the dev-mode localhost defaults, and carries the scoring exactly as
/// before (points only for an explicit configuration).
///
/// The case this converts: `ALLOWED_ORIGIN=""` is a value the old presence
/// test called "not configured" and `ALLOWED_ORIGIN=","` is one it called
/// "explicitly configured" — and both parse to ZERO origins, meaning the CORS
/// layer rejects every origin.
#[must_use]
pub fn check_cors_origins(parsed: &Result<Vec<String>, String>, explicitly_set: bool) -> Check {
    match parsed {
        Err(e) => Check {
            name: "cors_origins",
            status: Status::Fail,
            detail: format!("CRITICAL: {}", e),
            verification: Verification::Parsed,
            points: 0,
        },
        Ok(origins) if origins.is_empty() => Check {
            name: "cors_origins",
            status: Status::Fail,
            detail: "CRITICAL: the CORS allowlist parses to ZERO origins, so `is_origin_allowed` \
                     rejects every origin. ALLOWED_ORIGIN is set but contains no usable entries \
                     (empty or separator-only values are dropped)."
                .to_string(),
            verification: Verification::Parsed,
            points: 0,
        },
        Ok(origins) if explicitly_set => Check {
            name: "cors_origins",
            status: Status::Pass,
            detail: format!(
                "ALLOWED_ORIGIN parses to {} enforced origin(s)",
                origins.len()
            ),
            verification: Verification::Parsed,
            points: 10,
        },
        Ok(origins) => Check {
            name: "cors_origins",
            status: Status::Pass,
            detail: format!(
                "Using default localhost origins (dev mode) — {} enforced origin(s)",
                origins.len()
            ),
            verification: Verification::Parsed,
            points: 0,
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Scoring + assembly
// ───────────────────────────────────────────────────────────────────────────

/// Maximum attainable score.
///
/// The per-outcome point values sum to more than this across all arms, which
/// reads as an over-100 bug on a first pass. They are not all attainable
/// together: `jwt_algorithm` awards 10 OR 5, never both. The reachable maximum
/// is 10 prod + 10 jwt + 15 master + 15 worker + 10 aot + 10 audit + 10
/// redis-tls + 10 triggers + 10 cors = 100.
///
/// Two consequences worth stating rather than rediscovering:
///  * Grade A (≥ 90) requires production, since `production_mode`'s 10 points
///    are unearnable outside it. A dev stack tops out at 90, and at 80
///    (grade B) with the usual plaintext local Redis.
///  * In production, A tolerates exactly one missing 10-point control.
pub const MAX_SCORE: u32 = 100;

pub const GRADE_A: u32 = 90;
pub const GRADE_B: u32 = 75;
pub const GRADE_C: u32 = 60;
pub const GRADE_D: u32 = 40;

#[must_use]
pub fn grade_for(score: u32) -> &'static str {
    if score >= GRADE_A {
        "A"
    } else if score >= GRADE_B {
        "B"
    } else if score >= GRADE_C {
        "C"
    } else if score >= GRADE_D {
        "D"
    } else {
        "F"
    }
}

/// Render a finished check list into the canonical `security_audit` response.
#[must_use]
pub fn render_report(checks: &[Check]) -> serde_json::Value {
    let score: u32 = checks.iter().map(|c| c.points).sum();
    let grade = grade_for(score);

    let mut pass_count = 0u32;
    let mut warn_count = 0u32;
    let mut fail_count = 0u32;
    let mut info_count = 0u32;
    let mut round_trip = 0u32;
    let mut parsed = 0u32;
    let mut config_presence = 0u32;
    let mut not_verified = 0u32;
    for c in checks {
        match c.status {
            Status::Pass => pass_count += 1,
            Status::Warn => warn_count += 1,
            Status::Fail => fail_count += 1,
            Status::Info => info_count += 1,
        }
        match c.verification {
            Verification::RoundTrip => round_trip += 1,
            Verification::Parsed => parsed += 1,
            Verification::ConfigPresence => config_presence += 1,
            Verification::NotVerified => not_verified += 1,
        }
    }

    serde_json::json!({
        "security_score": score,
        "max_score": MAX_SCORE,
        "grade": grade,
        "grade_thresholds": {
            "A": GRADE_A,
            "B": GRADE_B,
            "C": GRADE_C,
            "D": GRADE_D,
            "F": 0,
        },
        "status_counts": {
            "pass": pass_count,
            "warn": warn_count,
            "fail": fail_count,
            "info": info_count,
        },
        "status_legend": {
            "pass": "Security control is configured correctly.",
            "warn": "Control is configured but not at the recommended hardening level, or could not be verified.",
            "fail": "Control is missing, misconfigured, or present-but-non-functional — fix before going to production.",
            "info": "Configuration noted; not security-graded (e.g. dev-mode posture).",
        },
        "verification_counts": {
            "round_trip": round_trip,
            "parsed": parsed,
            "config_presence": config_presence,
            "not_verified": not_verified,
        },
        "verification_legend": {
            "round_trip": "The control was EXERCISED this run — a probe value was pushed through the real primitive and the result inspected.",
            "parsed": "The live configuration was read through the code that enforces it. There is no operation to exercise, or the control is definitively absent.",
            "config_presence": "Presence and shape only. This check CANNOT detect a control that is configured but non-functional.",
            "not_verified": "The verification could not run here. The status says what was NOT learned — it never means the control is good.",
        },
        "checks": checks.iter().map(Check::json).collect::<Vec<_>>(),
        "recommendation": if score >= GRADE_A { "Excellent security posture" }
            else if score >= GRADE_B { "Good — address warnings for production hardening" }
            else if score >= GRADE_C { "Acceptable for development — address failures before production" }
            else { "Critical gaps — do not deploy to production without fixing failures" },
    })
}

/// Run every check and render the report.
///
/// Idempotent and side-effect free: see the per-probe documentation. The only
/// database access is a read of `pg_trigger`.
pub async fn run_security_audit(
    sysrepo: &SystemRepository,
    secrets: &SecretsManager,
) -> serde_json::Value {
    let is_prod = talos_config::is_production();

    // KEK wrap→unwrap, bounded so a slow KMS yields a finding, not a hang.
    let kek = tokio::time::timeout(KEK_PROBE_TIMEOUT, secrets.kek_selftest())
        .await
        .ok();

    let triggers = sysrepo
        .count_triggers_like(IMMUTABILITY_TRIGGER_PATTERN)
        .await
        .inspect_err(|e| {
            tracing::error!(
                target: "talos_security",
                event_kind = "security_audit_trigger_query_failed",
                error = %e,
                "security_audit could not read the trigger catalogue"
            );
        })
        .ok();

    let checks = vec![
        check_production_mode(is_prod),
        check_jwt_algorithm(
            talos_auth::jwt_selftest(),
            &talos_config::get_env("TALOS_DEPLOYMENT_TOPOLOGY", "single_pod"),
        ),
        check_master_encryption_key(kek),
        check_job_signing_key(probe_job_signing_key()),
        check_aot_integrity_key(&std::env::var("TALOS_AOT_HMAC_KEY").unwrap_or_default()),
        check_audit_event_signing(
            talos_audit_event::audit_signing_selftest(),
            talos_config::env_var_is_set_nonempty("TALOS_AUDIT_SIGNING_KEY"),
            !talos_audit_event::audit_verify_keys().is_empty(),
        ),
        check_redis_tls(
            probe_redis_transport(&std::env::var("REDIS_URL").unwrap_or_default()),
            is_prod,
        ),
        check_audit_immutability_triggers(triggers),
        check_cors_origins(
            &talos_config::check_allowed_origins(),
            talos_config::env_var_is_set_nonempty("ALLOWED_ORIGIN"),
        ),
    ];

    render_report(&checks)
}

#[cfg(test)]
mod tests;
