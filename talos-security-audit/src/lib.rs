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
//! **"Cannot be exercised" is a claim with an expiry date.** `write_ceiling_enforcement`
//! said, verbatim, "the enforcing gate lives in the worker process, so the
//! controller cannot exercise it from here" — true when it was written, and
//! false from the moment the controller grew write-ceiling gates of its own
//! (#750's `__memory_write__` envelope gate, #757's signed-RPC gate). Both run
//! in THIS process; both are pure; both are now driven by
//! [`ControllerGateProbe::run`] on every audit. When a check's own reason for
//! not exercising something stops being true, the check becomes a false
//! statement about the control it audits — which is the misleading-report class
//! this crate exists to remove, arriving from inside.
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
//! and [`talos_auth::jwt_selftest`]. The write-ceiling probes are the same:
//! [`ControllerGateProbe::run`] pushes a synthetic node output and four
//! synthetic ceiling reads through the two real gates, touching no database, no
//! actor row and no counter.
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

/// What a check is actually measuring.
///
/// This axis exists because `production_mode` is not a security *control* —
/// it is a statement about where this deployment is running, and its ten
/// points are unearnable on a developer's laptop no matter how well every
/// control is configured. Collapsing it into the same undifferentiated score
/// as a broken KEK is a real modelling choice, so the report now says which
/// is which instead of leaving the operator to infer it from the check name.
///
/// **The weights are unchanged** — posture is still scored exactly as it
/// always was, so a score recorded last month still means what it meant. What
/// is new is that `score_accounting.forfeited_by_kind` lets a reader subtract
/// it: "30 points short, of which 10 is because this is a dev box" is a
/// different sentence from "30 points of broken controls", and before this
/// field the response could not tell them apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckKind {
    /// A security control: something that protects the system, and whose
    /// absence or malfunction is a security finding anywhere it runs.
    Control,
    /// A deployment-posture fact. Scored, but not a control — a dev stack
    /// cannot earn these points and is not less secure for it.
    DeploymentPosture,
}

impl CheckKind {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            CheckKind::Control => "control",
            CheckKind::DeploymentPosture => "deployment_posture",
        }
    }
}

/// The point weight and kind of every check, keyed by check name.
///
/// **This is the only place a weight is written down.** Each check function
/// awards `points` for the outcome it found; the *maximum* that check could
/// have awarded is a property of the check, not of the outcome, so it lives
/// here. Keeping it out of the per-arm literals is what makes
/// `max_points` uniform across a check's arms by construction — a
/// `jwt_algorithm` that warns at 5 still reports `max_points: 10`, so
/// `security_score / max_score` decomposes the same way whatever the
/// deployment looks like.
///
/// The nine SCORED weights sum to [`MAX_SCORE`]; `weights_sum_to_max_score`
/// pins it. `write_ceiling_enforcement` is deliberately weighted **0** — see
/// its entry below.
const CHECK_WEIGHTS: &[(&str, u32, CheckKind)] = &[
    ("production_mode", 10, CheckKind::DeploymentPosture),
    ("jwt_algorithm", 10, CheckKind::Control),
    ("master_encryption_key", 15, CheckKind::Control),
    ("job_signing_key", 15, CheckKind::Control),
    ("aot_integrity_key", 10, CheckKind::Control),
    ("audit_event_signing", 10, CheckKind::Control),
    ("redis_tls", 10, CheckKind::Control),
    ("audit_immutability_triggers", 10, CheckKind::Control),
    ("cors_origins", 10, CheckKind::Control),
    // WEIGHT 0 — REPORTED, NOT SCORED, and the zero is a decision rather than
    // an oversight.
    //
    // Three reasons, in order:
    //  1. `TALOS_WRITE_CEILING_ENFORCED` is DEFAULT OFF by design (a staged
    //     rollout, the same shape as TALOS_ENVELOPE_SEALING). Docking points
    //     for using the documented default would make the score say "less
    //     secure" about a deployment that did nothing wrong.
    //  2. The grade bands here are ABSOLUTE against a 100-point total, and
    //     `MAX_SCORE`'s own doc block leans on that calibration (a dev stack
    //     tops out at exactly 90, which is exactly GRADE_A). A tenth weighted
    //     check would silently re-grade every deployment — collateral far
    //     larger than this finding.
    //  3. The finding is CONDITIONAL: an unenforced ceiling only matters where
    //     an actor is configured `readonly`, and this check deliberately does
    //     not read actor rows (see `check_write_ceiling_enforcement`).
    //
    // A zero weight does NOT make it decorative. It carries `Status` and
    // `Verification`, so it lands in `status_counts`, in
    // `verification_counts`, and — the part an operator actually reads — in
    // `recommendation_for`, which names warning and unverified checks by name.
    // `unweighted_checks_cost_nothing` pins the arithmetic, because a check
    // whose legend says "ungraded" while it quietly costs points is a defect
    // this file has shipped before.
    ("write_ceiling_enforcement", 0, CheckKind::Control),
];

/// One rendered check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
    pub verification: Verification,
    /// Points this outcome contributes to `security_score`.
    pub points: u32,
    /// Optional per-HALF breakdown, for a check whose subject has more than
    /// one enforcement surface and whose halves are verified to DIFFERENT
    /// standards.
    ///
    /// `None` for every check with a single surface — which is all of them but
    /// one. `write_ceiling_enforcement` uses it because the write ceiling is
    /// ONE control with a controller half this process can EXERCISE and a
    /// worker-fleet half it can only read a self-report about, and collapsing
    /// those into a single `verification` word necessarily misstates one of
    /// them. Each part carries its own `verification`; the check's top-level
    /// `verification` remains the WEAKEST of the facts its `status` rests on,
    /// so `verification_counts` can never over-claim.
    pub parts: Option<serde_json::Value>,
}

impl Check {
    /// The most this check could have awarded, from [`CHECK_WEIGHTS`].
    ///
    /// An unlisted name falls back to `self.points`, i.e. a forfeit of zero.
    /// That is the safe direction: an unregistered check can never invent a
    /// shortfall the operator is then asked to explain. `every_check_name_has_a_weight`
    /// is what stops the fallback being reached in production.
    #[must_use]
    pub fn max_points(&self) -> u32 {
        CHECK_WEIGHTS
            .iter()
            .find(|(n, _, _)| *n == self.name)
            .map_or(self.points, |(_, max, _)| *max)
    }

    /// Whether this check grades a security control or a deployment fact.
    #[must_use]
    pub fn kind(&self) -> CheckKind {
        CHECK_WEIGHTS
            .iter()
            .find(|(n, _, _)| *n == self.name)
            .map_or(CheckKind::Control, |(_, _, k)| *k)
    }

    /// Points this outcome did NOT award. Saturating, so a hypothetical
    /// over-award reports `0` rather than wrapping.
    #[must_use]
    pub fn forfeited(&self) -> u32 {
        self.max_points().saturating_sub(self.points)
    }

    fn json(&self) -> serde_json::Value {
        let mut v = serde_json::json!({
            "check": self.name,
            "status": self.status.as_str(),
            "detail": self.detail,
            "verification": self.verification.as_str(),
            "points": self.points,
            "max_points": self.max_points(),
            "kind": self.kind().as_str(),
        });
        // Only the check that HAS halves emits the key. An empty `parts: {}`
        // on every other check would read as "this check has halves and they
        // were not measured", which is the opposite of true.
        if let (Some(parts), Some(obj)) = (self.parts.clone(), v.as_object_mut()) {
            obj.insert("parts".to_string(), parts);
        }
        v
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
        parts: None,
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
            parts: None,
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
            parts: None,
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
            parts: None,
        },
        talos_auth::JwtSelfTest::Broken { stage: "secret" } => Check {
            name: "jwt_algorithm",
            status: Status::Fail,
            detail: "CRITICAL: JWT_SECRET is not set — this process cannot mint or verify \
                     access tokens."
                .to_string(),
            verification: Verification::RoundTrip,
            points: 0,
            parts: None,
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
            parts: None,
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
            parts: None,
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
            parts: None,
        },
        Some(KekSelfTest::Unavailable) => Check {
            name: "master_encryption_key",
            status: Status::Warn,
            detail: "NOT VERIFIED: the KEK provider could not be read (lock poisoned), so this \
                     run did not establish whether envelope encryption works."
                .to_string(),
            verification: Verification::NotVerified,
            points: 0,
            parts: None,
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
            parts: None,
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
            parts: None,
        },
        JobSigningProbe::Absent => Check {
            name: "job_signing_key",
            status: Status::Warn,
            detail: "WORKER_SHARED_KEY not set — job payloads are unsigned".to_string(),
            verification: Verification::Parsed,
            points: 0,
            parts: None,
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
            parts: None,
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
            parts: None,
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
            parts: None,
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
            parts: None,
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
        parts: None,
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
            parts: None,
        },
        (_, false, _) => Check {
            name: "audit_event_signing",
            status: Status::Warn,
            detail: "TALOS_AUDIT_SIGNING_KEY not set — audit events are unsigned".to_string(),
            verification: Verification::Parsed,
            points: 0,
            parts: None,
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
            parts: None,
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
            parts: None,
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

/// Render `redis_tls`.
///
/// **Known scoring wrinkle, surfaced rather than fixed.** Two arms report no
/// problem and still forfeit all ten points: `NotConfigured` (`pass`, "Redis
/// not configured") and `UnixSocket` (`info`, "transport TLS does not
/// apply"). A deployment with no Redis, or one reaching it over a unix
/// socket, therefore cannot reach `max_score` however well it is configured.
///
/// That is real, and it is now VISIBLE — both arms appear in
/// `score_accounting.shortfalls` carrying their own detail as the reason, so
/// an operator can see the ten points and why. It is not repaired here
/// because the repair is not local: making a check inapplicable means making
/// the denominator per-deployment, and [`GRADE_A`] and friends are ABSOLUTE
/// point thresholds, not percentages. Under a variable denominator, 80/90
/// (89 %) would grade B while 90/100 (90 %) grades A — the letter would stop
/// meaning one thing. Re-grading on percentage is a deliberate change to
/// every historical comparison an operator has made, and belongs in its own
/// change with its own justification, not smuggled in beside a reporting fix.
#[must_use]
pub fn check_redis_tls(transport: RedisTransport, is_prod: bool) -> Check {
    match transport {
        RedisTransport::NotConfigured => Check {
            name: "redis_tls",
            status: Status::Pass,
            detail: "Redis not configured".to_string(),
            verification: Verification::Parsed,
            points: 0,
            parts: None,
        },
        RedisTransport::Tls => Check {
            name: "redis_tls",
            status: Status::Pass,
            detail: "Redis using TLS (rediss://) — resolved through the redis client's own URL \
                     parser, with certificate verification enabled"
                .to_string(),
            verification: Verification::Parsed,
            points: 10,
            parts: None,
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
            parts: None,
        },
        RedisTransport::Plaintext => Check {
            name: "redis_tls",
            status: if is_prod { Status::Fail } else { Status::Info },
            detail: "Redis using plaintext (redis://) — use rediss:// in production".to_string(),
            verification: Verification::Parsed,
            points: 0,
            parts: None,
        },
        RedisTransport::UnixSocket => Check {
            name: "redis_tls",
            status: Status::Info,
            detail: "Redis is reached over a unix socket — transport TLS does not apply"
                .to_string(),
            verification: Verification::Parsed,
            points: 0,
            parts: None,
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
            parts: None,
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
            parts: None,
        },
        Some(_) => Check {
            name: "audit_immutability_triggers",
            status: Status::Fail,
            detail: "No audit immutability triggers found — run migrations".to_string(),
            verification: Verification::RoundTrip,
            points: 0,
            parts: None,
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
            parts: None,
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Check 10 — per-actor write-ceiling enforcement (reported, unscored)
// ───────────────────────────────────────────────────────────────────────────

/// What one exercise of the CONTROLLER's own write-ceiling gates found.
///
/// # Why this type exists
///
/// The write ceiling is ONE control with THREE enforcement surfaces, and until
/// this change the audit knew about one of them. The worker gates
/// `agent_memory::set` and friends in its own process; the CONTROLLER gates the
/// `__memory_write__` envelope on node completion (#750) and every
/// actor-attributed signed-RPC mutation (#757). Both controller gates run in
/// THIS process, both are pure functions, and both can therefore be handed a
/// probe value and inspected — which is precisely the `round_trip` standard
/// this audit's own legend sets.
///
/// The check used to say, verbatim, "the enforcing gate lives in the worker
/// process, so the controller cannot exercise it from here." That was true when
/// #752 wrote it and false by the time it was read: a false statement about the
/// control being audited, inside the audit of that control.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ControllerGateProbe {
    /// Whether THIS process enforces the ceiling, from the controller's ONE
    /// reader of `TALOS_WRITE_CEILING_ENFORCED`.
    ///
    /// Deliberately not re-read here. A second reader of a flag is a second
    /// answer to "is this control live" (check 69's class), and an audit that
    /// disagrees with the gate it audits is worse than one that stays quiet.
    pub enforced: bool,
    /// The `__memory_write__` envelope route (#750).
    pub envelope: Result<(), &'static str>,
    /// The signed-RPC mutation route (#757).
    pub rpc: Result<(), &'static str>,
}

impl ControllerGateProbe {
    /// Exercise both controller gates and read the controller's own flag.
    ///
    /// Pure, in-process, side-effect free and allocation-light — no database,
    /// no env read beyond the already-cached `OnceLock`. That is what lets
    /// [`run_security_audit`] keep its "the only database access is a read of
    /// `pg_trigger`" promise while raising this check to `round_trip`.
    #[must_use]
    pub fn run() -> Self {
        Self {
            enforced: talos_workflow_engine::write_ceiling_gate::controller_write_ceiling_enforced(
            ),
            envelope: talos_workflow_engine::write_ceiling_gate::probe_envelope_gate(),
            rpc: talos_rpc_subscribers::write_ceiling::probe_rpc_gate(),
        }
    }

    /// The first broken arm, if either gate misbehaved.
    #[must_use]
    pub fn broken_arm(&self) -> Option<&'static str> {
        self.envelope.err().or_else(|| self.rpc.err())
    }
}

/// Render `write_ceiling_enforcement`.
///
/// # What this grades
///
/// `actors.max_write_ceiling` (`readonly` | `write`) is ONE control with two
/// halves this process can know to two DIFFERENT standards, and the shape of
/// this check follows from refusing to average them:
///
/// * **The controller half** — the `__memory_write__` envelope gate (#750) and
///   the signed-RPC mutation gate (#757) — runs here. It is EXERCISED every run
///   by [`ControllerGateProbe::run`]: a readonly probe must be refused, a
///   write-capable probe permitted, an unreadable rule refused (fail closed),
///   and an unenforcing deployment must permit everything. That is
///   `round_trip`.
/// * **The worker-fleet half** is a value another process reported about its
///   own env at ITS boot, transported UNSIGNED. Nothing was exercised. That is
///   `config_presence` — the same standing as `aot_integrity_key`, whose
///   enforcing key ring likewise lives in the worker.
///
/// # The top-level `verification`, and the rule behind it
///
/// **The weakest verification among the facts the `status` rests on**, with one
/// exception: a BROKEN controller gate is [`RoundTrip`], because that finding
/// came from an exercise (the shape `job_signing_key`'s failing arm already
/// uses).
///
/// So a healthy, fully-enforcing deployment still reports `config_presence` at
/// the top, and `parts.controller_gate.verification` reports the `round_trip`
/// that actually happened. Promoting the WHOLE check to `round_trip` because
/// half of it was exercised would overstate — the fleet half is still an
/// unsigned self-report — and overstating is the defect this change exists to
/// remove. Understating, with a per-half breakdown that says which half is
/// which, is the safe direction.
///
/// # Why `None` is never a pass
///
/// `None` means the fleet registry could not be read: "nobody looked" and
/// "nothing enforces" are different findings and only one of them is about the
/// database. [`Unknown`] is likewise not a pass — it is what a fleet reports
/// when nothing has registered, the state in which the most tempting wrong
/// answer ("no evidence of a problem") is exactly backwards.
///
/// # The split
///
/// A fleet reporting `all` while THIS controller's flag is unset is a
/// `some`-shaped split across the two halves of one control, in the other
/// direction from the one #757 called dangerous: every worker refuses a
/// readonly actor's host calls, and the controller honours the same actor's
/// returned `__memory_write__` envelope and its signed-RPC mutations. #750's
/// chart note says to set the variable on BOTH processes; this is the check
/// that can now say whether you did.
///
/// # What it deliberately does not do
///
/// It does not count `readonly` actors — that needs a cross-tenant actor query
/// for a platform-wide audit, and the per-actor consequence is disclosed where
/// it is actionable (`set_actor_write_ceiling`). It does not probe the
/// DB-backed ceiling READ; see
/// [`talos_rpc_subscribers::write_ceiling::probe_rpc_gate`] for why, and
/// `controller/tests/rpc_write_ceiling_tests.rs` for what covers it.
///
/// [`RoundTrip`]: Verification::RoundTrip
/// [`Unknown`]: talos_worker_identity_repository::FleetWriteCeilingState::Unknown
#[must_use]
pub fn check_write_ceiling_enforcement(
    fleet: Option<talos_worker_identity_repository::WriteCeilingFleetSummary>,
    probe: ControllerGateProbe,
) -> Check {
    use talos_worker_identity_repository::FleetWriteCeilingState as S;

    let controller_part = |probe_json: serde_json::Value, verification: &'static str| {
        serde_json::json!({
            "enforced_flag": probe.enforced,
            "probe": probe_json,
            "verification": verification,
        })
    };

    // A broken controller gate outranks every fleet finding: the process
    // running this audit does not refuse what it is configured to refuse.
    if let Some(arm) = probe.broken_arm() {
        return Check {
            name: "write_ceiling_enforcement",
            status: Status::Fail,
            detail: format!(
                "CRITICAL: the CONTROLLER's own write-ceiling gate did not behave as the \
                 control requires — {arm}. A probe value was pushed through the real gate and \
                 the result inspected; this is not a reading of configuration. Until it is \
                 fixed, a 'readonly' actor's writes are bounded by nothing the controller does."
            ),
            verification: Verification::RoundTrip,
            points: 0,
            parts: Some(serde_json::json!({
                "controller_gate": controller_part(
                    serde_json::json!({"result": "BROKEN", "arm": arm}),
                    "round_trip",
                ),
                "worker_fleet": fleet_part(fleet.as_ref()),
            })),
        };
    }

    // Both controller gates behaved. Say exactly which values were pushed
    // through them, so `round_trip` is a claim an operator can check.
    let probe_json = serde_json::json!({
        "readonly_actor": "refused",
        "write_capable_actor": "permitted",
        "unreadable_rule": "refused (fail closed)",
        "enforcement_disabled": "permitted",
        "routes": ["__memory_write__ envelope (#750)", "signed-RPC mutation (#757)"],
    });

    let Some(f) = fleet else {
        return Check {
            name: "write_ceiling_enforcement",
            status: Status::Warn,
            detail: format!(
                "PARTLY VERIFIED. Controller half, EXERCISED this run: {} Fleet half, NOT \
                 VERIFIED: the worker-identity registry query failed, so this run did not \
                 establish whether any WORKER enforces the ceiling — a database problem, not a \
                 finding about the ceiling.",
                controller_posture(probe.enforced)
            ),
            verification: Verification::NotVerified,
            points: 0,
            parts: Some(serde_json::json!({
                "controller_gate": controller_part(probe_json, "round_trip"),
                "worker_fleet": fleet_part(None),
            })),
        };
    };

    // The split: every worker enforces, this controller does not. Not a pass —
    // the controller's two routes are ungated for the same actors the fleet is
    // refusing.
    let split = matches!(f.state, S::All) && !probe.enforced;

    let (status, verification) = if split {
        // The finding rests on the flag — read through the ONE reader the gate
        // itself uses, i.e. `Parsed` — and on the exercised gates. It does not
        // rest on the fleet self-report, which agrees with neither. `Parsed` is
        // the weaker of the two facts it does rest on.
        (Status::Warn, Verification::Parsed)
    } else {
        match f.state {
            S::All => (Status::Pass, Verification::ConfigPresence),
            // A mixed fleet is a real finding: nothing routes jobs by
            // enforcement posture, so a readonly actor's job may land on the
            // worker that does not enforce.
            S::Some | S::None => (Status::Warn, Verification::ConfigPresence),
            // Not a pass. Nothing was established about the fleet.
            S::Unknown => (Status::Warn, Verification::NotVerified),
        }
    };

    let split_note = if split {
        " SPLIT CONTROL: every registered worker enforces the ceiling and THIS CONTROLLER does \
         not — TALOS_WRITE_CEILING_ENFORCED is unset here, so the controller's own two routes \
         (a module's returned __memory_write__ envelope, and every actor-attributed signed-RPC \
         mutation) are ungated for the same actors the fleet is refusing. Set the variable on \
         BOTH processes."
    } else {
        ""
    };

    Check {
        name: "write_ceiling_enforcement",
        status,
        detail: format!(
            "{} Worker-self-reported at registration and UNSIGNED — diagnostic only, never an \
             authorization input.{} CONTROLLER HALF, EXERCISED this run: {} Reported, not \
             scored.",
            f.note(),
            split_note,
            controller_posture(probe.enforced),
        ),
        verification,
        points: 0,
        parts: Some(serde_json::json!({
            "controller_gate": controller_part(probe_json, "round_trip"),
            "worker_fleet": fleet_part(Some(&f)),
        })),
    }
}

/// One sentence describing what the controller's own gates do, given the flag.
///
/// Both halves are true statements about an EXERCISED gate: with the flag off
/// the gates were still driven and still permitted everything, which is the
/// documented staged-rollout default rather than an absence of evidence.
fn controller_posture(enforced: bool) -> &'static str {
    if enforced {
        "TALOS_WRITE_CEILING_ENFORCED is set here, and both controller gates (the \
         __memory_write__ envelope gate and the signed-RPC mutation gate) refused a readonly \
         probe, permitted a write-capable one, and failed CLOSED on an unreadable rule."
    } else {
        "TALOS_WRITE_CEILING_ENFORCED is NOT set here, so both controller gates permit every \
         write by design (the staged-rollout default) — the gates themselves were driven and \
         are correct; they are switched off."
    }
}

/// The fleet half of `parts`, at the only standard it can honestly claim.
fn fleet_part(
    fleet: Option<&talos_worker_identity_repository::WriteCeilingFleetSummary>,
) -> serde_json::Value {
    match fleet {
        Some(f) => serde_json::json!({
            "state": f.state.as_str(),
            "note": f.note(),
            "source": "worker self-report at registration, UNSIGNED",
            "verification": "config_presence",
        }),
        None => serde_json::json!({
            "state": null,
            "note": "the worker-identity registry query failed — nothing was established about \
                     the fleet",
            "source": "worker self-report at registration, UNSIGNED",
            "verification": "not_verified",
        }),
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
            parts: None,
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
            parts: None,
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
            parts: None,
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
            parts: None,
        },
    }
}

// ───────────────────────────────────────────────────────────────────────────
// Scoring + assembly
// ───────────────────────────────────────────────────────────────────────────

/// Maximum attainable score — the sum of every entry in [`CHECK_WEIGHTS`].
///
/// The per-outcome point values sum to more than this across all arms, which
/// reads as an over-100 bug on a first pass. They are not all attainable
/// together: `jwt_algorithm` awards 10 OR 5, never both. The reachable maximum
/// is 10 prod + 10 jwt + 15 master + 15 worker + 10 aot + 10 audit + 10
/// redis-tls + 10 triggers + 10 cors = 100.
///
/// Three consequences worth stating rather than rediscovering:
///  * `production_mode`'s 10 points are unearnable outside production, so a
///    dev stack tops out at exactly 90 — which is precisely [`GRADE_A`].
///    Grade A is therefore *reachable* in development, but only at
///    perfection: every other control must be at full marks, including
///    `rediss://` for the local Redis and a persistent `TALOS_AOT_HMAC_KEY`.
///    One missing 10-point control in dev is a B.
///  * In production, A tolerates exactly one missing 10-point control.
///  * Because posture is scored, part of any shortfall may be posture rather
///    than control health. `score_accounting.forfeited_by_kind` splits it;
///    see [`CheckKind`] for why that split is reported instead of removed.
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

/// Build the `recommendation` string from the FACTS, never from the score.
///
/// The string this replaced was selected purely by score band, and the
/// grade-C band read *"Acceptable for development — address failures before
/// production"*. On the deployment that motivated this change that sentence
/// was emitted alongside `"fail": 0`: it told the operator to go and fix an
/// empty set. Advice keyed off an aggregate cannot know whether the thing it
/// names exists, so this builds one clause per class and emits a clause only
/// when that class has members. `recommendation_names_only_present_classes`
/// is the guard.
///
/// Unverified checks are pulled out of the warn clause and named separately:
/// they carry `Status::Warn`, but "could not tell" and "configured below the
/// recommended level" are different jobs for the operator, and
/// [`Verification::NotVerified`]'s whole contract is that it never reads as a
/// verdict about the control.
#[must_use]
pub fn recommendation_for(checks: &[Check]) -> String {
    fn names(checks: &[Check], f: impl Fn(&Check) -> bool) -> Vec<&'static str> {
        checks.iter().filter(|c| f(c)).map(|c| c.name).collect()
    }

    let failing = names(checks, |c| c.status == Status::Fail);
    let unverified = names(checks, |c| c.verification == Verification::NotVerified);
    let warning = names(checks, |c| {
        c.status == Status::Warn && c.verification != Verification::NotVerified
    });
    // Points lost by checks that reported no problem at all. This is the
    // class the old wording had no vocabulary for, and the entire reason a
    // clean report could still be a C.
    let quiet_shortfall: Vec<&Check> = checks
        .iter()
        .filter(|c| {
            !matches!(c.status, Status::Fail | Status::Warn)
                && c.verification != Verification::NotVerified
                && c.forfeited() > 0
        })
        .collect();

    let score: u32 = checks.iter().map(|c| c.points).sum();
    let max: u32 = checks.iter().map(Check::max_points).sum();
    let mut parts = vec![format!(
        "Score {}/{} (grade {}).",
        score,
        max,
        grade_for(score)
    )];

    if !failing.is_empty() {
        parts.push(format!(
            "Fix {} failing control(s): {}.",
            failing.len(),
            failing.join(", ")
        ));
    }
    if !unverified.is_empty() {
        parts.push(format!(
            "{} check(s) could not be verified ({}) — that says what was not learned, not that the control is good.",
            unverified.len(),
            unverified.join(", ")
        ));
    }
    if !warning.is_empty() {
        parts.push(format!(
            "Harden {} warning(s): {}.",
            warning.len(),
            warning.join(", ")
        ));
    }
    if !quiet_shortfall.is_empty() {
        let lost: u32 = quiet_shortfall.iter().map(|c| c.forfeited()).sum();
        let detail: Vec<String> = quiet_shortfall
            .iter()
            .map(|c| format!("{} (-{})", c.name, c.forfeited()))
            .collect();
        parts.push(format!(
            "{} point(s) are not awarded by check(s) that reported no problem: {} — see score_accounting.",
            lost,
            detail.join(", ")
        ));
    }
    if parts.len() == 1 {
        parts.push(
            "No failing, warning or unverified checks, and every check scored in full.".to_string(),
        );
    }
    parts.join(" ")
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

    // The denominator is DERIVED from the same checks the response renders,
    // not read from the MAX_SCORE constant. A constant can disagree with the
    // list (add a tenth check, forget to bump it) and the response would then
    // print a ratio neither half of which the reader can check.
    // `weights_sum_to_max_score` pins the two together for the production nine.
    let max_score: u32 = checks.iter().map(Check::max_points).sum();
    let forfeited = max_score.saturating_sub(score);
    let shortfalls: Vec<serde_json::Value> = checks
        .iter()
        .filter(|c| c.forfeited() > 0)
        .map(|c| {
            serde_json::json!({
                "check": c.name,
                "status": c.status.as_str(),
                "kind": c.kind().as_str(),
                "awarded": c.points,
                "max_points": c.max_points(),
                "forfeited": c.forfeited(),
                "reason": c.detail,
            })
        })
        .collect();
    let forfeited_control: u32 = checks
        .iter()
        .filter(|c| c.kind() == CheckKind::Control)
        .map(Check::forfeited)
        .sum();
    let forfeited_posture: u32 = checks
        .iter()
        .filter(|c| c.kind() == CheckKind::DeploymentPosture)
        .map(Check::forfeited)
        .sum();

    serde_json::json!({
        "security_score": score,
        "max_score": max_score,
        "grade": grade,
        // Why this number, in full. Before this block the response emitted a
        // score no emitted field could reconstruct, and a status legend that
        // asserted the opposite of the arithmetic — `info` was described as
        // "not security-graded" while three info outcomes were forfeiting ten
        // points each. Anything an operator needs to answer "why 70?" is here.
        "score_accounting": {
            "awarded": score,
            "max": max_score,
            "forfeited": forfeited,
            "formula": "security_score = sum(checks[].points); max_score = sum(checks[].max_points). EVERY status can forfeit points, `info` included — a status is a description of the finding, not a statement about whether it is scored.",
            "forfeited_by_kind": {
                "control": forfeited_control,
                "deployment_posture": forfeited_posture,
            },
            "kind_legend": {
                "control": "A security control. Points not awarded here are control health.",
                "deployment_posture": "A fact about WHERE this is deployed, not a control. Scored (the weights are unchanged and historical scores stay comparable), but a development stack cannot earn these points and is not less secure for it — subtract them before reading the score as control health.",
            },
            "shortfalls": shortfalls,
        },
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
            "pass": "The check found nothing to fix. It may still forfeit points — a control that is not configured at all (no Redis, dev-default CORS) passes without scoring; see checks[].points and score_accounting.shortfalls.",
            "warn": "Control is configured but not at the recommended hardening level, or could not be verified.",
            "fail": "Control is missing, misconfigured, or present-but-non-functional — fix before going to production.",
            "info": "Configuration noted, and NOT a control failure in this environment. It is still scored: an info outcome forfeits that check's points, which is why a report with zero failures and zero warnings can score well under max. score_accounting.shortfalls names every point not awarded.",
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
        "recommendation": recommendation_for(checks),
    })
}

/// Run every check and render the report.
///
/// Idempotent and side-effect free: see the per-probe documentation. The only
/// database access is a read of `pg_trigger`.
/// `write_ceiling_fleet` is supplied by the CALLER rather than read here, so
/// this crate keeps its single database touchpoint (`pg_trigger`) and every
/// branch of the check stays unit-testable without Postgres. `None` = the
/// caller's fleet read failed, which the check reports as NOT VERIFIED.
pub async fn run_security_audit(
    sysrepo: &SystemRepository,
    secrets: &SecretsManager,
    write_ceiling_fleet: Option<talos_worker_identity_repository::WriteCeilingFleetSummary>,
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
        check_write_ceiling_enforcement(write_ceiling_fleet, ControllerGateProbe::run()),
        check_cors_origins(
            &talos_config::check_allowed_origins(),
            talos_config::env_var_is_set_nonempty("ALLOWED_ORIGIN"),
        ),
    ];

    render_report(&checks)
}

#[cfg(test)]
mod tests;
