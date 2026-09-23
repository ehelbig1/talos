//! Closed label sets for the three security-surface counters that were
//! REGISTERED but never INCREMENTED from 2026-05 until 2026-09-11 —
//! `talos_auth_2fa_attempts_total`, `talos_api_key_validations_total` and
//! `talos_rate_limit_hits_total`. Check 58 carried them in its burn-down
//! baseline the whole time; a dead metric with no alert is debt, and this
//! module is the payment. `talos_mcp_auth_total` (2026-09-13) is the fourth:
//! the MCP agent token is the third bearer credential the controller accepts
//! and, until then, the only one whose refusals were counted nowhere and
//! logged nowhere — a guessed token got a bare 401 and left no trace.
//! `talos_password_changes_total` (2026-09-18) and, for the refresh-token
//! REUSE DETECTOR, `talos_auth_token_reuse_total` +
//! `talos_auth_rotation_audit_arm_total` (2026-09-21) followed: that last
//! pair covers the platform's only automated stolen-credential response,
//! whose single `talos_security_alert` log line was — measured — the sole
//! emitter of that target in the workspace, with nothing subscribing to it.
//!
//! Each set is an ENUM so the label value is closed by the COMPILER: a call
//! site cannot spell a fifth API-key verdict without adding it here, where
//! the seed loop in `TalosMetrics::new` picks it up. Every value is
//! pre-seeded at 0 — a counter born at 1 loses its first increment to
//! `increase()`/`rate()` (the 2026-09-11 MCP-counter finding), and for
//! security counters the FIRST event is exactly the one an operator wants
//! counted.

/// Outcome of one interactive 2FA verification (`TotpService::verify_2fa_login`
/// and the backup-code path), recorded at the two recorders every path
/// already calls — `record_2fa_success` / `record_2fa_failure` — so a new
/// verification branch cannot forget the metric without also forgetting the
/// rate-limit bookkeeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TwoFactorOutcome {
    Success,
    Failure,
}

impl TwoFactorOutcome {
    pub const ALL: &'static [Self] = &[Self::Success, Self::Failure];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
        }
    }
}

/// Verdict of one `ApiKeyService::validate_key` call. `Expired` is reported
/// only when EVERY candidate for the prefix was expired — a live key that
/// simply does not match is `Invalid`, and a caller must not be able to tell
/// the two apart from the reply (they get the same sentence); the split
/// exists for the OPERATOR, who reads the series. A DB failure mid-validation
/// is not a verdict and records nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ApiKeyValidation {
    Valid,
    Invalid,
    Expired,
    RateLimited,
}

impl ApiKeyValidation {
    pub const ALL: &'static [Self] =
        &[Self::Valid, Self::Invalid, Self::Expired, Self::RateLimited];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Valid => "valid",
            Self::Invalid => "invalid",
            Self::Expired => "expired",
            Self::RateLimited => "rate_limited",
        }
    }
}

/// Which limiter refused a request. `Ip` is the per-IP middleware (429, or
/// the GraphQL 200-with-error variant — both are hits), `Global` the
/// controller-wide limiter (503), `ApiKey` the per-prefix limiter inside
/// `validate_key` (which also records `ApiKeyValidation::RateLimited` — two
/// series, two questions), `Webhook` the per-trigger limiter in the webhook
/// router, `McpAuth` the per-IP limiter in front of MCP agent-token
/// authentication (`mcp_auth_middleware`, 429 — also recorded as
/// `McpAuthOutcome::RateLimited`; its defense-in-depth entry cap refusing a
/// NEW ip counts here too, since the caller sees the same 429). The webhook
/// IP circuit breaker is NOT a rate limit and is counted nowhere here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateLimitKind {
    Ip,
    Global,
    ApiKey,
    Webhook,
    McpAuth,
    /// The per-USER GraphQL throttle on heavy mutations (an LLM call or a
    /// synchronous WASM compile/run). A separate bucket from `Rhai` because
    /// they are two limiters with two limits, and collapsing them would hide
    /// which one an operator has to raise.
    GraphqlHeavyMutation,
    /// The per-USER GraphQL throttle on inline Rhai evaluation of a
    /// caller-supplied script.
    GraphqlRhai,
}

impl RateLimitKind {
    pub const ALL: &'static [Self] = &[
        Self::Ip,
        Self::Global,
        Self::ApiKey,
        Self::Webhook,
        Self::McpAuth,
        Self::GraphqlHeavyMutation,
        Self::GraphqlRhai,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Global => "global",
            Self::ApiKey => "api_key",
            Self::Webhook => "webhook",
            Self::McpAuth => "mcp_auth",
            Self::GraphqlHeavyMutation => "graphql_heavy_mutation",
            Self::GraphqlRhai => "graphql_rhai",
        }
    }
}

/// Outcome of one `require_second_factor` check — the gate on the PRIVILEGED
/// tier (master-key and DEK rotation, the re-encryption sweeps, API-key
/// lifecycle, MCP-agent registration, capability grants, audit settings,
/// ownership transfer: 15 mutations across 17 call sites as of 2026-09-23).
///
/// Every other bearer surface on this platform counts its outcomes —
/// `talos_auth_attempts_total`, `talos_api_key_validations_total`,
/// `talos_mcp_auth_total`, `talos_ws_handshakes_total`. This one was log-only
/// from the day it shipped, so "nobody has been refused a key rotation" and
/// "the gate is not wired" rendered identically.
///
/// The three non-policy arms are deliberately NOT folded into the policy ones:
/// a caller who could not be identified, a rule that could not be READ, and a
/// rule that said no are three different operator actions — the same split
/// `write_ceiling_unreadable` makes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivilegedOpOutcome {
    /// The second factor was verified for this session and still enrolled.
    Permitted,
    /// No session and no API key on the request (an expired session, usually).
    Unauthenticated,
    /// An API key. Keys skip 2FA by design, so they cannot stand in for it.
    ApiKey,
    /// The session is still half-way through its 2FA login.
    Pending,
    /// A password-only or OAuth session, or one minted before enrolment.
    NotVerified,
    /// The account has no second factor enrolled (or it was removed).
    NotEnrolled,
    /// The enrolment rule could NOT BE READ. A refusal, never a grant — and a
    /// value of its own, because it is a fault to fix rather than a policy
    /// decision to respect.
    Unreadable,
}

impl PrivilegedOpOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Permitted,
        Self::Unauthenticated,
        Self::ApiKey,
        Self::Pending,
        Self::NotVerified,
        Self::NotEnrolled,
        Self::Unreadable,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permitted => "permitted",
            Self::Unauthenticated => "unauthenticated",
            Self::ApiKey => "api_key",
            Self::Pending => "pending",
            Self::NotVerified => "not_verified",
            Self::NotEnrolled => "not_enrolled",
            Self::Unreadable => "unreadable",
        }
    }
    /// Did this outcome admit the call? One predicate, so a reader never has
    /// to enumerate the refusals and miss one when a variant is added.
    #[must_use]
    pub const fn permitted(self) -> bool {
        matches!(self, Self::Permitted)
    }
}

/// Outcome of one `require_platform_admin` check — the gate on cross-tenant
/// and system-wide operations.
///
/// Same three-way split as [`PrivilegedOpOutcome`]: an unidentified caller, an
/// unreadable rule and a rule that said no are not one event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformAdminOutcome {
    Permitted,
    /// No user id on the request.
    Unauthenticated,
    /// The caller is not a platform admin.
    NotAdmin,
    /// The `is_platform_admin` read failed. Refused, never granted.
    Unreadable,
}

impl PlatformAdminOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Permitted,
        Self::Unauthenticated,
        Self::NotAdmin,
        Self::Unreadable,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Permitted => "permitted",
            Self::Unauthenticated => "unauthenticated",
            Self::NotAdmin => "not_admin",
            Self::Unreadable => "unreadable",
        }
    }
    #[must_use]
    pub const fn permitted(self) -> bool {
        matches!(self, Self::Permitted)
    }
}

/// Outcome of one request through `mcp_auth_middleware` — the bearer
/// surface for MCP agent tokens, which MCP-1201 calls "long-lived bearer
/// tokens with no 2FA equivalent". One value per request, recorded at the
/// middleware's single exit from a refusal enum whose `outcome()` match is
/// exhaustive, so a new refusal branch cannot forget the series.
///
/// The CALLER cannot tell `MissingToken`, `UnknownToken` and `InvalidToken`
/// apart (each is a bare 401 — a token-existence oracle otherwise); the
/// split is for the OPERATOR. `UnknownToken` is the guessing signal: no
/// active `mcp_agents` row carries the token's SHA-256 lookup hash, which is
/// also what a REVOKED token reads as (the lookup filters `is_active`), so
/// there is deliberately no `revoked` value. `InvalidToken` is a row whose
/// lookup hash matches and whose bcrypt hash does not — two stored hashes
/// disagreeing about one token, a corrupted or hand-edited row rather than a
/// guess. `Error` is "the middleware could not decide" (agent lookup failed,
/// bcrypt worker panicked, stored hash malformed) and is a verdict here,
/// unlike `ApiKeyValidation`, because an auth surface that fails 100 % of
/// requests for an infrastructure reason must not read as quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum McpAuthOutcome {
    Ok,
    MissingToken,
    UnknownToken,
    InvalidToken,
    UnscopedAgent,
    RateLimited,
    Error,
}

impl McpAuthOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Ok,
        Self::MissingToken,
        Self::UnknownToken,
        Self::InvalidToken,
        Self::UnscopedAgent,
        Self::RateLimited,
        Self::Error,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::MissingToken => "missing_token",
            Self::UnknownToken => "unknown_token",
            Self::InvalidToken => "invalid_token",
            Self::UnscopedAgent => "unscoped_agent",
            Self::RateLimited => "rate_limited",
            Self::Error => "error",
        }
    }
}

/// Outcome of one WebSocket HANDSHAKE on `/ws` — the fourth bearer surface
/// (the access-token COOKIE, read on the upgrade request), and until
/// 2026-09-22 the one with no series at all: `talos-ws-auth` had nine
/// refusal / close arms and every one was a log line only. One value per
/// socket, recorded once at the handshake's single exit through
/// `report_handshake`, from an enum whose match is exhaustive, so a new
/// refusal arm cannot forget the series (package AX's shape, one surface
/// over).
///
/// The three origin values are the Cross-Site WebSocket Hijacking signal.
/// `NoToken` / `InvalidToken` / `InvalidUserId` are recorded when the client
/// completes `connection_init` WITHOUT a usable cookie — the moment the
/// server tells it "Authentication required"; a cookieless socket that never
/// sends `connection_init` ends as `InitNotReceived` instead. The CALLER sees
/// one `connection_error` for the three token outcomes (a token-existence
/// oracle otherwise); the split is for the operator. `Authenticated` means
/// the ack was sent and a session began.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WsHandshakeOutcome {
    Authenticated,
    OriginMissing,
    OriginMalformed,
    OriginNotAllowed,
    NoToken,
    InvalidToken,
    InvalidUserId,
    ProtocolViolation,
    InitNotReceived,
    ClosedBeforeInit,
}

impl WsHandshakeOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Authenticated,
        Self::OriginMissing,
        Self::OriginMalformed,
        Self::OriginNotAllowed,
        Self::NoToken,
        Self::InvalidToken,
        Self::InvalidUserId,
        Self::ProtocolViolation,
        Self::InitNotReceived,
        Self::ClosedBeforeInit,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Authenticated => "authenticated",
            Self::OriginMissing => "origin_missing",
            Self::OriginMalformed => "origin_malformed",
            Self::OriginNotAllowed => "origin_not_allowed",
            Self::NoToken => "no_token",
            Self::InvalidToken => "invalid_token",
            Self::InvalidUserId => "invalid_user_id",
            Self::ProtocolViolation => "protocol_violation",
            // The deadline elapsed with the socket still open. NARROWED by
            // this package: it previously also counted a client that closed
            // before connection_init, which is now `closed_before_init`. No
            // series was removed and nothing alerts on either.
            Self::InitNotReceived => "init_not_received",
            // The client went away before connection_init — an ordinary
            // browser reconnect or navigation, not a deadline and not a
            // refusal.
            Self::ClosedBeforeInit => "closed_before_init",
        }
    }
    /// A refusal the operator reads as a security signal (as opposed to a
    /// client that simply went away). Drives the log level at the one
    /// report site; the metric carries every value regardless.
    #[must_use]
    pub const fn is_security_refusal(self) -> bool {
        matches!(
            self,
            Self::OriginMissing
                | Self::OriginMalformed
                | Self::OriginNotAllowed
                | Self::InvalidToken
                | Self::InvalidUserId
        )
    }
}

/// How an AUTHENTICATED WebSocket session ended. `TokenExpired` is the
/// one that matters for security: the session is wrapped in a hard deadline equal to
/// the access token's remaining life, so a stolen-and-later-revoked cookie
/// is bounded — this is that bound firing. `ClientTerminated` is a
/// `connection_terminate` frame or a Close frame; `StreamEnded` is the
/// transport going away without either.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WsSessionEnd {
    TokenExpired,
    ClientTerminated,
    StreamEnded,
}

impl WsSessionEnd {
    pub const ALL: &'static [Self] = &[
        Self::TokenExpired,
        Self::ClientTerminated,
        Self::StreamEnded,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TokenExpired => "token_expired",
            Self::ClientTerminated => "client_terminated",
            Self::StreamEnded => "stream_ended",
        }
    }
}

/// One `start` / `subscribe` frame on an authenticated session: `Started`
/// when a subscription stream was opened; the two refusals are the lane's
/// own gates (2026-09-10: the WebSocket transport executes SUBSCRIPTIONS
/// only; 2026-07-19 P3: a password-only session may not subscribe) — both
/// were `talos_audit` log lines with no counter.
///
/// Two more since the lane multiplexes subscriptions over one socket
/// (package DV, 2026-09-22): `RefusedTooManySubscriptions` — the per-socket
/// cap (`talos_ws_auth::MAX_SUBSCRIPTIONS_PER_SOCKET`) refused a `start`,
/// a client bug or a probe, never a legitimate dashboard; and
/// `RefusedDuplicateId` — a `start` reusing an id that is still live, a
/// protocol violation the graphql-ws spec names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WsOperationOutcome {
    Started,
    RefusedNonSubscription,
    RefusedPreSecondFactor,
    RefusedTooManySubscriptions,
    RefusedDuplicateId,
}

impl WsOperationOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Started,
        Self::RefusedNonSubscription,
        Self::RefusedPreSecondFactor,
        Self::RefusedTooManySubscriptions,
        Self::RefusedDuplicateId,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::RefusedNonSubscription => "refused_non_subscription",
            Self::RefusedPreSecondFactor => "refused_pre_second_factor",
            Self::RefusedTooManySubscriptions => "refused_too_many",
            Self::RefusedDuplicateId => "refused_duplicate_id",
        }
    }
}

/// Outcome of one `AuthService::change_password` call, recorded once per call
/// at its single wrapper — the only way a user changes their own password.
/// `WrongCurrentPassword` is the guessing signal: a caller holding a session
/// but not the password (a stolen cookie). It shares the account-lockout
/// counter with login, so `Locked` follows five of them. `PolicyRejected`
/// and `Unchanged` are refused BEFORE any guess is counted. `Conflict` is
/// another request changing the password between this call's check and its
/// write. `Error` is "could not decide" and is a verdict, so a surface
/// failing every request for an infrastructure reason is not quiet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PasswordChangeOutcome {
    Changed,
    WrongCurrentPassword,
    Locked,
    PolicyRejected,
    Unchanged,
    Conflict,
    Error,
}

impl PasswordChangeOutcome {
    pub const ALL: &'static [Self] = &[
        Self::Changed,
        Self::WrongCurrentPassword,
        Self::Locked,
        Self::PolicyRejected,
        Self::Unchanged,
        Self::Conflict,
        Self::Error,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::WrongCurrentPassword => "wrong_current_password",
            Self::Locked => "locked",
            Self::PolicyRejected => "policy_rejected",
            Self::Unchanged => "unchanged",
            Self::Conflict => "conflict",
            Self::Error => "error",
        }
    }
}

/// What the refresh-token REUSE DETECTOR concluded about one failed refresh.
///
/// Refresh-token rotation makes a stolen token self-announcing: the thief's
/// first use succeeds and deletes the session, so the legitimate client's
/// next refresh misses. `rotated_session_audit` is what turns that miss into
/// evidence, and the response is `revoke_all_sessions` — the platform's ONLY
/// automated stolen-credential response.
///
/// Until 2026-09-21 that control produced no machine-readable output at all:
/// its one `target: "talos_security_alert"` line was the sole emitter of that
/// target in the workspace and nothing subscribed to it, so a detection and a
/// non-detection were indistinguishable to every dashboard and every rule.
/// Worse, the detector's own read was written `if let Ok(Some(..))`, which put
/// a DATABASE FAILURE in the same branch as "no reuse record" — the control
/// could silently not run at all.
///
/// One value per failed refresh that reaches the detector. The CALLER cannot
/// tell any of them apart (every path answers the same generic
/// `Invalid or expired refresh token`, deliberately — a different response on
/// detection is an oracle that tells a thief their token was recognised); the
/// split is for the OPERATOR.
///
/// `Detected` and `RevokeFailed` are both "a stolen token was replayed" and
/// an alert on reuse must select BOTH; they differ in whether the RESPONSE
/// happened. `DetectorUnreadable` is NOT a finding about the token — it is
/// the control reporting that it could not look, which is why it is a value
/// of its own rather than folded into `NotReused`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenReuseOutcome {
    /// No audit row for this lookup hash: the token was never a rotated
    /// token of a live session (a stale bookmark, a logged-out session, or
    /// garbage). The overwhelmingly common case.
    NotReused,
    /// An audit row inside the grace window — two tabs raced one rotation
    /// and the loser arrived here. Not revoked, by design.
    WithinGrace,
    /// Reuse past the grace window AND every session for the affected user
    /// was revoked: the control worked end to end.
    Detected,
    /// Reuse past the grace window and `revoke_all_sessions` FAILED. The
    /// detection is real and the response did not happen — the thief's own
    /// freshly minted session is still alive. Distinct from `Detected`
    /// because "we saw it" and "we acted on it" are different claims.
    RevokeFailed,
    /// The `rotated_session_audit` read itself failed. The control did not
    /// run; nothing here says the token was or was not reused. The refresh
    /// is still refused, so this is not a fail-open on the request — it is a
    /// fail-open on the RESPONSE.
    DetectorUnreadable,
}

impl TokenReuseOutcome {
    pub const ALL: &'static [Self] = &[
        Self::NotReused,
        Self::WithinGrace,
        Self::Detected,
        Self::RevokeFailed,
        Self::DetectorUnreadable,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotReused => "not_reused",
            Self::WithinGrace => "within_grace",
            Self::Detected => "detected",
            Self::RevokeFailed => "revoke_failed",
            Self::DetectorUnreadable => "detector_unreadable",
        }
    }
}

/// Did one successful rotation ARM the reuse detector?
///
/// The detector can only recognise a replayed token if the rotation that
/// retired it wrote a `rotated_session_audit` row. That INSERT is
/// deliberately best-effort — it must never fail a legitimate refresh — so a
/// failure disarms the detector for that one token and used to leave nothing
/// but a `warn!`. A PERSISTENT arm failure disarms it for the whole fleet
/// while every subsequent detection reads `NotReused`: a green detector over
/// a dead control, which is exactly check 58's class.
///
/// Recorded once per rotation, so `Failed / (Armed + Failed)` is a real
/// ratio and the failure series has a denominator. It is also this platform's
/// first volume series for the refresh path at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RotationAuditArmOutcome {
    /// The audit row was written (or already existed): a later replay of
    /// this token is detectable.
    Armed,
    /// The INSERT failed. The rotation itself still succeeded — the user got
    /// their new token — but a replay of the retired token will read as
    /// `NotReused`.
    Failed,
}

impl RotationAuditArmOutcome {
    pub const ALL: &'static [Self] = &[Self::Armed, Self::Failed];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Armed => "armed",
            Self::Failed => "failed",
        }
    }
}
