//! Closed label sets for the three security-surface counters that were
//! REGISTERED but never INCREMENTED from 2026-05 until 2026-09-11 —
//! `talos_auth_2fa_attempts_total`, `talos_api_key_validations_total` and
//! `talos_rate_limit_hits_total`. Check 58 carried them in its burn-down
//! baseline the whole time; a dead metric with no alert is debt, and this
//! module is the payment. `talos_mcp_auth_total` (2026-09-13) is the fourth:
//! the MCP agent token is the third bearer credential the controller accepts
//! and, until then, the only one whose refusals were counted nowhere and
//! logged nowhere — a guessed token got a bare 401 and left no trace.
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
}

impl RateLimitKind {
    pub const ALL: &'static [Self] = &[
        Self::Ip,
        Self::Global,
        Self::ApiKey,
        Self::Webhook,
        Self::McpAuth,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ip => "ip",
            Self::Global => "global",
            Self::ApiKey => "api_key",
            Self::Webhook => "webhook",
            Self::McpAuth => "mcp_auth",
        }
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
