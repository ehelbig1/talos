//! Closed label sets for the Google push-authentication counters —
//! `talos_google_push_refusals_total{integration,reason}` and
//! `talos_google_jwk_refresh_total{outcome}`.
//!
//! Why they exist (2026-09-12, deploy of #837): ONE failed fetch of Google's
//! JWK set opened `GoogleOidcVerifier`'s 60 s backoff window and the 92 Gmail
//! Pub/Sub pushes that arrived inside it were each refused `unknown signing
//! key` with a WARN of their own — 94 WARN lines for one network blip, and
//! NO series anywhere: `google_jwt.rs` had no metric, and neither
//! `talos-gmail`, `talos-google-cloud` nor `talos-integration-helpers`
//! depended on this crate. Fail-closed was the right behaviour; the
//! REPORTING was a log storm with no count, so a sustained JWK outage (every
//! push refused, Pub/Sub retrying then dropping) would have been visible only
//! as log volume.
//!
//! Every value is an ENUM so the label set is closed by the compiler, and
//! every `(integration, reason)` pair is pre-seeded at 0: both handlers can
//! produce every reason (Gmail through `PubsubJwtVerifier::verify`, which
//! chains signature and service-account checks; GCP through `verify_signed`
//! plus its own `require_service_account` step; `missing_bearer` from each
//! handler's Authorization check), so no seeded pair is unreachable — check
//! 58's rule — and a counter born at 1 loses its first increment to
//! `increase()` (the 2026-09-11 MCP finding).

/// Which push integration refused the delivery. Two today; a third push
/// integration (`docs/integration-pattern.md`) adds a variant here and is
/// seeded the same run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PushIntegration {
    Gmail,
    Gcp,
}

impl PushIntegration {
    pub const ALL: &'static [Self] = &[Self::Gmail, Self::Gcp];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gmail => "gmail",
            Self::Gcp => "gcp",
        }
    }
}

/// Why a push was refused at the HTTP boundary, before any database read.
/// One variant per `talos_integration_helpers::google_jwt::VerifyError` arm
/// (paired by an exhaustive match in that crate) plus `MissingBearer`, the
/// handler-level refusal that never reaches the verifier.
///
/// `UnknownKey` is the one to read beside `talos_google_jwk_refresh_total`:
/// during a JWK backoff window every push carrying a key the cache does not
/// hold is refused with this reason — that is the fail-closed control
/// working, and it is why the verifier logs those at DEBUG with a per-window
/// summary rather than one WARN each.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PushRefusalReason {
    MissingBearer,
    MalformedHeader,
    WrongAlgorithm,
    MissingKid,
    UnknownKey,
    Invalid,
    WrongEmail,
    EmailNotVerified,
    JwkFetchFailed,
}

impl PushRefusalReason {
    pub const ALL: &'static [Self] = &[
        Self::MissingBearer,
        Self::MalformedHeader,
        Self::WrongAlgorithm,
        Self::MissingKid,
        Self::UnknownKey,
        Self::Invalid,
        Self::WrongEmail,
        Self::EmailNotVerified,
        Self::JwkFetchFailed,
    ];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MissingBearer => "missing_bearer",
            Self::MalformedHeader => "malformed_header",
            Self::WrongAlgorithm => "wrong_algorithm",
            Self::MissingKid => "missing_kid",
            Self::UnknownKey => "unknown_key",
            Self::Invalid => "invalid",
            Self::WrongEmail => "wrong_email",
            Self::EmailNotVerified => "email_not_verified",
            Self::JwkFetchFailed => "jwk_fetch_failed",
        }
    }
}

/// Outcome of one attempt to fetch Google's JWK set. `Failed` opens the
/// verifier's backoff window; sustained `Failed` with live push traffic is
/// the "control not working" signal `TalosGoogleJwkRefreshFailing` reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JwkRefreshOutcome {
    Ok,
    Failed,
}

impl JwkRefreshOutcome {
    pub const ALL: &'static [Self] = &[Self::Ok, Self::Failed];
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Failed => "failed",
        }
    }
}
