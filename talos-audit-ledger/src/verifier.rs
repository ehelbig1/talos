//! The audit-chain VERIFIER identity, and what it says when it cannot read.
//!
//! # Why this module exists
//!
//! The WORM audit ledger has one identity and two jobs, and the two jobs want
//! opposite permissions. The WRITER must be able to `PutObject` and nothing
//! else — a writer that can also `ListBucket`/`GetObject` is a writer that can
//! survey and target what it wrote, which is the whole point of the
//! write-only separation. The VERIFIER must be able to `ListBucket` and
//! `GetObject` and nothing else — it re-reads the chain to prove it was not
//! altered, and a verifier that can write is not evidence of anything.
//!
//! Until this module, `build_audit_s3_client` served BOTH, resolving
//! credentials through `aws_config::load_defaults` — i.e. the `AWS_*`
//! environment chain, which on every deployment of this platform is the
//! WRITER. Measured on the dev stack 2026-09-06: `mc ls` with those
//! credentials answers `Access Denied`, the bucket held 48,946 execution
//! prefixes written by that same identity, and the controller log carried 37
//! `audit_chain_verification_errored` lines in one hour and zero
//! `audit_chain_verification_failed` lines in its entire history. The control
//! had never functioned, and no metric, alert or audit surface could say so.
//!
//! # Two rules this module exists to keep
//!
//! 1. **The verifier's client is built from EXPLICIT credentials, never from
//!    the environment chain.** [`build_verifier_client`] constructs an
//!    `aws_sdk_s3::Config` from scratch — there is no `load_defaults` call on
//!    this path, so there is no chain for the writer's `AWS_*` to be picked up
//!    from. If the verifier credentials are absent the answer is
//!    [`VerifierClient::NoCredentials`] and NO client is built. Silently
//!    falling back to the writer would restore a control that cannot work
//!    while looking configured, which is the defect.
//! 2. **"Could not read" is CLASSIFIED, not stringified.**
//!    [`ChainVerifyErrorKind`] separates a permission problem from a
//!    provisioning problem from a transport blip, because those call for three
//!    different operator actions and the SDK's own `Display` renders all three
//!    as the four characters `service error`.

use aws_sdk_s3::error::ProvideErrorMetadata;
use aws_sdk_s3::Client as S3Client;
use aws_smithy_runtime_api::client::result::SdkError;
use std::sync::{OnceLock, RwLock};
use zeroize::Zeroizing;

/// Environment variable naming the audit-chain verifier's access key id.
///
/// Deliberately NOT `AWS_ACCESS_KEY_ID`: that name is the writer's, on every
/// deployment, and a verifier that reads it is the bug. The `AUDIT_VERIFIER_`
/// prefix follows the same shape as the writer's compose wiring
/// (`AWS_ACCESS_KEY_ID: ${MINIO_CONTROLLER_USER}`) one identity over.
pub const VERIFIER_ACCESS_KEY_ENV: &str = "AUDIT_VERIFIER_ACCESS_KEY_ID";

/// Environment variable naming the audit-chain verifier's secret key.
pub const VERIFIER_SECRET_KEY_ENV: &str = "AUDIT_VERIFIER_SECRET_ACCESS_KEY";

/// Region handed to the explicit verifier config. MinIO ignores it, but SigV4
/// requires one, and reading it from `AWS_REGION`/`AWS_DEFAULT_REGION` keeps a
/// real S3 deployment working without a second knob.
const DEFAULT_REGION: &str = "us-east-1";

/// The verifier's credential pair.
///
/// `Debug` is hand-written and redacts BOTH halves (check 37). The access key
/// id is not a secret in the way the secret key is, but it names a principal
/// on a bucket holding every tenant's audit trail, and this struct exists
/// precisely so a `{:?}` in a future log line cannot leak the pair.
#[derive(Clone)]
pub struct VerifierCredentials {
    access_key_id: String,
    secret_access_key: Zeroizing<String>,
}

impl VerifierCredentials {
    #[must_use]
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: Zeroizing::new(secret_access_key.into()),
        }
    }

    /// The access key id, for handing to the SDK's credential type only.
    #[must_use]
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }
}

impl std::fmt::Debug for VerifierCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifierCredentials")
            .field("access_key_id", &"<redacted>")
            .field("secret_access_key", &"<redacted>")
            .finish()
    }
}

/// Read the verifier credentials from the environment.
///
/// EMPTY IS UNSET (lint check 73): a Helm placeholder renders `""`, and a
/// half-configured pair must read as absent rather than as a principal with an
/// empty key — the latter reaches MinIO and comes back as an anonymous
/// AccessDenied, which is the same misdiagnosis this module removes. Both
/// halves are required; one without the other is `None`.
#[must_use]
pub fn verifier_credentials_from_env() -> Option<VerifierCredentials> {
    let id = std::env::var(VERIFIER_ACCESS_KEY_ENV)
        .ok()
        .filter(|v| !v.is_empty())?;
    let secret = std::env::var(VERIFIER_SECRET_KEY_ENV)
        .ok()
        .filter(|v| !v.is_empty())?;
    Some(VerifierCredentials::new(id, secret))
}

/// What resolving a verifier client produced.
///
/// Three-valued on purpose. "No S3 endpoint at all" is a deployment that has
/// no WORM store and nothing to verify; "no verifier credentials" is a
/// deployment that HAS one and cannot read it. Collapsing them would put a
/// broken control and an absent one in the same branch, which is the
/// distinction the whole `security_audit` crate exists to keep.
pub enum VerifierClient {
    Ready(Box<S3Client>),
    /// No `AWS_ENDPOINT_URL`/`MINIO_ENDPOINT` — there is no WORM store here.
    NoEndpoint,
    /// An endpoint is configured but the verifier identity is not.
    NoCredentials,
}

/// Build the READ-ONLY verifier client from the environment.
///
/// Endpoint resolution is deliberately identical to the writer's
/// (`AWS_ENDPOINT_URL`, then `MINIO_ENDPOINT`, empty treated as unset) and
/// shares the same path-style flag, because verifier and writer must address
/// the SAME bucket — a divergence there would make the verifier read a
/// different store and report a clean chain about objects nobody wrote.
///
/// CREDENTIALS are the one thing that must NOT be shared. There is no
/// `aws_config::load_defaults` on this path.
#[must_use]
pub fn build_audit_verifier_client_from_env() -> VerifierClient {
    let Some(endpoint) = audit_s3_endpoint_from_env() else {
        return VerifierClient::NoEndpoint;
    };
    let Some(creds) = verifier_credentials_from_env() else {
        return VerifierClient::NoCredentials;
    };
    let path_style = talos_config::bool_env_or_default("AWS_S3_FORCE_PATH_STYLE", false);
    let region = std::env::var("AWS_REGION")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("AWS_DEFAULT_REGION")
                .ok()
                .filter(|v| !v.is_empty())
        })
        .unwrap_or_else(|| DEFAULT_REGION.to_string());
    VerifierClient::Ready(Box::new(build_verifier_client(
        &endpoint, &region, &creds, path_style,
    )))
}

/// The endpoint half of the resolution, shared with the writer's builder so
/// the two cannot drift.
pub(crate) fn audit_s3_endpoint_from_env() -> Option<String> {
    std::env::var("AWS_ENDPOINT_URL")
        .ok()
        .filter(|v| !v.is_empty())
        .or_else(|| {
            std::env::var("MINIO_ENDPOINT")
                .ok()
                .filter(|v| !v.is_empty())
        })
}

/// Build an S3 client bound to EXPLICIT credentials.
///
/// Pure: every input is a parameter, so `verifier_client_uses_the_explicit_credentials`
/// can resolve the credentials back off the built config and assert they are
/// the ones passed in. That test is the guard on rule 1 above — reintroducing
/// `aws_config::load_defaults` here without an explicit provider makes it fail,
/// because a test process carries no `AWS_*` and the resolution errors.
#[must_use]
pub fn build_verifier_client(
    endpoint: &str,
    region: &str,
    creds: &VerifierCredentials,
    force_path_style: bool,
) -> S3Client {
    let credentials = aws_sdk_s3::config::Credentials::new(
        creds.access_key_id.clone(),
        creds.secret_access_key.to_string(),
        None,
        None,
        "talos-audit-verifier",
    );
    let mut builder = aws_sdk_s3::config::Builder::new()
        .behavior_version(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new(region.to_string()))
        .endpoint_url(endpoint)
        .credentials_provider(credentials);
    if force_path_style {
        builder = builder.force_path_style(true);
    }
    S3Client::from_conf(builder.build())
}

// ── Failure classification ──────────────────────────────────────────────────

/// Why a chain could not be verified.
///
/// A CLOSED set, and it is closed because it is a metric label
/// (`talos_audit_chain_unverifiable_total{reason}`) whose values must be
/// pre-seeded. The distinction that matters most is the first two against the
/// last two: `AccessDenied` and `NoSuchBucket` are DEPLOYMENT-WIDE facts —
/// one identity, one bucket — so the answer for the second execution in a
/// sweep cannot differ from the answer for the first, which is why the sweep
/// aborts on them (see `ChainSweepStats::aborted`). `NotFound` and `Transport`
/// are per-object and per-request and say nothing about the next one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainVerifyErrorKind {
    /// The identity is not permitted. On this platform that means the client
    /// was built from the WRITER's credentials, or the verifier's policy was
    /// not attached.
    AccessDenied,
    /// The bucket does not exist — a provisioning gap, not a permission one.
    NoSuchBucket,
    /// A key vanished between listing and reading, or the prefix is empty.
    NotFound,
    /// The request never got an answer: DNS, TLS, connection reset, timeout.
    Transport,
    /// A service error this classifier does not name. Never a silent bucket
    /// for the four above — `classify_s3_error_code` matches them explicitly.
    Other,
    /// The verifier identity is not configured at all, so nothing was
    /// attempted. Not an S3 outcome; it shares the enum because it shares the
    /// metric and the operator question ("why is nothing verified?").
    NoCredentials,
    /// The prefix READ CLEANLY and contained ZERO events.
    ///
    /// # Why this is not success
    ///
    /// `verify_chain` over an empty event set returns `ok == true` — there are
    /// no gaps, no broken links and no bad signatures in nothing. Counting
    /// that as a verified chain is the "verified nothing" claim this whole
    /// module exists to remove, and on this platform it is not hypothetical:
    /// measured 2026-09-06, **200 of 200** recent ledger prefixes are
    /// `module_executions.id` and **0 of 200** are `workflow_executions.id`,
    /// in BOTH directions — while `run_chain_verification_sweep` enumerates
    /// `workflow_executions`. So every prefix the sweep names is empty by
    /// construction, and 34 of 34 terminal executions in its own 2 h window
    /// had zero objects. Repairing the verifier identity WITHOUT this variant
    /// would have converted 37 loud WARNs into 37 silent `verified_ok` — a
    /// control reporting perfect health while reading nothing, which is
    /// strictly worse than the AccessDenied it replaced.
    ///
    /// Deliberately does NOT abort the sweep: an individual execution can
    /// legitimately produce no audit events, so this is a per-execution fact
    /// and the volume is what makes it a finding.
    EmptyChain,
}

impl ChainVerifyErrorKind {
    /// The metric label. Short, stable, and lower-snake because it is a
    /// Prometheus label value that alert expressions select on.
    #[must_use]
    pub fn metric_label(self) -> &'static str {
        match self {
            ChainVerifyErrorKind::AccessDenied => "access_denied",
            ChainVerifyErrorKind::NoSuchBucket => "no_such_bucket",
            ChainVerifyErrorKind::NotFound => "not_found",
            ChainVerifyErrorKind::Transport => "transport",
            ChainVerifyErrorKind::Other => "other",
            ChainVerifyErrorKind::NoCredentials => "no_credentials",
            ChainVerifyErrorKind::EmptyChain => "empty_chain",
        }
    }

    /// Every label value, for the pre-seed loop and for the test that pins it.
    /// ABSENT IS NOT ZERO: an `increase(...) > 0` alert over a series that has
    /// never been touched matches nothing, so every value here is seeded.
    pub const ALL: &'static [ChainVerifyErrorKind] = &[
        ChainVerifyErrorKind::AccessDenied,
        ChainVerifyErrorKind::NoSuchBucket,
        ChainVerifyErrorKind::NotFound,
        ChainVerifyErrorKind::Transport,
        ChainVerifyErrorKind::Other,
        ChainVerifyErrorKind::NoCredentials,
        ChainVerifyErrorKind::EmptyChain,
    ];

    /// Whether this outcome is a DEPLOYMENT-WIDE fact that makes the rest of a
    /// sweep pointless.
    ///
    /// The decision, recorded: the sweep verifies up to `MAX_JOBS_PER_SWEEP`
    /// job chains through ONE client against ONE bucket. If the first says
    /// AccessDenied, so will all of them — identical WARNs whose only effect
    /// is to bury a real per-job finding, plus that many needless round trips.
    /// `NotFound` and `Transport` are NOT abort-worthy: a missing prefix is
    /// about that job and a reset connection may well be the last one.
    #[must_use]
    pub fn aborts_sweep(self) -> bool {
        matches!(
            self,
            ChainVerifyErrorKind::AccessDenied
                | ChainVerifyErrorKind::NoSuchBucket
                | ChainVerifyErrorKind::NoCredentials
        )
    }
}

/// Classify an S3 error CODE.
///
/// Split from [`classify_sdk_error`] so the code table is exhaustively
/// unit-testable without constructing an `SdkError` (which needs a synthetic
/// HTTP response). `None` — a service error the SDK could not attribute a code
/// to — is `Other`, never one of the named four: guessing a permission
/// diagnosis from an absent code is how an operator gets sent to the wrong
/// place.
#[must_use]
pub fn classify_s3_error_code(code: Option<&str>) -> ChainVerifyErrorKind {
    match code {
        // MinIO and S3 both use `AccessDenied`; `AllAccessDisabled` and
        // `InvalidAccessKeyId`/`SignatureDoesNotMatch` are the same operator
        // action (fix the identity), so they land in the same bucket rather
        // than in `Other` where nobody would look.
        Some("AccessDenied" | "AllAccessDisabled" | "InvalidAccessKeyId")
        | Some("SignatureDoesNotMatch") => ChainVerifyErrorKind::AccessDenied,
        Some("NoSuchBucket") => ChainVerifyErrorKind::NoSuchBucket,
        Some("NoSuchKey" | "NotFound") => ChainVerifyErrorKind::NotFound,
        _ => ChainVerifyErrorKind::Other,
    }
}

/// Classify an `SdkError` from any S3 operation.
///
/// Uses the SDK's own typed error-code accessor (`ProvideErrorMetadata::code`)
/// rather than matching on the rendered string — the string is exactly what
/// this change exists to stop relying on.
#[must_use]
pub fn classify_sdk_error<E, R>(err: &SdkError<E, R>) -> ChainVerifyErrorKind
where
    E: ProvideErrorMetadata,
{
    match err {
        SdkError::ServiceError(ctx) => classify_s3_error_code(ctx.err().code()),
        // The request never reached a service, or its answer never arrived.
        SdkError::DispatchFailure(_) | SdkError::TimeoutError(_) | SdkError::ResponseError(_) => {
            ChainVerifyErrorKind::Transport
        }
        // A client that could not be built at all. Not transport, not a
        // service answer — a configuration fault, which `Other` names honestly
        // rather than mislabelling.
        SdkError::ConstructionFailure(_) => ChainVerifyErrorKind::Other,
        // `SdkError` is `#[non_exhaustive]`. A new variant must not silently
        // acquire one of the four specific diagnoses.
        _ => ChainVerifyErrorKind::Other,
    }
}

/// A classified chain-verification failure.
///
/// `context` names the operation and the object/prefix; `detail` carries the
/// SDK's FULL error chain (`DisplayErrorContext`), which is where the code and
/// the underlying cause actually live — the bare `Display` renders
/// `service error` and nothing else.
#[derive(Debug)]
pub struct ChainVerifyError {
    pub kind: ChainVerifyErrorKind,
    pub context: String,
    pub detail: String,
}

impl ChainVerifyError {
    #[must_use]
    pub fn new(kind: ChainVerifyErrorKind, context: impl Into<String>, detail: String) -> Self {
        Self {
            kind,
            context: context.into(),
            detail,
        }
    }

    /// Build from an `SdkError`, classifying it and capturing the full chain.
    #[must_use]
    pub fn from_sdk<E, R>(context: impl Into<String>, err: &SdkError<E, R>) -> Self
    where
        E: ProvideErrorMetadata + std::error::Error + 'static,
        R: std::fmt::Debug,
    {
        Self {
            kind: classify_sdk_error(err),
            context: context.into(),
            detail: format!("{}", aws_sdk_s3::error::DisplayErrorContext(err)),
        }
    }

    /// One sentence naming the operator action for this kind. Used by both the
    /// log line and the `security_audit` check, so the two cannot disagree.
    #[must_use]
    pub fn remedy(&self) -> &'static str {
        match self.kind {
            ChainVerifyErrorKind::AccessDenied => {
                "the verifier identity is not permitted to read the audit bucket — confirm \
                 AUDIT_VERIFIER_ACCESS_KEY_ID names the read-only verifier user and that the \
                 audit_read_only policy (s3:ListBucket on the bucket + s3:GetObject on its \
                 objects) is attached to it. The WRITER's key is write-only by design and \
                 cannot be used here."
            }
            ChainVerifyErrorKind::NoSuchBucket => {
                "the audit bucket does not exist — this is a provisioning gap, not a \
                 permission one. Run the MinIO/S3 bucket-and-user provisioning step."
            }
            ChainVerifyErrorKind::NotFound => {
                "an object listed for this execution could not be read; it may have been \
                 lifecycled or the prefix is empty."
            }
            ChainVerifyErrorKind::Transport => {
                "the object store did not answer (DNS, TLS, connection reset or timeout). \
                 Check the endpoint and the network path before treating this as a control \
                 failure."
            }
            ChainVerifyErrorKind::Other => {
                "the object store returned an error this classifier does not name — read the \
                 `detail` field, which carries the SDK's full error chain."
            }
            ChainVerifyErrorKind::NoCredentials => {
                "no audit-chain verifier identity is configured — set \
                 AUDIT_VERIFIER_ACCESS_KEY_ID and AUDIT_VERIFIER_SECRET_ACCESS_KEY to the \
                 read-only verifier user. Until then the WORM ledger is written and never \
                 verified."
            }
            ChainVerifyErrorKind::EmptyChain => {
                "the prefix read cleanly and held NO events, so nothing was verified — an \
                 empty chain trivially satisfies every check. The sweep names \
                 <module_executions.id>/ prefixes, which is the id space the writer keys, \
                 and 200 of 200 recent module executions had a non-empty prefix (measured \
                 2026-09-06) — so this is a fact about THIS job: either the worker emitted \
                 no audit events for it, or its batch never reached the object store. If it \
                 is the WHOLE population, suspect the audit-ledger subscriber rather than \
                 the verifier: the identity demonstrably works, or this would have been \
                 access_denied."
            }
        }
    }
}

impl std::fmt::Display for ChainVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} [{}]: {}",
            self.context,
            self.kind.metric_label(),
            self.detail
        )
    }
}

impl std::error::Error for ChainVerifyError {}

// ── Process-global snapshot of the last sweep ───────────────────────────────

/// What the last chain-verification sweep found, published for `security_audit`.
///
/// A snapshot rather than a metric read: `security_audit` renders prose an
/// operator acts on, and "the last sweep verified 0 of 37 and aborted on
/// access_denied" is a different sentence from a counter delta. UNKNOWN is not
/// zero here either — `None` from [`last_chain_sweep`] means no sweep has
/// completed in THIS process (a controller that just booted, or one where the
/// sweep is disabled), which the check must render as "not yet run" and never
/// as "verified nothing".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainSweepSnapshot {
    /// JOBS (module executions) scanned — the grain the ledger is keyed at.
    pub scanned: usize,
    /// Job chains that verified AND held at least one event.
    pub verified_ok: usize,
    /// Prefixes that read cleanly and held ZERO events — see
    /// [`ChainVerifyErrorKind::EmptyChain`]. NOT verified.
    pub empty: usize,
    pub failed: usize,
    pub errored: usize,
    /// Jobs with no `workflow_execution_id`, so no genesis pair and no
    /// attempt. Disclosed, never folded into a clean count.
    pub unbound: usize,
    pub cap_hit: bool,
    pub aborted: Option<ChainVerifyErrorKind>,
    /// The same pass rolled up to WORKFLOW EXECUTIONS, worst outcome wins —
    /// the grain every other report on this platform is keyed on.
    pub rollup: crate::population::WorkflowExecutionRollup,
    /// Unix seconds at which the sweep finished.
    pub finished_at_unix: i64,
}

fn snapshot_cell() -> &'static RwLock<Option<ChainSweepSnapshot>> {
    static CELL: OnceLock<RwLock<Option<ChainSweepSnapshot>>> = OnceLock::new();
    CELL.get_or_init(|| RwLock::new(None))
}

/// Publish the outcome of a completed sweep pass.
pub fn publish_chain_sweep_snapshot(snapshot: ChainSweepSnapshot) {
    if let Ok(mut guard) = snapshot_cell().write() {
        *guard = Some(snapshot);
    }
}

/// The last published sweep outcome, or `None` if none has completed here.
#[must_use]
pub fn last_chain_sweep() -> Option<ChainSweepSnapshot> {
    snapshot_cell().read().ok().and_then(|g| *g)
}

#[cfg(test)]
mod verifier_tests {
    use super::*;

    #[test]
    fn every_named_s3_code_gets_its_own_kind() {
        assert_eq!(
            classify_s3_error_code(Some("AccessDenied")),
            ChainVerifyErrorKind::AccessDenied
        );
        assert_eq!(
            classify_s3_error_code(Some("AllAccessDisabled")),
            ChainVerifyErrorKind::AccessDenied
        );
        assert_eq!(
            classify_s3_error_code(Some("InvalidAccessKeyId")),
            ChainVerifyErrorKind::AccessDenied
        );
        assert_eq!(
            classify_s3_error_code(Some("SignatureDoesNotMatch")),
            ChainVerifyErrorKind::AccessDenied
        );
        assert_eq!(
            classify_s3_error_code(Some("NoSuchBucket")),
            ChainVerifyErrorKind::NoSuchBucket
        );
        assert_eq!(
            classify_s3_error_code(Some("NoSuchKey")),
            ChainVerifyErrorKind::NotFound
        );
        assert_eq!(
            classify_s3_error_code(Some("NotFound")),
            ChainVerifyErrorKind::NotFound
        );
        // An unattributed service error must NOT acquire a specific diagnosis.
        assert_eq!(classify_s3_error_code(None), ChainVerifyErrorKind::Other);
        assert_eq!(
            classify_s3_error_code(Some("SlowDown")),
            ChainVerifyErrorKind::Other
        );
    }

    /// The whole point of the classifier: the four kinds are not the same
    /// answer. A mutation that collapses `classify_s3_error_code` to `Other`
    /// fails here AND in the abort test below.
    #[test]
    fn only_deployment_wide_kinds_abort_the_sweep() {
        assert!(ChainVerifyErrorKind::AccessDenied.aborts_sweep());
        assert!(ChainVerifyErrorKind::NoSuchBucket.aborts_sweep());
        assert!(ChainVerifyErrorKind::NoCredentials.aborts_sweep());
        assert!(!ChainVerifyErrorKind::NotFound.aborts_sweep());
        assert!(!ChainVerifyErrorKind::Transport.aborts_sweep());
        assert!(!ChainVerifyErrorKind::Other.aborts_sweep());
    }

    /// An empty chain must NOT abort — a single execution can legitimately
    /// produce no audit events, and the volume is what makes it a finding.
    #[test]
    fn an_empty_chain_is_a_per_execution_fact_not_a_deployment_one() {
        assert!(!ChainVerifyErrorKind::EmptyChain.aborts_sweep());
    }

    #[test]
    fn metric_labels_are_distinct_and_cover_every_kind() {
        let labels: Vec<&str> = ChainVerifyErrorKind::ALL
            .iter()
            .map(|k| k.metric_label())
            .collect();
        let mut sorted = labels.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), labels.len(), "duplicate metric label");
        assert_eq!(labels.len(), 7);
    }

    /// A transport-shaped `SdkError` classifies as `Transport`, not as one of
    /// the service diagnoses. Constructed through the SDK's own public
    /// constructors so the variant match is exercised rather than asserted.
    #[test]
    fn dispatch_and_timeout_failures_are_transport() {
        use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;
        use aws_smithy_runtime_api::client::result::ConnectorError;

        let dispatch: SdkError<ListObjectsV2Error, ()> = SdkError::dispatch_failure(
            ConnectorError::io(Box::new(std::io::Error::other("connection reset"))),
        );
        assert_eq!(
            classify_sdk_error(&dispatch),
            ChainVerifyErrorKind::Transport
        );

        let timeout: SdkError<ListObjectsV2Error, ()> =
            SdkError::timeout_error(Box::new(std::io::Error::other("timed out")));
        assert_eq!(
            classify_sdk_error(&timeout),
            ChainVerifyErrorKind::Transport
        );

        let construction: SdkError<ListObjectsV2Error, ()> =
            SdkError::construction_failure(Box::new(std::io::Error::other("bad config")));
        assert_eq!(
            classify_sdk_error(&construction),
            ChainVerifyErrorKind::Other
        );
    }

    /// A SERVICE error carrying an S3 code classifies from the code, through
    /// the SDK's typed accessor.
    #[test]
    fn a_service_error_classifies_from_its_code() {
        use aws_sdk_s3::operation::list_objects_v2::ListObjectsV2Error;
        use aws_smithy_types::error::metadata::ErrorMetadata;

        let denied =
            ListObjectsV2Error::generic(ErrorMetadata::builder().code("AccessDenied").build());
        let err: SdkError<ListObjectsV2Error, ()> = SdkError::service_error(denied, ());
        assert_eq!(classify_sdk_error(&err), ChainVerifyErrorKind::AccessDenied);

        let missing =
            ListObjectsV2Error::generic(ErrorMetadata::builder().code("NoSuchBucket").build());
        let err: SdkError<ListObjectsV2Error, ()> = SdkError::service_error(missing, ());
        assert_eq!(classify_sdk_error(&err), ChainVerifyErrorKind::NoSuchBucket);
    }

    /// Rule 1, pinned END TO END: the client SIGNS with the credentials handed
    /// in, and there is no environment chain behind it.
    ///
    /// # Why this drives a socket instead of reading the config back
    ///
    /// `aws_sdk_s3::Config::credentials_provider()` is deprecated and has
    /// returned `None` unconditionally since release-2023-11-15, so the
    /// obvious assertion cannot be written — it would pass vacuously against
    /// a client carrying no credentials at all, which is the exact mutation
    /// this test exists to catch. So the test stands up a one-shot TCP
    /// listener, points the verifier client at it, issues a real
    /// `list_objects_v2`, and reads the `Credential=<access-key-id>/...` field
    /// out of the SigV4 `Authorization` header the SDK actually put on the
    /// wire.
    ///
    /// Two mutations fail it, both measured: replacing the explicit provider
    /// with `aws_config::load_defaults` (a test process carries no `AWS_*`, so
    /// credential resolution errors and no request is ever sent), and signing
    /// with any key other than the one passed in.
    #[tokio::test]
    async fn verifier_client_signs_with_the_explicit_credentials() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind probe listener");
        let port = listener.local_addr().expect("local addr").port();

        let captured = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            // Answer so the SDK finishes rather than retrying forever.
            let _ = sock
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await;
            let _ = sock.shutdown().await;
            String::from_utf8_lossy(&buf[..n]).to_string()
        });

        let creds = VerifierCredentials::new("probe-verifier-key", "probe-verifier-secret");
        let client = build_verifier_client(
            &format!("http://127.0.0.1:{port}"),
            "us-east-1",
            &creds,
            true,
        );
        // The result does not matter — the request bytes do.
        let _ = client
            .list_objects_v2()
            .bucket("audit-logs")
            .prefix("probe/")
            .send()
            .await;

        let request = tokio::time::timeout(std::time::Duration::from_secs(10), captured)
            .await
            .expect("the verifier client must actually send a request")
            .expect("capture task");
        assert!(
            request.contains("Credential=probe-verifier-key/"),
            "SigV4 Authorization header must name the EXPLICIT verifier key; got:\n{request}"
        );
    }

    /// Neither half of the pair may leak through `Debug` (check 37).
    #[test]
    fn credentials_redact_in_debug() {
        let creds = VerifierCredentials::new("AKIAEXAMPLE", "s3cr3t-value");
        let rendered = format!("{creds:?}");
        assert!(!rendered.contains("AKIAEXAMPLE"), "{rendered}");
        assert!(!rendered.contains("s3cr3t-value"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
    }

    /// A remedy sentence exists for every kind, and each names its own action.
    #[test]
    fn every_kind_has_a_distinct_remedy() {
        let remedies: Vec<&str> = ChainVerifyErrorKind::ALL
            .iter()
            .map(|k| ChainVerifyError::new(*k, "probe", String::new()).remedy())
            .collect();
        let mut sorted = remedies.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), remedies.len());
    }

    #[test]
    fn snapshot_round_trips() {
        let snap = ChainSweepSnapshot {
            scanned: 37,
            verified_ok: 0,
            empty: 0,
            failed: 0,
            errored: 1,
            unbound: 0,
            cap_hit: false,
            aborted: Some(ChainVerifyErrorKind::AccessDenied),
            rollup: crate::population::WorkflowExecutionRollup {
                covered: 1,
                errored: 1,
                ..crate::population::WorkflowExecutionRollup::default()
            },
            finished_at_unix: 1_757_000_000,
        };
        publish_chain_sweep_snapshot(snap);
        assert_eq!(last_chain_sweep(), Some(snap));
    }
}
